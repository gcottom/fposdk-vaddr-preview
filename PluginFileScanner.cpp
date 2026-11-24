#include "PluginFileScanner.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <zlib.h>

namespace vaddr {
namespace {

constexpr std::size_t kRecordHeaderSize = 24;
constexpr std::size_t kSubrecordHeaderSize = 6;
constexpr std::uint32_t kCompressedRecordFlag = 0x0004'0000U;

[[noreturn]] void BadPlugin(std::string_view reason, const std::filesystem::path& path) {
    throw MappingError("invalid plugin file '" + path.string() + "': " + std::string(reason));
}

std::uint16_t ReadU16(std::span<const std::byte> bytes, std::size_t at) {
    return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[at])) |
           static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(bytes[at + 1]) << 8);
}

std::uint32_t ReadU32(std::span<const std::byte> bytes, std::size_t at) {
    return static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[at])) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[at + 1])) << 8) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[at + 2])) << 16) |
           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[at + 3])) << 24);
}

bool TagEquals(std::span<const std::byte> bytes, std::size_t at, std::string_view tag) {
    if (tag.size() != 4) return false;
    for (std::size_t i = 0; i < tag.size(); ++i) {
        if (std::to_integer<unsigned char>(bytes[at + i]) !=
            static_cast<unsigned char>(tag[i])) return false;
    }
    return true;
}

std::string ReadTag(std::span<const std::byte> bytes, std::size_t at) {
    std::string tag;
    tag.reserve(4);
    for (std::size_t i = 0; i < 4; ++i) {
        tag.push_back(static_cast<char>(std::to_integer<unsigned char>(bytes[at + i])));
    }
    return tag;
}

void ReadExact(std::ifstream& input, std::span<std::byte> bytes,
               const std::filesystem::path& path, std::string_view what) {
    if (bytes.empty()) return;
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (input.gcount() != static_cast<std::streamsize>(bytes.size())) {
        BadPlugin("truncated " + std::string(what), path);
    }
}

std::uint64_t Position(std::ifstream& input, const std::filesystem::path& path) {
    const auto position = input.tellg();
    if (position < 0) BadPlugin("unable to determine stream position", path);
    return static_cast<std::uint64_t>(static_cast<std::streamoff>(position));
}

void Seek(std::ifstream& input, std::uint64_t offset, const std::filesystem::path& path) {
    if (offset > static_cast<std::uint64_t>(std::numeric_limits<std::streamoff>::max())) {
        BadPlugin("offset exceeds stream limits", path);
    }
    input.clear();
    input.seekg(static_cast<std::streamoff>(offset), std::ios::beg);
    if (!input) BadPlugin("failed to seek within the file", path);
}

std::vector<std::byte> ReadVector(std::ifstream& input, std::uint64_t size,
                                  const std::filesystem::path& path,
                                  std::string_view what) {
    if (size > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max())) {
        BadPlugin(std::string(what) + " exceeds addressable memory", path);
    }
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    ReadExact(input, bytes, path, what);
    return bytes;
}

void AddCount(std::uint64_t& value, std::uint64_t amount,
              const std::filesystem::path& path, std::string_view what) {
    if (amount > std::numeric_limits<std::uint64_t>::max() - value) {
        BadPlugin(std::string(what) + " count overflow", path);
    }
    value += amount;
}

void ScanSubrecords(std::span<const std::byte> body,
                    PluginFileScanSummary& summary,
                    const std::filesystem::path& path) {
    std::size_t at = 0;
    std::optional<std::uint32_t> extendedSize;
    while (at < body.size()) {
        if (body.size() - at < kSubrecordHeaderSize) {
            BadPlugin("truncated subrecord header", path);
        }
        const auto size16 = ReadU16(body, at + 4);
        const bool isExtended = TagEquals(body, at, "XXXX");
        at += kSubrecordHeaderSize;

        if (isExtended) {
            if (extendedSize || size16 != 4 || body.size() - at < 4) {
                BadPlugin("malformed or repeated XXXX extended-size subrecord", path);
            }
            extendedSize = ReadU32(body, at);
            at += 4;
            AddCount(summary.extendedSubrecordCount, 1, path, "extended subrecord");
            continue;
        }

        const auto dataSize = extendedSize.value_or(size16);
        extendedSize.reset();
        if (dataSize > body.size() - at) {
            BadPlugin("subrecord data exceeds its record body", path);
        }
        at += dataSize;
        AddCount(summary.subrecordCount, 1, path, "subrecord");
    }
    if (extendedSize) BadPlugin("XXXX is not followed by a subrecord", path);
}

std::vector<std::byte> InflateRecord(std::span<const std::byte> data,
                                     const PluginScanOptions& options,
                                     const std::filesystem::path& path) {
    if (data.size() < sizeof(std::uint32_t)) {
        BadPlugin("compressed record is missing its inflated-size prefix", path);
    }
    const auto expectedSize = ReadU32(data, 0);
    if (expectedSize > options.maxInflatedRecordSize) {
        BadPlugin("inflated record exceeds configured safety limit", path);
    }
    const auto compressed = data.subspan(sizeof(std::uint32_t));
    if (compressed.size() > std::numeric_limits<uInt>::max()) {
        BadPlugin("compressed record exceeds zlib input limits", path);
    }
    const auto outputCapacity = std::max<std::size_t>(1, static_cast<std::size_t>(expectedSize));
    if (outputCapacity > std::numeric_limits<uInt>::max()) {
        BadPlugin("inflated record exceeds zlib output limits", path);
    }
    std::vector<std::byte> output(outputCapacity);

    z_stream stream{};
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<std::byte*>(compressed.data()));
    stream.avail_in = static_cast<uInt>(compressed.size());
    stream.next_out = reinterpret_cast<Bytef*>(output.data());
    stream.avail_out = static_cast<uInt>(output.size());
    const auto initResult = inflateInit(&stream);
    if (initResult != Z_OK) BadPlugin("zlib could not initialize record decompression", path);
    const auto inflateResult = inflate(&stream, Z_FINISH);
    const auto totalInput = stream.total_in;
    const auto totalOutput = stream.total_out;
    const auto endResult = inflateEnd(&stream);
    if (inflateResult != Z_STREAM_END || endResult != Z_OK ||
        totalInput != compressed.size() || totalOutput != expectedSize) {
        BadPlugin("compressed record failed exact zlib size/stream validation", path);
    }
    output.resize(expectedSize);
    return output;
}

void ScanRecordBody(std::span<const std::byte> bytes,
                    const PluginRecordHeader& header,
                    std::uint32_t flags,
                    const PluginScanOptions& options,
                    PluginFileScanSummary& summary,
                    const std::filesystem::path& path) {
    if ((flags & kCompressedRecordFlag) != 0) {
        auto inflated = InflateRecord(bytes, options, path);
        ScanSubrecords(inflated, summary, path);
        if (options.recordBodyObserver) {
            options.recordBodyObserver({header, inflated, true});
        }
        AddCount(summary.compressedRecordCount, 1, path, "compressed record");
    } else {
        ScanSubrecords(bytes, summary, path);
        if (options.recordBodyObserver) {
            options.recordBodyObserver({header, bytes, false});
        }
    }
}

void ScanElementRange(std::ifstream& input,
                      std::uint64_t endOffset,
                      std::uint32_t groupDepth,
                      const PluginScanOptions& options,
                      PluginFileScanSummary& summary,
                      const std::filesystem::path& path) {
    while (Position(input, path) < endOffset) {
        const auto elementStart = Position(input, path);
        if (endOffset - elementStart < kRecordHeaderSize) {
            BadPlugin("trailing bytes are shorter than a record/group header", path);
        }
        std::array<std::byte, kRecordHeaderSize> header{};
        ReadExact(input, header, path, "record/group header");
        const auto bytes = std::span<const std::byte>(header);

        if (TagEquals(bytes, 0, "GRUP")) {
            const auto groupSize = ReadU32(bytes, 4);
            if (groupSize < kRecordHeaderSize || groupSize > endOffset - elementStart) {
                BadPlugin("group size is invalid or exceeds its parent bounds", path);
            }
            if (groupDepth >= options.maxGroupDepth) {
                BadPlugin("group nesting exceeds configured safety limit", path);
            }
            const auto groupType = ReadU32(bytes, 12);
            if (summary.groupCount >= options.maxGroups) {
                BadPlugin("group count exceeds configured safety limit", path);
            }
            AddCount(summary.groupCount, 1, path, "group");
            AddCount(summary.groupTypes[groupType], 1, path, "group-type");
            const auto groupEnd = elementStart + groupSize;
            ScanElementRange(input, groupEnd, groupDepth + 1, options, summary, path);
            if (Position(input, path) != groupEnd) {
                BadPlugin("group parser did not end at the declared group boundary", path);
            }
            continue;
        }

        const auto dataSize = ReadU32(bytes, 4);
        const auto flags = ReadU32(bytes, 8);
        if (dataSize > options.maxRecordDataSize || dataSize > endOffset - elementStart - kRecordHeaderSize) {
            BadPlugin("record body exceeds configured or parent bounds", path);
        }
        auto body = ReadVector(input, dataSize, path, "record body");
        const auto type = ReadTag(bytes, 0);
        const PluginRecordHeader recordHeader{
            type, ReadU32(bytes, 12), flags, elementStart, ReadU16(bytes, 20)};
        ScanRecordBody(body, recordHeader, flags, options, summary, path);
        if (options.recordHeaderObserver) {
            options.recordHeaderObserver(recordHeader);
        }
        AddCount(summary.dataRecordCount, 1, path, "data record");
        if (summary.dataRecordCount > options.maxDataRecords) {
            BadPlugin("record count exceeds configured safety limit", path);
        }
        AddCount(summary.recordTypes[type], 1, path, "record-type");
    }
    if (Position(input, path) != endOffset) {
        BadPlugin("element range did not end on a record/group boundary", path);
    }
}

}  // namespace

PluginFileScanSummary ScanPluginFile(const std::filesystem::path& path,
                                     PluginFormat format,
                                     const PluginScanOptions& options) {
    std::error_code error;
    const auto fileSize = std::filesystem::file_size(path, error);
    if (error) throw MappingError("cannot stat plugin file '" + path.string() + "': " + error.message());
    if (fileSize > options.maxFileSize) {
        BadPlugin("file exceeds configured size limit", path);
    }
    if (fileSize < kRecordHeaderSize) BadPlugin("file is shorter than its TES4 record header", path);

    std::ifstream input(path, std::ios::binary);
    if (!input) throw MappingError("cannot open plugin file: " + path.string());

    std::array<std::byte, kRecordHeaderSize> firstHeader{};
    ReadExact(input, firstHeader, path, "TES4 record header");
    const auto firstHeaderBytes = std::span<const std::byte>(firstHeader);
    if (!TagEquals(firstHeaderBytes, 0, "TES4")) BadPlugin("first record is not TES4", path);
    const auto tes4BodySize = ReadU32(firstHeaderBytes, 4);
    if (tes4BodySize > options.maxRecordDataSize ||
        tes4BodySize > fileSize - kRecordHeaderSize) {
        BadPlugin("TES4 header record exceeds file or configured bounds", path);
    }
    if ((ReadU32(firstHeaderBytes, 8) & kCompressedRecordFlag) != 0) {
        BadPlugin("compressed TES4 header records are unsupported", path);
    }

    std::vector<std::byte> tes4Bytes(kRecordHeaderSize + static_cast<std::size_t>(tes4BodySize));
    std::copy(firstHeader.begin(), firstHeader.end(), tes4Bytes.begin());
    ReadExact(input,
              std::span<std::byte>(tes4Bytes).subspan(kRecordHeaderSize),
              path,
              "TES4 header body");

    PluginFileScanSummary summary;
    summary.fileSize = fileSize;
    summary.header = ParsePluginHeader(tes4Bytes, path.filename().string(), format);
    const auto tes4Body = std::span<const std::byte>(tes4Bytes).subspan(kRecordHeaderSize);
    ScanSubrecords(tes4Body, summary, path);
    if (options.recordBodyObserver) {
        options.recordBodyObserver({
            {"TES4", ReadU32(firstHeaderBytes, 12), ReadU32(firstHeaderBytes, 8), 0,
             ReadU16(firstHeaderBytes, 20)},
            tes4Body,
            false});
    }
    ScanElementRange(input, fileSize, 0, options, summary, path);
    summary.observedRecordAndGroupCount = summary.dataRecordCount + summary.groupCount;
    if (summary.observedRecordAndGroupCount > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        BadPlugin("record/group count exceeds comparison limits", path);
    }
    summary.headerCountDelta = static_cast<std::int64_t>(summary.header.recordCount) -
        static_cast<std::int64_t>(summary.observedRecordAndGroupCount);
    summary.headerCountMatchesStructure = summary.headerCountDelta == 0;
    return summary;
}

}  // namespace vaddr
