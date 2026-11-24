#include "PluginHeader.hpp"

#include <array>
#include <bit>
#include <fstream>
#include <limits>
#include <string_view>
#include <vector>

namespace vaddr {
namespace {

constexpr std::size_t kRecordHeaderSize = 24;

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
    for (std::size_t i = 0; i < 4; ++i) {
        if (std::to_integer<char>(bytes[at + i]) != tag[i]) return false;
    }
    return true;
}

[[noreturn]] void BadHeader(std::string_view reason) {
    throw MappingError("invalid TES4 plugin header: " + std::string(reason));
}

}  // namespace

ParsedPluginHeader ParsePluginHeader(
    std::span<const std::byte> bytes, std::string filename, PluginFormat format) {
    if (bytes.size() < kRecordHeaderSize) BadHeader("truncated record header");
    if (!TagEquals(bytes, 0, "TES4")) BadHeader("first record is not TES4");
    const auto recordSize = ReadU32(bytes, 4);
    if (recordSize > bytes.size() - kRecordHeaderSize) BadHeader("TES4 record exceeds input bounds");
    if ((ReadU32(bytes, 8) & 0x0004'0000U) != 0) {
        BadHeader("compressed TES4 headers are not supported by this metadata reader");
    }
    const auto flags = ReadU32(bytes, 8);
    constexpr std::uint32_t kLightFlag = 0x0000'0200U;
    const auto extension = CanonicalPluginName(filename).substr(
        CanonicalPluginName(filename).find_last_of('.'));
    const auto inferredFormat = (flags & kLightFlag) != 0 || extension == ".esl"
        ? PluginFormat::light : PluginFormat::full;
    if (format != PluginFormat::automatic && format != inferredFormat) {
        BadHeader("declared plugin format does not match extension or ESL header flag");
    }

    ParsedPluginHeader result;
    result.plugin.filename = CanonicalPluginName(filename);
    result.plugin.format = inferredFormat;
    result.plugin.isMaster = (flags & 0x0000'0001U) != 0;
    result.pluginFlags = flags;
    const auto end = kRecordHeaderSize + recordSize;
    auto at = kRecordHeaderSize;
    std::optional<std::uint32_t> extendedSize;
    bool sawHedr = false;
    while (at < end) {
        if (end - at < 6) BadHeader("truncated subrecord header");
        const auto size16 = ReadU16(bytes, at + 4);
        const bool isExtended = TagEquals(bytes, at, "XXXX");
        at += 6;
        std::uint32_t size = size16;
        if (isExtended) {
            if (size16 != 4 || end - at < 4) BadHeader("malformed XXXX subrecord");
            extendedSize = ReadU32(bytes, at);
            at += 4;
            continue;
        }
        if (extendedSize) {
            size = *extendedSize;
            extendedSize.reset();
        }
        if (size > end - at) BadHeader("subrecord exceeds TES4 record bounds");

        if (TagEquals(bytes, at - 6, "HEDR")) {
            if (size != 12 || sawHedr) BadHeader("HEDR must occur once and contain 12 bytes");
            result.headerVersion = std::bit_cast<float>(ReadU32(bytes, at));
            result.plugin.headerVersion = result.headerVersion;
            result.recordCount = ReadU32(bytes, at + 4);
            result.nextObjectID = ReadU32(bytes, at + 8);
            sawHedr = true;
        } else if (TagEquals(bytes, at - 6, "MAST")) {
            if (size < 2) BadHeader("empty MAST subrecord");
            std::string master;
            master.reserve(size - 1);
            bool terminated = false;
            for (std::size_t i = 0; i < size; ++i) {
                const auto ch = std::to_integer<unsigned char>(bytes[at + i]);
                if (ch == 0) {
                    if (i != size - 1) BadHeader("MAST has trailing data after terminator");
                    terminated = true;
                    break;
                }
                master.push_back(static_cast<char>(ch));
            }
            if (!terminated) BadHeader("MAST is not NUL terminated");
            result.plugin.masters.push_back(CanonicalPluginName(master));
        }
        at += size;
    }
    if (extendedSize) BadHeader("XXXX is not followed by a subrecord");
    if (!sawHedr) BadHeader("required HEDR subrecord is missing");
    return result;
}

ParsedPluginHeader ReadPluginHeader(const std::filesystem::path& path, PluginFormat format) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) throw MappingError("cannot open plugin: " + path.string());
    const auto length = input.tellg();
    if (length < static_cast<std::streamoff>(kRecordHeaderSize)) {
        throw MappingError("plugin is truncated before its TES4 record header: " + path.string());
    }
    std::array<std::byte, kRecordHeaderSize> recordHeader{};
    input.seekg(0);
    if (!input.read(reinterpret_cast<char*>(recordHeader.data()), static_cast<std::streamsize>(recordHeader.size()))) {
        throw MappingError("failed reading plugin TES4 header: " + path.string());
    }
    if (!TagEquals(recordHeader, 0, "TES4")) BadHeader("first record is not TES4");
    const auto bodySize = ReadU32(recordHeader, 4);
    constexpr std::uint32_t kMaximumHeaderSize = 64 * 1024 * 1024;
    if (bodySize > kMaximumHeaderSize ||
        static_cast<std::uint64_t>(bodySize) + kRecordHeaderSize > static_cast<std::uint64_t>(length)) {
        BadHeader("TES4 header is too large or exceeds plugin file bounds");
    }
    std::vector<std::byte> bytes(kRecordHeaderSize + bodySize);
    std::copy(recordHeader.begin(), recordHeader.end(), bytes.begin());
    if (bodySize && !input.read(reinterpret_cast<char*>(bytes.data() + kRecordHeaderSize), bodySize)) {
        throw MappingError("failed reading TES4 header body: " + path.string());
    }
    return ParsePluginHeader(bytes, path.filename().string(), format);
}

}  // namespace vaddr
