#pragma once

#include "PluginHeader.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <span>
#include <string>

namespace vaddr {

struct PluginRecordHeader {
    std::string signature;
    std::uint32_t formID{};
    std::uint32_t flags{};
    std::uint64_t fileOffset{};
    std::uint16_t formVersion{};
};

struct PluginRecordBody {
    PluginRecordHeader header;
    // A validated, uncompressed subrecord stream, valid only during the
    // callback. The offsets in this view are not raw file offsets when the
    // source record was compressed.
    std::span<const std::byte> data;
    bool wasCompressed{};
};

struct PluginScanOptions {
    std::uint64_t maxFileSize{16ULL * 1024 * 1024 * 1024};
    std::uint64_t maxRecordDataSize{512ULL * 1024 * 1024};
    std::uint64_t maxInflatedRecordSize{512ULL * 1024 * 1024};
    // Bounds aggregate parser work and the groupTypes map on malformed files.
    std::uint64_t maxGroups{1'000'000};
    std::uint32_t maxGroupDepth{128};
    std::uint64_t maxDataRecords{100'000'000};
    // Optional read-only observer for validated record headers. This exposes
    // only each record's own FormID; FormIDs embedded in subrecords remain opaque.
    std::function<void(const PluginRecordHeader&)> recordHeaderObserver;
    // Optional read-only observer for validated and inflated record bodies.
    std::function<void(const PluginRecordBody&)> recordBodyObserver;
};

struct PluginFileScanSummary {
    ParsedPluginHeader header;
    std::uint64_t fileSize{};
    std::uint64_t dataRecordCount{};
    std::uint64_t groupCount{};
    std::uint64_t compressedRecordCount{};
    std::uint64_t subrecordCount{};
    std::uint64_t extendedSubrecordCount{};
    std::uint64_t observedRecordAndGroupCount{};
    std::int64_t headerCountDelta{};
    bool headerCountMatchesStructure{};
    std::map<std::string, std::uint64_t> recordTypes;
    std::map<std::uint32_t, std::uint64_t> groupTypes;
};

// Validates the complete record/group and subrecord framing of a plugin without
// modifying it. Compressed record bodies are inflated and checked with zlib.
// FormID-bearing fields inside subrecords remain opaque; this is not a relocator.
[[nodiscard]] PluginFileScanSummary ScanPluginFile(
    const std::filesystem::path& path,
    PluginFormat format = PluginFormat::automatic,
    const PluginScanOptions& options = {});

}  // namespace vaddr
