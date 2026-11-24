#pragma once

#include "PluginGraph.hpp"
#include "Legacy163PluginFlags.hpp"

#include <cstddef>
#include <filesystem>
#include <span>
#include <vector>

namespace vaddr {

struct ParsedPluginHeader {
    PluginNode plugin;
    std::uint32_t pluginFlags{};
    float headerVersion{};
    std::uint32_t recordCount{};
    std::uint32_t nextObjectID{};
};

// Parses only the uncompressed TES4 file header and its HEDR/MAST metadata.
// It does not parse data records and is not a plugin validator/compiler.
[[nodiscard]] ParsedPluginHeader ParsePluginHeader(
    std::span<const std::byte> bytes, std::string filename, PluginFormat format);
[[nodiscard]] ParsedPluginHeader ReadPluginHeader(
    const std::filesystem::path& path, PluginFormat format);
// Returns the validated TES4 record body (including MAST/ONAM/TNAM subrecords)
// for schema-level header auditing. This reads only the first, uncompressed record.
[[nodiscard]] std::vector<std::byte> ReadPluginHeaderBody(
    const std::filesystem::path& path);

}  // namespace vaddr
