#pragma once

#include "LogicalFormID.hpp"
#include "PluginGraph.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace vaddr {

struct PluginFormInventory {
    std::string pluginFilename;
    std::uint64_t recordCount{};
    std::uint64_t ownedDefinitionCount{};
    std::uint64_t overrideCount{};
    std::vector<LogicalFormID> ownedForms;
    std::vector<LogicalFormID> overriddenForms;
};

// Assigns each selected light plugin's owned forms to one reserved full
// carrier namespace. A dependency-closed cohort may share an assignment;
// distinct cohorts may use distinct slots/ranges in one combined map.
struct LightToFullCarrierAssignment {
    std::vector<std::string> lightPluginFilenames;
    CarrierRange carrierRange;
};

// Enumerates self-owned and overridden logical record FormIDs in one
// already-indexed plugin. Overrides do not create new logical identities.
// The scan fails closed on unresolved record headers, duplicate owned IDs,
// or a HEDR count mismatch; this is a planning input, not a plugin relocator.
[[nodiscard]] PluginFormInventory ScanPluginFormInventory(
    const PluginGraph& graph,
    const std::filesystem::path& dataDirectory,
    std::string_view pluginFilename);

// Adds selected, installed full plugins to a copy of the active graph for
// file-relative identity analysis. The active graph itself remains unchanged.
[[nodiscard]] PluginGraph ExtendGraphWithLogicalPlugins(
    const PluginGraph& activeGraph,
    const std::filesystem::path& dataDirectory,
    const std::vector<std::string>& logicalPluginFilenames);

// Builds a deterministic mapping plan from selected, enabled full plugins.
// Carrier ranges must already be reserved by the caller; this function does
// not rewrite plugins, validate physical carrier files, or resolve overrides.
[[nodiscard]] MappingTable BuildPluginMappingTable(
    const PluginGraph& graph,
    const std::filesystem::path& dataDirectory,
    std::vector<std::string> logicalPluginFilenames,
    std::vector<CarrierRange> carrierRanges,
    std::vector<MappingEntry> previousEntries = {});

// Builds a deterministic mapping for light plugins being merged into one
// ordinary full-plugin carrier. The caller chooses a reserved full-plugin
// slot/range; this does not discover a dependency-closed group, rewrite
// dependents, or construct a generated profile. Override-only sources are
// allowed as long as the selected group has at least one owned form overall.
[[nodiscard]] MappingTable BuildLightToFullCarrierMappingTable(
    const PluginGraph& graph,
    const std::filesystem::path& dataDirectory,
    std::vector<std::string> lightPluginFilenames,
    CarrierRange carrierRange,
    std::vector<MappingEntry> previousEntries = {});

[[nodiscard]] MappingTable BuildLightToFullCarrierMappingTable(
    const PluginGraph& graph,
    const std::filesystem::path& dataDirectory,
    std::vector<LightToFullCarrierAssignment> assignments,
    std::vector<MappingEntry> previousEntries = {});

}  // namespace vaddr
