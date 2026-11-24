#include "PluginFormInventory.hpp"

#include "PluginFileScanner.hpp"
#include "PluginHeader.hpp"

#include <algorithm>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <unordered_set>

namespace vaddr {
namespace {

std::filesystem::path PluginPath(const std::filesystem::path& dataDirectory,
                                 std::string_view filename) {
    std::u8string utf8;
    utf8.reserve(filename.size());
    for (const unsigned char character : filename) {
        utf8.push_back(static_cast<char8_t>(character));
    }
    return dataDirectory / std::filesystem::path(utf8);
}

std::string Hex(std::uint32_t value) {
    std::ostringstream output;
    output << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
    return output.str();
}

}  // namespace

PluginFormInventory ScanPluginFormInventory(const PluginGraph& graph,
                                            const std::filesystem::path& dataDirectory,
                                            std::string_view pluginFilename) {
    std::string canonical;
    try {
        canonical = CanonicalPluginName(pluginFilename);
    } catch (const MappingError&) {
        throw MappingError("invalid plugin filename for form inventory");
    }

    const auto found = std::find_if(graph.LoadOrder().begin(), graph.LoadOrder().end(),
        [&canonical](const PluginNode& plugin) { return plugin.filename == canonical; });
    if (found == graph.LoadOrder().end()) {
        throw MappingError("form inventory plugin is absent from the validated load order: " + canonical);
    }

    PluginFormInventory inventory;
    inventory.pluginFilename = canonical;
    PluginScanOptions options;
    options.recordHeaderObserver = [&](const PluginRecordHeader& record) {
        ++inventory.recordCount;
        const auto logical = graph.Resolve({canonical, record.formID});
        if (!logical) {
            throw MappingError("unresolved record-header FormID " + Hex(record.formID) +
                               " in " + canonical + " at file offset " +
                               std::to_string(record.fileOffset));
        }
        if (logical->plugin == canonical) {
            inventory.ownedForms.push_back(*logical);
            ++inventory.ownedDefinitionCount;
        } else {
            inventory.overriddenForms.push_back(*logical);
            ++inventory.overrideCount;
        }
    };

    const auto scan = ScanPluginFile(PluginPath(dataDirectory, canonical), found->format, options);
    if (inventory.recordCount != scan.dataRecordCount) {
        throw MappingError("record inventory observer count differs from structural scan for " + canonical);
    }
    if (!scan.headerCountMatchesStructure) {
        throw MappingError("plugin HEDR record count does not match observed record/group structure: " + canonical);
    }

    std::sort(inventory.ownedForms.begin(), inventory.ownedForms.end());
    std::sort(inventory.overriddenForms.begin(), inventory.overriddenForms.end());
    const auto duplicate = std::adjacent_find(inventory.ownedForms.begin(), inventory.ownedForms.end());
    if (duplicate != inventory.ownedForms.end()) {
        throw MappingError("duplicate self-owned FormID in plugin " + canonical + ": " +
                           Hex(duplicate->localID));
    }
    if (inventory.ownedForms.size() != inventory.ownedDefinitionCount) {
        throw MappingError("owned FormID count changed during inventory for " + canonical);
    }
    if (inventory.overriddenForms.size() != inventory.overrideCount) {
        throw MappingError("override FormID count changed during inventory for " + canonical);
    }
    return inventory;
}

PluginGraph ExtendGraphWithLogicalPlugins(const PluginGraph& activeGraph,
                                          const std::filesystem::path& dataDirectory,
                                          const std::vector<std::string>& logicalPluginFilenames) {
    std::vector<PluginNode> nodes = activeGraph.LoadOrder();
    std::unordered_set<std::string> known;
    known.reserve(nodes.size() + logicalPluginFilenames.size());
    for (const auto& node : nodes) known.insert(node.filename);

    std::unordered_set<std::string> selected;
    selected.reserve(logicalPluginFilenames.size());
    std::vector<PluginNode> pending;
    pending.reserve(logicalPluginFilenames.size());
    for (const auto& rawName : logicalPluginFilenames) {
        std::string filename;
        try {
            filename = CanonicalPluginName(rawName);
        } catch (const MappingError&) {
            throw MappingError("invalid selected logical plugin filename");
        }
        if (!selected.insert(filename).second) {
            throw MappingError("duplicate selected logical plugin: " + filename);
        }
        const auto header = ReadPluginHeader(PluginPath(dataDirectory, filename), PluginFormat::automatic);
        if (header.plugin.format != PluginFormat::full) {
            throw MappingError("mapping plan currently accepts full plugins only: " + filename);
        }
        if (known.contains(filename)) {
            const auto active = std::find_if(nodes.begin(), nodes.end(), [&filename](const PluginNode& node) {
                return node.filename == filename;
            });
            if (active == nodes.end() || active->format != header.plugin.format ||
                active->masters != header.plugin.masters ||
                active->headerVersion != header.plugin.headerVersion) {
                throw MappingError("selected active plugin metadata differs from its file header: " + filename);
            }
            continue;
        }
        pending.push_back(header.plugin);
    }

    while (!pending.empty()) {
        bool added = false;
        for (auto current = pending.begin(); current != pending.end();) {
            const bool mastersAvailable = std::all_of(current->masters.begin(), current->masters.end(),
                [&known](const std::string& master) { return known.contains(master); });
            if (!mastersAvailable) {
                ++current;
                continue;
            }
            known.insert(current->filename);
            nodes.push_back(std::move(*current));
            current = pending.erase(current);
            added = true;
        }
        if (!added) {
            const auto& blocked = pending.front();
            const auto missing = std::find_if(blocked.masters.begin(), blocked.masters.end(),
                [&known](const std::string& master) { return !known.contains(master); });
            if (missing != blocked.masters.end()) {
                throw MappingError("logical plugin master is not in the active graph or selected logical set: " +
                                   *missing + " (required by " + blocked.filename + ")");
            }
            throw MappingError("selected logical plugins contain a master cycle");
        }
    }
    return PluginGraph::Build(std::move(nodes));
}

MappingTable BuildPluginMappingTable(const PluginGraph& graph,
                                     const std::filesystem::path& dataDirectory,
                                     std::vector<std::string> logicalPluginFilenames,
                                     std::vector<CarrierRange> carrierRanges,
                                     std::vector<MappingEntry> previousEntries) {
    if (logicalPluginFilenames.empty()) {
        throw MappingError("mapping plan requires at least one selected logical plugin");
    }

    const auto analysisGraph = ExtendGraphWithLogicalPlugins(
        graph, dataDirectory, logicalPluginFilenames);

    std::unordered_set<std::string> selected;
    selected.reserve(logicalPluginFilenames.size());
    std::vector<LogicalFormID> logicalForms;
    for (const auto& filename : logicalPluginFilenames) {
        std::string canonical;
        try {
            canonical = CanonicalPluginName(filename);
        } catch (const MappingError&) {
            throw MappingError("invalid selected logical plugin filename");
        }
        if (!selected.insert(canonical).second) {
            throw MappingError("duplicate selected logical plugin: " + canonical);
        }

        const auto plugin = std::find_if(analysisGraph.LoadOrder().begin(), analysisGraph.LoadOrder().end(),
            [&canonical](const PluginNode& node) { return node.filename == canonical; });
        if (plugin == analysisGraph.LoadOrder().end()) {
            throw MappingError("selected logical plugin is absent from the analysis graph: " + canonical);
        }
        if (plugin->format != PluginFormat::full) {
            throw MappingError("mapping plan currently accepts full plugins only: " + canonical);
        }

        std::size_t fullIndex = 0;
        bool foundFullIndex = false;
        for (const auto& node : analysisGraph.LoadOrder()) {
            if (node.format != PluginFormat::full) continue;
            if (node.filename == canonical) {
                foundFullIndex = true;
                break;
            }
            ++fullIndex;
        }
        if (!foundFullIndex || fullIndex == 0) {
            throw MappingError("the base-game full plugin cannot be virtualized: " + canonical);
        }

        auto inventory = ScanPluginFormInventory(analysisGraph, dataDirectory, canonical);
        logicalForms.insert(logicalForms.end(),
                            std::make_move_iterator(inventory.ownedForms.begin()),
                            std::make_move_iterator(inventory.ownedForms.end()));
    }
    return MappingTable::BuildPreserving(std::move(logicalForms), std::move(carrierRanges),
                                         std::move(previousEntries));
}

MappingTable BuildLightToFullCarrierMappingTable(
    const PluginGraph& graph,
    const std::filesystem::path& dataDirectory,
    std::vector<std::string> lightPluginFilenames,
    CarrierRange carrierRange,
    std::vector<MappingEntry> previousEntries) {
    if (lightPluginFilenames.empty())
        throw MappingError("light-to-full mapping requires at least one selected light plugin");

    std::unordered_set<std::string> selected;
    selected.reserve(lightPluginFilenames.size());
    std::vector<LogicalFormID> logicalForms;
    for (const auto& rawFilename : lightPluginFilenames) {
        std::string canonical;
        try {
            canonical = CanonicalPluginName(rawFilename);
        } catch (const MappingError&) {
            throw MappingError("invalid selected light plugin filename");
        }
        if (!selected.insert(canonical).second)
            throw MappingError("light-to-full mapping contains a duplicate plugin: " + canonical);

        const auto plugin = std::find_if(graph.LoadOrder().begin(), graph.LoadOrder().end(),
            [&canonical](const PluginNode& node) { return node.filename == canonical; });
        if (plugin == graph.LoadOrder().end())
            throw MappingError("selected light plugin is absent from the active graph: " + canonical);
        if (plugin->format != PluginFormat::light)
            throw MappingError("light-to-full mapping accepts light plugin sources only: " + canonical);
        if (plugin == graph.LoadOrder().begin())
            throw MappingError("the base-game plugin cannot be selected for light-to-full conversion");

        const auto inventory = ScanPluginFormInventory(graph, dataDirectory, canonical);
        for (const auto& form : inventory.ownedForms) {
            if (form.localID > 0x0FFFU)
                throw MappingError("light plugin owns a FormID outside its 12-bit object-ID range: " + canonical);
            logicalForms.push_back(form);
        }
    }

    for (const auto& entry : previousEntries) {
        const auto canonical = CanonicalPluginName(entry.logical.plugin);
        if (!selected.contains(canonical))
            throw MappingError("persisted light-to-full mapping contains a plugin outside the selected group");
    }

    if (logicalForms.empty()) {
        if (!previousEntries.empty())
            throw MappingError("override-only light group cannot retain mappings for removed owned forms");
        return MappingTable{};
    }

    return MappingTable::BuildPreserving(
        std::move(logicalForms), {carrierRange}, std::move(previousEntries));
}

MappingTable BuildLightToFullCarrierMappingTable(
    const PluginGraph& graph,
    const std::filesystem::path& dataDirectory,
    std::vector<LightToFullCarrierAssignment> assignments,
    std::vector<MappingEntry> previousEntries) {
    if (assignments.empty())
        throw MappingError("light-to-full mapping requires at least one carrier assignment");
    std::vector<MappingTable> cohortMappings;
    std::unordered_set<std::string> selected;
    for (auto& assignment : assignments) {
        if (assignment.lightPluginFilenames.empty())
            throw MappingError("light-to-full carrier assignment cannot be empty");
        std::vector<LogicalFormID> logicalForms;
        std::vector<MappingEntry> cohortPreviousEntries;
        for (const auto& rawFilename : assignment.lightPluginFilenames) {
            std::string canonical;
            try { canonical = CanonicalPluginName(rawFilename); }
            catch (const MappingError&) { throw MappingError("invalid selected light plugin filename"); }
            if (!selected.insert(canonical).second)
                throw MappingError("light-to-full mapping assigns a plugin more than once: " + canonical);
            const auto plugin = std::find_if(graph.LoadOrder().begin(), graph.LoadOrder().end(),
                [&canonical](const PluginNode& node) { return node.filename == canonical; });
            if (plugin == graph.LoadOrder().end())
                throw MappingError("selected light plugin is absent from the active graph: " + canonical);
            if (plugin->format != PluginFormat::light)
                throw MappingError("light-to-full mapping accepts light plugin sources only: " + canonical);
            if (plugin == graph.LoadOrder().begin())
                throw MappingError("the base-game plugin cannot be selected for light-to-full conversion");
            const auto inventory = ScanPluginFormInventory(graph, dataDirectory, canonical);
            for (const auto& form : inventory.ownedForms) {
                if (form.localID > 0x0FFFU)
                    throw MappingError("light plugin owns a FormID outside its 12-bit object-ID range: " + canonical);
                logicalForms.push_back(form);
            }
        }
        for (const auto& entry : previousEntries) {
            if (std::any_of(assignment.lightPluginFilenames.begin(), assignment.lightPluginFilenames.end(),
                [&](const std::string& name) { return CanonicalPluginName(name) == CanonicalPluginName(entry.logical.plugin); }))
                cohortPreviousEntries.push_back(entry);
        }
        if (!logicalForms.empty())
            cohortMappings.push_back(MappingTable::BuildPreserving(
                std::move(logicalForms), {assignment.carrierRange}, std::move(cohortPreviousEntries)));
        else if (!cohortPreviousEntries.empty())
            throw MappingError("override-only light groups cannot retain mappings for removed owned forms");
    }
    for (const auto& entry : previousEntries) {
        if (!selected.contains(CanonicalPluginName(entry.logical.plugin)))
            throw MappingError("persisted light-to-full mapping contains a plugin outside the assigned cohorts");
    }
    if (cohortMappings.empty()) {
        if (!previousEntries.empty())
            throw MappingError("override-only light groups cannot retain mappings for removed owned forms");
        return MappingTable{};
    }
    return MappingTable::MergeAssignments(std::move(cohortMappings));
}

}  // namespace vaddr
