#include "PluginGraph.hpp"

#include <algorithm>
#include <unordered_set>

namespace vaddr {

namespace {

std::unordered_set<std::string> NormalizeSelectedRoots(
    const std::vector<std::string>& selectedPlugins,
    const std::unordered_map<std::string, std::size_t>& indices) {
    if (selectedPlugins.empty()) {
        throw MappingError("dependent discovery requires at least one selected logical plugin");
    }

    std::unordered_set<std::string> roots;
    roots.reserve(selectedPlugins.size());
    for (const auto& rawName : selectedPlugins) {
        const auto name = CanonicalPluginName(rawName);
        if (!indices.contains(name)) {
            throw MappingError("selected logical plugin is not in the enabled graph: " + name);
        }
        if (!roots.insert(name).second) {
            throw MappingError("duplicate selected logical plugin: " + name);
        }
    }
    return roots;
}

}  // namespace

std::optional<LogicalFormID> ResolveFullFileRelativeFormID(
    const std::string_view sourcePlugin,
    const std::span<const std::string_view> orderedMasters,
    const std::optional<float> sourceHeaderVersion,
    const std::uint32_t rawFormID) {
    std::string canonicalSource;
    try {
        canonicalSource = CanonicalPluginName(sourcePlugin);
    } catch (const MappingError&) {
        return std::nullopt;
    }

    const auto ownerByte = static_cast<std::uint8_t>(rawFormID >> 24);
    const auto objectID = rawFormID & 0x00FF'FFFFU;
    // Only the all-zero FormID is null. A nonzero file-relative FormID may
    // legitimately name local object 0; keep that identity intact so the
    // caller can map it or reject it if the destination encoding cannot carry it.
    if (ownerByte >= 0xFE || rawFormID == 0) {
        return std::nullopt;
    }

    constexpr std::string_view kBaseGamePlugin = "fallout4.esm";
    if (rawFormID < 0x800) {
        return LogicalFormID{std::string(kBaseGamePlugin), objectID};
    }

    if (objectID < 0x800) {
        if (!sourceHeaderVersion.has_value() && !orderedMasters.empty()) {
            return std::nullopt;
        }
        const bool allowsHardcodedRange = sourceHeaderVersion.has_value() &&
            *sourceHeaderVersion >= 1.0F && !orderedMasters.empty();
        if (!allowsHardcodedRange) {
            return LogicalFormID{std::string(kBaseGamePlugin), objectID};
        }
    }

    const auto ownerIndex = static_cast<std::size_t>(ownerByte);
    std::string owner;
    if (ownerIndex < orderedMasters.size()) {
        try {
            owner = CanonicalPluginName(orderedMasters[ownerIndex]);
        } catch (const MappingError&) {
            return std::nullopt;
        }
    } else {
        owner = std::move(canonicalSource);
    }
    return LogicalFormID{std::move(owner), objectID};
}

std::optional<LogicalFormID> ResolveFileRelativeFormID(
    const std::string_view sourcePlugin,
    const PluginFormat sourceFormat,
    const std::span<const std::string_view> orderedMasters,
    const std::span<const PluginFormat> orderedMasterFormats,
    const std::optional<float> sourceHeaderVersion,
    const std::uint32_t rawFormID) {
    if ((sourceFormat != PluginFormat::full && sourceFormat != PluginFormat::light) ||
        orderedMasters.size() != orderedMasterFormats.size() || rawFormID == 0) {
        return std::nullopt;
    }

    for (const auto format : orderedMasterFormats) {
        if (format != PluginFormat::full && format != PluginFormat::light)
            return std::nullopt;
    }

    std::string canonicalSource;
    try {
        canonicalSource = CanonicalPluginName(sourcePlugin);
    } catch (const MappingError&) {
        return std::nullopt;
    }

    constexpr std::string_view kBaseGamePlugin = "fallout4.esm";
    const auto ownerByte = static_cast<std::uint8_t>(rawFormID >> 24);

    if (rawFormID < 0x800U) {
        return LogicalFormID{std::string(kBaseGamePlugin), rawFormID};
    }
    if (ownerByte == 0xFFU)
        return std::nullopt;

    if (ownerByte == 0xFEU) {
        // xEdit parses FE as FullSlot=FE plus separate light-slot/object bits.
        // In file-relative conversion that FullSlot is beyond the complete
        // MAST count and falls back to the source file; it is not an external
        // light-master ordinal. Keep only the object's low 12 bits.
        const auto objectID = rawFormID & 0x0FFFU;
        return LogicalFormID{std::move(canonicalSource), objectID};
    }

    const auto objectID = rawFormID & 0x00FF'FFFFU;
    if (objectID < 0x800U) {
        if (!sourceHeaderVersion.has_value() && !orderedMasters.empty())
            return std::nullopt;
        const bool allowsHardcodedRange = sourceHeaderVersion.has_value() &&
            *sourceHeaderVersion >= 1.0F && !orderedMasters.empty();
        if (!allowsHardcodedRange) {
            return LogicalFormID{std::string(kBaseGamePlugin), objectID};
        }
        // Keep xEdit's hardcoded/low-object-ID path separate from ordinary
        // record references. Its typed full/light slot treatment is a distinct
        // rule and is intentionally unchanged by the complete-MAST correction.
        std::size_t fullIndex = 0;
        for (std::size_t index = 0; index < orderedMasters.size(); ++index) {
            if (orderedMasterFormats[index] != PluginFormat::full)
                continue;
            if (fullIndex == ownerByte) {
                try {
                    return LogicalFormID{CanonicalPluginName(orderedMasters[index]), objectID};
                } catch (const MappingError&) {
                    return std::nullopt;
                }
            }
            ++fullIndex;
        }
        if (ownerByte >= fullIndex)
            return LogicalFormID{std::move(canonicalSource), objectID};
        return std::nullopt;
    }

    const auto masterIndex = static_cast<std::size_t>(ownerByte);
    if (masterIndex < orderedMasters.size()) {
        try {
            return LogicalFormID{CanonicalPluginName(orderedMasters[masterIndex]), objectID};
        } catch (const MappingError&) {
            return std::nullopt;
        }
    } else {
        return LogicalFormID{std::move(canonicalSource), objectID};
    }
}

std::uint32_t EncodeFileRelativeFormID(
    const std::string_view sourcePlugin,
    const PluginFormat sourceFormat,
    const std::span<const std::string> orderedMasters,
    const LogicalFormID& target,
    const PluginFormat targetFormat) {
    if ((sourceFormat != PluginFormat::full && sourceFormat != PluginFormat::light) ||
        (targetFormat != PluginFormat::full && targetFormat != PluginFormat::light))
        throw MappingError("file-relative FormID encoding requires full or light plugin formats");

    std::string source;
    std::string owner;
    try {
        source = CanonicalPluginName(sourcePlugin);
        owner = CanonicalPluginName(target.plugin);
    } catch (const MappingError&) {
        throw MappingError("file-relative FormID encoding received an invalid plugin identity");
    }

    if (target.localID > 0x00FF'FFFFU)
        throw MappingError("file-relative target object ID exceeds its plugin format's range");
    if (targetFormat == PluginFormat::light && target.localID > 0x0FFFU)
        throw MappingError("file-relative target object ID exceeds the 12-bit light plugin range");

    std::size_t ownerIndex = orderedMasters.size();
    if (owner != source) {
        const auto master = std::find_if(orderedMasters.begin(), orderedMasters.end(),
            [&owner](const std::string& candidate) {
                try { return CanonicalPluginName(candidate) == owner; }
                catch (const MappingError&) { return false; }
            });
        if (master == orderedMasters.end())
            throw MappingError("file-relative target is absent from the complete ordered MAST list: " + owner);
        ownerIndex = static_cast<std::size_t>(master - orderedMasters.begin());
    }
    if (ownerIndex >= 0xFEU)
        throw MappingError("file-relative owner ordinal is outside the representable plugin range");

    const auto raw = (static_cast<std::uint32_t>(ownerIndex) << 24) | target.localID;
    if (raw == 0)
        throw MappingError("file-relative target collides with the null FormID");
    return raw;
}

PluginGraph PluginGraph::Build(std::vector<PluginNode> plugins) {
    if (plugins.empty()) {
        throw MappingError("plugin graph cannot be empty");
    }

    PluginGraph graph;
    graph.plugins_.reserve(plugins.size());
    graph.indices_.reserve(plugins.size());
    for (auto& plugin : plugins) {
        plugin.filename = CanonicalPluginName(plugin.filename);
        if (!graph.indices_.emplace(plugin.filename, graph.plugins_.size()).second) {
            throw MappingError("duplicate plugin in enabled load order: " + plugin.filename);
        }
        graph.plugins_.push_back(std::move(plugin));
    }

    graph.masterFormats_.reserve(graph.plugins_.size());
    for (std::size_t i = 0; i < graph.plugins_.size(); ++i) {
        auto& plugin = graph.plugins_[i];
        std::unordered_set<std::string> seenMasters;
        std::vector<PluginFormat> formats;
        formats.reserve(plugin.masters.size());
        for (auto& master : plugin.masters) {
            master = CanonicalPluginName(master);
            if (master == plugin.filename || !seenMasters.insert(master).second) {
                throw MappingError("self or duplicate master in " + plugin.filename);
            }
            const auto found = graph.indices_.find(master);
            if (found == graph.indices_.end()) {
                throw MappingError("enabled plugin has a missing master: " + master +
                                   " (required by " + plugin.filename + ")");
            }
            if (found->second >= i) {
                throw MappingError("master must precede dependent plugin: " + master +
                                   " (required by " + plugin.filename + ")");
            }
            formats.push_back(graph.plugins_[found->second].format);
        }
        graph.masterFormats_.push_back(std::move(formats));
    }
    return graph;
}

std::optional<LogicalFormID> PluginGraph::Resolve(const FileRelativeFormID& id) const {
    std::string sourceName;
    try {
        sourceName = CanonicalPluginName(id.sourcePlugin);
    } catch (const MappingError&) {
        return std::nullopt;
    }
    const auto sourceIt = indices_.find(sourceName);
    if (sourceIt == indices_.end()) {
        return std::nullopt;
    }
    const auto& source = plugins_[sourceIt->second];
    if (source.format != PluginFormat::full && source.format != PluginFormat::light) {
        return std::nullopt;
    }

    std::vector<std::string_view> orderedMasters;
    orderedMasters.reserve(source.masters.size());
    for (const auto& master : source.masters) {
        orderedMasters.emplace_back(master);
    }
    auto logical = ResolveFileRelativeFormID(
        source.filename, source.format, orderedMasters,
        masterFormats_[sourceIt->second], source.headerVersion, id.raw);
    if (!logical) {
        return std::nullopt;
    }
    const auto ownerIt = indices_.find(logical->plugin);
    if (ownerIt == indices_.end()) return std::nullopt;
    if (plugins_[ownerIt->second].format == PluginFormat::light &&
        logical->localID > 0x0FFFU)
        return std::nullopt;
    return logical;
}

std::vector<std::string> PluginGraph::DirectDependents(
    const std::vector<std::string>& selectedPlugins) const {
    const auto roots = NormalizeSelectedRoots(selectedPlugins, indices_);
    std::vector<std::string> dependents;
    for (const auto& plugin : plugins_) {
        if (roots.contains(plugin.filename)) {
            continue;
        }
        const bool dependsOnRoot = std::any_of(
            plugin.masters.begin(), plugin.masters.end(),
            [&roots](const std::string& master) { return roots.contains(master); });
        if (dependsOnRoot) {
            dependents.push_back(plugin.filename);
        }
    }
    return dependents;
}

std::vector<std::string> PluginGraph::TransitiveDependents(
    const std::vector<std::string>& selectedPlugins) const {
    auto closure = NormalizeSelectedRoots(selectedPlugins, indices_);
    std::vector<std::string> dependents;
    dependents.reserve(plugins_.size());
    for (const auto& plugin : plugins_) {
        if (closure.contains(plugin.filename)) {
            continue;
        }
        const bool dependsOnClosure = std::any_of(
            plugin.masters.begin(), plugin.masters.end(),
            [&closure](const std::string& master) { return closure.contains(master); });
        if (dependsOnClosure) {
            closure.insert(plugin.filename);
            dependents.push_back(plugin.filename);
        }
    }
    return dependents;
}

std::vector<std::string> PluginGraph::LightMasterDependencyClosure(
    const std::vector<std::string>& selectedLightPlugins) const {
    auto closure = NormalizeSelectedRoots(selectedLightPlugins, indices_);
    std::vector<std::size_t> pending;
    pending.reserve(closure.size());
    for (const auto& name : closure) {
        const auto index = indices_.at(name);
        if (plugins_[index].format != PluginFormat::light) {
            throw MappingError("light carrier selection contains a non-light plugin: " + name);
        }
        pending.push_back(index);
    }

    while (!pending.empty()) {
        const auto index = pending.back();
        pending.pop_back();
        for (const auto& master : plugins_[index].masters) {
            const auto masterIndex = indices_.at(master);
            const auto masterFormat = plugins_[masterIndex].format;
            if (masterFormat == PluginFormat::light) {
                if (closure.insert(master).second) pending.push_back(masterIndex);
            } else if (masterFormat != PluginFormat::full) {
                throw MappingError("cannot establish light-master format in dependency closure: " + master);
            }
        }
    }

    std::vector<std::string> result;
    result.reserve(closure.size());
    for (const auto& plugin : plugins_) {
        if (closure.contains(plugin.filename)) result.push_back(plugin.filename);
    }
    return result;
}

}  // namespace vaddr
