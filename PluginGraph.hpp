#pragma once

#include "LogicalFormID.hpp"

#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace vaddr {

enum class PluginFormat { full, light, automatic };

struct PluginNode {
    std::string filename;
    PluginFormat format{PluginFormat::full};
    std::vector<std::string> masters;
    std::optional<float> headerVersion;
    bool isMaster{};
    bool extensionPromotesMaster{};

    [[nodiscard]] bool EffectiveMaster() const noexcept {
        return isMaster || extensionPromotesMaster;
    }
};

struct FileRelativeFormID {
    std::string sourcePlugin;
    std::uint32_t raw{};
};

// Resolves a full-namespace file-relative FormID using a list containing only
// full masters. Callers with mixed full/light masters must use
// ResolveFileRelativeFormID and supply each master's type.
[[nodiscard]] std::optional<LogicalFormID> ResolveFullFileRelativeFormID(
    std::string_view sourcePlugin,
    std::span<const std::string_view> orderedMasters,
    std::optional<float> sourceHeaderVersion,
    std::uint32_t rawFormID);

// Resolves a serialized FormID relative to the complete ordered TES4 MAST
// list. Ordinary owner bytes index every master in list order, regardless of
// full/light format. Out-of-range slots follow xEdit's source-file fallback;
// raw FE is that fallback namespace, not an external light-master index, and
// raw FF is rejected. Hardcoded full-range handling follows the source HEDR.
[[nodiscard]] std::optional<LogicalFormID> ResolveFileRelativeFormID(
    std::string_view sourcePlugin,
    PluginFormat sourceFormat,
    std::span<const std::string_view> orderedMasters,
    std::span<const PluginFormat> orderedMasterFormats,
    std::optional<float> sourceHeaderVersion,
    std::uint32_t rawFormID);

// Encodes a logical target as a raw plugin-file FormID. External owners use
// their ordinal in the complete ordered MAST list; source-self uses MAST count.
// The output format controls the local object-ID bound; no load-order FE ID is
// emitted into plugin bytes.
[[nodiscard]] std::uint32_t EncodeFileRelativeFormID(
    std::string_view sourcePlugin,
    PluginFormat sourceFormat,
    std::span<const std::string> orderedMasters,
    const LogicalFormID& target,
    PluginFormat targetFormat);

// Validates an enabled logical plugin set and resolves serialized file-relative
// IDs using the complete ordered MAST list.
class PluginGraph {
public:
    static PluginGraph Build(std::vector<PluginNode> plugins);

    [[nodiscard]] std::optional<LogicalFormID> Resolve(const FileRelativeFormID& id) const;
    // Returns enabled plugins that directly or transitively depend on any
    // selected logical plugin, preserving validated load order. The selected
    // roots must be present in this graph.
    [[nodiscard]] std::vector<std::string> DirectDependents(
        const std::vector<std::string>& selectedPlugins) const;
    [[nodiscard]] std::vector<std::string> TransitiveDependents(
        const std::vector<std::string>& selectedPlugins) const;
    // Returns selected light plugins plus every transitive light master they
    // require, preserving the validated load order. Full masters remain
    // external dependencies and are not added to the conversion group.
    [[nodiscard]] std::vector<std::string> LightMasterDependencyClosure(
        const std::vector<std::string>& selectedLightPlugins) const;
    [[nodiscard]] const std::vector<PluginNode>& LoadOrder() const noexcept { return plugins_; }

private:
    std::vector<PluginNode> plugins_;
    std::vector<std::vector<PluginFormat>> masterFormats_;
    std::unordered_map<std::string, std::size_t> indices_;
};

}  // namespace vaddr
