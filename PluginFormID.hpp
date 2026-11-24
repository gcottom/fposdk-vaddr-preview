#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace vaddr {

// Fallout 4 stores a form's source file in the high byte for a full plugin,
// or in the high 12 bits plus a 12-bit object ID for a light plugin.
enum class PluginKind { full, light };

struct EncodedPluginFormID {
    std::uint32_t raw{};
    std::uint32_t objectID{};
    std::uint16_t ownerIndex{};
    PluginKind kind{PluginKind::full};
};

// Decode the source-plugin index from a record's stored ID. FE/FF are reserved
// namespaces and are rejected instead of guessed to be a normal plugin.
[[nodiscard]] std::optional<EncodedPluginFormID> DecodePluginFormID(
    std::uint32_t raw, std::optional<std::uint16_t> expectedLightIndex = std::nullopt);

}  // namespace vaddr
