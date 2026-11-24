#include "PluginFormID.hpp"

namespace vaddr {

std::optional<EncodedPluginFormID> DecodePluginFormID(
    std::uint32_t raw, std::optional<std::uint16_t> expectedLightIndex) {
    const auto fileByte = static_cast<std::uint8_t>(raw >> 24);
    if (fileByte == 0xFF) {
        return std::nullopt;
    }
    if (fileByte != 0xFE) {
        const auto objectID = raw & 0x00FF'FFFFU;
        if (raw == 0) return std::nullopt;
        return EncodedPluginFormID{raw, objectID, fileByte, PluginKind::full};
    }

    if (fileByte == 0xFE && !expectedLightIndex) {
        // FE must be matched against TESFile::smallFileCompileIndex. A raw
        // number alone cannot distinguish a light FormID from reserved FE.
        return std::nullopt;
    }
    const auto lightIndex = static_cast<std::uint16_t>((raw >> 12) & 0x0FFFU);
    const auto objectID = raw & 0x0000'0FFFU;
    if (lightIndex != *expectedLightIndex) {
        return std::nullopt;
    }
    return EncodedPluginFormID{raw, objectID, lightIndex, PluginKind::light};
}

}  // namespace vaddr
