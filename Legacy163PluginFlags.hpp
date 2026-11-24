#pragma once

#include <cstdint>
#include <string_view>

namespace vaddr {
// Applies only the exact filename normalization observed in legacy TESFile's
// header-load chain: RVA12F2E0..12F361 (OR1 at12F327, OR200 at12F357).
// The caller validates the filename separately. Other bits are preserved.
[[nodiscard]] inline std::uint32_t NormalizeLegacy163TES4Flags(
    const std::string_view filename, const std::uint32_t diskFlags) noexcept {
    if (filename.size() < 4) return diskFlags;
    const auto suffix = filename.substr(filename.size() - 4);
    const auto lower = [](const char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c; };
    if (suffix[0] != '.' || lower(suffix[1]) != 'e' || lower(suffix[2]) != 's') return diskFlags;
    const char last = lower(suffix[3]);
    if (last == 'm') return diskFlags | 0x1u;
    if (last == 'l') return diskFlags | 0x1u | 0x200u;
    return diskFlags;
}
}  // namespace vaddr
