#pragma once

#include <compare>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace vaddr {

using PhysicalFormID = std::uint32_t;

struct LogicalFormID {
    std::string plugin;
    // Zero is a valid plugin-local object when its defining record header is
    // resolved with owner context. Zero references are still NULL.
    std::uint32_t localID{};

    auto operator<=>(const LogicalFormID&) const = default;
};

struct CarrierRange {
    std::uint8_t pluginIndex{};
    std::uint32_t firstLocalID{};
    std::uint32_t lastLocalID{};
};

struct MappingEntry {
    LogicalFormID logical;
    PhysicalFormID physical{};
};

class MappingError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Builds a canonical map from an explicit, already-reserved carrier policy.
// This core does not select or reserve carrier slots in a real load order.
class MappingTable {
public:
    static MappingTable Build(std::vector<LogicalFormID> logicalForms,
                              std::vector<CarrierRange> carrierRanges);
    // Existing assignments stay fixed. Removed forms remain reserved as
    // tombstones so their physical IDs cannot be assigned to another form.
    static MappingTable BuildPreserving(std::vector<LogicalFormID> logicalForms,
                                        std::vector<CarrierRange> carrierRanges,
                                        std::vector<MappingEntry> previousEntries);
    static MappingTable MergeAssignments(std::vector<MappingTable> assignments);

    [[nodiscard]] std::optional<PhysicalFormID> Resolve(const LogicalFormID& logical) const;
    [[nodiscard]] std::optional<LogicalFormID> Reverse(PhysicalFormID physical) const;
    [[nodiscard]] const std::vector<MappingEntry>& Entries() const noexcept { return entries_; }

private:
    std::vector<MappingEntry> entries_;
    std::vector<std::pair<PhysicalFormID, LogicalFormID>> reverse_;
};

[[nodiscard]] std::string CanonicalPluginName(std::string_view filename);

}  // namespace vaddr
