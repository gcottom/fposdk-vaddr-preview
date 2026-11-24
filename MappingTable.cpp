#include "LogicalFormID.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

namespace vaddr {
namespace {

constexpr std::uint32_t kObjectIDMask = 0x00FF'FFFF;
constexpr std::uint64_t kFnvOffset = 14695981039346656037ULL;
constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

struct Slot {
    std::uint8_t pluginIndex{};
    std::uint32_t localID{};
};

std::uint64_t StableHash(const LogicalFormID& id) {
    std::uint64_t hash = kFnvOffset;
    const auto name = CanonicalPluginName(id.plugin);
    for (const unsigned char byte : name) {
        hash = (hash ^ byte) * kFnvPrime;
    }
    hash = (hash ^ 0xFFU) * kFnvPrime;
    for (unsigned shift = 0; shift < 32; shift += 8) {
        hash = (hash ^ static_cast<unsigned char>(id.localID >> shift)) * kFnvPrime;
    }
    return hash;
}

Slot AtOrdinal(const std::vector<CarrierRange>& ranges, std::uint64_t ordinal) {
    for (const auto& range : ranges) {
        const auto count = static_cast<std::uint64_t>(range.lastLocalID) - range.firstLocalID + 1;
        if (ordinal < count) {
            return {range.pluginIndex, range.firstLocalID + static_cast<std::uint32_t>(ordinal)};
        }
        ordinal -= count;
    }
    throw MappingError("carrier ordinal is outside the configured namespace");
}

}  // namespace

std::string CanonicalPluginName(std::string_view filename) {
    if (filename.empty() || filename == "." || filename == "..") {
        throw MappingError("plugin filename is empty or invalid");
    }
    if (filename.find_first_of("/\\:") != std::string_view::npos) {
        throw MappingError("plugin identity must be a filename, not a path");
    }
    std::string result;
    result.reserve(filename.size());
    for (const unsigned char ch : filename) {
        if (ch < 0x20 || ch == 0x7F) {
            throw MappingError("plugin filename contains a control character");
        }
        result.push_back(static_cast<char>(ch < 0x80 ? std::tolower(ch) : ch));
    }
    const auto dot = result.find_last_of('.');
    if (dot == std::string::npos ||
        (result.substr(dot) != ".esp" && result.substr(dot) != ".esm" && result.substr(dot) != ".esl")) {
        throw MappingError("plugin filename must end in .esp, .esm, or .esl");
    }
    return result;
}

MappingTable MappingTable::Build(std::vector<LogicalFormID> logicalForms,
                                 std::vector<CarrierRange> carrierRanges) {
    return BuildPreserving(std::move(logicalForms), std::move(carrierRanges), {});
}

MappingTable MappingTable::BuildPreserving(std::vector<LogicalFormID> logicalForms,
                                           std::vector<CarrierRange> carrierRanges,
                                           std::vector<MappingEntry> previousEntries) {
    if (logicalForms.empty()) {
        throw MappingError("cannot build an empty mapping");
    }
    if (carrierRanges.empty()) {
        throw MappingError("at least one explicit carrier range is required");
    }

    for (auto& form : logicalForms) {
        form.plugin = CanonicalPluginName(form.plugin);
        if (form.localID > kObjectIDMask) {
            throw MappingError("logical local FormID must be in the range 0..0xFFFFFF");
        }
    }
    std::sort(logicalForms.begin(), logicalForms.end());
    if (std::adjacent_find(logicalForms.begin(), logicalForms.end()) != logicalForms.end()) {
        throw MappingError("duplicate logical FormID");
    }

    std::sort(carrierRanges.begin(), carrierRanges.end(), [](const auto& left, const auto& right) {
        return std::tie(left.pluginIndex, left.firstLocalID, left.lastLocalID) <
               std::tie(right.pluginIndex, right.firstLocalID, right.lastLocalID);
    });
    std::uint64_t capacity = 0;
    std::unordered_set<std::uint8_t> carrierSlots;
    for (std::size_t i = 0; i < carrierRanges.size(); ++i) {
        const auto& range = carrierRanges[i];
        if (range.pluginIndex == 0 || range.pluginIndex == 0xFE || range.pluginIndex == 0xFF) {
            throw MappingError("carrier slot cannot use the base-game, light, or engine-created namespace");
        }
        if (range.firstLocalID == 0 || range.firstLocalID > range.lastLocalID ||
            range.lastLocalID > kObjectIDMask) {
            throw MappingError("carrier local-ID range must be a non-empty subset of 1..0xFFFFFF");
        }
        if (!carrierSlots.insert(range.pluginIndex).second) {
            throw MappingError("carrier slot may be declared only once");
        }
        capacity += static_cast<std::uint64_t>(range.lastLocalID) - range.firstLocalID + 1;
        if (i > 0) {
            const auto& previous = carrierRanges[i - 1];
            const auto previousEnd = (static_cast<std::uint64_t>(previous.pluginIndex) << 24) |
                                     previous.lastLocalID;
            const auto currentStart = (static_cast<std::uint64_t>(range.pluginIndex) << 24) |
                                      range.firstLocalID;
            if (currentStart <= previousEnd) {
                throw MappingError("carrier physical ranges overlap");
            }
        }
    }
    if (logicalForms.size() > capacity) {
        throw MappingError("logical forms exceed the configured carrier capacity");
    }

    std::map<LogicalFormID, PhysicalFormID> preserved;
    std::unordered_set<PhysicalFormID> preservedPhysical;
    for (auto& entry : previousEntries) {
        entry.logical.plugin = CanonicalPluginName(entry.logical.plugin);
        if (entry.logical.localID > kObjectIDMask) {
            throw MappingError("persisted logical local FormID is invalid");
        }
        const auto slot = static_cast<std::uint8_t>(entry.physical >> 24);
        const auto local = entry.physical & kObjectIDMask;
        const auto inRange = std::any_of(carrierRanges.begin(), carrierRanges.end(),
            [slot, local](const CarrierRange& range) {
                return range.pluginIndex == slot && local >= range.firstLocalID && local <= range.lastLocalID;
            });
        if (!inRange || !preservedPhysical.insert(entry.physical).second ||
            !preserved.emplace(entry.logical, entry.physical).second) {
            throw MappingError("persisted mapping contains an invalid or duplicate assignment");
        }
    }
    for (const auto& [logical, _] : preserved) {
        if (!std::binary_search(logicalForms.begin(), logicalForms.end(), logical)) {
            logicalForms.push_back(logical);  // Retain removed entries as address tombstones.
        }
    }
    std::sort(logicalForms.begin(), logicalForms.end());
    if (logicalForms.size() > capacity) {
        throw MappingError("persisted mappings and new forms exceed carrier capacity");
    }

    MappingTable table;
    table.entries_.reserve(logicalForms.size());
    std::unordered_set<std::uint64_t> usedSlots;
    for (const auto& [_, physical] : preserved) {
        const auto slot = static_cast<std::uint64_t>((physical >> 24) & 0xFF);
        const auto local = static_cast<std::uint64_t>(physical & kObjectIDMask);
        std::uint64_t ordinal = 0;
        bool found = false;
        for (const auto& range : carrierRanges) {
            const auto count = static_cast<std::uint64_t>(range.lastLocalID) - range.firstLocalID + 1;
            if (range.pluginIndex == slot && local >= range.firstLocalID && local <= range.lastLocalID) {
                ordinal += local - range.firstLocalID;
                found = true;
                break;
            }
            ordinal += count;
        }
        if (!found) throw MappingError("persisted mapping escaped carrier ranges");
        usedSlots.insert(ordinal);
    }
    for (const auto& logical : logicalForms) {
        if (const auto found = preserved.find(logical); found != preserved.end()) {
            table.entries_.push_back({logical, found->second});
            continue;
        }
        const auto start = StableHash(logical) % capacity;
        std::uint64_t probe = 0;
        while (probe < capacity && usedSlots.contains((start + probe) % capacity)) {
            ++probe;
        }
        if (probe == capacity) {
            throw MappingError("carrier namespace is exhausted");
        }
        const auto index = (start + probe) % capacity;
        usedSlots.insert(index);
        const auto slot = AtOrdinal(carrierRanges, index);
        const auto physical = (static_cast<PhysicalFormID>(slot.pluginIndex) << 24) | slot.localID;
        table.entries_.push_back({logical, physical});
    }

    table.reverse_.reserve(table.entries_.size());
    for (const auto& entry : table.entries_) {
        table.reverse_.emplace_back(entry.physical, entry.logical);
    }
    std::sort(table.reverse_.begin(), table.reverse_.end(),
        [](const auto& left, const auto& right) { return left.first < right.first; });

    return table;
}

MappingTable MappingTable::MergeAssignments(std::vector<MappingTable> assignments) {
    MappingTable merged;
    std::set<LogicalFormID> logicals;
    std::unordered_set<PhysicalFormID> physicals;
    for (const auto& assignment : assignments) {
        for (const auto& entry : assignment.entries_) {
            if (!logicals.insert(entry.logical).second)
                throw MappingError("carrier assignments contain a duplicate logical FormID");
            if (!physicals.insert(entry.physical).second)
                throw MappingError("carrier assignments contain a duplicate physical FormID");
            merged.entries_.push_back(entry);
        }
    }
    std::sort(merged.entries_.begin(), merged.entries_.end(),
        [](const MappingEntry& left, const MappingEntry& right) { return left.logical < right.logical; });
    merged.reverse_.reserve(merged.entries_.size());
    for (const auto& entry : merged.entries_)
        merged.reverse_.emplace_back(entry.physical, entry.logical);
    std::sort(merged.reverse_.begin(), merged.reverse_.end(),
        [](const auto& left, const auto& right) { return left.first < right.first; });
    return merged;
}

std::optional<PhysicalFormID> MappingTable::Resolve(const LogicalFormID& logical) const {
    std::string canonical;
    try {
        canonical = CanonicalPluginName(logical.plugin);
    } catch (const MappingError&) {
        return std::nullopt;
    }
    if (logical.localID > kObjectIDMask) {
        return std::nullopt;
    }
    const LogicalFormID key{std::move(canonical), logical.localID};
    const auto it = std::lower_bound(entries_.begin(), entries_.end(), key,
        [](const MappingEntry& entry, const LogicalFormID& key) { return entry.logical < key; });
    if (it == entries_.end() || it->logical != key) {
        return std::nullopt;
    }
    return it->physical;
}

std::optional<LogicalFormID> MappingTable::Reverse(PhysicalFormID physical) const {
    const auto it = std::lower_bound(reverse_.begin(), reverse_.end(), physical,
        [](const auto& entry, PhysicalFormID key) { return entry.first < key; });
    if (it == reverse_.end() || it->first != physical) {
        return std::nullopt;
    }
    return it->second;
}

}  // namespace vaddr
