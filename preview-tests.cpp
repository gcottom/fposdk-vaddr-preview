#include "LogicalFormID.hpp"
#include "PluginGraph.hpp"
#include "PluginHeader.hpp"

#include <array>
#include <cstddef>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <stdexcept>
#include <vector>

using namespace vaddr;

void check(bool condition, const char* description) {
    if (!condition) {
        std::cerr << description << '\n';
        std::exit(1);
    }
}

int main() {
    using enum PluginFormat;
    const auto graph = PluginGraph::Build({
        {"Example.esm", full, {}, 1.0F},
        {"Light.esl", light, {"Example.esm"}, 1.0F},
        {"Addon.esp", full, {"Example.esm", "Light.esl"}, 1.0F},
    });
    const auto external = graph.Resolve({"Addon.esp", 0x01000801});
    check(external && external->plugin == "light.esl" && external->localID == 0x801,
          "mixed-master lookup must retain the ordered light master");
    const auto self = graph.Resolve({"Addon.esp", 0x02000800});
    check(self && self->plugin == "addon.esp" && self->localID == 0x800,
          "the slot after the ordered masters belongs to the source plugin");

    const LogicalFormID first{"Addon.esp", 0x801}, second{"Addon.esp", 0x802};
    const std::vector<CarrierRange> ranges{{0x21, 0x800, 0x8FF}};
    const auto before = MappingTable::Build({first}, ranges);
    const auto after = MappingTable::BuildPreserving({first, second}, ranges, before.Entries());
    check(after.Resolve(first) == before.Resolve(first), "existing mapping must remain stable");
    check(after.Resolve(second).has_value() && after.Resolve(second) != after.Resolve(first),
          "new forms must receive a distinct carrier ID");
    check(after.Reverse(*after.Resolve(second)) ==
              std::optional<LogicalFormID>{{"addon.esp", second.localID}},
          "reverse lookup must recover the canonical logical ID");

    const std::array<std::byte, 4> truncated{
        std::byte{'T'}, std::byte{'E'}, std::byte{'S'}, std::byte{'4'}};
    bool rejected = false;
    try {
        static_cast<void>(ParsePluginHeader(truncated, "Truncated.esp", automatic));
    } catch (const std::exception&) {
        rejected = true;
    }
    check(rejected, "a truncated TES4 record header must be rejected");
    std::cout << "6 synthetic checks passed\n";
}
