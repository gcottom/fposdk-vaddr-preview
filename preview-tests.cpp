#include "LogicalFormID.hpp"
#include "PluginGraph.hpp"
#include "PluginHeader.hpp"
#include "PluginFormInventory.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string_view>
#include <vector>

using namespace vaddr;

unsigned checksPassed = 0;

void check(bool condition, const char* description) {
    if (!condition) {
        std::cerr << description << '\n';
        std::exit(1);
    }
    ++checksPassed;
}

void tag(std::vector<char>& out, std::string_view text) {
    out.insert(out.end(), text.begin(), text.end());
}

void le32(std::vector<char>& out, std::uint32_t value) {
    for (unsigned i = 0; i != 4; ++i)
        out.push_back(static_cast<char>((value >> (8 * i)) & 0xFFU));
}

std::vector<char> fixture(float hedrVersion, std::uint32_t declaredRecordCount) {
    std::vector<char> bytes;
    tag(bytes, "TES4");
    le32(bytes, 18);
    bytes.resize(24);
    tag(bytes, "HEDR");
    bytes.push_back(12);
    bytes.push_back(0);
    le32(bytes, std::bit_cast<std::uint32_t>(hedrVersion));
    le32(bytes, declaredRecordCount);
    le32(bytes, 0x801);
    tag(bytes, "MISC");
    le32(bytes, 0);
    le32(bytes, 0);
    le32(bytes, 0x800);
    bytes.resize(bytes.size() + 8);
    return bytes;
}

std::vector<char> readFixture(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

void writeFixture(const std::filesystem::path& path, const std::vector<char>& bytes) {
    std::ofstream output(path, std::ios::binary);
    output.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!output) throw std::runtime_error("failed to write synthetic plugin");
}

int main(int argc, char** argv) {
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
    check(argc == 2, "test runner requires a disposable fixture directory");
    const std::filesystem::path root = argv[1];
    check(!std::filesystem::exists(root / "Fallout4.exe"),
          "compatibility fixtures must not depend on Fallout4.exe");
    for (const auto version : {0.95F, 1.0F}) {
        const auto original = fixture(version, 1);
        const auto file = root / "fixture.esp";
        writeFixture(file, original);
        const auto header = ReadPluginHeader(file, automatic);
        check(header.headerVersion == version && header.plugin.format == full,
              "read supported binary layout without treating HEDR as an executable version");
        const auto fixtureGraph = PluginGraph::Build({
            {"Fallout4.esm", full, {}, version}, header.plugin,
        });
        const auto inventory = ScanPluginFormInventory(fixtureGraph, root, "fixture.esp");
        check(inventory.ownedDefinitionCount == 1 && inventory.overrideCount == 0 &&
                  inventory.ownedForms == std::vector<LogicalFormID>{{"fixture.esp", 0x800}},
              "inventory must recover the self-owned record on both HEDR fixtures");
        const auto mapping = BuildPluginMappingTable(
            fixtureGraph, root, {"fixture.esp"}, {{0x21, 0x800, 0x8FF}});
        check(mapping.Resolve({"fixture.esp", 0x800}).has_value(),
              "read-only mapping must not require an executable to plan an existing record");
        check(readFixture(file) == original, "analysis unexpectedly changed the source plugin");
    }
    const auto badFile = root / "bad.esp";
    const auto badBytes = fixture(1.0F, 2);
    writeFixture(badFile, badBytes);
    rejected = false;
    try {
        const auto badGraph = PluginGraph::Build({ReadPluginHeader(badFile, automatic).plugin});
        static_cast<void>(ScanPluginFormInventory(badGraph, root, "bad.esp"));
    } catch (const MappingError& error) {
        rejected = std::string_view(error.what()).find("HEDR record count") != std::string_view::npos;
    }
    check(rejected && readFixture(badFile) == badBytes,
          "layout independence must preserve the HEDR count check and leave malformed files untouched");
    std::cout << checksPassed << " synthetic checks passed\n";
}
