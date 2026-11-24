# Fallout Plugin Optimization SDK: VAddr Core Preview

A buildable source preview of VAddr, the engine behind the Fallout Plugin Optimization SDK (FPOSDK). The engineering goal is to make more room in a Fallout 4 load order without changing the game's full-plugin cap.

This snapshot shows how VAddr reads and validates plugin structure, resolves file-relative FormIDs against an ordered dependency graph, separates owned records from overrides, and assigns stable carrier IDs. Mapping decisions are kept separate from file changes; nothing in this preview rewrites a plugin or changes a load order.

- **PluginHeader / PluginFileScanner**: read TES4 metadata and check record, group, and subrecord boundaries, including compressed record bodies.
- **PluginGraph / PluginFormInventory**: resolve ownership in mixed full/light dependencies and inventory records.
- **MappingTable**: assign deterministic IDs within reserved carrier ranges. Existing assignments are retained, and removed forms leave their slots reserved.

## Run the synthetic checks

On Linux, with Make, a C++23 compiler and zlib development headers installed:

```sh
make test
```

No game, mods, or saves are required for the tests. This repository is a source preview, not the complete SDK or a production installer. It does not include the runtime integration, private test profiles, third-party game files, or the LoadForge extension.

## Compatibility

The preview's offline analysis does not inspect or require `Fallout4.exe`,
F4SE, or an Address Library. It takes plugin bytes and the ordered dependency
graph as inputs, not a game-version allowlist. The synthetic checks exercise
both HEDR 0.95 and 1.0 inputs, confirm that the plugin is not rewritten, and
reject a malformed record count. HEDR is plugin metadata, not a game build.

Structural limits, FormID interpretation, and master validation still apply.
This is not a claim of in-game compatibility on every build. The public
preview cannot apply ESP-to-ESL changes or replace a VAddr runtime adapter.

[Project and test notes](https://voidobscura.com/#fallout-tooling) · [LoadForge Studio on Nexus Mods](https://www.nexusmods.com/fallout4/mods/111745)
