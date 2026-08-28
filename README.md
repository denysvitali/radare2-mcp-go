# radare2 MCP

radare2 MCP is a Go Model Context Protocol server for radare2. It provides
typed tools for binary analysis while retaining a guarded raw-command escape
hatch for radare2 capabilities that do not yet have a dedicated tool.

Each named target runs in an independent persistent `r2 -q0` process. Multiple
executables and libraries can remain open simultaneously without losing
analysis state.

## Requirements

- Go 1.27.0 or newer
- radare2 on `PATH`
- r2ghidra when Ghidra-quality decompilation is required

## Build

```sh
go test ./...
make lint
go build ./cmd/radare2-mcp
```

## MCP configuration

```json
{
  "mcpServers": {
    "radare2": {
      "command": "radare2-mcp",
      "args": ["--root", "/analysis"]
    }
  }
}
```

For Codex:

```sh
go build -trimpath -ldflags='-s -w' -o ~/.local/bin/radare2-mcp ./cmd/radare2-mcp
codex mcp add radare2 -- ~/.local/bin/radare2-mcp
codex mcp get radare2
```

Long analysis operations may require extended MCP timeouts:

```toml
[mcp_servers.radare2]
command = "/absolute/path/to/radare2-mcp"
startup_timeout_sec = 20
tool_timeout_sec = 3600
default_tools_approval_mode = "approve"
```

The CLI uses Cobra and Viper. Options may be supplied as flags, through a
YAML/JSON/TOML file selected with `--config`, or through `RADARE2_MCP_*`
environment variables. Without `--config`, the command looks for
`radare2-mcp` configuration in the current and user configuration directories.

`--root` may be repeated and restricts binaries, symbol files, and saved
projects to approved filesystem roots. Paths are unrestricted when it is
omitted. Shell escapes, redirection, command chaining, and non-loopback GDB
endpoints remain disabled unless `--allow-unsafe-commands` is supplied.

## Basic workflow

```text
workspace_open {name:"app", path:"/analysis/app"}
workspace_open {name:"library", path:"/analysis/libexample.so"}
analyze {target:"app", level:"standard"}
cross_binary_xrefs {from_targets:["app"], to_targets:["library"]}
workspace_save {path:"/analysis/project"}
```

Analysis levels use explicit radare2 passes instead of version-dependent
`aaa`/`aaaa` aliases. Full and exhaustive levels include `aav0` for data
reference recovery. Results identify each completed pass and the resulting
function count. Completed passes and input file identity are persisted, so a
repeated request skips completed work unless `force:true` is supplied.

For indirect table analysis:

```text
recover_dispatch_table {
  target:"app", address:"0x401000", count:16, entry_size:8,
  pointer_slots:["0x404000"], scan_pointers:true
}
emulate_function {
  target:"app", address:"0x402000",
  registers:{rdi:"0x500000", rsi:"3"}, steps:500, trace:true
}
```

`list_strings` returns virtual and physical addresses. `string_xrefs`
combines direct references with a value-search and second xref pass through
pointer slots.

Symbol maps can be applied to raw kernel images:

```text
load_kernel_symbols {target:"image", symbol_file:"/analysis/System.map"}
```

Without a map, `load_kernel_symbols` can scan classic absolute and PREL32
`__ksymtab` records. Every recovered name includes its source.

## Tools

- Workspace: `workspace_open`, `workspace_list`, `workspace_select`,
  `workspace_close`, `workspace_save`, `workspace_load`, `workspace_delete`
- References: `cross_binary_xrefs`, `recover_dispatch_table`,
  `string_xrefs`, `load_kernel_symbols`
- Analysis: `analyze`, `analysis_status`, `capabilities`, `inspect`, `search`, `search_gadgets`,
  `list_strings`, `decompile`, `emulate_function`, `diff_functions`
- Annotations: `annotate`, `type_define`, `type_apply`, `type_inspect`
- Escape hatch: `r2_command`

`inspect` covers binary information, functions, imports, exports, symbols,
sections, xrefs, disassembly, hexdumps, and registers. Decoded results are
address-sorted by default and do not duplicate a serialized copy. Large
inspect, decompiler, and cross-target results include pagination or truncation
metadata. Every tool response includes `duration_ms` in MCP `_meta`; analysis
and workspace project operations also emit MCP progress notifications.

Gadget search uses current `/g` with a legacy `/R` fallback. Filters include
gadget kind, depth, final opcode, class, registers written, contained text, and
result count. Results carry alignment, containing section, executable status,
matched filters, and the exact instructions used as register-write evidence.

`decompile` tries r2ghidra, `pdd`, and `pdc` in order. Plugin-install and
error text are rejected as decompiler output. The selected backend is included
in the result together with the status, reason, and duration of every attempt.

`type_apply` accepts both bare names and natural forms such as `struct record`.
`type_inspect` exposes radare2's native definition and type-link evidence. A
warning is returned when radare2 reports a zero or otherwise unverifiable
layout instead of presenting guessed offsets as authoritative.

`workspace_save` stores a manifest and native `.r2pj` project for every
target. Names, comments, prototypes, flags, types, and analysis can be restored
with `workspace_load`.
Project saves and loads run independent targets concurrently. Deletion is a
separate destructive tool requiring `confirm:true`; it validates the manifest
and refuses symlinks, non-regular entries, and unexpected files.

`diff_functions` compares normalized instruction features, size, stable
names, and exact normalized hashes. Scores identify candidates and are not
proof of function identity.

## Live debugging

Local GDB endpoints can be opened as debugger targets:

```text
workspace_open {
  name:"live", path:"gdb://127.0.0.1:1234", debug:true,
  arch:"mips", bits:32, endian:"big"
}
inspect {target:"live", kind:"registers"}
```

Non-loopback endpoints require `--allow-unsafe-commands`.

## Guarantees

- MCP lifecycle, negotiation, schemas, structured results, cancellation, and
  stdio framing use the official Go SDK.
- Each target has one serialized command stream and independent radare2 state.
- Request cancellation interrupts long commands without discarding unrelated
  targets.
- Workspace manifests are written by atomic rename.
- Typed tools validate addresses, bounds, identifiers, paths, and enums.
- Raw commands block external execution and command composition by default.
- Heuristic matches and emulation results are returned as evidence, not runtime
  reachability claims.
