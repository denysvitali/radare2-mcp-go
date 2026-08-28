package server

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/denysvitali/radare2-mcp-go/internal/workspace"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type CapabilitiesInput struct {
	Target string `json:"target,omitempty"`
}
type CapabilitiesOutput struct {
	ServerVersion  string                  `json:"server_version"`
	Policy         workspace.Policy        `json:"policy"`
	Selected       string                  `json:"selected,omitempty"`
	Targets        []string                `json:"targets"`
	Target         string                  `json:"target,omitempty"`
	Radare2Version string                  `json:"radare2_version,omitempty"`
	Decompilers    any                     `json:"decompilers,omitempty"`
	ESILPlugins    []string                `json:"esil_plugins,omitempty"`
	TraceAvailable bool                    `json:"trace_available"`
	Analysis       workspace.AnalysisState `json:"analysis,omitempty"`
}

func (s *Service) capabilities(ctx context.Context, _ *mcp.CallToolRequest, in CapabilitiesInput) (*mcp.CallToolResult, CapabilitiesOutput, error) {
	targets, selected := s.ws.List()
	result := CapabilitiesOutput{ServerVersion: Version, Policy: s.ws.Policy(), Selected: selected, Targets: make([]string, 0, len(targets))}
	for _, target := range targets {
		result.Targets = append(result.Targets, target.Name)
	}
	if len(targets) == 0 {
		return nil, result, nil
	}
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, result, err
	}
	result.Target = t.Name
	result.Analysis, _ = s.ws.Analysis(t.Name)
	if out, cmdErr := t.R2.Cmd(ctx, "?Vq"); cmdErr == nil {
		result.Radare2Version = strings.TrimSpace(out)
	}
	if out, cmdErr := t.R2.Cmd(ctx, "LDj"); cmdErr == nil {
		_ = decodeJSONNumbers(out, &result.Decompilers)
	}
	if out, cmdErr := t.R2.Cmd(ctx, "Lej"); cmdErr == nil {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				result.ESILPlugins = append(result.ESILPlugins, line)
			}
		}
	}
	if out, cmdErr := t.R2.Cmd(ctx, "aet?"); cmdErr == nil {
		result.TraceAvailable = strings.TrimSpace(out) != ""
	}
	return nil, result, nil
}

type SymbolRecord struct {
	Name     string `json:"name"`
	RealName string `json:"realname,omitempty"`
	VAddr    uint64 `json:"vaddr,omitempty"`
	PAddr    uint64 `json:"paddr,omitempty"`
	PLT      uint64 `json:"plt,omitempty"`
	Bind     string `json:"bind,omitempty"`
	Type     string `json:"type,omitempty"`
}

type CrossXrefInput struct {
	FromTargets []string `json:"from_targets,omitempty" jsonschema:"importing targets; empty means all"`
	ToTargets   []string `json:"to_targets,omitempty" jsonschema:"provider targets; empty means all"`
	Symbol      string   `json:"symbol,omitempty" jsonschema:"optional exact or substring filter"`
	MaxResults  int      `json:"max_results,omitempty" jsonschema:"maximum links to return; default 1000"`
}
type CrossLink struct {
	Symbol          string `json:"symbol"`
	Importer        string `json:"importer"`
	ImportAddress   uint64 `json:"import_address,omitempty"`
	Provider        string `json:"provider"`
	ProviderAddress uint64 `json:"provider_address"`
	ProviderKind    string `json:"provider_kind"`
}
type CrossXrefOutput struct {
	Links      []CrossLink         `json:"links"`
	Unresolved map[string][]string `json:"unresolved,omitempty"`
	Total      int                 `json:"total"`
	Truncated  bool                `json:"truncated,omitempty"`
}

func (s *Service) crossBinaryXrefs(ctx context.Context, _ *mcp.CallToolRequest, in CrossXrefInput) (*mcp.CallToolResult, CrossXrefOutput, error) {
	all, _ := s.ws.List()
	if len(all) == 0 {
		return nil, CrossXrefOutput{}, errors.New("workspace is empty")
	}
	fromSet := stringSet(in.FromTargets)
	toSet := stringSet(in.ToTargets)
	type provider struct {
		target string
		addr   uint64
		kind   string
	}
	providers := map[string][]provider{}
	providerSeen := map[string]bool{}
	imports := map[string][]SymbolRecord{}
	for _, spec := range all {
		t, _ := s.ws.Get(spec.Name)
		if len(toSet) == 0 || toSet[t.Name] {
			for _, query := range []struct{ cmd, kind string }{{"iEj", "export"}, {"isj", "symbol"}, {"fj", "flag"}} {
				out, err := t.R2.Cmd(ctx, query.cmd)
				if err != nil {
					continue
				}
				var records []SymbolRecord
				if query.cmd == "fj" {
					var flags []struct {
						Name   string `json:"name"`
						Offset uint64 `json:"offset"`
					}
					if json.Unmarshal([]byte(out), &flags) == nil {
						for _, f := range flags {
							records = append(records, SymbolRecord{Name: f.Name, VAddr: f.Offset})
						}
					}
				} else {
					_ = json.Unmarshal([]byte(out), &records)
				}
				for _, sym := range records {
					name := canonicalSymbol(sym.Name)
					if name == "" {
						name = canonicalSymbol(sym.RealName)
					}
					if name != "" && sym.VAddr != 0 {
						key := fmt.Sprintf("%s\x00%s\x00%x", name, t.Name, sym.VAddr)
						if !providerSeen[key] {
							providers[name] = append(providers[name], provider{t.Name, sym.VAddr, query.kind})
							providerSeen[key] = true
						}
					}
				}
			}
		}
		if len(fromSet) == 0 || fromSet[t.Name] {
			out, err := t.R2.Cmd(ctx, "iij")
			if err != nil {
				return nil, CrossXrefOutput{}, fmt.Errorf("%s imports: %w", t.Name, err)
			}
			var records []SymbolRecord
			if err := json.Unmarshal([]byte(out), &records); err != nil {
				return nil, CrossXrefOutput{}, fmt.Errorf("%s imports: %w", t.Name, err)
			}
			imports[t.Name] = records
		}
	}
	result := CrossXrefOutput{Links: []CrossLink{}, Unresolved: map[string][]string{}}
	for importer, records := range imports {
		for _, imp := range records {
			name := canonicalSymbol(imp.Name)
			if name == "" {
				name = canonicalSymbol(imp.RealName)
			}
			if in.Symbol != "" && !strings.Contains(name, in.Symbol) {
				continue
			}
			matched := false
			importAddress := imp.VAddr
			if importAddress == 0 {
				importAddress = imp.PLT
			}
			for _, p := range providers[name] {
				if p.target == importer {
					continue
				}
				result.Links = append(result.Links, CrossLink{name, importer, importAddress, p.target, p.addr, p.kind})
				matched = true
			}
			if !matched && name != "" {
				result.Unresolved[importer] = append(result.Unresolved[importer], name)
			}
		}
	}
	sort.Slice(result.Links, func(i, j int) bool {
		a, b := result.Links[i], result.Links[j]
		if a.Symbol != b.Symbol {
			return a.Symbol < b.Symbol
		}
		if a.Importer != b.Importer {
			return a.Importer < b.Importer
		}
		return a.Provider < b.Provider
	})
	for k := range result.Unresolved {
		sort.Strings(result.Unresolved[k])
	}
	if len(result.Unresolved) == 0 {
		result.Unresolved = nil
	}
	result.Total = len(result.Links)
	if in.MaxResults <= 0 {
		in.MaxResults = 1000
	}
	if len(result.Links) > in.MaxResults {
		result.Links = result.Links[:in.MaxResults]
		result.Truncated = true
	}
	return nil, result, nil
}

func stringSet(items []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range items {
		m[v] = true
	}
	return m
}
func canonicalSymbol(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"sym.imp.", "sym.", "imp.", "reloc.", "fcn.", "kernel."} {
		s = strings.TrimPrefix(s, p)
	}
	if i := strings.Index(s, "@@"); i >= 0 {
		s = s[:i]
	}
	return s
}

type DispatchInput struct {
	Target       string   `json:"target,omitempty"`
	Address      string   `json:"address" jsonschema:"dispatch table start"`
	Count        int      `json:"count" jsonschema:"number of pointer entries"`
	EntrySize    int      `json:"entry_size,omitempty" jsonschema:"4 or 8; defaults from target bits"`
	PointerSlots []string `json:"pointer_slots,omitempty" jsonschema:"known RW slots whose loaded value reaches the table"`
	ScanPointers bool     `json:"scan_pointers,omitempty" jsonschema:"search for slots pointing to table start and every entry boundary"`
}
type DispatchEntry struct {
	Index   int    `json:"index"`
	Address uint64 `json:"address"`
	Value   uint64 `json:"value"`
	Name    string `json:"name,omitempty"`
}
type DispatchConsumer struct {
	Slot  uint64 `json:"slot"`
	Xrefs []Xref `json:"xrefs"`
}
type DispatchOutput struct {
	Target     string             `json:"target"`
	Table      uint64             `json:"table"`
	Entries    []DispatchEntry    `json:"entries"`
	Direct     []Xref             `json:"direct"`
	Consumers  []DispatchConsumer `json:"consumers"`
	MethodNote string             `json:"method_note"`
}

func (s *Service) recoverDispatchTable(ctx context.Context, _ *mcp.CallToolRequest, in DispatchInput) (*mcp.CallToolResult, DispatchOutput, error) {
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, DispatchOutput{}, err
	}
	base, err := parseAddress(in.Address)
	if err != nil {
		return nil, DispatchOutput{}, err
	}
	if in.Count < 1 || in.Count > 65536 {
		return nil, DispatchOutput{}, errors.New("count must be 1..65536")
	}
	if in.EntrySize == 0 {
		in.EntrySize = t.Bits / 8
		if in.EntrySize != 8 {
			in.EntrySize = 4
		}
	}
	if in.EntrySize != 4 && in.EntrySize != 8 {
		return nil, DispatchOutput{}, errors.New("entry_size must be 4 or 8")
	}
	cmd := fmt.Sprintf("pxwj %d @ 0x%x", in.Count*in.EntrySize, base)
	if in.EntrySize == 8 {
		cmd = fmt.Sprintf("pxqj %d @ 0x%x", in.Count*in.EntrySize, base)
	}
	raw, err := t.R2.Cmd(ctx, cmd)
	if err != nil {
		return nil, DispatchOutput{}, err
	}
	var values []any
	if err := decodeJSONNumbers(raw, &values); err != nil {
		return nil, DispatchOutput{}, fmt.Errorf("decode table: %w", err)
	}
	flagsOut, _ := t.R2.Cmd(ctx, "fj")
	var flags []struct {
		Name   string `json:"name"`
		Offset uint64 `json:"offset"`
	}
	_ = json.Unmarshal([]byte(flagsOut), &flags)
	flagAt := map[uint64]string{}
	for _, f := range flags {
		flagAt[f.Offset] = f.Name
	}
	result := DispatchOutput{Target: t.Name, Table: base, MethodNote: "Consumers are xrefs to RW pointer slots; inspect their surrounding instructions or emulate_function to prove negative-adjustment and index semantics."}
	for i, v := range values {
		addr := base + uint64(i*in.EntrySize)
		value := number(v)
		result.Entries = append(result.Entries, DispatchEntry{i, addr, value, flagAt[value]})
	}
	result.Direct, _ = xrefsAt(ctx, t, base)
	slots := map[uint64]bool{}
	for _, text := range in.PointerSlots {
		a, e := parseAddress(text)
		if e != nil {
			return nil, DispatchOutput{}, fmt.Errorf("pointer slot: %w", e)
		}
		slots[a] = true
	}
	if in.ScanPointers {
		for i := 0; i < in.Count; i++ {
			target := base + uint64(i*in.EntrySize)
			out, e := t.R2.Cmd(ctx, fmt.Sprintf("/vj 0x%x", target))
			if e != nil {
				continue
			}
			var hits []map[string]any
			if decodeJSONNumbers(out, &hits) != nil {
				continue
			}
			for _, hit := range hits {
				a := number(hit["offset"])
				if a == 0 {
					a = number(hit["addr"])
				}
				if a != 0 && (a < base || a >= base+uint64(in.Count*in.EntrySize)) {
					slots[a] = true
				}
			}
		}
	}
	for _, slot := range sortedUint64Keys(slots) {
		refs, _ := xrefsAt(ctx, t, slot)
		result.Consumers = append(result.Consumers, DispatchConsumer{slot, refs})
	}
	return nil, result, nil
}

func sortedUint64Keys(m map[uint64]bool) []uint64 {
	out := make([]uint64, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

type DecompileInput struct {
	Target    string `json:"target,omitempty"`
	Address   string `json:"address"`
	Backend   string `json:"backend,omitempty" jsonschema:"auto, r2ghidra, pdd, or pdc"`
	StartLine int    `json:"start_line,omitempty" jsonschema:"zero-based output line"`
	MaxLines  int    `json:"max_lines,omitempty" jsonschema:"default 400, maximum 5000"`
}
type DecompileOutput struct {
	Target     string           `json:"target"`
	Backend    string           `json:"backend"`
	Code       string           `json:"code"`
	StartLine  int              `json:"start_line,omitempty"`
	NextLine   int              `json:"next_line,omitempty"`
	TotalLines int              `json:"total_lines"`
	Truncated  bool             `json:"truncated,omitempty"`
	Attempts   []BackendAttempt `json:"attempts"`
}
type BackendAttempt struct {
	Backend    string `json:"backend"`
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

func (s *Service) decompile(ctx context.Context, _ *mcp.CallToolRequest, in DecompileInput) (*mcp.CallToolResult, DecompileOutput, error) {
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, DecompileOutput{}, err
	}
	if _, err := parseAddress(in.Address); err != nil {
		return nil, DecompileOutput{}, err
	}
	if in.StartLine < 0 {
		return nil, DecompileOutput{}, errors.New("start_line must not be negative")
	}
	if in.MaxLines == 0 {
		in.MaxLines = 400
	}
	if in.MaxLines < 1 || in.MaxLines > 5000 {
		return nil, DecompileOutput{}, errors.New("max_lines must be 1..5000")
	}
	_, _ = t.R2.Cmd(ctx, "e asm.emu=true; e anal.jmp.after=true; e anal.hasnext=true")
	backends := []struct{ name, cmd string }{{"r2ghidra", "pdg"}, {"pdd", "pdd"}, {"pdc", "pdc"}}
	if in.Backend != "" && in.Backend != "auto" {
		found := false
		for i, b := range backends {
			if b.name == in.Backend {
				backends = []struct{ name, cmd string }{backends[i]}
				found = true
				break
			}
		}
		if !found {
			return nil, DecompileOutput{}, errors.New("backend must be auto, r2ghidra, pdd, or pdc")
		}
	}
	var failures []string
	var attempts []BackendAttempt
	for _, b := range backends {
		started := time.Now()
		out, e := t.R2.Cmd(ctx, b.cmd+" @ "+in.Address)
		reason := decompilerFailureReason(out, e)
		attempt := BackendAttempt{Backend: b.name, Status: "failed", Reason: reason, DurationMS: time.Since(started).Milliseconds()}
		if reason == "" {
			attempt.Status = "selected"
			attempts = append(attempts, attempt)
			lines := strings.Split(out, "\n")
			start := min(in.StartLine, len(lines))
			end := min(len(lines), start+in.MaxLines)
			return nil, DecompileOutput{Target: t.Name, Backend: b.name, Code: strings.Join(lines[start:end], "\n"), StartLine: start, NextLine: end, TotalLines: len(lines), Truncated: end < len(lines), Attempts: attempts}, nil
		}
		attempts = append(attempts, attempt)
		failures = append(failures, b.name)
	}
	return nil, DecompileOutput{}, fmt.Errorf("no usable decompiler backend (%s)", strings.Join(failures, ", "))
}

func decompilerFailureReason(out string, commandErr error) string {
	if commandErr != nil {
		return commandErr.Error()
	}
	lower := strings.ToLower(strings.TrimSpace(out))
	if lower == "" {
		return "empty output"
	}
	for _, marker := range []string{"not found", "cannot find", "need to install", "unknown command", "no decompiler", "error:"} {
		if strings.Contains(lower, marker) {
			trimmed := strings.TrimSpace(out)
			if len(trimmed) > 300 {
				trimmed = trimmed[:300] + "..."
			}
			return trimmed
		}
	}
	return ""
}

type EmulateInput struct {
	Target    string            `json:"target,omitempty"`
	Address   string            `json:"address"`
	Registers map[string]string `json:"registers,omitempty" jsonschema:"initial register values, e.g. {a0: 0x1000}"`
	Steps     int               `json:"steps,omitempty" jsonschema:"bounded ESIL steps; default 100, max 100000"`
	Trace     bool              `json:"trace,omitempty"`
}
type EmulateOutput struct {
	Target    string         `json:"target"`
	Registers map[string]any `json:"registers"`
	Trace     any            `json:"trace,omitempty"`
	Warning   string         `json:"warning,omitempty"`
}

func (s *Service) emulate(ctx context.Context, _ *mcp.CallToolRequest, in EmulateInput) (*mcp.CallToolResult, EmulateOutput, error) {
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, EmulateOutput{}, err
	}
	if _, err := parseAddress(in.Address); err != nil {
		return nil, EmulateOutput{}, err
	}
	if in.Steps == 0 {
		in.Steps = 100
	}
	if in.Steps < 1 || in.Steps > 100000 {
		return nil, EmulateOutput{}, errors.New("steps must be 1..100000")
	}
	if _, err = t.R2.Cmd(ctx, "s "+in.Address); err != nil {
		return nil, EmulateOutput{}, err
	}
	if _, err = t.R2.Cmd(ctx, "aeim; aei; aeip"); err != nil {
		return nil, EmulateOutput{}, err
	}
	if in.Trace {
		_, _ = t.R2.Cmd(ctx, "aets+")
	}
	for _, reg := range sortedKeys(in.Registers) {
		if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`).MatchString(reg) {
			return nil, EmulateOutput{}, fmt.Errorf("invalid register %q", reg)
		}
		if _, err := parseAddress(in.Registers[reg]); err != nil {
			return nil, EmulateOutput{}, fmt.Errorf("register %s: %w", reg, err)
		}
		if _, err = t.R2.Cmd(ctx, "aer "+reg+"="+in.Registers[reg]); err != nil {
			return nil, EmulateOutput{}, err
		}
	}
	if _, err = t.R2.Cmd(ctx, fmt.Sprintf("aes %d", in.Steps)); err != nil {
		return nil, EmulateOutput{}, err
	}
	out, err := t.R2.Cmd(ctx, "aerj")
	if err != nil {
		return nil, EmulateOutput{}, err
	}
	regs := map[string]any{}
	if err = json.Unmarshal([]byte(out), &regs); err != nil {
		return nil, EmulateOutput{}, err
	}
	result := EmulateOutput{Target: t.Name, Registers: regs}
	if in.Trace {
		traceOut, _ := t.R2.Cmd(ctx, "aet")
		_, _ = t.R2.Cmd(ctx, "aets-")
		if strings.TrimSpace(traceOut) == "" {
			result.Warning = "radare2 returned no ESIL trace for this target/version"
		}
		var trace any
		if json.Unmarshal([]byte(traceOut), &trace) == nil {
			result.Trace = trace
		} else {
			result.Trace = traceOut
		}
	}
	return nil, result, nil
}

type TypeDefineInput struct {
	Target     string `json:"target,omitempty"`
	Definition string `json:"definition" jsonschema:"C type declaration, e.g. struct record { int count; ... };"`
}

type TypeDefineOutput struct {
	OK           bool     `json:"ok"`
	Kind         string   `json:"kind,omitempty"`
	Name         string   `json:"name,omitempty"`
	Native       any      `json:"native,omitempty"`
	ReportedSize uint64   `json:"reported_size,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

func (s *Service) typeDefine(ctx context.Context, _ *mcp.CallToolRequest, in TypeDefineInput) (*mcp.CallToolResult, TypeDefineOutput, error) {
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, TypeDefineOutput{}, err
	}
	if err = safeTypeText(in.Definition); err != nil {
		return nil, TypeDefineOutput{}, err
	}
	kind, name := declaredType(in.Definition)
	result := TypeDefineOutput{Kind: kind, Name: name}
	out, err := t.R2.Cmd(ctx, "\"td "+in.Definition+"\"")
	if err == nil && strings.Contains(strings.ToLower(out), "error") {
		err = errors.New(out)
	}
	if err == nil {
		if name != "" {
			listCmd := map[string]string{"struct": "ts", "union": "tu", "enum": "te"}[kind]
			listing, listErr := t.R2.Cmd(ctx, listCmd)
			if listErr != nil {
				err = fmt.Errorf("verify type registration: %w", listErr)
			} else if !hasExactLine(listing, name) {
				err = fmt.Errorf("radare2 did not register %s %s", kind, name)
			}
		}
	}
	if err == nil && name != "" && (kind == "struct" || kind == "union") {
		inspectCmd := map[string]string{"struct": "tsj ", "union": "tuj "}[kind] + name
		if nativeOut, inspectErr := t.R2.Cmd(ctx, inspectCmd); inspectErr == nil {
			_ = decodeJSONNumbers(nativeOut, &result.Native)
		}
		if sizeOut, sizeErr := t.R2.Cmd(ctx, "tss "+name); sizeErr == nil {
			result.ReportedSize, _ = strconv.ParseUint(strings.TrimSpace(sizeOut), 0, 64)
		}
		if result.ReportedSize == 0 {
			result.Warnings = append(result.Warnings, "radare2 reported a zero layout size; treat native field offsets as unverified")
		}
	}
	result.OK = err == nil
	return nil, result, err
}

type TypeApplyInput struct {
	Target  string `json:"target,omitempty"`
	Type    string `json:"type"`
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
}

type TypeApplyOutput struct {
	OK             bool   `json:"ok"`
	RequestedType  string `json:"requested_type"`
	NormalizedType string `json:"normalized_type,omitempty"`
	Address        string `json:"address"`
	Name           string `json:"name,omitempty"`
	Link           string `json:"link,omitempty"`
	Warning        string `json:"warning,omitempty"`
}

func (s *Service) typeApply(ctx context.Context, _ *mcp.CallToolRequest, in TypeApplyInput) (*mcp.CallToolResult, TypeApplyOutput, error) {
	result := TypeApplyOutput{RequestedType: in.Type, Address: in.Address, Name: in.Name}
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, result, err
	}
	_, normalized, normalizeErr := normalizeTypeName(in.Type)
	if normalizeErr != nil {
		return nil, result, normalizeErr
	}
	result.NormalizedType = normalized
	if _, err = parseAddress(in.Address); err != nil {
		return nil, result, err
	}
	if in.Name != "" && !validIdentifier(in.Name) {
		return nil, result, errors.New("invalid instance name")
	}
	cmd := "tl " + normalized + " = " + in.Address
	if in.Name != "" {
		if _, err = t.R2.Cmd(ctx, "f "+in.Name+" @ "+in.Address); err != nil {
			return nil, result, err
		}
	}
	out, err := t.R2.Cmd(ctx, cmd)
	if err == nil {
		listing, listErr := t.R2.Cmd(ctx, "tls "+in.Address)
		switch {
		case listErr != nil:
			err = fmt.Errorf("verify type link: %w", listErr)
		case !strings.Contains(listing, "("+normalized+")"):
			err = fmt.Errorf("radare2 did not link type %s at %s", normalized, in.Address)
		default:
			result.Link = strings.TrimSpace(listing)
		}
	}
	result.OK = err == nil
	if strings.TrimSpace(out) != "" {
		result.Warning = strings.TrimSpace(out)
	}
	return nil, result, err
}

var naturalTypeNamePattern = regexp.MustCompile(`^\s*(?:(struct|union|enum)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*$`)

func normalizeTypeName(value string) (kind, name string, err error) {
	match := naturalTypeNamePattern.FindStringSubmatch(value)
	if len(match) != 3 {
		return "", "", errors.New("type must be a bare name or 'struct|union|enum name'")
	}
	return match[1], match[2], nil
}

type TypeInspectInput struct {
	Target  string `json:"target,omitempty"`
	Kind    string `json:"kind,omitempty" jsonschema:"struct, union, or enum"`
	Type    string `json:"type,omitempty"`
	Address string `json:"address,omitempty"`
}
type TypeLink struct {
	Type    string `json:"type"`
	Address uint64 `json:"address"`
}
type TypeInspectOutput struct {
	Target   string     `json:"target"`
	Kind     string     `json:"kind"`
	Type     string     `json:"type,omitempty"`
	Native   any        `json:"native,omitempty"`
	Links    []TypeLink `json:"links,omitempty"`
	Warnings []string   `json:"warnings,omitempty"`
}

func (s *Service) typeInspect(ctx context.Context, _ *mcp.CallToolRequest, in TypeInspectInput) (*mcp.CallToolResult, TypeInspectOutput, error) {
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, TypeInspectOutput{}, err
	}
	kind := in.Kind
	if kind == "" {
		kind = "struct"
	}
	cmdPrefix, ok := map[string]string{"struct": "tsj", "union": "tuj", "enum": "tej"}[kind]
	if !ok {
		return nil, TypeInspectOutput{}, errors.New("kind must be struct, union, or enum")
	}
	result := TypeInspectOutput{Target: t.Name, Kind: kind}
	if in.Type != "" {
		_, name, nameErr := normalizeTypeName(in.Type)
		if nameErr != nil {
			return nil, result, nameErr
		}
		result.Type = name
		cmdPrefix += " " + name
	}
	out, err := t.R2.Cmd(ctx, cmdPrefix)
	if err != nil {
		return nil, result, err
	}
	if decodeJSONNumbers(out, &result.Native) != nil {
		result.Native = strings.TrimSpace(out)
	}
	linksOut, _ := t.R2.Cmd(ctx, "tl*")
	linkRE := regexp.MustCompile(`(?m)^tl\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9a-fA-F]+)\s*$`)
	for _, match := range linkRE.FindAllStringSubmatch(linksOut, -1) {
		address, _ := strconv.ParseUint(match[2], 0, 64)
		result.Links = append(result.Links, TypeLink{Type: match[1], Address: address})
	}
	if in.Address != "" {
		address, parseErr := parseAddress(in.Address)
		if parseErr != nil {
			return nil, result, parseErr
		}
		result.Links = slices.DeleteFunc(result.Links, func(link TypeLink) bool { return link.Address != address })
	}
	if in.Type != "" && (kind == "struct" || kind == "union") {
		sizeOut, _ := t.R2.Cmd(ctx, "tss "+result.Type)
		size, _ := strconv.ParseUint(strings.TrimSpace(sizeOut), 0, 64)
		if size == 0 {
			result.Warnings = append(result.Warnings, "radare2 reported a zero layout size; treat native field offsets as unverified")
		}
	}
	return nil, result, nil
}

var declaredTypePattern = regexp.MustCompile(`^\s*(struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\b`)

func declaredType(definition string) (kind, name string) {
	match := declaredTypePattern.FindStringSubmatch(definition)
	if len(match) == 3 {
		return match[1], match[2]
	}
	return "", ""
}

func hasExactLine(output, wanted string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == wanted {
			return true
		}
	}
	return false
}

func safeTypeText(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("definition is required")
	}
	if strings.ContainsAny(s, "\r\n`|\"") || strings.Contains(s, "$(") || strings.Contains(s, ";!") {
		return errors.New("unsafe characters in type definition")
	}
	return nil
}

type DiffInput struct {
	Left       string  `json:"left"`
	Right      string  `json:"right"`
	MinScore   float64 `json:"min_score,omitempty"`
	MaxResults int     `json:"max_results,omitempty"`
}
type FunctionMatch struct {
	LeftAddress  uint64  `json:"left_address"`
	LeftName     string  `json:"left_name"`
	RightAddress uint64  `json:"right_address"`
	RightName    string  `json:"right_name"`
	Score        float64 `json:"score"`
	Basis        string  `json:"basis"`
}
type DiffOutput struct {
	Matches        []FunctionMatch `json:"matches"`
	UnmatchedLeft  int             `json:"unmatched_left"`
	UnmatchedRight int             `json:"unmatched_right"`
}
type functionInfo struct {
	Addr     uint64         `json:"addr"`
	Offset   uint64         `json:"offset"`
	Name     string         `json:"name"`
	Size     int            `json:"size"`
	Ninstr   int            `json:"ninstrs"`
	Features map[string]int `json:"-"`
	Hash     string         `json:"-"`
}
type opInfo struct {
	Type     string `json:"type"`
	Mnemonic string `json:"mnemonic"`
	Opcode   string `json:"opcode"`
	Family   string `json:"family"`
}

func (s *Service) diffFunctions(ctx context.Context, _ *mcp.CallToolRequest, in DiffInput) (*mcp.CallToolResult, DiffOutput, error) {
	left, err := s.ws.Get(in.Left)
	if err != nil {
		return nil, DiffOutput{}, err
	}
	right, err := s.ws.Get(in.Right)
	if err != nil {
		return nil, DiffOutput{}, err
	}
	if in.MinScore == 0 {
		in.MinScore = .72
	}
	if in.MinScore < 0 || in.MinScore > 1 {
		return nil, DiffOutput{}, errors.New("min_score must be 0..1")
	}
	ls, err := functionSignatures(ctx, left)
	if err != nil {
		return nil, DiffOutput{}, err
	}
	rs, err := functionSignatures(ctx, right)
	if err != nil {
		return nil, DiffOutput{}, err
	}
	used := map[int]bool{}
	hashes := map[string][]int{}
	names := map[string][]int{}
	buckets := map[string][]int{}
	for j, r := range rs {
		hashes[r.Hash] = append(hashes[r.Hash], j)
		if !isAutoName(r.Name) {
			names[canonicalFunction(r.Name)] = append(names[canonicalFunction(r.Name)], j)
		}
		buckets[functionBucket(r)] = append(buckets[functionBucket(r)], j)
	}
	result := DiffOutput{}
	for _, l := range ls {
		best := -1
		score := 0.0
		basis := "features"
		candidates := append([]int{}, hashes[l.Hash]...)
		if !isAutoName(l.Name) {
			candidates = append(candidates, names[canonicalFunction(l.Name)]...)
		}
		candidates = append(candidates, buckets[functionBucket(l)]...)
		seenCandidate := map[int]bool{}
		for _, j := range candidates {
			if seenCandidate[j] {
				continue
			}
			seenCandidate[j] = true
			if used[j] {
				continue
			}
			r := rs[j]
			candidate := featureScore(l, r)
			b := "features"
			if canonicalFunction(l.Name) == canonicalFunction(r.Name) && !isAutoName(l.Name) {
				candidate = math.Max(candidate, .98)
				b = "name"
			}
			if l.Hash != "" && l.Hash == r.Hash {
				candidate = 1
				b = "normalized instructions"
			}
			if candidate > score {
				score = candidate
				best = j
				basis = b
			}
		}
		if best >= 0 && score >= in.MinScore {
			r := rs[best]
			used[best] = true
			result.Matches = append(result.Matches, FunctionMatch{l.Offset, l.Name, r.Offset, r.Name, math.Round(score*1000) / 1000, basis})
		} else {
			result.UnmatchedLeft++
		}
	}
	result.UnmatchedRight = len(rs) - len(used)
	sort.Slice(result.Matches, func(i, j int) bool { return result.Matches[i].Score > result.Matches[j].Score })
	if in.MaxResults > 0 && len(result.Matches) > in.MaxResults {
		result.Matches = result.Matches[:in.MaxResults]
	}
	return nil, result, nil
}

func functionSignatures(ctx context.Context, t *workspace.Target) ([]functionInfo, error) {
	out, err := t.R2.Cmd(ctx, "aflj")
	if err != nil {
		return nil, err
	}
	var fs []functionInfo
	if err = json.Unmarshal([]byte(out), &fs); err != nil {
		return nil, err
	}
	filtered := fs[:0]
	for i := range fs {
		if fs[i].Offset == 0 {
			fs[i].Offset = fs[i].Addr
		}
		if fs[i].Offset == 0 || fs[i].Size <= 0 {
			continue
		}
		count := fs[i].Ninstr
		if count <= 0 {
			count = 64
		}
		if count > 512 {
			count = 512
		}
		opsOut, e := t.R2.Cmd(ctx, fmt.Sprintf("aoj %d @ 0x%x", count, fs[i].Offset))
		if e != nil {
			continue
		}
		var ops []opInfo
		if json.Unmarshal([]byte(opsOut), &ops) != nil {
			continue
		}
		fs[i].Features = map[string]int{}
		var norm strings.Builder
		for _, op := range ops {
			key := op.Type + ":" + op.Family
			if key == ":" {
				fields := strings.Fields(op.Opcode)
				if len(fields) == 0 {
					continue
				}
				key = fields[0]
			}
			fs[i].Features[key]++
			norm.WriteString(key)
			norm.WriteByte(';')
		}
		sum := sha256.Sum256([]byte(norm.String()))
		if norm.Len() > 0 {
			fs[i].Hash = hex.EncodeToString(sum[:])
		}
		filtered = append(filtered, fs[i])
	}
	return filtered, nil
}
func featureScore(a, b functionInfo) float64 {
	if len(a.Features) == 0 || len(b.Features) == 0 {
		return 0
	}
	intersection, total := 0, 0
	keys := map[string]bool{}
	for k := range a.Features {
		keys[k] = true
	}
	for k := range b.Features {
		keys[k] = true
	}
	for k := range keys {
		x, y := a.Features[k], b.Features[k]
		if x < y {
			intersection += x
		} else {
			intersection += y
		}
		if x > y {
			total += x
		} else {
			total += y
		}
	}
	j := float64(intersection) / float64(total)
	size := 1 - math.Abs(float64(a.Size-b.Size))/math.Max(1, float64(max(a.Size, b.Size)))
	return .75*j + .25*math.Max(0, size)
}
func functionBucket(f functionInfo) string {
	dominant, count := "none", 0
	for feature, n := range f.Features {
		if n > count {
			dominant, count = feature, n
		}
	}
	return dominant + ":" + strconv.Itoa(f.Size/32)
}
func canonicalFunction(s string) string {
	for _, p := range []string{"sym.", "fcn.", "sub.", "loc."} {
		s = strings.TrimPrefix(s, p)
	}
	return s
}
func isAutoName(s string) bool {
	return strings.HasPrefix(s, "fcn.") || strings.HasPrefix(s, "sub.") || strings.HasPrefix(s, "loc.")
}

type KernelSymbolsInput struct {
	Target     string `json:"target,omitempty"`
	SymbolFile string `json:"symbol_file,omitempty"`
	Mode       string `json:"mode,omitempty" jsonschema:"auto, absolute, or prel32"`
	MaxSymbols int    `json:"max_symbols,omitempty"`
}
type KernelSymbol struct {
	Address uint64 `json:"address"`
	Name    string `json:"name"`
	Source  string `json:"source"`
}
type KernelSymbolsOutput struct {
	Target  string         `json:"target"`
	Symbols []KernelSymbol `json:"symbols"`
}

func (s *Service) loadKernelSymbols(ctx context.Context, _ *mcp.CallToolRequest, in KernelSymbolsInput) (*mcp.CallToolResult, KernelSymbolsOutput, error) {
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, KernelSymbolsOutput{}, err
	}
	var symbols []KernelSymbol
	if in.SymbolFile != "" {
		path, pathErr := s.ws.ResolvePath(in.SymbolFile, true)
		if pathErr != nil {
			return nil, KernelSymbolsOutput{}, pathErr
		}
		symbols, err = parseSymbolFile(path)
	} else {
		symbols, err = scanKernelSymbols(t, in.Mode, in.MaxSymbols)
	}
	if err != nil {
		return nil, KernelSymbolsOutput{}, err
	}
	if in.MaxSymbols > 0 && len(symbols) > in.MaxSymbols {
		symbols = symbols[:in.MaxSymbols]
	}
	for _, sym := range symbols {
		if !validIdentifier(sym.Name) {
			continue
		}
		if _, err = t.R2.Cmd(ctx, fmt.Sprintf("f kernel.%s = 0x%x", sym.Name, sym.Address)); err != nil {
			return nil, KernelSymbolsOutput{}, err
		}
	}
	return nil, KernelSymbolsOutput{t.Name, symbols}, nil
}

func parseSymbolFile(path string) ([]KernelSymbol, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []KernelSymbol
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		addr, e := strconv.ParseUint(f[0], 16, 64)
		if e != nil {
			continue
		}
		name := f[len(f)-1]
		if !validIdentifier(name) {
			continue
		}
		out = append(out, KernelSymbol{addr, name, fmt.Sprintf("%s:%d", path, i+1)})
	}
	if len(out) == 0 {
		return nil, errors.New("symbol file contained no address/name records")
	}
	return out, nil
}

func scanKernelSymbols(t *workspace.Target, mode string, maxSymbols int) ([]KernelSymbol, error) {
	if strings.HasPrefix(t.Path, "gdb://") {
		return nil, errors.New("automatic ksymtab scan requires a file target")
	}
	b, err := os.ReadFile(t.Path)
	if err != nil {
		return nil, err
	}
	if mode == "" || mode == "auto" {
		mode = "both"
	}
	if mode != "both" && mode != "absolute" && mode != "prel32" {
		return nil, errors.New("mode must be auto, absolute, or prel32")
	}
	var order binary.ByteOrder = binary.LittleEndian
	if strings.EqualFold(t.Endian, "big") || strings.EqualFold(t.Endian, "be") {
		order = binary.BigEndian
	}
	width := t.Bits / 8
	if width != 4 && width != 8 {
		width = 4
	}
	// Candidate export names are NUL-terminated identifiers of useful length.
	type candidate struct {
		off  int
		name string
	}
	var names []candidate
	for i := 0; i < len(b); {
		j := i
		for j < len(b) && b[j] != 0 {
			j++
		}
		if j > i+2 && j-i < 128 {
			name := string(b[i:j])
			if validIdentifier(name) {
				names = append(names, candidate{i, name})
			}
		}
		i = j + 1
	}
	var out []KernelSymbol
	seen := map[string]bool{}
	add := func(addr uint64, name, source string) {
		if addr < t.Base || addr >= t.Base+uint64(len(b)) || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, KernelSymbol{addr, name, source})
	}
	nameAtOffset := map[uint64]string{}
	for _, n := range names {
		nameAtOffset[uint64(n.off)] = n.name
	}
	for off := 0; off+width*2 <= len(b); off += 4 {
		if mode == "both" || mode == "absolute" {
			nameAddr := readWord(b[off+width:off+width*2], order, width)
			if nameAddr >= t.Base {
				if name, ok := nameAtOffset[nameAddr-t.Base]; ok {
					add(readWord(b[off:off+width], order, width), name, "__ksymtab:absolute")
				}
			}
		}
		if (mode == "both" || mode == "prel32") && off+8 <= len(b) {
			nameRel := int64(int32(order.Uint32(b[off+4 : off+8])))
			nameOffset := int64(off+4) + nameRel
			if nameOffset >= 0 {
				if name, ok := nameAtOffset[uint64(nameOffset)]; ok {
					valueRel := int64(int32(order.Uint32(b[off : off+4])))
					add(uint64(int64(t.Base)+int64(off)+valueRel), name, "__ksymtab:prel32")
				}
			}
		}
		if maxSymbols > 0 && len(out) >= maxSymbols {
			break
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no __ksymtab entries recovered; provide symbol_file or explicit endian/bits/base")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address < out[j].Address })
	return out, nil
}
func readWord(b []byte, order binary.ByteOrder, width int) uint64 {
	if width == 8 {
		return order.Uint64(b)
	}
	return uint64(order.Uint32(b))
}
