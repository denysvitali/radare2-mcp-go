package server

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/denysvitali/radare2-mcp-go/internal/workspace"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const Version = "0.3.0"

var identifierRE = regexp.MustCompile(`^[A-Za-z_.$][A-Za-z0-9_.$:-]*$`)

type Service struct {
	ws *workspace.Workspace
}

func New(ws *workspace.Workspace) *mcp.Server {
	svc := &Service{ws: ws}
	s := mcp.NewServer(&mcp.Implementation{Name: "radare2-mcp", Version: Version}, &mcp.ServerOptions{Instructions: "Use named workspace targets to keep every binary alive at once. Open each participant with workspace_open, run analyze at the needed depth, then use cross_binary_xrefs, string_xrefs, or recover_dispatch_table for evidence-bearing reachability. Prefer focused typed tools; use r2_command only for capabilities they do not expose. Save multi-day work with workspace_save. A target argument defaults to the selected target. Heuristic matches and emulation are evidence, not proof of runtime reachability."})
	s.AddReceivingMiddleware(timingMiddleware)
	mcp.AddTool(s, writeTool("workspace_open", "Open a binary as a named target without closing or altering other targets. Supports raw base/architecture/endian and local gdb:// endpoints.", false), svc.workspaceOpen)
	mcp.AddTool(s, readTool("workspace_list", "List every simultaneously open target and the selected default."), svc.workspaceList)
	mcp.AddTool(s, writeTool("workspace_select", "Select the default target used when a target argument is omitted.", false), svc.workspaceSelect)
	mcp.AddTool(s, writeTool("workspace_close", "Close one target while preserving every other target and its analysis.", true), svc.workspaceClose)
	mcp.AddTool(s, writeTool("workspace_save", "Atomically save the workspace manifest and one native radare2 project per target.", false), svc.workspaceSave)
	mcp.AddTool(s, writeTool("workspace_load", "Restore all binaries, analysis, names, comments, types, and the selected target from a saved workspace.", false), svc.workspaceLoad)
	mcp.AddTool(s, writeTool("workspace_delete", "Delete a saved workspace only after validation and explicit confirmation. Refuses directories containing unexpected files.", true), svc.workspaceDelete)
	mcp.AddTool(s, writeTool("analyze", "Analyze a target. Full mode explicitly runs data-reference recovery even on raw images with a nonzero mapped base.", false), svc.analyze)
	mcp.AddTool(s, readTool("analysis_status", "Report persisted analysis passes, freshness, function counts, and missing work for one or all targets."), svc.analysisStatus)
	mcp.AddTool(s, readTool("capabilities", "Report server policy plus live radare2, decompiler, ESIL, and analysis capabilities."), svc.capabilities)
	mcp.AddTool(s, readTool("search", "Search without the old sandbox-range failure. Supports string, wide, hex/opcode, numeric value, assembly, regex, explicit ranges, and all-target scope."), svc.search)
	mcp.AddTool(s, readTool("search_gadgets", "Search return/call/jump gadgets using r2 /g (and legacy /R fallback), filtered by registers written, depth, end opcode, class, and result count."), svc.searchGadgets)
	mcp.AddTool(s, readTool("list_strings", "List discovered or whole-file strings with virtual and physical addresses."), svc.listStrings)
	mcp.AddTool(s, readTool("string_xrefs", "Find a string and direct plus two-step references through pointer slots, including MIPS RW-slot patterns."), svc.stringXrefs)
	mcp.AddTool(s, readTool("recover_dispatch_table", "Enumerate an indirect dispatch table and recover reachability evidence through direct refs, pointer slots, and their consumers, including GP-relative MIPS slot loads followed by negative addiu adjustments."), svc.recoverDispatchTable)
	mcp.AddTool(s, readTool("cross_binary_xrefs", "Resolve imports in every open binary against exports, symbols, and shared workspace flags in every other binary."), svc.crossBinaryXrefs)
	mcp.AddTool(s, writeTool("load_kernel_symbols", "Name a raw kernel from System.map/kallsyms text, or recover classic absolute/PREL32 __ksymtab entries by scanning the image.", false), svc.loadKernelSymbols)
	mcp.AddTool(s, readTool("decompile", "Decompile with r2ghidra first when installed, retaining target architecture and MIPS delay-slot settings, with safe fallbacks."), svc.decompile)
	mcp.AddTool(s, writeTool("emulate_function", "Run bounded per-function ESIL emulation with initial register arguments and return final registers plus ESIL trace.", false), svc.emulate)
	mcp.AddTool(s, writeTool("type_define", "Define C structs/types in a target's native r2 type database.", false), svc.typeDefine)
	mcp.AddTool(s, writeTool("type_apply", "Apply a defined type to an address so analysis and capable decompilers can use it.", false), svc.typeApply)
	mcp.AddTool(s, readTool("type_inspect", "Inspect native radare2 type definitions and address links, including layout reliability warnings."), svc.typeInspect)
	mcp.AddTool(s, readTool("diff_functions", "Match functions across binary versions using normalized instruction features, names, and similarity scores."), svc.diffFunctions)
	mcp.AddTool(s, writeTool("r2_command", "Raw r2 command escape hatch. Shell escapes and command chaining are rejected unless the server starts with --allow-unsafe-commands.", true), svc.r2Command)
	mcp.AddTool(s, readTool("inspect", "Run common address-aware read operations: info, functions, imports, exports, symbols, sections, xrefs, disassembly, function disassembly, hexdump, or registers."), svc.inspect)
	mcp.AddTool(s, writeTool("annotate", "Rename a function/flag, set a comment or function prototype; persisted by workspace_save.", true), svc.annotate)
	return s
}

func timingMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		started := time.Now()
		result, err := next(ctx, method, req)
		if method == "tools/call" {
			if call, ok := result.(*mcp.CallToolResult); ok {
				compactDuplicatedStructuredContent(call)
				if call.Meta == nil {
					call.Meta = mcp.Meta{}
				}
				call.Meta["duration_ms"] = time.Since(started).Milliseconds()
			}
		}
		return result, err
	}
}

const structuredResultSummary = "Structured result returned."

// AddTool mirrors typed structured output into a text block for clients that do
// not support structuredContent. That doubles every successful tool result for
// clients that retain both representations, which is especially expensive for
// disassembly and cross-reference results. Replace only that exact SDK-generated
// mirror; explicitly authored content is left untouched.
func compactDuplicatedStructuredContent(call *mcp.CallToolResult) {
	if call.StructuredContent == nil || len(call.Content) != 1 {
		return
	}
	text, ok := call.Content[0].(*mcp.TextContent)
	if !ok {
		return
	}
	structured, err := json.Marshal(call.StructuredContent)
	if err != nil || text.Text != string(structured) {
		return
	}
	text.Text = structuredResultSummary
}

func notifyProgress(ctx context.Context, req *mcp.CallToolRequest, done, total int, message string) {
	if req == nil || req.Params == nil || req.Session == nil {
		return
	}
	token := req.Params.GetProgressToken()
	if token == nil {
		return
	}
	_ = req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: token, Progress: float64(done), Total: float64(total), Message: message})
}

func readTool(name, description string) *mcp.Tool {
	closedWorld := false
	return &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: boolPtr(false), IdempotentHint: true, OpenWorldHint: &closedWorld}}
}

func writeTool(name, description string, destructive bool) *mcp.Tool {
	closedWorld := false
	return &mcp.Tool{Name: name, Description: description, Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive, OpenWorldHint: &closedWorld}}
}

func boolPtr(value bool) *bool { return &value }

type OpenInput struct {
	Name   string `json:"name" jsonschema:"short unique target name"`
	Path   string `json:"path" jsonschema:"absolute binary path or local gdb:// endpoint"`
	Base   string `json:"base,omitempty" jsonschema:"raw image base address, for example 0x80010000"`
	Arch   string `json:"arch,omitempty" jsonschema:"architecture override such as mips"`
	Bits   int    `json:"bits,omitempty" jsonschema:"bit width override"`
	CPU    string `json:"cpu,omitempty" jsonschema:"CPU override"`
	Endian string `json:"endian,omitempty" jsonschema:"auto, big, or little"`
	Debug  bool   `json:"debug,omitempty" jsonschema:"open as a debugger target"`
}

type TargetOutput struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

func (s *Service) workspaceOpen(ctx context.Context, _ *mcp.CallToolRequest, in OpenInput) (*mcp.CallToolResult, TargetOutput, error) {
	base, err := parseOptionalAddress(in.Base)
	if err != nil {
		return nil, TargetOutput{}, err
	}
	t, err := s.ws.Open(ctx, workspace.Target{Name: in.Name, Path: in.Path, Base: base, Arch: in.Arch, Bits: in.Bits, CPU: in.CPU, Endian: in.Endian, Debug: in.Debug})
	if err != nil {
		return nil, TargetOutput{}, err
	}
	return nil, TargetOutput{Name: t.Name, Path: t.Path}, nil
}

type EmptyInput struct{}
type ListOutput struct {
	Selected string             `json:"selected,omitempty"`
	Targets  []workspace.Target `json:"targets"`
}

func (s *Service) workspaceList(context.Context, *mcp.CallToolRequest, EmptyInput) (*mcp.CallToolResult, ListOutput, error) {
	t, selected := s.ws.List()
	return nil, ListOutput{Selected: selected, Targets: t}, nil
}

type NameInput struct {
	Name string `json:"name" jsonschema:"target name"`
}
type StatusOutput struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

func (s *Service) workspaceSelect(_ context.Context, _ *mcp.CallToolRequest, in NameInput) (*mcp.CallToolResult, StatusOutput, error) {
	err := s.ws.Select(in.Name)
	return nil, StatusOutput{OK: err == nil}, err
}
func (s *Service) workspaceClose(_ context.Context, _ *mcp.CallToolRequest, in NameInput) (*mcp.CallToolResult, StatusOutput, error) {
	err := s.ws.Close(in.Name)
	return nil, StatusOutput{OK: err == nil}, err
}

type PathInput struct {
	Path string `json:"path" jsonschema:"workspace directory"`
}

func (s *Service) workspaceSave(ctx context.Context, req *mcp.CallToolRequest, in PathInput) (*mcp.CallToolResult, StatusOutput, error) {
	err := s.ws.SaveWithProgress(ctx, in.Path, func(done, total int, target string) { notifyProgress(ctx, req, done, total, "saved "+target) })
	return nil, StatusOutput{OK: err == nil}, err
}
func (s *Service) workspaceLoad(ctx context.Context, req *mcp.CallToolRequest, in PathInput) (*mcp.CallToolResult, StatusOutput, error) {
	err := s.ws.LoadWithProgress(ctx, in.Path, func(done, total int, target string) { notifyProgress(ctx, req, done, total, "loaded "+target) })
	return nil, StatusOutput{OK: err == nil}, err
}

type DeleteInput struct {
	Path    string `json:"path" jsonschema:"saved workspace directory"`
	Confirm bool   `json:"confirm" jsonschema:"must be true to authorize deletion"`
}
type DeleteOutput struct {
	OK      bool     `json:"ok"`
	Removed []string `json:"removed,omitempty"`
}

func (s *Service) workspaceDelete(_ context.Context, _ *mcp.CallToolRequest, in DeleteInput) (*mcp.CallToolResult, DeleteOutput, error) {
	if !in.Confirm {
		return nil, DeleteOutput{}, errors.New("confirm must be true")
	}
	removed, err := s.ws.DeleteProject(in.Path)
	return nil, DeleteOutput{OK: err == nil, Removed: removed}, err
}

type TargetInput struct {
	Target string `json:"target,omitempty" jsonschema:"target name; defaults to selected"`
}
type AnalyzeInput struct {
	Target         string `json:"target,omitempty"`
	Level          string `json:"level,omitempty" jsonschema:"basic, standard, full, or exhaustive"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"zero uses the request deadline"`
	Force          bool   `json:"force,omitempty" jsonschema:"rerun passes already recorded as complete"`
}
type CommandOutput struct {
	Target        string         `json:"target"`
	Output        string         `json:"output,omitempty"`
	Data          any            `json:"data,omitempty"`
	Passes        []AnalysisPass `json:"passes,omitempty"`
	FunctionCount int            `json:"function_count,omitempty"`
	Total         int            `json:"total,omitempty"`
	Start         int            `json:"start,omitempty"`
	Count         int            `json:"count,omitempty"`
	Truncated     bool           `json:"truncated,omitempty"`
	SkippedPasses []string       `json:"skipped_passes,omitempty"`
}

type AnalysisPass struct {
	Command string `json:"command"`
	Output  string `json:"output,omitempty"`
}

func (s *Service) analyze(ctx context.Context, req *mcp.CallToolRequest, in AnalyzeInput) (*mcp.CallToolResult, CommandOutput, error) {
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, CommandOutput{}, err
	}
	if in.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(in.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	level := in.Level
	if level == "" {
		level = "standard"
	}
	passes, err := analysisPasses(level)
	if err != nil {
		return nil, CommandOutput{}, err
	}
	state, _ := s.ws.Analysis(t.Name)
	completed := make(map[string]bool, len(state.CompletedPasses))
	for _, pass := range state.CompletedPasses {
		completed[pass] = true
	}
	result := CommandOutput{Target: t.Name}
	if in.Force || state.Stale {
		completed = map[string]bool{}
	}
	var pending []string
	for _, pass := range passes {
		if completed[pass] {
			result.SkippedPasses = append(result.SkippedPasses, pass)
		} else {
			pending = append(pending, pass)
		}
	}
	started := time.Now()
	for i, command := range pending {
		notifyProgress(ctx, req, i, len(pending), "running "+command)
		out, cmdErr := t.R2.Cmd(ctx, command)
		if cmdErr != nil {
			return nil, result, fmt.Errorf("analysis pass %s: %w", command, cmdErr)
		}
		result.Passes = append(result.Passes, AnalysisPass{Command: command, Output: out})
		completed[command] = true
		notifyProgress(ctx, req, i+1, len(pending), "completed "+command)
	}
	count, countErr := t.R2.Cmd(ctx, "aflc")
	if countErr == nil {
		result.FunctionCount, _ = strconv.Atoi(strings.TrimSpace(count))
	}
	allCompleted := make([]string, 0, len(completed))
	for _, pass := range passes {
		if completed[pass] {
			allCompleted = append(allCompleted, pass)
		}
	}
	_ = s.ws.UpdateAnalysis(t.Name, func(update *workspace.AnalysisState) {
		update.Level = level
		update.CompletedPasses = allCompleted
		update.FunctionCount = result.FunctionCount
		update.DurationMS = time.Since(started).Milliseconds()
		update.UpdatedAt = time.Now().UTC()
		update.Stale = false
	})
	return nil, result, nil
}

func analysisPasses(level string) ([]string, error) {
	switch level {
	case "basic":
		return []string{"aa"}, nil
	case "standard":
		return []string{"aa", "aap", "aac", "aar", "aanr"}, nil
	case "full":
		return []string{"aa", "aap", "aac", "aar", "aad", "aav0", "aaf", "aanr", "aax"}, nil
	case "exhaustive":
		return []string{"aa", "aap", "aac", "aar", "aad", "aav0", "aaf", "aanr", "aax", "aaef", "aaj", "aat", "aaw"}, nil
	default:
		return nil, errors.New("level must be basic, standard, full, or exhaustive")
	}
}

type AnalysisStatusInput struct {
	Target string `json:"target,omitempty"`
	Scope  string `json:"scope,omitempty" jsonschema:"target or all"`
	Level  string `json:"level,omitempty" jsonschema:"desired basic, standard, full, or exhaustive level"`
}
type TargetAnalysisStatus struct {
	Target        string                  `json:"target"`
	Identity      workspace.FileIdentity  `json:"identity"`
	Analysis      workspace.AnalysisState `json:"analysis"`
	MissingPasses []string                `json:"missing_passes,omitempty"`
	NeedsAnalysis bool                    `json:"needs_analysis"`
}
type AnalysisStatusOutput struct {
	Targets []TargetAnalysisStatus `json:"targets"`
}

func (s *Service) analysisStatus(_ context.Context, _ *mcp.CallToolRequest, in AnalysisStatusInput) (*mcp.CallToolResult, AnalysisStatusOutput, error) {
	targets, err := s.targets(in.Target, in.Scope)
	if err != nil {
		return nil, AnalysisStatusOutput{}, err
	}
	level := in.Level
	if level == "" {
		level = "standard"
	}
	passes, err := analysisPasses(level)
	if err != nil {
		return nil, AnalysisStatusOutput{}, err
	}
	out := AnalysisStatusOutput{}
	for _, target := range targets {
		state, _ := s.ws.Analysis(target.Name)
		done := map[string]bool{}
		for _, pass := range state.CompletedPasses {
			done[pass] = true
		}
		status := TargetAnalysisStatus{Target: target.Name, Identity: target.Identity, Analysis: state}
		for _, pass := range passes {
			if !done[pass] || state.Stale {
				status.MissingPasses = append(status.MissingPasses, pass)
			}
		}
		status.NeedsAnalysis = len(status.MissingPasses) > 0
		out.Targets = append(out.Targets, status)
	}
	return nil, out, nil
}

type SearchInput struct {
	Target     string `json:"target,omitempty"`
	Scope      string `json:"scope,omitempty" jsonschema:"target or all"`
	Type       string `json:"type,omitempty" jsonschema:"string, wide, hex, opcode, value, assembly, or regex"`
	Query      string `json:"query"`
	ValueSize  int    `json:"value_size,omitempty"`
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"`
	MaxResults int    `json:"max_results,omitempty"`
}
type SearchTargetResult struct {
	Target string `json:"target"`
	Hits   any    `json:"hits"`
}
type SearchOutput struct {
	RequestedType string               `json:"requested_type"`
	Encoding      string               `json:"encoding"`
	Results       []SearchTargetResult `json:"results"`
}

func (s *Service) search(ctx context.Context, _ *mcp.CallToolRequest, in SearchInput) (*mcp.CallToolResult, SearchOutput, error) {
	if in.Query == "" {
		return nil, SearchOutput{}, errors.New("query is required")
	}
	targets, err := s.targets(in.Target, in.Scope)
	if err != nil {
		return nil, SearchOutput{}, err
	}
	cmd, err := searchCommand(in)
	if err != nil {
		return nil, SearchOutput{}, err
	}
	requestedType := strings.ToLower(in.Type)
	if requestedType == "" {
		requestedType = "string"
	}
	result := SearchOutput{RequestedType: requestedType, Encoding: searchEncoding(requestedType)}
	for _, t := range targets {
		out, err := t.R2.Cmd(ctx, cmd)
		if err != nil {
			return nil, result, fmt.Errorf("%s: %w", t.Name, err)
		}
		var hits any
		if err := decodeJSONNumbers(out, &hits); err != nil {
			hits = out
		}
		result.Results = append(result.Results, SearchTargetResult{Target: t.Name, Hits: hits})
	}
	return nil, result, nil
}

func searchEncoding(kind string) string {
	switch kind {
	case "string":
		return "UTF-8 bytes"
	case "wide":
		return "Latin-1 code units encoded as UTF-16LE"
	case "hex", "opcode":
		return "hexadecimal bytes"
	case "value":
		return "numeric value in target endianness"
	case "assembly":
		return "radare2 assembler syntax"
	case "regex":
		return "radare2 regular expression"
	default:
		return "unknown"
	}
}

func searchCommand(in SearchInput) (string, error) {
	prefix := ""
	if in.From != "" {
		if _, err := parseAddress(in.From); err != nil {
			return "", fmt.Errorf("from: %w", err)
		}
		prefix += "e search.from=" + in.From + "; "
	}
	if in.To != "" {
		if _, err := parseAddress(in.To); err != nil {
			return "", fmt.Errorf("to: %w", err)
		}
		prefix += "e search.to=" + in.To + "; "
	}
	if in.MaxResults <= 0 {
		in.MaxResults = 1000
	}
	prefix += fmt.Sprintf("e search.maxhits=%d; ", in.MaxResults)
	typ := strings.ToLower(in.Type)
	var cmd string
	switch typ {
	case "", "string":
		cmd = "/xj " + hex.EncodeToString([]byte(in.Query))
	case "wide":
		var b strings.Builder
		for _, r := range in.Query {
			if r > 255 {
				return "", errors.New("wide search currently accepts Latin-1 text")
			}
			fmt.Fprintf(&b, "%02x00", r)
		}
		cmd = "/xj " + b.String()
	case "hex", "opcode":
		q := strings.ReplaceAll(strings.ReplaceAll(in.Query, " ", ""), "0x", "")
		if _, err := hex.DecodeString(q); err != nil {
			return "", fmt.Errorf("invalid hex query: %w", err)
		}
		cmd = "/xj " + q
	case "value":
		if _, err := parseAddress(in.Query); err != nil {
			return "", err
		}
		suffix := map[int]string{1: "1", 2: "2", 4: "4", 8: "8"}[in.ValueSize]
		if suffix == "" && in.ValueSize != 0 {
			return "", errors.New("value_size must be 1, 2, 4, or 8")
		}
		cmd = "/v" + suffix + "j " + in.Query
	case "assembly":
		if strings.ContainsAny(in.Query, "\r\n;") {
			return "", errors.New("assembly query contains a command delimiter")
		}
		cmd = "/aj " + in.Query
	case "regex":
		if strings.ContainsAny(in.Query, "\r\n;") {
			return "", errors.New("regex query contains a command delimiter")
		}
		cmd = "/ej " + in.Query
	default:
		return "", fmt.Errorf("unsupported search type %q", in.Type)
	}
	return prefix + cmd, nil
}

func (s *Service) targets(name, scope string) ([]*workspace.Target, error) {
	if scope == "all" {
		all, _ := s.ws.List()
		out := make([]*workspace.Target, 0, len(all))
		for _, spec := range all {
			t, _ := s.ws.Get(spec.Name)
			out = append(out, t)
		}
		if len(out) == 0 {
			return nil, errors.New("workspace is empty")
		}
		return out, nil
	}
	t, err := s.ws.Get(name)
	if err != nil {
		return nil, err
	}
	return []*workspace.Target{t}, nil
}

type GadgetInput struct {
	Target           string   `json:"target,omitempty"`
	Kind             string   `json:"kind,omitempty" jsonschema:"return, call, jump, or all"`
	Contains         string   `json:"contains,omitempty"`
	RegistersWritten []string `json:"registers_written,omitempty"`
	MaxDepth         int      `json:"max_depth,omitempty"`
	EndOpcode        string   `json:"end_opcode,omitempty"`
	Class            string   `json:"class,omitempty"`
	MaxResults       int      `json:"max_results,omitempty"`
	Alignment        int      `json:"alignment,omitempty" jsonschema:"required gadget address alignment; defaults to architecture alignment"`
	ExecutableOnly   bool     `json:"executable_only,omitempty"`
}
type GadgetOpcode struct {
	Addr   uint64 `json:"addr"`
	Size   int    `json:"size"`
	Opcode string `json:"opcode"`
	Type   string `json:"type"`
}
type Gadget struct {
	Address        uint64              `json:"address"`
	Opcodes        []GadgetOpcode      `json:"opcodes"`
	RetAddr        uint64              `json:"retaddr"`
	Size           int                 `json:"size"`
	Classes        []string            `json:"classes"`
	Section        string              `json:"section,omitempty"`
	Executable     bool                `json:"executable"`
	Aligned        bool                `json:"aligned"`
	MatchedFilters []string            `json:"matched_filters,omitempty"`
	RegisterWrites map[string][]string `json:"register_writes,omitempty"`
}
type GadgetOutput struct {
	Target  string   `json:"target"`
	Gadgets []Gadget `json:"gadgets"`
}

func (s *Service) searchGadgets(ctx context.Context, _ *mcp.CallToolRequest, in GadgetInput) (*mcp.CallToolResult, GadgetOutput, error) {
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, GadgetOutput{}, err
	}
	if strings.ContainsAny(in.Contains+in.EndOpcode, "\r\n;") {
		return nil, GadgetOutput{}, errors.New("gadget filter contains a command delimiter")
	}
	if in.Alignment < 0 {
		return nil, GadgetOutput{}, errors.New("alignment must not be negative")
	}
	if in.Alignment == 0 {
		in.Alignment = architectureAlignment(t.Arch)
	}
	sections := readSections(ctx, t)
	mode := map[string]string{"": "/gj", "all": "/gj", "return": "/gRj", "call": "/gCj", "jump": "/gJj"}[in.Kind]
	if mode == "" {
		return nil, GadgetOutput{}, errors.New("kind must be return, call, jump, or all")
	}
	out, err := t.R2.Cmd(ctx, "e search.maxhits=100000; "+mode+" "+in.Contains)
	if err != nil {
		return nil, GadgetOutput{}, err
	}
	var gadgets []Gadget
	if err := json.Unmarshal([]byte(out), &gadgets); err != nil {
		// radare2 < 6 uses /R. Keep compatibility without making the caller care.
		out, err = t.R2.Cmd(ctx, "e search.maxhits=100000; /Rj "+in.Contains)
		if err != nil {
			return nil, GadgetOutput{}, err
		}
		if err := json.Unmarshal([]byte(out), &gadgets); err != nil {
			return nil, GadgetOutput{}, fmt.Errorf("decode gadget search: %w", err)
		}
	}
	filtered := gadgets[:0]
	for _, g := range gadgets {
		if len(g.Opcodes) > 0 {
			g.Address = g.Opcodes[0].Addr
		}
		g.Aligned = g.Address%uint64(in.Alignment) == 0
		g.Section, g.Executable = sectionForAddress(sections, g.Address)
		if !g.Aligned || (in.ExecutableOnly && !g.Executable) {
			continue
		}
		g.MatchedFilters = []string{fmt.Sprintf("alignment:%d", in.Alignment)}
		if in.ExecutableOnly {
			g.MatchedFilters = append(g.MatchedFilters, "executable_section")
		}
		if in.MaxDepth > 0 && len(g.Opcodes) > in.MaxDepth {
			continue
		}
		if in.EndOpcode != "" && (len(g.Opcodes) == 0 || !strings.Contains(strings.ToLower(g.Opcodes[len(g.Opcodes)-1].Opcode), strings.ToLower(in.EndOpcode))) {
			continue
		}
		if in.Class != "" && !containsFold(g.Classes, in.Class) {
			continue
		}
		ok := true
		g.RegisterWrites = map[string][]string{}
		for _, reg := range in.RegistersWritten {
			evidence := registerWriteEvidence(g.Opcodes, reg)
			if len(evidence) == 0 {
				ok = false
				break
			}
			g.RegisterWrites[reg] = evidence
			g.MatchedFilters = append(g.MatchedFilters, "register_written:"+reg)
		}
		if !ok {
			continue
		}
		filtered = append(filtered, g)
		if in.MaxResults > 0 && len(filtered) >= in.MaxResults {
			break
		}
	}
	return nil, GadgetOutput{Target: t.Name, Gadgets: filtered}, nil
}

func registerWriteEvidence(ops []GadgetOpcode, reg string) []string {
	reg = strings.ToLower(strings.TrimSpace(reg))
	var evidence []string
	for _, opcode := range ops {
		fields := strings.Fields(strings.ToLower(strings.TrimSpace(opcode.Opcode)))
		if len(fields) < 2 {
			continue
		}
		mnemonic := fields[0]
		if strings.HasPrefix(mnemonic, "cmp") || strings.HasPrefix(mnemonic, "test") || strings.HasPrefix(mnemonic, "j") || strings.HasPrefix(mnemonic, "call") || strings.HasPrefix(mnemonic, "ret") || strings.HasPrefix(mnemonic, "str") || strings.HasPrefix(mnemonic, "sw") || strings.HasPrefix(mnemonic, "sb") || strings.HasPrefix(mnemonic, "sh") {
			continue
		}
		operands := strings.Split(strings.Join(fields[1:], " "), ",")
		dst := strings.Trim(strings.TrimSpace(operands[0]), "[]{}()")
		writes := dst == reg
		if strings.HasPrefix(mnemonic, "xchg") && len(operands) > 1 {
			writes = writes || strings.TrimSpace(operands[1]) == reg
		}
		if writes {
			evidence = append(evidence, fmt.Sprintf("0x%x: %s", opcode.Addr, opcode.Opcode))
		}
	}
	return evidence
}

type sectionRecord struct {
	Name, Perm   string
	VAddr, VSize uint64
}

func readSections(ctx context.Context, t *workspace.Target) []sectionRecord {
	out, err := t.R2.Cmd(ctx, "iSj")
	if err != nil {
		return nil
	}
	var raw []map[string]any
	if decodeJSONNumbers(out, &raw) != nil {
		return nil
	}
	sections := make([]sectionRecord, 0, len(raw))
	for _, entry := range raw {
		sections = append(sections, sectionRecord{Name: fmt.Sprint(entry["name"]), Perm: fmt.Sprint(entry["perm"]), VAddr: number(entry["vaddr"]), VSize: max(number(entry["vsize"]), number(entry["size"]))})
	}
	return sections
}

func sectionForAddress(sections []sectionRecord, address uint64) (string, bool) {
	for _, section := range sections {
		if address >= section.VAddr && address < section.VAddr+section.VSize {
			return section.Name, strings.Contains(section.Perm, "x")
		}
	}
	return "", false
}

func architectureAlignment(arch string) int {
	switch strings.ToLower(arch) {
	case "arm", "thumb":
		return 2
	case "mips", "ppc", "sparc":
		return 4
	default:
		return 1
	}
}

func containsFold(items []string, want string) bool {
	for _, item := range items {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}

type StringsInput struct {
	Target     string `json:"target,omitempty"`
	All        bool   `json:"all,omitempty"`
	Filter     string `json:"filter,omitempty"`
	MaxResults int    `json:"max_results,omitempty"`
}
type StringRecord struct {
	VAddr   uint64 `json:"vaddr"`
	PAddr   uint64 `json:"paddr"`
	Size    int    `json:"size"`
	Length  int    `json:"length"`
	Section string `json:"section"`
	Type    string `json:"type"`
	String  string `json:"string"`
}
type StringsOutput struct {
	Target  string         `json:"target"`
	Strings []StringRecord `json:"strings"`
}

func (s *Service) listStrings(ctx context.Context, _ *mcp.CallToolRequest, in StringsInput) (*mcp.CallToolResult, StringsOutput, error) {
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, StringsOutput{}, err
	}
	cmd := "izj"
	if in.All {
		cmd = "izzj"
	}
	out, err := t.R2.Cmd(ctx, cmd)
	if err != nil {
		return nil, StringsOutput{}, err
	}
	var records []StringRecord
	if err := json.Unmarshal([]byte(out), &records); err != nil {
		return nil, StringsOutput{}, err
	}
	var re *regexp.Regexp
	if in.Filter != "" {
		re, err = regexp.Compile(in.Filter)
		if err != nil {
			return nil, StringsOutput{}, err
		}
	}
	filtered := records[:0]
	for _, rec := range records {
		if re == nil || re.MatchString(rec.String) {
			filtered = append(filtered, rec)
			if in.MaxResults > 0 && len(filtered) >= in.MaxResults {
				break
			}
		}
	}
	return nil, StringsOutput{Target: t.Name, Strings: filtered}, nil
}

type StringXrefInput struct {
	Target     string `json:"target,omitempty"`
	Query      string `json:"query"`
	Regex      bool   `json:"regex,omitempty"`
	MaxStrings int    `json:"max_strings,omitempty"`
}
type Xref struct {
	From       uint64 `json:"from"`
	To         uint64 `json:"to"`
	Type       string `json:"type,omitempty"`
	Perm       string `json:"perm,omitempty"`
	Opcode     string `json:"opcode,omitempty"`
	Function   string `json:"function,omitempty"`
	FcnAddress uint64 `json:"fcn_addr,omitempty"`
	FcnName    string `json:"fcn_name,omitempty"`
	RefName    string `json:"refname,omitempty"`
}
type PointerSlot struct {
	Address uint64 `json:"address"`
	Xrefs   []Xref `json:"xrefs"`
}
type StringXrefRecord struct {
	String       StringRecord  `json:"string"`
	Direct       []Xref        `json:"direct"`
	PointerSlots []PointerSlot `json:"pointer_slots"`
}
type StringXrefOutput struct {
	Target  string             `json:"target"`
	Results []StringXrefRecord `json:"results"`
}

func (s *Service) stringXrefs(ctx context.Context, _ *mcp.CallToolRequest, in StringXrefInput) (*mcp.CallToolResult, StringXrefOutput, error) {
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, StringXrefOutput{}, err
	}
	out, err := t.R2.Cmd(ctx, "izzj")
	if err != nil {
		return nil, StringXrefOutput{}, err
	}
	var stringsFound []StringRecord
	if err := json.Unmarshal([]byte(out), &stringsFound); err != nil {
		return nil, StringXrefOutput{}, err
	}
	var re *regexp.Regexp
	if in.Regex {
		re, err = regexp.Compile(in.Query)
		if err != nil {
			return nil, StringXrefOutput{}, err
		}
	}
	result := StringXrefOutput{Target: t.Name}
	for _, str := range stringsFound {
		match := strings.Contains(str.String, in.Query)
		if re != nil {
			match = re.MatchString(str.String)
		}
		if !match {
			continue
		}
		rec := StringXrefRecord{String: str}
		rec.Direct, _ = xrefsAt(ctx, t, str.VAddr)
		pointerOut, _ := t.R2.Cmd(ctx, fmt.Sprintf("/vj 0x%x", str.VAddr))
		var raw []map[string]any
		_ = decodeJSONNumbers(pointerOut, &raw)
		seen := map[uint64]bool{}
		for _, hit := range raw {
			addr := number(hit["offset"])
			if addr == 0 {
				addr = number(hit["addr"])
			}
			if addr == 0 || seen[addr] {
				continue
			}
			seen[addr] = true
			xr, _ := xrefsAt(ctx, t, addr)
			rec.PointerSlots = append(rec.PointerSlots, PointerSlot{Address: addr, Xrefs: xr})
		}
		result.Results = append(result.Results, rec)
		if in.MaxStrings > 0 && len(result.Results) >= in.MaxStrings {
			break
		}
	}
	return nil, result, nil
}

func xrefsAt(ctx context.Context, t *workspace.Target, addr uint64) ([]Xref, error) {
	out, err := t.R2.Cmd(ctx, fmt.Sprintf("axtj @ 0x%x", addr))
	if err != nil {
		return nil, err
	}
	var refs []Xref
	if err := json.Unmarshal([]byte(out), &refs); err != nil {
		return nil, err
	}
	for i := range refs {
		if refs[i].To == 0 {
			refs[i].To = addr
		}
		if refs[i].Function == "" {
			refs[i].Function = refs[i].FcnName
		}
	}
	return refs, nil
}

type InspectInput struct {
	Target  string `json:"target,omitempty"`
	Kind    string `json:"kind"`
	Address string `json:"address,omitempty"`
	Start   int    `json:"start,omitempty"`
	Count   int    `json:"count,omitempty"`
	Sort    string `json:"sort,omitempty" jsonschema:"address, name, or none; defaults to address"`
}

func (s *Service) inspect(ctx context.Context, _ *mcp.CallToolRequest, in InspectInput) (*mcp.CallToolResult, CommandOutput, error) {
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, CommandOutput{}, err
	}
	if in.Count <= 0 {
		in.Count = 64
	}
	if in.Count > 10000 {
		return nil, CommandOutput{}, errors.New("count exceeds 10000")
	}
	if in.Start < 0 {
		return nil, CommandOutput{}, errors.New("start must not be negative")
	}
	if in.Sort == "" {
		in.Sort = "address"
	}
	if in.Sort != "address" && in.Sort != "name" && in.Sort != "none" {
		return nil, CommandOutput{}, errors.New("sort must be address, name, or none")
	}
	requiresAddress := in.Kind == "xrefs" || in.Kind == "disassembly" || in.Kind == "function_disassembly" || in.Kind == "hexdump"
	if requiresAddress && in.Address == "" {
		return nil, CommandOutput{}, fmt.Errorf("address is required for inspect kind %s", in.Kind)
	}
	if in.Address != "" {
		if _, err := parseAddress(in.Address); err != nil {
			return nil, CommandOutput{}, err
		}
	}
	cmds := map[string]string{"info": "ij", "functions": "aflj", "imports": "iij", "exports": "iEj", "symbols": "isj", "sections": "iSj", "registers": "aerj"}
	cmd := cmds[in.Kind]
	switch in.Kind {
	case "xrefs":
		cmd = "axtj @ " + in.Address
	case "disassembly":
		cmd = fmt.Sprintf("pdj %d @ %s", in.Count, in.Address)
	case "function_disassembly":
		cmd = "pdfj @ " + in.Address
	case "hexdump":
		cmd = fmt.Sprintf("pxj %d @ %s", in.Count, in.Address)
	}
	if cmd == "" {
		return nil, CommandOutput{}, errors.New("unknown inspect kind")
	}
	out, err := t.R2.Cmd(ctx, cmd)
	if err != nil {
		return nil, CommandOutput{}, err
	}
	result := CommandOutput{Target: t.Name, Output: out}
	var data any
	if decodeJSONNumbers(out, &data) == nil {
		result.Output = ""
		result.Data = data
		switch value := data.(type) {
		case []any:
			sortInspectValues(value, in.Sort)
			result.Total = len(value)
			end := min(len(value), in.Start+in.Count)
			if in.Start > len(value) {
				in.Start = len(value)
			}
			page := value[in.Start:end]
			result.Data = page
			result.Start = in.Start
			result.Count = len(page)
			result.Truncated = end < len(value)
		case map[string]any:
			if ops, ok := value["ops"].([]any); ok {
				sortInspectValues(ops, in.Sort)
				result.Total = len(ops)
				end := min(len(ops), in.Start+in.Count)
				if in.Start > len(ops) {
					in.Start = len(ops)
				}
				value["ops"] = ops[in.Start:end]
				result.Start = in.Start
				result.Count = end - in.Start
				result.Truncated = end < len(ops)
			}
		}
	}
	return nil, result, nil
}

func sortInspectValues(values []any, mode string) {
	if mode == "none" {
		return
	}
	sort.SliceStable(values, func(i, j int) bool {
		a, aok := values[i].(map[string]any)
		b, bok := values[j].(map[string]any)
		if !aok || !bok {
			return false
		}
		if mode == "name" {
			return fmt.Sprint(a["name"]) < fmt.Sprint(b["name"])
		}
		return inspectAddress(a) < inspectAddress(b)
	})
}

func inspectAddress(value map[string]any) uint64 {
	for _, key := range []string{"addr", "offset", "vaddr", "paddr", "from", "to"} {
		if address := number(value[key]); address != 0 {
			return address
		}
	}
	return 0
}

type AnnotateInput struct {
	Target  string `json:"target,omitempty"`
	Kind    string `json:"kind"`
	Address string `json:"address"`
	Value   string `json:"value"`
}

func (s *Service) annotate(ctx context.Context, _ *mcp.CallToolRequest, in AnnotateInput) (*mcp.CallToolResult, StatusOutput, error) {
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, StatusOutput{}, err
	}
	if _, err := parseAddress(in.Address); err != nil {
		return nil, StatusOutput{}, err
	}
	var cmd string
	switch in.Kind {
	case "function_name":
		if !validIdentifier(in.Value) {
			return nil, StatusOutput{}, errors.New("invalid function name")
		}
		cmd = "afn " + in.Value + " @ " + in.Address
	case "flag_name":
		if !validIdentifier(in.Value) {
			return nil, StatusOutput{}, errors.New("invalid flag name")
		}
		cmd = "f " + in.Value + " @ " + in.Address
	case "comment":
		cmd = "CCu base64:" + base64.StdEncoding.EncodeToString([]byte(in.Value)) + " @ " + in.Address
	case "prototype":
		if strings.ContainsAny(in.Value, "\r\n;") || strings.Contains(in.Value, "$(") || strings.ContainsAny(in.Value, "`|") {
			return nil, StatusOutput{}, errors.New("prototype contains a command delimiter")
		}
		cmd = "afs " + in.Value + " @ " + in.Address
	default:
		return nil, StatusOutput{}, errors.New("kind must be function_name, flag_name, comment, or prototype")
	}
	_, err = t.R2.Cmd(ctx, cmd)
	return nil, StatusOutput{OK: err == nil}, err
}

type RawInput struct {
	Target  string `json:"target,omitempty"`
	Command string `json:"command"`
}

func (s *Service) r2Command(ctx context.Context, _ *mcp.CallToolRequest, in RawInput) (*mcp.CallToolResult, CommandOutput, error) {
	t, err := s.ws.Get(in.Target)
	if err != nil {
		return nil, CommandOutput{}, err
	}
	if err := validateRaw(in.Command, s.ws.AllowUnsafe()); err != nil {
		return nil, CommandOutput{}, err
	}
	out, err := t.R2.Cmd(ctx, in.Command)
	return nil, CommandOutput{Target: t.Name, Output: out}, err
}

func validateRaw(cmd string, unsafe bool) error {
	if strings.TrimSpace(cmd) == "" {
		return errors.New("command is required")
	}
	if strings.ContainsAny(cmd, "\r\n\x00") {
		return errors.New("command contains a line delimiter")
	}
	if unsafe {
		return nil
	}
	if strings.Contains(cmd, ";") || strings.Contains(cmd, "`") || strings.Contains(cmd, "$(") || strings.ContainsAny(cmd, "|><") {
		return errors.New("command chaining, redirection, and substitution require --allow-unsafe-commands")
	}
	trim := strings.TrimSpace(cmd)
	if strings.HasPrefix(trim, "!") || strings.HasPrefix(trim, "=") || strings.HasPrefix(trim, "#!") || strings.Contains(trim, "r2pipe") {
		return errors.New("external command execution requires --allow-unsafe-commands")
	}
	return nil
}

func parseAddress(s string) (uint64, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid address %q", s)
	}
	return v, nil
}
func parseOptionalAddress(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	return parseAddress(s)
}
func validIdentifier(s string) bool {
	return identifierRE.MatchString(s)
}
func number(v any) uint64 {
	switch n := v.(type) {
	case float64:
		return uint64(n)
	case json.Number:
		x, _ := strconv.ParseUint(string(n), 10, 64)
		return x
	case string:
		x, _ := strconv.ParseUint(n, 0, 64)
		return x
	}
	return 0
}

func decodeJSONNumbers(text string, out any) error {
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	return decoder.Decode(out)
}

// Keep stable ordering in outputs assembled from maps.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
