package server

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denysvitali/radare2-mcp-go/internal/r2"
	"github.com/denysvitali/radare2-mcp-go/internal/workspace"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fakeRunner struct {
	answers  map[string]string
	commands []string
}

func (f *fakeRunner) Cmd(_ context.Context, cmd string) (string, error) {
	f.commands = append(f.commands, cmd)
	if v, ok := f.answers[cmd]; ok {
		return v, nil
	}
	return "[]", nil
}
func (f *fakeRunner) Close() error { return nil }

func openFake(t *testing.T, answers map[string]string) (*Service, *fakeRunner) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bin")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	w := workspace.New("r2", nil, false)
	f := &fakeRunner{answers: answers}
	w.SetFactory(func(context.Context, r2.OpenOptions) (r2.Runner, error) { return f, nil })
	if _, err := w.Open(context.Background(), workspace.Target{Name: "one", Path: path}); err != nil {
		t.Fatal(err)
	}
	return &Service{ws: w}, f
}

func TestSearchStringUsesHexAndExplicitRange(t *testing.T) {
	cmd, err := searchCommand(SearchInput{Type: "string", Query: "hello; shell", From: "0x1000", To: "0x2000", MaxResults: 5})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cmd, "hello") || !strings.Contains(cmd, "68656c6c6f3b207368656c6c") {
		t.Fatalf("query was not safely encoded: %s", cmd)
	}
	if !strings.Contains(cmd, "search.from=0x1000") || !strings.Contains(cmd, "search.to=0x2000") {
		t.Fatalf("range missing: %s", cmd)
	}
}

func TestRawCommandPolicy(t *testing.T) {
	for _, cmd := range []string{"!sh", "ij;!sh", "ij | cat", "ij > /tmp/x", "#!pipe"} {
		if validateRaw(cmd, false) == nil {
			t.Errorf("accepted %q", cmd)
		}
	}
	if err := validateRaw("aav0", false); err != nil {
		t.Fatal(err)
	}
	if err := validateRaw("ij;pd 2", true); err != nil {
		t.Fatal(err)
	}
}

func TestStringXrefsIncludesPointerSlot(t *testing.T) {
	stringsJSON := `[{"vaddr":4096,"paddr":0,"size":5,"length":4,"string":"gate"}]`
	svc, _ := openFake(t, map[string]string{"izzj": stringsJSON, "axtj @ 0x1000": `[{"from":8192,"to":4096,"type":"DATA"}]`, "/vj 0x1000": `[{"offset":12288}]`, "axtj @ 0x3000": `[{"from":16384,"to":12288,"opcode":"addiu a0, a0, 0x3000"}]`})
	_, out, err := svc.stringXrefs(context.Background(), nil, StringXrefInput{Query: "gate"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 || len(out.Results[0].Direct) != 1 || len(out.Results[0].PointerSlots) != 1 || len(out.Results[0].PointerSlots[0].Xrefs) != 1 {
		b, _ := json.Marshal(out)
		t.Fatalf("missing two-step xrefs: %s", b)
	}
}

func TestDispatchRecoveryEnumeratesHandlersAndConsumers(t *testing.T) {
	answers := map[string]string{
		"pxwj 8 @ 0x1000": `[8192,12288]`,
		"fj":              `[{"name":"sym.first","offset":8192},{"name":"sym.second","offset":12288}]`,
		"axtj @ 0x1000":   `[]`,
		"axtj @ 0x1800":   `[{"from":16384,"to":6144,"opcode":"lw v0, -4(gp)"}]`,
	}
	svc, _ := openFake(t, answers)
	_, out, err := svc.recoverDispatchTable(context.Background(), nil, DispatchInput{Target: "one", Address: "0x1000", Count: 2, EntrySize: 4, PointerSlots: []string{"0x1800"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 2 || out.Entries[1].Name != "sym.second" || len(out.Consumers) != 1 || len(out.Consumers[0].Xrefs) != 1 {
		t.Fatalf("bad recovery: %+v", out)
	}
}

func TestCommentIsBase64Encoded(t *testing.T) {
	svc, f := openFake(t, nil)
	_, _, err := svc.annotate(context.Background(), nil, AnnotateInput{Target: "one", Kind: "comment", Address: "0x1000", Value: "gate;\nmeaning"})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.commands) != 1 || !strings.Contains(f.commands[0], "base64:") || strings.Contains(f.commands[0], "meaning") {
		t.Fatalf("comment not safely encoded: %v", f.commands)
	}
}

func TestAnalyzeUsesExplicitModernPasses(t *testing.T) {
	svc, f := openFake(t, map[string]string{"aflc": "42"})
	_, out, err := svc.analyze(context.Background(), nil, AnalyzeInput{Target: "one", Level: "full"})
	if err != nil {
		t.Fatal(err)
	}
	if out.FunctionCount != 42 {
		t.Fatalf("function count = %d", out.FunctionCount)
	}
	for _, cmd := range f.commands {
		if cmd == "aaa" || strings.Contains(cmd, "aaaa") {
			t.Fatalf("obsolete ambiguous analysis command used: %q", cmd)
		}
	}
	if !slices.Contains(f.commands, "aav0") {
		t.Fatalf("data-reference pass missing: %v", f.commands)
	}
}

func TestAnalyzeSkipsCompletedPasses(t *testing.T) {
	svc, f := openFake(t, map[string]string{"aflc": "42"})
	if _, _, err := svc.analyze(context.Background(), nil, AnalyzeInput{Target: "one", Level: "standard"}); err != nil {
		t.Fatal(err)
	}
	f.commands = nil
	_, out, err := svc.analyze(context.Background(), nil, AnalyzeInput{Target: "one", Level: "standard"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Passes) != 0 || len(out.SkippedPasses) != 5 || !slices.Equal(f.commands, []string{"aflc"}) {
		t.Fatalf("analysis was repeated: %+v commands=%v", out, f.commands)
	}
}

func TestXrefsPreserveDestinationAndFunction(t *testing.T) {
	svc, _ := openFake(t, map[string]string{"axtj @ 0x1234": `[{"from":8192,"fcn_addr":8176,"fcn_name":"main","refname":"str.gate"}]`})
	target, _ := svc.ws.Get("one")
	refs, err := xrefsAt(context.Background(), target, 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 1 || refs[0].To != 0x1234 || refs[0].Function != "main" || refs[0].FcnAddress != 8176 {
		t.Fatalf("metadata lost: %+v", refs)
	}
}

func TestDecompilerFallsBackAndPaginates(t *testing.T) {
	svc, _ := openFake(t, map[string]string{
		"pdg @ 0x1000": "You need to install the plugin with r2pm -ci r2ghidra",
		"pdd @ 0x1000": "ERROR: no decompiler",
		"pdc @ 0x1000": "line0\nline1\nline2\nline3",
	})
	_, out, err := svc.decompile(context.Background(), nil, DecompileInput{Target: "one", Address: "0x1000", StartLine: 1, MaxLines: 2})
	if err != nil {
		t.Fatal(err)
	}
	if out.Backend != "pdc" || out.Code != "line1\nline2" || !out.Truncated || out.NextLine != 3 || len(out.Attempts) != 3 || out.Attempts[0].Reason == "" {
		t.Fatalf("bad fallback/page: %+v", out)
	}
}

func TestTypeDefinitionQuotesWholeR2Command(t *testing.T) {
	svc, f := openFake(t, map[string]string{"ts": "audit\n"})
	_, _, err := svc.typeDefine(context.Background(), nil, TypeDefineInput{Target: "one", Definition: "struct audit { int x; char y; };"})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.commands) != 4 || !strings.HasPrefix(f.commands[0], `"td `) || !strings.HasSuffix(f.commands[0], `"`) || f.commands[1] != "ts" || f.commands[2] != "tsj audit" || f.commands[3] != "tss audit" {
		t.Fatalf("definition not quoted: %v", f.commands)
	}
}

func TestFunctionSignaturesUseCurrentR2Fields(t *testing.T) {
	svc, _ := openFake(t, map[string]string{
		"aflj":           `[{"addr":4096,"name":"main","size":8,"ninstrs":2}]`,
		"aoj 2 @ 0x1000": `[{"type":"mov","family":"cpu"},{"type":"ret","family":"cpu"}]`,
	})
	target, _ := svc.ws.Get("one")
	fs, err := functionSignatures(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Offset != 0x1000 || fs[0].Ninstr != 2 || fs[0].Hash == "" {
		t.Fatalf("bad signature: %+v", fs)
	}
}

func TestInspectPaginatesLargeLists(t *testing.T) {
	svc, _ := openFake(t, map[string]string{"aflj": `[{"addr":1},{"addr":2},{"addr":3},{"addr":4}]`})
	_, out, err := svc.inspect(context.Background(), nil, InspectInput{Target: "one", Kind: "functions", Start: 1, Count: 2})
	if err != nil {
		t.Fatal(err)
	}
	if out.Total != 4 || out.Count != 2 || !out.Truncated {
		t.Fatalf("bad page metadata: %+v", out)
	}
	if out.Output != "" {
		t.Fatalf("decoded inspect duplicated serialized output: %q", out.Output)
	}
	page, ok := out.Data.([]any)
	if !ok || len(page) != 2 {
		t.Fatalf("bad page data: %#v", out.Data)
	}
}

func TestKernelPrel32Scanner(t *testing.T) {
	base := uint64(0x80010000)
	blob := make([]byte, 256)
	copy(blob[128:], "exported_symbol\x00")
	entry := 64
	binary.LittleEndian.PutUint32(blob[entry:], uint32(int32(32-entry)))
	binary.LittleEndian.PutUint32(blob[entry+4:], uint32(int32(128-(entry+4))))
	path := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(path, blob, 0600); err != nil {
		t.Fatal(err)
	}
	symbols, err := scanKernelSymbols(&workspace.Target{Path: path, Base: base, Bits: 32, Endian: "little"}, "prel32", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(symbols) != 1 || symbols[0].Name != "exported_symbol" || symbols[0].Address != base+32 {
		t.Fatalf("bad symbols: %+v", symbols)
	}
}

func TestMCPToolSchemasAndDispatch(t *testing.T) {
	svc, _ := openFake(t, nil)
	server := New(svc.ws)
	st, ct := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.Run(ctx, st) }()
	var progress atomic.Int32
	progressReceived := make(chan struct{}, 4)
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, &mcp.ClientOptions{ProgressNotificationHandler: func(context.Context, *mcp.ProgressNotificationClientRequest) {
		progress.Add(1)
		progressReceived <- struct{}{}
	}})
	session, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			t.Errorf("close session: %v", err)
		}
	}()
	listed, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) < 24 {
		t.Fatalf("only %d tools registered", len(listed.Tools))
	}
	annotations := map[string]*mcp.ToolAnnotations{}
	for _, tool := range listed.Tools {
		if tool.InputSchema == nil {
			t.Fatalf("%s has no input schema", tool.Name)
		}
		annotations[tool.Name] = tool.Annotations
	}
	if annotations["workspace_list"] == nil || !annotations["workspace_list"].ReadOnlyHint {
		t.Fatal("workspace_list is not marked read-only")
	}
	if annotations["workspace_close"] == nil || annotations["workspace_close"].DestructiveHint == nil || !*annotations["workspace_close"].DestructiveHint {
		t.Fatal("workspace_close is not marked destructive")
	}
	if annotations["workspace_delete"] == nil || annotations["workspace_delete"].DestructiveHint == nil || !*annotations["workspace_delete"].DestructiveHint {
		t.Fatal("workspace_delete is not marked destructive")
	}
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "workspace_list", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res.Content)
	}
	if res.StructuredContent == nil {
		t.Fatal("typed structured result missing")
	}
	if _, ok := res.Meta["duration_ms"]; !ok {
		t.Fatalf("tool timing metadata missing: %#v", res.Meta)
	}
	params := &mcp.CallToolParams{Meta: mcp.Meta{}, Name: "analyze", Arguments: map[string]any{"target": "one", "level": "basic"}}
	params.SetProgressToken("analysis-progress")
	if _, err := session.CallTool(ctx, params); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(time.Second)
waitForProgress:
	for progress.Load() < 2 {
		select {
		case <-progressReceived:
		case <-deadline:
			break waitForProgress
		}
	}
	if progress.Load() < 2 {
		t.Fatalf("expected analysis progress notifications, got %d", progress.Load())
	}
}

func TestSearchReportsRequestedEncoding(t *testing.T) {
	svc, _ := openFake(t, map[string]string{"e search.maxhits=1000; /xj 6869": `[{"offset":1,"type":"hexpair"}]`})
	_, out, err := svc.search(context.Background(), nil, SearchInput{Query: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if out.RequestedType != "string" || out.Encoding != "UTF-8 bytes" {
		t.Fatalf("missing provenance: %+v", out)
	}
}

func TestRegisterWriteEvidenceRejectsReadsAndStores(t *testing.T) {
	ops := []GadgetOpcode{{Addr: 1, Opcode: "cmp eax, ebx"}, {Addr: 2, Opcode: "mov ecx, eax"}, {Addr: 3, Opcode: "sw eax, 0(sp)"}, {Addr: 4, Opcode: "mov eax, edx"}}
	evidence := registerWriteEvidence(ops, "eax")
	if len(evidence) != 1 || !strings.Contains(evidence[0], "mov eax") {
		t.Fatalf("bad evidence: %v", evidence)
	}
}

func TestNaturalTypeNameIsAccepted(t *testing.T) {
	svc, _ := openFake(t, map[string]string{"tls 0x1000": "0x1000 = (audit)"})
	_, out, err := svc.typeApply(context.Background(), nil, TypeApplyInput{Type: "struct audit", Address: "0x1000"})
	if err != nil || out.NormalizedType != "audit" || !out.OK {
		t.Fatalf("natural type failed: %+v %v", out, err)
	}
}

func TestLiveRadare2SearchStringsAndGadgets(t *testing.T) {
	if _, err := exec.LookPath("r2"); err != nil {
		if os.Getenv("RADARE2_REQUIRED") == "1" {
			t.Fatal("r2 required by test environment")
		}
		t.Skip("r2 not installed")
	}
	w := workspace.New("r2", nil, false)
	defer w.CloseAll()
	if _, err := w.Open(context.Background(), workspace.Target{Name: "live", Path: "/bin/true"}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{ws: w}
	_, stringsOut, err := svc.listStrings(context.Background(), nil, StringsInput{Target: "live", All: true, Filter: "ld-linux"})
	if err != nil {
		t.Fatal(err)
	}
	if len(stringsOut.Strings) == 0 || stringsOut.Strings[0].VAddr == 0 {
		t.Fatalf("address-bearing string missing: %+v", stringsOut)
	}
	_, searchOut, err := svc.search(context.Background(), nil, SearchInput{Target: "live", Type: "string", Query: "ld-linux", MaxResults: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(searchOut.Results) != 1 {
		t.Fatalf("search returned no target result: %+v", searchOut)
	}
	_, gadgets, err := svc.searchGadgets(context.Background(), nil, GadgetInput{Target: "live", Kind: "return", Contains: "ret", MaxDepth: 6, MaxResults: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(gadgets.Gadgets) == 0 {
		t.Fatal("live gadget search returned no gadgets")
	}
}

func TestLiveCompatibilityWorkflows(t *testing.T) {
	if _, err := exec.LookPath("r2"); err != nil {
		if os.Getenv("RADARE2_REQUIRED") == "1" {
			t.Fatal("r2 required by test environment")
		}
		t.Skip("r2 not installed")
	}
	libc := "/lib/x86_64-linux-gnu/libc.so.6"
	if _, err := os.Stat(libc); err != nil {
		t.Skip("glibc fixture not available")
	}
	w := workspace.New("r2", nil, false)
	defer w.CloseAll()
	ctx := context.Background()
	for name, path := range map[string]string{"true": "/bin/true", "false": "/bin/false", "libc": libc} {
		if _, err := w.Open(ctx, workspace.Target{Name: name, Path: path}); err != nil {
			t.Fatal(err)
		}
	}
	svc := &Service{ws: w}
	_, analysis, err := svc.analyze(ctx, nil, AnalyzeInput{Target: "true", Level: "standard", TimeoutSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if analysis.FunctionCount == 0 || len(analysis.Passes) != 5 {
		t.Fatalf("analysis incomplete: %+v", analysis)
	}
	_, _, err = svc.analyze(ctx, nil, AnalyzeInput{Target: "false", Level: "basic", TimeoutSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	_, defined, err := svc.typeDefine(ctx, nil, TypeDefineInput{Target: "true", Definition: "struct radare2_audit { int x; char y; };"})
	if err != nil || !defined.OK {
		t.Fatalf("type define: %+v %v", defined, err)
	}
	target, _ := w.Get("true")
	typeList, err := target.R2.Cmd(ctx, "ts~radare2_audit")
	if err != nil || !strings.Contains(typeList, "radare2_audit") {
		t.Fatalf("type missing after success: %q %v", typeList, err)
	}
	_, applied, err := svc.typeApply(ctx, nil, TypeApplyInput{Target: "true", Type: "radare2_audit", Address: "0x4000"})
	if err != nil || !applied.OK {
		t.Fatalf("type apply: %+v %v", applied, err)
	}
	_, dec, err := svc.decompile(ctx, nil, DecompileInput{Target: "true", Address: "0x1490", MaxLines: 20})
	if err != nil {
		t.Fatal(err)
	}
	if dec.Backend != "pdc" || dec.TotalLines <= 20 || !dec.Truncated {
		t.Fatalf("decompiler fallback/page failed: %+v", dec)
	}
	_, links, err := svc.crossBinaryXrefs(ctx, nil, CrossXrefInput{FromTargets: []string{"true"}, ToTargets: []string{"libc"}, Symbol: "abort"})
	if err != nil {
		t.Fatal(err)
	}
	if len(links.Links) != 1 || links.Links[0].ImportAddress == 0 {
		t.Fatalf("cross-link not deduplicated/addressed: %+v", links)
	}
	_, diff, err := svc.diffFunctions(ctx, nil, DiffInput{Left: "true", Right: "false", MinScore: .8, MaxResults: 20})
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range diff.Matches {
		if match.LeftAddress == 0 || match.RightAddress == 0 {
			t.Fatalf("zero-address match: %+v", match)
		}
	}
}
