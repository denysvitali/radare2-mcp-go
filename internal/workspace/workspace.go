package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/denysvitali/radare2-mcp-go/internal/r2"
)

var validName = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

type Factory func(context.Context, r2.OpenOptions) (r2.Runner, error)

type FileIdentity struct {
	Size            int64 `json:"size,omitempty"`
	ModTimeUnixNano int64 `json:"mod_time_unix_nano,omitempty"`
}

type AnalysisState struct {
	Level           string    `json:"level,omitempty"`
	CompletedPasses []string  `json:"completed_passes,omitempty"`
	FunctionCount   int       `json:"function_count,omitempty"`
	DurationMS      int64     `json:"duration_ms,omitempty"`
	UpdatedAt       time.Time `json:"updated_at,omitempty"`
	Stale           bool      `json:"stale,omitempty"`
}

type Target struct {
	Name     string         `json:"name"`
	Path     string         `json:"path"`
	Base     uint64         `json:"base,omitempty"`
	Arch     string         `json:"arch,omitempty"`
	Bits     int            `json:"bits,omitempty"`
	CPU      string         `json:"cpu,omitempty"`
	Endian   string         `json:"endian,omitempty"`
	Debug    bool           `json:"debug,omitempty"`
	Identity FileIdentity   `json:"identity,omitempty"`
	Analysis AnalysisState  `json:"analysis,omitempty"`
	R2       r2.Runner      `json:"-"`
	Meta     map[string]any `json:"meta,omitempty"`
}

type Policy struct {
	R2Binary     string   `json:"r2_binary"`
	AllowedRoots []string `json:"allowed_roots,omitempty"`
	AllowUnsafe  bool     `json:"allow_unsafe_commands"`
}

type ProgressFunc func(done, total int, target string)

type Workspace struct {
	mu            sync.RWMutex
	targets       map[string]*Target
	selected      string
	r2Binary      string
	allowUnsafe   bool
	allowedRoots  []string
	factory       Factory
	workspacePath string
}

func New(r2Binary string, roots []string, allowUnsafe bool) *Workspace {
	w := &Workspace{targets: make(map[string]*Target), r2Binary: r2Binary, allowUnsafe: allowUnsafe}
	for _, root := range roots {
		if abs, err := filepath.Abs(root); err == nil {
			w.allowedRoots = append(w.allowedRoots, filepath.Clean(abs))
		}
	}
	w.factory = func(ctx context.Context, o r2.OpenOptions) (r2.Runner, error) { return r2.Open(ctx, r2Binary, o) }
	return w
}

func (w *Workspace) SetFactory(f Factory) { w.factory = f }
func (w *Workspace) AllowUnsafe() bool    { return w.allowUnsafe }
func (w *Workspace) Policy() Policy {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return Policy{R2Binary: w.r2Binary, AllowedRoots: append([]string(nil), w.allowedRoots...), AllowUnsafe: w.allowUnsafe}
}

func (w *Workspace) validatePath(path string) (string, error) {
	if strings.HasPrefix(path, "gdb://") {
		if w.allowUnsafe || strings.HasPrefix(path, "gdb://127.0.0.1:") || strings.HasPrefix(path, "gdb://localhost:") {
			return path, nil
		}
		return "", errors.New("remote gdb endpoints require --allow-unsafe-commands")
	}
	return w.ResolvePath(path, true)
}

// ResolvePath applies the configured filesystem policy to binaries,
// auxiliary inputs, and project destinations.
func (w *Workspace) ResolvePath(path string, mustExist bool) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if len(w.allowedRoots) > 0 {
		allowed := false
		for _, root := range w.allowedRoots {
			rel, err := filepath.Rel(root, abs)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", fmt.Errorf("path %q is outside configured roots", abs)
		}
	}
	if mustExist {
		if _, err := os.Stat(abs); err != nil {
			return "", err
		}
	}
	return abs, nil
}

func (w *Workspace) Open(ctx context.Context, t Target) (*Target, error) {
	if !validName.MatchString(t.Name) {
		return nil, errors.New("target name must match [A-Za-z0-9_.-]+")
	}
	path, err := w.validatePath(t.Path)
	if err != nil {
		return nil, err
	}
	w.mu.RLock()
	_, exists := w.targets[t.Name]
	w.mu.RUnlock()
	if exists {
		return nil, fmt.Errorf("target %q is already open", t.Name)
	}
	t.Path = path
	if !strings.HasPrefix(path, "gdb://") {
		if info, statErr := os.Stat(path); statErr == nil {
			current := FileIdentity{Size: info.Size(), ModTimeUnixNano: info.ModTime().UnixNano()}
			if t.Identity != (FileIdentity{}) && t.Identity != current {
				t.Analysis.Stale = true
				t.Analysis.CompletedPasses = nil
				t.Analysis.Level = ""
			}
			t.Identity = current
		}
	}
	runner, err := w.factory(ctx, r2.OpenOptions{Path: path, Base: t.Base, Arch: t.Arch, Bits: t.Bits, CPU: t.CPU, Endian: t.Endian, Debug: t.Debug})
	if err != nil {
		return nil, err
	}
	t.R2 = runner
	w.mu.Lock()
	w.targets[t.Name] = &t
	if w.selected == "" {
		w.selected = t.Name
	}
	w.mu.Unlock()
	return &t, nil
}

func (w *Workspace) UpdateAnalysis(name string, update func(*AnalysisState)) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	t := w.targets[name]
	if t == nil {
		return fmt.Errorf("target %q is not open", name)
	}
	update(&t.Analysis)
	return nil
}

func (w *Workspace) Analysis(name string) (AnalysisState, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if name == "" {
		name = w.selected
	}
	t := w.targets[name]
	if t == nil {
		return AnalysisState{}, fmt.Errorf("target %q is not open", name)
	}
	state := t.Analysis
	state.CompletedPasses = append([]string(nil), state.CompletedPasses...)
	return state, nil
}

func (w *Workspace) Get(name string) (*Target, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if name == "" {
		name = w.selected
	}
	t := w.targets[name]
	if t == nil {
		return nil, fmt.Errorf("target %q is not open", name)
	}
	return t, nil
}

func (w *Workspace) Select(name string) error {
	if _, err := w.Get(name); err != nil {
		return err
	}
	w.mu.Lock()
	w.selected = name
	w.mu.Unlock()
	return nil
}

func (w *Workspace) List() ([]Target, string) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]Target, 0, len(w.targets))
	for _, t := range w.targets {
		copy := *t
		copy.R2 = nil
		out = append(out, copy)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, w.selected
}

func (w *Workspace) Close(name string) error {
	w.mu.Lock()
	t := w.targets[name]
	if t == nil {
		w.mu.Unlock()
		return fmt.Errorf("target %q is not open", name)
	}
	delete(w.targets, name)
	if w.selected == name {
		w.selected = ""
		for next := range w.targets {
			w.selected = next
			break
		}
	}
	w.mu.Unlock()
	return t.R2.Close()
}

func (w *Workspace) CloseAll() {
	targets, _ := w.List()
	for _, t := range targets {
		_ = w.Close(t.Name)
	}
}

type manifest struct {
	Version  int      `json:"version"`
	Selected string   `json:"selected,omitempty"`
	Targets  []Target `json:"targets"`
}

func (w *Workspace) Save(ctx context.Context, path string) error {
	return w.SaveWithProgress(ctx, path, nil)
}

func (w *Workspace) SaveWithProgress(ctx context.Context, path string, progress ProgressFunc) error {
	abs, err := w.ResolvePath(path, false)
	if err != nil {
		return err
	}
	if unsafeProjectPath(abs) {
		return errors.New("workspace path contains characters unsafe for the radare2 project command")
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return err
	}
	targets, selected := w.List()
	errs := make([]error, len(targets))
	var completed atomic.Int64
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			t := targets[i]
			live, getErr := w.Get(t.Name)
			if getErr != nil {
				errs[i] = getErr
				return
			}
			project := filepath.Join(abs, t.Name+".r2pj")
			if _, cmdErr := live.R2.Cmd(ctx, "e prj.vc=false; Ps "+project); cmdErr != nil {
				errs[i] = fmt.Errorf("save target %s: %w", t.Name, cmdErr)
				return
			}
			if _, statErr := os.Stat(project); statErr != nil {
				errs[i] = fmt.Errorf("save target %s did not create project: %w", t.Name, statErr)
				return
			}
			if progress != nil {
				progress(int(completed.Add(1)), len(targets), t.Name)
			}
		}(i)
	}
	wg.Wait()
	for _, saveErr := range errs {
		if saveErr != nil {
			return saveErr
		}
	}
	b, err := json.MarshalIndent(manifest{Version: 1, Selected: selected, Targets: targets}, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(abs, "workspace.json.tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(abs, "workspace.json")); err != nil {
		return err
	}
	w.mu.Lock()
	w.workspacePath = abs
	w.mu.Unlock()
	return nil
}

func (w *Workspace) Load(ctx context.Context, path string) error {
	return w.LoadWithProgress(ctx, path, nil)
}

func (w *Workspace) LoadWithProgress(ctx context.Context, path string, progress ProgressFunc) error {
	abs, err := w.ResolvePath(path, true)
	if err != nil {
		return err
	}
	if unsafeProjectPath(abs) {
		return errors.New("workspace path contains characters unsafe for the radare2 project command")
	}
	b, err := os.ReadFile(filepath.Join(abs, "workspace.json"))
	if err != nil {
		return err
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	if m.Version != 1 {
		return fmt.Errorf("unsupported workspace version %d", m.Version)
	}
	if err := validateManifest(m); err != nil {
		return err
	}
	if current, _ := w.List(); len(current) != 0 {
		return errors.New("load requires an empty workspace")
	}
	for _, spec := range m.Targets {
		if _, statErr := os.Stat(filepath.Join(abs, spec.Name+".r2pj")); statErr != nil {
			return fmt.Errorf("project for target %s: %w", spec.Name, statErr)
		}
	}
	errs := make([]error, len(m.Targets))
	var completed atomic.Int64
	var wg sync.WaitGroup
	for i := range m.Targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			spec := m.Targets[i]
			t, openErr := w.Open(ctx, spec)
			if openErr != nil {
				errs[i] = fmt.Errorf("open target %s: %w", spec.Name, openErr)
				return
			}
			project := filepath.Join(abs, spec.Name+".r2pj")
			if _, cmdErr := t.R2.Cmd(ctx, "P "+project); cmdErr != nil {
				errs[i] = fmt.Errorf("load target %s project: %w", spec.Name, cmdErr)
				return
			}
			if progress != nil {
				progress(int(completed.Add(1)), len(m.Targets), spec.Name)
			}
		}(i)
	}
	wg.Wait()
	for _, loadErr := range errs {
		if loadErr != nil {
			w.CloseAll()
			return loadErr
		}
	}
	if m.Selected != "" {
		_ = w.Select(m.Selected)
	}
	w.mu.Lock()
	w.workspacePath = abs
	w.mu.Unlock()
	return nil
}

func (w *Workspace) DeleteProject(path string) ([]string, error) {
	if current, _ := w.List(); len(current) != 0 {
		return nil, errors.New("project deletion requires an empty workspace")
	}
	abs, err := w.ResolvePath(path, true)
	if err != nil {
		return nil, err
	}
	if unsafeProjectPath(abs) {
		return nil, errors.New("workspace path contains unsafe characters")
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, errors.New("workspace path must be a real directory, not a symlink")
	}
	manifestPath := filepath.Join(abs, "workspace.json")
	b, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read workspace manifest: %w", err)
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil || m.Version != 1 {
		return nil, errors.New("refusing to delete directory without a valid workspace manifest")
	}
	if err := validateManifest(m); err != nil {
		return nil, fmt.Errorf("refusing to delete invalid workspace: %w", err)
	}
	expected := map[string]bool{"workspace.json": true}
	for _, target := range m.Targets {
		expected[target.Name+".r2pj"] = true
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !expected[entry.Name()] {
			return nil, fmt.Errorf("refusing to delete workspace containing unexpected entry %q", entry.Name())
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return nil, infoErr
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("refusing to delete non-regular workspace entry %q", entry.Name())
		}
	}
	for name := range expected {
		if _, err := os.Stat(filepath.Join(abs, name)); err != nil {
			return nil, fmt.Errorf("workspace entry %q: %w", name, err)
		}
	}
	names := make([]string, 0, len(expected))
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	removed := make([]string, 0, len(names)+1)
	for _, name := range names {
		entryPath := filepath.Join(abs, name)
		if err := os.Remove(entryPath); err != nil {
			return removed, err
		}
		removed = append(removed, entryPath)
	}
	if err := os.Remove(abs); err != nil {
		return removed, err
	}
	removed = append(removed, abs)
	w.mu.Lock()
	if w.workspacePath == abs {
		w.workspacePath = ""
	}
	w.mu.Unlock()
	return removed, nil
}

func validateManifest(m manifest) error {
	seen := make(map[string]bool, len(m.Targets))
	for _, target := range m.Targets {
		if !validName.MatchString(target.Name) {
			return fmt.Errorf("invalid target name %q in workspace manifest", target.Name)
		}
		if seen[target.Name] {
			return fmt.Errorf("duplicate target name %q in workspace manifest", target.Name)
		}
		seen[target.Name] = true
	}
	if m.Selected != "" && !seen[m.Selected] {
		return fmt.Errorf("selected target %q is not in workspace manifest", m.Selected)
	}
	return nil
}

func unsafeProjectPath(path string) bool {
	return strings.ContainsAny(path, "\r\n;`$\"") || strings.IndexFunc(path, unicode.IsSpace) >= 0
}
