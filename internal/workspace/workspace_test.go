package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/denysvitali/radare2-mcp-go/internal/r2"
)

type fakeRunner struct {
	mu       sync.Mutex
	commands []string
	closed   bool
}

func (f *fakeRunner) Cmd(_ context.Context, cmd string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, cmd)
	if strings.Contains(cmd, " Ps ") {
		parts := strings.Split(cmd, "Ps ")
		path := parts[len(parts)-1]
		_ = os.WriteFile(path, []byte("project"), 0600)
	}
	return "", nil
}
func (f *fakeRunner) Close() error { f.mu.Lock(); defer f.mu.Unlock(); f.closed = true; return nil }

func TestMultipleTargetsRemainIndependent(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	b := filepath.Join(dir, "b.bin")
	if err := os.WriteFile(a, []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("b"), 0600); err != nil {
		t.Fatal(err)
	}
	w := New("r2", []string{dir}, false)
	created := map[string]*fakeRunner{}
	w.SetFactory(func(_ context.Context, o r2.OpenOptions) (r2.Runner, error) {
		f := &fakeRunner{}
		created[o.Path] = f
		return f, nil
	})
	if _, err := w.Open(context.Background(), Target{Name: "primary", Path: a, Base: 0x80010000}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Open(context.Background(), Target{Name: "secondary", Path: b}); err != nil {
		t.Fatal(err)
	}
	if created[a].closed {
		t.Fatal("opening second target closed first target")
	}
	if err := w.Close("secondary"); err != nil {
		t.Fatal(err)
	}
	if created[a].closed {
		t.Fatal("closing second target closed first target")
	}
	if _, err := w.Get("primary"); err != nil {
		t.Fatal(err)
	}
}

func TestPathRootBoundary(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	p := filepath.Join(outside, "x")
	_ = os.WriteFile(p, []byte("x"), 0600)
	w := New("r2", []string{root}, false)
	if _, err := w.validatePath(p); err == nil {
		t.Fatal("outside path accepted")
	}
}

func TestSaveWritesManifestAndEveryProject(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "x")
	_ = os.WriteFile(bin, []byte("x"), 0600)
	w := New("r2", nil, false)
	f := &fakeRunner{}
	w.SetFactory(func(context.Context, r2.OpenOptions) (r2.Runner, error) { return f, nil })
	_, _ = w.Open(context.Background(), Target{Name: "x", Path: bin})
	dest := filepath.Join(dir, "project")
	if err := w.Save(context.Background(), dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "workspace.json")); err != nil {
		t.Fatal(err)
	}
	if len(f.commands) != 1 || !strings.Contains(f.commands[0], " Ps ") {
		t.Fatalf("project not saved: %v", f.commands)
	}
}

func TestLiveProjectRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("r2"); err != nil {
		if os.Getenv("RADARE2_REQUIRED") == "1" {
			t.Fatal("r2 required by test environment")
		}
		t.Skip("r2 not installed")
	}
	ctx := context.Background()
	project := filepath.Join(t.TempDir(), "workspace")
	w := New("r2", nil, false)
	target, err := w.Open(ctx, Target{Name: "binary", Path: "/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = target.R2.Cmd(ctx, "f persisted_flag = 0x1234"); err != nil {
		t.Fatal(err)
	}
	if err = w.Save(ctx, project); err != nil {
		t.Fatal(err)
	}
	w.CloseAll()
	restored := New("r2", nil, false)
	defer restored.CloseAll()
	if err = restored.Load(ctx, project); err != nil {
		t.Fatal(err)
	}
	target, err = restored.Get("binary")
	if err != nil {
		t.Fatal(err)
	}
	out, err := target.R2.Cmd(ctx, "fs *; f~persisted_flag")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "persisted_flag") {
		t.Fatalf("annotation did not survive: %q", out)
	}
}

func TestDeleteProjectRejectsUnexpectedFiles(t *testing.T) {
	dir := t.TempDir()
	project := filepath.Join(dir, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "workspace.json"), []byte(`{"version":1,"targets":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "notes"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	w := New("r2", nil, false)
	if _, err := w.DeleteProject(project); err == nil {
		t.Fatal("deleted directory containing an unexpected file")
	}
	if _, err := os.Stat(filepath.Join(project, "notes")); err != nil {
		t.Fatalf("unexpected file was changed: %v", err)
	}
}

func TestDeleteProjectRemovesValidatedWorkspace(t *testing.T) {
	dir := t.TempDir()
	project := filepath.Join(dir, "project")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "workspace.json"), []byte(`{"version":1,"targets":[{"name":"one","path":"/bin/true"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "one.r2pj"), []byte("project"), 0600); err != nil {
		t.Fatal(err)
	}
	w := New("r2", nil, false)
	removed, err := w.DeleteProject(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Fatalf("removed = %v", removed)
	}
	if _, err := os.Stat(project); !os.IsNotExist(err) {
		t.Fatalf("project still exists: %v", err)
	}
}

type concurrentRunner struct {
	entered *atomic.Int32
	release <-chan struct{}
	path    string
}

func (f *concurrentRunner) Cmd(_ context.Context, cmd string) (string, error) {
	if strings.Contains(cmd, " Ps ") {
		f.entered.Add(1)
		<-f.release
		parts := strings.Split(cmd, "Ps ")
		return "", os.WriteFile(parts[len(parts)-1], []byte("project"), 0600)
	}
	return "", nil
}
func (*concurrentRunner) Close() error { return nil }

func TestSaveRunsTargetsConcurrently(t *testing.T) {
	dir := t.TempDir()
	w := New("r2", nil, false)
	var entered atomic.Int32
	release := make(chan struct{})
	w.SetFactory(func(_ context.Context, o r2.OpenOptions) (r2.Runner, error) {
		return &concurrentRunner{entered: &entered, release: release, path: o.Path}, nil
	})
	for _, name := range []string{"one", "two"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Open(context.Background(), Target{Name: name, Path: path}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() { done <- w.Save(context.Background(), filepath.Join(dir, "project")) }()
	deadline := time.After(2 * time.Second)
	for entered.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("project saves did not overlap")
		default:
			runtime.Gosched()
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
