package r2

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestProcessPersistsAfterOpenContextCancellation(t *testing.T) {
	if _, err := exec.LookPath("r2"); err != nil {
		if os.Getenv("RADARE2_REQUIRED") == "1" {
			t.Fatal("r2 required by test environment")
		}
		t.Skip("r2 not installed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p, err := Open(ctx, "r2", OpenOptions{Path: "/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	defer func() {
		if err := p.Close(); err != nil {
			t.Errorf("close process: %v", err)
		}
	}()
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	out, err := p.Cmd(callCtx, "ij")
	if err != nil {
		t.Fatalf("worker died with open context: %v", err)
	}
	if !strings.Contains(out, `"core"`) {
		t.Fatalf("unexpected info: %.200s", out)
	}
}

func TestRejectsMultilineCommand(t *testing.T) {
	p := &Process{}
	if _, err := p.Cmd(context.Background(), "ij\n!sh"); err == nil {
		t.Fatal("expected delimiter rejection")
	}
}
