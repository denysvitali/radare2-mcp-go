package r2

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Runner is the narrow radare2 boundary used by the workspace and by tests.
type Runner interface {
	Cmd(context.Context, string) (string, error)
	Close() error
}

type OpenOptions struct {
	Path   string
	Base   uint64
	Arch   string
	Bits   int
	CPU    string
	Endian string
	Debug  bool
}

// Process is a persistent r2 -q0 worker. One worker is created per target so
// opening one target can never destroy another target's analysis state.
type Process struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	closed bool
}

func Open(ctx context.Context, binary string, o OpenOptions) (*Process, error) {
	args := []string{"-q0", "-e", "scr.color=0", "-e", "scr.interactive=false", "-e", "bin.relocs.apply=true"}
	if o.Arch != "" {
		args = append(args, "-a", o.Arch)
	}
	if o.Bits != 0 {
		args = append(args, "-b", strconv.Itoa(o.Bits))
	}
	if o.Base != 0 {
		args = append(args, "-m", fmt.Sprintf("0x%x", o.Base))
	}
	if o.CPU != "" {
		args = append(args, "-e", "asm.cpu="+o.CPU)
	}
	switch strings.ToLower(o.Endian) {
	case "big", "be":
		args = append(args, "-e", "cfg.bigendian=true")
	case "little", "le":
		args = append(args, "-e", "cfg.bigendian=false")
	case "", "auto":
	default:
		return nil, fmt.Errorf("endian must be auto, big, or little")
	}
	if o.Debug {
		args = append(args, "-d")
	}
	// Paths are normalized to absolute paths by the workspace (or are gdb://
	// URIs), so they cannot be mistaken for options and need no "--" marker;
	// radare2 itself treats that marker as a filename.
	args = append(args, o.Path)
	// The worker outlives the workspace_open request, so it must not inherit that
	// request's cancellation. Startup itself is still bounded below.
	cmd := exec.CommandContext(context.WithoutCancel(ctx), binary, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start radare2: %w", err)
	}
	p := &Process{cmd: cmd, stdin: stdin, stdout: bufio.NewReader(stdout)}
	ready := make(chan error, 1)
	go func() {
		_, err := p.stdout.ReadString(0)
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			_ = p.Close()
			return nil, fmt.Errorf("radare2 startup: %w", err)
		}
		return p, nil
	case <-ctx.Done():
		_ = p.Close()
		return nil, ctx.Err()
	}
}

func (p *Process) Cmd(ctx context.Context, command string) (string, error) {
	if strings.ContainsAny(command, "\r\n\x00") {
		return "", errors.New("r2 command contains a line delimiter")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return "", errors.New("radare2 process is closed")
	}
	if _, err := io.WriteString(p.stdin, command+"\n"); err != nil {
		return "", fmt.Errorf("write radare2 command: %w", err)
	}
	type answer struct {
		text string
		err  error
	}
	done := make(chan answer, 1)
	go func() {
		text, err := p.stdout.ReadString(0)
		done <- answer{strings.TrimSuffix(text, "\x00"), err}
	}()
	select {
	case a := <-done:
		return strings.TrimSpace(a.text), a.err
	case <-ctx.Done():
		_ = p.cmd.Process.Signal(os.Interrupt)
		select {
		case a := <-done:
			if a.err != nil {
				p.closed = true
			}
		case <-time.After(2 * time.Second):
			_ = p.cmd.Process.Kill()
			p.closed = true
		}
		return "", ctx.Err()
	}
}

func (p *Process) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	_, _ = io.WriteString(p.stdin, "q!\n")
	_ = p.stdin.Close()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		_ = p.cmd.Process.Kill()
		return <-done
	}
}
