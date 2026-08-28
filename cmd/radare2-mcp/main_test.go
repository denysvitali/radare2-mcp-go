package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/denysvitali/radare2-mcp-go/internal/server"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCobraViperConfiguration(t *testing.T) {
	t.Setenv("RADARE2_MCP_R2", "/env/r2")
	cmd := newRootCommand()
	if err := cmd.Flags().Set("root", "/binaries,/projects"); err != nil {
		t.Fatal(err)
	}
	settings, err := loadSettings(cmd, "")
	if err != nil {
		t.Fatal(err)
	}
	if settings.GetString("r2") != "/env/r2" {
		t.Fatalf("environment setting not loaded: %q", settings.GetString("r2"))
	}
	if roots := settings.GetStringSlice("root"); len(roots) != 2 || roots[0] != "/binaries" || roots[1] != "/projects" {
		t.Fatalf("Cobra roots not bound through Viper: %v", roots)
	}

	version := newRootCommand()
	var output bytes.Buffer
	version.SetOut(&output)
	version.SetArgs([]string{"--version"})
	if err := version.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), server.Version) {
		t.Fatalf("version output missing %s: %q", server.Version, output.String())
	}
}

func TestLoadSettingsFromConfigFile(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(config, []byte("r2: /config/r2\nroot:\n  - /one\n  - /two\nallow-unsafe-commands: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := loadSettings(newRootCommand(), config)
	if err != nil {
		t.Fatal(err)
	}
	if got := settings.GetString("r2"); got != "/config/r2" {
		t.Fatalf("r2 = %q", got)
	}
	if roots := settings.GetStringSlice("root"); len(roots) != 2 || roots[0] != "/one" || roots[1] != "/two" {
		t.Fatalf("roots = %v", roots)
	}
	if !settings.GetBool("allow-unsafe-commands") {
		t.Fatal("boolean configuration was not loaded")
	}
}

func TestFlagsOverrideEnvironmentAndConfig(t *testing.T) {
	t.Setenv("RADARE2_MCP_R2", "/env/r2")
	config := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(config, []byte(`r2 = "/config/r2"`), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newRootCommand()
	if err := cmd.Flags().Set("r2", "/flag/r2"); err != nil {
		t.Fatal(err)
	}
	settings, err := loadSettings(cmd, config)
	if err != nil {
		t.Fatal(err)
	}
	if got := settings.GetString("r2"); got != "/flag/r2" {
		t.Fatalf("r2 precedence = %q", got)
	}
}

func TestExplicitConfigFileMustExist(t *testing.T) {
	_, err := loadSettings(newRootCommand(), filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil || !strings.Contains(err.Error(), "read configuration") {
		t.Fatalf("expected configuration error, got %v", err)
	}
}

// This test crosses the actual process/stdio boundary used by Codex. The
// in-memory protocol tests under internal/server deliberately cover a
// different boundary.
func TestStdioServerEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("r2"); err != nil {
		if os.Getenv("RADARE2_REQUIRED") == "1" {
			t.Fatal("r2 required by test environment")
		}
		t.Skip("r2 not installed")
	}
	binary := filepath.Join(t.TempDir(), "radare2-mcp")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build server: %v\n%s", err, output)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "stdio-smoke-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: exec.CommandContext(ctx, binary)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := session.Close(); err != nil {
			t.Errorf("close session: %v", err)
		}
	}()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) < 24 {
		t.Fatalf("expected full tool surface, got %d", len(tools.Tools))
	}
	opened, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "workspace_open",
		Arguments: map[string]any{
			"name": "smoke",
			"path": "/bin/true",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if opened.IsError {
		t.Fatalf("workspace_open failed: %+v", opened.Content)
	}
	stringsResult, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name: "list_strings",
		Arguments: map[string]any{
			"target":      "smoke",
			"all":         true,
			"filter":      "ld-linux",
			"max_results": 5,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stringsResult.IsError || stringsResult.StructuredContent == nil {
		t.Fatalf("list_strings failed: %+v", stringsResult.Content)
	}
	if _, ok := stringsResult.Meta["duration_ms"]; !ok {
		t.Fatalf("list_strings omitted duration metadata: %#v", stringsResult.Meta)
	}
	for _, call := range []*mcp.CallToolParams{
		{Name: "capabilities", Arguments: map[string]any{"target": "smoke"}},
		{Name: "analyze", Arguments: map[string]any{"target": "smoke", "level": "basic"}},
		{Name: "analysis_status", Arguments: map[string]any{"target": "smoke", "level": "basic"}},
		{Name: "inspect", Arguments: map[string]any{"target": "smoke", "kind": "functions", "count": 5}},
	} {
		result, callErr := session.CallTool(ctx, call)
		if callErr != nil || result.IsError || result.StructuredContent == nil {
			t.Fatalf("%s failed: result=%+v err=%v", call.Name, result, callErr)
		}
	}
}
