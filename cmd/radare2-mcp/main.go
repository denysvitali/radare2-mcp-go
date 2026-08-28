package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/denysvitali/radare2-mcp-go/internal/server"
	"github.com/denysvitali/radare2-mcp-go/internal/workspace"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRootCommand().ExecuteContext(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func newRootCommand() *cobra.Command {
	var configFile string
	cmd := &cobra.Command{
		Use:           "radare2-mcp",
		Short:         "A multi-binary radare2 MCP server",
		Version:       server.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			settings, err := loadSettings(cmd, configFile)
			if err != nil {
				return err
			}
			ws := workspace.New(settings.GetString("r2"), settings.GetStringSlice("root"), settings.GetBool("allow-unsafe-commands"))
			defer ws.CloseAll()
			return server.New(ws).Run(cmd.Context(), &mcp.StdioTransport{})
		},
	}
	cmd.Flags().String("r2", "r2", "radare2 executable")
	cmd.Flags().StringSlice("root", nil, "allowed filesystem root (repeatable or comma-separated; unrestricted when omitted)")
	cmd.Flags().Bool("allow-unsafe-commands", false, "allow command chaining, shell escapes, remote GDB, and redirection in r2_command")
	cmd.Flags().StringVar(&configFile, "config", "", "configuration file (YAML, JSON, or TOML)")
	return cmd
}

func loadSettings(cmd *cobra.Command, configFile string) (*viper.Viper, error) {
	settings := viper.New()
	settings.SetEnvPrefix("RADARE2_MCP")
	settings.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	settings.AutomaticEnv()
	if err := settings.BindPFlags(cmd.Flags()); err != nil {
		return nil, fmt.Errorf("bind flags: %w", err)
	}

	if configFile != "" {
		settings.SetConfigFile(configFile)
		if err := settings.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read configuration: %w", err)
		}
		return settings, nil
	}

	settings.SetConfigName("radare2-mcp")
	settings.AddConfigPath(".")
	if configDir, err := os.UserConfigDir(); err == nil {
		settings.AddConfigPath(configDir)
		settings.AddConfigPath(configDir + string(os.PathSeparator) + "radare2-mcp")
	}
	if err := settings.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if !errors.As(err, &notFound) {
			return nil, fmt.Errorf("read configuration: %w", err)
		}
	}
	return settings, nil
}
