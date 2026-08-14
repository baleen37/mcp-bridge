package mcp

import (
	"context"
	"fmt"

	"github.com/baleen37/mcp-bridge/internal/auth"
	"github.com/baleen37/mcp-bridge/internal/config"
	"github.com/baleen37/mcp-bridge/internal/tools"
	"github.com/baleen37/mcp-bridge/internal/workspace"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type OpenWorkspaceInput struct {
	Path    string `json:"path"`
	Mode    string `json:"mode,omitempty"`
	BaseRef string `json:"base_ref,omitempty"`
}

type OpenWorkspaceOutput struct {
	WorkspaceID  string `json:"workspace_id"`
	Root         string `json:"root"`
	Instructions string `json:"instructions"`
}

type TextOutput struct {
	Text string `json:"text"`
}

type ExecOutput struct {
	Text      string `json:"text"`
	ExitCode  int    `json:"exit_code"`
	Truncated bool   `json:"truncated"`
	TimedOut  bool   `json:"timed_out"`
}

type ReadFileInput struct {
	WorkspaceID string `json:"workspace_id"`
	Path        string `json:"path"`
	Offset      int    `json:"offset,omitempty"`
	Limit       int    `json:"limit,omitempty"`
}

type GrepFilesInput struct {
	WorkspaceID string `json:"workspace_id"`
	Pattern     string `json:"pattern"`
	Path        string `json:"path,omitempty"`
	Include     string `json:"include,omitempty"`
	Limit       int    `json:"limit,omitempty"`
}

type ListDirInput struct {
	WorkspaceID string `json:"workspace_id"`
	Path        string `json:"path"`
}

type ApplyPatchInput struct {
	WorkspaceID string       `json:"workspace_id"`
	Path        string       `json:"path"`
	Edits       []EditChange `json:"edits"`
}

type EditChange struct {
	OldText string `json:"old_text"`
	NewText string `json:"new_text"`
}

type ExecCommandInput struct {
	WorkspaceID     string `json:"workspace_id"`
	Command         string `json:"cmd"`
	Workdir         string `json:"workdir,omitempty"`
	TimeoutMS       int    `json:"timeout_ms,omitempty"`
	MaxOutputTokens int    `json:"max_output_tokens,omitempty"`
}

type DownloadArtifactInput struct {
	WorkspaceID string `json:"workspace_id"`
	File        string `json:"file"`
	Path        string `json:"path"`
}

type DownloadArtifactOutput struct {
	Text   string `json:"text"`
	SHA256 string `json:"sha256"`
}

func NewServer(cfg config.Config, _ *auth.Provider, workspaces *workspace.Registry, service *tools.Service) *sdkmcp.Server {
	server := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "mcp-bridge", Version: "0.1.0"}, &sdkmcp.ServerOptions{
		Instructions: "Open a workspace first, then use the workspace_id in subsequent calls.",
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "open_workspace", Title: "Open workspace", Description: "Open a project checkout or create a detached Git worktree."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input OpenWorkspaceInput) (*sdkmcp.CallToolResult, OpenWorkspaceOutput, error) {
		record, err := workspaces.Open(ctx, input.Path, input.Mode, input.BaseRef)
		if err != nil {
			return nil, OpenWorkspaceOutput{}, err
		}
		return textResult(fmt.Sprintf("Opened workspace %s at %s.", record.ID, record.Root)), OpenWorkspaceOutput{
			WorkspaceID:  record.ID,
			Root:         record.Root,
			Instructions: "Reuse this workspace_id for subsequent tool calls.",
		}, nil
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "read_file", Title: "Read file", Description: "Read a UTF-8 file."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input ReadFileInput) (*sdkmcp.CallToolResult, TextOutput, error) {
		result, err := service.Read(ctx, tools.ReadInput{WorkspaceID: input.WorkspaceID, Path: input.Path, Offset: input.Offset, Limit: input.Limit})
		return textResult(result.Text), TextOutput{Text: result.Text}, err
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "grep_files", Title: "Grep files", Description: "Search file contents."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input GrepFilesInput) (*sdkmcp.CallToolResult, TextOutput, error) {
		result, err := service.Grep(ctx, tools.GrepInput{WorkspaceID: input.WorkspaceID, Pattern: input.Pattern, Path: input.Path, Include: input.Include})
		return textResult(result.Text), TextOutput{Text: result.Text}, err
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "list_dir", Title: "List directory", Description: "List a directory."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input ListDirInput) (*sdkmcp.CallToolResult, TextOutput, error) {
		result, err := service.LS(ctx, tools.LSInput{WorkspaceID: input.WorkspaceID, Path: input.Path})
		return textResult(result.Text), TextOutput{Text: result.Text}, err
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "apply_patch", Title: "Apply patch", Description: "Replace exact unique text blocks in a file."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input ApplyPatchInput) (*sdkmcp.CallToolResult, TextOutput, error) {
		edits := make([]tools.Edit, len(input.Edits))
		for i, edit := range input.Edits {
			edits[i] = tools.Edit{OldText: edit.OldText, NewText: edit.NewText}
		}
		result, err := service.Edit(ctx, tools.EditInput{WorkspaceID: input.WorkspaceID, Path: input.Path, Edits: edits})
		return textResult(result.Text), TextOutput{Text: result.Text}, err
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "exec_command", Title: "Execute command", Description: "Run a bounded shell command."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input ExecCommandInput) (*sdkmcp.CallToolResult, ExecOutput, error) {
		result, err := service.Exec(ctx, tools.ExecInput{WorkspaceID: input.WorkspaceID, Command: input.Command, WorkingDir: input.Workdir, TimeoutMS: input.TimeoutMS, MaxOutputTokens: input.MaxOutputTokens})
		return textResult(result.Text), ExecOutput{Text: result.Text, ExitCode: result.ExitCode, Truncated: result.Truncated, TimedOut: result.TimedOut}, err
	})

	if cfg.ArtifactDownloadsEnabled {
		sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "download_artifact", Title: "Download artifact", Description: "Download an HTTPS artifact into the workspace."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input DownloadArtifactInput) (*sdkmcp.CallToolResult, DownloadArtifactOutput, error) {
			result, err := service.DownloadArtifact(ctx, tools.DownloadArtifactInput{WorkspaceID: input.WorkspaceID, File: input.File, Path: input.Path})
			return textResult(result.Text), DownloadArtifactOutput{Text: result.Text, SHA256: result.SHA256}, err
		})
	}

	return server
}

func textResult(text string) *sdkmcp.CallToolResult {
	return &sdkmcp.CallToolResult{Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: text}}}
}
