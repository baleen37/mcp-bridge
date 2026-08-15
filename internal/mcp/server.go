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
	Path    string `json:"path" jsonschema:"Absolute or user-relative path to the project directory, which must live beneath an allowed root."`
	Mode    string `json:"mode,omitempty" jsonschema:"Either \"checkout\" to use the directory as is, or \"worktree\" to create a detached Git worktree. Defaults to \"checkout\"."`
	BaseRef string `json:"base_ref,omitempty" jsonschema:"Git ref the worktree is created from in \"worktree\" mode. Defaults to HEAD, and is ignored in \"checkout\" mode."`
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

type ChangesOutput struct {
	Text         string   `json:"text"`
	FilesChanged int      `json:"files_changed"`
	Additions    int      `json:"additions"`
	Deletions    int      `json:"deletions"`
	Untracked    []string `json:"untracked"`
	Truncated    bool     `json:"truncated"`
}

type ReadFileInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"Workspace handle returned by open_workspace."`
	Path        string `json:"path" jsonschema:"File path relative to the workspace root. It cannot escape that root."`
	Offset      int    `json:"offset,omitempty" jsonschema:"1-based line number to start reading from. Defaults to 1, meaning the first line."`
	Limit       int    `json:"limit,omitempty" jsonschema:"Maximum number of lines to return starting at offset. Omit or use 0 to read to the end of the file."`
}

type WriteFileInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"Workspace handle returned by open_workspace."`
	Path        string `json:"path" jsonschema:"File path relative to the workspace root. Missing parent directories are created, and it cannot escape that root."`
	Content     string `json:"content" jsonschema:"Full UTF-8 contents to write. This replaces the whole file, so pass the complete text rather than a fragment."`
}

type GrepFilesInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"Workspace handle returned by open_workspace."`
	Pattern     string `json:"pattern" jsonschema:"Go RE2 regular expression matched against each line. This is a regex, not a glob, so escape regex metacharacters to search for them literally."`
	Path        string `json:"path,omitempty" jsonschema:"Directory relative to the workspace root to search under. Defaults to the whole workspace."`
	Include     string `json:"include,omitempty" jsonschema:"Glob filter on the file path relative to the search directory, such as \"*.go\" or \"**/*_test.go\". Defaults to every file."`
	Limit       int    `json:"limit,omitempty" jsonschema:"Stop after this many matching lines. Omit or use 0 for no limit."`
}

type ListDirInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"Workspace handle returned by open_workspace."`
	Path        string `json:"path" jsonschema:"Directory path relative to the workspace root. Use \".\" for the workspace root itself."`
}

type ShowChangesInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"Workspace handle returned by open_workspace."`
	Path        string `json:"path,omitempty" jsonschema:"Limit the report to this file or directory, relative to the workspace root. Defaults to the whole repository."`
}

type ApplyPatchInput struct {
	WorkspaceID string       `json:"workspace_id" jsonschema:"Workspace handle returned by open_workspace."`
	Path        string       `json:"path" jsonschema:"File path relative to the workspace root. The file must already exist; use write_file to create one."`
	Edits       []EditChange `json:"edits" jsonschema:"One or more replacements applied to the file in a single atomic write. They must not overlap."`
}

type EditChange struct {
	OldText string `json:"old_text" jsonschema:"Exact existing text to replace, including indentation and newlines. It must occur exactly once in the file, so include surrounding context to make it unique."`
	NewText string `json:"new_text" jsonschema:"Replacement text. Use an empty string to delete the matched block."`
}

type ExecCommandInput struct {
	WorkspaceID     string `json:"workspace_id" jsonschema:"Workspace handle returned by open_workspace."`
	Command         string `json:"cmd" jsonschema:"Shell command line run through /bin/sh -lc, so pipes, redirection, and shell operators work."`
	Workdir         string `json:"workdir,omitempty" jsonschema:"Directory relative to the workspace root to run in. Defaults to the workspace root."`
	TimeoutMS       int    `json:"timeout_ms,omitempty" jsonschema:"Timeout in milliseconds, between 1 and 300000. Defaults to 30000, meaning 30 seconds."`
	MaxOutputTokens int    `json:"max_output_tokens,omitempty" jsonschema:"Output budget counted at 4 bytes per token. Total output never exceeds 1 MiB regardless of this value."`
}

type DownloadArtifactInput struct {
	WorkspaceID string `json:"workspace_id" jsonschema:"Workspace handle returned by open_workspace."`
	File        string `json:"file" jsonschema:"HTTPS URL of the artifact to download. Append a \"#sha256=...\" fragment to verify the digest."`
	Path        string `json:"path" jsonschema:"Destination path relative to the workspace root. It must not already exist."`
}

type DownloadArtifactOutput struct {
	Text   string `json:"text"`
	SHA256 string `json:"sha256"`
}

func NewServer(cfg config.Config, _ *auth.Provider, workspaces *workspace.Registry, service *tools.Service) *sdkmcp.Server {
	server := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "mcp-bridge", Version: "0.1.0"}, &sdkmcp.ServerOptions{
		Instructions: "Open a workspace first, then use the workspace_id in subsequent calls.",
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "open_workspace", Title: "Open workspace", Description: "Open a project checkout or create a detached Git worktree, and return the workspace_id every other tool requires. The path must live beneath a configured allowed root. In \"checkout\" mode the directory is used as is; in \"worktree\" mode a detached Git worktree is created from base_ref, defaulting to HEAD, under the state directory. Call this first."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input OpenWorkspaceInput) (*sdkmcp.CallToolResult, OpenWorkspaceOutput, error) {
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

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "read_file", Title: "Read file", Description: "Read a UTF-8 text file inside a workspace and return its contents. Paths are relative to the workspace root and cannot escape it. Use offset, a 1-based line number, together with limit to page through a large file; both are optional and the whole file is returned by default."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input ReadFileInput) (*sdkmcp.CallToolResult, TextOutput, error) {
		result, err := service.Read(ctx, tools.ReadInput{WorkspaceID: input.WorkspaceID, Path: input.Path, Offset: input.Offset, Limit: input.Limit})
		if err != nil {
			return nil, TextOutput{}, err
		}
		return textResult(result.Text), TextOutput{Text: result.Text}, nil
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "write_file", Title: "Write file", Description: "Create a file, or replace an existing one, with the exact content given. Missing parent directories are created, and the write is atomic. Use this to create new files, since apply_patch can only replace text that already exists. Prefer apply_patch when changing part of a file you have already read, because write_file discards everything else."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input WriteFileInput) (*sdkmcp.CallToolResult, TextOutput, error) {
		result, err := service.Write(ctx, tools.WriteInput{WorkspaceID: input.WorkspaceID, Path: input.Path, Content: input.Content})
		if err != nil {
			return nil, TextOutput{}, err
		}
		return textResult(result.Text), TextOutput{Text: result.Text}, nil
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "grep_files", Title: "Grep files", Description: "Search file contents line by line and return \"path:line:text\" matches sorted by path. The pattern is a Go RE2 regular expression, not a glob, and it is matched against each line rather than the whole file. Narrow the search with path for a subdirectory and include for a filename glob such as \"*.go\". Binary files, symlinks, and build or dependency directories such as .git, node_modules, vendor, target, dist, and build are always skipped."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input GrepFilesInput) (*sdkmcp.CallToolResult, TextOutput, error) {
		result, err := service.Grep(ctx, tools.GrepInput{WorkspaceID: input.WorkspaceID, Pattern: input.Pattern, Path: input.Path, Include: input.Include, Limit: input.Limit})
		if err != nil {
			return nil, TextOutput{}, err
		}
		return textResult(result.Text), TextOutput{Text: result.Text}, nil
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "list_dir", Title: "List directory", Description: "List the immediate entries of a directory inside a workspace, one per line as \"name\\tfile|dir\\tsize\" sorted by name. This is not recursive; call it again on a subdirectory to descend. Use \".\" for the workspace root."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input ListDirInput) (*sdkmcp.CallToolResult, TextOutput, error) {
		result, err := service.LS(ctx, tools.LSInput{WorkspaceID: input.WorkspaceID, Path: input.Path})
		if err != nil {
			return nil, TextOutput{}, err
		}
		return textResult(result.Text), TextOutput{Text: result.Text}, nil
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "show_changes", Title: "Show changes", Description: "Show the uncommitted changes in a Git workspace as porcelain status followed by a unified diff against HEAD, including the contents of untracked files. Also reports how many files changed and how many lines were added and removed. Pass path to limit the report to one file or directory. The workspace must be a Git repository, and very large output is truncated."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input ShowChangesInput) (*sdkmcp.CallToolResult, ChangesOutput, error) {
		result, err := service.ShowChanges(ctx, tools.ShowChangesInput{WorkspaceID: input.WorkspaceID, Path: input.Path})
		if err != nil {
			return nil, ChangesOutput{}, err
		}
		return textResult(result.Text), ChangesOutput{
			Text:         result.Text,
			FilesChanged: result.FilesChanged,
			Additions:    result.Additions,
			Deletions:    result.Deletions,
			Untracked:    result.Untracked,
			Truncated:    result.Truncated,
		}, nil
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "apply_patch", Title: "Apply patch", Description: "Replace exact text blocks in an existing file. Each old_text must match the file byte for byte, including indentation and newlines, and must occur exactly once, so include enough surrounding context to make it unique. Edits must not overlap, and all of them are applied in one atomic write, or none are. Read the file first, and use write_file to create a new one."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input ApplyPatchInput) (*sdkmcp.CallToolResult, TextOutput, error) {
		edits := make([]tools.Edit, len(input.Edits))
		for i, edit := range input.Edits {
			edits[i] = tools.Edit{OldText: edit.OldText, NewText: edit.NewText}
		}
		result, err := service.Edit(ctx, tools.EditInput{WorkspaceID: input.WorkspaceID, Path: input.Path, Edits: edits})
		if err != nil {
			return nil, TextOutput{}, err
		}
		return textResult(result.Text), TextOutput{Text: result.Text}, nil
	})

	sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "exec_command", Title: "Execute command", Description: "Run a shell command through /bin/sh -lc inside the workspace, and return the combined stdout and stderr along with the exit code. The default timeout is 30000 ms, and timeout_ms accepts 1 to 300000 ms. An ordinary non-zero exit is a normal result, not an error, so check exit_code. Output is capped at 1 MiB and the truncated flag reports when it was cut."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input ExecCommandInput) (*sdkmcp.CallToolResult, ExecOutput, error) {
		result, err := service.Exec(ctx, tools.ExecInput{WorkspaceID: input.WorkspaceID, Command: input.Command, WorkingDir: input.Workdir, TimeoutMS: input.TimeoutMS, MaxOutputTokens: input.MaxOutputTokens})
		if err != nil {
			return nil, ExecOutput{}, err
		}
		return textResult(result.Text), ExecOutput{Text: result.Text, ExitCode: result.ExitCode, Truncated: result.Truncated, TimedOut: result.TimedOut}, nil
	})

	if cfg.ArtifactDownloadsEnabled {
		sdkmcp.AddTool(server, &sdkmcp.Tool{Name: "download_artifact", Title: "Download artifact", Description: "Download an HTTPS artifact into the workspace and return its SHA-256 digest. Only a fixed allow-list of hosts is accepted, and the destination path must not already exist. Append a \"#sha256=...\" fragment to the URL to have the digest verified before the file is kept."}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, input DownloadArtifactInput) (*sdkmcp.CallToolResult, DownloadArtifactOutput, error) {
			result, err := service.DownloadArtifact(ctx, tools.DownloadArtifactInput{WorkspaceID: input.WorkspaceID, File: input.File, Path: input.Path})
			if err != nil {
				return nil, DownloadArtifactOutput{}, err
			}
			return textResult(result.Text), DownloadArtifactOutput{Text: result.Text, SHA256: result.SHA256}, nil
		})
	}

	return server
}

func textResult(text string) *sdkmcp.CallToolResult {
	return &sdkmcp.CallToolResult{Content: []sdkmcp.Content{&sdkmcp.TextContent{Text: text}}}
}
