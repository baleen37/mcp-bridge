package tools

import (
	"context"
	"strings"
	"testing"
	"time"
)

// RunLimited buffers stdout and stderr before Exec joins and trims them, so the
// shared budget has to be checked at the buffer, not on the final text: capping
// each stream separately still yields a correctly sized result.
func TestRunLimitedSharesBudgetBetweenStreams(t *testing.T) {
	const limit = 40
	stdout, stderr, _, truncated, err := OSCommandRunner{}.RunLimited(
		context.Background(),
		t.TempDir(),
		"printf 'o%.0s' $(seq 100); printf 'e%.0s' $(seq 100) >&2",
		10*time.Second,
		limit,
	)
	if err != nil {
		t.Fatal(err)
	}
	if buffered := len(stdout) + len(stderr); buffered > limit {
		t.Fatalf("buffered %d bytes (stdout %d, stderr %d), want at most %d", buffered, len(stdout), len(stderr), limit)
	}
	if !truncated {
		t.Fatal("truncated = false, want true")
	}
}

func TestExecSharesOutputLimitAcrossStdoutAndStderr(t *testing.T) {
	service, workspaceRecord := testService(t)
	result, err := service.Exec(context.Background(), ExecInput{
		WorkspaceID: workspaceRecord.ID,
		// 100 bytes on each stream, against a 40-byte limit.
		Command:         "printf 'o%.0s' $(seq 100); printf 'e%.0s' $(seq 100) >&2",
		MaxOutputTokens: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Text) > 40 {
		t.Fatalf("text is %d bytes, want at most 40", len(result.Text))
	}
	if !result.Truncated {
		t.Fatalf("result = %#v, want Truncated", result)
	}
}

func TestExecReportsNotTruncatedWithinLimit(t *testing.T) {
	service, workspaceRecord := testService(t)
	result, err := service.Exec(context.Background(), ExecInput{
		WorkspaceID:     workspaceRecord.ID,
		Command:         "printf 'out'; printf 'err' >&2",
		MaxOutputTokens: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Text != "out\nerr" || result.Truncated {
		t.Fatalf("result = %#v, want untruncated %q", result, "out\nerr")
	}
}

func TestExecTruncatesOnRuneBoundary(t *testing.T) {
	service, workspaceRecord := testService(t)
	// Each 한 is 3 bytes, so the 8-byte limit lands mid-rune: 2 runes fit, the
	// third would need byte 9.
	result, err := service.Exec(context.Background(), ExecInput{
		WorkspaceID:     workspaceRecord.ID,
		Command:         "printf '한한한한'",
		MaxOutputTokens: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Text != "한한" || !result.Truncated {
		t.Fatalf("result = %#v, want 6-byte rune-aligned output", result)
	}
	if strings.ContainsRune(result.Text, '�') {
		t.Fatalf("text %q contains a broken rune", result.Text)
	}
}
