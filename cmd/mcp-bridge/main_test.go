package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"--help"}, &out, &errOut); err != nil {
		t.Fatalf("run --help: %v", err)
	}
	for _, command := range []string{"setup", "status", "remove"} {
		if !strings.Contains(out.String(), command) {
			t.Fatalf("help output does not mention %q: %s", command, out.String())
		}
	}
	for _, command := range []string{"init", "start", "stop", "smoke-test", "install", "uninstall"} {
		if strings.Contains(out.String(), "  "+command+"\n") {
			t.Fatalf("help output exposes advanced command %q: %s", command, out.String())
		}
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"unknown"}, &out, &errOut); err == nil {
		t.Fatal("expected unknown command to fail")
	}
}
