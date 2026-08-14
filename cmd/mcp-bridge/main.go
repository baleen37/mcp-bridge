package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/baleen37/mcp-bridge/internal/cli"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "mcp-bridge:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	return cli.Execute(context.Background(), args, os.Stdin, stdout, stderr)
}
