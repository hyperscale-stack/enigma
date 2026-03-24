package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/hyperscale-stack/enigma/document"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: enigma-inspect <encrypted-file>\n")
		os.Exit(2)
	}
	info, err := document.Inspect(context.Background(), os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "inspect failed: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(info); err != nil {
		fmt.Fprintf(os.Stderr, "encode failed: %v\n", err)
		os.Exit(1)
	}
}
