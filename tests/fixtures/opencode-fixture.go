// OpenCode host preflight verifies native executable bytes and rejects
// script/npm shims, so readiness fixtures must be real binaries. This
// metadata-only fixture answers only --version and executes no client
// runtime actions.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("1.18.34")
		return
	}
	os.Exit(1)
}
