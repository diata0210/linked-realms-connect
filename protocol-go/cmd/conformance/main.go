// conformance is usable by private Hub CI from the exact pinned public module.
package main

import (
	"flag"
	"fmt"
	"github.com/diata0210/linked-realms-connect/protocol-go/conformance"
	"os"
)

func main() {
	path := flag.String("vectors", "", "path to hash-verified matching public vectors/v1.json")
	flag.Parse()
	if *path == "" {
		fmt.Fprintln(os.Stderr, "-vectors is required; verify release manifest before invoking")
		os.Exit(1)
	}
	b, err := os.ReadFile(*path)
	if err != nil {
		panic(err)
	}
	results, err := conformance.CheckVectors(b)
	if err != nil {
		panic(err)
	}
	bad := false
	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", r.Name, r.Err)
			bad = true
		}
	}
	if bad {
		os.Exit(1)
	}
	fmt.Printf("%d production codec cases passed\n", len(results))
}
