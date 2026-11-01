// checkdeps enforces the public-protocol / private-Hub dependency boundary.
// Run from protocol-go by default; use -hub ./cmd/hub in the private checkout.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func main() {
	hub := flag.String("hub", "", "Hub package; also require a real immutable protocol module pin")
	flag.Parse()
	target := "./..."
	if *hub != "" {
		target = *hub
	}
	out, err := exec.Command("go", "list", "-deps", target).Output()
	if err != nil {
		fmt.Fprintln(os.Stderr, "dependency graph unavailable:", err)
		os.Exit(1)
	}
	for _, dep := range strings.Fields(string(out)) {
		if dep == "github.com/flynn/noise" || strings.Contains(dep, "linked-realms-connect/internal/") {
			fmt.Fprintln(os.Stderr, "forbidden dependency:", dep)
			os.Exit(1)
		}
	}
	if *hub != "" {
		out, err = exec.Command("go", "list", "-m", "-json", "github.com/diata0210/linked-realms-connect/protocol-go").Output()
		if err != nil {
			panic(err)
		}
		var m struct {
			Version, Sum string
			Replace      any
		}
		if json.Unmarshal(out, &m) != nil || m.Version == "" || m.Sum == "" || m.Replace != nil {
			fmt.Fprintln(os.Stderr, "Hub must pin the published protocol module with checksum and no replace/workspace")
			os.Exit(1)
		}
	}
	fmt.Println("protocol/Hub dependency boundary passed")
}
