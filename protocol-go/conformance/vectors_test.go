package conformance

import (
	"os"
	"testing"
)

func TestFrozenVectors(t *testing.T) {
	b, err := os.ReadFile("../../protocol/vectors/v1.json")
	if err != nil {
		t.Fatal(err)
	}
	results, err := CheckVectors(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		t.Run(r.Name, func(t *testing.T) {
			if r.Err != nil {
				t.Fatal(r.Err)
			}
		})
	}
}
