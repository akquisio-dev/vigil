// Command verifysums checks a signed SHA256SUMS the way agents do before
// they update themselves. The release workflow runs it, so a release whose
// signature agents could not check is never published.
//
//	go run ./tools/verifysums SHA256SUMS SHA256SUMS.sigstore.json v0.19.0
package main

import (
	"fmt"
	"os"

	"github.com/akquisio-dev/vigil/internal/release"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: verifysums SHA256SUMS BUNDLE VERSION")
		os.Exit(2)
	}
	sums, err := os.ReadFile(os.Args[1])
	if err == nil {
		var bundle []byte
		if bundle, err = os.ReadFile(os.Args[2]); err == nil {
			err = release.VerifySums(sums, bundle, release.Repo, os.Args[3])
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "verifysums:", err)
		os.Exit(1)
	}
	fmt.Println("signature of", os.Args[1], "for", os.Args[3], "verified")
}
