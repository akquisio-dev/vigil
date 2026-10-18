package release

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const repoName = "akquisio-dev/vigil"

func fixture(t *testing.T, v string) (sums, bundle []byte) {
	t.Helper()
	sums, err := os.ReadFile("testdata/" + v + ".SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err = os.ReadFile("testdata/" + v + ".sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	return sums, bundle
}

// The fixtures are the real files of the v0.17.0 and v0.18.0 releases.
func TestVerifySumsReleases(t *testing.T) {
	for _, v := range []string{"v0.17.0", "v0.18.0"} {
		sums, b := fixture(t, v)
		if err := VerifySums(sums, b, repoName, v); err != nil {
			t.Errorf("%s: %v", v, err)
		}
	}
}

func TestVerifySumsRefuses(t *testing.T) {
	sums, b := fixture(t, "v0.18.0")
	oldSums, oldB := fixture(t, "v0.17.0")

	expect := func(name string, err error, want string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error with %q", name, err, want)
		}
	}
	// An older release passed off as a newer one.
	expect("old as new", VerifySums(oldSums, oldB, repoName, "v0.18.0"), "signed by")
	expect("fork", VerifySums(sums, b, "someone/vigil", "v0.18.0"), "signed by")
	// The new bundle for the old file, and the other way round.
	expect("other file", VerifySums(oldSums, b, repoName, "v0.18.0"), "does not match")

	// A changed byte anywhere in SHA256SUMS.
	bad := bytes.Clone(sums)
	bad[10] ^= 1
	expect("changed sums", VerifySums(bad, b, repoName, "v0.18.0"), "does not match")

	edit := func(f func(m map[string]any)) []byte {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		f(m)
		out, _ := json.Marshal(m)
		return out
	}
	rb := func(m map[string]any) map[string]any { return m["rekorBundle"].(map[string]any) }
	pl := func(m map[string]any) map[string]any { return rb(m)["Payload"].(map[string]any) }

	// A log entry timestamp that was not signed by Rekor.
	expect("time", VerifySums(sums, edit(func(m map[string]any) { pl(m)["integratedTime"] = pl(m)["integratedTime"].(float64) + 1 }), repoName, "v0.18.0"), "")
	expect("index", VerifySums(sums, edit(func(m map[string]any) { pl(m)["logIndex"] = pl(m)["logIndex"].(float64) + 1 }), repoName, "v0.18.0"), "timestamp does not verify")
	expect("log id", VerifySums(sums, edit(func(m map[string]any) { pl(m)["logID"] = strings.Repeat("0", 64) }), repoName, "v0.18.0"), "unknown log")
	expect("set", VerifySums(sums, edit(func(m map[string]any) {
		set, _ := base64.StdEncoding.DecodeString(rb(m)["SignedEntryTimestamp"].(string))
		set[len(set)-1] ^= 1
		rb(m)["SignedEntryTimestamp"] = base64.StdEncoding.EncodeToString(set)
	}), repoName, "v0.18.0"), "timestamp does not verify")
	// The log entry of another release under this signature.
	expect("other entry", VerifySums(sums, edit(func(m map[string]any) {
		var o map[string]any
		json.Unmarshal(oldB, &o)
		rb(m)["Payload"] = rb(o)["Payload"]
		rb(m)["SignedEntryTimestamp"] = rb(o)["SignedEntryTimestamp"]
	}), repoName, "v0.18.0"), "certificate")
	// The certificate of the old release with the new signature.
	expect("other cert", VerifySums(sums, edit(func(m map[string]any) {
		var o map[string]any
		json.Unmarshal(oldB, &o)
		m["cert"] = o["cert"]
	}), repoName, "v0.18.0"), "certificate")
	expect("no log", VerifySums(sums, edit(func(m map[string]any) { delete(m, "rekorBundle") }), repoName, "v0.18.0"), "incomplete")
	expect("garbage", VerifySums(sums, []byte("{"), repoName, "v0.18.0"), "bundle")
}
