package tofu_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zorneth/osg-core/tofu"
)

func TestTOFUFirstThenMismatch(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := tofu.Open(filepath.Join(dir, "tofu.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyOrCache(bin); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyOrCache(bin); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("v2-changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyOrCache(bin); err == nil {
		t.Fatal("expected fingerprint mismatch")
	}
}
