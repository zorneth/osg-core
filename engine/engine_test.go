package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zorneth/osg-core/engine"
	"github.com/zorneth/osg-core/policy"
	"github.com/zorneth/osg-core/tofu"
)

func TestRegoDenyHost(t *testing.T) {
	dir := t.TempDir()
	rego := filepath.Join(dir, "deny.rego")
	if err := os.WriteFile(rego, []byte("deny host evil.example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc := policy.Document{Version: 1, RegoPath: rego}
	doc.SetNetworkAllows([]policy.AllowRule{
		{Host: "evil.example", Port: 443},
		{Host: "good.example", Port: 443},
	})
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	d, _ := eng.Decide(context.Background(), engine.EgressRequest{Host: "evil.example", Port: 443})
	if d.Allow {
		t.Fatal("expected rego deny")
	}
	d, _ = eng.Decide(context.Background(), engine.EgressRequest{Host: "good.example", Port: 443})
	if !d.Allow {
		t.Fatal("expected allow")
	}
}

func TestBinaryTOFU(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "curl")
	_ = os.WriteFile(bin, []byte("bin"), 0o755)
	store, err := tofu.Open(filepath.Join(dir, "tofu.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc := policy.Document{Version: 1, Binaries: []string{bin}}
	doc.SetNetworkAllows([]policy.AllowRule{{Host: "example.com", Port: 443}})
	var eng engine.Allowlist
	eng.SetTOFU(store)
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	d, _ := eng.Decide(context.Background(), engine.EgressRequest{Host: "example.com", Port: 443, Binary: bin})
	if !d.Allow {
		t.Fatalf("first: %v", d)
	}
	_ = os.WriteFile(bin, []byte("changed"), 0o755)
	d, _ = eng.Decide(context.Background(), engine.EgressRequest{Host: "example.com", Port: 443, Binary: bin})
	if d.Allow {
		t.Fatal("expected tofu deny")
	}
}
