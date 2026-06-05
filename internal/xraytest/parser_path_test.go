package xraytest

import (
	"strings"
	"testing"
)

func TestParseVLESS_PathWithEmbeddedQueryAndAmpersand(t *testing.T) {
	raw := "vless://3a24f4fb-c574-43f4-8041-2c1a381779af@188.114.97.3:443?encryption=none&security=tls&sni=test.workers.dev&fp=chrome&alpn=http%2F1.1&type=ws&host=mmm.example.workers.dev&path=/eyJqdW5rIjoidmlIaTNjaHNmWE1pIiwicHJvdG9jb2wiOiJ2bCIsIm1vZGUiOiJwcmVmaXgiLCJwYW5lbElQcyI6WyJbMjYwMjpmYzU5OmIwOjY0OjpdIl19?ed=2560#test"

	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatalf("ParseVLESS failed: %v", err)
	}
	if len(cfg.Path) < 80 {
		t.Fatalf("path too short (%d chars): %q", len(cfg.Path), cfg.Path)
	}
	if !strings.Contains(cfg.Path, "eyJ") || !strings.Contains(cfg.Path, "ed=2560") {
		t.Fatalf("path missing expected segments: %q", cfg.Path)
	}
	if cfg.Host != "mmm.example.workers.dev" {
		t.Fatalf("host = %q", cfg.Host)
	}
}

func TestParseVLESS_PathSplitByBareAmpersand(t *testing.T) {
	// Simulates a partially-encoded link where '&' inside the path value breaks ParseQuery.
	raw := "vless://12345678-1234-1234-1234-123456789abc@1.1.1.1:443?type=ws&host=worker.example.dev&path=/eyJqdW5rIjoidmlI&mode=prefix&security=tls&sni=worker.example.dev"

	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatalf("ParseVLESS failed: %v", err)
	}
	if cfg.Path != "/eyJqdW5rIjoidmlI" {
		t.Fatalf("path = %q", cfg.Path)
	}
}

func TestPhase2SanityErrorTruncatedPath(t *testing.T) {
	cfg := &VLESSConfig{Network: "ws", Host: "x.workers.dev", Path: "/eyJqdW5rI"}
	if got := cfg.Phase2SanityError(); got == "" {
		t.Fatal("expected sanity error for truncated path")
	}
}
