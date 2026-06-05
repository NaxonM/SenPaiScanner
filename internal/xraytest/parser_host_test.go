package xraytest

import "testing"

func TestParseVLESS_WinterThunderWorkersHostPreserved(t *testing.T) {
	raw := "vless://3441b906-471f-4160-8f2c-a981793e6155@104.18.151.101:2087?encryption=none&security=tls&sni=winter-thunder-0638.matinsenpaivideo2.workers.dev&fp=chrome&insecure=0&allowInsecure=0&type=ws&host=winter-thunder-0638.matinsenpaivideo2.workers.dev&path=%2F#CF%E5%AE%98%E6%96%B9%E4%BC%98%E9%80%8916"

	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatalf("ParseVLESS failed: %v", err)
	}
	want := "winter-thunder-0638.matinsenpaivideo2.workers.dev"
	if cfg.Host != want {
		t.Fatalf("Host = %q, want %q", cfg.Host, want)
	}
	if cfg.SNI != want {
		t.Fatalf("SNI = %q, want %q", cfg.SNI, want)
	}
	if cfg.Path != "/" {
		t.Fatalf("Path = %q, want /", cfg.Path)
	}
}

func TestNormalizeKnownHostTypos_FixesWorersDev(t *testing.T) {
	got := normalizeKnownHostTypos("winter-thunder-0638.matinsenpaivideo2.worers.dev")
	want := "winter-thunder-0638.matinsenpaivideo2.workers.dev"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseVLESS_FixesSavedWorersTypo(t *testing.T) {
	raw := "vless://3441b906-471f-4160-8f2c-a981793e6155@104.18.151.101:2087?encryption=none&security=tls&sni=winter-thunder-0638.matinsenpaivideo2.worers.dev&fp=chrome&insecure=0&allowInsecure=0&type=ws&host=winter-thunder-0638.matinsenpaivideo2.worers.dev&path=%2F#test"
	cfg, err := ParseVLESS(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := "winter-thunder-0638.matinsenpaivideo2.workers.dev"
	if cfg.Host != want || cfg.SNI != want {
		t.Fatalf("Host=%q SNI=%q, want %q", cfg.Host, cfg.SNI, want)
	}
}

func TestExtractQueryValue_DoesNotTruncateWorkersInHost(t *testing.T) {
	query := "encryption=none&security=tls&sni=winter-thunder-0638.matinsenpaivideo2.workers.dev&fp=chrome&insecure=0&allowInsecure=0&type=ws&host=winter-thunder-0638.matinsenpaivideo2.workers.dev&path=%2F"
	got := extractQueryValue(query, "host")
	want := "winter-thunder-0638.matinsenpaivideo2.workers.dev"
	if got != want {
		t.Fatalf("host = %q, want %q", got, want)
	}
}
