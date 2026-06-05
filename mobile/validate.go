package mobile

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/matinsenpai/senpaiscanner/internal/xraytest"

	xcore "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
)

// ---------------------------------------------------------------------------
// Mobile-safe xray validation
//
// The shared xraytest.ValidateConfig in runner.go has three issues on Android:
//
//  1. It globally redirects os.Stdout/os.Stderr to /dev/null to suppress xray
//     output. On Android the gomobile/JNI bridge uses these FDs for cross-
//     language communication — swapping them causes deadlocks.
//
//  2. If xcore.New() fails (line 134-138 in runner.go), os.Stdout/os.Stderr
//     are NEVER restored and the devNull file descriptor leaks. After several
//     failed IPs the process runs out of FDs.
//
//  3. It writes a temp file and re-reads it, which can fail on Android
//     depending on the temp directory setup.
//
// This file reimplements the validation loop specifically for mobile, avoiding
// all three issues while keeping the same test logic (connectivity check via
// cloudflare trace + best-effort speed measurement).
// ---------------------------------------------------------------------------

var (
	mobilePortCounter atomic.Int32
	// mobileInstanceMu serializes xray instance creation/teardown so that
	// we never have two instances competing for ports and FDs on Android.
	mobileInstanceMu sync.Mutex
)

func init() {
	mobilePortCounter.Store(30000) // different range than desktop to avoid collisions
}

func mobileNextPort() int {
	return int(mobilePortCounter.Add(1))
}

const mobileTraceURL = "https://cp.cloudflare.com/cdn-cgi/trace"

// mobileValidateConfig is the Android-safe replacement for xraytest.ValidateConfig.
// It starts an xray instance, sends test traffic through it, and returns
// the result. Retries once on failure.
func mobileValidateConfig(ctx context.Context, cfg *xraytest.VLESSConfig, timeout time.Duration) *xraytest.ValidationResult {
	res := mobileValidateOnce(ctx, cfg, timeout)
	if !res.Success {
		time.Sleep(500 * time.Millisecond)
		res2 := mobileValidateOnce(ctx, cfg, timeout)
		res2.Retries = 1
		if res2.Success {
			return res2
		}
		res.Retries = 1
	}
	return res
}

func mobileValidateOnce(ctx context.Context, cfg *xraytest.VLESSConfig, timeout time.Duration) *xraytest.ValidationResult {
	res := &xraytest.ValidationResult{
		IP:        cfg.Address,
		Port:      cfg.Port,
		Transport: cfg.Network,
	}

	socksPort := mobileNextPort()

	configJSON, err := xraytest.BuildXrayConfig(cfg, socksPort)
	if err != nil {
		res.Error = fmt.Sprintf("build config: %v", err)
		return res
	}

	// Parse JSON config directly from bytes — no temp file needed.
	jsonConfig, err := serial.DecodeJSONConfig(bytes.NewReader(configJSON))
	if err != nil {
		res.Error = fmt.Sprintf("decode json config: %v", err)
		return res
	}

	pbConfig, err := jsonConfig.Build()
	if err != nil {
		res.Error = fmt.Sprintf("build pb config: %v", err)
		return res
	}

	// Serialize instance lifecycle to prevent resource contention on Android.
	mobileInstanceMu.Lock()

	instance, err := xcore.New(pbConfig)
	if err != nil {
		mobileInstanceMu.Unlock()
		res.Error = fmt.Sprintf("create instance: %v", err)
		return res
	}

	if err := instance.Start(); err != nil {
		instance.Close()
		mobileInstanceMu.Unlock()
		time.Sleep(100 * time.Millisecond)
		res.Error = fmt.Sprintf("start xray: %v", err)
		return res
	}

	// Instance is running and SOCKS port is bound — release the lock.
	mobileInstanceMu.Unlock()

	// NOTE: We intentionally do NOT redirect os.Stdout/os.Stderr.
	// The xray config already sets loglevel to "none" (see builder.go).
	// On Android, touching these global FDs deadlocks the JNI bridge.

	// Ensure cleanup + short delay for the OS to release the port.
	defer func() {
		instance.Close()
		time.Sleep(150 * time.Millisecond)
	}()

	if !mobileWaitForPort(socksPort, 5*time.Second) {
		res.Error = "socks port not ready after 5s"
		return res
	}

	proxyURL := fmt.Sprintf("socks5h://127.0.0.1:%d", socksPort)

	connectTimeout := timeout
	if connectTimeout > 18*time.Second {
		connectTimeout = 18 * time.Second
	}
	testCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	// Step 1: connectivity check (tunnel path, IP trace, then data-path fallback).
	traceOk, latency, traceErr := xraytest.ProxyConnectivityCheck(testCtx, proxyURL, cfg)
	res.Latency = latency
	if !traceOk {
		res.Error = fmt.Sprintf("connectivity: %v", traceErr)
		return res
	}

	// Step 2: best-effort speed measurement (does not affect Success).
	speedCtx, speedCancel := context.WithTimeout(ctx, mobileSpeedBudget(timeout, latency))
	defer speedCancel()
	bytesRecv, throughput := mobileSpeedTest(speedCtx, proxyURL, cfg)
	res.BytesRecv = bytesRecv
	res.Throughput = throughput
	res.Success = true
	return res
}

// ---------------------------------------------------------------------------
// Helper functions (re-implemented to avoid depending on unexported xraytest)
// ---------------------------------------------------------------------------

func mobileWaitForPort(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func mobileProxyTransport(proxyAddr string) *http.Transport {
	return &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			return url.Parse(proxyAddr)
		},
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   true,
	}
}

func mobileClientTimeout(ctx context.Context, fallback time.Duration) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return fallback
	}
	if remaining := time.Until(deadline); remaining > 0 {
		return remaining
	}
	return fallback
}

func mobileSpeedBudget(total, spent time.Duration) time.Duration {
	budget := 4 * time.Second
	remaining := total - spent
	if remaining < budget {
		budget = remaining
	}
	if budget < time.Second {
		return time.Second
	}
	return budget
}

func mobileDownload(ctx context.Context, proxyAddr, dlURL string, maxBytes int64, relaxed bool) (int64, float64, error) {
	if maxBytes <= 0 {
		return 0, 0, fmt.Errorf("invalid maxBytes %d", maxBytes)
	}
	client := &http.Client{
		Transport: mobileProxyTransport(proxyAddr),
		Timeout:   mobileClientTimeout(ctx, 30*time.Second),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("User-Agent", "senpaiscanner/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	if !relaxed && (resp.StatusCode < 200 || resp.StatusCode >= 400) {
		return 0, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if relaxed && resp.StatusCode >= 500 {
		return 0, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBytes))
	elapsed := time.Since(start).Seconds()
	if err != nil || n <= 0 || elapsed <= 0 {
		return n, 0, err
	}
	return n, float64(n) / elapsed, nil
}

func mobileSpeedTest(ctx context.Context, proxyAddr string, cfg *xraytest.VLESSConfig) (int64, float64) {
	const sampleBytes int64 = 128 * 1024
	const minBytes int64 = 8 * 1024

	// Try speed.cloudflare.com first.
	dlURL := fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", sampleBytes)
	bytesRecv, throughput, err := mobileDownload(ctx, proxyAddr, dlURL, sampleBytes, false)
	if err == nil && bytesRecv >= minBytes && throughput > 0 {
		return bytesRecv, throughput
	}

	// Fallback: host-based download through the config's host/path.
	if cfg != nil {
		host := cfg.Host
		if host == "" {
			host = cfg.SNI
		}
		if host != "" {
			fallbackURL := "https://" + host + "/"
			if cfg.Path != "" {
				p := cfg.Path
				if !strings.HasPrefix(p, "/") {
					p = "/" + p
				}
				fallbackURL = "https://" + host + p
			}
			bytesRecv, throughput, err = mobileDownload(ctx, proxyAddr, fallbackURL, sampleBytes, true)
			if err == nil && bytesRecv >= minBytes && throughput > 0 {
				return bytesRecv, throughput
			}
		}
	}

	// Last fallback: burst trace requests.
	return mobileBurstThroughput(ctx, proxyAddr, mobileTraceURL, sampleBytes)
}

func mobileBurstThroughput(ctx context.Context, proxyAddr, targetURL string, targetBytes int64) (int64, float64) {
	if targetBytes <= 0 {
		return 0, 0
	}
	start := time.Now()
	var total int64
	const workers = 4 // fewer workers on mobile to conserve resources

	for total < targetBytes && ctx.Err() == nil {
		var wg sync.WaitGroup
		var batch int64
		var bmu sync.Mutex

		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				n, _, err := mobileDownload(ctx, proxyAddr, targetURL, 16384, true)
				if err != nil || n <= 0 {
					return
				}
				bmu.Lock()
				batch += n
				bmu.Unlock()
			}()
		}
		wg.Wait()
		if batch == 0 {
			break
		}
		total += batch
	}

	elapsed := time.Since(start).Seconds()
	if total < 4096 || elapsed <= 0 {
		return total, 0
	}
	return total, float64(total) / elapsed
}
