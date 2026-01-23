// Package httputil provides shared HTTP utilities with connection pooling
// and safe response handling for the Citadel gateway.
package httputil

import (
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// MaxResponseSize is the default maximum size for reading HTTP response bodies.
// This prevents OOM attacks from malicious/compromised services.
const MaxResponseSize = 10 * 1024 * 1024 // 10MB

// Shared transport with optimized connection pooling.
// This is safe for concurrent use and dramatically improves performance
// by reusing TCP connections across requests.
var sharedTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	MaxIdleConnsPerHost:   10,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// TimeoutTier defines standard timeout categories for different operation types.
type TimeoutTier int

const (
	// TierFast for quick operations like health checks (5s)
	TierFast TimeoutTier = iota
	// TierMedium for standard API calls (30s)
	TierMedium
	// TierSlow for AI/ML operations that may take longer (60s)
	TierSlow
)

var timeoutDurations = map[TimeoutTier]time.Duration{
	TierFast:   5 * time.Second,
	TierMedium: 30 * time.Second,
	TierSlow:   60 * time.Second,
}

// Singleton clients for each timeout tier - initialized once, reused everywhere.
var (
	clientFast   *http.Client
	clientMedium *http.Client
	clientSlow   *http.Client
	clientOnce   sync.Once
)

func initClients() {
	clientFast = &http.Client{
		Timeout:   timeoutDurations[TierFast],
		Transport: sharedTransport,
	}
	clientMedium = &http.Client{
		Timeout:   timeoutDurations[TierMedium],
		Transport: sharedTransport,
	}
	clientSlow = &http.Client{
		Timeout:   timeoutDurations[TierSlow],
		Transport: sharedTransport,
	}
}

// Client returns a shared HTTP client for the given timeout tier.
// These clients share a connection pool and should be used instead of
// creating new http.Client instances per request.
//
// Usage:
//
//	client := httputil.Client(httputil.TierMedium)
//	resp, err := client.Post(url, "application/json", body)
func Client(tier TimeoutTier) *http.Client {
	clientOnce.Do(initClients)
	switch tier {
	case TierFast:
		return clientFast
	case TierMedium:
		return clientMedium
	case TierSlow:
		return clientSlow
	default:
		return clientMedium
	}
}

// FastClient returns a client with 5s timeout (health checks, simple queries).
func FastClient() *http.Client {
	return Client(TierFast)
}

// MediumClient returns a client with 30s timeout (standard API calls).
func MediumClient() *http.Client {
	return Client(TierMedium)
}

// SlowClient returns a client with 60s timeout (AI/ML operations).
func SlowClient() *http.Client {
	return Client(TierSlow)
}

// ReadResponseBody safely reads an HTTP response body with size limits.
// This prevents OOM attacks from malicious or compromised services.
//
// Usage:
//
//	body, err := httputil.ReadResponseBody(resp.Body, httputil.MaxResponseSize)
func ReadResponseBody(r io.Reader, maxSize int64) ([]byte, error) {
	if maxSize <= 0 {
		maxSize = MaxResponseSize
	}
	return io.ReadAll(io.LimitReader(r, maxSize))
}

// ReadErrorBody reads the response body for error messages with a reasonable limit.
// Uses a smaller limit (1MB) since error messages shouldn't be large.
func ReadErrorBody(r io.Reader) ([]byte, error) {
	const maxErrorSize = 1 * 1024 * 1024 // 1MB for error messages
	return io.ReadAll(io.LimitReader(r, maxErrorSize))
}

// DrainAndClose properly drains and closes an HTTP response body.
// This ensures connection reuse in the pool.
func DrainAndClose(body io.ReadCloser) {
	if body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(body, MaxResponseSize))
		_ = body.Close()
	}
}
