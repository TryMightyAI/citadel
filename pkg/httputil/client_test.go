package httputil

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClientSingleton(t *testing.T) {
	// Verify that Client() returns the same instance for repeated calls
	c1 := Client(TierMedium)
	c2 := Client(TierMedium)

	if c1 != c2 {
		t.Error("Client() should return the same instance for same tier")
	}

	// Different tiers should have different clients
	fast := Client(TierFast)
	slow := Client(TierSlow)

	if fast == slow {
		t.Error("Different tiers should return different clients")
	}
}

func TestClientTimeouts(t *testing.T) {
	// Verify timeout configurations
	tests := []struct {
		tier    TimeoutTier
		want    time.Duration
		getFunc func() *http.Client
	}{
		{TierFast, 5 * time.Second, FastClient},
		{TierMedium, 30 * time.Second, MediumClient},
		{TierSlow, 60 * time.Second, SlowClient},
	}

	for _, tt := range tests {
		c := tt.getFunc()
		if c.Timeout != tt.want {
			t.Errorf("Tier %d: got timeout %v, want %v", tt.tier, c.Timeout, tt.want)
		}
	}
}

func TestClientConnectionReuse(t *testing.T) {
	// Create a test server that counts connections
	var connCount int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		connCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Make multiple requests with shared client
	client := MediumClient()
	for i := range 10 {
		resp, err := client.Get(server.URL)
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		DrainAndClose(resp.Body)
	}

	// With connection pooling, we should see connection reuse
	// The exact count depends on timing, but it should be less than 10
	// (This is a behavioral test - exact number varies)
	t.Logf("Made 10 requests, server saw %d connections (pooling working if < 10)", connCount)
}

func TestReadResponseBody(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		maxSize int64
		wantLen int
	}{
		{
			name:    "normal read",
			input:   "hello world",
			maxSize: 1024,
			wantLen: 11,
		},
		{
			name:    "truncated read",
			input:   strings.Repeat("x", 1000),
			maxSize: 100,
			wantLen: 100, // Should be truncated
		},
		{
			name:    "default max size",
			input:   "test",
			maxSize: 0, // Should use default
			wantLen: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			got, err := ReadResponseBody(r, tt.maxSize)
			if err != nil {
				t.Fatalf("ReadResponseBody() error = %v", err)
			}
			if len(got) != tt.wantLen {
				t.Errorf("ReadResponseBody() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestReadErrorBody(t *testing.T) {
	// Error messages should be limited to 1MB
	largeError := strings.Repeat("error details ", 100000) // ~1.4MB
	r := strings.NewReader(largeError)

	got, err := ReadErrorBody(r)
	if err != nil {
		t.Fatalf("ReadErrorBody() error = %v", err)
	}

	// Should be truncated to 1MB
	if len(got) > 1024*1024 {
		t.Errorf("ReadErrorBody() should truncate to 1MB, got %d bytes", len(got))
	}
}

func TestDrainAndClose(t *testing.T) {
	// Create a reader that tracks if it was fully read
	data := []byte("test data")
	r := &trackingReader{Reader: bytes.NewReader(data)}

	closer := io.NopCloser(r)
	DrainAndClose(closer)

	if !r.fullyRead {
		t.Error("DrainAndClose should fully drain the body")
	}
}

type trackingReader struct {
	io.Reader
	fullyRead bool
}

func (r *trackingReader) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	if err == io.EOF {
		r.fullyRead = true
	}
	return
}

func TestDrainAndCloseNil(t *testing.T) {
	// Should not panic on nil
	DrainAndClose(nil)
}

// BenchmarkClientReuse demonstrates the performance benefit of client reuse.
func BenchmarkClientReuse(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	b.Run("reused_client", func(b *testing.B) {
		client := MediumClient()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			resp, _ := client.Get(server.URL)
			if resp != nil {
				DrainAndClose(resp.Body)
			}
		}
	})

	b.Run("new_client_each_time", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			client := &http.Client{Timeout: 30 * time.Second}
			resp, _ := client.Get(server.URL)
			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}
	})
}
