// Package ml provides OpenRouter-based embedding generation.
// Uses Qwen3 embedding model via OpenRouter API for high-quality vector embeddings.
package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/TryMightyAI/citadel/pkg/httputil"
)

// OpenRouterEmbedder implements EmbeddingProvider using OpenRouter API.
// Supports Qwen3 embedding model with configurable dimensions.
type OpenRouterEmbedder struct {
	apiKey     string
	baseURL    string
	model      string
	dimension  int
	httpClient *http.Client
	mu         sync.RWMutex

	// Rate limiting
	lastRequest time.Time
	minInterval time.Duration

	// Stats
	totalCalls   int64
	totalTokens  int64
	totalLatency time.Duration
}

// OpenRouterEmbedderConfig configures the OpenRouter embedder.
type OpenRouterEmbedderConfig struct {
	APIKey    string // OpenRouter API key (defaults to OPENROUTER_API_KEY env)
	BaseURL   string // API base URL (defaults to https://openrouter.ai/api/v1)
	Model     string // Model name (defaults to qwen/qwen3-embedding-4b)
	Dimension int    // Embedding dimension (defaults to 1024, max 2048 for Qwen3)
	Timeout   time.Duration
}

// DefaultOpenRouterEmbedderConfig returns sensible defaults.
func DefaultOpenRouterEmbedderConfig() OpenRouterEmbedderConfig {
	return OpenRouterEmbedderConfig{
		APIKey:    os.Getenv("OPENROUTER_API_KEY"),
		BaseURL:   "https://openrouter.ai/api/v1",
		Model:     "qwen/qwen3-embedding-4b",
		Dimension: 1024, // Good balance of quality vs storage
		Timeout:   30 * time.Second,
	}
}

// NewOpenRouterEmbedder creates a new OpenRouter-based embedder.
func NewOpenRouterEmbedder(cfg OpenRouterEmbedderConfig) (*OpenRouterEmbedder, error) {
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("OPENROUTER_API_KEY")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("OpenRouter API key not configured (set OPENROUTER_API_KEY)")
	}

	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://openrouter.ai/api/v1"
	}

	if cfg.Model == "" {
		cfg.Model = "qwen/qwen3-embedding-4b"
	}

	if cfg.Dimension <= 0 {
		cfg.Dimension = 1024
	}
	if cfg.Dimension > 2048 {
		cfg.Dimension = 2048 // Qwen3 max
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	embedder := &OpenRouterEmbedder{
		apiKey:      cfg.APIKey,
		baseURL:     cfg.BaseURL,
		model:       cfg.Model,
		dimension:   cfg.Dimension,
		httpClient:  httputil.MediumClient(), // Shared client with connection pooling (30s timeout)
		minInterval: 50 * time.Millisecond,   // Rate limit: max 20 req/sec
	}

	log.Printf("[EMBEDDER] OpenRouter initialized: model=%s, dim=%d", cfg.Model, cfg.Dimension)
	return embedder, nil
}

// embeddingRequest is the OpenRouter embedding API request format.
type embeddingRequest struct {
	Model      string   `json:"model"`
	Input      []string `json:"input"`
	Dimensions int      `json:"dimensions,omitempty"` // For models that support matryoshka
}

// embeddingResponse is the OpenRouter embedding API response format.
type embeddingResponse struct {
	Object string `json:"object"`
	Data   []struct {
		Object    string    `json:"object"`
		Embedding []float64 `json:"embedding"`
		Index     int       `json:"index"`
	} `json:"data"`
	Model string `json:"model"`
	Usage struct {
		PromptTokens int `json:"prompt_tokens"`
		TotalTokens  int `json:"total_tokens"`
	} `json:"usage"`
}

// Embed generates an embedding for a single text.
func (e *OpenRouterEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	embeddings, err := e.EmbedBatch(ctx, []string{text})
	if err != nil {
		return nil, err
	}
	if len(embeddings) == 0 {
		return nil, fmt.Errorf("no embedding returned")
	}
	return embeddings[0], nil
}

// EmbedBatch generates embeddings for multiple texts.
func (e *OpenRouterEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}

	// Rate limiting
	e.mu.Lock()
	elapsed := time.Since(e.lastRequest)
	if elapsed < e.minInterval {
		time.Sleep(e.minInterval - elapsed)
	}
	e.lastRequest = time.Now()
	e.mu.Unlock()

	start := time.Now()

	// Build request
	reqBody := embeddingRequest{
		Model:      e.model,
		Input:      texts,
		Dimensions: e.dimension,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", e.baseURL+"/embeddings", bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.apiKey)
	req.Header.Set("HTTP-Referer", "https://citadel.security") // OpenRouter requires this
	req.Header.Set("X-Title", "Citadel AI Security")

	// Execute request
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("embedding request failed: %w", err)
	}
	defer httputil.DrainAndClose(resp.Body)

	// Read response with bounded size to prevent OOM
	body, err := httputil.ReadResponseBody(resp.Body, httputil.MaxResponseSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embedding API error (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var embResp embeddingResponse
	if err := json.Unmarshal(body, &embResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Convert to float32 slices
	result := make([][]float32, len(texts))
	for _, data := range embResp.Data {
		if data.Index >= len(texts) {
			continue
		}
		embedding := make([]float32, len(data.Embedding))
		for i, v := range data.Embedding {
			embedding[i] = float32(v)
		}
		result[data.Index] = embedding
	}

	// Update stats
	e.mu.Lock()
	e.totalCalls++
	e.totalTokens += int64(embResp.Usage.TotalTokens)
	e.totalLatency += time.Since(start)
	e.mu.Unlock()

	return result, nil
}

// Dimension returns the embedding dimension.
func (e *OpenRouterEmbedder) Dimension() int {
	return e.dimension
}

// Stats returns embedder statistics.
func (e *OpenRouterEmbedder) Stats() map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()

	avgLatency := time.Duration(0)
	if e.totalCalls > 0 {
		avgLatency = e.totalLatency / time.Duration(e.totalCalls)
	}

	return map[string]any{
		"model":           e.model,
		"dimension":       e.dimension,
		"total_calls":     e.totalCalls,
		"total_tokens":    e.totalTokens,
		"avg_latency_ms":  avgLatency.Milliseconds(),
		"total_latency_s": e.totalLatency.Seconds(),
	}
}

// =============================================================================
// NoOpEmbedder: For testing or when embeddings are disabled
// =============================================================================

// NoOpEmbedder is a placeholder that returns zero vectors.
// Used when no embedding service is configured.
type NoOpEmbedder struct {
	dimension int
}

// NewNoOpEmbedder creates a no-op embedder.
func NewNoOpEmbedder(dimension int) *NoOpEmbedder {
	if dimension <= 0 {
		dimension = 1024
	}
	return &NoOpEmbedder{dimension: dimension}
}

// Embed returns a zero vector.
func (e *NoOpEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	return make([]float32, e.dimension), nil
}

// EmbedBatch returns zero vectors.
func (e *NoOpEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	result := make([][]float32, len(texts))
	for i := range texts {
		result[i] = make([]float32, e.dimension)
	}
	return result, nil
}

// Dimension returns the embedding dimension.
func (e *NoOpEmbedder) Dimension() int {
	return e.dimension
}

// =============================================================================
// Factory function for creating embedders
// =============================================================================

// EmbedderConfig holds configuration for creating an embedder.
type EmbedderConfig struct {
	Provider  string // "openrouter", "local", "noop"
	APIKey    string // API key for the provider
	Model     string // Model name
	Dimension int    // Embedding dimension
	BaseURL   string // Custom API URL
}

// NewEmbedder creates an EmbeddingProvider based on configuration.
func NewEmbedder(cfg EmbedderConfig) (EmbeddingProvider, error) {
	switch cfg.Provider {
	case "openrouter", "":
		// Default to OpenRouter if API key is available
		if cfg.APIKey == "" {
			cfg.APIKey = os.Getenv("OPENROUTER_API_KEY")
		}
		if cfg.APIKey != "" {
			return NewOpenRouterEmbedder(OpenRouterEmbedderConfig{
				APIKey:    cfg.APIKey,
				Model:     cfg.Model,
				Dimension: cfg.Dimension,
				BaseURL:   cfg.BaseURL,
			})
		}
		// Fall back to NoOp if no API key
		log.Printf("[EMBEDDER] No API key configured, using NoOp embedder (semantic search disabled)")
		return NewNoOpEmbedder(cfg.Dimension), nil

	case "noop":
		return NewNoOpEmbedder(cfg.Dimension), nil

	default:
		return nil, fmt.Errorf("unknown embedding provider: %s", cfg.Provider)
	}
}
