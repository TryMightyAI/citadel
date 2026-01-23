package ml

import (
	"context"
	"fmt"
)

// IntentResult represents the response from the intent classifier
type IntentResult struct {
	Label      string  `json:"label"`      // "SAFE" or "INJECTION"
	Confidence float64 `json:"confidence"` // 0.0 to 1.0
	Model      string  `json:"model"`      // Model name used
	LatencyMs  float64 `json:"latency_ms"` // Inference time

	// Enhanced fields for bi-directional detection
	AnalyzedText     string   `json:"analyzed_text,omitempty"`     // Which text was actually analyzed
	WasDeobfuscated  bool     `json:"was_deobfuscated,omitempty"`  // If deobfuscated text was used
	ObfuscationTypes []string `json:"obfuscation_types,omitempty"` // Obfuscation types from Go

	// Mode/profile fields for unified dual-stack routing
	Action      string `json:"action,omitempty"`       // "BLOCK", "WARN", "ALLOW" (from Python)
	ModeUsed    string `json:"mode_used,omitempty"`    // Detection mode used
	ProfileUsed string `json:"profile_used,omitempty"` // Detection profile used
	Skipped     bool   `json:"skipped,omitempty"`      // True if Python skipped inference (fast mode)
}

// IntentRequest is the request body for the intent classifier
type IntentRequest struct {
	Text             string   `json:"text"`                        // Original text
	DeobfuscatedText string   `json:"deobfuscated_text,omitempty"` // Pre-decoded text from Go
	ObfuscationTypes []string `json:"obfuscation_types,omitempty"` // What decoders triggered

	// Detection configuration (passed to Python for unified routing)
	Mode            string `json:"mode,omitempty"`             // "fast", "secure", "auto"
	Profile         string `json:"profile,omitempty"`          // "strict", "balanced", "permissive"
	EstimatedTokens int    `json:"estimated_tokens,omitempty"` // Token count for model routing
}

// IntentClassifier defines the interface for intent classification.
// The default implementation is disabled; Pro registers the real implementation.
type IntentClassifier interface {
	// IsAvailable checks if the classifier service is available
	IsAvailable() bool
	// IsEnabled returns whether classification is enabled
	IsEnabled() bool
	// Enable turns on intent classification
	Enable()
	// Disable turns off intent classification
	Disable()
	// ClassifyIntent calls the transformer model to classify text
	ClassifyIntent(ctx context.Context, text string) (*IntentResult, error)
	// ClassifyIntentWithContext calls the transformer model with deobfuscation context
	ClassifyIntentWithContext(ctx context.Context, text string, deobResult *DeobfuscationResult) (*IntentResult, error)
	// ClassifyIntentWithOptions calls the transformer model with full options
	ClassifyIntentWithOptions(ctx context.Context, text string, deobResult *DeobfuscationResult, opts *DetectionOptions) (*IntentResult, error)
}

// intentClientFactory is the factory function to create IntentClient.
// Pro package overrides this at init() time.
var intentClientFactory func() IntentClassifier

// RegisterIntentClientFactory registers the Pro IntentClient factory.
// Called from pro/pkg/ml/init().
func RegisterIntentClientFactory(factory func() IntentClassifier) {
	intentClientFactory = factory
}

// NewIntentClient creates an IntentClient.
// Returns a disabled client in OSS mode, or the Pro implementation if registered.
func NewIntentClient() IntentClassifier {
	if intentClientFactory != nil {
		return intentClientFactory()
	}
	return &disabledIntentClient{}
}

// disabledIntentClient is the OSS stub that returns disabled/not available.
type disabledIntentClient struct{}

func (c *disabledIntentClient) IsAvailable() bool { return false }
func (c *disabledIntentClient) IsEnabled() bool   { return false }
func (c *disabledIntentClient) Enable()           {}
func (c *disabledIntentClient) Disable()          {}

func (c *disabledIntentClient) ClassifyIntent(ctx context.Context, text string) (*IntentResult, error) {
	return nil, fmt.Errorf("intent classifier not available (OSS build)")
}

func (c *disabledIntentClient) ClassifyIntentWithContext(ctx context.Context, text string, deobResult *DeobfuscationResult) (*IntentResult, error) {
	return nil, fmt.Errorf("intent classifier not available (OSS build)")
}

func (c *disabledIntentClient) ClassifyIntentWithOptions(ctx context.Context, text string, deobResult *DeobfuscationResult, opts *DetectionOptions) (*IntentResult, error) {
	return nil, fmt.Errorf("intent classifier not available (OSS build)")
}
