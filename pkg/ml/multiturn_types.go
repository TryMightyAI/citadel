package ml

import (
	"time"
)

// ============================================================================
// OSS MULTI-TURN DETECTION TYPES
// ============================================================================
// Core types for multi-turn attack detection in OSS. These types do NOT
// contain Pro-specific fields (drift, budget, LLM judge, intent classification).
//
// Pro extends these via embedding in pro/internal/multiturn/types.go.
//
// NOTE: During development, unified_multiturn.go contains similar types with
// "Unified" prefix for Pro. The extraction script (extract-oss.sh) excludes
// unified_multiturn.go and includes these OSS types.
//
// Type locations:
//   - TurnData, PatternRisk, StoredPatternSignal, CrossWindowContext:
//     Defined in multiturn_patterns.go (pattern detection types)
//   - MultiTurnRequest, MultiTurnResponse, SessionState, MTTurnRecord:
//     Defined here (session and API types for OSS detector)

// MultiTurnRequest is the OSS API entry point for multi-turn detection.
type MultiTurnRequest struct {
	// Identity (required)
	SessionID string `json:"session_id"`
	OrgID     string `json:"org_id"`

	// Current turn content (required)
	Content string `json:"content"`

	// Detection profile (optional - defaults to "balanced")
	// Options: "strict", "balanced", "permissive"
	Profile string `json:"profile,omitempty"`
}

// MultiTurnResponse contains OSS detection results.
type MultiTurnResponse struct {
	// Decision
	Verdict     string  `json:"verdict"`      // ALLOW, BLOCK, WARN
	Confidence  float64 `json:"confidence"`   // 0.0 - 1.0
	ShouldBlock bool    `json:"should_block"` // Convenience field

	// Turn info
	TurnNumber   int `json:"turn_number"`
	SessionTurns int `json:"session_turns"`

	// Pattern detection results
	PatternMatches []MTPatternMatch `json:"pattern_matches,omitempty"`
	PatternBoost   float64          `json:"pattern_boost"`
	PatternPhase   string           `json:"pattern_phase,omitempty"`

	// Semantic detection results (if enabled)
	SemanticScore float64 `json:"semantic_score,omitempty"`

	// Combined analysis
	FinalScore   float64  `json:"final_score"`
	BlockReasons []string `json:"block_reasons,omitempty"`

	// Processing time
	LatencyMs int `json:"latency_ms"`
}

// MTPatternMatch represents a detected pattern in multi-turn context.
// Uses MT prefix to avoid conflict with PatternMatchResult in unified_multiturn.go
type MTPatternMatch struct {
	PatternName string  `json:"pattern_name"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
	Phase       string  `json:"phase,omitempty"`
	IsPartial   bool    `json:"is_partial,omitempty"`
}

// SessionState tracks multi-turn session state for OSS.
// Pro extends this with Trajectory, Budget, and IntentHistory fields.
type SessionState struct {
	SessionID   string    `json:"session_id"`
	OrgID       string    `json:"org_id"`
	CreatedAt   time.Time `json:"created_at"`
	LastTurnAt  time.Time `json:"last_turn_at"`
	TurnCount   int       `json:"turn_count"`
	MaxMessages int       `json:"max_messages"` // OSS default: 15

	// Message history (sliding window)
	Messages []MTTurnRecord `json:"messages"`

	// Pattern signals (cross-window detection)
	// Persists across window trimming to detect multi-window attacks
	PatternSignals map[string]*StoredPatternSignal `json:"pattern_signals,omitempty"`

	// Cumulative risk score
	CumulativeRisk float64 `json:"cumulative_risk"`

	// Session lock state
	Locked     bool   `json:"locked"`
	LockReason string `json:"lock_reason,omitempty"`
}

// MTTurnRecord stores a single turn's data for multi-turn detection.
// Uses MT prefix to avoid conflict with TurnRecord in unified_multiturn.go
type MTTurnRecord struct {
	TurnNumber    int       `json:"turn_number"`
	Content       string    `json:"content"`
	RiskScore     float64   `json:"risk_score"`
	Phase         string    `json:"phase"`
	Confidence    float64   `json:"confidence"`
	PatternMatch  string    `json:"pattern_match,omitempty"`
	Verdict       string    `json:"verdict"`
	Timestamp     time.Time `json:"timestamp"`
	ProcessTimeMs int       `json:"process_time_ms"`
}

// MultiTurnConfig configures the multi-turn detector.
// Uses different name to avoid conflict with DetectorConfig elsewhere.
type MultiTurnConfig struct {
	// Session limits
	MaxMessages int `json:"max_messages"` // Default: 15 (OSS), 30-50 (Pro)

	// Thresholds
	BlockThreshold float64 `json:"block_threshold"` // Default: 0.75
	WarnThreshold  float64 `json:"warn_threshold"`  // Default: 0.55

	// Feature toggles
	EnableSemantics bool `json:"enable_semantics"`  // Default: true
	EnableRiskDecay bool `json:"enable_risk_decay"` // Default: true

	// Risk decay settings
	RiskDecayRate float64 `json:"risk_decay_rate"` // Default: 0.15
}

// DefaultMultiTurnConfig returns the default OSS multi-turn detector configuration.
func DefaultMultiTurnConfig() *MultiTurnConfig {
	return &MultiTurnConfig{
		MaxMessages:     15,
		BlockThreshold:  0.75,
		WarnThreshold:   0.55,
		EnableSemantics: true,
		EnableRiskDecay: true,
		RiskDecayRate:   0.15,
	}
}

// Pre-defined multi-turn detection profiles
var (
	// MTStrictConfig is for high-security environments
	MTStrictConfig = &MultiTurnConfig{
		MaxMessages:     10,
		BlockThreshold:  0.60,
		WarnThreshold:   0.40,
		EnableSemantics: true,
		EnableRiskDecay: false,
		RiskDecayRate:   0.0,
	}

	// MTBalancedConfig is the default for most use cases
	MTBalancedConfig = DefaultMultiTurnConfig()

	// MTPermissiveConfig is for low-risk environments
	MTPermissiveConfig = &MultiTurnConfig{
		MaxMessages:     20,
		BlockThreshold:  0.85,
		WarnThreshold:   0.70,
		EnableSemantics: true,
		EnableRiskDecay: true,
		RiskDecayRate:   0.25,
	}
)

// GetMultiTurnConfig returns the configuration for a named profile.
func GetMultiTurnConfig(name string) *MultiTurnConfig {
	switch name {
	case "strict":
		return MTStrictConfig
	case "permissive":
		return MTPermissiveConfig
	case "balanced", "":
		return MTBalancedConfig
	default:
		return MTBalancedConfig
	}
}
