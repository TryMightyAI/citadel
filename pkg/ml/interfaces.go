package ml

import (
	"context"
)

// ============================================================================
// SHARED INTERFACES FOR OSS + PRO MULTI-TURN DETECTION
// ============================================================================
// These interfaces define the contract for multi-turn attack detection.
// Both OSS (pkg/ml) and Pro (pro/internal/multiturn) implement these interfaces.
//
// OSS implementations:
//   - InMemorySessionStore: In-memory session storage (15-turn window)
//   - MultiTurnDetector: Pattern + semantic detection
//
// Pro extensions (via embedding):
//   - RedisSessionStore: Redis-backed session storage (30-50 turn window)
//   - ProMultiTurnDetector: Adds drift detection, LLM judge, cost tracking

// MTSessionStore defines pluggable session storage for multi-turn state.
// OSS uses MTInMemoryStore; Pro can use Redis-backed store.
// Uses MT prefix to avoid conflict with SessionStore in unified_multiturn.go
type MTSessionStore interface {
	// Get retrieves a session by ID. Returns nil, nil if not found.
	Get(sessionID string) (*SessionState, error)

	// Save creates or updates a session.
	Save(state *SessionState) error

	// UpdateTurn appends a turn record to an existing session.
	UpdateTurn(sessionID string, turn *MTTurnRecord) error

	// Delete removes a session.
	Delete(sessionID string) error
}

// MultiTurnAnalyzer defines the multi-turn detection interface.
// OSS uses MultiTurnDetector; Pro wraps it with additional layers.
type MultiTurnAnalyzer interface {
	// Analyze processes a single turn within a session context.
	// Returns detection results including verdict, confidence, and pattern matches.
	Analyze(ctx context.Context, req *MultiTurnRequest) (*MultiTurnResponse, error)

	// GetSession retrieves the current session state.
	GetSession(sessionID string) (*SessionState, error)
}

// SemanticAnalyzer defines optional semantic similarity detection.
// Uses chromem-go + local embeddings (Hugot MiniLM/BGE) for OSS.
type SemanticAnalyzer interface {
	// Detect analyzes text for semantic similarity to known attack patterns.
	Detect(ctx context.Context, text string) (*SemanticResult, error)

	// IsReady returns true if the semantic detector is initialized and ready.
	IsReady() bool
}

// PatternAnalyzer defines pattern-based multi-turn attack detection.
// Detects skeleton_key, crescendo, boiling_frog, context_manipulation, ICL patterns.
type PatternAnalyzer interface {
	// DetectPatterns analyzes turn history for known attack patterns.
	DetectPatterns(history []TurnData) []PatternRisk

	// DetectPatternsWithContext analyzes with cross-window pattern signals.
	// Enables detecting attacks that span window boundaries.
	DetectPatternsWithContext(history []TurnData, ctx *CrossWindowContext) []PatternRisk

	// CalculateBoost computes the risk boost factor from detected patterns.
	CalculateBoost(patterns []PatternRisk) float64
}

// SemanticResult contains results from semantic similarity analysis.
// This is the OSS version - Pro may extend with additional fields.
type SemanticResult struct {
	Score       float64 `json:"score"`        // Similarity score (0.0-1.0)
	Category    string  `json:"category"`     // Attack category if detected
	IsThreat    bool    `json:"is_threat"`    // True if score >= threshold
	MatchedText string  `json:"matched_text"` // Matched attack pattern
}
