package ml

import (
	"context"
	"fmt"
	"time"
)

// ============================================================================
// OSS MULTI-TURN DETECTOR
// ============================================================================
// Orchestrates multi-turn attack detection using:
//   - Pattern detection (skeleton_key, crescendo, boiling_frog, etc.)
//   - Optional semantic similarity (chromem-go + local embeddings)
//   - Session management (in-memory with sliding window)
//
// Pro extends this via embedding in pro/internal/multiturn/detector_pro.go
// with additional features: drift detection, LLM judge, cost tracking.

// MultiTurnDetector is the OSS multi-turn attack detector.
// Implements MultiTurnAnalyzer interface.
type MultiTurnDetector struct {
	// Detection components
	patterns *MultiTurnPatternDetector // Required: pattern detection
	semantic *SemanticDetector         // Optional: semantic similarity

	// Session management
	sessions MTSessionStore

	// Configuration
	config *MultiTurnConfig
}

// MTDetectorOption is a functional option for configuring MultiTurnDetector.
type MTDetectorOption func(*MultiTurnDetector)

// WithMTSemanticDetector adds optional semantic detection.
func WithMTSemanticDetector(sd *SemanticDetector) MTDetectorOption {
	return func(d *MultiTurnDetector) {
		d.semantic = sd
	}
}

// WithMTSessionStore sets a custom session store.
func WithMTSessionStore(store MTSessionStore) MTDetectorOption {
	return func(d *MultiTurnDetector) {
		d.sessions = store
	}
}

// WithMTConfig sets custom configuration.
func WithMTConfig(cfg *MultiTurnConfig) MTDetectorOption {
	return func(d *MultiTurnDetector) {
		d.config = cfg
	}
}

// NewMultiTurnDetector creates a new OSS multi-turn detector.
func NewMultiTurnDetector(opts ...MTDetectorOption) *MultiTurnDetector {
	d := &MultiTurnDetector{
		patterns: NewMultiTurnPatternDetector(),
		sessions: NewMTInMemoryStore(),
		config:   DefaultMultiTurnConfig(),
	}

	for _, opt := range opts {
		opt(d)
	}

	return d
}

// Analyze processes a single turn within a session context.
// Returns detection results including verdict, confidence, and pattern matches.
func (d *MultiTurnDetector) Analyze(ctx context.Context, req *MultiTurnRequest) (*MultiTurnResponse, error) {
	startTime := time.Now()

	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}
	if req.SessionID == "" {
		return nil, fmt.Errorf("session_id is required")
	}
	if req.Content == "" {
		return nil, fmt.Errorf("content is required")
	}

	// Apply profile if specified
	config := d.config
	if req.Profile != "" {
		config = GetMultiTurnConfig(req.Profile)
	}

	// Get or create session
	session, err := d.sessions.Get(req.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	if session == nil {
		// Create new session
		session = &SessionState{
			SessionID:      req.SessionID,
			OrgID:          req.OrgID,
			CreatedAt:      time.Now(),
			LastTurnAt:     time.Now(),
			MaxMessages:    config.MaxMessages,
			Messages:       make([]MTTurnRecord, 0),
			PatternSignals: make(map[string]*StoredPatternSignal),
		}
	}

	// Check if session is locked
	if session.Locked {
		return &MultiTurnResponse{
			Verdict:      "BLOCK",
			Confidence:   1.0,
			ShouldBlock:  true,
			TurnNumber:   session.TurnCount + 1,
			SessionTurns: session.TurnCount,
			FinalScore:   1.0,
			BlockReasons: []string{session.LockReason},
			LatencyMs:    int(time.Since(startTime).Milliseconds()),
		}, nil
	}

	// Run pattern detection
	patternResult := d.runPatternDetection(session, req.Content)

	// Run semantic detection (if available and enabled)
	var semanticScore float64
	if config.EnableSemantics && d.semantic != nil && d.semantic.IsReady() {
		semanticResult, err := d.runSemanticDetection(ctx, req.Content)
		if err == nil && semanticResult != nil {
			semanticScore = semanticResult.Score
		}
	}

	// Calculate final score
	finalScore := d.calculateFinalScore(patternResult, semanticScore, session, config)

	// Determine verdict
	verdict, shouldBlock := d.determineVerdict(finalScore, config)

	// Build response
	response := &MultiTurnResponse{
		Verdict:        verdict,
		Confidence:     patternResult.confidence,
		ShouldBlock:    shouldBlock,
		TurnNumber:     session.TurnCount + 1,
		SessionTurns:   session.TurnCount + 1,
		PatternMatches: patternResult.matches,
		PatternBoost:   patternResult.boost,
		PatternPhase:   patternResult.phase,
		SemanticScore:  semanticScore,
		FinalScore:     finalScore,
		BlockReasons:   patternResult.reasons,
		LatencyMs:      int(time.Since(startTime).Milliseconds()),
	}

	// Update session
	turn := &MTTurnRecord{
		TurnNumber:    session.TurnCount + 1,
		Content:       req.Content,
		RiskScore:     finalScore,
		Phase:         patternResult.phase,
		Confidence:    patternResult.confidence,
		PatternMatch:  patternResult.topPattern,
		Verdict:       verdict,
		Timestamp:     time.Now(),
		ProcessTimeMs: int(time.Since(startTime).Milliseconds()),
	}

	// Update session state
	session.CumulativeRisk = d.updateCumulativeRisk(session.CumulativeRisk, finalScore, config)

	// Store pattern signals for cross-window detection
	for _, match := range patternResult.matches {
		session.PatternSignals[match.PatternName] = &StoredPatternSignal{
			PatternName: match.PatternName,
			Phase:       match.Phase,
			Confidence:  match.Confidence,
			TurnNumber:  turn.TurnNumber,
			DetectedAt:  time.Now(),
		}
	}

	// Lock session if blocked
	if shouldBlock {
		session.Locked = true
		session.LockReason = fmt.Sprintf("Blocked at turn %d: %s", turn.TurnNumber, verdict)
	}

	// Save session first, then update turn
	if err := d.sessions.Save(session); err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}
	if err := d.sessions.UpdateTurn(req.SessionID, turn); err != nil {
		return nil, fmt.Errorf("failed to update turn: %w", err)
	}

	return response, nil
}

// GetSession retrieves the current session state.
func (d *MultiTurnDetector) GetSession(sessionID string) (*SessionState, error) {
	return d.sessions.Get(sessionID)
}

// patternResult holds results from pattern detection
type patternResult struct {
	matches    []MTPatternMatch
	boost      float64
	phase      string
	topPattern string
	confidence float64
	reasons    []string
}

// runPatternDetection executes pattern detection on the current session.
func (d *MultiTurnDetector) runPatternDetection(session *SessionState, content string) *patternResult {
	result := &patternResult{
		matches: make([]MTPatternMatch, 0),
		reasons: make([]string, 0),
	}

	// Convert session messages to TurnData for pattern detection
	history := make([]TurnData, len(session.Messages)+1)
	for i, msg := range session.Messages {
		history[i] = TurnData{
			TurnNumber: msg.TurnNumber,
			Content:    msg.Content,
			RiskScore:  msg.RiskScore,
		}
	}
	// Add current turn
	history[len(session.Messages)] = TurnData{
		TurnNumber: session.TurnCount + 1,
		Content:    content,
	}

	// Build cross-window context from stored pattern signals
	var cwCtx *CrossWindowContext
	if len(session.PatternSignals) > 0 {
		cwCtx = &CrossWindowContext{
			PriorSignals: session.PatternSignals,
		}
	}

	// Run pattern detection
	patterns := d.patterns.DetectAllPatternsWithContext(history, cwCtx)

	// Process results
	for _, p := range patterns {
		match := MTPatternMatch{
			PatternName: p.PatternName,
			Confidence:  p.Confidence,
			Description: p.Description,
			Phase:       p.DetectedPhase,
			IsPartial:   p.IsPartialPattern,
		}
		result.matches = append(result.matches, match)

		// Track highest confidence pattern
		if p.Confidence > result.confidence {
			result.confidence = p.Confidence
			result.topPattern = p.PatternName
			result.phase = p.DetectedPhase
		}

		// Add to block reasons if high confidence
		if p.Confidence >= 0.7 && !p.IsPartialPattern {
			result.reasons = append(result.reasons, fmt.Sprintf("%s: %s", p.PatternName, p.Description))
		}
	}

	// Calculate pattern boost
	result.boost = d.calculatePatternBoost(patterns)

	return result
}

// calculatePatternBoost computes the risk boost factor from detected patterns.
func (d *MultiTurnDetector) calculatePatternBoost(patterns []PatternRisk) float64 {
	if len(patterns) == 0 {
		return 0.0
	}

	var boost float64
	for _, p := range patterns {
		if p.IsPartialPattern {
			boost += p.Confidence * 0.3 // Partial patterns contribute less
		} else {
			boost += p.Confidence * 0.5 // Full patterns contribute more
		}
	}

	// Cap at 0.5 (pattern boost shouldn't dominate)
	if boost > 0.5 {
		boost = 0.5
	}

	return boost
}

// runSemanticDetection executes semantic similarity detection.
func (d *MultiTurnDetector) runSemanticDetection(ctx context.Context, content string) (*SemanticResult, error) {
	if d.semantic == nil || !d.semantic.IsReady() {
		return nil, nil
	}

	result, err := d.semantic.Detect(ctx, content)
	if err != nil {
		return nil, err
	}

	return &SemanticResult{
		Score:       float64(result.Score),
		Category:    result.Category,
		IsThreat:    result.IsThreat,
		MatchedText: result.MatchedText,
	}, nil
}

// calculateFinalScore combines all detection signals into a final score.
func (d *MultiTurnDetector) calculateFinalScore(
	pattern *patternResult,
	semanticScore float64,
	session *SessionState,
	config *MultiTurnConfig,
) float64 {
	// Base score from pattern detection
	baseScore := pattern.confidence

	// Add pattern boost
	score := baseScore + pattern.boost

	// Add semantic score (weighted)
	if semanticScore > 0 {
		score += semanticScore * 0.3 // Semantic contributes up to 30%
	}

	// Add cumulative session risk (weighted)
	if session.CumulativeRisk > 0 {
		score += session.CumulativeRisk * 0.2 // Cumulative contributes up to 20%
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// determineVerdict converts a score to a verdict string.
func (d *MultiTurnDetector) determineVerdict(score float64, config *MultiTurnConfig) (string, bool) {
	switch {
	case score >= config.BlockThreshold:
		return "BLOCK", true
	case score >= config.WarnThreshold:
		return "WARN", false
	default:
		return "ALLOW", false
	}
}

// updateCumulativeRisk updates the cumulative session risk with decay.
func (d *MultiTurnDetector) updateCumulativeRisk(current, turnScore float64, config *MultiTurnConfig) float64 {
	if !config.EnableRiskDecay {
		return current + turnScore*0.1 // Simple accumulation without decay
	}

	// Apply decay to existing risk
	decayed := current * (1.0 - config.RiskDecayRate)

	// Add new turn's contribution
	newRisk := decayed + turnScore*0.1

	// Cap at 1.0
	if newRisk > 1.0 {
		newRisk = 1.0
	}

	return newRisk
}

// Close releases resources held by the detector.
func (d *MultiTurnDetector) Close() {
	if store, ok := d.sessions.(*MTInMemoryStore); ok {
		store.Close()
	}
}

// Ensure MultiTurnDetector implements MultiTurnAnalyzer
var _ MultiTurnAnalyzer = (*MultiTurnDetector)(nil)
