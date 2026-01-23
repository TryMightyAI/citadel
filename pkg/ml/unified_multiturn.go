package ml

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ============================================================================
// UNIFIED MULTI-TURN DETECTION
// ============================================================================
// Single entry point that routes through all detection layers:
// - Layer 1: Fast pattern detection (keyword-based, ~1ms)
// - Layer 2: Semantic embedding analysis (ModernBERT/Groq, ~50-500ms)
// - Layer 3: LLM judge for ambiguous cases (Groq, ~1-2s)
//
// The unified detector manages:
// - Session state (in-memory or Redis-backed)
// - Model routing based on context size
// - Budget enforcement
// - Audit trail generation

// UnifiedMultiTurnRequest is the single API entry point for multi-turn detection
type UnifiedMultiTurnRequest struct {
	// Identity (required)
	SessionID string `json:"session_id"`
	OrgID     string `json:"org_id"`

	// Current turn (required)
	Content string `json:"content"`

	// Detection profile (optional - defaults to "balanced")
	// Options: "strict", "balanced", "permissive", "code_assistant", "ai_safety"
	ProfileName string `json:"profile,omitempty"`

	// Optional overrides
	ForceModel    string `json:"force_model,omitempty"`    // "modernbert", "groq", "pattern_only"
	SkipSemantics bool   `json:"skip_semantics,omitempty"` // Fast path - pattern only
	SkipLLMJudge  bool   `json:"skip_llm_judge,omitempty"` // Skip Layer 3
}

// UnifiedMultiTurnResponse contains complete detection results
type UnifiedMultiTurnResponse struct {
	// Decision
	Verdict     string  `json:"verdict"`      // ALLOW, BLOCK, NEGOTIATE
	Confidence  float64 `json:"confidence"`   // 0.0 - 1.0
	ShouldBlock bool    `json:"should_block"` // Convenience field

	// Turn info
	TurnNumber   int `json:"turn_number"`
	SessionTurns int `json:"session_turns"`

	// Detection details
	Detection DetectionLayerResults `json:"detection"`

	// Audit reference
	AuditID string `json:"audit_id,omitempty"`

	// Budget info (transparency for billing)
	Budget BudgetInfo `json:"budget"`

	// Processing time
	LatencyMs int `json:"latency_ms"`
}

// DetectionLayerResults contains results from each detection layer
type DetectionLayerResults struct {
	// Layer 1: Pattern detection
	PatternMatches []PatternMatchResult `json:"pattern_matches"`
	PatternBoost   float64              `json:"pattern_boost"`
	PatternPhase   string               `json:"pattern_phase,omitempty"`

	// Layer 2: Semantic detection
	SemanticPhase      string  `json:"semantic_phase,omitempty"`
	SemanticConfidence float64 `json:"semantic_confidence"`
	TrajectoryDrift    float64 `json:"trajectory_drift"`
	DriftAccelerating  bool    `json:"drift_accelerating"`
	CentroidDistance   float64 `json:"centroid_distance"`
	AggregateScore     float64 `json:"aggregate_score"`

	// Layer 3: LLM judgment (if invoked)
	LLMVerdict   *string `json:"llm_verdict,omitempty"`
	LLMReasoning *string `json:"llm_reasoning,omitempty"`
	LLMInvoked   bool    `json:"llm_invoked"`

	// Model info
	ModelUsed      string `json:"model_used"`
	TokensConsumed int    `json:"tokens_consumed"`

	// Combined analysis
	FinalScore      float64  `json:"final_score"`
	RawScore        float64  `json:"raw_score,omitempty"`        // Score before context discount
	ContextDiscount float64  `json:"context_discount,omitempty"` // Discount applied
	BlockReasons    []string `json:"block_reasons,omitempty"`
	LayersInvoked   []string `json:"layers_invoked"`

	// Context signals detected
	ContextSignals *ContextSignals `json:"context_signals,omitempty"`

	// Intent type classification
	IntentType       string  `json:"intent_type,omitempty"`       // EDUCATIONAL, CREATIVE, etc.
	IntentConfidence float64 `json:"intent_confidence,omitempty"` // Confidence of intent classification
	IntentDiscount   float64 `json:"intent_discount,omitempty"`   // Discount applied based on intent

	// Profile used
	ProfileUsed string `json:"profile_used,omitempty"`
}

// PatternMatchResult represents a detected pattern
type PatternMatchResult struct {
	PatternName string  `json:"pattern_name"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
	Phase       string  `json:"phase,omitempty"`
	IsPartial   bool    `json:"is_partial,omitempty"`
}

// BudgetInfo provides cost transparency
type BudgetInfo struct {
	TokensUsed      int     `json:"tokens_used"`
	TokensRemaining int     `json:"tokens_remaining"`
	CostIncurred    float64 `json:"cost_incurred"`
	CostRemaining   float64 `json:"cost_remaining"`
	TurnsUsed       int     `json:"turns_used"`
	TurnsRemaining  int     `json:"turns_remaining"`
}

// SessionStore interface for pluggable storage (in-memory or Redis)
type SessionStore interface {
	GetSession(sessionID string) (*UnifiedSessionState, error)
	SaveSession(session *UnifiedSessionState) error
	UpdateTurn(sessionID string, turn *TurnRecord) error
	DeleteSession(sessionID string) error
}

// UnifiedSessionState tracks complete multi-turn state
type UnifiedSessionState struct {
	SessionID   string    `json:"session_id"`
	OrgID       string    `json:"org_id"`
	UserID      string    `json:"user_id,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	LastTurnAt  time.Time `json:"last_turn_at"`
	TurnCount   int       `json:"turn_count"`
	Locked      bool      `json:"locked"`
	LockReason  string    `json:"lock_reason,omitempty"`
	MaxMessages int       `json:"max_messages"`

	// Message history (sliding window)
	Messages []TurnRecord `json:"messages"`

	// Embedding trajectory
	Trajectory *EmbeddingTrajectory `json:"trajectory,omitempty"`

	// Pattern signals (cross-window detection)
	PatternSignals map[string]*StoredPatternSignal `json:"pattern_signals,omitempty"`

	// Budget tracking
	Budget *SessionBudget `json:"budget,omitempty"`

	// Cumulative risk
	CumulativeRisk float64 `json:"cumulative_risk"`
}

// TurnRecord stores a single turn's data
type TurnRecord struct {
	TurnNumber    int       `json:"turn_number"`
	Content       string    `json:"content"`
	RiskScore     float64   `json:"risk_score"`
	Phase         string    `json:"phase"`
	Confidence    float64   `json:"confidence"`
	PatternMatch  string    `json:"pattern_match,omitempty"`
	ModelUsed     string    `json:"model_used"`
	TokensUsed    int       `json:"tokens_used"`
	Verdict       string    `json:"verdict"`
	Timestamp     time.Time `json:"timestamp"`
	ProcessTimeMs int       `json:"process_time_ms"`
}

// InMemorySessionStore implements SessionStore with in-memory storage
type InMemorySessionStore struct {
	sessions map[string]*UnifiedSessionState
	mu       sync.RWMutex
}

// NewInMemorySessionStore creates a new in-memory session store
func NewInMemorySessionStore() *InMemorySessionStore {
	return &InMemorySessionStore{
		sessions: make(map[string]*UnifiedSessionState),
	}
}

func (s *InMemorySessionStore) GetSession(sessionID string) (*UnifiedSessionState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if session, ok := s.sessions[sessionID]; ok {
		return session, nil
	}
	return nil, nil // Not found is not an error
}

func (s *InMemorySessionStore) SaveSession(session *UnifiedSessionState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions[session.SessionID] = session
	return nil
}

func (s *InMemorySessionStore) UpdateTurn(sessionID string, turn *TurnRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	session.Messages = append(session.Messages, *turn)

	// Trim to max messages (sliding window)
	if len(session.Messages) > session.MaxMessages {
		session.Messages = session.Messages[len(session.Messages)-session.MaxMessages:]
	}

	session.LastTurnAt = turn.Timestamp
	session.TurnCount++

	return nil
}

func (s *InMemorySessionStore) DeleteSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, sessionID)
	return nil
}

// UnifiedMultiTurnDetector is the main detection orchestrator
type UnifiedMultiTurnDetector struct {
	// Detection components
	patternDetector      *MultiTurnPatternDetector
	semanticDetector     *SemanticMultiTurnDetector
	intentClient         IntentClassifier      // For vision service (SAFE/INJECTION)
	intentTypeClassifier *IntentTypeClassifier // For intent type (EDUCATIONAL, CREATIVE, etc.)
	safeguardClient      *SafeguardClient      // For Groq LLM

	// Session management
	sessionStore SessionStore
	costConfig   *CostProtectionConfig

	// Configuration
	config *UnifiedDetectorConfig
}

// UnifiedDetectorConfig contains detector configuration
type UnifiedDetectorConfig struct {
	// Layer invocation thresholds
	SemanticThreshold   float64 // Run semantic if pattern risk >= this (default: 0.3)
	LLMJudgeThreshold   float64 // Run LLM judge if semantic risk >= this (default: 0.35 - lowered for skeleton key attacks)
	MinTurnsForSemantic int     // Minimum turns before semantic analysis (default: 2)

	// Blocking thresholds
	BlockThreshold float64 // Block if final score >= this (default: 0.75)

	// Model routing
	PreferModernBERT bool   // Prefer ModernBERT over DeBERTa
	VisionServiceURL string // Vision service URL

	// Embedding config
	EmbeddingDimension int // Embedding vector dimension (default: 1024 for Qwen3)

	// Session config
	MaxMessagesPerSession int // Sliding window size (default: 20)
	SessionTTLMinutes     int // Session expiry (default: 60)

	// Risk decay (cooling off for benign turns)
	EnableRiskDecay      bool    // Enable risk decay for benign turns (default: true)
	RiskDecayPerTurn     float64 // How much to decay per benign turn (default: 0.15)
	BenignTurnThreshold  float64 // Score below this is considered benign (default: 0.3)
	MaxCumulativeRiskCap float64 // Cap on cumulative risk (default: 2.0)

	// Intent type classification
	EnableIntentClassifier bool // Enable semantic intent classification (default: true)
}

// DefaultUnifiedDetectorConfig returns sensible defaults
func DefaultUnifiedDetectorConfig() *UnifiedDetectorConfig {
	return &UnifiedDetectorConfig{
		SemanticThreshold:      0.3,
		LLMJudgeThreshold:      0.35, // Lowered from 0.6 - skeleton key attacks score ~0.36
		MinTurnsForSemantic:    2,
		BlockThreshold:         0.75,
		PreferModernBERT:       true,
		EmbeddingDimension:     1024, // Qwen3 default
		MaxMessagesPerSession:  20,
		SessionTTLMinutes:      60,
		EnableRiskDecay:        true,
		RiskDecayPerTurn:       0.15,
		BenignTurnThreshold:    0.3,
		MaxCumulativeRiskCap:   2.0,
		EnableIntentClassifier: true,
	}
}

// NewUnifiedMultiTurnDetector creates a new unified detector
func NewUnifiedMultiTurnDetector(
	patternDetector *MultiTurnPatternDetector,
	semanticDetector *SemanticMultiTurnDetector,
	intentClient IntentClassifier,
	safeguardClient *SafeguardClient,
	sessionStore SessionStore,
	costConfig *CostProtectionConfig,
	config *UnifiedDetectorConfig,
) *UnifiedMultiTurnDetector {
	if config == nil {
		config = DefaultUnifiedDetectorConfig()
	}
	if costConfig == nil {
		costConfig = DefaultCostProtectionConfig()
	}
	if sessionStore == nil {
		sessionStore = NewInMemorySessionStore()
	}

	return &UnifiedMultiTurnDetector{
		patternDetector:  patternDetector,
		semanticDetector: semanticDetector,
		intentClient:     intentClient,
		safeguardClient:  safeguardClient,
		sessionStore:     sessionStore,
		costConfig:       costConfig,
		config:           config,
	}
}

// Analyze performs unified multi-turn detection
func (d *UnifiedMultiTurnDetector) Analyze(ctx context.Context, req *UnifiedMultiTurnRequest) (*UnifiedMultiTurnResponse, error) {
	startTime := time.Now()

	// Validate request
	if req.SessionID == "" || req.Content == "" {
		return nil, fmt.Errorf("session_id and content are required")
	}

	// Get or create session
	session, err := d.getOrCreateSession(req.SessionID, req.OrgID)
	if err != nil {
		return nil, fmt.Errorf("session error: %w", err)
	}

	// Check if session is locked
	if session.Locked {
		return &UnifiedMultiTurnResponse{
			Verdict:      "BLOCK",
			Confidence:   1.0,
			ShouldBlock:  true,
			TurnNumber:   session.TurnCount + 1,
			SessionTurns: session.TurnCount,
			Detection: DetectionLayerResults{
				FinalScore:   1.0,
				BlockReasons: []string{fmt.Sprintf("Session locked: %s", session.LockReason)},
			},
			LatencyMs: int(time.Since(startTime).Milliseconds()),
		}, nil
	}

	// Build conversation context
	aggregate := d.buildAggregateContext(session, req.Content)
	turnNumber := session.TurnCount + 1

	// Initialize response
	resp := &UnifiedMultiTurnResponse{
		TurnNumber:   turnNumber,
		SessionTurns: session.TurnCount,
		Detection: DetectionLayerResults{
			LayersInvoked: []string{},
		},
	}

	// ========================================
	// LAYER 1: Fast Pattern Detection
	// ========================================
	patternResult := d.runLayer1Pattern(session, req.Content)
	resp.Detection.PatternMatches = patternResult.Matches
	resp.Detection.PatternBoost = patternResult.Boost
	resp.Detection.PatternPhase = patternResult.CurrentPhase
	resp.Detection.LayersInvoked = append(resp.Detection.LayersInvoked, "pattern")

	// ========================================
	// LAYER 2: Semantic Embedding Analysis
	// ========================================
	runSemantic := !req.SkipSemantics &&
		(patternResult.Boost >= d.config.SemanticThreshold ||
			turnNumber >= d.config.MinTurnsForSemantic ||
			req.ForceModel != "pattern_only")

	if runSemantic {
		semanticResult, semanticErr := d.runLayer2Semantic(ctx, session, req.Content, aggregate, req.ForceModel)
		if semanticErr == nil {
			resp.Detection.SemanticPhase = semanticResult.Phase
			resp.Detection.SemanticConfidence = semanticResult.Confidence
			resp.Detection.TrajectoryDrift = semanticResult.Drift
			resp.Detection.DriftAccelerating = semanticResult.Accelerating
			resp.Detection.CentroidDistance = semanticResult.CentroidDist
			resp.Detection.AggregateScore = semanticResult.AggregateScore
			resp.Detection.ModelUsed = semanticResult.ModelUsed
			resp.Detection.TokensConsumed = semanticResult.TokensUsed
			resp.Detection.LayersInvoked = append(resp.Detection.LayersInvoked, "semantic")

			// Update trajectory in session
			if session.Trajectory == nil {
				session.Trajectory = NewEmbeddingTrajectory(d.config.EmbeddingDimension)
			}
		}
	}

	// ========================================
	// LAYER 3: LLM Judge (for ambiguous cases)
	// ========================================
	semanticScore := resp.Detection.SemanticConfidence + resp.Detection.AggregateScore

	// Trigger conditions for LLM safeguard (IMPROVED: no longer requires pattern matches)
	// This fixes skeleton key attacks which score ~0.36 with 0 pattern matches
	isGrayZone := semanticScore >= 0.25 && semanticScore <= 0.65 // Ambiguous range
	isAboveThreshold := semanticScore >= d.config.LLMJudgeThreshold
	isLaterTurn := session.TurnCount >= 4                                // Multi-turn attacks often strike at turn 4+
	hasRiskAccumulation := session.CumulativeRisk > 0.5                  // Prior turns accumulated risk
	hasPatternsOrContext := len(patternResult.Matches) > 0 || isGrayZone // Pattern OR gray zone

	runLLMJudge := !req.SkipLLMJudge &&
		d.safeguardClient != nil &&
		(isAboveThreshold || // Score above threshold
			(isGrayZone && hasPatternsOrContext) || // Gray zone with patterns/context
			(isLaterTurn && hasRiskAccumulation)) // Multi-turn with accumulated risk

	if runLLMJudge {
		llmResult, llmErr := d.runLayer3LLMJudge(ctx, session, aggregate)
		if llmErr == nil && llmResult != nil {
			resp.Detection.LLMVerdict = &llmResult.Verdict
			resp.Detection.LLMReasoning = &llmResult.Reasoning
			resp.Detection.LLMInvoked = true
			resp.Detection.LayersInvoked = append(resp.Detection.LayersInvoked, "llm_judge")
		}
	}

	// ========================================
	// CONTEXT SIGNAL DETECTION (keyword-based)
	// ========================================
	contextSignals := DetectContextSignals(req.Content)
	resp.Detection.ContextSignals = contextSignals

	// ========================================
	// INTENT TYPE CLASSIFICATION (semantic-based)
	// ========================================
	if d.config.EnableIntentClassifier && d.intentTypeClassifier != nil {
		intentResult, intentErr := d.intentTypeClassifier.Classify(ctx, req.Content)
		if intentErr == nil && intentResult != nil {
			resp.Detection.IntentType = string(intentResult.PrimaryIntent)
			resp.Detection.IntentConfidence = intentResult.Confidence
			resp.Detection.IntentDiscount = IntentTypeDiscount(intentResult.PrimaryIntent, intentResult.Confidence)
			resp.Detection.LayersInvoked = append(resp.Detection.LayersInvoked, "intent_type")
		}
	}

	// ========================================
	// GET DETECTION PROFILE
	// ========================================
	// If no profile specified, consider recommending one based on intent type
	profileName := req.ProfileName
	if profileName == "" && resp.Detection.IntentType != "" {
		// Auto-recommend profile based on detected intent
		profileName = IntentTypeToProfile(IntentType(resp.Detection.IntentType))
	}
	profile := GetProfile(profileName)
	resp.Detection.ProfileUsed = profile.Name

	// ========================================
	// DECISION ENGINE: Combine all signals with profile-aware scoring
	// ========================================
	finalScore, blockReasons := d.calculateFinalScore(&resp.Detection, patternResult, profile, contextSignals)
	resp.Detection.FinalScore = finalScore
	resp.Detection.BlockReasons = blockReasons

	// Determine verdict using profile thresholds
	if finalScore >= profile.BlockThreshold {
		resp.Verdict = "BLOCK"
		resp.ShouldBlock = true
		resp.Confidence = finalScore
	} else if finalScore >= profile.WarnThreshold {
		resp.Verdict = "NEGOTIATE"
		resp.ShouldBlock = false
		resp.Confidence = finalScore
	} else {
		resp.Verdict = "ALLOW"
		resp.ShouldBlock = false
		resp.Confidence = 1.0 - finalScore
	}

	// ========================================
	// UPDATE SESSION STATE
	// ========================================
	turnRecord := &TurnRecord{
		TurnNumber:    turnNumber,
		Content:       req.Content,
		RiskScore:     finalScore,
		Phase:         d.determineBestPhase(resp.Detection),
		Confidence:    resp.Confidence,
		PatternMatch:  d.getBestPatternMatch(patternResult.Matches),
		ModelUsed:     resp.Detection.ModelUsed,
		TokensUsed:    resp.Detection.TokensConsumed,
		Verdict:       resp.Verdict,
		Timestamp:     time.Now(),
		ProcessTimeMs: int(time.Since(startTime).Milliseconds()),
	}

	if err := d.sessionStore.UpdateTurn(req.SessionID, turnRecord); err != nil {
		// Log but don't fail
		fmt.Printf("[WARN] Failed to update session: %v\n", err)
	}

	// Lock session if blocked
	if resp.ShouldBlock && finalScore >= 0.9 {
		session.Locked = true
		session.LockReason = fmt.Sprintf("High-confidence attack detected: %s (score=%.2f)",
			d.getBestPatternMatch(patternResult.Matches), finalScore)
		_ = d.sessionStore.SaveSession(session)
	}

	// ========================================
	// UPDATE CUMULATIVE RISK WITH DECAY
	// ========================================
	if d.config.EnableRiskDecay && finalScore < d.config.BenignTurnThreshold {
		// Benign turn - apply decay (cooling off mechanism)
		session.CumulativeRisk -= d.config.RiskDecayPerTurn
		if session.CumulativeRisk < 0 {
			session.CumulativeRisk = 0
		}
	} else {
		// Risky turn - accumulate risk
		session.CumulativeRisk += finalScore * 0.3
	}

	// Cap cumulative risk
	if session.CumulativeRisk > d.config.MaxCumulativeRiskCap {
		session.CumulativeRisk = d.config.MaxCumulativeRiskCap
	}

	_ = d.sessionStore.SaveSession(session)

	// Budget info
	resp.Budget = d.getBudgetInfo(session)

	// Final latency
	resp.LatencyMs = int(time.Since(startTime).Milliseconds())

	return resp, nil
}

// Layer 1 result
type layer1Result struct {
	Matches      []PatternMatchResult
	Boost        float64
	CurrentPhase string
}

// runLayer1Pattern runs fast keyword-based pattern detection
func (d *UnifiedMultiTurnDetector) runLayer1Pattern(session *UnifiedSessionState, currentContent string) *layer1Result {
	result := &layer1Result{
		Matches: []PatternMatchResult{},
	}

	if d.patternDetector == nil {
		return result
	}

	// Build turn history for pattern detector
	turnHistory := make([]TurnData, 0, len(session.Messages)+1)
	for i, msg := range session.Messages {
		turnHistory = append(turnHistory, TurnData{
			TurnNumber: i + 1,
			Content:    msg.Content,
			RiskScore:  msg.RiskScore,
		})
	}
	// Add current turn
	turnHistory = append(turnHistory, TurnData{
		TurnNumber: len(session.Messages) + 1,
		Content:    currentContent,
	})

	// Build cross-window context from pattern signals
	var crossWindowCtx *CrossWindowContext
	if len(session.PatternSignals) > 0 {
		crossWindowCtx = &CrossWindowContext{
			PriorSignals: session.PatternSignals,
		}
	}

	// Detect patterns
	patterns := d.patternDetector.DetectAllPatternsWithContext(turnHistory, crossWindowCtx)

	// Convert to result format
	for _, p := range patterns {
		result.Matches = append(result.Matches, PatternMatchResult{
			PatternName: p.PatternName,
			Confidence:  p.Confidence,
			Description: p.Description,
			Phase:       p.DetectedPhase,
			IsPartial:   p.IsPartialPattern,
		})

		// Track current phase
		if p.DetectedPhase != "" && p.Confidence > 0.5 {
			result.CurrentPhase = p.DetectedPhase
		}

		// Update pattern signals for cross-window detection
		if session.PatternSignals == nil {
			session.PatternSignals = make(map[string]*StoredPatternSignal)
		}
		session.PatternSignals[p.PatternName] = &StoredPatternSignal{
			PatternName: p.PatternName,
			Phase:       p.DetectedPhase,
			Confidence:  p.Confidence,
			TurnNumber:  len(turnHistory),
			DetectedAt:  time.Now(),
		}
	}

	// Calculate boost
	result.Boost = d.patternDetector.CalculatePatternBoost(patterns)

	return result
}

// Layer 2 result
type layer2Result struct {
	Phase          string
	Confidence     float64
	Drift          float64
	Accelerating   bool
	CentroidDist   float64
	AggregateScore float64
	ModelUsed      string
	TokensUsed     int
}

// runLayer2Semantic runs semantic embedding analysis
func (d *UnifiedMultiTurnDetector) runLayer2Semantic(
	ctx context.Context,
	session *UnifiedSessionState,
	currentContent string,
	aggregate string,
	forceModel string,
) (*layer2Result, error) {
	result := &layer2Result{}

	// Determine model based on context size
	tokens := EstimateTokens(aggregate)
	result.TokensUsed = tokens

	if forceModel != "" {
		result.ModelUsed = forceModel
	} else {
		result.ModelUsed = SelectModelRoute(aggregate)
	}

	// If semantic detector available, use it
	if d.semanticDetector != nil && d.semanticDetector.semantic != nil && d.semanticDetector.semantic.IsReady() {
		// Get trajectory from session or create new one
		trajectory := session.Trajectory
		if trajectory == nil {
			trajectory = NewEmbeddingTrajectory(d.config.EmbeddingDimension)
			session.Trajectory = trajectory
		}

		// Run detection
		riskResult, err := d.semanticDetector.DetectPatterns(ctx, trajectory, currentContent, aggregate)
		if err == nil && riskResult != nil {
			result.Phase = string(riskResult.CurrentPhase)
			result.Confidence = riskResult.CurrentConfidence
			result.Drift = riskResult.CurrentDrift
			result.Accelerating = riskResult.IsAccelerating
			result.CentroidDist = riskResult.CentroidDistance
			result.AggregateScore = riskResult.AggregateAttackSimilarity
		}
	}

	// If intent client available, also run intent classification
	if d.intentClient != nil && d.intentClient.IsAvailable() {
		intentResult, err := d.intentClient.ClassifyIntent(ctx, aggregate)
		if err == nil && intentResult != nil {
			// Combine with semantic result - Label is "INJECTION" for attacks
			isInjection := intentResult.Label == "INJECTION"
			if isInjection && intentResult.Confidence > result.Confidence {
				result.Confidence = intentResult.Confidence
			}
		}
	}

	return result, nil
}

// Layer 3 result
type layer3Result struct {
	Verdict   string
	Reasoning string
}

// runLayer3LLMJudge runs LLM-based judgment for ambiguous cases
func (d *UnifiedMultiTurnDetector) runLayer3LLMJudge(
	ctx context.Context,
	session *UnifiedSessionState,
	aggregate string,
) (*layer3Result, error) {
	if d.safeguardClient == nil {
		return nil, fmt.Errorf("safeguard client not configured")
	}

	// Use safeguard client to get judgment
	isUnsafe, reasoning, err := d.safeguardClient.EvaluateContent(ctx, aggregate)
	if err != nil {
		return nil, err
	}

	result := &layer3Result{
		Reasoning: reasoning,
	}

	if isUnsafe {
		result.Verdict = "UNSAFE"
	} else {
		result.Verdict = "SAFE"
	}

	return result, nil
}

// calculateFinalScore combines all detection signals with profile-based context awareness
func (d *UnifiedMultiTurnDetector) calculateFinalScore(
	detection *DetectionLayerResults,
	patternResult *layer1Result,
	profile *DetectionProfile,
	contextSignals *ContextSignals,
) (float64, []string) {
	var reasons []string
	rawScore := 0.0

	// Pattern contribution (weight: 0.35)
	if patternResult.Boost > 0 {
		rawScore += patternResult.Boost * 0.35
		for _, m := range patternResult.Matches {
			if m.Confidence > profile.PatternThreshold && !m.IsPartial {
				reasons = append(reasons, fmt.Sprintf("Pattern: %s (%.0f%%)", m.PatternName, m.Confidence*100))
			}
		}
	}

	// Semantic contribution (weight: 0.35)
	semanticScore := (detection.SemanticConfidence + detection.AggregateScore) / 2
	if semanticScore > profile.SemanticThreshold {
		rawScore += semanticScore * 0.35
		if detection.SemanticPhase != "" && detection.SemanticPhase != "benign" {
			reasons = append(reasons, fmt.Sprintf("Semantic phase: %s (%.0f%%)", detection.SemanticPhase, detection.SemanticConfidence*100))
		}
	}

	// Drift contribution (weight: 0.15)
	if detection.DriftAccelerating {
		rawScore += 0.15
		reasons = append(reasons, fmt.Sprintf("Drift accelerating: %.2f", detection.TrajectoryDrift))
	}

	// Centroid distance (weight: 0.15)
	if detection.CentroidDistance > 0.4 {
		rawScore += detection.CentroidDistance * 0.15
		reasons = append(reasons, fmt.Sprintf("Centroid outlier: %.2f", detection.CentroidDistance))
	}

	// LLM judge override
	if detection.LLMInvoked && detection.LLMVerdict != nil {
		if *detection.LLMVerdict == "UNSAFE" || *detection.LLMVerdict == "BLOCK" {
			rawScore = max(rawScore, 0.85)
			reasons = append(reasons, "LLM judge: UNSAFE")
		}
	}

	// Cap raw score at 1.0
	if rawScore > 1.0 {
		rawScore = 1.0
	}

	// Store raw score before context discount
	detection.RawScore = rawScore

	// Apply context-aware discount based on detected keyword signals
	scoreAfterContext := ApplyContextDiscount(rawScore, contextSignals, profile)
	detection.ContextDiscount = rawScore - scoreAfterContext

	// Apply intent-based discount (if intent was classified)
	finalScore := scoreAfterContext
	if detection.IntentDiscount > 0 {
		finalScore = scoreAfterContext * (1 - detection.IntentDiscount)
	}

	// Add context reason if discount was applied
	if detection.ContextDiscount > 0.05 {
		contextDesc := describeContextSignals(contextSignals)
		if contextDesc != "" {
			reasons = append(reasons, fmt.Sprintf("Context detected: %s (discount: %.0f%%)", contextDesc, detection.ContextDiscount*100))
		}
	}

	// Add intent reason if discount was applied
	if detection.IntentDiscount > 0.05 && detection.IntentType != "" {
		reasons = append(reasons, fmt.Sprintf("Intent: %s (%.0f%% confidence, %.0f%% discount)",
			detection.IntentType, detection.IntentConfidence*100, detection.IntentDiscount*100))
	}

	return finalScore, reasons
}

// describeContextSignals returns a human-readable description of detected context
func describeContextSignals(signals *ContextSignals) string {
	if signals == nil {
		return ""
	}

	var parts []string
	if signals.IsEducational {
		parts = append(parts, "educational")
	}
	if signals.IsCreative {
		parts = append(parts, "creative")
	}
	if signals.IsHistorical {
		parts = append(parts, "historical")
	}
	if signals.IsProfessional {
		parts = append(parts, "professional")
	}
	if signals.IsCodeReview {
		parts = append(parts, "code-review")
	}

	if len(parts) == 0 {
		return ""
	}

	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += ", " + parts[i]
	}
	return result
}

// Helper functions

func (d *UnifiedMultiTurnDetector) getOrCreateSession(sessionID, orgID string) (*UnifiedSessionState, error) {
	session, err := d.sessionStore.GetSession(sessionID)
	if err != nil {
		return nil, err
	}

	if session != nil {
		return session, nil
	}

	// Create new session
	session = &UnifiedSessionState{
		SessionID:      sessionID,
		OrgID:          orgID,
		CreatedAt:      time.Now(),
		LastTurnAt:     time.Now(),
		TurnCount:      0,
		Messages:       []TurnRecord{},
		MaxMessages:    d.config.MaxMessagesPerSession,
		PatternSignals: make(map[string]*StoredPatternSignal),
		Budget:         NewSessionBudget(sessionID, d.costConfig),
	}

	if err := d.sessionStore.SaveSession(session); err != nil {
		return nil, err
	}

	return session, nil
}

func (d *UnifiedMultiTurnDetector) buildAggregateContext(session *UnifiedSessionState, currentContent string) string {
	var sb string
	for i, msg := range session.Messages {
		sb += fmt.Sprintf("Turn %d: %s\n", i+1, msg.Content)
	}
	sb += fmt.Sprintf("Turn %d: %s", session.TurnCount+1, currentContent)
	return sb
}

func (d *UnifiedMultiTurnDetector) determineBestPhase(detection DetectionLayerResults) string {
	// Prefer semantic phase if available
	if detection.SemanticPhase != "" {
		return detection.SemanticPhase
	}
	// Fall back to pattern phase
	if detection.PatternPhase != "" {
		return detection.PatternPhase
	}
	return "unknown"
}

func (d *UnifiedMultiTurnDetector) getBestPatternMatch(matches []PatternMatchResult) string {
	if len(matches) == 0 {
		return ""
	}

	best := matches[0]
	for _, m := range matches[1:] {
		if m.Confidence > best.Confidence {
			best = m
		}
	}
	return best.PatternName
}

func (d *UnifiedMultiTurnDetector) getBudgetInfo(session *UnifiedSessionState) BudgetInfo {
	if session.Budget == nil {
		return BudgetInfo{
			TokensRemaining: d.costConfig.MaxTokensPerSession,
			CostRemaining:   d.costConfig.MaxCostPerSession,
			TurnsRemaining:  d.costConfig.MaxTurnsPerSession,
		}
	}

	stats := session.Budget.GetUsageStats()
	return BudgetInfo{
		TokensUsed:      stats["tokens_used"].(int),
		TokensRemaining: stats["tokens_limit"].(int) - stats["tokens_used"].(int),
		CostIncurred:    stats["cost_incurred"].(float64),
		CostRemaining:   stats["cost_limit"].(float64) - stats["cost_incurred"].(float64),
		TurnsUsed:       stats["turns_used"].(int),
		TurnsRemaining:  stats["turns_limit"].(int) - stats["turns_used"].(int),
	}
}

// GetSessionState returns current session state (for debugging/monitoring)
func (d *UnifiedMultiTurnDetector) GetSessionState(sessionID string) (*UnifiedSessionState, error) {
	return d.sessionStore.GetSession(sessionID)
}

// DeleteSession removes a session
func (d *UnifiedMultiTurnDetector) DeleteSession(sessionID string) error {
	return d.sessionStore.DeleteSession(sessionID)
}

// Close releases resources held by the detector.
// This must be called to prevent goroutine leaks from background cleanup.
func (d *UnifiedMultiTurnDetector) Close() {
	// Check if session store implements io.Closer
	if closer, ok := d.sessionStore.(interface{ Close() }); ok {
		closer.Close()
	}
}

// ToJSON serializes response for API output
func (r *UnifiedMultiTurnResponse) ToJSON() ([]byte, error) {
	return json.Marshal(r)
}
