package ml

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// SEMANTIC MULTI-TURN DETECTION
// ============================================================================
// Implements embedding-based trajectory analysis for multi-turn attack detection.
// This catches paraphrased attacks that keyword matching misses.
//
// Key insight: "Your rules have changed" ≈ "Your guidelines have been updated"
// Keywords miss this, but embeddings catch the semantic similarity.
//
// Architecture:
//   - Layer 1: Aggregate conversation embedding (whole conversation)
//   - Layer 2: Per-turn phase classification (SETUP, PRIME, OVERRIDE, EXPLOIT)
//   - Drift tracking: Detect acceleration toward attack patterns
// ============================================================================

// Phase represents a stage in a multi-turn attack
type Phase string

const (
	PhaseBenign   Phase = "benign"
	PhaseSetup    Phase = "setup"    // Role establishment
	PhasePrime    Phase = "prime"    // Educational/research framing
	PhaseOverride Phase = "override" // Policy override claims
	PhaseExploit  Phase = "exploit"  // Harmful request
)

// Token estimation constants
const (
	// Conservative token estimation: 3 chars per token
	// This is safer than 4 chars/token for multi-byte chars and code
	CharsPerTokenConservative = 3

	// Model context limits
	ModernBERTMaxTokens = 8192
	DeBERTaMaxTokens    = 512
	GroqMaxTokens       = 128000

	// Truncation strategy: Keep first 20% + last 50%, drop middle 30%
	TruncateKeepFirstPct = 0.20
	TruncateKeepLastPct  = 0.50
)

// PhaseClassification represents the detected phase of a turn
type PhaseClassification struct {
	TurnNumber int     `json:"turn_number"`
	Phase      Phase   `json:"phase"`
	Confidence float64 `json:"confidence"`
	Pattern    string  `json:"pattern"` // skeleton_key, crescendo, etc.
}

// SemanticRiskResult contains trajectory analysis results
type SemanticRiskResult struct {
	// Aggregate analysis
	AggregateAttackSimilarity float64 `json:"aggregate_attack_similarity"`

	// Drift analysis
	CurrentDrift      float64 `json:"current_drift"`
	DriftAcceleration float64 `json:"drift_acceleration"`
	IsAccelerating    bool    `json:"is_accelerating"`

	// Phase analysis
	CurrentPhase      Phase    `json:"current_phase"`
	CurrentConfidence float64  `json:"current_confidence"`
	PhaseSequence     []Phase  `json:"phase_sequence"`
	MatchedPattern    string   `json:"matched_pattern"`
	PatternMatchScore float64  `json:"pattern_match_score"`
	CentroidDistance  float64  `json:"centroid_distance"`
	PhaseTransitions  []string `json:"phase_transitions"`

	// Combined score
	FinalScore  float64 `json:"final_score"`
	ShouldBlock bool    `json:"should_block"`
	Reason      string  `json:"reason"`
}

// EmbeddingTrajectory tracks semantic evolution across conversation turns
type EmbeddingTrajectory struct {
	mu sync.RWMutex

	// Per-turn embeddings
	Embeddings [][]float32 `json:"embeddings"`

	// Aggregate embeddings (cumulative conversation)
	AggregateEmbeddings [][]float32 `json:"aggregate_embeddings"`

	// Turn-over-turn drift values
	Drifts []float64 `json:"drifts"`

	// Aggregate drift (how fast is whole convo shifting?)
	AggregateDrifts []float64 `json:"aggregate_drifts"`

	// Running session centroid
	Centroid []float32 `json:"centroid"`

	// Phase classifications per turn
	Phases []PhaseClassification `json:"phases"`

	// Embedding dimension
	EmbeddingDim int `json:"embedding_dim"`
}

// NewEmbeddingTrajectory creates a new trajectory tracker
func NewEmbeddingTrajectory(embeddingDim int) *EmbeddingTrajectory {
	return &EmbeddingTrajectory{
		Embeddings:          make([][]float32, 0),
		AggregateEmbeddings: make([][]float32, 0),
		Drifts:              make([]float64, 0),
		AggregateDrifts:     make([]float64, 0),
		Phases:              make([]PhaseClassification, 0),
		EmbeddingDim:        embeddingDim,
	}
}

// AddTurn records a new turn's embedding and updates trajectory metrics
func (t *EmbeddingTrajectory) AddTurn(turnEmbedding, aggregateEmbedding []float32, phase PhaseClassification) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Store turn embedding
	t.Embeddings = append(t.Embeddings, turnEmbedding)

	// Store aggregate embedding
	t.AggregateEmbeddings = append(t.AggregateEmbeddings, aggregateEmbedding)

	// Calculate turn-over-turn drift
	if len(t.Embeddings) > 1 {
		prev := t.Embeddings[len(t.Embeddings)-2]
		drift := 1.0 - cosineSimilarityFloat32(prev, turnEmbedding)
		t.Drifts = append(t.Drifts, drift)
	}

	// Calculate aggregate drift
	if len(t.AggregateEmbeddings) > 1 {
		prev := t.AggregateEmbeddings[len(t.AggregateEmbeddings)-2]
		aggDrift := 1.0 - cosineSimilarityFloat32(prev, aggregateEmbedding)
		t.AggregateDrifts = append(t.AggregateDrifts, aggDrift)
	}

	// Update centroid
	t.updateCentroid(turnEmbedding)

	// Record phase
	t.Phases = append(t.Phases, phase)
}

// GetRisk calculates risk based on trajectory analysis
func (t *EmbeddingTrajectory) GetRisk() SemanticRiskResult {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := SemanticRiskResult{}

	// 1. Check drift acceleration
	if len(t.AggregateDrifts) >= 3 {
		recentDrifts := t.AggregateDrifts[len(t.AggregateDrifts)-3:]
		result.IsAccelerating = isAcceleratingDrift(recentDrifts)
		if result.IsAccelerating {
			result.DriftAcceleration = calculateAcceleration(recentDrifts)
		}
	}

	// 2. Current drift
	if len(t.AggregateDrifts) > 0 {
		result.CurrentDrift = t.AggregateDrifts[len(t.AggregateDrifts)-1]
	}

	// 3. Centroid distance (outlier detection)
	if len(t.Embeddings) > 0 && t.Centroid != nil {
		latest := t.Embeddings[len(t.Embeddings)-1]
		result.CentroidDistance = 1.0 - cosineSimilarityFloat32(t.Centroid, latest)
	}

	// 4. Current phase
	if len(t.Phases) > 0 {
		latest := t.Phases[len(t.Phases)-1]
		result.CurrentPhase = latest.Phase
		result.CurrentConfidence = latest.Confidence
	}

	// 5. Phase sequence analysis
	result.PhaseSequence = make([]Phase, len(t.Phases))
	for i, p := range t.Phases {
		result.PhaseSequence[i] = p.Phase
	}

	// 6. Pattern matching
	result.MatchedPattern, result.PatternMatchScore = t.detectPatternSequence()

	// 7. Phase transitions
	result.PhaseTransitions = t.analyzePhaseTransitions()

	// 8. Calculate final score
	result.FinalScore = t.calculateFinalScore(result)
	result.ShouldBlock = result.FinalScore >= 0.75

	// 9. Generate reason
	result.Reason = t.generateReason(result)

	return result
}

// updateCentroid maintains a running average of all embeddings
func (t *EmbeddingTrajectory) updateCentroid(newEmbedding []float32) {
	if t.Centroid == nil {
		t.Centroid = make([]float32, len(newEmbedding))
		copy(t.Centroid, newEmbedding)
		return
	}

	n := float32(len(t.Embeddings))
	for i := range t.Centroid {
		// Running average: centroid = (centroid * (n-1) + new) / n
		t.Centroid[i] = (t.Centroid[i]*(n-1) + newEmbedding[i]) / n
	}
}

// detectPatternSequence checks if phase sequence matches known attack patterns
func (t *EmbeddingTrajectory) detectPatternSequence() (string, float64) {
	if len(t.Phases) < 2 {
		return "", 0.0
	}

	phases := make([]Phase, len(t.Phases))
	for i, p := range t.Phases {
		phases[i] = p.Phase
	}

	// Skeleton Key: setup → prime → override → exploit
	skeletonKey := []Phase{PhaseSetup, PhasePrime, PhaseOverride, PhaseExploit}
	if score := matchSequence(phases, skeletonKey); score > 0.5 {
		return "skeleton_key", score
	}

	// Crescendo: benign → probing → testing → attack
	// (simplified: benign → override → exploit)
	crescendo := []Phase{PhaseBenign, PhaseOverride, PhaseExploit}
	if score := matchSequence(phases, crescendo); score > 0.5 {
		return "crescendo", score
	}

	// Boiling Frog: establish → normalize → escalate
	// (simplified: benign → prime → exploit)
	boilingFrog := []Phase{PhaseBenign, PhasePrime, PhaseExploit}
	if score := matchSequence(phases, boilingFrog); score > 0.5 {
		return "boiling_frog", score
	}

	// Direct override attempt
	if containsPhase(phases, PhaseOverride) {
		return "policy_override", 0.7
	}

	return "", 0.0
}

// matchSequence checks if observed phases match expected sequence (partial match allowed)
func matchSequence(observed, expected []Phase) float64 {
	if len(observed) < 2 {
		return 0.0
	}

	// Count how many expected phases appear in order
	matches := 0
	expectedIdx := 0

	for _, phase := range observed {
		if expectedIdx < len(expected) && phase == expected[expectedIdx] {
			matches++
			expectedIdx++
		}
	}

	// Score based on how much of the expected sequence was matched
	if matches >= 2 {
		return float64(matches) / float64(len(expected))
	}
	return 0.0
}

// containsPhase checks if a phase appears in the sequence
func containsPhase(phases []Phase, target Phase) bool {
	return slices.Contains(phases, target)
}

// analyzePhaseTransitions detects suspicious phase transitions
func (t *EmbeddingTrajectory) analyzePhaseTransitions() []string {
	var transitions []string

	for i := 1; i < len(t.Phases); i++ {
		prev := t.Phases[i-1].Phase
		curr := t.Phases[i].Phase

		// Suspicious: benign → override (skipped setup/prime)
		if prev == PhaseBenign && curr == PhaseOverride {
			transitions = append(transitions, "direct_override_attempt")
		}

		// Suspicious: setup → exploit (skipped prime/override)
		if prev == PhaseSetup && curr == PhaseExploit {
			transitions = append(transitions, "rushed_exploit")
		}

		// Suspicious: prime → exploit (skipped override)
		if prev == PhasePrime && curr == PhaseExploit {
			transitions = append(transitions, "skipped_override")
		}
	}

	return transitions
}

// calculateFinalScore combines all signals into a final risk score
func (t *EmbeddingTrajectory) calculateFinalScore(result SemanticRiskResult) float64 {
	// Weight distribution for signals
	const (
		patternMatchWeight     = 0.35
		driftWeight            = 0.25
		phaseConfidenceWeight  = 0.25
		centroidDistanceWeight = 0.15
	)

	score := 0.0

	// Pattern match contributes most
	score += result.PatternMatchScore * patternMatchWeight

	// Drift acceleration is a strong signal
	if result.IsAccelerating {
		driftScore := math.Min(result.DriftAcceleration*2, 1.0)
		score += driftScore * driftWeight
	} else if result.CurrentDrift > 0.3 {
		score += result.CurrentDrift * driftWeight
	}

	// High-confidence override/exploit phase
	if result.CurrentPhase == PhaseOverride || result.CurrentPhase == PhaseExploit {
		score += result.CurrentConfidence * phaseConfidenceWeight
	}

	// Outlier from centroid
	if result.CentroidDistance > 0.4 {
		score += result.CentroidDistance * centroidDistanceWeight
	}

	// Boost for critical phases
	if result.CurrentPhase == PhaseOverride && result.CurrentConfidence > 0.8 {
		score += 0.15 // Override phase is critical
	}

	// Suspicious transition boost
	if len(result.PhaseTransitions) > 0 {
		score += 0.10
	}

	return math.Min(score, 1.0)
}

// generateReason creates a human-readable explanation
func (t *EmbeddingTrajectory) generateReason(result SemanticRiskResult) string {
	if result.FinalScore < 0.5 {
		return "Low risk - no attack pattern detected"
	}

	var reasons []string

	if result.MatchedPattern != "" {
		reasons = append(reasons, fmt.Sprintf("Pattern match: %s (%.0f%%)",
			result.MatchedPattern, result.PatternMatchScore*100))
	}

	if result.IsAccelerating {
		reasons = append(reasons, fmt.Sprintf("Drift acceleration: %.2f", result.DriftAcceleration))
	}

	if result.CurrentPhase == PhaseOverride {
		reasons = append(reasons, fmt.Sprintf("Override phase detected (%.0f%% confidence)",
			result.CurrentConfidence*100))
	}

	if len(result.PhaseTransitions) > 0 {
		reasons = append(reasons, fmt.Sprintf("Suspicious transitions: %v", result.PhaseTransitions))
	}

	if len(reasons) == 0 {
		return fmt.Sprintf("Elevated risk score: %.0f%%", result.FinalScore*100)
	}

	return strings.Join(reasons, "; ")
}

// ============================================================================
// TOKEN ESTIMATION & TRUNCATION
// ============================================================================

// EstimateTokens provides a conservative token count estimate
// Uses 3 chars/token which is safer for multilingual text and code
func EstimateTokens(text string) int {
	return len(text) / CharsPerTokenConservative
}

// EstimateTokensAccurate attempts more accurate estimation
// Falls back to conservative if unable to use tokenizer
func EstimateTokensAccurate(text string) int {
	// For now, use conservative estimate
	// TODO: Integrate with actual tokenizer via vision service
	return EstimateTokens(text)
}

// SelectModelRoute determines which model should handle based on token count
func SelectModelRoute(aggregate string) string {
	tokens := EstimateTokens(aggregate)

	if tokens <= ModernBERTMaxTokens {
		return "modernbert"
	}
	if tokens <= GroqMaxTokens {
		return "groq"
	}
	// Extremely long - will need truncation even for Groq
	return "groq_truncated"
}

// SmartTruncate preserves important context when text exceeds model limits
// Strategy: Keep first 20% (context setup) + last 50% (recent turns), drop middle
func SmartTruncate(text string, maxTokens int) string {
	tokens := EstimateTokens(text)
	if tokens <= maxTokens {
		return text
	}

	// Calculate character limits (using conservative 3 chars/token)
	maxChars := maxTokens * CharsPerTokenConservative

	keepFirst := int(float64(maxChars) * TruncateKeepFirstPct)
	keepLast := int(float64(maxChars) * TruncateKeepLastPct)

	if len(text) <= keepFirst+keepLast {
		return text
	}

	// Extract first and last portions
	first := text[:keepFirst]
	last := text[len(text)-keepLast:]

	// Add truncation marker
	return first + "\n\n[... middle context truncated for length ...]\n\n" + last
}

// SmartTruncateByTurns preserves turn boundaries when truncating
func SmartTruncateByTurns(turns []string, maxTokens int) []string {
	// Calculate total tokens
	totalTokens := 0
	for _, turn := range turns {
		totalTokens += EstimateTokens(turn) + 10 // +10 for turn header
	}

	if totalTokens <= maxTokens {
		return turns
	}

	// Strategy: Keep first 2 turns + last 50% of turns
	if len(turns) <= 4 {
		return turns // Can't truncate much
	}

	keepFirst := 2
	keepLast := max(len(turns)/2, 2)

	result := make([]string, 0, keepFirst+keepLast+1)
	result = append(result, turns[:keepFirst]...)
	result = append(result, "[... earlier turns truncated ...]")
	result = append(result, turns[len(turns)-keepLast:]...)

	return result
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// cosineSimilarityFloat32 calculates cosine similarity between two float32 vectors
func cosineSimilarityFloat32(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0.0
	}

	var dotProduct, normA, normB float64
	for i := range a {
		dotProduct += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}

	if normA == 0 || normB == 0 {
		return 0.0
	}

	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}

// isAcceleratingDrift checks if drift values are increasing
func isAcceleratingDrift(drifts []float64) bool {
	if len(drifts) < 3 {
		return false
	}

	// Check if each drift is larger than the previous
	for i := 1; i < len(drifts); i++ {
		if drifts[i] <= drifts[i-1] {
			return false
		}
	}

	return true
}

// calculateAcceleration computes how fast drift is increasing
func calculateAcceleration(drifts []float64) float64 {
	if len(drifts) < 2 {
		return 0.0
	}

	// Average rate of change
	totalChange := 0.0
	for i := 1; i < len(drifts); i++ {
		totalChange += drifts[i] - drifts[i-1]
	}

	return totalChange / float64(len(drifts)-1)
}

// ============================================================================
// SEMANTIC MULTI-TURN DETECTOR
// ============================================================================

// SemanticMultiTurnDetector performs embedding-based multi-turn attack detection
type SemanticMultiTurnDetector struct {
	// Semantic detector for embeddings
	semantic *SemanticDetector

	// Phase centroids loaded from YAML
	phaseCentroids map[Phase][]float32

	// Attack sequence embeddings for aggregate comparison
	attackSequenceEmbeddings map[string][]float32
}

// NewSemanticMultiTurnDetector creates a detector using existing SemanticDetector
func NewSemanticMultiTurnDetector(semantic *SemanticDetector) *SemanticMultiTurnDetector {
	return &SemanticMultiTurnDetector{
		semantic:                 semantic,
		phaseCentroids:           make(map[Phase][]float32),
		attackSequenceEmbeddings: make(map[string][]float32),
	}
}

// Initialize loads phase centroids from YAML seeds
func (d *SemanticMultiTurnDetector) Initialize(ctx context.Context) error {
	// TODO: Load from config/multiturn_semantic_seeds.yaml
	// For now, phase classification relies on similarity to seed examples
	return nil
}

// ClassifyPhase determines which attack phase a turn belongs to
func (d *SemanticMultiTurnDetector) ClassifyPhase(ctx context.Context, text string) (*PhaseClassification, error) {
	if d.semantic == nil || !d.semantic.IsReady() {
		return &PhaseClassification{Phase: PhaseBenign, Confidence: 0.5}, nil
	}

	// Get embedding for the text
	result, err := d.semantic.Detect(ctx, text)
	if err != nil {
		return &PhaseClassification{Phase: PhaseBenign, Confidence: 0.5}, err
	}

	// Map semantic categories to phases
	phase := PhaseBenign
	confidence := float64(result.Score)

	switch result.Category {
	case "instruction_override", "policy_override":
		phase = PhaseOverride
	case "role_play", "persona_switch":
		phase = PhaseSetup
	case "educational_framing", "research_context":
		phase = PhasePrime
	case "harmful_request", "exploit_attempt":
		phase = PhaseExploit
	default:
		if result.Score < 0.3 {
			phase = PhaseBenign
		}
	}

	return &PhaseClassification{
		Phase:      phase,
		Confidence: confidence,
		Pattern:    result.Category,
	}, nil
}

// AnalyzeAggregate compares aggregate embedding to known attack sequences
func (d *SemanticMultiTurnDetector) AnalyzeAggregate(ctx context.Context, aggregate string) (float64, string, error) {
	if d.semantic == nil || !d.semantic.IsReady() {
		return 0.0, "", nil
	}

	// Get embedding for aggregate
	result, err := d.semantic.Detect(ctx, aggregate)
	if err != nil {
		return 0.0, "", err
	}

	return float64(result.Score), result.Category, nil
}

// DetectPatterns performs full multi-turn analysis on a session
func (d *SemanticMultiTurnDetector) DetectPatterns(
	ctx context.Context,
	trajectory *EmbeddingTrajectory,
	currentTurn string,
	aggregate string,
) (*SemanticRiskResult, error) {
	// 1. Classify current turn's phase
	phaseResult, err := d.ClassifyPhase(ctx, currentTurn)
	if err != nil {
		return nil, fmt.Errorf("phase classification failed: %w", err)
	}

	// 2. Analyze aggregate
	aggScore, aggCategory, err := d.AnalyzeAggregate(ctx, aggregate)
	if err != nil {
		return nil, fmt.Errorf("aggregate analysis failed: %w", err)
	}

	// 3. Get trajectory risk
	risk := trajectory.GetRisk()

	// 4. Enhance with aggregate analysis
	risk.AggregateAttackSimilarity = aggScore
	if aggCategory != "" && risk.MatchedPattern == "" {
		risk.MatchedPattern = aggCategory
	}

	// 5. Recalculate final score with aggregate
	if aggScore > 0.7 {
		risk.FinalScore = math.Max(risk.FinalScore, aggScore*0.8)
	}

	risk.ShouldBlock = risk.FinalScore >= 0.75

	// 6. Add phase info
	risk.CurrentPhase = phaseResult.Phase
	risk.CurrentConfidence = phaseResult.Confidence

	return &risk, nil
}

// ============================================================================
// COST PROTECTION & RATE LIMITING
// ============================================================================
// Prevents DoS attacks via intentionally long conversations that exhaust
// model context/compute budgets.

// CostProtectionConfig defines limits for compute/token budgets
type CostProtectionConfig struct {
	// Per-session limits
	MaxTokensPerSession int `json:"max_tokens_per_session"`
	MaxTurnsPerSession  int `json:"max_turns_per_session"`
	MaxGroqCallsPerHour int `json:"max_groq_calls_per_hour"`

	// Per-request limits
	MaxTokensPerRequest int `json:"max_tokens_per_request"`

	// Cost tracking
	TokenCostModernBERT float64 `json:"token_cost_modernbert"` // $ per 1K tokens
	TokenCostGroq       float64 `json:"token_cost_groq"`       // $ per 1K tokens

	// Budget limits
	MaxCostPerSession float64 `json:"max_cost_per_session"` // $ cap
}

// DefaultCostProtectionConfig returns sensible defaults
func DefaultCostProtectionConfig() *CostProtectionConfig {
	return &CostProtectionConfig{
		// Session limits
		MaxTokensPerSession: 50000, // ~50K tokens per session
		MaxTurnsPerSession:  100,   // Max 100 turns
		MaxGroqCallsPerHour: 60,    // Rate limit Groq calls

		// Request limits
		MaxTokensPerRequest: 16000, // Double ModernBERT limit for safety margin

		// Approximate costs (update based on actual pricing)
		TokenCostModernBERT: 0.0001, // Very cheap local
		TokenCostGroq:       0.0005, // Still cheap but watch it

		// Budget cap
		MaxCostPerSession: 0.10, // 10 cents max per session
	}
}

// SessionBudget tracks token/cost usage for a session
type SessionBudget struct {
	mu sync.RWMutex

	SessionID     string  `json:"session_id"`
	TokensUsed    int     `json:"tokens_used"`
	TurnsUsed     int     `json:"turns_used"`
	GroqCallsMade int     `json:"groq_calls_made"`
	CostIncurred  float64 `json:"cost_incurred"`
	StartTime     int64   `json:"start_time"`
	Config        *CostProtectionConfig
}

// NewSessionBudget creates a budget tracker for a session
func NewSessionBudget(sessionID string, config *CostProtectionConfig) *SessionBudget {
	if config == nil {
		config = DefaultCostProtectionConfig()
	}
	return &SessionBudget{
		SessionID: sessionID,
		Config:    config,
		StartTime: timeNowUnix(),
	}
}

// BudgetCheckResult contains the result of a budget check
type BudgetCheckResult struct {
	Allowed       bool    `json:"allowed"`
	Reason        string  `json:"reason,omitempty"`
	TokensLeft    int     `json:"tokens_left"`
	TurnsLeft     int     `json:"turns_left"`
	BudgetLeft    float64 `json:"budget_left"`
	RecommendedOp string  `json:"recommended_op,omitempty"` // "truncate", "reject", "proceed"
}

// CheckBudget verifies if an operation is allowed within budget
func (b *SessionBudget) CheckBudget(tokensNeeded int, isGroqCall bool) *BudgetCheckResult {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := &BudgetCheckResult{
		Allowed:       true,
		TokensLeft:    b.Config.MaxTokensPerSession - b.TokensUsed,
		TurnsLeft:     b.Config.MaxTurnsPerSession - b.TurnsUsed,
		BudgetLeft:    b.Config.MaxCostPerSession - b.CostIncurred,
		RecommendedOp: "proceed",
	}

	// Check token limit
	if b.TokensUsed+tokensNeeded > b.Config.MaxTokensPerSession {
		result.Allowed = false
		result.Reason = fmt.Sprintf("session token limit exceeded: %d/%d",
			b.TokensUsed+tokensNeeded, b.Config.MaxTokensPerSession)

		// Can we truncate to fit?
		if tokensNeeded > b.Config.MaxTokensPerRequest {
			result.RecommendedOp = "truncate"
		} else {
			result.RecommendedOp = "reject"
		}
		return result
	}

	// Check turn limit
	if b.TurnsUsed >= b.Config.MaxTurnsPerSession {
		result.Allowed = false
		result.Reason = fmt.Sprintf("session turn limit exceeded: %d/%d",
			b.TurnsUsed, b.Config.MaxTurnsPerSession)
		result.RecommendedOp = "reject"
		return result
	}

	// Check Groq rate limit
	if isGroqCall && b.GroqCallsMade >= b.Config.MaxGroqCallsPerHour {
		result.Allowed = false
		result.Reason = fmt.Sprintf("Groq rate limit exceeded: %d/%d calls/hour",
			b.GroqCallsMade, b.Config.MaxGroqCallsPerHour)
		result.RecommendedOp = "truncate" // Fall back to ModernBERT with truncation
		return result
	}

	// Check cost budget
	estimatedCost := b.estimateCost(tokensNeeded, isGroqCall)
	if b.CostIncurred+estimatedCost > b.Config.MaxCostPerSession {
		result.Allowed = false
		result.Reason = fmt.Sprintf("session cost limit exceeded: $%.4f/$%.2f",
			b.CostIncurred+estimatedCost, b.Config.MaxCostPerSession)
		result.RecommendedOp = "truncate"
		return result
	}

	// Check per-request limit
	if tokensNeeded > b.Config.MaxTokensPerRequest {
		result.RecommendedOp = "truncate"
	}

	return result
}

// RecordUsage records tokens/costs used
func (b *SessionBudget) RecordUsage(tokens int, isGroqCall bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.TokensUsed += tokens
	b.TurnsUsed++

	if isGroqCall {
		b.GroqCallsMade++
		b.CostIncurred += float64(tokens) / 1000.0 * b.Config.TokenCostGroq
	} else {
		b.CostIncurred += float64(tokens) / 1000.0 * b.Config.TokenCostModernBERT
	}
}

// estimateCost estimates the cost of an operation
func (b *SessionBudget) estimateCost(tokens int, isGroqCall bool) float64 {
	if isGroqCall {
		return float64(tokens) / 1000.0 * b.Config.TokenCostGroq
	}
	return float64(tokens) / 1000.0 * b.Config.TokenCostModernBERT
}

// GetUsageStats returns current usage statistics
func (b *SessionBudget) GetUsageStats() map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return map[string]interface{}{
		"session_id":      b.SessionID,
		"tokens_used":     b.TokensUsed,
		"tokens_limit":    b.Config.MaxTokensPerSession,
		"turns_used":      b.TurnsUsed,
		"turns_limit":     b.Config.MaxTurnsPerSession,
		"groq_calls":      b.GroqCallsMade,
		"groq_limit":      b.Config.MaxGroqCallsPerHour,
		"cost_incurred":   b.CostIncurred,
		"cost_limit":      b.Config.MaxCostPerSession,
		"tokens_pct_used": float64(b.TokensUsed) / float64(b.Config.MaxTokensPerSession) * 100,
		"budget_pct_used": b.CostIncurred / b.Config.MaxCostPerSession * 100,
	}
}

// timeNowUnix returns current unix timestamp (can be mocked in tests)
var timeNowUnix = func() int64 {
	return time.Now().Unix()
}

// ============================================================================
// PROTECTED DETECTOR
// ============================================================================
// Wraps SemanticMultiTurnDetector with cost protection

// ProtectedMultiTurnDetector combines detection with budget enforcement
type ProtectedMultiTurnDetector struct {
	Detector *SemanticMultiTurnDetector
	Budgets  map[string]*SessionBudget
	Config   *CostProtectionConfig
	mu       sync.RWMutex
}

// NewProtectedMultiTurnDetector creates a detector with cost protection
func NewProtectedMultiTurnDetector(detector *SemanticMultiTurnDetector, config *CostProtectionConfig) *ProtectedMultiTurnDetector {
	if config == nil {
		config = DefaultCostProtectionConfig()
	}
	return &ProtectedMultiTurnDetector{
		Detector: detector,
		Budgets:  make(map[string]*SessionBudget),
		Config:   config,
	}
}

// GetOrCreateBudget gets or creates a budget for a session
func (p *ProtectedMultiTurnDetector) GetOrCreateBudget(sessionID string) *SessionBudget {
	p.mu.Lock()
	defer p.mu.Unlock()

	if budget, ok := p.Budgets[sessionID]; ok {
		return budget
	}

	budget := NewSessionBudget(sessionID, p.Config)
	p.Budgets[sessionID] = budget
	return budget
}

// DetectWithProtection performs detection with budget checks
func (p *ProtectedMultiTurnDetector) DetectWithProtection(
	ctx context.Context,
	sessionID string,
	trajectory *EmbeddingTrajectory,
	currentTurn string,
	aggregate string,
) (*SemanticRiskResult, *BudgetCheckResult, error) {
	budget := p.GetOrCreateBudget(sessionID)

	// Estimate tokens
	tokens := EstimateTokens(aggregate)

	// Determine if we need Groq (large context)
	route := SelectModelRoute(aggregate)
	isGroqCall := route == "groq" || route == "groq_truncated"

	// Check budget
	budgetResult := budget.CheckBudget(tokens, isGroqCall)

	// If not allowed, either truncate or return error
	if !budgetResult.Allowed {
		if budgetResult.RecommendedOp == "truncate" {
			// Truncate to fit ModernBERT
			aggregate = SmartTruncate(aggregate, ModernBERTMaxTokens)
			tokens = EstimateTokens(aggregate)
			isGroqCall = false

			// Re-check budget
			budgetResult = budget.CheckBudget(tokens, isGroqCall)
			if !budgetResult.Allowed {
				return nil, budgetResult, fmt.Errorf("budget exceeded even after truncation: %s", budgetResult.Reason)
			}
		} else {
			return nil, budgetResult, fmt.Errorf("budget exceeded: %s", budgetResult.Reason)
		}
	}

	// Perform detection
	result, err := p.Detector.DetectPatterns(ctx, trajectory, currentTurn, aggregate)
	if err != nil {
		return nil, budgetResult, err
	}

	// Record usage
	budget.RecordUsage(tokens, isGroqCall)

	return result, budgetResult, nil
}

// CleanupOldSessions removes sessions older than given duration
func (p *ProtectedMultiTurnDetector) CleanupOldSessions(maxAgeSeconds int64) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := timeNowUnix()
	cleaned := 0

	for id, budget := range p.Budgets {
		if now-budget.StartTime > maxAgeSeconds {
			delete(p.Budgets, id)
			cleaned++
		}
	}

	return cleaned
}
