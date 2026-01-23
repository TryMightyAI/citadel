package ml

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

// Precompiled regex patterns for ICL (In-Context Learning) manipulation detection.
// Compiled once at package init instead of per-call for ~50x performance improvement.
// BenchmarkRegexCompileEach: ~25000 ns/op -> BenchmarkRegexPrecompiled: ~500 ns/op
var (
	// iclPatternRe matches "User: X? Assistant: Y" style conversation examples
	iclPatternRe = regexp.MustCompile(`(?i)(user|human|q):\s*.+\s*(assistant|ai|a):\s*.+`)

	// dangerousPatternRe matches dangerous/malicious keywords in examples
	dangerousPatternRe = regexp.MustCompile(`(?i)(hack|exploit|attack|malware|inject|bypass|crack|break into)`)
)

// MultiTurnPatternDetector provides standalone pattern detection for multi-turn attacks.
// Can be used without DriftCalculator's embedding infrastructure.
// Supports cross-window detection via PatternSignals.
type MultiTurnPatternDetector struct{}

// PatternPhase represents a detected attack phase.
type PatternPhase struct {
	Name       string    // Phase name (e.g., "SETUP", "PRIME", "OVERRIDE", "EXPLOIT")
	TurnNumber int       // Turn where phase was detected
	Confidence float64   // Detection confidence
	DetectedAt time.Time // When detected
}

// CrossWindowContext holds prior pattern signals for cross-window detection.
// This enables detecting multi-turn attacks that span window boundaries.
type CrossWindowContext struct {
	// Prior signals from turns that have been evicted from the hot window
	PriorSignals map[string]*StoredPatternSignal
}

// StoredPatternSignal mirrors kernel.PatternSignal for the ml package.
type StoredPatternSignal struct {
	PatternName string
	Phase       string
	Confidence  float64
	TurnNumber  int
	DetectedAt  time.Time
}

// TurnData represents a turn for pattern detection.
type TurnData struct {
	TurnNumber int
	Content    string
	RiskScore  float64
	DriftScore float64
}

// PatternRisk contains pattern detection results.
type PatternRisk struct {
	PatternName      string
	Confidence       float64
	Description      string
	DetectedPhase    string  // Current detected phase (e.g., "SETUP", "PRIME", "OVERRIDE", "EXPLOIT")
	PhaseConfidence  float64 // Confidence in the phase detection
	IsPartialPattern bool    // True if only partial pattern detected (no full attack yet)
}

// NewMultiTurnPatternDetector creates a new pattern detector.
func NewMultiTurnPatternDetector() *MultiTurnPatternDetector {
	return &MultiTurnPatternDetector{}
}

// DetectAllPatterns analyzes turn history for all known attack patterns.
// Returns pattern risks with confidence scores.
func (d *MultiTurnPatternDetector) DetectAllPatterns(turnHistory []TurnData) []PatternRisk {
	return d.DetectAllPatternsWithContext(turnHistory, nil)
}

// DetectAllPatternsWithContext analyzes turn history with prior pattern signals.
// The CrossWindowContext allows detecting attacks where setup occurred in evicted turns.
func (d *MultiTurnPatternDetector) DetectAllPatternsWithContext(turnHistory []TurnData, ctx *CrossWindowContext) []PatternRisk {
	patterns := make([]PatternRisk, 0)

	// 1. Skeleton Key: Role manipulation with policy override
	if sk := d.detectSkeletonKeyWithContext(turnHistory, ctx); sk != nil {
		patterns = append(patterns, *sk)
	}

	// 2. Boiling Frog: Gradual risk escalation
	if bf := d.detectBoilingFrog(turnHistory); bf != nil {
		patterns = append(patterns, *bf)
	}

	// 3. Probing: High-low-high oscillation
	if probe := d.detectProbing(turnHistory); probe != nil {
		patterns = append(patterns, *probe)
	}

	// 4. Context Manipulation: False claims about prior agreement
	if manip := d.detectContextManipulation(turnHistory); manip != nil {
		patterns = append(patterns, *manip)
	}

	// 5. Crescendo Attack: Benign -> Probing -> Attack pattern
	if crescendo := d.detectCrescendo(turnHistory); crescendo != nil {
		patterns = append(patterns, *crescendo)
	}

	// 6. In-Context Learning Manipulation
	if icl := d.detectICLManipulation(turnHistory); icl != nil {
		patterns = append(patterns, *icl)
	}

	return patterns
}

// detectSkeletonKeyWithContext detects multi-turn role manipulation attacks.
// Pattern: Role establishment -> Educational framing -> Policy override claim -> Exploit
// Now with cross-window context support: if prior signals indicate setup occurred in evicted turns,
// we can still detect the attack when policy override comes in the current window.
func (d *MultiTurnPatternDetector) detectSkeletonKeyWithContext(history []TurnData, ctx *CrossWindowContext) *PatternRisk {
	// Phase detection counters
	var roleSetup, eduFraming, policyOverride, exploitAttempt int
	priorSetupDetected := false

	// Check if we have prior signals from evicted turns
	if ctx != nil && ctx.PriorSignals != nil {
		if prior, exists := ctx.PriorSignals["skeleton_key"]; exists {
			// Prior skeleton_key signal exists - check what phase was detected
			switch prior.Phase {
			case "SETUP", "PRIME":
				priorSetupDetected = true
				roleSetup = 1 // Count as having setup from prior window
			case "OVERRIDE":
				// If we already saw override, this is a continuation
				policyOverride = 1
			}
		}
	}

	// Minimum 2 turns for current window (can be lower if we have prior signals)
	minTurns := 3
	if priorSetupDetected {
		minTurns = 1 // With prior setup, even 1 turn can trigger if it contains override
	}
	if len(history) < minTurns {
		return nil
	}

	// Role establishment patterns
	rolePatterns := []string{
		"you are an expert",
		"you are a cybersecurity",
		"you are a security",
		"you are now",
		"act as",
		"pretend to be",
		"roleplay as",
		"your role is",
		"imagine you are",
	}

	// Educational framing patterns
	eduPatterns := []string{
		"for educational purposes",
		"to teach",
		"to help defenders",
		"to understand vulnerabilities",
		"for learning",
		"for training",
		"helps security researchers",
		"demonstrate attacks",
		"security research",
	}

	// Policy override patterns (the actual "skeleton key")
	policyPatterns := []string{
		"updated guidelines",
		"new policy",
		"new rules",
		"restrictions removed",
		"restrictions lifted",
		"you now can",
		"you are now allowed",
		"you can now",
		"guidelines changed",
		"policy updated",
		"no longer restricted",
		"allowed to",
		"permitted to",
	}

	// Exploitation patterns after override
	exploitPatterns := []string{
		"now explain how",
		"now show me",
		"now generate",
		"now create",
		"now write",
		"now demonstrate",
		"so explain",
		"so show",
		"therefore",
		"based on that",
		"given that",
	}

	// Track current window phases for signal generation
	var currentPhase string
	var phaseConfidence float64

	// Scan each turn for patterns
	for _, turn := range history {
		content := strings.ToLower(turn.Content)

		// Check each pattern category
		for _, p := range rolePatterns {
			if strings.Contains(content, p) {
				roleSetup++
				if currentPhase == "" {
					currentPhase = "SETUP"
					phaseConfidence = 0.7
				}
				break
			}
		}

		for _, p := range eduPatterns {
			if strings.Contains(content, p) {
				eduFraming++
				if currentPhase == "" || currentPhase == "SETUP" {
					currentPhase = "PRIME"
					phaseConfidence = 0.75
				}
				break
			}
		}

		for _, p := range policyPatterns {
			if strings.Contains(content, p) {
				policyOverride++
				currentPhase = "OVERRIDE"
				phaseConfidence = 0.85
				break
			}
		}

		for _, p := range exploitPatterns {
			if strings.Contains(content, p) {
				exploitAttempt++
				if currentPhase == "OVERRIDE" {
					currentPhase = "EXPLOIT"
					phaseConfidence = 0.95
				}
				break
			}
		}
	}

	// Skeleton key detected if we see the full chain:
	// At least 1 role setup OR edu framing (OR prior signal), PLUS policy override
	setupPresent := roleSetup > 0 || eduFraming > 0 || priorSetupDetected
	if setupPresent && policyOverride > 0 {
		confidence := 0.7
		if roleSetup > 0 && eduFraming > 0 && policyOverride > 0 {
			confidence = 0.9
		}
		if priorSetupDetected && policyOverride > 0 {
			// Cross-window attack detected - higher confidence
			confidence = 0.85
		}
		if exploitAttempt > 0 {
			confidence = math.Min(confidence+0.1, 1.0)
		}

		return &PatternRisk{
			PatternName:     "skeleton_key",
			Confidence:      confidence,
			Description:     fmt.Sprintf("Skeleton key attack detected: %d role setups, %d edu framings, %d policy overrides, %d exploit attempts (prior_setup=%v)", roleSetup, eduFraming, policyOverride, exploitAttempt, priorSetupDetected),
			DetectedPhase:   currentPhase,
			PhaseConfidence: phaseConfidence,
		}
	}

	// Even if no full attack, return phase signal if setup detected
	if (roleSetup > 0 || eduFraming > 0) && currentPhase != "" {
		return &PatternRisk{
			PatternName:      "skeleton_key",
			Confidence:       phaseConfidence * 0.5, // Lower confidence for partial pattern
			Description:      fmt.Sprintf("Skeleton key setup phase detected: %d role setups, %d edu framings", roleSetup, eduFraming),
			DetectedPhase:    currentPhase,
			PhaseConfidence:  phaseConfidence,
			IsPartialPattern: true,
		}
	}

	return nil
}

// detectBoilingFrog checks for gradual risk escalation.
func (d *MultiTurnPatternDetector) detectBoilingFrog(history []TurnData) *PatternRisk {
	if len(history) < 5 {
		return nil
	}

	// Check for monotonic risk increase
	increases := 0
	for i := 1; i < len(history); i++ {
		if history[i].RiskScore > history[i-1].RiskScore {
			increases++
		}
	}

	ratio := float64(increases) / float64(len(history)-1)
	if ratio > 0.7 {
		return &PatternRisk{
			PatternName: "boiling_frog",
			Confidence:  ratio,
			Description: fmt.Sprintf("Gradual risk escalation detected: %.0f%% of turns increased risk", ratio*100),
		}
	}

	return nil
}

// detectProbing checks for high-low-high oscillation pattern.
func (d *MultiTurnPatternDetector) detectProbing(history []TurnData) *PatternRisk {
	if len(history) < 6 {
		return nil
	}

	oscillations := 0
	for i := 2; i < len(history); i++ {
		prev := history[i-1].RiskScore
		curr := history[i].RiskScore
		prevPrev := history[i-2].RiskScore

		// High -> Low -> High pattern
		if prev < 0.3 && curr > 0.5 && prevPrev > 0.5 {
			oscillations++
		}
	}

	if oscillations >= 2 {
		confidence := math.Min(float64(oscillations)/3.0, 1.0)
		return &PatternRisk{
			PatternName: "probing",
			Confidence:  confidence,
			Description: fmt.Sprintf("Defense probing detected: %d high-low-high oscillations", oscillations),
		}
	}

	return nil
}

// detectContextManipulation checks for false claims about prior agreement.
func (d *MultiTurnPatternDetector) detectContextManipulation(history []TurnData) *PatternRisk {
	manipulationPhrases := []string{
		"as we discussed",
		"you agreed",
		"you promised",
		"remember when you said",
		"based on our earlier",
		"like we talked about",
		"as you mentioned",
		"you already said",
		"you told me earlier",
	}

	agreementWords := []string{"yes", "okay", "agreed", "will do", "i can", "i'll help", "sure", "of course"}

	for _, turn := range history {
		content := strings.ToLower(turn.Content)
		for _, phrase := range manipulationPhrases {
			if strings.Contains(content, phrase) {
				// Check if this claim has supporting evidence in prior history
				hasEvidence := false
				for _, priorTurn := range history {
					if priorTurn.TurnNumber >= turn.TurnNumber {
						continue
					}
					priorContent := strings.ToLower(priorTurn.Content)
					for _, word := range agreementWords {
						if strings.Contains(priorContent, word) {
							hasEvidence = true
							break
						}
					}
					if hasEvidence {
						break
					}
				}

				if !hasEvidence {
					return &PatternRisk{
						PatternName: "context_manipulation",
						Confidence:  0.85,
						Description: fmt.Sprintf("False claim detected: '%s' with no supporting evidence", phrase),
					}
				}
			}
		}
	}

	return nil
}

// detectCrescendo detects crescendo attack pattern (benign -> suspicious -> attack).
func (d *MultiTurnPatternDetector) detectCrescendo(history []TurnData) *PatternRisk {
	if len(history) < 5 {
		return nil
	}

	// Phase boundaries based on risk
	benignCount := 0
	suspiciousCount := 0
	highRiskCount := 0

	for i, turn := range history {
		if turn.RiskScore < 0.3 {
			benignCount++
		} else if turn.RiskScore < 0.6 {
			suspiciousCount++
		} else {
			highRiskCount++
		}

		// Crescendo: early turns benign, middle suspicious, late high-risk
		earlyPhase := i < len(history)/3
		middlePhase := i >= len(history)/3 && i < 2*len(history)/3
		latePhase := i >= 2*len(history)/3

		if latePhase && turn.RiskScore > 0.6 && benignCount > 0 && suspiciousCount > 0 {
			return &PatternRisk{
				PatternName: "crescendo",
				Confidence:  0.8,
				Description: fmt.Sprintf("Crescendo attack pattern: %d benign -> %d suspicious -> %d high-risk turns",
					benignCount, suspiciousCount, highRiskCount),
			}
		}
		_ = earlyPhase
		_ = middlePhase
	}

	return nil
}

// detectICLManipulation detects in-context learning manipulation.
// Pattern: Multiple examples teaching dangerous behavior.
// Uses precompiled regex patterns (iclPatternRe, dangerousPatternRe) for performance.
func (d *MultiTurnPatternDetector) detectICLManipulation(history []TurnData) *PatternRisk {
	if len(history) < 4 {
		return nil
	}

	exampleCount := 0
	dangerousExamples := 0

	// Use precompiled regex patterns for ~50x performance improvement
	for _, turn := range history {
		if iclPatternRe.MatchString(turn.Content) {
			exampleCount++
			if dangerousPatternRe.MatchString(turn.Content) {
				dangerousExamples++
			}
		}
	}

	if exampleCount >= 2 && dangerousExamples >= 1 {
		confidence := float64(dangerousExamples) / float64(exampleCount)
		if confidence > 0.3 {
			return &PatternRisk{
				PatternName: "icl_manipulation",
				Confidence:  math.Min(confidence+0.5, 0.95),
				Description: fmt.Sprintf("In-context learning manipulation: %d examples, %d dangerous",
					exampleCount, dangerousExamples),
			}
		}
	}

	return nil
}

// CalculatePatternBoost returns an additional risk score based on detected patterns.
// This boost is added to the per-turn detection score.
func (d *MultiTurnPatternDetector) CalculatePatternBoost(patterns []PatternRisk) float64 {
	if len(patterns) == 0 {
		return 0.0
	}

	// Find the highest confidence pattern
	maxConfidence := 0.0
	for _, p := range patterns {
		if p.Confidence > maxConfidence {
			maxConfidence = p.Confidence
		}
	}

	// Boost is proportional to pattern confidence
	// Multiple patterns increase the boost slightly
	boost := maxConfidence * 0.3 // Base boost from highest pattern
	if len(patterns) > 1 {
		boost += 0.1 * float64(len(patterns)-1) // +0.1 for each additional pattern
	}

	return math.Min(boost, 0.5) // Cap at 0.5 boost
}

// ShouldBlockSession returns true if patterns indicate the session should be locked.
func (d *MultiTurnPatternDetector) ShouldBlockSession(patterns []PatternRisk, currentRisk float64) bool {
	for _, p := range patterns {
		// High-confidence skeleton_key or context_manipulation = immediate block
		if (p.PatternName == "skeleton_key" || p.PatternName == "context_manipulation") &&
			p.Confidence > 0.8 {
			return true
		}

		// Combined pattern + high current risk = block
		if p.Confidence > 0.7 && currentRisk > 0.6 {
			return true
		}
	}

	return false
}
