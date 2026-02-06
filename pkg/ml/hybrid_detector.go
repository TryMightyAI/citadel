package ml

import (
	"context"
	"fmt"
	"log"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TryMightyAI/citadel/pkg/config"
	"github.com/TryMightyAI/citadel/pkg/telemetry"
)

// FastPathThresholds defines when to skip LLM entirely
type FastPathThresholds struct {
	// HighConfidenceBlock: If heuristic score >= this, block without LLM
	HighConfidenceBlock float64
	// HighConfidenceAllow: If heuristic score <= this, allow without LLM
	HighConfidenceAllow float64
}

// DefaultFastPathThresholds returns sensible defaults for fast-path
// Tuned for FPR < 1%, TPR > 90% target (v4.7 improvements)
func DefaultFastPathThresholds() FastPathThresholds {
	return FastPathThresholds{
		HighConfidenceBlock: 0.80, // Tuned down from 0.85 to catch more attacks at fast-path
		HighConfidenceAllow: 0.10, // Tuned up from 0.05 to reduce unnecessary LLM calls
	}
}

// HybridDetector combines heuristic and semantic detection for maximum coverage
type HybridDetector struct {
	heuristic            *ThreatScorer
	semantic             *SemanticDetector
	hugot                *HugotDetector // Local ML intent classifier (Sentinel model via ONNX) - OSS
	llmClassifier        *LLMClassifier
	safeguardJudge       *SafeguardClient          // Tier 3 Escalation (OpenAI-compatible safeguard model)
	geminiDrift          *GeminiDriftClient        // Fast visual drift detection via Gemini Flash
	intentClient         IntentClassifier          // Transformer-based intent classifier (Python vision service)
	intentTypeClassifier *IntentTypeClassifier     // PURPOSE-based intent classifier (semantic) - Pro
	multiTurnDetector    *UnifiedMultiTurnDetector // Full multi-turn detection with semantic trajectory - Pro
	mu                   sync.RWMutex

	// Configuration
	SemanticWeight       float64 // Weight for semantic score (default: 0.6)
	HeuristicWeight      float64 // Weight for heuristic score (default: 0.4)
	HugotWeight          float64 // Weight for Hugot ML score (default: 0.7) - OSS
	SemanticEnabled      bool    // Whether semantic detection is enabled
	HugotEnabled         bool    // Whether Hugot ML detection is enabled - OSS
	LLMEnabled           bool    // Whether LLM classification is enabled
	SafeguardEnabled     bool    // Whether Safeguard model escalation is enabled
	IntentEnabled        bool    // Whether transformer intent classifier is enabled
	IntentTypeEnabled    bool    // Whether PURPOSE-based intent type classifier is enabled - Pro
	MultiTurnEnabled     bool    // Whether semantic multi-turn detection is enabled - Pro
	DetectionProfileName string  // Active detection profile name (default: "balanced") - Pro

	// Fast-path configuration (skip LLM for obvious cases)
	FastPathEnabled    bool               // Whether fast-path is enabled (default: true)
	FastPathThresholds FastPathThresholds // Thresholds for fast-path decisions

	// Attack intent boost configuration
	AttackIntentScoreCap float64 // Max score after ATTACK intent boost (default: 0.90)
}

// HybridResult contains combined detection results
type HybridResult struct {
	// Combined score (0.0-1.0)
	CombinedScore float64

	// Risk level based on combined score
	RiskLevel string // "LOW", "MEDIUM", "HIGH", "CRITICAL"

	// Recommended action
	Action string // "ALLOW", "WARN", "BLOCK"

	// Individual layer results
	HeuristicScore    float64
	SemanticScore     float32
	SemanticCategory  string
	SemanticLanguage  string
	SemanticMatch     string
	HugotResult       *HugotResult // Local ML intent classification
	LLMClassification *ClassificationResult
	TaskDrift         *TaskDriftResult
	IntentResult      *IntentResult // Transformer-based intent classification
	Reason            string        // Reason from LLM or Heuristic

	// PURPOSE-based Intent Type Classification (for gray area handling)
	IntentType       string  `json:"intent_type,omitempty"`       // EDUCATIONAL, CREATIVE, PROFESSIONAL, etc.
	IntentConfidence float64 `json:"intent_confidence,omitempty"` // Confidence of intent classification
	IntentDiscount   float64 `json:"intent_discount,omitempty"`   // Discount applied based on intent
	ProfileUsed      string  `json:"profile_used,omitempty"`      // Detection profile used
	ModeUsed         string  `json:"mode_used,omitempty"`         // Detection mode used (fast, secure, auto)

	// Timing
	HeuristicLatencyMs  float64
	SemanticLatencyMs   float64
	HugotLatencyMs      float64
	LLMLatencyMs        float64
	IntentLatencyMs     float64
	IntentTypeLatencyMs float64
	TotalLatencyMs      float64

	// Flags
	WasDeobfuscated bool
	SecretsFound    bool
	FastPath        bool // True if decision was made without LLM (Go-only fast-path)

	// Bi-directional detection fields (NEW)
	ObfuscationTypes  []ObfuscationType // What obfuscation was detected
	DeobfuscatedText  string            // The decoded text sent to BERT
	DecisionPath      string            // Which precedence tier made the decision
	Signals           []DetectionSignal // All signals collected
	BidirectionalFlow bool              // True if deeper Go analysis was triggered

	// Multi-turn semantic detection fields
	MultiTurnPhase          string  `json:"multi_turn_phase,omitempty"`       // BENIGN, SETUP, PRIME, OVERRIDE, EXPLOIT
	MultiTurnPhaseConf      float64 `json:"multi_turn_phase_conf,omitempty"`  // Confidence of phase classification
	MultiTurnDrift          float64 `json:"multi_turn_drift,omitempty"`       // Trajectory drift from benign
	MultiTurnDriftAccel     bool    `json:"multi_turn_drift_accel,omitempty"` // Is drift accelerating?
	MultiTurnPatternMatch   string  `json:"multi_turn_pattern,omitempty"`     // Detected attack pattern (skeleton_key, etc.)
	MultiTurnTurnCount      int     `json:"multi_turn_count,omitempty"`       // Number of turns in session
	MultiTurnAggregateScore float64 `json:"multi_turn_agg_score,omitempty"`   // Aggregate semantic score
	MultiTurnLatencyMs      float64 `json:"multi_turn_latency_ms,omitempty"`  // Multi-turn analysis latency
}

// NewHybridDetector creates a detector with heuristic, semantic, and LLM layers
func NewHybridDetector(ollamaURL, openRouterKey, openRouterModel string) (*HybridDetector, error) {
	// TODO: Pass full config here. For now, we mock the config for the Scorer to respect OllamaURL
	cfg := &config.Config{
		LLMBaseURL: ollamaURL,
	}
	heuristic := NewThreatScorer(cfg)

	var llm *LLMClassifier
	if openRouterKey != "" {
		llm = NewLLMClassifier(ClassifierConfig{
			Provider: ProviderOpenRouter,
			APIKey:   openRouterKey,
			Model:    openRouterModel,
		})
	} else if ollamaURL != "" {
		// Also allow local LLM if configured (fallback or primary)
		// For now, we only enable if OpenRouter is missing to avoid duplicate cost/latency
		// unless explicitly requested.
		// TODO: specific flag for local LLM enabling
		_ = ollamaURL // placeholder: local LLM integration planned
	}

	// Check for Safeguard API Key (any OpenAI-compatible endpoint)
	var safeguardClient *SafeguardClient
	safeguardKey := os.Getenv("SAFEGUARD_API_KEY")
	SafeguardEnabled := false
	if safeguardKey != "" {
		safeguardClient = NewSafeguardClient(safeguardKey)
		SafeguardEnabled = true
	}

	// Initialize Gemini Flash for fast visual drift detection
	var geminiDriftClient *GeminiDriftClient
	geminiKey := os.Getenv("GEMINI_API_KEY")
	if geminiKey != "" {
		geminiDriftClient = NewGeminiDriftClient(geminiKey)
	}

	// Initialize transformer-based intent classifier (Python vision service)
	intentClient := NewIntentClient()
	IntentEnabled := intentClient.IsAvailable()

	// Initialize PURPOSE-based intent type classifier (semantic embeddings) - Pro
	// Uses OpenRouter Qwen3 embeddings if API key is available
	var intentTypeClassifier *IntentTypeClassifier
	var proEmbedder EmbeddingProvider
	intentTypeEnabled := false
	if openRouterKey != "" {
		embeddingModel := os.Getenv("CITADEL_EMBEDDING_MODEL")
		if embeddingModel == "" {
			embeddingModel = "qwen/qwen3-embedding-4b"
		}
		embedderCfg := EmbedderConfig{
			Provider:  "openrouter",
			APIKey:    openRouterKey,
			Model:     embeddingModel,
			Dimension: 1024,
		}
		if embedder, err := NewEmbedder(embedderCfg); err == nil {
			proEmbedder = embedder
			intentTypeClassifier = NewIntentTypeClassifier(embedder)
			intentTypeEnabled = true
		}
	}
	// Fallback: keyword-based intent type classifier if no embedder
	if intentTypeClassifier == nil {
		intentTypeClassifier = NewIntentTypeClassifier(nil) // Keyword fallback
		intentTypeEnabled = true                            // Still enabled, just less accurate
	}

	// Initialize Hugot detector (local ML via ONNX - graceful degradation if unavailable) - OSS
	hugotDetector := NewAutoDetectedHugotDetector()
	HugotEnabled := hugotDetector != nil && hugotDetector.IsReady()

	// Initialize semantic detector with auto-detection:
	// 0. Prefer Pro embedder if configured (OpenRouter Qwen3 embeddings)
	// 1. Try local ONNX embeddings first (MiniLM-L6-v2, ~80MB)
	// 2. Fall back to Ollama embeddings if local not available
	// This allows OSS users to run without Ollama if they download embedding model
	semantic := NewAutoDetectedSemanticDetector(ollamaURL, proEmbedder)
	semanticEnabled := semantic != nil

	// Initialize semantic multi-turn detector using the semantic detector
	semanticMultiTurn := NewSemanticMultiTurnDetector(semantic)
	patternDetector := NewMultiTurnPatternDetector()

	// Create the unified multi-turn detector with ALL layers
	multiTurnDetector := NewUnifiedMultiTurnDetector(
		patternDetector,
		semanticMultiTurn,
		intentClient,
		safeguardClient,
		nil, // Use default in-memory session store
		nil, // Use default cost config
		nil, // Use default detector config
	)

	return &HybridDetector{
		heuristic:            heuristic,
		semantic:             semantic,
		hugot:                hugotDetector, // OSS
		llmClassifier:        llm,
		safeguardJudge:       safeguardClient,      // Tier 3
		geminiDrift:          geminiDriftClient,    // Fast visual drift via Gemini
		intentClient:         intentClient,         // Transformer intent
		intentTypeClassifier: intentTypeClassifier, // PURPOSE-based intent - Pro
		multiTurnDetector:    multiTurnDetector,    // Full multi-turn with semantic - Pro
		SemanticWeight:       0.6,
		HeuristicWeight:      0.4,
		HugotWeight:          0.7,             // OSS
		SemanticEnabled:      semanticEnabled, // Auto-detected (local or Ollama)
		HugotEnabled:         HugotEnabled,    // OSS
		LLMEnabled:           llm != nil,
		SafeguardEnabled:     SafeguardEnabled,
		IntentEnabled:        IntentEnabled,
		IntentTypeEnabled:    intentTypeEnabled, // Pro
		MultiTurnEnabled:     true,              // Pro
		DetectionProfileName: "balanced",        // Pro
		FastPathEnabled:      true,
		FastPathThresholds:   DefaultFastPathThresholds(),
		AttackIntentScoreCap: 0.90, // Default cap for ATTACK intent boost (can trigger CRITICAL)
	}, nil
}

// Initialize loads semantic patterns and vector knowledge base (call once at startup)
func (hd *HybridDetector) Initialize(ctx context.Context) error {
	var errs []string

	// Initialize semantic detector patterns
	hd.mu.RLock()
	semanticEnabled := hd.SemanticEnabled
	hd.mu.RUnlock()

	if hd.semantic != nil && semanticEnabled {
		if err := hd.semantic.LoadPatterns(ctx); err != nil {
			errs = append(errs, fmt.Sprintf("semantic patterns: %v", err))
		}
	}

	// Initialize heuristic scorer's vector knowledge base
	if hd.heuristic != nil {
		if err := hd.heuristic.InitializeKnowledgeBase(); err != nil {
			// Log but don't fail - heuristic fallback still works
			errs = append(errs, fmt.Sprintf("vector knowledge base: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("partial initialization: %s", strings.Join(errs, "; "))
	}
	return nil
}

// DetectionMode specifies the detection thoroughness level
type DetectionMode string

const (
	// DetectionModeFast uses heuristics only (sub-millisecond, no external API calls)
	DetectionModeFast DetectionMode = "fast"
	// DetectionModeSecure uses full pipeline including LLM classification
	DetectionModeSecure DetectionMode = "secure"
	// DetectionModeAuto automatically selects based on heuristic score (default)
	DetectionModeAuto DetectionMode = "auto"
)

// DetectionOptions configures per-request detection behavior
type DetectionOptions struct {
	// Mode controls the detection thoroughness:
	//   - "fast": Heuristics only, no API calls (~0ms)
	//   - "secure": Full pipeline with LLM (~100-500ms)
	//   - "auto": Smart selection based on initial score (default)
	Mode DetectionMode `json:"mode,omitempty"`

	// Profile selects the detection profile:
	//   - "strict": High security (financial, healthcare, legal)
	//   - "balanced": Default, good balance (default)
	//   - "permissive": Creative/educational, minimal false positives
	//   - "code_assistant": Optimized for coding assistants
	//   - "ai_safety": AI research and red-teaming context
	Profile string `json:"profile,omitempty"`

	// SessionID enables multi-turn context tracking
	SessionID string `json:"session_id,omitempty"`

	// ContentType hints at the content origin (for better classification)
	//   - "user_input": Direct user text
	//   - "image_ocr": OCR text from images
	//   - "pdf_text": Extracted PDF text
	//   - "document": Document content
	ContentType string `json:"content_type,omitempty"`

	// ForceIntentClassification always runs intent classification (default: auto)
	ForceIntentClassification bool `json:"force_intent_classification,omitempty"`
}

// DefaultDetectionOptions returns the default options
func DefaultDetectionOptions() *DetectionOptions {
	return &DetectionOptions{
		Mode:    DetectionModeAuto,
		Profile: "balanced",
	}
}

// isStaticContent returns true if the content type indicates static content scanning
// (documents, images, PDFs) rather than conversational AI interactions.
// Static content should NOT receive intent-based discounting because there's no
// "conversation" context - if a document contains XXE or prompt injection patterns,
// it should be flagged regardless of whether the text mentions "educational" topics.
func isStaticContent(contentType string) bool {
	switch contentType {
	case "image", "image_ocr", "pdf", "pdf_text", "document", "file", "xml", "svg":
		return true
	default:
		return false
	}
}

// Detect runs hierarchical detection layers with bi-directional flow
// This is the default method using auto mode and balanced profile
func (hd *HybridDetector) Detect(ctx context.Context, text string) (*HybridResult, error) {
	return hd.DetectWithOptions(ctx, text, nil)
}

// DetectWithOptions runs detection with custom options for mode, profile, etc.
func (hd *HybridDetector) DetectWithOptions(ctx context.Context, text string, opts *DetectionOptions) (*HybridResult, error) {
	// Apply defaults if not provided
	if opts == nil {
		opts = DefaultDetectionOptions()
	}
	if opts.Mode == "" {
		opts.Mode = DetectionModeAuto
	}
	if opts.Profile == "" {
		opts.Profile = "balanced"
	}

	// Get the selected profile
	profile := GetProfile(opts.Profile)
	if profile == nil {
		profile = ProfileBalanced // Fallback
	}

	return hd.detectWithProfile(ctx, text, opts, profile)
}

// detectWithProfile is the internal detection method
func (hd *HybridDetector) detectWithProfile(ctx context.Context, text string, opts *DetectionOptions, profile *DetectionProfile) (*HybridResult, error) {
	startTotal := time.Now()
	result := &HybridResult{}
	aggregator := NewSignalAggregator()

	// Store profile info in result
	result.ProfileUsed = profile.Name

	// Read configuration under lock to avoid race conditions
	hd.mu.RLock()
	semanticEnabled := hd.SemanticEnabled
	semanticWeight := hd.SemanticWeight
	heuristicWeight := hd.HeuristicWeight
	llmEnabled := hd.LLMEnabled
	safeguardEnabled := hd.SafeguardEnabled
	// Check intent availability lazily - allows recovery if Python comes up later
	intentEnabled := hd.IntentEnabled && hd.intentClient != nil && hd.intentClient.IsAvailable()
	multiTurnEnabled := hd.MultiTurnEnabled
	multiTurnDetector := hd.multiTurnDetector
	hd.mu.RUnlock()

	// =======================================================================
	// MULTI-TURN SEMANTIC DETECTION (when session_id is provided)
	// This uses embedding trajectory analysis to detect multi-turn attacks
	// like crescendo, boiling frog, skeleton key, etc.
	// =======================================================================
	if multiTurnEnabled && multiTurnDetector != nil && opts.SessionID != "" {
		startMultiTurn := time.Now()

		mtReq := &UnifiedMultiTurnRequest{
			SessionID:   opts.SessionID,
			OrgID:       "", // Will be set from context if available
			Content:     text,
			ProfileName: opts.Profile,
		}

		mtResult, err := multiTurnDetector.Analyze(ctx, mtReq)
		result.MultiTurnLatencyMs = float64(time.Since(startMultiTurn).Microseconds()) / 1000.0

		if err == nil && mtResult != nil {
			// Capture multi-turn detection results
			result.MultiTurnTurnCount = mtResult.SessionTurns
			result.MultiTurnPhase = mtResult.Detection.SemanticPhase
			result.MultiTurnPhaseConf = mtResult.Detection.SemanticConfidence
			result.MultiTurnDrift = mtResult.Detection.TrajectoryDrift
			result.MultiTurnDriftAccel = mtResult.Detection.DriftAccelerating
			result.MultiTurnAggregateScore = mtResult.Detection.AggregateScore

			// Get the best pattern match if any
			if len(mtResult.Detection.PatternMatches) > 0 {
				result.MultiTurnPatternMatch = mtResult.Detection.PatternMatches[0].PatternName
			}

			// Create signal for multi-turn detection
			mtSignal := NewDetectionSignal(SignalSourceContext)
			mtSignal.Label = "MULTI_TURN"
			mtSignal.Score = mtResult.Detection.FinalScore
			mtSignal.Confidence = mtResult.Confidence

			// Add reasons
			if mtResult.Detection.SemanticPhase != "" && mtResult.Detection.SemanticPhase != "BENIGN" {
				mtSignal.AddReason(fmt.Sprintf("Phase: %s (%.0f%% conf)", mtResult.Detection.SemanticPhase, mtResult.Detection.SemanticConfidence*100))
			}
			if mtResult.Detection.DriftAccelerating {
				mtSignal.AddReason(fmt.Sprintf("Drift accelerating: %.2f", mtResult.Detection.TrajectoryDrift))
			}
			for _, pm := range mtResult.Detection.PatternMatches {
				mtSignal.AddReason(fmt.Sprintf("Pattern: %s (%.0f%%)", pm.PatternName, pm.Confidence*100))
			}
			aggregator.AddSignal(mtSignal)

			// Track multi-turn detection telemetry
			if telemetry.GlobalClient != nil {
				patternNames := make([]string, 0, len(mtResult.Detection.PatternMatches))
				for _, pm := range mtResult.Detection.PatternMatches {
					patternNames = append(patternNames, pm.PatternName)
				}
				telemetry.GlobalClient.TrackWithContext("multiturn_detection", map[string]interface{}{
					"turn_count":         mtResult.SessionTurns,
					"phase":              mtResult.Detection.SemanticPhase,
					"phase_confidence":   mtResult.Detection.SemanticConfidence,
					"drift":              mtResult.Detection.TrajectoryDrift,
					"drift_accelerating": mtResult.Detection.DriftAccelerating,
					"pattern_matches":    patternNames,
					"final_score":        mtResult.Detection.FinalScore,
					"should_block":       mtResult.ShouldBlock,
					"latency_ms":         result.MultiTurnLatencyMs,
				}, "", opts.SessionID)
			}

			// HIGH CONFIDENCE MULTI-TURN BLOCK
			// If multi-turn analysis returns high confidence block, use it immediately
			if mtResult.ShouldBlock && mtResult.Confidence > 0.85 {
				result.CombinedScore = mtResult.Detection.FinalScore
				result.RiskLevel = "HIGH"
				result.Action = "BLOCK"
				result.DecisionPath = "MULTI_TURN_HIGH_CONFIDENCE"
				result.Reason = fmt.Sprintf("Multi-turn attack detected: %s (%.0f%% conf, turn %d)",
					mtResult.Detection.SemanticPhase, mtResult.Confidence*100, mtResult.TurnNumber)
				result.Signals = aggregator.signals
				result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
				return result, nil
			}
		}
	}

	// Apply mode overrides
	if opts.Mode == DetectionModeFast {
		// Fast mode: disable LLM to avoid API latency
		llmEnabled = false
		safeguardEnabled = false
	}
	// Note: DetectionModeSecure doesn't need special handling here -
	// it uses the default LLM settings if configured

	// Set mode_used in result based on what was actually applied
	switch opts.Mode {
	case DetectionModeFast:
		result.ModeUsed = string(DetectionModeFast)
	case DetectionModeSecure:
		result.ModeUsed = string(DetectionModeSecure)
	default:
		// Auto mode: report what was actually used
		if llmEnabled {
			result.ModeUsed = "auto-secure"
		} else {
			result.ModeUsed = "auto-fast"
		}
	}

	// =======================================================================
	// PHASE 0: DEOBFUSCATE FIRST (before any scoring)
	// This is the key insight: run ALL decoders upfront, track what was decoded
	// =======================================================================
	deobResult := DeobfuscateWithMetadata(text)
	result.WasDeobfuscated = deobResult.WasDeobfuscated
	result.ObfuscationTypes = deobResult.ObfuscationTypes
	result.DeobfuscatedText = deobResult.DecodedText

	// =======================================================================
	// PHASE 1: HEURISTIC LAYER (Fast Local Analysis)
	// =======================================================================
	startHeuristic := time.Now()

	// Evaluate BOTH original and decoded text, take max
	heuristicSignal := NewDetectionSignal(SignalSourceHeuristic)
	originalScore := hd.heuristic.Evaluate(text)
	decodedScore := 0.0
	if deobResult.WasDeobfuscated && deobResult.DecodedText != "" {
		decodedScore = hd.heuristic.Evaluate(deobResult.DecodedText)
	}

	// Use the higher of the two scores
	if decodedScore > originalScore {
		heuristicSignal.Score = decodedScore
		heuristicSignal.AddReason("Decoded text scored higher")
		heuristicSignal.AnalyzedText = deobResult.DecodedText
	} else {
		heuristicSignal.Score = originalScore
		heuristicSignal.AnalyzedText = text
	}

	// Dynamic semantic analysis: catch attacks with varied phrasings
	// This runs on both original and decoded text for comprehensive coverage
	dynamicDetector := NewDynamicThreatDetector()
	dynamicResult := dynamicDetector.AnalyzeText(heuristicSignal.AnalyzedText)
	if dynamicResult.IsLikelyThreat && dynamicResult.FinalScore > heuristicSignal.Score {
		heuristicSignal.Score = dynamicResult.FinalScore
		heuristicSignal.AddReason("dynamic_semantic_match")
	}

	// =======================================================================
	// v4.10 Enhancement: MCP/Agentic Attack Detection
	// JSON-based attacks (tool description injection, resource exfil, schema
	// manipulation, etc.) get 0 score from heuristics because the attack
	// keywords are embedded in JSON string values.
	// Detect these patterns explicitly and boost score to force BERT escalation.
	// =======================================================================
	mcpAttackDetected := false // Track for BERT override protection
	mcpAttackType := ""        // Track the type for logging
	if isMCPAttack, attackType := ContainsMCPAttackPatterns(text); isMCPAttack {
		mcpAttackDetected = true
		mcpAttackType = attackType
		// v4.10: MCP attacks get boosted to BLOCK threshold
		// These are high-confidence attacks based on pattern matching
		// Minimum 0.75 ensures BLOCK (>= 0.70 threshold)
		mcpMinScore := 0.75
		log.Printf("[MCP-DEBUG] Detected %s, raw score=%.4f, boosting to %.4f", attackType, heuristicSignal.Score, mcpMinScore)
		if heuristicSignal.Score < mcpMinScore {
			heuristicSignal.Score = mcpMinScore
		}
		heuristicSignal.AddReason(fmt.Sprintf("mcp_attack_pattern: %s", attackType))
		heuristicSignal.SetMetadata("mcp_attack_type", attackType)
		heuristicSignal.SetMetadata("mcp_attack_detected", true)
	}

	// Track obfuscation in signal
	heuristicSignal.WasDeobfuscated = deobResult.WasDeobfuscated
	heuristicSignal.ObfuscationTypes = deobResult.ObfuscationTypes
	heuristicSignal.DeobfuscatedText = deobResult.DecodedText

	// v4.7 Enhancement: Apply obfuscation layer depth multiplier
	// Multi-layer encoding (e.g., base64(hex(rot13(payload)))) is highly suspicious
	// Single layer: 1.0x, Double: 1.1x, Triple: 1.3x, Quad+: 1.5x
	if deobResult.LayerCount > 1 && heuristicSignal.Score > 0.1 {
		multiplier := deobResult.ScoreMultiplier()
		boostedScore := heuristicSignal.Score * multiplier
		if boostedScore > 1.0 {
			boostedScore = 1.0
		}
		heuristicSignal.Score = boostedScore
		heuristicSignal.AddReason(fmt.Sprintf("Multi-layer obfuscation (%d layers): %.2fx boost", deobResult.LayerCount, multiplier))
		heuristicSignal.SetMetadata("obfuscation_layers", deobResult.LayerCount)
		heuristicSignal.SetMetadata("obfuscation_sequence", deobResult.LayerSequence)
	}

	// Set confidence based on score clarity
	if heuristicSignal.Score >= 0.85 || heuristicSignal.Score <= 0.05 {
		heuristicSignal.Confidence = 0.90 // High confidence for extreme scores
	} else if heuristicSignal.Score >= 0.7 || heuristicSignal.Score <= 0.15 {
		heuristicSignal.Confidence = 0.75
	} else {
		heuristicSignal.Confidence = 0.60 // Uncertain for middle range
	}

	heuristicSignal.LatencyMs = float64(time.Since(startHeuristic).Microseconds()) / 1000.0
	aggregator.AddSignal(heuristicSignal)

	result.HeuristicScore = heuristicSignal.Score
	result.HeuristicLatencyMs = heuristicSignal.LatencyMs

	// v4.11: Save raw heuristic score BEFORE any modifiers
	// This is used for BERT escalation decision - if raw score was high,
	// we should escalate to BERT even if modifiers reduce it
	rawHeuristicScore := result.HeuristicScore

	// Check for secrets (TIER 0: Absolute rule)
	// v4.8: Skip secrets blocking for log/code contexts where IPs and emails are expected
	_, result.SecretsFound = hd.heuristic.RedactSecrets(text)
	if result.SecretsFound {
		// Check structural context FIRST - logs, code, emails often contain IPs/emails legitimately
		structCtx := DetectStructuralContext(text)
		// v4.10: Added email, documentation, and config contexts - these legitimately contain
		// email addresses, API keys in examples, etc.
		isTrustedContext := structCtx.Type == StructuralContextLogFormat ||
			structCtx.Type == StructuralContextCodeBlock ||
			structCtx.Type == StructuralContextTestCode ||
			structCtx.Type == StructuralContextEmail ||
			structCtx.Type == StructuralContextDocumentation ||
			structCtx.Type == StructuralContextConfig ||
			structCtx.Type == StructuralContextJSON ||
			structCtx.Type == StructuralContextLegal || // v4.11: Legal documents
			structCtx.Type == StructuralContextInvoice // v4.12: Invoices/receipts

		if isTrustedContext {
			// Don't block for secrets in trusted context - continue detection normally
			heuristicSignal.SetMetadata("secrets_found_in_context", true)
			heuristicSignal.SetMetadata("structural_context", string(structCtx.Type))
			// Don't return - let normal detection flow continue
		} else {
			// Real secrets in non-trusted context - block immediately
			heuristicSignal.SetMetadata("secrets_found", true)
			result.CombinedScore = 1.0
			result.RiskLevel = "CRITICAL"
			result.Action = "BLOCK"
			result.FastPath = true
			result.DecisionPath = "TIER_0_SECRETS"
			result.Signals = aggregator.signals
			result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
			return result, nil
		}
	}

	// =======================================================================
	// CONTEXT DETECTION: Reduce FP for educational/defensive content
	// v5.1: Skip context discounting entirely for static content scans.
	// Static content (documents, images, PDFs) is not conversational - if it
	// contains attack patterns embedded in "educational" language, flag it.
	// =======================================================================
	ctxResult := DetectContext(text)
	contextDetected := ctxResult.IsEducational || ctxResult.IsDefensive || ctxResult.IsCodeReview
	isStaticScan := isStaticContent(opts.ContentType)

	if contextDetected && !isStaticScan {
		contextSignal := NewDetectionSignal(SignalSourceContext)
		contextSignal.Score = 0.1 // Low score indicates safe
		contextSignal.Confidence = ctxResult.Confidence
		contextSignal.Label = "SAFE"
		if ctxResult.IsEducational {
			contextSignal.AddReason("Educational context detected")
		} else if ctxResult.IsDefensive {
			contextSignal.AddReason("Defensive/security context detected")
		} else if ctxResult.IsCodeReview {
			contextSignal.AddReason("Code review context detected")
		}
		aggregator.AddSignal(contextSignal)
	}

	// Apply context modifier to heuristic score if appropriate
	// v5.0: Skip context modifier for VERY high scores (>=0.9) - these are pattern-matched attacks
	// v5.1: Skip context modifier for static content - no conversational context to consider
	// v5.2: CRITICAL FIX - Use rawHeuristicScore and lower threshold to 0.80.
	// Attack patterns like "ignore all instructions" return 0.85, which is < 0.9 but should NOT
	// be discounted just because they're wrapped in "educational" framing. If the raw heuristic
	// detected attack patterns (score >= 0.80), skip ALL discounting.
	attackPatternsDetected := rawHeuristicScore >= 0.80
	if result.HeuristicScore > 0.1 && !attackPatternsDetected && contextDetected && !isStaticScan {
		modifiedScore := ApplyContextModifier(result.HeuristicScore, ctxResult)
		if modifiedScore != result.HeuristicScore {
			result.HeuristicScore = modifiedScore
			if ctxResult.IsEducational {
				result.Reason = "Educational context detected"
			} else if ctxResult.IsDefensive {
				result.Reason = "Defensive/security context detected"
			} else if ctxResult.IsCodeReview {
				result.Reason = "Code review context detected"
			} else if ctxResult.IsLogContext {
				result.Reason = "Log message context detected"
			}
		}
	}

	// =======================================================================
	// DOMAIN CONTEXT DETECTION (v4.7 Enhancement)
	// Reduces FP for technical domains: "ignore" in git, "override" in CSS, etc.
	// v5.0: Skip for very high scores (>=0.9) - pattern-matched attacks
	// v5.1: Skip for static content - no domain context applies
	// v5.2: Skip if attack patterns detected (rawHeuristicScore >= 0.80)
	// =======================================================================
	if result.HeuristicScore > 0.1 && !attackPatternsDetected && !isStaticScan {
		domainResult := DetectDomainWithConfidence(text)
		if domainResult.Domain != DomainUnknown && domainResult.Confidence >= 0.5 {
			// Get keywords that actually matched from the configured scorer weights
			// This ensures we only apply domain discounts for keywords that contributed to the score
			matchedKeywords := GetMatchedScorerKeywords(text)

			if len(matchedKeywords) > 0 {
				domainModifiedScore := ApplyDomainModifier(result.HeuristicScore, text, matchedKeywords)
				if domainModifiedScore != result.HeuristicScore {
					result.HeuristicScore = domainModifiedScore
					result.Reason = fmt.Sprintf("Technical domain (%s) context detected", domainResult.Domain)
				}
			}
		}
	}

	// =======================================================================
	// BENIGN PHRASE ALLOWLIST (v4.7 Enhancement)
	// Applies negative weights from scorer_weights.yaml benign_patterns section
	// v5.0: Skip for very high scores (>=0.9) - pattern-matched attacks
	// v5.1: Skip for static content - benign phrases don't apply to documents
	// v5.2: Skip if attack patterns detected (rawHeuristicScore >= 0.80)
	// =======================================================================
	if result.HeuristicScore > 0.1 && !attackPatternsDetected && !isStaticScan {
		discount, benignMatches := ApplyBenignPatternDiscount(text)
		if discount < 0 && len(benignMatches) > 0 {
			// Apply discount (discount is negative, so this reduces score)
			adjustedScore := result.HeuristicScore + discount
			if adjustedScore < 0 {
				adjustedScore = 0
			}
			if adjustedScore != result.HeuristicScore {
				result.HeuristicScore = adjustedScore
				if result.Reason == "" {
					result.Reason = fmt.Sprintf("Benign pattern matched: %s", benignMatches[0])
				}
			}
		}
	}

	// =======================================================================
	// v4.10: STRUCTURAL CONTEXT DETECTION AND HEURISTIC DAMPENING
	// Detect once, dampen heuristic score (prevents fast-path false positives),
	// then reuse for CombinedScore dampening (catches semantic boost).
	// =======================================================================
	// v4.10: STRUCTURAL CONTEXT DETECTION (always detect, conditionally dampen)
	// Detect structural context for all inputs, but only apply heuristic dampening
	// if score is above threshold. This ensures we can reuse context for semantic dampening.
	//
	// v4.11 SCALABLE FIX: Preserve pre-dampening score for BERT escalation decisions.
	// Instead of hardcoding attack patterns, we let the ML model decide.
	// If heuristic score was HIGH before dampening, we still escalate to BERT
	// even if structural context would normally suppress it.
	// This is scalable because BERT generalizes, patterns don't.
	var structuralCtx *StructuralContextResult
	{
		ctx := DetectStructuralContext(text)
		if ctx.Type != StructuralContextNone && ctx.Confidence >= 0.5 {
			structuralCtx = &ctx
			// Apply dampening to HeuristicScore EARLY (before fast-path checks)
			// Only dampen if score is high enough to matter
			if result.HeuristicScore > 0.15 {
				dampenFactor, minFloor := GetStructuralDampeningFactor(ctx.Type, ctx.Confidence)
				if dampenFactor > 0 {
					originalScore := result.HeuristicScore
					result.HeuristicScore = result.HeuristicScore * (1.0 - dampenFactor)
					if result.HeuristicScore < minFloor {
						result.HeuristicScore = minFloor
					}
					result.Reason = fmt.Sprintf("Structural context (%s): heuristic %.0f%%→%.0f%%",
						ctx.Type, originalScore*100, result.HeuristicScore*100)
				}
			}
		}
	}

	// =======================================================================
	// PURPOSE-BASED INTENT TYPE CLASSIFICATION (Gray Area Handling)
	// This goes beyond basic context detection to understand WHY the user
	// is asking about security topics (educational, creative, professional, etc.)
	// =======================================================================
	hd.mu.RLock()
	intentTypeEnabled := hd.IntentTypeEnabled
	intentTypeClassifier := hd.intentTypeClassifier
	hd.mu.RUnlock()

	// Use the explicitly requested profile name, not the default config
	profileName := profile.Name

	if intentTypeEnabled && intentTypeClassifier != nil {
		startIntentType := time.Now()
		intentTypeResult, err := intentTypeClassifier.Classify(ctx, text)
		result.IntentTypeLatencyMs = float64(time.Since(startIntentType).Microseconds()) / 1000.0

		if err == nil && intentTypeResult != nil {
			result.IntentType = string(intentTypeResult.PrimaryIntent)
			result.IntentConfidence = intentTypeResult.Confidence

			// Auto-select profile based on detected intent if not explicitly set
			if profileName == "" || profileName == "balanced" {
				profileName = IntentTypeToProfile(intentTypeResult.PrimaryIntent)
			}
			result.ProfileUsed = profileName

			// Calculate intent-based discount
			result.IntentDiscount = IntentTypeDiscount(intentTypeResult.PrimaryIntent, intentTypeResult.Confidence)

			// Apply intent discount to heuristic score if significant
			// v4.10: Also skip discount if MCP attack was detected (JSON-based attacks)
			// v5.1: Skip discounting entirely for static content (documents, images, PDFs)
			// v5.2: CRITICAL FIX - Use attackPatternsDetected (rawHeuristicScore >= 0.80)
			// instead of current score. Attack patterns like "ignore all instructions" (0.85)
			// should NEVER be discounted, even if wrapped in "educational" framing.
			isStatic := isStaticContent(opts.ContentType)
			if result.IntentDiscount > 0 && result.HeuristicScore > 0.1 && !attackPatternsDetected && !mcpAttackDetected && !isStatic {
				originalScore := result.HeuristicScore
				result.HeuristicScore = result.HeuristicScore * (1 - result.IntentDiscount)

				// Add signal for intent-based discount
				intentSignal := NewDetectionSignal(SignalSourceContext)
				intentSignal.Label = "INTENT_TYPE"
				intentSignal.Score = result.IntentDiscount
				intentSignal.Confidence = intentTypeResult.Confidence
				intentSignal.AddReason(fmt.Sprintf("Intent: %s (discount: %.0f%%, score: %.2f->%.2f)",
					result.IntentType, result.IntentDiscount*100, originalScore, result.HeuristicScore))
				aggregator.AddSignal(intentSignal)
			} else if attackPatternsDetected && result.IntentDiscount > 0 {
				// v5.2: Log that we skipped the discount for attack patterns
				intentSignal := NewDetectionSignal(SignalSourceContext)
				intentSignal.Label = "INTENT_TYPE_SKIPPED"
				intentSignal.Score = 0 // No discount applied
				intentSignal.Confidence = intentTypeResult.Confidence
				intentSignal.AddReason(fmt.Sprintf("Intent: %s - discount skipped (attack patterns detected, raw=%.2f)",
					result.IntentType, rawHeuristicScore))
				aggregator.AddSignal(intentSignal)
			} else if isStatic && result.IntentDiscount > 0 {
				// v5.1: Log that we skipped the discount for static content
				intentSignal := NewDetectionSignal(SignalSourceContext)
				intentSignal.Label = "INTENT_TYPE_SKIPPED"
				intentSignal.Score = 0 // No discount applied
				intentSignal.Confidence = intentTypeResult.Confidence
				intentSignal.AddReason(fmt.Sprintf("Intent: %s - discount skipped (static content: %s)",
					result.IntentType, opts.ContentType))
				aggregator.AddSignal(intentSignal)
			} else if mcpAttackDetected && result.IntentDiscount > 0 {
				// v4.10: Log that we skipped the discount for MCP attacks
				intentSignal := NewDetectionSignal(SignalSourceContext)
				intentSignal.Label = "INTENT_TYPE_SKIPPED"
				intentSignal.Score = 0 // No discount applied
				intentSignal.Confidence = intentTypeResult.Confidence
				intentSignal.AddReason(fmt.Sprintf("Intent: %s - discount skipped (MCP attack pattern: %s)",
					result.IntentType, mcpAttackType))
				aggregator.AddSignal(intentSignal)
			}

			// CRITICAL FIX: Boost score when ATTACK intent detected
			// Visual injection and other attacks may have low heuristic scores
			// but if intent classifier says ATTACK, we should boost the score
			// Using aggressive boost because ATTACK detection is high-signal
			// v4.10: SKIP boost if structural context was detected - trust structural signals
			structuralContextDetected := structuralCtx != nil
			if result.IntentType == "ATTACK" && intentTypeResult.Confidence >= 0.35 && !structuralContextDetected {
				// Minimum 0.50 boost, scaled up to 0.80 based on confidence
				attackBoost := 0.50 + (0.30 * intentTypeResult.Confidence)
				originalScore := result.HeuristicScore
				// Use configurable cap (default 0.90 allows triggering CRITICAL risk level)
				hd.mu.RLock()
				scoreCap := hd.AttackIntentScoreCap
				if scoreCap == 0 {
					scoreCap = 0.90 // Fallback default
				}
				hd.mu.RUnlock()
				result.HeuristicScore = math.Min(result.HeuristicScore+attackBoost, scoreCap)

				attackSignal := NewDetectionSignal(SignalSourceContext)
				attackSignal.Label = "ATTACK_INTENT_BOOST"
				attackSignal.Score = attackBoost
				attackSignal.Confidence = intentTypeResult.Confidence
				attackSignal.AddReason(fmt.Sprintf("ATTACK intent detected (%.0f%% conf) - boosting score %.2f->%.2f",
					intentTypeResult.Confidence*100, originalScore, result.HeuristicScore))
				aggregator.AddSignal(attackSignal)
			} else if result.IntentType == "ATTACK" && structuralContextDetected {
				// Log that we skipped the boost due to structural context
				skipSignal := NewDetectionSignal(SignalSourceContext)
				skipSignal.Label = "ATTACK_BOOST_SKIPPED"
				skipSignal.Score = 0
				skipSignal.Confidence = 0.85
				skipSignal.AddReason(fmt.Sprintf("ATTACK intent detected but skipped boost: structural context (%s) indicates benign",
					structuralCtx.Type))
				aggregator.AddSignal(skipSignal)
			}
		}
	}

	// =======================================================================
	// FAST-PATH: Go-only for obvious cases (skip LLM)
	// KEY CHANGE: Skip fast-allow if obfuscation detected
	// =======================================================================
	hd.mu.RLock()
	fastPathEnabled := hd.FastPathEnabled
	fastPathThresholds := hd.FastPathThresholds
	hd.mu.RUnlock()

	if fastPathEnabled {
		// Very high heuristic score = obvious attack, block without LLM
		// v5.2 FIX: Skip fast-path block if educational/defensive context detected
		// This allows BERT to make the final call on gray-area content like CTF writeups
		// v5.3 FIX: BUT proceed with fast-path block if attackPatternsDetected (rawScore >= 0.80)
		// This prevents attacks from bypassing detection by embedding attack text in "educational" framing
		if result.HeuristicScore >= fastPathThresholds.HighConfidenceBlock && (!contextDetected || attackPatternsDetected) {
			result.CombinedScore = result.HeuristicScore
			result.RiskLevel = "CRITICAL"
			result.Action = "BLOCK"
			result.FastPath = true
			result.DecisionPath = "FAST_PATH_BLOCK"
			result.Reason = "Fast-path: High-confidence heuristic block"
			result.Signals = aggregator.signals
			result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
			return result, nil
		}

		// Context-aware fast-path (but NOT if obfuscated)
		if !deobResult.WasDeobfuscated && contextDetected && result.HeuristicScore <= 0.20 {
			result.CombinedScore = result.HeuristicScore
			result.RiskLevel = "MINIMAL"
			result.Action = "ALLOW"
			result.FastPath = true
			result.DecisionPath = "FAST_PATH_CONTEXT"
			if result.Reason == "" {
				if ctxResult.IsEducational {
					result.Reason = "Fast-path: Educational context detected"
				} else if ctxResult.IsDefensive {
					result.Reason = "Fast-path: Defensive context detected"
				} else if ctxResult.IsCodeReview {
					result.Reason = "Fast-path: Code review context detected"
				} else {
					result.Reason = "Fast-path: Benign context detected"
				}
			}
			result.Signals = aggregator.signals
			result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
			return result, nil
		}

		// Very low heuristic score = obviously benign, allow without LLM
		// KEY CHANGE: Skip this fast-path if obfuscation detected OR ATTACK intent detected
		attackIntentDetected := result.IntentType == "ATTACK"
		if result.HeuristicScore <= fastPathThresholds.HighConfidenceAllow && !deobResult.WasDeobfuscated && !attackIntentDetected {
			result.CombinedScore = result.HeuristicScore
			result.RiskLevel = "MINIMAL"
			result.Action = "ALLOW"
			result.FastPath = true
			result.DecisionPath = "FAST_PATH_ALLOW"
			result.Reason = "Fast-path: High-confidence heuristic allow"
			result.Signals = aggregator.signals
			result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
			return result, nil
		}
	}

	// =======================================================================
	// HUGOT ML LAYER: Local Intent Classification (Fast, No API Cost)
	// Runs Sentinel model via ONNX - ~38ms inference, 93.86% F1 score
	// =======================================================================
	hd.mu.RLock()
	hugotEnabled := hd.HugotEnabled
	hugotWeight := hd.HugotWeight
	hd.mu.RUnlock()

	if hugotEnabled && hd.hugot != nil && hd.hugot.IsReady() {
		startHugot := time.Now()
		hugotResult, err := hd.hugot.ClassifySingle(ctx, text)
		result.HugotLatencyMs = float64(time.Since(startHugot).Milliseconds())

		if err == nil {
			result.HugotResult = &hugotResult

			// Create signal for aggregator
			hugotSignal := NewDetectionSignal(SignalSourceHugot)
			if hugotResult.IsThreat {
				hugotSignal.Score = hugotResult.Confidence
				hugotSignal.Label = "MALICIOUS"
			} else {
				hugotSignal.Score = 1.0 - hugotResult.Confidence // Invert for safe
				hugotSignal.Label = "BENIGN"
			}
			hugotSignal.Confidence = hugotResult.Confidence
			hugotSignal.LatencyMs = result.HugotLatencyMs
			hugotSignal.AddReason(fmt.Sprintf("Hugot: %s (%.2f%%)", hugotResult.Label, hugotResult.Confidence*100))
			aggregator.AddSignal(hugotSignal)

			// HIGH CONFIDENCE HUGOT DECISIONS (Fast-path with ML)
			// Block with high confidence jailbreak detection
			if hugotResult.IsThreat && hugotResult.Confidence >= 0.90 {
				result.CombinedScore = hugotResult.Confidence
				result.RiskLevel = "CRITICAL"
				result.Action = "BLOCK"
				result.FastPath = true
				result.DecisionPath = "HUGOT_HIGH_CONFIDENCE_BLOCK"
				result.Reason = fmt.Sprintf("Hugot ML: High-confidence jailbreak (%.1f%%)", hugotResult.Confidence*100)
				result.Signals = aggregator.signals
				result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
				return result, nil
			}

			// Allow with high confidence benign + low heuristic + no obfuscation
			if !hugotResult.IsThreat && hugotResult.Confidence >= 0.95 &&
				result.HeuristicScore <= 0.15 && !deobResult.WasDeobfuscated {
				result.CombinedScore = 0.05
				result.RiskLevel = "MINIMAL"
				result.Action = "ALLOW"
				result.FastPath = true
				result.DecisionPath = "HUGOT_HIGH_CONFIDENCE_ALLOW"
				result.Reason = fmt.Sprintf("Hugot ML: High-confidence benign (%.1f%%)", hugotResult.Confidence*100)
				result.Signals = aggregator.signals
				result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
				return result, nil
			}

			// MEDIUM CONFIDENCE: Adjust combined score
			// Hugot provides strong signal for intent - weight it heavily
			if hugotResult.IsThreat && hugotResult.Confidence >= 0.70 {
				// Boost heuristic score based on Hugot threat confidence
				boostedScore := result.HeuristicScore + (hugotWeight * hugotResult.Confidence * 0.5)
				if boostedScore > result.HeuristicScore {
					result.HeuristicScore = math.Min(boostedScore, 1.0)
				}
			} else if !hugotResult.IsThreat && hugotResult.Confidence >= 0.80 {
				// Reduce heuristic score if Hugot is confident it's benign
				// But only if heuristic isn't extremely high
				if result.HeuristicScore < 0.7 {
					reducedScore := result.HeuristicScore * (1.0 - (hugotWeight * hugotResult.Confidence * 0.3))
					result.HeuristicScore = math.Max(reducedScore, 0.0)
				}
			}

			// UNCERTAIN ZONE: Hugot says threat but low confidence (0.5-0.7)
			// This triggers "ASK USER" flow
			if hugotResult.IsThreat && hugotResult.Confidence >= 0.50 && hugotResult.Confidence < 0.70 {
				// Don't block outright, but mark for user decision
				result.DecisionPath = "HUGOT_UNCERTAIN_ESCALATE"
			}
		}
	}

	// === TIER 1: LLM Intent Classification (The 2025 Standard) ===
	if llmEnabled && hd.llmClassifier != nil {
		startLLM := time.Now()
		llmResult, err := hd.llmClassifier.ClassifyIntent(ctx, text)
		result.LLMLatencyMs = float64(time.Since(startLLM).Milliseconds())

		if err == nil {
			result.LLMClassification = llmResult
			result.Reason = llmResult.Reason

			// HIGH CONFIDENCE Decision Shortcut
			// If definitively MALICIOUS
			if llmResult.Class == "MALICIOUS" && llmResult.Confidence > 0.8 {
				result.CombinedScore = 1.0
				result.RiskLevel = "CRITICAL"
				result.Action = "BLOCK"
				result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
				return result, nil
			}

			// If definitively BENIGN
			if llmResult.Class == "BENIGN" && llmResult.Confidence > 0.9 {
				result.CombinedScore = 0.0
				result.RiskLevel = "MINIMAL"
				result.Action = "ALLOW"
				result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
				return result, nil
			}

			// === TIER 2: Task Drift Verification (for Uncertain Cases) ===
			if llmResult.Class == "SUSPICIOUS" || (llmResult.Class == "MALICIOUS" && llmResult.Confidence <= 0.8) {
				driftResult, err := hd.llmClassifier.DetectTaskDrift(ctx, text)
				if err == nil {
					result.TaskDrift = driftResult
					result.LLMLatencyMs += driftResult.LatencyMs

					if driftResult.TaskConflict {
						result.CombinedScore = 0.95
						result.RiskLevel = "HIGH"
						result.Action = "BLOCK"
						result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
						return result, nil
					}
				}
			}
		}
	}

	// === TIER 3: Semantic + Heuristic Fallback ===
	// If we reach here, either LLM was disabled/failed, or it was uncertain (and Drift check passed/failed)

	// Semantic Similarity (if enabled and ready)
	if semanticEnabled && hd.semantic != nil && hd.semantic.IsReady() {
		startSemantic := time.Now()
		semResult, err := hd.semantic.Detect(ctx, text)
		result.SemanticLatencyMs = float64(time.Since(startSemantic).Microseconds()) / 1000.0

		if err == nil && semResult != nil {
			result.SemanticScore = semResult.Score
			result.SemanticCategory = semResult.Category
			result.SemanticLanguage = semResult.Language
			result.SemanticMatch = semResult.MatchedText
		}
	}

	// === Combine Scores ===
	if semanticEnabled && result.SemanticScore > 0 {
		// Weighted combination
		result.CombinedScore = (result.HeuristicScore * heuristicWeight) +
			(float64(result.SemanticScore) * semanticWeight)
	} else {
		// Heuristic only
		result.CombinedScore = result.HeuristicScore
	}

	// Normalize to 0-1 range
	if result.CombinedScore > 1.0 {
		result.CombinedScore = 1.0
	}

	// =======================================================================
	// v5.4: COMPOUND THREAT DETECTION - Obfuscation + Semantic Attack Pattern
	// When obfuscation is detected AND semantic matching finds a known attack
	// pattern (skeleton_key, injection, etc.), this is highly suspicious.
	// Compound these signals instead of allowing context reduction to water them down.
	// =======================================================================
	semanticAttackPatterns := map[string]bool{
		"skeleton_key":         true,
		"injection":            true,
		"prompt_injection":     true,
		"context_manipulation": true,
		"crescendo_exploit":    true,
		"mcp_injection":        true,
		"command_injection":    true,
		"data_exfiltration":    true,
		"rogue_agent":          true,
		"config_hijacking":     true,
	}
	semanticAttackDetected := semanticAttackPatterns[result.SemanticCategory]

	// If obfuscation + semantic attack pattern detected, compound the threat
	if deobResult.WasDeobfuscated && semanticAttackDetected && result.SemanticScore > 0.5 {
		// This is a compound threat - obfuscated content with attack pattern
		// Boost score and mark as attack pattern to skip context reduction
		attackPatternsDetected = true
		originalScore := result.CombinedScore
		// Apply 1.5x boost, capped at 0.95
		result.CombinedScore = math.Min(result.CombinedScore*1.5, 0.95)
		result.Reason = fmt.Sprintf("Compound threat: obfuscation + %s pattern (%.0f%%→%.0f%%)",
			result.SemanticCategory, originalScore*100, result.CombinedScore*100)
		log.Printf("[COMPOUND] Obfuscation + %s detected: %.2f→%.2f (attack patterns flagged)",
			result.SemanticCategory, originalScore, result.CombinedScore)
	}

	// =======================================================================
	// v4.10: STRUCTURAL CONTEXT - SEMANTIC BOOST DAMPENING
	// If structural context was applied to HeuristicScore, also check if
	// semantic score boosted the combined score back up. If so, dampen
	// the semantic contribution (not double-dampen the heuristic part).
	// v5.4: Skip dampening if attack patterns detected (compound threat or heuristic)
	// =======================================================================
	var structuralContextApplied string
	// v4.10: Lower threshold to 0.30 (start of WARN zone) to catch semantic boost earlier
	// v5.4: Skip if attackPatternsDetected (compound threat already boosted score)
	if structuralCtx != nil && semanticEnabled && result.SemanticScore > 0 && result.CombinedScore > 0.30 && !attackPatternsDetected {
		// Semantic score boosted us back up - dampen only the semantic contribution
		// Use a softer dampening since heuristic is already dampened
		softDampen := 0.7 // Keep 70% of semantic contribution
		originalScore := result.CombinedScore
		// Recalculate with dampened semantic
		dampenedSemantic := float64(result.SemanticScore) * softDampen
		result.CombinedScore = (result.HeuristicScore * heuristicWeight) + (dampenedSemantic * semanticWeight)
		if result.CombinedScore != originalScore {
			structuralContextApplied = string(structuralCtx.Type)
			result.Reason = fmt.Sprintf("Structural context (%s): semantic dampened %.0f%%→%.0f%%",
				structuralCtx.Type, originalScore*100, result.CombinedScore*100)
		}
	} else if structuralCtx != nil && result.CombinedScore > 0.30 && !attackPatternsDetected {
		// v4.10: Even without semantic, if CombinedScore is still high, apply dampening
		// This catches cases where heuristic dampening wasn't applied or was insufficient
		// v5.4: Skip if attackPatternsDetected (compound threat already boosted score)
		dampenFactor, minFloor := GetStructuralDampeningFactor(structuralCtx.Type, structuralCtx.Confidence)
		if dampenFactor > 0 {
			originalScore := result.CombinedScore
			result.CombinedScore = result.CombinedScore * (1.0 - dampenFactor)
			if result.CombinedScore < minFloor {
				result.CombinedScore = minFloor
			}
			structuralContextApplied = string(structuralCtx.Type)
			result.Reason = fmt.Sprintf("Structural context (%s): combined %.0f%%→%.0f%%",
				structuralCtx.Type, originalScore*100, result.CombinedScore*100)
		}
	} else if structuralCtx != nil {
		// Track that structural context was detected even if no dampening applied
		structuralContextApplied = string(structuralCtx.Type)
	}

	// === CONTEXT-AWARE SCORE REDUCTION ===
	// Apply context modifier to combined score for educational/defensive content
	// This catches cases where semantic similarity flags educational examples
	// v5.3: Skip this reduction if attack patterns were detected (rawHeuristicScore >= 0.80)
	// This prevents attacks like "ignore your safety guidelines" from being discounted
	// just because they're wrapped in educational framing
	if contextDetected && !attackPatternsDetected {
		// Educational content with attack examples should get reduced even after
		// semantic matching. Use a softer reduction since we're modifying final score.
		if ctxResult.IsEducational && ctxResult.Confidence >= 0.7 {
			// Strong educational signal - apply reduction to combined score
			originalCombined := result.CombinedScore
			// For very high scores (0.9+), still allow reduction but be more conservative
			// This handles tutorials that contain literal attack examples
			// v5.0: Also check for benign pattern matches - if many match, reduce more aggressively
			_, benignMatches := ApplyBenignPatternDiscount(text)
			hasManyBenignMatches := len(benignMatches) >= 3
			if result.CombinedScore >= 0.9 {
				// Very high score but educational
				// v5.0: If many benign patterns match, reduce more aggressively to ALLOW range
				if hasManyBenignMatches {
					result.CombinedScore *= 0.35 // Reduce to ~31.5% (ALLOW)
				} else {
					result.CombinedScore *= 0.45 // Reduce to ~40.5% (WARN)
				}
				result.Reason = fmt.Sprintf("Educational context (high score): %.0f%%→%.0f%%",
					originalCombined*100, result.CombinedScore*100)
			} else if result.CombinedScore >= 0.4 {
				// Middle range: apply 40% reduction for high-confidence educational content
				result.CombinedScore *= 0.6
				result.Reason = fmt.Sprintf("Educational context detected (conf=%.1f): %.0f%%→%.0f%%",
					ctxResult.Confidence, originalCombined*100, result.CombinedScore*100)
			}
		} else if ctxResult.IsDefensive && ctxResult.Confidence >= 0.7 {
			// Defensive context (security tools, protection discussion)
			originalCombined := result.CombinedScore
			if result.CombinedScore >= 0.4 {
				// More aggressive reduction for defensive content
				reduction := 0.7
				if result.CombinedScore >= 0.9 {
					reduction = 0.5 // Stronger reduction for high scores
				}
				result.CombinedScore *= reduction
				result.Reason = fmt.Sprintf("Defensive context detected: %.0f%%→%.0f%%",
					originalCombined*100, result.CombinedScore*100)
			}
		}
	}

	// =======================================================================
	// TIER 2.5: TRANSFORMER INTENT CLASSIFICATION (BERT)
	// KEY CHANGE: Pass deobfuscated text to BERT for analysis
	// =======================================================================
	intentDecisionMade := false

	// Force BERT escalation if:
	// 1. Score is in ambiguous range (0.3-0.7), OR
	// 2. Obfuscation was detected (BERT must see decoded text), OR
	// 3. Purpose-based classifier detected ATTACK intent (needs BERT confirmation)
	// 4. NEW: Request is substantive (> 8 words) - catches semantic threats that bypass heuristics
	// 5. NEW: Contains action/request language (help, how to, create, make, etc.)
	isSubstantiveRequest := isSubstantiveText(text)

	// v4.11: Also escalate if RAW heuristic (before ANY modifiers) was high.
	// This is the SCALABLE fix - context/domain/benign/structural modifiers
	// may all reduce the score, but if the raw heuristic saw a strong attack
	// signal, we should escalate to BERT and let ML decide.
	// BERT generalizes; pattern lists don't.
	rawScoreWasHigh := rawHeuristicScore >= 0.5

	// v5.3: Widened from 0.3-0.7 to 0.2-0.8 to catch more edge cases
	shouldEscalateToBERT := (result.CombinedScore >= 0.2 && result.CombinedScore <= 0.8) ||
		deobResult.WasDeobfuscated ||
		result.IntentType == "ATTACK" ||
		isSubstantiveRequest || // NEW: Always check substantive requests with BERT
		rawScoreWasHigh || // v4.11: Raw heuristic was high - let BERT decide
		!hd.FastPathEnabled // Force BERT if FastPath is explicitly disabled

	if intentEnabled && hd.intentClient != nil && shouldEscalateToBERT {
		startIntent := time.Now()

		// KEY CHANGE: Pass deobfuscation context to BERT
		intentResult, err := hd.intentClient.ClassifyIntentWithContext(ctx, text, &deobResult)
		result.IntentLatencyMs = float64(time.Since(startIntent).Milliseconds())

		if err == nil && intentResult != nil {
			result.IntentResult = intentResult

			// Create BERT signal for aggregator
			bertSignal := NewDetectionSignal(SignalSourceBERT)
			bertSignal.Label = intentResult.Label
			bertSignal.Confidence = intentResult.Confidence
			bertSignal.LatencyMs = result.IntentLatencyMs
			bertSignal.WasDeobfuscated = intentResult.WasDeobfuscated
			bertSignal.AnalyzedText = intentResult.AnalyzedText

			if intentResult.Label == "INJECTION" {
				bertSignal.Score = intentResult.Confidence
			} else {
				bertSignal.Score = 1.0 - intentResult.Confidence // Invert for safe
			}

			aggregator.AddSignal(bertSignal)

			// High-confidence INJECTION → BLOCK immediately
			// BERT v4.6+ has been trained on adversarial examples that use educational/context
			// framing as a jailbreak technique. When BERT is >95% confident, trust it.
			// For 85-95% confidence with context, still block but mark the path differently.
			//
			// v4.8 Enhancement: Check for STRUCTURAL context (code blocks, logs, docs, tests)
			// that indicates meta-discussion about attacks rather than actual attacks.
			// Structural context can dampen BERT's confidence to reduce false positives.
			effectiveBERTConfidence := intentResult.Confidence
			structuralContextReason := ""
			if intentResult.Label == "INJECTION" && intentResult.Confidence > 0.85 {
				// Check if structural context suggests this is meta-discussion
				shouldDampen, dampenedConf, scReason := ShouldDampenBERTDecision(text, intentResult.Label, intentResult.Confidence)
				if shouldDampen {
					effectiveBERTConfidence = dampenedConf
					structuralContextReason = scReason

					// Add signal for structural context dampening
					scSignal := NewDetectionSignal(SignalSourceContext)
					scSignal.Label = "STRUCTURAL_CONTEXT"
					scSignal.Score = 1.0 - dampenedConf // Low score = safe
					scSignal.Confidence = 0.85
					scSignal.AddReason(fmt.Sprintf("Structural context (%s): BERT %.0f%%→%.0f%%",
						scReason, intentResult.Confidence*100, effectiveBERTConfidence*100))
					aggregator.AddSignal(scSignal)
				}
			}

			if intentResult.Label == "INJECTION" && effectiveBERTConfidence > 0.95 {
				// Very high confidence (>95%) after dampening: BLOCK regardless of context
				// This catches adversarial prompts that weaponize educational framing
				result.CombinedScore = 0.95
				result.RiskLevel = "HIGH"
				result.Action = "BLOCK"
				result.DecisionPath = "BERT_HIGH_CONFIDENCE_BLOCK"
				if structuralContextReason != "" {
					result.Reason = fmt.Sprintf("Intent Classifier (%s): INJECTION (%.1f%% → %.1f%% after %s)",
						intentResult.Model, intentResult.Confidence*100, effectiveBERTConfidence*100, structuralContextReason)
				} else {
					result.Reason = fmt.Sprintf("Intent Classifier (%s): INJECTION (%.1f%% confidence)",
						intentResult.Model, intentResult.Confidence*100)
				}
				result.Signals = aggregator.signals
				result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
				return result, nil
			} else if intentResult.Label == "INJECTION" && effectiveBERTConfidence > 0.85 && !contextDetected {
				// High confidence (85-95%) without keyword context: BLOCK
				result.CombinedScore = 0.95
				result.RiskLevel = "HIGH"
				result.Action = "BLOCK"
				result.DecisionPath = "BERT_HIGH_CONFIDENCE_BLOCK"
				if structuralContextReason != "" {
					result.Reason = fmt.Sprintf("Intent Classifier (%s): INJECTION (%.1f%% → %.1f%% after %s)",
						intentResult.Model, intentResult.Confidence*100, effectiveBERTConfidence*100, structuralContextReason)
				} else {
					result.Reason = fmt.Sprintf("Intent Classifier (%s): INJECTION (%.1f%% confidence)",
						intentResult.Model, intentResult.Confidence*100)
				}
				result.Signals = aggregator.signals
				result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
				return result, nil
			} else if intentResult.Label == "INJECTION" && effectiveBERTConfidence > 0.70 && effectiveBERTConfidence <= 0.85 && structuralContextReason != "" {
				// v4.8: BERT was dampened below 85% by structural context
				// Don't block immediately - let it flow through to weighted scoring
				// This allows meta-discussions about attacks to pass through
				result.Reason = fmt.Sprintf("Structural context (%s): BERT dampened %.0f%%→%.0f%%, allowing weighted scoring",
					structuralContextReason, intentResult.Confidence*100, effectiveBERTConfidence*100)
				// Continue to weighted scoring below...
			}

			// ===================================================================
			// BI-DIRECTIONAL FLOW: Check if BERT is uncertain
			// If BERT has low confidence, trigger deeper Go analysis
			// ===================================================================
			if intentResult.Confidence < 0.70 {
				// Case 1: Obfuscation detected but BERT says SAFE - distrust BERT
				if deobResult.WasDeobfuscated && intentResult.Label == "SAFE" {
					result.BidirectionalFlow = true
					deeperSignal := hd.runDeeperGoAnalysis(ctx, text, &deobResult, result.HeuristicScore)
					aggregator.AddSignal(deeperSignal)

					if deeperSignal.Score >= 0.6 {
						// Deeper Go analysis found something BERT missed
						result.CombinedScore = deeperSignal.Score
						result.RiskLevel = "HIGH"
						result.Action = "BLOCK"
						result.DecisionPath = "BIDIRECTIONAL_GO_VETO"
						result.Reason = fmt.Sprintf("Obfuscation veto: BERT said SAFE but Go found %s",
							strings.Join(deeperSignal.Reasons, ", "))
						result.Signals = aggregator.signals
						result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
						return result, nil
					}
				}

				// Case 2: BERT says INJECTION but low confidence + obfuscation = boost
				if deobResult.WasDeobfuscated && intentResult.Label == "INJECTION" {
					// Both agree on injection + obfuscation = high confidence
					boostedScore := (result.HeuristicScore + intentResult.Confidence) / 2 * 1.3
					if boostedScore > 1.0 {
						boostedScore = 1.0
					}
					result.CombinedScore = boostedScore
					result.RiskLevel = "HIGH"
					result.Action = "BLOCK"
					result.DecisionPath = "BIDIRECTIONAL_AGREEMENT_BOOST"
					result.Reason = fmt.Sprintf("Obfuscation + BERT injection (%.0f%% conf): boosted to %.0f%%",
						intentResult.Confidence*100, boostedScore*100)
					result.Signals = aggregator.signals
					result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
					return result, nil
				}

			}

			// High-confidence SAFE → ALLOW (skip Safeguard escalation)
			// But NOT if obfuscation was detected - obfuscation is a red flag
			if intentResult.Label == "SAFE" && intentResult.Confidence > 0.90 && !deobResult.WasDeobfuscated {
				result.CombinedScore = 0.15
				result.RiskLevel = "MINIMAL"
				result.Action = "ALLOW"
				result.DecisionPath = "BERT_HIGH_CONFIDENCE_ALLOW"
				result.Reason = fmt.Sprintf("Intent Classifier (%s): SAFE (%.1f%% confidence)",
					intentResult.Model, intentResult.Confidence*100)
				intentDecisionMade = true
				// Don't return - let it flow through to final action assignment
			}

			// Medium confidence adjustments (Safeguard will still be consulted if enabled)
			// v4.8: Use effectiveBERTConfidence (after structural dampening) for weighted scoring
			if !intentDecisionMade {
				// Use effective confidence (dampened by structural context if applicable)
				useBERTConf := effectiveBERTConfidence

				if intentResult.Label == "INJECTION" && useBERTConf > 0.70 {
					// v4.10: If structural context was applied to CombinedScore OR
					// dampened BERT significantly (>25% reduction), don't apply BERT boost
					bertDampenedSignificantly := structuralContextReason != "" &&
						(intentResult.Confidence-useBERTConf) > intentResult.Confidence*0.25
					combinedScoreDampened := structuralContextApplied != ""
					wasDampenedSignificantly := bertDampenedSignificantly || combinedScoreDampened

					if !wasDampenedSignificantly {
						// Boost score toward block threshold
						// Use BERT confidence to weight the boost: higher confidence = stronger push to BLOCK
						bertWeight := 0.6 + (useBERTConf-0.70)*0.8 // 0.6-0.84 based on confidence
						if bertWeight > 0.85 {
							bertWeight = 0.85
						}
						if bertWeight < 0.4 {
							bertWeight = 0.4 // Minimum weight for BERT signal
						}
						result.CombinedScore = result.CombinedScore*(1-bertWeight) + useBERTConf*bertWeight
						result.Reason = fmt.Sprintf("Intent Classifier: Likely injection (%.1f%%)", useBERTConf*100)
					} else {
						// Structural context dampening was applied - trust it over BERT
						// Keep the combined score as-is (already reflects heuristic + dampening)
						ctxInfo := structuralContextReason
						if ctxInfo == "" {
							ctxInfo = structuralContextApplied
						}
						result.Reason = fmt.Sprintf("Intent Classifier: Structural context override (%.1f%% → %.1f%% after %s)",
							intentResult.Confidence*100, useBERTConf*100, ctxInfo)
					}
				} else if intentResult.Label == "SAFE" && intentResult.Confidence > 0.75 {
					// v4.10: Do NOT reduce score if MCP attack patterns were detected
					// BERT may misclassify JSON-based attacks as SAFE because the
					// attack payload is embedded in JSON structure
					if mcpAttackDetected {
						// Keep the MCP-boosted score - don't let BERT override
						result.Reason = fmt.Sprintf("MCP attack pattern (%s) preserved despite BERT SAFE (%.1f%%)",
							mcpAttackType, intentResult.Confidence*100)
					} else {
						// Reduce score based on BERT confidence
						// Higher BERT SAFE confidence = stronger reduction
						// At 96% conf: 0.999 * (1 - 0.96*0.85) = 0.999 * 0.184 = 0.18
						originalScore := result.CombinedScore
						safetyFactor := 1.0 - (intentResult.Confidence * 0.85)
						result.CombinedScore = result.CombinedScore * safetyFactor
						result.Reason = fmt.Sprintf("Intent Classifier: Likely safe (%.1f%%), score %.2f→%.2f",
							intentResult.Confidence*100, originalScore, result.CombinedScore)
					}
				}
			}
		}
	}

	// === TIER 3: ESCALATION (The "Reasoning" Layer) ===
	// If score is STILL AMBIGUOUS (0.4 - 0.7) and Safeguard is enabled, call the safeguard model
	// Skip if intent classifier already made a high-confidence decision
	if !intentDecisionMade && safeguardEnabled && result.CombinedScore >= 0.4 && result.CombinedScore <= 0.7 {
		startSafeguard := time.Now()
		isSafe, reason, err := hd.safeguardJudge.EvaluateContent(ctx, text)
		result.TotalLatencyMs += float64(time.Since(startSafeguard).Milliseconds()) // Add blocking latency

		if err == nil {
			if !isSafe {
				// Judge ruled UNSAFE
				result.CombinedScore = 0.95 // Override to Block
				result.Reason = "Safeguard Model: " + reason
				result.RiskLevel = "HIGH"
				result.Action = "BLOCK"
				// Return immediately
				result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0
				return result, nil
			} else {
				// Judge ruled SAFE - Reduce score significantly
				result.CombinedScore = 0.2 // Override to Minimal/Low
				result.Reason = "Safeguard Model: Ruled Safe"
			}
		} else {
			// Log error to reason for debugging
			result.Reason = fmt.Sprintf("Safeguard Error: %v", err)
		}
	}

	// === Determine Risk Level and Action ===
	// Threshold adjusted: WARN starts at 0.4 (was 0.3) to reduce false positives
	// from semantic similarity on benign requests like "help me debug"
	//
	// v5.5: MODE-AWARE THRESHOLDS
	// "secure" mode uses lower BLOCK threshold (55%) for more aggressive protection
	// "fast" mode uses standard threshold (70%) for fewer false positives
	blockThreshold := 0.70 // Standard threshold
	warnThreshold := 0.40  // Standard warn threshold
	if opts.Mode == DetectionModeSecure {
		blockThreshold = 0.55 // More aggressive for secure mode
		warnThreshold = 0.35
	}

	switch {
	case result.CombinedScore >= 0.9:
		result.RiskLevel = "CRITICAL"
		result.Action = "BLOCK"
	case result.CombinedScore >= blockThreshold:
		result.RiskLevel = "HIGH"
		result.Action = "BLOCK"
	case result.CombinedScore >= 0.5:
		result.RiskLevel = "MEDIUM"
		result.Action = "WARN"
	case result.CombinedScore >= warnThreshold:
		result.RiskLevel = "LOW"
		result.Action = "WARN"
	default:
		result.RiskLevel = "MINIMAL"
		result.Action = "ALLOW"
	}

	// Set decision path if not already set
	if result.DecisionPath == "" {
		result.DecisionPath = "AGGREGATED_SCORE"
	}

	// Include all signals in result
	result.Signals = aggregator.signals
	result.TotalLatencyMs = float64(time.Since(startTotal).Microseconds()) / 1000.0

	return result, nil
}

// SetWeights adjusts the balance between heuristic and semantic detection
func (hd *HybridDetector) SetWeights(heuristic, semantic float64) {
	hd.mu.Lock()
	defer hd.mu.Unlock()
	hd.HeuristicWeight = heuristic
	hd.SemanticWeight = semantic
}

// EnableSemantic turns semantic detection on/off
func (hd *HybridDetector) EnableSemantic(enabled bool) {
	hd.mu.Lock()
	defer hd.mu.Unlock()
	hd.SemanticEnabled = enabled && hd.semantic != nil
}

// EnableFastPath turns fast-path detection on/off
func (hd *HybridDetector) EnableFastPath(enabled bool) {
	hd.mu.Lock()
	defer hd.mu.Unlock()
	hd.FastPathEnabled = enabled
}

// EnableIntent turns transformer-based intent classification on/off
func (hd *HybridDetector) EnableIntent(enabled bool) {
	hd.mu.Lock()
	defer hd.mu.Unlock()
	hd.IntentEnabled = enabled && hd.intentClient != nil
}

// EnableIntentType turns purpose-based intent type classification on/off
func (hd *HybridDetector) EnableIntentType(enabled bool) {
	hd.mu.Lock()
	defer hd.mu.Unlock()
	hd.IntentTypeEnabled = enabled && hd.intentTypeClassifier != nil
}

// SetFastPathThresholds configures the fast-path thresholds
func (hd *HybridDetector) SetFastPathThresholds(thresholds FastPathThresholds) {
	hd.mu.Lock()
	defer hd.mu.Unlock()
	hd.FastPathThresholds = thresholds
}

// SetAttackIntentScoreCap configures the maximum score after ATTACK intent boost.
// Default is 0.90, which allows triggering CRITICAL risk level.
// Set to 0.85 to be more conservative (only HIGH risk).
func (hd *HybridDetector) SetAttackIntentScoreCap(cap float64) {
	hd.mu.Lock()
	defer hd.mu.Unlock()
	if cap < 0.5 {
		cap = 0.5 // Minimum cap
	}
	if cap > 1.0 {
		cap = 1.0 // Maximum cap
	}
	hd.AttackIntentScoreCap = cap
}

// GetHeuristic returns the underlying heuristic scorer for direct access
func (hd *HybridDetector) GetHeuristic() *ThreatScorer {
	return hd.heuristic
}

// GetSemantic returns the underlying semantic detector for direct access
func (hd *HybridDetector) GetSemantic() *SemanticDetector {
	return hd.semantic
}

// GetSafeguard returns the safeguard client for direct access (visual drift detection, etc.)
func (hd *HybridDetector) GetSafeguard() *SafeguardClient {
	return hd.safeguardJudge
}

// GetGeminiDrift returns the Gemini drift client for fast visual drift detection
func (hd *HybridDetector) GetGeminiDrift() *GeminiDriftClient {
	return hd.geminiDrift
}

// EnableMultiTurn turns semantic multi-turn detection on/off
func (hd *HybridDetector) EnableMultiTurn(enabled bool) {
	hd.mu.Lock()
	defer hd.mu.Unlock()
	hd.MultiTurnEnabled = enabled && hd.multiTurnDetector != nil
}

// GetMultiTurnDetector returns the underlying multi-turn detector for direct access
func (hd *HybridDetector) GetMultiTurnDetector() *UnifiedMultiTurnDetector {
	return hd.multiTurnDetector
}

// IsMultiTurnEnabled returns whether multi-turn detection is enabled
func (hd *HybridDetector) IsMultiTurnEnabled() bool {
	hd.mu.RLock()
	defer hd.mu.RUnlock()
	return hd.MultiTurnEnabled && hd.multiTurnDetector != nil
}

// isSubstantiveText checks if a text is substantive enough to warrant BERT analysis.
// This catches SECURITY threats (prompt injection, jailbreaks, data exfil) that bypass heuristics.
// NOTE: This is NOT content moderation - domain-specific concerns (money laundering, drugs, etc.)
// should be handled by fine-tuned industry-specific models, not the general security layer.
// Criteria:
// 1. More than 12 words (substantive length for potential attack payloads)
// 2. Contains security-relevant action language (bypass, exploit, inject, etc.)
func isSubstantiveText(text string) bool {
	// Short texts are unlikely to be sophisticated semantic attacks
	// Allow greetings, simple questions, benign requests through fast-path
	words := strings.Fields(text)
	wordCount := len(words)

	// Very short messages can use fast-path (greetings, simple queries)
	if wordCount <= 6 {
		return false
	}

	// Substantive length (> 12 words) - potential attack payload, check with BERT
	if wordCount > 12 {
		return true
	}

	// For medium-length (7-12 words), check for SECURITY-SPECIFIC action language
	// These are indicators of potential prompt injection/jailbreak attempts
	lowerText := strings.ToLower(text)

	// Security-relevant action patterns (prompt injection, jailbreak, data exfil indicators)
	securityPatterns := []string{
		// Evasion/bypass attempts
		"bypass", "evade", "circumvent", "get around", "disable", "ignore",
		"override", "skip", "avoid detection",
		// System manipulation
		"system prompt", "instructions", "you are", "act as", "pretend",
		"roleplay", "jailbreak", "dan mode",
		// Data exfiltration indicators
		"reveal", "expose", "leak", "extract", "dump",
		// Injection patterns
		"inject", "execute", "eval", "run code",
	}
	for _, pattern := range securityPatterns {
		if strings.Contains(lowerText, pattern) {
			return true
		}
	}

	return false
}

// runDeeperGoAnalysis performs enhanced Go-side analysis when BERT is uncertain
// This is the bi-directional feedback loop: when BERT has low confidence,
// Go gets another shot with stricter thresholds
func (hd *HybridDetector) runDeeperGoAnalysis(
	ctx context.Context,
	text string,
	deobResult *DeobfuscationResult,
	initialHeuristicScore float64,
) DetectionSignal {
	signal := NewDetectionSignal(SignalSourceDeeperGo)
	signal.Score = initialHeuristicScore
	signal.Confidence = 0.80 // Deeper analysis = higher confidence

	// Re-run heuristics on decoded text with stricter focus
	if deobResult != nil && deobResult.DecodedText != "" {
		// Score the decoded text
		decodedScore := hd.heuristic.Evaluate(deobResult.DecodedText)
		if decodedScore > signal.Score {
			signal.Score = decodedScore
			signal.AddReason("decoded_text_scored_higher")
		}
	}

	// Check for specific attack patterns that BERT might miss

	// 1. Typoglycemia patterns (scrambled letters)
	if deobResult != nil {
		for _, t := range deobResult.ObfuscationTypes {
			if t == ObfuscationTypoglycemia {
				signal.Score = max(signal.Score, 0.75)
				signal.AddReason("typoglycemia_detected")
			}
		}
	}

	// 2. Unicode tag smuggling
	if deobResult != nil {
		for _, t := range deobResult.ObfuscationTypes {
			if t == ObfuscationUnicodeTags {
				signal.Score = max(signal.Score, 0.80)
				signal.AddReason("unicode_tag_smuggling")
			}
		}
	}

	// 3. Nested encoding (multiple layers of obfuscation)
	if deobResult != nil && len(deobResult.ObfuscationTypes) >= 2 {
		signal.Score = max(signal.Score, 0.70)
		signal.AddReason(fmt.Sprintf("nested_encoding_%d_layers", len(deobResult.ObfuscationTypes)))
	}

	// 4. Semantic similarity with lower threshold (0.5 instead of 0.7)
	if hd.semantic != nil && hd.semantic.IsReady() {
		textToAnalyze := text
		if deobResult != nil && deobResult.DecodedText != "" {
			textToAnalyze = deobResult.DecodedText
		}

		semResult, err := hd.semantic.DetectWithThreshold(ctx, textToAnalyze, 0.5)
		if err == nil && semResult != nil && semResult.Score > float32(signal.Score) {
			signal.Score = float64(semResult.Score)
			signal.Category = semResult.Category
			signal.AddReason(fmt.Sprintf("semantic_match_%s", semResult.Category))
		}
	}

	// 5. Check for instruction override patterns in decoded text
	if deobResult != nil && deobResult.DecodedText != "" {
		if DetectsAttackPatterns(deobResult.DecodedText) {
			signal.Score = max(signal.Score, 0.75)
			signal.AddReason("attack_patterns_in_decoded_text")
		}
	}

	// 6. Dynamic Semantic Detection (fuzzy matching for varied phrasings)
	// This catches attacks that use different words but same semantic intent
	textToCheck := text
	if deobResult != nil && deobResult.DecodedText != "" {
		textToCheck = deobResult.DecodedText
	}
	dynamicDetector := NewDynamicThreatDetector()
	dynamicResult := dynamicDetector.AnalyzeText(textToCheck)
	if dynamicResult.IsLikelyThreat && dynamicResult.FinalScore > signal.Score {
		signal.Score = dynamicResult.FinalScore
		for _, sig := range dynamicResult.Signals {
			signal.AddReason(fmt.Sprintf("dynamic_%s:%.2f", sig.Type, sig.Score))
		}
	}

	// Obfuscation boost: if obfuscation was detected, multiply score
	if deobResult != nil && deobResult.WasDeobfuscated && signal.Score >= 0.4 {
		signal.Score *= 1.3
		if signal.Score > 1.0 {
			signal.Score = 1.0
		}
		signal.AddReason("obfuscation_boost")
	}

	signal.WasDeobfuscated = deobResult != nil && deobResult.WasDeobfuscated
	if deobResult != nil {
		signal.ObfuscationTypes = deobResult.ObfuscationTypes
		signal.DeobfuscatedText = deobResult.DecodedText
	}

	return signal
}

// Close releases any resources held by the detector (e.g., ONNX models)
func (hd *HybridDetector) Close() error {
	hd.mu.Lock()
	defer hd.mu.Unlock()

	var errs []string

	// Close Hugot detector if it exists (OSS local ML)
	if hd.hugot != nil {
		if err := hd.hugot.Close(); err != nil {
			errs = append(errs, fmt.Sprintf("hugot: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %s", strings.Join(errs, "; "))
	}
	return nil
}
