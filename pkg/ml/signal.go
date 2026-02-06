package ml

// SignalSource identifies which detection layer produced a signal
type SignalSource string

const (
	SignalSourceHeuristic SignalSource = "heuristic"
	SignalSourceSemantic  SignalSource = "semantic"
	SignalSourceHugot     SignalSource = "hugot"      // Local ML via Hugot/ONNX (Sentinel model)
	SignalSourceBERT      SignalSource = "bert"       // Transformer intent classifier
	SignalSourceSafeguard SignalSource = "safeguard"  // Groq/OpenAI safeguard model
	SignalSourceLLM       SignalSource = "llm"        // OpenRouter LLM classifier
	SignalSourceDeeperGo  SignalSource = "deeper_go"  // Re-analysis when BERT uncertain
	SignalSourceContext   SignalSource = "context"    // Educational/defensive context
	SignalSourceTaskDrift SignalSource = "task_drift" // Task drift detection
	SignalSourceMultiBERT SignalSource = "multi_bert" // Multi-BERT ensemble (Phase 1+)
)

// ObfuscationType identifies the type of obfuscation detected
type ObfuscationType string

const (
	ObfuscationBase64         ObfuscationType = "base64"
	ObfuscationBase32         ObfuscationType = "base32"
	ObfuscationHex            ObfuscationType = "hex"
	ObfuscationROT13          ObfuscationType = "rot13"
	ObfuscationURL            ObfuscationType = "url"
	ObfuscationHTML           ObfuscationType = "html_entity"
	ObfuscationUnicodeTags    ObfuscationType = "unicode_tags"
	ObfuscationHomoglyphs     ObfuscationType = "homoglyphs"
	ObfuscationReverse        ObfuscationType = "reverse"
	ObfuscationTypoglycemia   ObfuscationType = "typoglycemia"
	ObfuscationGzip           ObfuscationType = "gzip"
	ObfuscationUnicodeEscapes ObfuscationType = "unicode_escapes"
	ObfuscationOctalEscapes   ObfuscationType = "octal_escapes"
	ObfuscationASCIIArt       ObfuscationType = "ascii_art"
	ObfuscationBlockASCII     ObfuscationType = "block_ascii"
	ObfuscationInvisibleChars ObfuscationType = "invisible_chars"
	ObfuscationZeroWidth      ObfuscationType = "zero_width"
	ObfuscationBidiOverride   ObfuscationType = "bidi_override"
	ObfuscationCombiningChars ObfuscationType = "combining_chars"
	ObfuscationLeetspeak      ObfuscationType = "leetspeak"
	ObfuscationEmojiSeparator ObfuscationType = "emoji_separator"
)

// DetectionSignal represents a detection result from a single layer
// This is the universal signal format that all detection layers produce
type DetectionSignal struct {
	// Source identifies which detection layer produced this signal
	Source SignalSource `json:"source"`

	// Score is the raw threat score (0.0 = safe, 1.0 = definitely malicious)
	Score float64 `json:"score"`

	// Confidence indicates how confident the layer is in its score (0.0 - 1.0)
	// High confidence = trust this score more in aggregation
	Confidence float64 `json:"confidence"`

	// Weight is the configurable weight for this layer in aggregation
	// Default weights: Heuristic=0.4, Semantic=0.6, BERT=0.8, Safeguard=0.9
	Weight float64 `json:"weight"`

	// Label is the classification label (e.g., "INJECTION", "SAFE", "SUSPICIOUS")
	Label string `json:"label,omitempty"`

	// Category is the threat category (e.g., "instruction_override", "data_exfiltration")
	Category string `json:"category,omitempty"`

	// Reasons provides human-readable explanations for the score
	Reasons []string `json:"reasons,omitempty"`

	// WasDeobfuscated indicates if obfuscation was detected and decoded
	WasDeobfuscated bool `json:"was_deobfuscated"`

	// DeobfuscatedText is the decoded content (for passing to BERT)
	DeobfuscatedText string `json:"deobfuscated_text,omitempty"`

	// ObfuscationTypes lists what obfuscation techniques were detected
	ObfuscationTypes []ObfuscationType `json:"obfuscation_types,omitempty"`

	// AnalyzedText is the text that was actually analyzed (may differ from input)
	AnalyzedText string `json:"analyzed_text,omitempty"`

	// Latency is the time taken for this layer in milliseconds
	LatencyMs float64 `json:"latency_ms"`

	// Metadata allows layers to pass extra information
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// DeobfuscationResult contains the result of running all decoders
type DeobfuscationResult struct {
	// OriginalText is the input text before any decoding
	OriginalText string `json:"original_text"`

	// DecodedText is the fully decoded text (all decoders applied)
	DecodedText string `json:"decoded_text"`

	// WasDeobfuscated is true if any decoder produced output
	WasDeobfuscated bool `json:"was_deobfuscated"`

	// ObfuscationTypes lists which decoders produced output
	ObfuscationTypes []ObfuscationType `json:"obfuscation_types"`

	// DecodedSegments maps decoder type to the text it decoded
	DecodedSegments map[ObfuscationType]string `json:"decoded_segments,omitempty"`

	// v4.7 Enhancement: Layer depth tracking for score boosting
	// Multi-layer encoding (e.g., base64(hex(rot13(payload)))) is highly suspicious

	// LayerCount is how many encoding layers were decoded (max depth reached)
	// Triple-encoded content (LayerCount=3) gets 1.3x score boost
	LayerCount int `json:"layer_count"`

	// LayerSequence records the encoding types in order from outer to inner
	// e.g., ["base64", "hex", "rot13"] for base64(hex(rot13(payload)))
	LayerSequence []ObfuscationType `json:"layer_sequence,omitempty"`
}

// ScoreMultiplier returns a multiplier based on obfuscation depth
// Single layer: 1.0x, Double: 1.1x, Triple: 1.3x, Quad+: 1.5x
// Rationale: Multi-layer encoding is a strong indicator of attack obfuscation
func (r *DeobfuscationResult) ScoreMultiplier() float64 {
	if r.LayerCount <= 1 {
		return 1.0
	}
	if r.LayerCount == 2 {
		return 1.1
	}
	if r.LayerCount == 3 {
		return 1.3
	}
	return 1.5 // 4+ layers is very suspicious
}

// IsHighConfidence returns true if confidence is above the threshold (default 0.85)
func (s *DetectionSignal) IsHighConfidence() bool {
	return s.Confidence >= 0.85
}

// IsMediumConfidence returns true if confidence is in the uncertain range (0.60-0.85)
func (s *DetectionSignal) IsMediumConfidence() bool {
	return s.Confidence >= 0.60 && s.Confidence < 0.85
}

// IsLowConfidence returns true if confidence is below 0.60
func (s *DetectionSignal) IsLowConfidence() bool {
	return s.Confidence < 0.60
}

// IsMalicious returns true if the label indicates malicious intent
func (s *DetectionSignal) IsMalicious() bool {
	return s.Label == "INJECTION" || s.Label == "MALICIOUS" || s.Label == "UNSAFE"
}

// IsSafe returns true if the label indicates safe content
func (s *DetectionSignal) IsSafe() bool {
	return s.Label == "SAFE" || s.Label == "BENIGN"
}

// HasObfuscation returns true if any obfuscation was detected
func (s *DetectionSignal) HasObfuscation() bool {
	return s.WasDeobfuscated || len(s.ObfuscationTypes) > 0
}

// NewDetectionSignal creates a new signal with default values
func NewDetectionSignal(source SignalSource) DetectionSignal {
	return DetectionSignal{
		Source:     source,
		Confidence: 0.5, // Default to medium confidence
		Weight:     getDefaultWeight(source),
		Metadata:   make(map[string]interface{}),
	}
}

// getDefaultWeight returns the default weight for a signal source
func getDefaultWeight(source SignalSource) float64 {
	switch source {
	case SignalSourceHeuristic:
		return 0.4
	case SignalSourceSemantic:
		return 0.6
	case SignalSourceHugot:
		return 0.75 // High weight - ML-based intent detection
	case SignalSourceBERT:
		return 0.8
	case SignalSourceSafeguard:
		return 0.9
	case SignalSourceLLM:
		return 0.7
	case SignalSourceDeeperGo:
		return 0.7
	case SignalSourceContext:
		return 0.3
	case SignalSourceTaskDrift:
		return 0.8
	case SignalSourceMultiBERT:
		return 0.85 // High weight - ensemble between BERT (0.8) and Safeguard (0.9)
	default:
		return 0.5
	}
}

// AddReason appends a reason to the signal
func (s *DetectionSignal) AddReason(reason string) {
	s.Reasons = append(s.Reasons, reason)
}

// AddObfuscationType records a detected obfuscation type
func (s *DetectionSignal) AddObfuscationType(t ObfuscationType) {
	// Avoid duplicates
	for _, existing := range s.ObfuscationTypes {
		if existing == t {
			return
		}
	}
	s.ObfuscationTypes = append(s.ObfuscationTypes, t)
	s.WasDeobfuscated = true
}

// SetMetadata sets a metadata key-value pair
func (s *DetectionSignal) SetMetadata(key string, value interface{}) {
	if s.Metadata == nil {
		s.Metadata = make(map[string]interface{})
	}
	s.Metadata[key] = value
}
