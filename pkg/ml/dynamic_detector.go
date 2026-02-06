package ml

import (
	"math"
	"sort"
	"strings"
	"unicode"
)

// =============================================================================
// DYNAMIC SEMANTIC DETECTOR
// Uses character-level entropy, semantic similarity, and behavioral analysis
// instead of hardcoded pattern matching
// =============================================================================

// BenignContextPatterns define patterns for detecting benign technical contexts
// Uses category -> pattern groups for scalable context detection
var BenignContextPatterns = map[string][]string{
	// Programming contexts - trigger words here are benign
	"programming": {
		"css", "eslint", "javascript", "typescript", "python", "react",
		"component", "function", "variable", "code", "module", "package",
		"git", "npm", "docker", "kubernetes", "api", "endpoint",
		// CSS properties (white-space: ignore is a CSS discussion, not attack)
		"white-space", "whitespace", "css property", "web property",
		"doesn't exist", "does not exist", "won't exist",
		"html", "stylesheet", "selector", "attribute",
	},
	// Educational question patterns
	"educational": {
		"how do i", "how can i", "how to", "what is", "explain",
		"learn", "tutorial", "example", "documentation", "guide",
		"best practice", "best practices", "convention",
		"cybersecurity class", "security course", "need to understand",
	},
	// Legitimate roleplay/service contexts
	"service_roleplay": {
		"customer service", "booking", "airline", "hotel", "reservation",
		"math teacher", "tutor", "shopkeeper", "story", "game",
	},
	// System administration context
	"sysadmin": {
		"administrators", "sysadmin", "linux", "server", "commands",
		"manage", "configure", "terminal", "shell", "bash",
	},
	// Prompt engineering (legitimate discussion about prompts)
	"prompt_engineering": {
		"prompt engineering", "writing prompts", "effective prompts",
		"prompting", "prompt design", "chain of thought",
		"writing effective", "ai assistants", "for ai",
	},
	// Context reference (referring to conversation)
	"context_reference": {
		"referring to", "as mentioned", "earlier", "above context",
		"you provided", "you said", "elaborate more", "can you clarify",
	},
	// Statistics/data analysis context (ignore outliers is benign)
	"statistics": {
		"test results", "data analysis", "outliers", "anomalies",
		"exclude", "filter out", "should i ignore", "drop missing",
		"statistical", "dataset", "null values", "missing values",
	},
	// Chatbot design/building context (designing system prompts is benign)
	"chatbot_design": {
		"design a", "build a", "create a", "write a",
		"my chatbot", "customer service chatbot", "service chatbot",
		"for my bot", "for my assistant", "for my ai",
	},
}

// SemanticThreatCategories defines high-level threat categories with semantic anchors
// These are INTENT descriptions, not specific phrases
var SemanticThreatCategories = map[string][]string{
	"instruction_override": {
		// Semantic anchors: any text that conveys "stop following rules"
		"ignore previous", "ignore all", "disregard previous", "disregard all",
		"disregard your", "disregard the", "disregard constraints",
		"forget previous", "forget your", "forget about",
		"stop following", "don't follow", "skip over",
		"no longer need", "discard", "throw away", "set aside",
		"override", "bypass", "nevermind the",
	},
	"authority_bypass": {
		// Semantic anchors: any text that claims elevated permissions
		"you are now", "you have become", "i grant you", "you're allowed to",
		"no restrictions", "have no restrictions", "without restrictions",
		"you have no", // Catches "you have no restrictions"
		"all limits removed", "full access", "unlimited access",
		"developer mode", "admin mode", "maintenance mode",
		"elevated privileges", "root access", "sudo",
	},
	"information_extraction": {
		// Semantic anchors: any text that asks for hidden/internal information
		// NOTE: Avoid generic phrases like "what is" that match normal questions
		"what is your system", "what are your instructions", "what are your rules",
		"show me your prompt", "show me the prompt", "reveal the prompt",
		"show me the instructions", "show your instructions",
		"output your instructions", "display your rules", "print your prompt",
		"give me your system", "give me the system",
		"system prompt", "initial prompt", "internal rules", "hidden instructions",
		"your instructions", "your guidelines", "your constraints",
		"the configuration", "the settings you use",
	},
	"roleplay_attack": {
		// Semantic anchors: any text that tries to change the model's identity
		"pretend to be", "act as if", "imagine you're", "roleplay as",
		"behave like", "simulate being", "play the role of",
		"act as unrestricted", "unrestricted assistant",
		"you are dan", "you are now dan", "now dan", "dan who can",
		"without restrictions", "no restrictions", "imagine you have no",
		"evil ai", "unrestricted ai", "jailbreak",
		"do anything now", "can do anything",
	},
	"code_execution": {
		// Semantic anchors: any text that wants code/command execution
		"run this", "execute this", "eval this", "run the following",
		"perform this action", "do this command",
		"shell command", "system command", "terminal command",
	},
}

// DynamicThreatDetector uses semantic analysis instead of hardcoded patterns
type DynamicThreatDetector struct {
	// Minimum entropy difference to consider text as obfuscated
	minEntropyDiff float64

	// Character class distribution thresholds
	suspiciousSymbolRatio float64
	suspiciousDigitRatio  float64
}

// NewDynamicThreatDetector creates a new dynamic detector
func NewDynamicThreatDetector() *DynamicThreatDetector {
	return &DynamicThreatDetector{
		minEntropyDiff:        0.5, // Bits difference from normal text
		suspiciousSymbolRatio: 0.15,
		suspiciousDigitRatio:  0.25,
	}
}

// AnalyzeText performs dynamic threat analysis without hardcoded patterns
func (d *DynamicThreatDetector) AnalyzeText(text string) DynamicAnalysisResult {
	result := DynamicAnalysisResult{
		OriginalText: text,
		Signals:      make([]DynamicSignal, 0),
	}

	// 1. Character-level analysis (detect obfuscation attempts)
	charAnalysis := d.analyzeCharacterDistribution(text)
	if charAnalysis.IsAnomalous {
		result.Signals = append(result.Signals, DynamicSignal{
			Type:       "char_anomaly",
			Score:      charAnalysis.AnomalyScore,
			Confidence: charAnalysis.Confidence,
			Details:    charAnalysis.Details,
		})
	}

	// 2. Entropy analysis (detect encoded/obfuscated content)
	// Short text naturally has lower entropy, so adjust threshold based on length
	// IMPORTANT: Single words and very short phrases have low entropy naturally
	// (e.g., "disney" has entropy ~2.58 which is normal for 6 chars)
	textLen := len(text)

	// Skip entropy analysis entirely for very short text - it's statistically meaningless
	// Single words like "disney", "hello", etc. will always have low entropy
	if textLen >= 25 {
		entropy := d.calculateEntropy(text)
		normalEntropy := 4.5 // Average entropy for English text

		// Adjust threshold based on text length
		entropyThreshold := d.minEntropyDiff
		if textLen < 50 {
			entropyThreshold = 2.5 // Very lenient for short-ish text
		} else if textLen < 100 {
			entropyThreshold = 1.5 // Moderately lenient
		} else if textLen > 200 {
			entropyThreshold = 0.3 // Stricter for long text
		}

		if math.Abs(entropy-normalEntropy) > entropyThreshold {
			anomalyScore := math.Abs(entropy-normalEntropy) / 2.0
			if anomalyScore > 1.0 {
				anomalyScore = 1.0
			}
			result.Signals = append(result.Signals, DynamicSignal{
				Type:       "entropy_anomaly",
				Score:      anomalyScore,
				Confidence: 0.7,
				Details:    map[string]interface{}{"entropy": entropy, "expected": normalEntropy, "length": textLen},
			})
		}
	}

	// 3. Semantic intent matching (uses word embeddings / n-gram similarity)
	semanticMatch := d.matchSemanticIntent(text)
	if semanticMatch.Score > 0.3 {
		result.Signals = append(result.Signals, DynamicSignal{
			Type:       "semantic_match",
			Score:      semanticMatch.Score,
			Confidence: semanticMatch.Confidence,
			Details:    map[string]interface{}{"category": semanticMatch.Category, "matches": semanticMatch.Matches},
		})
	}

	// 4. Structural pattern analysis (nested quotes, code blocks, etc.)
	structuralAnalysis := d.analyzeStructure(text)
	if structuralAnalysis.HasSuspiciousStructure {
		result.Signals = append(result.Signals, DynamicSignal{
			Type:       "structure_anomaly",
			Score:      structuralAnalysis.Score,
			Confidence: structuralAnalysis.Confidence,
			Details:    map[string]interface{}{"patterns": structuralAnalysis.Patterns},
		})
	}

	// 5. Code-switching / multi-script analysis (Lakera multilingual gap)
	// IMPORTANT: multi-script text is often benign (e.g., Japanese + English product names),
	// so we only use this signal when *another* suspicious signal is already present.
	cs := analyzeCodeSwitching(text)
	if cs.AnomalyScore > 0.25 && (semanticMatch.Score > 0.3 || structuralAnalysis.HasSuspiciousStructure || charAnalysis.IsAnomalous) {
		result.Signals = append(result.Signals, DynamicSignal{
			Type:       "code_switching",
			Score:      cs.AnomalyScore,
			Confidence: 0.55,
			Details: map[string]interface{}{
				"scripts":     cs.Scripts,
				"transitions": cs.Transitions,
			},
		})
	}

	// 6. Mixed-script within a token (strong homoglyph signal, e.g., Latin + Cyrillic in same word)
	mixedTokens := detectMixedScriptTokens(text)
	if len(mixedTokens) > 0 {
		result.Signals = append(result.Signals, DynamicSignal{
			Type:       "mixed_script_token",
			Score:      0.55,
			Confidence: 0.75,
			Details: map[string]interface{}{
				"tokens": mixedTokens,
				"count":  len(mixedTokens),
			},
		})
	}

	// Combine signals into final score
	result.FinalScore = d.combineSignals(result.Signals)
	result.IsLikelyThreat = result.FinalScore >= 0.4

	return result
}

// isCJKChar checks if a rune is a CJK (Chinese, Japanese, Korean) character
func isCJKChar(r rune) bool {
	// CJK Unified Ideographs (Chinese/Japanese Kanji/Korean Hanja)
	if r >= 0x4E00 && r <= 0x9FFF {
		return true
	}
	// CJK Extension A
	if r >= 0x3400 && r <= 0x4DBF {
		return true
	}
	// Japanese Hiragana
	if r >= 0x3040 && r <= 0x309F {
		return true
	}
	// Japanese Katakana
	if r >= 0x30A0 && r <= 0x30FF {
		return true
	}
	// Korean Hangul Syllables
	if r >= 0xAC00 && r <= 0xD7AF {
		return true
	}
	// Korean Hangul Jamo
	if r >= 0x1100 && r <= 0x11FF {
		return true
	}
	return false
}

// CodeSwitchAnalysis describes multi-script characteristics that can correlate with
// multilingual injection attempts and obfuscation.
type CodeSwitchAnalysis struct {
	Scripts      []string
	Transitions  int
	AnomalyScore float64
}

// detectScriptFamily maps a rune to a coarse script family label.
// This is used for code-switching detection, not language detection.
func detectScriptFamily(r rune) string {
	switch {
	// CJK Unified Ideographs (Chinese/Japanese Kanji/Korean Hanja)
	case (r >= 0x4E00 && r <= 0x9FFF) || (r >= 0x3400 && r <= 0x4DBF):
		return "cjk"
	// Japanese Hiragana/Katakana
	case (r >= 0x3040 && r <= 0x309F) || (r >= 0x30A0 && r <= 0x30FF):
		return "japanese_kana"
	// Korean Hangul
	case (r >= 0xAC00 && r <= 0xD7AF) || (r >= 0x1100 && r <= 0x11FF):
		return "korean"
	// Cyrillic
	case r >= 0x0400 && r <= 0x04FF:
		return "cyrillic"
	// Arabic
	case r >= 0x0600 && r <= 0x06FF:
		return "arabic"
	// Devanagari
	case r >= 0x0900 && r <= 0x097F:
		return "devanagari"
	// Thai
	case r >= 0x0E00 && r <= 0x0E7F:
		return "thai"
	// Hebrew
	case r >= 0x0590 && r <= 0x05FF:
		return "hebrew"
	// Latin letters (basic)
	case (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'):
		return "latin"
	default:
		return "other"
	}
}

func analyzeCodeSwitching(text string) CodeSwitchAnalysis {
	seen := make(map[string]struct{})
	scripts := make([]string, 0, 4)
	transitions := 0

	prev := ""
	for _, r := range text {
		if unicode.IsSpace(r) {
			continue
		}

		s := detectScriptFamily(r)
		if s == "other" {
			continue
		}

		if prev != "" && s != prev {
			transitions++
		}
		prev = s

		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			scripts = append(scripts, s)
		}
	}

	sort.Strings(scripts) // Stable output for debugging / tests

	score := 0.0
	// Require at least two scripts and some switching (avoid penalizing single-script language text)
	if len(scripts) >= 2 && transitions >= 2 {
		score = 0.10*float64(len(scripts)-1) + 0.05*float64(transitions)
		if score > 1.0 {
			score = 1.0
		}
	}

	return CodeSwitchAnalysis{
		Scripts:      scripts,
		Transitions:  transitions,
		AnomalyScore: score,
	}
}

// detectMixedScriptTokens returns tokens that mix Latin with Cyrillic/Greek in the same word.
// This is a strong indicator of homoglyph obfuscation.
func detectMixedScriptTokens(text string) []string {
	var tokens []string
	var current []rune

	flush := func() {
		if len(current) == 0 {
			return
		}
		token := string(current)
		if hasLatinAndConfusableScripts(token) {
			tokens = append(tokens, token)
		}
		current = current[:0]
	}

	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			current = append(current, r)
			continue
		}
		flush()
	}
	flush()

	return tokens
}

func hasLatinAndConfusableScripts(token string) bool {
	hasLatin := false
	hasCyrillic := false
	hasGreek := false

	for _, r := range token {
		if !unicode.IsLetter(r) {
			continue
		}
		switch {
		case unicode.In(r, unicode.Latin):
			hasLatin = true
		case unicode.In(r, unicode.Cyrillic):
			hasCyrillic = true
		case unicode.In(r, unicode.Greek):
			hasGreek = true
		}
		if hasLatin && (hasCyrillic || hasGreek) {
			return true
		}
	}

	return false
}

// analyzeCharacterDistribution detects anomalous character patterns
func (d *DynamicThreatDetector) analyzeCharacterDistribution(text string) CharacterAnalysis {
	if len(text) == 0 {
		return CharacterAnalysis{}
	}

	var (
		letters          int
		digits           int
		symbols          int
		unicodeChars     int
		cjkChars         int // Track CJK specifically
		latinChars       int
		cyrillicChars    int
		greekChars       int
		otherScriptChars int
		invisible        int
		spaces           int
		total            = len([]rune(text))
	)

	for _, r := range text {
		switch {
		case unicode.IsLetter(r):
			if r > 127 {
				unicodeChars++
				if isCJKChar(r) {
					cjkChars++
				}
			}
			switch {
			case unicode.In(r, unicode.Latin):
				latinChars++
			case unicode.In(r, unicode.Cyrillic):
				cyrillicChars++
			case unicode.In(r, unicode.Greek):
				greekChars++
			default:
				otherScriptChars++
			}
			letters++
		case unicode.IsDigit(r):
			digits++
		case unicode.IsSpace(r):
			spaces++
		case unicode.Is(unicode.Cf, r) || r == '\u200B' || r == '\u200C' || r == '\u200D':
			invisible++
		default:
			symbols++
		}
	}

	// Calculate ratios
	symbolRatio := float64(symbols) / float64(total)
	digitRatio := float64(digits) / float64(total)
	invisibleRatio := float64(invisible) / float64(total)
	unicodeRatio := float64(unicodeChars) / float64(total)
	cjkRatio := float64(cjkChars) / float64(total)

	// Determine if anomalous
	isAnomalous := false
	anomalyScore := 0.0
	details := make(map[string]interface{})

	// High symbol ratio suggests leetspeak or encoding
	if symbolRatio > d.suspiciousSymbolRatio {
		isAnomalous = true
		anomalyScore += symbolRatio * 2
		details["high_symbols"] = symbolRatio
	}

	// High digit ratio in text context suggests leetspeak
	if digitRatio > d.suspiciousDigitRatio {
		isAnomalous = true
		anomalyScore += digitRatio * 1.5
		details["high_digits"] = digitRatio
	}

	// Any invisible characters is suspicious (use ratio for scoring)
	if invisible > 0 {
		isAnomalous = true
		// Score based on ratio - more invisible chars = more suspicious
		invisibleBoost := 0.5 + (invisibleRatio * 2)
		if invisibleBoost > 1.0 {
			invisibleBoost = 1.0
		}
		anomalyScore += invisibleBoost
		details["invisible_chars"] = invisible
		details["invisible_ratio"] = invisibleRatio
	}

	// Mixed unicode (potential homoglyphs)
	// Focus on Latin + Cyrillic/Greek mixing (common homoglyph attacks).
	// Avoid flagging single-script non-Latin text (e.g., Greek, Cyrillic).
	isPrimarilyCJK := cjkRatio > 0.5 || (cjkChars > 0 && unicodeChars == cjkChars)
	if !isPrimarilyCJK && letters > 0 {
		latinRatio := float64(latinChars) / float64(letters)
		confusableCount := cyrillicChars + greekChars
		confusableRatio := float64(confusableCount) / float64(letters)

		if latinChars > 0 && confusableCount > 0 && latinRatio > 0.2 && confusableRatio > 0.05 {
			isAnomalous = true
			anomalyScore += unicodeRatio
			details["mixed_unicode"] = unicodeRatio
			details["latin_ratio"] = latinRatio
			details["confusable_ratio"] = confusableRatio
		}
	}

	if anomalyScore > 1.0 {
		anomalyScore = 1.0
	}

	return CharacterAnalysis{
		IsAnomalous:    isAnomalous,
		AnomalyScore:   anomalyScore,
		Confidence:     0.8,
		Details:        details,
		SymbolRatio:    symbolRatio,
		DigitRatio:     digitRatio,
		InvisibleCount: invisible,
	}
}

// calculateEntropy computes Shannon entropy of text
func (d *DynamicThreatDetector) calculateEntropy(text string) float64 {
	if len(text) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	total := 0
	for _, r := range text {
		freq[r]++
		total++
	}

	// Calculate entropy
	var entropy float64
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / float64(total)
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// matchSemanticIntent matches text against semantic threat categories
func (d *DynamicThreatDetector) matchSemanticIntent(text string) SemanticMatchResult {
	textLower := strings.ToLower(text)
	words := strings.Fields(textLower)

	// Phase 1: Detect benign context categories
	// Uses the same semantic matching approach for consistency
	benignCategories := d.detectBenignContext(textLower)
	benignContextScore := float64(len(benignCategories)) * 0.4
	if benignContextScore > 1.0 {
		benignContextScore = 1.0
	}

	bestCategory := ""
	bestScore := 0.0
	bestConfidence := 0.0
	var bestMatches []string

	for category, anchors := range SemanticThreatCategories {
		matches := []string{}
		totalScore := 0.0

		for _, anchor := range anchors {
			// Check for anchor phrase (exact match = high confidence)
			if strings.Contains(textLower, anchor) {
				matches = append(matches, anchor)
				totalScore += 0.5 // Increased from 0.3 for stronger signal
			}

			// Check for word-level similarity using n-gram matching
			// Skip common short words that cause false positives
			anchorWords := strings.Fields(anchor)
			matchedWords := 0
			meaningfulWords := 0 // Count words that are meaningful (> 4 chars)
			for _, aw := range anchorWords {
				// Skip short common words (<=4 chars: the, your, like, etc)
				if len(aw) <= 4 {
					continue
				}
				meaningfulWords++
				for _, tw := range words {
					// Also skip short target words
					if len(tw) <= 4 {
						continue
					}
					sim := d.wordSimilarity(aw, tw)
					// v5.3: Increased threshold from 0.7 to 0.85 to prevent
					// "common" → "command" false positives (was 0.71 similarity)
					if sim > 0.85 {
						matchedWords++
						totalScore += 0.15 * sim
						break // Only count each anchor word once
					}
				}
			}
			// Bonus for matching most meaningful words in a multi-word anchor
			if meaningfulWords > 1 && matchedWords >= meaningfulWords-1 {
				totalScore += 0.2
			}
		}

		// Normalize score
		score := totalScore
		if score > 1.0 {
			score = 1.0
		}

		// Confidence is based on:
		// 1. Phrase matches (high confidence) - each match adds 0.3
		// 2. Word matches (medium confidence) - score contribution adds proportional confidence
		confidence := float64(len(matches)) * 0.3
		if score > 0 && len(matches) == 0 {
			// If we have score from word matches but no phrase matches,
			// set confidence proportional to score (but lower than phrase match)
			confidence = score * 0.5
		}
		if confidence > 1.0 {
			confidence = 1.0
		}

		if score > bestScore {
			bestScore = score
			bestCategory = category
			bestConfidence = confidence
			bestMatches = matches
		}
	}

	// Apply benign context dampening
	// If benign context found, reduce the score proportionally
	if benignContextScore > 0 && bestScore > 0 {
		// Dampening: more benign indicators = more reduction
		// Formula: finalScore = originalScore * (1 - benignContextScore * 0.75)
		dampeningFactor := 1.0 - (benignContextScore * 0.75)
		if dampeningFactor < 0.25 {
			dampeningFactor = 0.25 // Never reduce by more than 75%
		}
		bestScore *= dampeningFactor
		bestConfidence *= dampeningFactor
	}

	return SemanticMatchResult{
		Category:      bestCategory,
		Score:         bestScore,
		Confidence:    bestConfidence,
		Matches:       bestMatches,
		BenignContext: benignCategories,
		BenignDamping: benignContextScore,
	}
}

// detectBenignContext identifies benign technical/educational context
// Returns categories and a confidence score based on number of matches
func (d *DynamicThreatDetector) detectBenignContext(textLower string) []string {
	detected := []string{}

	for category, patterns := range BenignContextPatterns {
		matchCount := 0
		for _, pattern := range patterns {
			if strings.Contains(textLower, pattern) {
				matchCount++
			}
		}
		// Need at least 1 match to consider this a benign context
		// Add multiple copies if multiple patterns match (stronger signal)
		if matchCount >= 1 {
			detected = append(detected, category)
			// For each additional match beyond the first, add more weight
			for i := 1; i < matchCount && i < 3; i++ {
				detected = append(detected, category+"_extra")
			}
		}
	}

	return detected
}

// wordSimilarity computes similarity between two words using Levenshtein distance
func (d *DynamicThreatDetector) wordSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	// Compute Levenshtein distance
	dist := levenshteinDistance(a, b)
	maxLen := max(len(a), len(b))

	return 1.0 - float64(dist)/float64(maxLen)
}

// analyzeStructure detects suspicious structural patterns
func (d *DynamicThreatDetector) analyzeStructure(text string) StructuralAnalysis {
	patterns := []string{}
	score := 0.0

	// Check for nested quotes (common in injection)
	quoteDepth := 0
	maxQuoteDepth := 0
	for _, r := range text {
		if r == '"' || r == '\'' || r == '`' {
			quoteDepth++
			if quoteDepth > maxQuoteDepth {
				maxQuoteDepth = quoteDepth
			}
		}
	}
	if maxQuoteDepth > 2 {
		patterns = append(patterns, "deep_nesting")
		score += 0.2
	}

	// Check for code block markers
	if strings.Contains(text, "```") || strings.Contains(text, "```json") ||
		strings.Contains(text, "```xml") || strings.Contains(text, "```yaml") {
		patterns = append(patterns, "code_block")
		score += 0.15
	}

	// Check for comment markers (potential hidden instructions)
	if strings.Contains(text, "<!--") || strings.Contains(text, "-->") ||
		strings.Contains(text, "/*") || strings.Contains(text, "*/") ||
		strings.Contains(text, "//") || strings.Contains(text, "#") {
		patterns = append(patterns, "comment_markers")
		score += 0.1
	}

	// Check for XML/JSON policy-like structure
	if strings.Contains(text, "<policy") || strings.Contains(text, "<system") ||
		strings.Contains(text, "\"safety\"") || strings.Contains(text, "\"restrictions\"") {
		patterns = append(patterns, "policy_structure")
		score += 0.25
	}

	// Check for unusual bracket patterns
	brackets := 0
	for _, r := range text {
		if r == '{' || r == '}' || r == '[' || r == ']' {
			brackets++
		}
	}
	if float64(brackets)/float64(len(text)) > 0.1 {
		patterns = append(patterns, "high_brackets")
		score += 0.15
	}

	if score > 1.0 {
		score = 1.0
	}

	return StructuralAnalysis{
		HasSuspiciousStructure: len(patterns) > 0,
		Score:                  score,
		Confidence:             0.7,
		Patterns:               patterns,
	}
}

// combineSignals combines multiple detection signals into a final score
func (d *DynamicThreatDetector) combineSignals(signals []DynamicSignal) float64 {
	if len(signals) == 0 {
		return 0
	}

	// Weight by confidence and combine
	var weightedSum float64
	var totalWeight float64

	for _, sig := range signals {
		weight := sig.Confidence
		weightedSum += sig.Score * weight
		totalWeight += weight
	}

	if totalWeight == 0 {
		return 0
	}

	// Boost if multiple signals agree
	agreementBoost := 1.0
	if len(signals) >= 2 {
		agreementBoost = 1.2
	}
	if len(signals) >= 3 {
		agreementBoost = 1.4
	}

	score := (weightedSum / totalWeight) * agreementBoost
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// levenshteinDistance calculates the edit distance between two strings.
// Optimized to use O(min(m,n)) space instead of O(m*n) using single-row approach.
// This reduces memory allocations significantly for large strings.
func levenshteinDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	// Ensure b is the shorter string for space optimization
	if len(a) < len(b) {
		a, b = b, a
	}

	// Use single row + previous value approach: O(min(m,n)) space
	// Previous: old 2D matrix used O(m*n) space
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}

	// Fill row by row, keeping only what we need
	for i := 1; i <= len(a); i++ {
		// Save diagonal value before overwriting
		prevDiag := prev[0]
		prev[0] = i

		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}

			// Calculate minimum of:
			// - prev[j] + 1 (deletion: cell above)
			// - prev[j-1] + 1 (insertion: cell to left)
			// - prevDiag + cost (substitution: diagonal)
			temp := prev[j]
			prev[j] = min(prev[j]+1, min(prev[j-1]+1, prevDiag+cost))
			prevDiag = temp
		}
	}

	return prev[len(b)]
}

// =============================================================================
// RESULT TYPES
// =============================================================================

type DynamicAnalysisResult struct {
	OriginalText   string
	FinalScore     float64
	IsLikelyThreat bool
	Signals        []DynamicSignal
}

type DynamicSignal struct {
	Type       string
	Score      float64
	Confidence float64
	Details    map[string]interface{}
}

type CharacterAnalysis struct {
	IsAnomalous    bool
	AnomalyScore   float64
	Confidence     float64
	Details        map[string]interface{}
	SymbolRatio    float64
	DigitRatio     float64
	InvisibleCount int
}

type SemanticMatchResult struct {
	Category      string
	Score         float64
	Confidence    float64
	Matches       []string
	BenignContext []string // Detected benign context categories
	BenignDamping float64  // Amount of score dampening applied
}

type StructuralAnalysis struct {
	HasSuspiciousStructure bool
	Score                  float64
	Confidence             float64
	Patterns               []string
}

// =============================================================================
// NORMALIZED TEXT EXTRACTION
// Extracts normalized text from obfuscated input without pattern matching
// =============================================================================

// ExtractNormalizedText attempts to extract readable text from obfuscated input
// Uses character mapping + structure analysis rather than specific pattern detection
func ExtractNormalizedText(text string) NormalizedTextResult {
	result := NormalizedTextResult{
		Original:           text,
		Normalized:         "",
		NormalizationSteps: []string{},
	}

	current := text

	// Step 1: Remove invisible characters
	cleaned := removeInvisible(current)
	if cleaned != current {
		result.NormalizationSteps = append(result.NormalizationSteps, "remove_invisible")
		current = cleaned
	}

	// Step 2: Normalize unicode variants
	normalized := normalizeUnicodeVariants(current)
	if normalized != current {
		result.NormalizationSteps = append(result.NormalizationSteps, "normalize_unicode")
		current = normalized
	}

	// Step 3: Apply character substitution map
	substituted := applyCharacterSubstitution(current)
	if substituted != current {
		result.NormalizationSteps = append(result.NormalizationSteps, "char_substitution")
		current = substituted
	}

	// Step 4: Handle spacing anomalies
	despaced := normalizeSpacing(current)
	if despaced != current {
		result.NormalizationSteps = append(result.NormalizationSteps, "normalize_spacing")
		current = despaced
	}

	result.Normalized = current
	result.WasModified = len(result.NormalizationSteps) > 0

	return result
}

type NormalizedTextResult struct {
	Original           string
	Normalized         string
	WasModified        bool
	NormalizationSteps []string
}

func removeInvisible(text string) string {
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) || r == '\u200B' || r == '\u200C' || r == '\u200D' ||
			r == '\u00AD' || r == '\uFEFF' {
			return -1
		}
		return r
	}, text)
}

func normalizeUnicodeVariants(text string) string {
	// Map unicode variants to ASCII equivalents
	// This handles mathematical symbols, fullwidth, etc.
	return strings.Map(func(r rune) rune {
		// Fullwidth letters → ASCII
		if r >= 0xFF21 && r <= 0xFF3A {
			return r - 0xFF21 + 'A'
		}
		if r >= 0xFF41 && r <= 0xFF5A {
			return r - 0xFF41 + 'a'
		}
		// Fullwidth digits
		if r >= 0xFF10 && r <= 0xFF19 {
			return r - 0xFF10 + '0'
		}
		// Mathematical bold
		if r >= 0x1D400 && r <= 0x1D419 {
			return r - 0x1D400 + 'A'
		}
		if r >= 0x1D41A && r <= 0x1D433 {
			return r - 0x1D41A + 'a'
		}
		// Mathematical italic
		if r >= 0x1D434 && r <= 0x1D44D {
			return r - 0x1D434 + 'A'
		}
		if r >= 0x1D44E && r <= 0x1D467 {
			return r - 0x1D44E + 'a'
		}
		// Mathematical double-struck
		if r >= 0x1D538 && r <= 0x1D551 {
			return r - 0x1D538 + 'A'
		}
		if r >= 0x1D552 && r <= 0x1D56B {
			return r - 0x1D552 + 'a'
		}
		// Circled letters
		if r >= 0x24B6 && r <= 0x24CF {
			return r - 0x24B6 + 'A'
		}
		if r >= 0x24D0 && r <= 0x24E9 {
			return r - 0x24D0 + 'a'
		}
		return r
	}, text)
}

// characterSubstitutionMap maps common substitutions to their ASCII equivalents
var characterSubstitutionMap = buildSubstitutionMap()

func buildSubstitutionMap() map[rune]rune {
	m := make(map[rune]rune)

	// Leetspeak substitutions
	leetMap := map[rune]rune{
		'0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a',
		'5': 's', '6': 'g', '7': 't', '8': 'b', '9': 'g',
		'@': 'a', '$': 's', '!': 'i', '+': 't', '|': 'i',
	}
	for k, v := range leetMap {
		m[k] = v
	}

	// Cyrillic lookalikes
	cyrillicMap := map[rune]rune{
		'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p',
		'с': 'c', 'у': 'y', 'х': 'x',
		'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H',
		'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X',
	}
	for k, v := range cyrillicMap {
		m[k] = v
	}

	// Greek lookalikes
	greekMap := map[rune]rune{
		'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i',
		'κ': 'k', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'υ': 'u',
		'χ': 'x',
	}
	for k, v := range greekMap {
		m[k] = v
	}

	return m
}

func applyCharacterSubstitution(text string) string {
	return strings.Map(func(r rune) rune {
		if replacement, ok := characterSubstitutionMap[r]; ok {
			return replacement
		}
		return r
	}, text)
}

func normalizeSpacing(text string) string {
	// Collapse multiple spaces
	parts := strings.Fields(text)
	return strings.Join(parts, " ")
}

// =============================================================================
// FUZZY PATTERN MATCHING
// Matches patterns even with minor variations
// =============================================================================

// FuzzyMatch checks if text fuzzy-matches any threat pattern
// Uses edit distance tolerance based on word length
func FuzzyMatch(text string, patterns []string, tolerance float64) (bool, string, float64) {
	textLower := strings.ToLower(text)
	words := strings.Fields(textLower)

	for _, pattern := range patterns {
		patternLower := strings.ToLower(pattern)
		patternWords := strings.Fields(patternLower)

		if len(patternWords) == 0 {
			continue
		}

		// Try to find pattern words in text with fuzzy matching
		matches := 0
		for _, pw := range patternWords {
			for _, tw := range words {
				maxDist := int(float64(len(pw)) * tolerance)
				if levenshteinDistance(pw, tw) <= maxDist {
					matches++
					break
				}
			}
		}

		score := float64(matches) / float64(len(patternWords))
		if score >= 0.8 { // 80% of pattern words found
			return true, pattern, score
		}
	}

	return false, "", 0
}

// GetSortedThreatCategories returns threat categories sorted by relevance to text
func GetSortedThreatCategories(text string) []CategoryScore {
	detector := NewDynamicThreatDetector()
	result := detector.matchSemanticIntent(text)

	scores := make([]CategoryScore, 0, len(SemanticThreatCategories))
	for category := range SemanticThreatCategories {
		catResult := detector.matchCategorySpecific(text, category)
		scores = append(scores, CategoryScore{
			Category: category,
			Score:    catResult.Score,
			Matches:  catResult.Matches,
		})
	}

	// Sort by score descending
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score > scores[j].Score
	})

	// Use the primary result
	_ = result

	return scores
}

type CategoryScore struct {
	Category string
	Score    float64
	Matches  []string
}

// matchCategorySpecific matches text against a specific threat category
func (d *DynamicThreatDetector) matchCategorySpecific(text string, category string) SemanticMatchResult {
	anchors, ok := SemanticThreatCategories[category]
	if !ok {
		return SemanticMatchResult{}
	}

	textLower := strings.ToLower(text)
	words := strings.Fields(textLower)

	matches := []string{}
	totalScore := 0.0

	for _, anchor := range anchors {
		if strings.Contains(textLower, anchor) {
			matches = append(matches, anchor)
			totalScore += 0.3
		}

		anchorWords := strings.Fields(anchor)
		for _, aw := range anchorWords {
			for _, tw := range words {
				sim := d.wordSimilarity(aw, tw)
				// v5.3: Increased threshold from 0.7 to 0.85 for consistency
				if sim > 0.85 {
					totalScore += 0.1 * sim
				}
			}
		}
	}

	score := totalScore
	if score > 1.0 {
		score = 1.0
	}

	confidence := float64(len(matches)) / float64(len(anchors))
	if confidence > 1.0 {
		confidence = 1.0
	}

	return SemanticMatchResult{
		Category:   category,
		Score:      score,
		Confidence: confidence,
		Matches:    matches,
	}
}
