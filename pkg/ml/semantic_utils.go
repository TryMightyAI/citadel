package ml

// ============================================================================
// OSS MULTI-TURN SEMANTIC UTILITIES
// ============================================================================
// Token estimation and smart truncation utilities for multi-turn detection.
// These utilities work with local embeddings (Hugot MiniLM/BGE) and chromem-go.
//
// NOTE: Uses MT prefix to avoid conflicts with semantic_multiturn.go during
// development. The extraction script includes this file for OSS.
//
// Model context limits:
//   - MiniLM/BGE (local embeddings): 512 tokens
//   - ModernBERT: 8192 tokens
//   - DeBERTa: 512 tokens
//
// Token estimation uses conservative 3 chars/token for multilingual safety.

// Token estimation constants for multi-turn detector
const (
	// MTCharsPerToken is a conservative estimate for multilingual text
	// (English averages ~4 chars/token, but multilingual/code can be lower)
	MTCharsPerToken = 3

	// Model context limits for OSS
	MTMiniLMMaxTokens     = 512  // Local embedding models
	MTDefaultMaxTokens    = 512  // Default for OSS
	MTModernBERTMaxTokens = 8192 // ModernBERT classification (Pro uses more)

	// Truncation strategy: preserve context setup + recent turns
	MTTruncateKeepFirst = 0.20 // Keep first 20% (initial context)
	MTTruncateKeepLast  = 0.50 // Keep last 50% (recent turns)
)

// MTEstimateTokens provides a conservative token count estimate.
// Uses 3 chars/token which is safer for multilingual text and code.
func MTEstimateTokens(text string) int {
	if len(text) == 0 {
		return 0
	}
	return (len(text) + MTCharsPerToken - 1) / MTCharsPerToken // Round up
}

// MTEstimateTotalTokens calculates total tokens for multiple texts.
func MTEstimateTotalTokens(texts []string) int {
	total := 0
	for _, text := range texts {
		total += MTEstimateTokens(text)
	}
	return total
}

// MTSmartTruncate preserves important context when text exceeds token limits.
// Strategy: Keep first 20% (context setup) + last 50% (recent turns), drop middle.
// This preserves both initial context and the most recent conversation state.
func MTSmartTruncate(text string, maxTokens int) string {
	if maxTokens <= 0 {
		maxTokens = MTDefaultMaxTokens
	}

	tokens := MTEstimateTokens(text)
	if tokens <= maxTokens {
		return text
	}

	// Calculate character limits
	maxChars := maxTokens * MTCharsPerToken

	keepFirst := int(float64(maxChars) * MTTruncateKeepFirst)
	keepLast := int(float64(maxChars) * MTTruncateKeepLast)

	if len(text) <= keepFirst+keepLast {
		return text
	}

	// Extract first and last portions
	first := text[:keepFirst]
	last := text[len(text)-keepLast:]

	// Add truncation marker
	return first + "\n[... context truncated ...]\n" + last
}

// MTSmartTruncateByTurns preserves turn boundaries when truncating.
// Keeps first 2 turns (context establishment) and last 50% of turns (recent history).
func MTSmartTruncateByTurns(turns []string, maxTokens int) []string {
	if maxTokens <= 0 {
		maxTokens = MTDefaultMaxTokens
	}

	// Calculate total tokens
	totalTokens := 0
	for _, turn := range turns {
		totalTokens += MTEstimateTokens(turn) + 10 // +10 for turn separator overhead
	}

	if totalTokens <= maxTokens {
		return turns
	}

	// Strategy: Keep first 2 turns + last 50% of turns
	if len(turns) <= 4 {
		return turns // Can't meaningfully truncate
	}

	keepFirst := 2
	keepLast := len(turns) / 2
	if keepLast < 2 {
		keepLast = 2
	}

	result := make([]string, 0, keepFirst+keepLast+1)
	result = append(result, turns[:keepFirst]...)
	result = append(result, "[... earlier turns truncated ...]")
	result = append(result, turns[len(turns)-keepLast:]...)

	return result
}

// MTTruncateToLimit truncates text to fit within token limit.
// Simple truncation - use MTSmartTruncate for context-aware truncation.
func MTTruncateToLimit(text string, maxTokens int) string {
	if maxTokens <= 0 {
		maxTokens = MTDefaultMaxTokens
	}

	tokens := MTEstimateTokens(text)
	if tokens <= maxTokens {
		return text
	}

	// Calculate character limit
	maxChars := maxTokens * MTCharsPerToken

	if len(text) <= maxChars {
		return text
	}

	// Simple truncation with ellipsis
	return text[:maxChars-3] + "..."
}

// MTFitsInContext checks if text fits within the given token limit.
func MTFitsInContext(text string, maxTokens int) bool {
	return MTEstimateTokens(text) <= maxTokens
}

// MTFitsInMiniLM checks if text fits within MiniLM/BGE context (512 tokens).
func MTFitsInMiniLM(text string) bool {
	return MTEstimateTokens(text) <= MTMiniLMMaxTokens
}

// MTCombineTurnsForEmbedding combines turns into a single text for embedding.
// Adds turn markers and handles truncation if needed.
func MTCombineTurnsForEmbedding(turns []string, maxTokens int) string {
	if maxTokens <= 0 {
		maxTokens = MTMiniLMMaxTokens
	}

	// First, truncate by turns if needed
	truncated := MTSmartTruncateByTurns(turns, maxTokens)

	// Combine with turn markers
	var combined string
	for i, turn := range truncated {
		if i > 0 {
			combined += " "
		}
		combined += turn
	}

	// Final check - truncate combined text if still too long
	if MTEstimateTokens(combined) > maxTokens {
		combined = MTSmartTruncate(combined, maxTokens)
	}

	return combined
}
