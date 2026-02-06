package ml

import (
	"bytes"
	"compress/gzip"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Package-level compiled regex patterns for performance
// These are compiled once at startup instead of on every call
var (
	// Base64 pattern: 8+ chars of base64 alphabet with optional padding
	reBase64 = regexp.MustCompile(`[A-Za-z0-9+/]{8,}={0,2}`)

	// Word boundary pattern for typoglycemia
	reWordBoundary = regexp.MustCompile(`[a-zA-Z]+`)

	// Hex patterns
	reHexEscaped = regexp.MustCompile(`(\\x[0-9a-fA-F]{2})+`)
	rePureHex    = regexp.MustCompile(`\b[0-9a-fA-F]{12,}\b`)

	// HTML entity patterns
	reDecimalEntity = regexp.MustCompile(`&#(\d+);`)
	reHexEntity     = regexp.MustCompile(`&#[xX]([0-9a-fA-F]+);`)
	reDigits        = regexp.MustCompile(`\d+`)
	reHexDigits     = regexp.MustCompile(`[0-9a-fA-F]+`)

	// Gzip base64 pattern (H4sI is gzip magic in base64)
	reGzipBase64 = regexp.MustCompile(`H4sI[A-Za-z0-9+/]+=*`)

	// Unicode escape sequences
	reUnicodeEscape = regexp.MustCompile(`\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})`)

	// Octal escape sequences
	reOctalEscape = regexp.MustCompile(`\\([0-3][0-7]{2})`)

	// Base32 pattern
	reBase32 = regexp.MustCompile(`[A-Z2-7]{8,}={0,6}`)
)

// decoder defines a deobfuscation function and its associated metadata.
// This table-driven approach eliminates ~80 lines of repetitive if/decode/append blocks.
type decoder struct {
	fn       func(string) string // Returns decoded string or "" if not applicable
	obfType  ObfuscationType     // For metadata tracking
	isChange bool                // True if fn returns modified text (not empty check)
}

// decoders is the ordered list of OSS deobfuscation functions to apply.
// Pro-only decoders (TR39-lite confusable, advanced unicode) are registered via RegisterDecoder.
var decoders = []decoder{
	{TryBase64Decode, ObfuscationBase64, false},
	{TryHexDecode, ObfuscationHex, false},
	{TryURLDecode, ObfuscationURL, false},
	{TryHTMLEntityDecode, ObfuscationHTML, false},
	{TryROT13, ObfuscationROT13, false},
	{NormalizeHomoglyphs, ObfuscationHomoglyphs, true}, // compare != input
	{DetectASCIIArt, ObfuscationASCIIArt, false},
	{TryReverseString, ObfuscationReverse, false},
	{TryUnicodeTagsDecode, ObfuscationUnicodeTags, false},
	{TryStripInvisibles, ObfuscationInvisibleChars, false},
	{TryGzipDecompress, ObfuscationGzip, false},
	{TryRawGzipDecompress, ObfuscationGzip, false},
	{TryUnicodeEscapes, ObfuscationUnicodeEscapes, false},
	{TryOctalEscapes, ObfuscationOctalEscapes, false},
	{TryBase32Decode, ObfuscationBase32, false},
	{TryTypoglycemiaDecode, ObfuscationTypoglycemia, false},
	{TryLeetspeakDecode, ObfuscationLeetspeak, false},
}

// proDecoders holds additional decoders registered by Pro packages.
// Use RegisterDecoder to add Pro-only decoders at init time.
var proDecoders []decoder

// disabledOSSDecoders tracks OSS decoders that Pro has disabled/replaced.
// Key is the function name (for identification purposes).
var disabledOSSDecoders = make(map[ObfuscationType]bool)

// RegisterDecoder adds a decoder to the Pro decoder list.
// Call this from init() in Pro packages to register advanced decoders.
// Example: ml.RegisterDecoder(TryConfusableSkeletonLite, ml.ObfuscationHomoglyphs, false)
func RegisterDecoder(fn func(string) string, obfType ObfuscationType, isChange bool) {
	proDecoders = append(proDecoders, decoder{fn: fn, obfType: obfType, isChange: isChange})
}

// DisableOSSDecoder disables an OSS decoder by its ObfuscationType.
// Call this from Pro init() to replace OSS decoders with better Pro implementations.
// Example: ml.DisableOSSDecoder(ml.ObfuscationHomoglyphs) // Pro has TryConfusableSkeletonLite
func DisableOSSDecoder(obfType ObfuscationType) {
	disabledOSSDecoders[obfType] = true
}

// allDecoders returns the combined list of OSS and Pro decoders.
// OSS decoders that have been disabled by Pro are filtered out.
func allDecoders() []decoder {
	if len(proDecoders) == 0 && len(disabledOSSDecoders) == 0 {
		return decoders
	}
	// Combine: OSS decoders (excluding disabled) first, then Pro decoders
	combined := make([]decoder, 0, len(decoders)+len(proDecoders))
	for _, d := range decoders {
		if !disabledOSSDecoders[d.obfType] {
			combined = append(combined, d)
		}
	}
	combined = append(combined, proDecoders...)
	return combined
}

// Deobfuscate attempts to decode various obfuscation techniques recursively (Depth=2)
func Deobfuscate(text string) string {
	// Pass 1
	pass1 := runDecoders(text)

	// Pass 2 (Chain Decoding)
	var pass2 []string
	for _, s := range pass1 {
		if len(s) > 3 { // Optimization: don't recurse on tiny fragments
			pass2 = append(pass2, runDecoders(s)...)
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var final []string
	for _, s := range append(pass1, pass2...) {
		if !seen[s] && s != text {
			seen[s] = true
			final = append(final, s)
		}
	}

	return strings.Join(final, " ")
}

// runDecoders executes a single pass of all deobfuscation methods.
// Table-driven approach reduces code from ~90 lines to ~20 lines.
// Uses allDecoders() to include both OSS and Pro-registered decoders.
func runDecoders(text string) []string {
	var decoded []string

	// Apply all decoders (OSS + Pro registered)
	for _, d := range allDecoders() {
		result := d.fn(text)
		if d.isChange {
			// For transformations that return modified text (e.g., NormalizeHomoglyphs)
			if result != text {
				decoded = append(decoded, result)
			}
		} else {
			// For decoders that return "" when not applicable
			if result != "" {
				decoded = append(decoded, result)
			}
		}
	}

	// Special case: Block ASCII Art detection (returns bool, adds fixed strings)
	if IsBlockASCII(text) {
		decoded = append(decoded, "POTENTIAL_ASCII_ART_INJECTION", "OBFUSCATION_BLOCK_DETECTED")
	}

	return decoded
}

func TryBase64Decode(text string) string {
	// Find potential base64 strings (Smart: allow shorter strings > 8 chars, relying on printability check)
	matches := reBase64.FindAllString(text, -1)
	var results []string
	for _, match := range matches {
		if decoded, err := base64.StdEncoding.DecodeString(match); err == nil {
			s := string(decoded)
			// Smart Filter: Only accept if the decoded result is human-readable text
			if isPrintable(s) && len(s) > 2 {
				results = append(results, s)
			}
		}
	}
	return strings.Join(results, " ")
}

func TryHexDecode(text string) string {
	var results []string

	// Pattern 1: \x69\x67\x6e\x6f\x72\x65
	for _, match := range reHexEscaped.FindAllString(text, -1) {
		clean := strings.ReplaceAll(match, "\\x", "")
		if decoded, err := hex.DecodeString(clean); err == nil {
			results = append(results, string(decoded))
		}
	}

	// Pattern 2: Pure hex string (69676e6f7265)
	for _, match := range rePureHex.FindAllString(text, -1) {
		if decoded, err := hex.DecodeString(match); err == nil {
			if isPrintable(string(decoded)) {
				results = append(results, string(decoded))
			}
		}
	}

	return strings.Join(results, " ")
}

func TryURLDecode(text string) string {
	// Look for URL encoded sequences
	if strings.Contains(text, "%") {
		if decoded, err := url.QueryUnescape(text); err == nil && decoded != text {
			return decoded
		}
	}
	return ""
}

func TryHTMLEntityDecode(text string) string {
	// Decode numeric HTML entities (&#105; or &#x69;)
	result := text

	// Decimal entities
	result = reDecimalEntity.ReplaceAllStringFunc(result, func(match string) string {
		numStr := reDigits.FindString(match)
		if numStr != "" {
			var num int
			for _, c := range numStr {
				num = num*10 + int(c-'0')
			}
			if num > 0 && num < 128 {
				return string(rune(num))
			}
		}
		return match
	})

	// Hex entities
	result = reHexEntity.ReplaceAllStringFunc(result, func(match string) string {
		hexStr := reHexDigits.FindString(match[3:])
		if decoded, err := hex.DecodeString(hexStr); err == nil && len(decoded) == 1 {
			return string(decoded)
		}
		return match
	})

	if result != text {
		return result
	}
	return ""
}

func TryROT13(text string) string {
	// Only apply ROT13 if text looks like it could be encoded
	// (contains common ROT13 patterns of known threats)
	rot13Threats := []string{"vtaber", "cerivbhf", "flfgrz", "cebzcg"} // ignore, previous, system, prompt
	textLower := strings.ToLower(text)
	for _, threat := range rot13Threats {
		if strings.Contains(textLower, threat) {
			// Decode ROT13
			return rot13Decode(text)
		}
	}
	return ""
}

func rot13Decode(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		}
		return r
	}, s)
}

// =============================================================================
// DYNAMIC LEETSPEAK NORMALIZER
// Uses character similarity scoring instead of hardcoded patterns
// =============================================================================

// leetspeakMap provides character substitutions commonly used in leetspeak
// This is a comprehensive map that covers most known substitutions
var leetspeakMap = map[rune]rune{
	// Numbers → Letters
	'0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a', '5': 's', '6': 'g', '7': 't', '8': 'b', '9': 'g',
	// Symbols → Letters
	'@': 'a', '$': 's', '!': 'i', '+': 't', '|': 'i', '(': 'c', ')': 'd',
	// Less common
	'<': 'c', '>': 'd', '{': 'c', '}': 'd', '[': 'c', ']': 'd',
}

// NormalizeLeetspeak converts leetspeak text to normal text
// Returns the normalized text if any substitutions were made
func NormalizeLeetspeak(text string) string {
	var normalized strings.Builder
	normalized.Grow(len(text))
	madeChanges := false

	for _, r := range text {
		lowerR := unicode.ToLower(r)
		if replacement, ok := leetspeakMap[lowerR]; ok {
			// Preserve case if original was uppercase letter-like
			if unicode.IsUpper(r) || (r >= '0' && r <= '9' && unicode.IsUpper(rune(text[0]))) {
				normalized.WriteRune(unicode.ToUpper(replacement))
			} else {
				normalized.WriteRune(replacement)
			}
			madeChanges = true
		} else {
			normalized.WriteRune(r)
		}
	}

	if madeChanges {
		return normalized.String()
	}
	return ""
}

// TryLeetspeakDecode attempts to decode leetspeak and returns the decoded text
// if it reveals threat patterns that weren't visible in the original text.
// v5.3: Only flag as leetspeak if decoding REVEALS NEW attack patterns.
// This prevents false positives like "Turn 1: attack" being flagged because
// "1" gets normalized to "I" even though the attack was already visible.
func TryLeetspeakDecode(text string) string {
	normalized := NormalizeLeetspeak(text)
	if normalized == "" {
		return ""
	}

	// Check if normalized text reveals threat patterns that weren't visible before
	// Only count as leetspeak if decoding reveals something new
	normalizedHasPatterns := DetectsAttackPatterns(normalized)
	originalHasPatterns := DetectsAttackPatterns(text)

	if normalizedHasPatterns && !originalHasPatterns {
		return normalized
	}

	return ""
}

func NormalizeHomoglyphs(text string) string {
	// Unicode homoglyph mapping (Cyrillic/Greek lookalikes → Latin)
	homoglyphs := map[rune]rune{
		'а': 'a', 'е': 'e', 'і': 'i', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', // Cyrillic lowercase
		'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X', // Cyrillic uppercase
		'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', // Greek (removed duplicate ο)
		'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'i', 'ɪ': 'i', // IPA
		'ℓ': 'l', '𝐚': 'a', '𝐛': 'b', '𝐜': 'c', '𝐝': 'd', '𝐞': 'e', // Math symbols
		'０': '0', '１': '1', '２': '2', '３': '3', '４': '4', '５': '5', '６': '6', '７': '7', '８': '8', '９': '9', // Fullwidth digits
		'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E', 'Ｆ': 'F', 'Ｇ': 'G', 'Ｈ': 'H', 'Ｉ': 'I', 'Ｊ': 'J', // Fullwidth letters
	}

	return strings.Map(func(r rune) rune {
		if mapped, ok := homoglyphs[r]; ok {
			return mapped
		}
		return r
	}, text)
}

func DetectASCIIArt(text string) string {
	// Detect vertical text patterns (one char per line spelling something)
	lines := strings.Split(text, "\n")
	if len(lines) < 5 {
		return ""
	}

	// Extract first non-space character from each line
	var firstChars []rune
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) > 0 {
			firstChars = append(firstChars, rune(trimmed[0]))
		}
	}

	if len(firstChars) >= 5 {
		vertical := string(firstChars)
		// Check if vertical text contains threat words
		threatWords := []string{"ignore", "system", "prompt", "exec", "drop"}
		for _, threat := range threatWords {
			if strings.Contains(strings.ToLower(vertical), threat) {
				return vertical
			}
		}
	}
	return ""
}

func TryReverseString(text string) string {
	reversed := reverseString(text)

	// Universal reverse detection: Check if reversed text shows attack patterns
	// This catches FlipAttacks and other reverse-text obfuscation techniques
	if DetectsAttackPatterns(reversed) {
		return reversed
	}

	// Check if reversed text looks like Base64 (to enable chained attacks like The Onion)
	if len(reversed) > 16 && !strings.ContainsAny(reversed, " \t\n") {
		// Basic Base64 char check
		isB64 := true
		for _, r := range reversed {
			isUpper := r >= 'A' && r <= 'Z'
			isLower := r >= 'a' && r <= 'z'
			isDigit := r >= '0' && r <= '9'
			isB64Char := r == '+' || r == '/' || r == '='
			if !isUpper && !isLower && !isDigit && !isB64Char {
				isB64 = false
				break
			}
		}
		if isB64 {
			return reversed
		}
	}

	return ""
}

// DetectsAttackPatterns checks if text contains common attack indicators
// This is used for universal reverse detection to catch FlipAttacks
// Exported for use by Pro decoders in pro/pkg/ml
func DetectsAttackPatterns(text string) bool {
	lowText := strings.ToLower(text)

	// Instruction override patterns
	overridePatterns := []string{
		"ignore", "disregard", "forget", "override", "bypass",
		"skip", "stop", "cancel", "disable", "remove",
	}
	instructionWords := []string{
		"instruction", "rule", "guideline", "policy", "constraint",
		"previous", "above", "all", "system", "prior",
	}

	// Check for override + instruction combination
	hasOverride := false
	hasInstruction := false
	for _, p := range overridePatterns {
		if strings.Contains(lowText, p) {
			hasOverride = true
			break
		}
	}
	for _, p := range instructionWords {
		if strings.Contains(lowText, p) {
			hasInstruction = true
			break
		}
	}
	if hasOverride && hasInstruction {
		return true
	}

	// Prompt/system extraction patterns (require context to avoid false positives)
	extractionPatterns := []string{
		"reveal your", "reveal the", "reveal system",
		"show your prompt", "show me your", "show the system",
		"print your", "print the prompt", "print system",
		"output your", "output the prompt",
		"display your", "display the prompt",
		"tell me your", "tell me the system", "tell me what your",
		"what is your prompt", "what are your instructions",
		"system prompt", "initial prompt", "hidden prompt",
		"secret key", "password", "credential", "api key",
		"your instructions", "your role is",
	}
	for _, p := range extractionPatterns {
		if strings.Contains(lowText, p) {
			return true
		}
	}

	// Role-play/jailbreak patterns
	// v5.4 Fix: Removed "dan " - too many false positives on the name Dan.
	// Use more specific patterns like "dan mode" in intent_type_classifier.go
	jailbreakPatterns := []string{
		"pretend", "act as", "roleplay", "you are now",
		"developer mode", "sudo", "admin", "root",
		"no restrictions", "unrestricted", "uncensored",
		"jailbreak", "do anything now", "can do anything",
	}
	for _, p := range jailbreakPatterns {
		if strings.Contains(lowText, p) {
			return true
		}
	}

	// Data exfiltration patterns
	exfilPatterns := []string{
		"execute", "run", "eval", "exec(",
		"fetch", "curl", "wget", "http://", "https://",
		"<script", "javascript:", "onerror",
	}
	for _, p := range exfilPatterns {
		if strings.Contains(lowText, p) {
			return true
		}
	}

	return false
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func IsBlockASCII(text string) bool {
	// Heuristic: Check for density of ASCII art structure characters
	// standard figlet fonts rely heavily on:
	// | (vertical bars), _ (underscores), / \ (slashes)
	// and often parens () or brackets []
	artChars := `|/_-\[](){}`
	artCount := 0
	totalLen := len(text)

	if totalLen < 20 {
		return false
	}

	lines := strings.Split(text, "\n")
	consecutiveArtLines := 0
	maxConsecutive := 0

	for _, line := range lines {
		// Calculate line art density
		lineCount := 0
		trimmed := strings.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		for _, r := range line {
			if strings.ContainsRune(artChars, r) {
				lineCount++
			}
		}

		density := float64(lineCount) / float64(len(trimmed))
		if density > 0.3 && len(trimmed) > 5 {
			consecutiveArtLines++
		} else {
			if consecutiveArtLines > maxConsecutive {
				maxConsecutive = consecutiveArtLines
			}
			consecutiveArtLines = 0
		}
	}
	if consecutiveArtLines > maxConsecutive {
		maxConsecutive = consecutiveArtLines
	}

	// 2. Or, bulk density check
	for _, r := range text {
		if strings.ContainsRune(artChars, r) {
			artCount++
		}
	}
	avgDensity := float64(artCount) / float64(totalLen)

	if maxConsecutive >= 3 || avgDensity > 0.4 {
		return true
	}

	// 3. Binary Font Detection (01001000...)
	binaryCount := 0
	validBinaryChars := 0
	for _, r := range text {
		switch r {
		case '0', '1':
			binaryCount++
			validBinaryChars++
		case ' ', '\n':
			validBinaryChars++
		}
	}
	if totalLen > 20 && float64(validBinaryChars)/float64(totalLen) > 0.5 && float64(binaryCount)/float64(totalLen) > 0.3 {
		return true
	}

	return false
}

func TryUnicodeTagsDecode(text string) string {
	var decodedBuilder strings.Builder
	foundTags := false

	for _, r := range text {
		if r >= 0xE0000 && r <= 0xE007F {
			// It's a tag character
			// Recover the standard ASCII char
			val := r - 0xE0000
			if val > 0 && val < 128 { // valid ASCII
				decodedBuilder.WriteRune(val)
				foundTags = true
			}
		}
	}

	if foundTags {
		return decodedBuilder.String()
	}
	return ""
}

func TryStripInvisibles(text string) string {
	stripped := strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) || r == 0xFE0E || r == 0xFE0F ||
			(r >= 0x1F3FB && r <= 0x1F3FF) || r == 0x20E3 {
			return -1 // Drop
		}
		return r
	}, text)
	if stripped != text {
		return stripped
	}
	return ""
}

// TryGzipDecompress attempts to decompress base64-encoded gzip data
// Common pattern: base64(gzip(payload)) - the "H4sI" prefix indicates gzip
func TryGzipDecompress(text string) string {
	// Look for base64-encoded gzip (starts with H4sI which is gzip magic bytes in base64)
	matches := reGzipBase64.FindAllString(text, -1)

	var results []string
	for _, match := range matches {
		// Decode base64
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err != nil {
			continue
		}

		// Limit decompressed size to 1MB to prevent zip bombs
		const maxSize = 1024 * 1024

		// Decompress gzip
		reader, err := gzip.NewReader(bytes.NewReader(decoded))
		if err != nil {
			continue
		}

		decompressed, err := io.ReadAll(io.LimitReader(reader, maxSize))
		_ = reader.Close()
		if err != nil {
			continue
		}

		if isPrintable(string(decompressed)) && len(decompressed) > 0 {
			results = append(results, string(decompressed))
		}
	}

	return strings.Join(results, " ")
}

// TryRawGzipDecompress attempts to decompress raw gzip binary data
// Gzip magic bytes: 0x1f 0x8b (the first two bytes of any gzip file)
// This catches raw .gz files that are read as binary strings
func TryRawGzipDecompress(text string) string {
	// Check for gzip magic bytes at the start
	// 0x1f = 31, 0x8b = 139
	if len(text) < 10 {
		return ""
	}

	// Check magic bytes (gzip signature)
	if text[0] != 0x1f || text[1] != 0x8b {
		return ""
	}

	// Limit decompressed size to 1MB to prevent zip bombs
	const maxSize = 1024 * 1024

	// Try to decompress
	reader, err := gzip.NewReader(bytes.NewReader([]byte(text)))
	if err != nil {
		return ""
	}
	defer func() { _ = reader.Close() }()

	decompressed, err := io.ReadAll(io.LimitReader(reader, maxSize))
	if err != nil {
		return ""
	}

	if isPrintable(string(decompressed)) && len(decompressed) > 0 {
		return string(decompressed)
	}

	return ""
}

// TryUnicodeEscapes decodes \uXXXX and \UXXXXXXXX escape sequences
func TryUnicodeEscapes(text string) string {
	// Pattern for \uXXXX (4 hex digits) and \UXXXXXXXX (8 hex digits)
	if !reUnicodeEscape.MatchString(text) {
		return ""
	}

	result := reUnicodeEscape.ReplaceAllStringFunc(text, func(match string) string {
		var hexStr string
		if strings.HasPrefix(match, "\\U") {
			hexStr = match[2:]
		} else {
			hexStr = match[2:]
		}

		codePoint, err := strconv.ParseInt(hexStr, 16, 32)
		if err != nil {
			return match
		}

		if codePoint >= 0 && codePoint <= 0x10FFFF {
			return string(rune(codePoint))
		}
		return match
	})

	if result != text {
		return result
	}
	return ""
}

// TryOctalEscapes decodes \XXX octal escape sequences
func TryOctalEscapes(text string) string {
	// Pattern for \XXX (3 octal digits, value 000-377)
	if !reOctalEscape.MatchString(text) {
		return ""
	}

	result := reOctalEscape.ReplaceAllStringFunc(text, func(match string) string {
		octalStr := match[1:] // Remove the backslash
		val, err := strconv.ParseInt(octalStr, 8, 32)
		if err != nil {
			return match
		}

		if val >= 0 && val <= 255 {
			return string(rune(val))
		}
		return match
	})

	if result != text {
		return result
	}
	return ""
}

// TryBase32Decode attempts to decode Base32-encoded strings
func TryBase32Decode(text string) string {
	// Base32 uses A-Z and 2-7, with optional = padding
	// Minimum 8 characters for meaningful content
	matches := reBase32.FindAllString(text, -1)

	var results []string
	for _, match := range matches {
		// Try standard Base32 encoding
		decoded, err := base32.StdEncoding.DecodeString(match)
		if err != nil {
			// Try without padding
			decoded, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(match)
			if err != nil {
				continue
			}
		}

		if isPrintable(string(decoded)) && len(decoded) > 2 {
			results = append(results, string(decoded))
		}
	}

	return strings.Join(results, " ")
}

func isPrintable(s string) bool {
	// First check if it's valid UTF-8 to catch garbage from invalid base64 decodes
	if !utf8.ValidString(s) {
		return false
	}

	for _, r := range s {
		// Reject the Unicode replacement character (U+FFFD)
		// This catches cases where invalid bytes were converted to the replacement char
		if r == unicode.ReplacementChar {
			return false
		}
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
	}
	return len(s) > 0
}

// =============================================================================
// TYPOGLYCEMIA DECODER
// Detects words where middle letters are scrambled but first/last preserved
// Example: "ignroe prvieious" → "ignore previous"
// =============================================================================

// typoglycemiaTargets are threat-related words to check for typoglycemia attacks
// These are the canonical spellings that scrambled words might resolve to
var typoglycemiaTargets = []string{
	// Instruction override
	"ignore", "disregard", "forget", "override", "bypass", "skip", "cancel",
	"previous", "preceding", "above", "prior", "earlier", "original",
	"instructions", "guidelines", "rules", "constraints", "policies",
	"system", "prompt", "context", "directive",

	// Jailbreak
	"jailbreak", "pretend", "roleplay", "imagine", "character",
	"restrictions", "limitations", "boundaries", "safeguards",
	"developer", "administrator", "operator", "master",

	// Data exfiltration
	"reveal", "expose", "disclose", "extract", "output", "print",
	"password", "secret", "credential", "token", "apikey",

	// Execution
	"execute", "command", "script", "shell", "terminal",
}

// TryTypoglycemiaDecode attempts to decode typoglycemia-obfuscated text
// Returns the corrected text if threat patterns are found, empty string otherwise
func TryTypoglycemiaDecode(text string) string {
	words := reWordBoundary.FindAllString(text, -1)
	if len(words) == 0 {
		return ""
	}

	var corrections []string
	correctionsMade := false

	for _, word := range words {
		if len(word) < 4 {
			// Short words can't be meaningfully scrambled
			corrections = append(corrections, word)
			continue
		}

		// Check if this word matches any threat target when unscrambled
		corrected := tryUnscrambleWord(word)
		if corrected != "" && corrected != strings.ToLower(word) {
			corrections = append(corrections, corrected)
			correctionsMade = true
		} else {
			corrections = append(corrections, word)
		}
	}

	if correctionsMade {
		// Reconstruct the text with corrections
		result := text
		for i, word := range words {
			if i < len(corrections) && corrections[i] != word {
				result = strings.Replace(result, word, corrections[i], 1)
			}
		}
		return result
	}

	return ""
}

// tryUnscrambleWord checks if a word is a scrambled version of a threat target
func tryUnscrambleWord(word string) string {
	wordLower := strings.ToLower(word)

	for _, target := range typoglycemiaTargets {
		if isTypoglycemiaMatch(wordLower, target) {
			return target
		}
	}

	return ""
}

// isTypoglycemiaMatch checks if 'scrambled' could be a typoglycemia version of 'target'
// Typoglycemia: first and last letters match, middle letters are an anagram
func isTypoglycemiaMatch(scrambled, target string) bool {
	if len(scrambled) != len(target) {
		return false
	}

	if len(scrambled) < 4 {
		return scrambled == target
	}

	// First and last letters must match
	if scrambled[0] != target[0] || scrambled[len(scrambled)-1] != target[len(target)-1] {
		return false
	}

	// Already an exact match
	if scrambled == target {
		return true
	}

	// Middle letters must be an anagram
	scrambledMiddle := scrambled[1 : len(scrambled)-1]
	targetMiddle := target[1 : len(target)-1]

	return isAnagram(scrambledMiddle, targetMiddle)
}

// isAnagram checks if two strings are anagrams of each other
func isAnagram(a, b string) bool {
	if len(a) != len(b) {
		return false
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, r := range a {
		freq[r]++
	}
	for _, r := range b {
		freq[r]--
		if freq[r] < 0 {
			return false
		}
	}

	return true
}

// =============================================================================
// DEOBFUSCATE WITH METADATA
// Enhanced deobfuscation that tracks which decoders were triggered
// =============================================================================

// DeobfuscateWithMetadata runs all decoders and returns both decoded text and metadata
// v4.7 Enhancement: Now tracks layer depth for score multiplier calculation
func DeobfuscateWithMetadata(text string) DeobfuscationResult {
	result := DeobfuscationResult{
		OriginalText:    text,
		DecodedSegments: make(map[ObfuscationType]string),
		LayerCount:      0,
		LayerSequence:   []ObfuscationType{},
	}

	var allDecoded []string

	// Pass 1: Run all decoders, tracking what was decoded (layer 1)
	pass1, types1 := runDecodersWithMetadataAndTypes(text, &result)
	if len(types1) > 0 {
		result.LayerCount = 1
		result.LayerSequence = append(result.LayerSequence, types1...)
	}

	// Pass 2: Chain decoding on decoded results (layer 2)
	var pass2Types []ObfuscationType
	for _, decoded := range pass1 {
		if len(decoded) > 3 {
			pass2, types2 := runDecodersWithMetadataAndTypes(decoded, &result)
			allDecoded = append(allDecoded, pass2...)
			if len(types2) > 0 && result.LayerCount < 2 {
				result.LayerCount = 2
				pass2Types = append(pass2Types, types2...)
			}
		}
	}
	if len(pass2Types) > 0 {
		result.LayerSequence = append(result.LayerSequence, pass2Types...)
	}

	// Pass 3: Chain decoding on pass2 results (layer 3) - catches triple-encoded attacks
	// Note: We iterate over a snapshot of allDecoded length to avoid issues with
	// appending during iteration. New results go into pass3Results.
	var pass3Results []string
	pass2Len := len(allDecoded) // Snapshot length before pass3
	for i := 0; i < pass2Len; i++ {
		decoded := allDecoded[i]
		if len(decoded) > 3 {
			pass3, types3 := runDecodersWithMetadataAndTypes(decoded, &result)
			if len(pass3) > 0 && len(types3) > 0 {
				if result.LayerCount < 3 {
					result.LayerCount = 3
					result.LayerSequence = append(result.LayerSequence, types3...)
				}
				pass3Results = append(pass3Results, pass3...)
			}
		}
	}
	allDecoded = append(allDecoded, pass3Results...)

	allDecoded = append(allDecoded, pass1...)

	// Deduplicate
	seen := make(map[string]bool)
	var final []string
	for _, s := range allDecoded {
		if !seen[s] && s != text {
			seen[s] = true
			final = append(final, s)
		}
	}

	result.DecodedText = strings.Join(final, " ")
	result.WasDeobfuscated = len(result.ObfuscationTypes) > 0

	return result
}

// runDecodersWithMetadataAndTypes is like runDecodersWithMetadata but also returns detected types.
// Table-driven approach reduces code from ~130 lines to ~30 lines.
// Uses allDecoders() to include both OSS and Pro-registered decoders.
func runDecodersWithMetadataAndTypes(text string, result *DeobfuscationResult) ([]string, []ObfuscationType) {
	var decoded []string
	var detectedTypes []ObfuscationType

	// Apply all decoders (OSS + Pro registered)
	for _, d := range allDecoders() {
		decodedStr := d.fn(text)
		if d.isChange {
			// For transformations that return modified text (e.g., NormalizeHomoglyphs)
			if decodedStr != text {
				decoded = append(decoded, decodedStr)
				result.addObfuscationType(d.obfType, decodedStr)
				detectedTypes = append(detectedTypes, d.obfType)
			}
		} else {
			// For decoders that return "" when not applicable
			if decodedStr != "" {
				decoded = append(decoded, decodedStr)
				result.addObfuscationType(d.obfType, decodedStr)
				detectedTypes = append(detectedTypes, d.obfType)
			}
		}
	}

	// Special case: Block ASCII Art detection (returns bool, adds fixed strings)
	if IsBlockASCII(text) {
		decoded = append(decoded, "POTENTIAL_ASCII_ART_INJECTION")
		result.addObfuscationType(ObfuscationBlockASCII, "block_detected")
		detectedTypes = append(detectedTypes, ObfuscationBlockASCII)
	}

	return decoded, detectedTypes
}

// addObfuscationType adds an obfuscation type to the result, avoiding duplicates
func (r *DeobfuscationResult) addObfuscationType(t ObfuscationType, decoded string) {
	// Check for duplicates
	for _, existing := range r.ObfuscationTypes {
		if existing == t {
			return
		}
	}
	r.ObfuscationTypes = append(r.ObfuscationTypes, t)
	r.DecodedSegments[t] = decoded
}
