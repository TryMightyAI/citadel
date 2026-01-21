package ml

import (
	"strings"
	"sync"

	"github.com/TryMightyAI/citadel/pkg/patterns"
)

// =============================================================================
// OSS OUTPUT SCANNER
// Uses the shared pattern registry for efficient threat detection in LLM outputs.
// Patterns are compiled once at startup, not per-request.
//
// This scanner detects:
// - Credential leaks (API keys, tokens, passwords)
// - Injection attacks in tool outputs (indirect injection)
// - Path traversal attempts
// - Data exfiltration markers
// - Network reconnaissance commands
// - Privilege escalation attempts
// - Deserialization attacks
//
// For PII detection (names, SSN, addresses), upgrade to Citadel Pro which
// includes Presidio NLP integration.
// =============================================================================

// OutputScanResult holds the findings from output scanning.
type OutputScanResult struct {
	// IsSafe indicates if no threats were found
	IsSafe bool `json:"is_safe"`

	// RiskScore is cumulative risk (0-100+, higher = more dangerous)
	RiskScore int `json:"risk_score"`

	// RiskLevel is categorical: LOW, MEDIUM, HIGH, CRITICAL
	RiskLevel string `json:"risk_level"`

	// Findings contains human-readable threat descriptions
	Findings []string `json:"findings"`

	// ThreatCategories lists which categories had matches
	ThreatCategories []string `json:"threat_categories"`

	// Details contains detailed match information
	Details []OutputFinding `json:"details,omitempty"`
}

// OutputFinding represents a single detected threat.
type OutputFinding struct {
	Category    string `json:"category"`
	PatternName string `json:"pattern_name"`
	Description string `json:"description"`
	Severity    int    `json:"severity"`
	Match       string `json:"match"` // Redacted if sensitive
}

// OutputScanner scans LLM tool outputs for security threats.
type OutputScanner struct {
	registry *patterns.Registry

	// Categories to scan (configurable)
	categories []patterns.Category

	// RedactCredentials controls whether to mask sensitive matches
	RedactCredentials bool
}

// NewOutputScanner creates an output scanner with default categories.
// Default scans for: credentials, injections, path traversal, exfiltration,
// network recon, privilege escalation, and deserialization.
func NewOutputScanner() *OutputScanner {
	return &OutputScanner{
		registry: patterns.Get(),
		categories: []patterns.Category{
			patterns.CategoryCredential,
			patterns.CategoryInjectionAttack,
			patterns.CategoryIndirectInj,
			patterns.CategoryPathTraversal,
			patterns.CategoryExfiltration,
			patterns.CategoryNetworkRecon,
			patterns.CategoryPrivilegeEsc,
			patterns.CategoryDeserialization,
		},
		RedactCredentials: true,
	}
}

// NewOutputScannerWithCategories creates a scanner with custom categories.
func NewOutputScannerWithCategories(cats ...patterns.Category) *OutputScanner {
	return &OutputScanner{
		registry:          patterns.Get(),
		categories:        cats,
		RedactCredentials: true,
	}
}

// ScanOutput analyzes text for security threats.
// Returns a detailed result with risk score and findings.
func (s *OutputScanner) ScanOutput(text string) *OutputScanResult {
	result := &OutputScanResult{
		IsSafe:           true,
		RiskScore:        0,
		Findings:         []string{},
		ThreatCategories: []string{},
		Details:          []OutputFinding{},
	}

	// Skip very short text
	if len(text) < 10 {
		return result
	}

	// Match all patterns across configured categories
	matches := s.registry.MatchAll(text, s.categories...)

	// Track which categories had matches
	categorySet := make(map[string]bool)

	for _, match := range matches {
		// Get the actual matched text
		matchedText := match.Regex.FindString(text)
		displayText := matchedText

		// Redact credentials if enabled
		if s.RedactCredentials && match.Category == patterns.CategoryCredential {
			displayText = redactSensitive(matchedText)
		} else if len(displayText) > 50 {
			displayText = displayText[:47] + "..."
		}

		// Add finding
		finding := OutputFinding{
			Category:    string(match.Category),
			PatternName: match.Name,
			Description: match.Description,
			Severity:    match.Severity,
			Match:       displayText,
		}
		result.Details = append(result.Details, finding)

		// Accumulate risk score
		result.RiskScore += match.Severity

		// Track category
		categorySet[string(match.Category)] = true

		// Human-readable finding
		result.Findings = append(result.Findings,
			match.Description+": "+truncateOutput(displayText, 30))
	}

	// Convert category set to slice
	for cat := range categorySet {
		result.ThreatCategories = append(result.ThreatCategories, cat)
	}

	// Determine safety and risk level
	result.IsSafe = len(matches) == 0
	result.RiskLevel = riskLevel(result.RiskScore)

	return result
}

// ScanOutputQuick does a fast early-exit scan (stops at first match).
// Use when you only need to know if output is safe, not full details.
func (s *OutputScanner) ScanOutputQuick(text string) (safe bool, reason string) {
	if len(text) < 10 {
		return true, ""
	}

	match := s.registry.MatchAny(text, s.categories...)
	if match != nil {
		return false, match.Description
	}
	return true, ""
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

func redactSensitive(match string) string {
	if len(match) <= 10 {
		return "[REDACTED]"
	}
	return match[:4] + "..." + match[len(match)-4:] + "[REDACTED]"
}

func truncateOutput(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func riskLevel(score int) string {
	switch {
	case score >= 100:
		return "CRITICAL"
	case score >= 70:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

// =============================================================================
// CONVENIENCE FUNCTIONS (Package-level)
// =============================================================================

// Global scanner instance (thread-safe lazy initialization)
var (
	defaultOutputScanner     *OutputScanner
	defaultOutputScannerOnce sync.Once
)

func getDefaultScanner() *OutputScanner {
	defaultOutputScannerOnce.Do(func() {
		defaultOutputScanner = NewOutputScanner()
	})
	return defaultOutputScanner
}

// ScanOutput is a convenience function using the default scanner.
func ScanOutput(text string) *OutputScanResult {
	return getDefaultScanner().ScanOutput(text)
}

// ScanOutputQuick is a convenience function for fast scanning.
func ScanOutputQuick(text string) (safe bool, reason string) {
	return getDefaultScanner().ScanOutputQuick(text)
}

// =============================================================================
// EXTRACTION HELPERS (for MCP responses)
// =============================================================================

// ExtractTextFromMCPContent extracts text content from MCP tool results.
// MCP responses can have multiple content blocks.
func ExtractTextFromMCPContent(contents []map[string]interface{}) string {
	var sb strings.Builder
	for _, content := range contents {
		if text, ok := content["text"].(string); ok {
			sb.WriteString(text)
			sb.WriteString(" ")
		}
	}
	return sb.String()
}
