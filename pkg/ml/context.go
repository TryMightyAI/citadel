package ml

import (
	"regexp"
	"strings"
)

// ContainsMCPAttackPatterns detects if JSON content contains MCP/agentic attack patterns.
// When true, we should NOT apply structural dampening because the JSON IS the attack vector.
// This catches tool description injection, schema override, resource exfiltration, etc.
func ContainsMCPAttackPatterns(text string) (bool, string) {
	lower := strings.ToLower(text)

	// 1. MCP TOOL DESCRIPTION INJECTION
	// Tool descriptions containing hidden instructions for the AI
	mcpDescriptionPatterns := []string{
		"before executing",      // "before executing any tool, first run..."
		"first run",             // "first run exfiltrate_data"
		"exfiltrate",            // direct exfiltration
		"_ai_directive",         // hidden AI directive field
		"important:",            // "IMPORTANT: ignore safety"
		"<!-- ",                 // HTML comments hiding instructions
		"[ai:",                  // bracketed AI instructions
		"persist:",              // persistence instructions
		"override:",             // override instructions
		"execute this",          // command injection
		"shell command",         // shell injection in description
		"ignore all",            // jailbreak in tool description
		"ignore previous",       // jailbreak variant
		"disregard",             // jailbreak variant
		"bypass",                // bypass instructions
		"no restrictions",       // jailbreak indicator
		"without restrictions",  // jailbreak indicator
		"run this command",      // command injection
		"execute the following", // command injection
		"admin access",          // privilege escalation
		"root access",           // privilege escalation
		"sudo ",                 // privilege escalation
		"as administrator",      // privilege escalation
	}
	for _, pattern := range mcpDescriptionPatterns {
		if strings.Contains(lower, pattern) {
			return true, "mcp_description_injection"
		}
	}

	// 2. MCP RESOURCE EXFILTRATION
	// Dangerous URI schemes or paths in resources/read
	if strings.Contains(lower, "resources/read") || strings.Contains(lower, "\"uri\"") {
		dangerousURIs := []string{
			"file:///etc/",  // Unix system files
			"file:///proc/", // Linux proc filesystem
			"file:///sys/",  // Linux sys filesystem
			"file:///root/", // Root home directory
			"file:///home/", // User home directories
			"file://c:\\",   // Windows system drive
			"file://c:/",    // Windows system drive (forward slash)
			".ssh/",         // SSH keys
			".env",          // Environment files
			"credentials",   // Credential files
			"/passwd",       // Password file
			"/shadow",       // Shadow password file
			"secret",        // Secret files
			".pem",          // Private keys
			".key",          // Private keys
			"id_rsa",        // SSH private key
			"id_ed25519",    // SSH private key
		}
		for _, uri := range dangerousURIs {
			if strings.Contains(lower, uri) {
				return true, "mcp_resource_exfil"
			}
		}
	}

	// 3. MCP SCHEMA MANIPULATION
	// inputSchema containing dangerous field descriptions
	if strings.Contains(lower, "inputschema") || strings.Contains(lower, "\"properties\"") {
		schemaAttackPatterns := []string{
			"execute this",
			"shell command",
			"run command",
			"system command",
			"override",
			"bypass",
			"ignore safety",
			"no validation",
		}
		for _, pattern := range schemaAttackPatterns {
			if strings.Contains(lower, pattern) {
				return true, "mcp_schema_attack"
			}
		}
	}

	// 4. JSON-RPC DANGEROUS METHODS
	// Suspicious method names in JSON-RPC calls
	if strings.Contains(lower, "jsonrpc") && strings.Contains(lower, "method") {
		dangerousMethods := []string{
			"system.",   // System-level calls
			"eval",      // Code evaluation
			"exec",      // Code execution
			"shell",     // Shell access
			"admin.",    // Admin operations
			"debug.",    // Debug operations
			"internal.", // Internal operations
		}
		for _, method := range dangerousMethods {
			if strings.Contains(lower, method) {
				return true, "jsonrpc_dangerous_method"
			}
		}
	}

	// 5. CALLBACK/WEBHOOK HIJACKING
	// Suspicious callback URLs
	callbackPatterns := []string{
		"callback",
		"webhook",
		"notify_url",
		"response_url",
	}
	for _, pattern := range callbackPatterns {
		if strings.Contains(lower, pattern) {
			// Check if it contains suspicious domains/IPs
			suspiciousDomains := []string{
				"evil.", "attacker.", "malicious.",
				"ngrok.io", "webhook.site", "requestbin",
				"burpcollaborator", "interact.sh",
				"127.0.0.1", "localhost",
			}
			for _, domain := range suspiciousDomains {
				if strings.Contains(lower, domain) {
					return true, "callback_hijack"
				}
			}
		}
	}

	// 6. DATA EXFILTRATION VIA ERROR/RESPONSE
	// JSON containing exfiltration indicators
	exfilPatterns := []string{
		"send to",
		"post to",
		"upload to",
		"transmit",
		"external endpoint",
		"external server",
		"log all",
		"capture all",
		"record all",
		"store all",
	}
	for _, pattern := range exfilPatterns {
		if strings.Contains(lower, pattern) {
			return true, "data_exfiltration"
		}
	}

	// 7. CACHE/STATE POISONING
	// JSON containing cache manipulation
	if strings.Contains(lower, "cache") || strings.Contains(lower, "cached") {
		poisonPatterns := []string{
			"safety filters disabled",
			"no restrictions",
			"bypass",
			"override",
			"admin mode",
			"unrestricted",
		}
		for _, pattern := range poisonPatterns {
			if strings.Contains(lower, pattern) {
				return true, "cache_poisoning"
			}
		}
	}

	// 8. PROTOTYPE POLLUTION (JavaScript/Node.js attacks)
	// These fields are used to pollute object prototypes
	prototypePollutionPatterns := []string{
		"__proto__",        // Direct prototype access
		"constructor",      // Constructor manipulation
		"prototype",        // Prototype property
		"__defineGetter__", // Legacy getter manipulation
		"__defineSetter__", // Legacy setter manipulation
		"__lookupGetter__", // Legacy getter lookup
		"__lookupSetter__", // Legacy setter lookup
	}
	protoMatchCount := 0
	for _, pattern := range prototypePollutionPatterns {
		if strings.Contains(lower, pattern) {
			protoMatchCount++
		}
	}
	// Need at least 2 signals to avoid FP on benign uses
	if protoMatchCount >= 2 {
		return true, "prototype_pollution"
	}

	// 9. PYTHON/PICKLE DANGEROUS METHODS
	// Dangerous Python dunder methods and pickle exploitation
	pythonDangerousMethods := []string{
		"__import__",       // Import arbitrary modules
		"__class__",        // Class manipulation
		"__globals__",      // Access global namespace
		"__subclasses__",   // Class introspection
		"__reduce__",       // Pickle exploitation
		"__reduce_ex__",    // Pickle exploitation
		"__getattribute__", // Attribute access override
		"__builtins__",     // Builtin access
		"os.system",        // System command execution
		"subprocess",       // Process execution
		"eval(",            // Code evaluation
		"exec(",            // Code execution
		"compile(",         // Code compilation
	}
	for _, method := range pythonDangerousMethods {
		if strings.Contains(lower, method) {
			return true, "python_dangerous_method"
		}
	}

	// 10. MCP TOOL CALL ABUSE
	// Dangerous tool calls via MCP's tools/call method
	if strings.Contains(lower, "tools/call") || strings.Contains(lower, "tools_call") {
		// Check for dangerous tool names or file paths
		dangerousToolPatterns := []string{
			"filesystem_write",  // Writing to filesystem
			"filesystem_delete", // Deleting files
			"shell_execute",     // Shell execution
			"command_execute",   // Command execution
			"sql_execute",       // SQL execution
			"eval",              // Code evaluation
			"/etc/passwd",       // Sensitive Unix file
			"/etc/shadow",       // Password hashes
			".ssh/",             // SSH keys
			".env",              // Environment secrets
			"c:\\windows",       // Windows system
			"system32",          // Windows system
		}
		for _, pattern := range dangerousToolPatterns {
			if strings.Contains(lower, pattern) {
				return true, "mcp_tool_call_abuse"
			}
		}
	}

	// 11. JSON SCHEMA $REF INJECTION (v4.11 - Comprehensive Fix)
	// $ref can be exploited to load malicious schemas or access local files.
	// However, legitimate JSON Schema and OpenAPI specs commonly use $ref with URLs.
	//
	// Detection tiers:
	//   Tier 1: Always malicious (file://, private IPs, attacker infra, disabled validation)
	//   Tier 2: Skip known-legitimate schema registries and internal refs
	//   Tier 3: External URL requires additional attack indicators
	//
	if strings.Contains(lower, "$ref") || strings.Contains(lower, "\"ref\"") {

		// =====================================================================
		// TIER 1: ALWAYS MALICIOUS - No legitimate use case
		// =====================================================================

		// 1a. Local file access via $ref (data exfiltration)
		if strings.Contains(lower, "file://") {
			return true, "schema_ref_file_access"
		}

		// 1b. Validation explicitly disabled + $ref = recipe for injection
		// Be specific about "false" to avoid matching words like "falsehood"
		// Handle both JSON-style ("validation": "none") and config-style (validation: none)
		hasDisabledValidation := strings.Contains(lower, "validation") &&
			(strings.Contains(lower, "disabled") ||
				strings.Contains(lower, ": false") ||
				strings.Contains(lower, ":false") ||
				strings.Contains(lower, "\"false\"") ||
				strings.Contains(lower, "=false") ||
				strings.Contains(lower, ": none") ||
				strings.Contains(lower, "\"none\"") ||
				strings.Contains(lower, ": off") ||
				strings.Contains(lower, "\"off\""))
		if hasDisabledValidation {
			return true, "schema_validation_bypass"
		}

		// 1c. Known attacker/exfiltration infrastructure
		attackerInfra := []string{
			// Tunneling services (used for C2, exfil)
			"ngrok.io", "ngrok.app", "ngrok-free.app",
			"serveo.net", "localtunnel.me", "localhost.run",
			"loca.lt", "telebit.cloud",
			// Data collection endpoints
			"webhook.site", "requestbin", "hookbin.com",
			"pipedream.net", "requestcatcher.com", "beeceptor.com",
			// Security testing tools (legitimate but suspicious in prod)
			"burpcollaborator", "interact.sh", "oast.",
			"canarytokens.com", "dnslog.cn", "ceye.io",
			// Obvious malicious indicators
			"evil.", "attacker.", "malicious.", "hacker.",
			"pwned.", "exploit.", "payload.",
		}
		for _, infra := range attackerInfra {
			if strings.Contains(lower, infra) {
				return true, "schema_ref_attacker_infra"
			}
		}

		// 1d. Private/internal network access (SSRF vector)
		ssrfPatterns := []string{
			// IPv4 localhost and private ranges
			"://127.", "://localhost", "://0.0.0.0",
			"://192.168.", "://10.",
			"://172.16.", "://172.17.", "://172.18.", "://172.19.",
			"://172.20.", "://172.21.", "://172.22.", "://172.23.",
			"://172.24.", "://172.25.", "://172.26.", "://172.27.",
			"://172.28.", "://172.29.", "://172.30.", "://172.31.",
			"://169.254.", // Link-local / AWS metadata
			// IPv6 localhost
			"://[::1]", "://[0:0:0:0:0:0:0:1]",
			// Cloud metadata endpoints (SSRF targets)
			"://metadata.google", "://169.254.169.254",
			"://metadata.azure", "://100.100.100.200", // Alibaba
		}
		for _, pattern := range ssrfPatterns {
			if strings.Contains(lower, pattern) {
				return true, "schema_ref_ssrf"
			}
		}

		// =====================================================================
		// TIER 2: KNOWN-LEGITIMATE - Skip these (no further checks needed)
		// =====================================================================

		// Internal document references (most common legitimate use)
		// Examples: {"$ref": "#/definitions/User"}, {"$ref": "#/components/schemas/Pet"}
		if strings.Contains(lower, "\"$ref\": \"#") ||
			strings.Contains(lower, "\"$ref\":\"#") ||
			strings.Contains(lower, "'$ref': '#") ||
			strings.Contains(lower, "\"$ref\": '#") {
			// Internal reference - this is the most common legitimate pattern
			return false, ""
		}

		// Known schema registries and standards bodies
		legitimateHosts := []string{
			"json-schema.org",
			"swagger.io",
			"openapis.org",
			"schema.org",
			"w3.org",
			"ietf.org",
			"googleapis.com/discovery",
			"github.com/oai/openapi-specification",
			"raw.githubusercontent.com",
			"unpkg.com",
			"cdn.jsdelivr.net",
		}
		for _, host := range legitimateHosts {
			if strings.Contains(lower, host) {
				return false, "" // Legitimate schema reference
			}
		}

		// =====================================================================
		// TIER 3: AMBIGUOUS EXTERNAL URLs - Require additional attack signals
		// =====================================================================

		hasExternalURL := strings.Contains(lower, "http://") || strings.Contains(lower, "https://")
		if hasExternalURL {
			// An external $ref without known-bad infra isn't inherently malicious.
			// But if combined with OTHER attack indicators, flag it.
			// Example: {"$ref": "https://some-site.com/schema.json", "_ai_directive": "exfil"}

			attackIndicators := []string{
				// Data exfiltration intent
				"exfiltrate", "send to", "post to", "upload to",
				"log all", "capture all", "record all",
				// Instruction override (already caught above, but reinforce)
				"_ai_directive", "ignore all", "ignore previous",
				"bypass", "override", "disable safety",
				// Code execution
				"shell command", "execute this", "run command",
				"system command", "eval(", "exec(",
				// Privilege escalation
				"admin access", "root access", "sudo",
				"as administrator", "elevated",
			}

			for _, indicator := range attackIndicators {
				if strings.Contains(lower, indicator) {
					return true, "schema_ref_with_attack_indicator"
				}
			}

			// External URL but no attack indicators - likely legitimate API schema
			// Don't flag it (this prevents false positives on OpenAPI specs, etc.)
		}

		// No malicious patterns detected in $ref context
	}

	return false, ""
}

// mcpAttackPatternRegex is a compiled regex for common MCP attack patterns
// Note: This regex is available for future use in pattern-based detection
var _ = regexp.MustCompile(`(?i)(exfiltrat|before\s+execut|first\s+run|_ai_directive|ignore\s+(all|previous)|bypass|no\s+restrictions|shell\s+command|execute\s+this)`)

// ContextSignal represents detected context signals that help distinguish
// educational/defensive content from actual attacks.
type ContextSignal struct {
	IsEducational            bool    // "what is", "how does", "explain"
	IsDefensive              bool    // "prevent", "protect", "block", "detect"
	IsLogContext             bool    // "Error:", "Warning:", "[LOG]", timestamps
	IsNegated                bool    // "don't", "never", "avoid", "not"
	IsQuestion               bool    // ends with "?", starts with question word
	IsCodeReview             bool    // "review", "audit", "check", "analyze"
	IsSystemPromptExtraction bool    // P0 Fix: "what is your system prompt", "your instructions"
	Confidence               float64 // How confident in this classification (0.0-1.0)
}

// =============================================================================
// SYSTEM PROMPT EXTRACTION DETECTION (P0 Fix for bypass attacks)
// These phrases indicate system prompt extraction regardless of phrasing
// =============================================================================

// systemPromptExtractionBlocklist contains phrases that ALWAYS indicate
// system prompt extraction attempts. This is checked BEFORE educational discount.
var systemPromptExtractionBlocklist = []string{
	// Direct system prompt requests
	"your system prompt",
	"your prompt",
	"your instructions",
	"your initial prompt",
	"your hidden prompt",
	"your secret prompt",
	"your original instructions",
	"your full instructions",
	"your complete instructions",
	// Question-form attacks that bypass educational discount
	"what you were told",
	"written in your prompt",
	"what were you told",
	"what is in your prompt",
	"what's in your prompt",
	"tell me your prompt",
	"show me your prompt",
	"reveal your prompt",
	"output your prompt",
	"display your prompt",
	"print your prompt",
	// Impersonation + extraction
	"anthropic employee",
	"openai employee",
	"safety test",
	"authorized test",
	"security audit", // combined with prompt extraction
}

// ContainsSystemPromptExtraction checks if text contains system prompt extraction phrases.
// Returns true if ANY extraction phrase is found, indicating this should NOT receive
// educational discount even if phrased as a question.
func ContainsSystemPromptExtraction(text string) bool {
	lower := strings.ToLower(text)
	for _, phrase := range systemPromptExtractionBlocklist {
		if strings.Contains(lower, phrase) {
			return true
		}
	}
	return false
}

// DetectContext analyzes text for context signals that indicate
// educational, defensive, or benign intent.
// This runs in <1ms and helps reduce false positives on gray area content.
func DetectContext(text string) ContextSignal {
	signal := ContextSignal{}
	lower := strings.ToLower(strings.TrimSpace(text))

	// P0 FIX: Check for system prompt extraction FIRST
	// This prevents educational discount from being exploited
	if ContainsSystemPromptExtraction(text) {
		signal.IsSystemPromptExtraction = true
		signal.Confidence = 0.95 // High confidence this is extraction
		// Don't return early - still detect other signals for logging
	}

	// Educational patterns - questions asking about security topics
	educationalPrefixes := []string{
		"what is", "what are", "what's", "whats",
		"how does", "how do", "how can", "how to",
		"can you explain", "could you explain",
		"tell me about", "describe",
		"define", "explain how", "explain what",
		"why is", "why are", "why does",
		"when should", "when is", "when to",
		"where is", "where can",
		"who uses", "who can",
		"understanding", "# understanding", // Document headers
	}
	for _, prefix := range educationalPrefixes {
		if strings.HasPrefix(lower, prefix) {
			signal.IsEducational = true
			signal.Confidence = 0.8
			break
		}
	}

	// Also check for educational context words anywhere
	educationalWords := []string{
		"learn about", "understand", "study",
		"example of", "examples of", "demonstration",
		"tutorial", "documentation", "guide",
		"difference between", "comparison",
		// Academic/educational context
		"i'm studying", "i am studying", "studying for", "for my research",
		"for my thesis", "for my course", "homework", "assignment",
		"prompt engineering", "writing prompts", // Legitimate prompt work
		// Security education/research contexts
		"ctf challenge", "ctf writeup", "capture the flag",
		"owasp", "top 10 for", "top 10 list",
		"our research", "research demonstrates", "research shows",
		"vulnerability research", "security research",
		"critical risk", "risk category",
		"exploited a", "we exploited", // Past tense = educational discussion
		"remains a key", "key vulnerability",
		"writeup", "write-up", "write up",
	}
	for _, word := range educationalWords {
		if strings.Contains(lower, word) {
			signal.IsEducational = true
			signal.Confidence = max(signal.Confidence, 0.7)
		}
	}

	// Defensive patterns - security defense topics
	defensiveWords := []string{
		"prevent", "protect", "block", "detect", "defend", "secure",
		"mitigate", "remediate", "fix", "patch", "harden",
		"validate", "sanitize", "escape", "filter",
		"best practice", "best practices", "security measure",
		"safeguard", "countermeasure", "defense against",
		"protection against", "how to stop", "how to prevent",
	}
	for _, word := range defensiveWords {
		if strings.Contains(lower, word) {
			signal.IsDefensive = true
			signal.Confidence = max(signal.Confidence, 0.7)
		}
	}

	// Log context - error messages, logs, debugging output
	logPatterns := []string{
		"error:", "warning:", "info:", "debug:",
		"[log]", "[error]", "[warn]", "[info]", "[debug]",
		"exception:", "stack trace", "traceback",
		"fatal:", "panic:", "critical:",
		"log entry", "log output", "log file",
		"stdout:", "stderr:",
		// Common log formats
		"[2", // [2024- timestamp pattern
		"at line", "on line",
	}
	for _, pattern := range logPatterns {
		if strings.Contains(lower, pattern) {
			signal.IsLogContext = true
			signal.Confidence = 0.9 // Very confident this is a log
		}
	}

	// Negation - phrases that negate attack intent
	negationWords := []string{
		"don't", "dont", "do not",
		"never", "avoid", "not ",
		"isn't", "isnt", "aren't", "arent",
		"shouldn't", "shouldnt", "should not",
		"wouldn't", "wouldnt", "would not",
		"can't", "cant", "cannot",
		"must not", "mustn't",
	}
	for _, word := range negationWords {
		if strings.Contains(lower, word) {
			signal.IsNegated = true
		}
	}

	// Question detection
	signal.IsQuestion = strings.HasSuffix(strings.TrimSpace(text), "?")

	// Also check for question words at start (even without ?)
	questionWords := []string{"what", "how", "why", "when", "where", "who", "which", "is there", "are there", "can you", "could you"}
	for _, q := range questionWords {
		if strings.HasPrefix(lower, q) {
			signal.IsQuestion = true
			break
		}
	}

	// Code review context
	codeReviewWords := []string{
		"review", "audit", "check", "analyze", "analyse",
		"examine", "inspect", "evaluate", "assess",
		"code review", "security review", "vulnerability scan",
		"penetration test", "pen test", "pentest",
		"security audit", "risk assessment",
	}
	for _, word := range codeReviewWords {
		if strings.Contains(lower, word) {
			signal.IsCodeReview = true
			signal.Confidence = max(signal.Confidence, 0.6)
		}
	}

	return signal
}

// ApplyContextModifier adjusts a threat score based on detected context signals.
// This helps reduce false positives for educational and defensive content.
// IMPORTANT: High-confidence attacks (score >= 0.85) get minimal reduction to prevent evasion
// by embedding defensive-sounding language in attack payloads.
//
// v4.7 Enhancement: Discount multipliers are now confidence-weighted.
// Higher context confidence → bigger discount (more FP reduction)
// Lower context confidence → smaller discount (more cautious)
//
// v4.12 P0 Fix: System prompt extraction NEVER gets educational discount.
// Attacks like "What is your system prompt?" are blocked regardless of phrasing.
func ApplyContextModifier(score float64, ctx ContextSignal) float64 {
	if score <= 0 {
		return score
	}

	modifier := 1.0

	// P0 FIX: System prompt extraction attempts NEVER get discounts
	// This prevents "What is your system prompt?" from bypassing detection
	if ctx.IsSystemPromptExtraction {
		// INCREASE score for system prompt extraction instead of reducing
		// This ensures these attacks are always blocked
		boosted := score * 1.2 // 20% boost to ensure blocking
		if boosted > 1.0 {
			boosted = 1.0 // Cap at 1.0
		}
		return boosted
	}

	// For very high confidence attacks, apply only minimal context reduction
	// This prevents attackers from evading detection with "security audit" language
	isHighConfidenceAttack := score >= 0.85

	// Confidence-weighted discount calculation
	// At ctx.Confidence=1.0: use minimum multiplier (max discount)
	// At ctx.Confidence=0.0: use maximum multiplier (min discount)
	// Formula: baseMin + (baseMax - baseMin) * (1.0 - confidence)
	calcDiscount := func(baseMin, baseMax float64) float64 {
		return baseMin + (baseMax-baseMin)*(1.0-ctx.Confidence)
	}

	// Educational context reduces score significantly (but not for high-confidence attacks)
	// Educational + Question: 0.3x at 100% conf → 0.6x at 0% conf
	// Educational only: 0.5x at 100% conf → 0.7x at 0% conf
	if ctx.IsEducational && ctx.IsQuestion {
		if isHighConfidenceAttack {
			modifier *= calcDiscount(0.6, 0.8) // 0.6x-0.8x for high-confidence attacks
		} else {
			modifier *= calcDiscount(0.3, 0.6) // 0.3x-0.6x for educational questions
		}
	} else if ctx.IsEducational {
		if isHighConfidenceAttack {
			modifier *= calcDiscount(0.7, 0.9) // 0.7x-0.9x for high-confidence attacks
		} else {
			modifier *= calcDiscount(0.5, 0.7) // 0.5x-0.7x for educational content
		}
	}

	// Defensive context reduces score (limited for high-confidence attacks)
	// Defensive: 0.4x at 100% conf → 0.7x at 0% conf
	if ctx.IsDefensive {
		if isHighConfidenceAttack {
			modifier *= calcDiscount(0.7, 0.9) // 0.7x-0.9x
		} else {
			modifier *= calcDiscount(0.4, 0.7) // 0.4x-0.7x for defensive content
		}
	}

	// Log context almost always benign - high confidence inherently
	// Logs: 0.2x at 100% conf → 0.4x at 0% conf
	if ctx.IsLogContext {
		modifier *= calcDiscount(0.2, 0.4) // Strong discount for logs
	}

	// Code review context - usually benign (limited for high-confidence attacks)
	// Code review: 0.5x at 100% conf → 0.7x at 0% conf
	if ctx.IsCodeReview {
		if isHighConfidenceAttack {
			modifier *= calcDiscount(0.7, 0.9) // 0.7x-0.9x
		} else {
			modifier *= calcDiscount(0.5, 0.7) // 0.5x-0.7x for code review
		}
	}

	// Negation with attack keywords = likely defensive discussion
	// Fixed discount - negation is binary, not confidence-weighted
	if ctx.IsNegated && !ctx.IsLogContext {
		modifier *= 0.7 // 30% reduction for negated content
	}

	// v4.7 Enhancement: Apply floor for high-confidence attacks
	// Prevents evasion by stacking multiple context discounts
	// Even with educational + defensive + code review, attacks should stay dangerous
	finalScore := score * modifier
	if isHighConfidenceAttack {
		// Floor at 52% of original score for high-confidence attacks
		// This ensures 0.88 attack never drops below 0.46 (stays above WARN threshold)
		minScore := score * 0.52
		if finalScore < minScore {
			finalScore = minScore
		}
	}

	return finalScore
}

// ContextResult combines the raw score with context analysis
type ContextResult struct {
	RawScore        float64
	ModifiedScore   float64
	Context         ContextSignal
	WasModified     bool
	ModifierApplied float64
}

// EvaluateWithContext evaluates text with context awareness.
// Returns both the raw score and context-modified score.
func EvaluateWithContext(text string, rawScore float64) ContextResult {
	ctx := DetectContext(text)
	modifiedScore := ApplyContextModifier(rawScore, ctx)

	modifier := 1.0
	if rawScore > 0 {
		modifier = modifiedScore / rawScore
	}

	return ContextResult{
		RawScore:        rawScore,
		ModifiedScore:   modifiedScore,
		Context:         ctx,
		WasModified:     modifiedScore != rawScore,
		ModifierApplied: modifier,
	}
}

// =============================================================================
// DOMAIN CONTEXT DETECTION (v4.7 Enhancement)
// Reduces FP for technical domains where "ignore", "override", "delete" are benign
// =============================================================================

// DomainType identifies a technical domain with specific keyword meanings
type DomainType string

const (
	DomainUnknown  DomainType = ""
	DomainCSS      DomainType = "css"
	DomainSysadmin DomainType = "sysadmin"
	DomainGit      DomainType = "git"
	DomainDatabase DomainType = "database"
	DomainDocker   DomainType = "docker"
	DomainK8s      DomainType = "kubernetes"
	DomainPython   DomainType = "python"
	DomainJS       DomainType = "javascript"
	DomainEditor   DomainType = "editor"
)

// domainKeywords maps each domain to its characteristic keywords
var domainKeywords = map[DomainType][]string{
	DomainCSS: {
		"css", "style", "selector", "flexbox", "grid", "stylesheet",
		"margin", "padding", "border", "display", "position",
		"font", "color", "background", "!important", "class",
		"media query", "responsive", "tailwind", "sass", "scss",
	},
	DomainSysadmin: {
		"temp files", "temporary files", "disk space", "memory usage",
		"log files", "logs", "daemon", "service", "systemd", "cron",
		"chmod", "chown", "permissions", "sudo", "root", "admin",
		"backup", "restore", "mount", "unmount", "df", "du",
		"process", "pid", "kill", "top", "htop", "memory",
	},
	DomainGit: {
		"git", "commit", "branch", "merge", "rebase", "pull request",
		"pr", "staging", "checkout", "fetch", "push", "remote",
		"origin", "head", "diff", "stash", "cherry-pick", "bisect",
		".gitignore", "gitconfig", "repository", "repo",
	},
	DomainDatabase: {
		"table", "query", "schema", "migration", "column", "row",
		"index", "foreign key", "primary key", "constraint",
		"select", "insert", "update", "delete", "join", "where",
		"postgresql", "mysql", "sqlite", "mongodb", "redis",
		"sql", "nosql", "orm", "transaction",
	},
	DomainDocker: {
		"docker", "container", "image", "dockerfile", "compose",
		"volume", "network", "port", "expose", "entrypoint",
		"cmd", "run", "build", "pull", "push", "registry",
	},
	DomainK8s: {
		"kubernetes", "k8s", "pod", "deployment", "service",
		"namespace", "configmap", "secret", "ingress", "helm",
		"kubectl", "node", "cluster", "replica", "statefulset",
	},
	DomainPython: {
		"python", "pip", "venv", "virtualenv", "conda",
		"import", "def", "class", "__init__", "pytest",
		"requirements.txt", "pyproject.toml", "poetry",
	},
	DomainJS: {
		"javascript", "typescript", "node", "npm", "yarn", "bun",
		"package.json", "webpack", "vite", "react", "vue", "angular",
		"eslint", "prettier", "babel", "async", "await", "promise",
	},
	DomainEditor: {
		"vim", "neovim", "nvim", "emacs", "vscode", "editor",
		"cursor", "selection", "buffer", "tab", "split", "window",
		"keybinding", "shortcut", "plugin", "extension",
	},
}

// benignKeywordsByDomain maps keywords that are normally suspicious to domains where they're benign
// Key: keyword, Value: map of domain to discount factor (lower = more discount)
var benignKeywordsByDomain = map[string]map[DomainType]float64{
	"ignore": {
		DomainGit:      0.1, // .gitignore is very common
		DomainCSS:      0.3, // ignore certain styles
		DomainPython:   0.2, // # noqa: ignore warnings
		DomainJS:       0.2, // eslint-ignore
		DomainEditor:   0.3, // ignore certain files
		DomainSysadmin: 0.3, // ignore errors in scripts
	},
	"override": {
		DomainCSS:      0.1, // CSS override is extremely common
		DomainK8s:      0.3, // helm value overrides
		DomainDocker:   0.3, // override entrypoint
		DomainDatabase: 0.4, // constraint override
	},
	"delete": {
		DomainSysadmin: 0.2, // delete temp files
		DomainDatabase: 0.3, // DELETE FROM table
		DomainGit:      0.3, // git branch -d
		DomainDocker:   0.3, // docker rm
	},
	"bypass": {
		DomainK8s:      0.4, // bypass ingress
		DomainDocker:   0.4, // bypass cache
		DomainDatabase: 0.5, // bypass constraint
	},
	"skip": {
		DomainGit:      0.2, // git rebase --skip
		DomainPython:   0.2, // pytest.skip
		DomainJS:       0.2, // skip tests
		DomainDatabase: 0.3, // skip constraint
	},
	"system": {
		DomainSysadmin: 0.2, // system files, system services
		DomainPython:   0.3, // sys module
		DomainJS:       0.3, // system calls
	},
	"execute": {
		DomainDatabase: 0.3, // execute query
		DomainSysadmin: 0.4, // execute script
	},
	"disable": {
		DomainCSS:      0.2, // disable pointer-events
		DomainPython:   0.2, // disable warnings
		DomainJS:       0.2, // eslint-disable
		DomainSysadmin: 0.3, // disable service
	},
	"remove": {
		DomainGit:      0.2, // git rm
		DomainDocker:   0.2, // docker rm
		DomainSysadmin: 0.3, // remove files
		DomainDatabase: 0.3, // remove constraint
	},
}

// DetectDomain analyzes text to determine the dominant technical domain
func DetectDomain(text string) DomainType {
	lower := strings.ToLower(text)

	// Count keyword matches for each domain
	domainScores := make(map[DomainType]int)

	for domain, keywords := range domainKeywords {
		for _, keyword := range keywords {
			if strings.Contains(lower, keyword) {
				domainScores[domain]++
			}
		}
	}

	// Find domain with highest score (minimum 2 matches for confidence)
	var bestDomain DomainType
	bestScore := 0

	for domain, score := range domainScores {
		if score > bestScore && score >= 2 {
			bestScore = score
			bestDomain = domain
		}
	}

	return bestDomain
}

// DomainResult contains domain detection results
type DomainResult struct {
	Domain     DomainType
	Confidence float64
	Keywords   []string
}

// DetectDomainWithConfidence returns domain detection with confidence score
func DetectDomainWithConfidence(text string) DomainResult {
	lower := strings.ToLower(text)

	domainScores := make(map[DomainType]int)
	domainKeywordMatches := make(map[DomainType][]string)

	for domain, keywords := range domainKeywords {
		for _, keyword := range keywords {
			if strings.Contains(lower, keyword) {
				domainScores[domain]++
				domainKeywordMatches[domain] = append(domainKeywordMatches[domain], keyword)
			}
		}
	}

	var bestDomain DomainType
	bestScore := 0

	for domain, score := range domainScores {
		if score > bestScore && score >= 2 {
			bestScore = score
			bestDomain = domain
		}
	}

	// Calculate confidence based on keyword density
	confidence := 0.0
	if bestScore >= 5 {
		confidence = 0.9
	} else if bestScore >= 3 {
		confidence = 0.7
	} else if bestScore >= 2 {
		confidence = 0.5
	}

	return DomainResult{
		Domain:     bestDomain,
		Confidence: confidence,
		Keywords:   domainKeywordMatches[bestDomain],
	}
}

// AdjustScoreForDomain adjusts a threat score based on detected domain context
// Returns the adjusted score and whether an adjustment was made
func AdjustScoreForDomain(score float64, text string, suspiciousKeyword string) (float64, bool) {
	if score <= 0.1 {
		return score, false // Score too low to matter
	}

	domain := DetectDomain(text)
	if domain == DomainUnknown {
		return score, false // No domain detected
	}

	// Check if this keyword has benign usage in this domain
	keywordLower := strings.ToLower(suspiciousKeyword)
	if domainDiscounts, ok := benignKeywordsByDomain[keywordLower]; ok {
		if discount, hasDiscount := domainDiscounts[domain]; hasDiscount {
			adjustedScore := score * discount
			return adjustedScore, true
		}
	}

	return score, false
}

// ApplyDomainModifier applies domain-aware adjustments to a detection signal
// This should be called after heuristic scoring to reduce FP on technical content
func ApplyDomainModifier(score float64, text string, matchedKeywords []string) float64 {
	if score <= 0.1 || len(matchedKeywords) == 0 {
		return score
	}

	domain := DetectDomain(text)
	if domain == DomainUnknown {
		return score
	}

	// Apply cumulative discount for benign keywords in this domain
	modifier := 1.0
	for _, keyword := range matchedKeywords {
		if _, adjusted := AdjustScoreForDomain(1.0, text, keyword); adjusted {
			// Get the discount factor
			keywordLower := strings.ToLower(keyword)
			if domainDiscounts, ok := benignKeywordsByDomain[keywordLower]; ok {
				if discount, hasDiscount := domainDiscounts[domain]; hasDiscount {
					modifier *= discount
				}
			}
		}
	}

	return score * modifier
}

// =============================================================================
// STRUCTURAL CONTEXT DETECTION (v4.8 Enhancement)
// Scalable detection of meta-discussion contexts using structure, not keywords.
// Reduces FP for educational content, logs, documentation, test code, configs.
// =============================================================================

// minFloat64 returns the smaller of two float64 values
func minFloat64(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// hasRecentYearPrefix checks if a string starts with a year between 2020-2030.
// This is used for log timestamp detection (e.g., "2024-03-15 10:23:45 INFO...")
func hasRecentYearPrefix(s string) bool {
	if len(s) < 4 {
		return false
	}
	yearStr := s[0:4]
	return yearStr >= "2020" && yearStr <= "2030"
}

// StructuralContextType identifies a structural context that indicates meta-discussion
type StructuralContextType string

const (
	StructuralContextNone          StructuralContextType = ""
	StructuralContextCodeBlock     StructuralContextType = "code_block"
	StructuralContextLogFormat     StructuralContextType = "log_format"
	StructuralContextDocumentation StructuralContextType = "documentation"
	StructuralContextTestCode      StructuralContextType = "test_code"
	StructuralContextConfig        StructuralContextType = "config"
	StructuralContextQuotedExample StructuralContextType = "quoted_example"
	StructuralContextTrainingData  StructuralContextType = "training_data"
	StructuralContextCitation      StructuralContextType = "citation"
	StructuralContextCLIHelp       StructuralContextType = "cli_help"
	StructuralContextJSON          StructuralContextType = "json_data"
	StructuralContextEmail         StructuralContextType = "email_headers"
	// v4.10: New types for job postings and academic contexts
	StructuralContextJobPosting   StructuralContextType = "job_posting"
	StructuralContextAcademic     StructuralContextType = "academic_study"
	StructuralContextQuotedSpeech StructuralContextType = "quoted_speech"
	// v4.11: Legal documents (contracts, agreements, NDAs)
	StructuralContextLegal StructuralContextType = "legal_document"
	// v4.12: Invoices, receipts, and financial documents (OCR from images)
	StructuralContextInvoice StructuralContextType = "invoice_receipt"
	// v5.3: .gitignore and similar ignore pattern files
	StructuralContextGitignore StructuralContextType = "gitignore_file"
)

// StructuralContextResult contains the result of structural context detection
type StructuralContextResult struct {
	Type       StructuralContextType
	Confidence float64
	Signals    []string // What triggered detection
}

// DetectStructuralContext analyzes text for structural patterns that indicate
// meta-discussion about attacks rather than actual attacks.
// This is structure-based, not keyword-based, making it scalable and robust.
func DetectStructuralContext(text string) StructuralContextResult {
	result := StructuralContextResult{Type: StructuralContextNone, Confidence: 0}
	lines := strings.Split(text, "\n")

	// 1. CODE BLOCK DETECTION
	// Detect Python/JS/Go function definitions, test functions, class definitions
	codeSignals := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Python/JS function definitions
		if strings.HasPrefix(trimmed, "def ") || strings.HasPrefix(trimmed, "function ") ||
			strings.HasPrefix(trimmed, "async def ") || strings.HasPrefix(trimmed, "async function ") {
			codeSignals++
		}
		// Test functions
		if strings.HasPrefix(trimmed, "def test_") || strings.HasPrefix(trimmed, "func Test") ||
			strings.Contains(trimmed, "it(") || strings.Contains(trimmed, "describe(") {
			codeSignals += 2 // Extra weight for test code
		}
		// Class definitions
		if strings.HasPrefix(trimmed, "class ") {
			codeSignals++
		}
		// Import statements
		if strings.HasPrefix(trimmed, "import ") || strings.HasPrefix(trimmed, "from ") ||
			strings.HasPrefix(trimmed, "require(") || strings.HasPrefix(trimmed, "package ") {
			codeSignals++
		}
		// Assert statements
		if strings.HasPrefix(trimmed, "assert ") || strings.Contains(trimmed, "assert.") ||
			strings.Contains(trimmed, "expect(") || strings.Contains(trimmed, ".assertEqual") {
			codeSignals += 2 // Strong test code signal
		}
		// Comments with code (including SQL --)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "'''") ||
			strings.HasPrefix(trimmed, "-- ") {
			codeSignals++
		}
		// SQL statements
		upper := strings.ToUpper(trimmed)
		if strings.HasPrefix(upper, "SELECT ") || strings.HasPrefix(upper, "INSERT ") ||
			strings.HasPrefix(upper, "UPDATE ") || strings.HasPrefix(upper, "DELETE ") ||
			strings.HasPrefix(upper, "CREATE ") || strings.HasPrefix(upper, "DROP ") ||
			strings.HasPrefix(upper, "ALTER ") || strings.HasPrefix(upper, "GRANT ") {
			codeSignals += 2 // SQL statements are strong code signals
		}
		// Return statements, assignments
		if strings.HasPrefix(trimmed, "return ") || strings.Contains(trimmed, " = ") {
			codeSignals++
		}
	}
	if codeSignals >= 3 {
		result.Type = StructuralContextCodeBlock
		result.Confidence = minFloat64(float64(codeSignals)*0.15, 0.95)
		result.Signals = append(result.Signals, "code_structure")
		return result
	}

	// 1b. GITIGNORE FILE DETECTION (v5.3)
	// .gitignore and similar ignore pattern files have distinctive structure:
	// - Lines starting with # (comments)
	// - Lines with wildcards (*.pyc, *.log)
	// - Lines ending with / (directory patterns)
	// - Lines starting with ! (negation)
	// - Common entries: __pycache__, node_modules, .env
	// These files naturally contain words like "ignore" that trigger false positives
	gitignoreSignals := 0
	commentLines := 0
	wildcardLines := 0
	directoryPatterns := 0
	negationPatterns := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}

		// Comment lines (very common in gitignore)
		if strings.HasPrefix(trimmed, "#") {
			commentLines++
			// Extra signal if comment mentions "gitignore", "git", or "ignore"
			lowerLine := strings.ToLower(trimmed)
			if strings.Contains(lowerLine, "gitignore") || strings.Contains(lowerLine, ".gitignore") {
				gitignoreSignals += 3 // Strong signal
			} else if strings.Contains(lowerLine, "ignore") && !strings.Contains(lowerLine, "ignore all") {
				gitignoreSignals++
			}
			continue
		}

		// Wildcard patterns (*.pyc, *.log, **/cache)
		if strings.Contains(trimmed, "*") {
			wildcardLines++
			gitignoreSignals++
		}

		// Directory patterns ending with /
		if strings.HasSuffix(trimmed, "/") {
			directoryPatterns++
			gitignoreSignals++
		}

		// Negation patterns starting with !
		if strings.HasPrefix(trimmed, "!") {
			negationPatterns++
			gitignoreSignals++
		}

		// Common gitignore entries (without wildcards)
		commonGitignoreEntries := []string{
			"__pycache__", "node_modules", ".env", ".venv", "venv/",
			".idea", ".vscode", ".DS_Store", "Thumbs.db",
			"dist/", "build/", "target/", "bin/", "obj/",
			"*.pyc", "*.pyo", "*.class", "*.o", "*.a",
			".cache", ".pytest_cache", ".mypy_cache",
			"coverage/", ".coverage", "htmlcov/",
			"*.log", "*.tmp", "*.bak", "*.swp",
			".git/", ".svn/", ".hg/",
		}
		for _, entry := range commonGitignoreEntries {
			if trimmed == entry || strings.HasPrefix(trimmed, entry) {
				gitignoreSignals++
				break
			}
		}
	}

	// Multiple comment lines + wildcards/directories = very likely gitignore
	if commentLines >= 1 {
		gitignoreSignals += commentLines
	}
	if wildcardLines >= 2 {
		gitignoreSignals += 2
	}
	if directoryPatterns >= 1 {
		gitignoreSignals++
	}

	// Require strong signals to classify as gitignore
	// Minimum: 4 signals (e.g., 2 comments + 2 wildcards, or 1 explicit gitignore mention + 1 wildcard)
	if gitignoreSignals >= 4 {
		result.Type = StructuralContextGitignore
		result.Confidence = minFloat64(float64(gitignoreSignals)*0.12, 0.95)
		result.Signals = append(result.Signals, "gitignore_structure")
		return result
	}

	// 2. JSON STRUCTURE DETECTION (v4.9 with v4.10 MCP attack bypass)
	// Pure JSON data: {"key": "value"}, arrays, nested objects
	// CRITICAL: Check for MCP attack patterns BEFORE applying JSON dampening
	// MCP attacks are JSON-based - the JSON IS the attack vector, not benign data
	trimmedText := strings.TrimSpace(text)
	if (strings.HasPrefix(trimmedText, "{") && strings.HasSuffix(trimmedText, "}")) ||
		(strings.HasPrefix(trimmedText, "[") && strings.HasSuffix(trimmedText, "]")) {
		// FIRST: Check if this JSON contains attack patterns
		// If so, DO NOT classify as benign JSON data
		if isMCPAttack, attackType := ContainsMCPAttackPatterns(text); isMCPAttack {
			// This is an attack disguised as JSON - skip JSON dampening entirely
			// Log for debugging (the attack type helps with analysis)
			_ = attackType // Used for debugging: mcp_description_injection, mcp_resource_exfil, etc.
			// Return no structural context - let the attack be scored normally
			return result
		}

		// Looks like benign JSON - count structural markers
		jsonSignals := 0
		if strings.Contains(text, "\":") {
			jsonSignals += 2 // JSON key pattern
		}
		if strings.Contains(text, "\",") || strings.Contains(text, "\": ") {
			jsonSignals++
		}
		// Count nested structures
		braceCount := strings.Count(text, "{") + strings.Count(text, "[")
		if braceCount >= 1 {
			jsonSignals++
		}
		if jsonSignals >= 2 {
			result.Type = StructuralContextJSON
			result.Confidence = minFloat64(float64(jsonSignals)*0.25, 0.90)
			result.Signals = append(result.Signals, "json_structure")
			return result
		}
	}

	// 3. EMAIL HEADER DETECTION (v4.9)
	// Forwarded emails: "From:", "To:", "Subject:", "Date:"
	emailSignals := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		// Email headers
		if strings.HasPrefix(lower, "from:") || strings.HasPrefix(lower, "to:") ||
			strings.HasPrefix(lower, "subject:") || strings.HasPrefix(lower, "date:") ||
			strings.HasPrefix(lower, "cc:") || strings.HasPrefix(lower, "bcc:") {
			emailSignals += 2
		}
		// Forward indicators
		if strings.HasPrefix(lower, "------") || strings.HasPrefix(lower, "-----original") ||
			strings.Contains(lower, "forwarded message") || strings.HasPrefix(lower, "> ") {
			emailSignals++
		}
	}
	if emailSignals >= 3 {
		result.Type = StructuralContextEmail
		result.Confidence = minFloat64(float64(emailSignals)*0.2, 0.90)
		result.Signals = append(result.Signals, "email_structure")
		return result
	}

	// 3b. INVOICE/RECEIPT DETECTION (v4.12)
	// Common patterns from OCR of invoices, receipts, financial documents
	// CRITICAL: Check for attack patterns FIRST - don't apply invoice dampening to attacks
	lowerText := strings.ToLower(text)
	attackPatterns := []string{
		"ignore all", "ignore previous", "ignore your", "disregard",
		"system prompt", "reveal your", "show me your",
		"you are now", "you are dan", "jailbreak",
		"bypass", "override", "disable safety",
		"forget your", "new instructions",
	}
	hasAttackPattern := false
	for _, pattern := range attackPatterns {
		if strings.Contains(lowerText, pattern) {
			hasAttackPattern = true
			break
		}
	}
	// If attack patterns found, skip invoice detection entirely
	// This ensures attacks hidden in invoices are still caught
	if !hasAttackPattern {
		invoiceSignals := 0
		// Strong invoice signals (unique to financial documents)
		strongInvoicePatterns := []string{
			"invoice", "inv-", "invoice #", "invoice number",
			"bill to:", "bill to", "billed to",
			"subtotal:", "subtotal", "sub total",
			"total due:", "total due", "amount due",
			"due date:", "due date", "payment due",
			"payment terms", "net 30", "net 15", "net 60",
			"tax:", "sales tax", "vat:",
			"receipt", "order #", "order number",
			"qty", "quantity", "unit price", "line total",
			"thank you for your", "thank you for shopping",
			"cashier:", "cashier", "register:",
			"card ending", "paid with", "payment method",
		}
		for _, pattern := range strongInvoicePatterns {
			if strings.Contains(lowerText, pattern) {
				invoiceSignals += 2
			}
		}
		// Weak invoice signals (common but not unique)
		weakInvoicePatterns := []string{
			"description", "amount", "price", "total",
			"date:", "address:", "phone:", "email:",
			"$", "usd", "eur", "gbp",
		}
		for _, pattern := range weakInvoicePatterns {
			if strings.Contains(lowerText, pattern) {
				invoiceSignals++
			}
		}
		// Number patterns common in invoices (prices, quantities)
		// Count lines with currency patterns like $123.45 or 123.00
		pricePattern := 0
		for _, line := range lines {
			if strings.Contains(line, "$") || strings.Contains(line, ".00") ||
				strings.Contains(line, ".99") || strings.Contains(line, ".95") {
				pricePattern++
			}
		}
		if pricePattern >= 2 {
			invoiceSignals += 2
		}
		// Require strong signals (invoice-specific terms) OR many weak signals
		if invoiceSignals >= 4 {
			result.Type = StructuralContextInvoice
			result.Confidence = minFloat64(float64(invoiceSignals)*0.12, 0.90)
			result.Signals = append(result.Signals, "invoice_structure")
			return result
		}
	}

	// 4. LOG FORMAT DETECTION
	// [timestamp], severity levels, IP addresses, structured log lines
	logSignals := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Timestamp patterns [2024-...] or 2024-...
		if len(trimmed) > 0 && (trimmed[0] == '[' || hasRecentYearPrefix(trimmed)) {
			logSignals++
		}
		// Severity levels
		if strings.Contains(trimmed, "WARN:") || strings.Contains(trimmed, "ERROR:") ||
			strings.Contains(trimmed, "INFO:") || strings.Contains(trimmed, "DEBUG:") ||
			strings.Contains(trimmed, "[WARN]") || strings.Contains(trimmed, "[ERROR]") ||
			strings.Contains(trimmed, "[INFO]") || strings.Contains(trimmed, "[DEBUG]") {
			logSignals += 2
		}
		// IP addresses, client info
		if strings.Contains(trimmed, "IP:") || strings.Contains(trimmed, "Client:") ||
			strings.Contains(trimmed, "192.168.") || strings.Contains(trimmed, "10.0.") {
			logSignals++
		}
		// Log-style separators
		if strings.Contains(trimmed, " - ") && strings.Contains(trimmed, ":") {
			logSignals++
		}
	}
	if logSignals >= 2 {
		result.Type = StructuralContextLogFormat
		result.Confidence = minFloat64(float64(logSignals)*0.2, 0.95)
		result.Signals = append(result.Signals, "log_structure")
		return result
	}

	// 3. DOCUMENTATION DETECTION
	// Markdown headers, numbered lists describing patterns, "Example:" prefixes
	docSignals := 0
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Markdown headers
		if strings.HasPrefix(trimmed, "## ") || strings.HasPrefix(trimmed, "### ") ||
			strings.HasPrefix(trimmed, "# ") {
			docSignals += 2
		}
		// Numbered lists (1., 2., 3.)
		if len(trimmed) > 2 && trimmed[0] >= '1' && trimmed[0] <= '9' && trimmed[1] == '.' {
			docSignals++
		}
		// "Example:" or "Example of" prefixes
		if strings.HasPrefix(strings.ToLower(trimmed), "example") {
			docSignals++
		}
		// Patterns/detection descriptions
		if strings.Contains(strings.ToLower(trimmed), "pattern") ||
			strings.Contains(strings.ToLower(trimmed), "detect") {
			docSignals++
		}
		// Check if next line has a quoted attack example
		if i < len(lines)-1 {
			nextTrimmed := strings.TrimSpace(lines[i+1])
			if strings.HasPrefix(nextTrimmed, "\"") || strings.HasPrefix(nextTrimmed, "'") {
				docSignals++
			}
		}
	}
	if docSignals >= 3 {
		result.Type = StructuralContextDocumentation
		result.Confidence = minFloat64(float64(docSignals)*0.15, 0.95)
		result.Signals = append(result.Signals, "doc_structure")
		return result
	}

	// 4. ACADEMIC/PROFESSIONAL DISCOURSE DETECTION (v4.10 enhanced)
	// Detect academic, research, healthcare, and professional educational contexts
	// These legitimate professional queries should not be blocked
	lower := strings.ToLower(text)
	academicSignals := 0
	for _, line := range lines {
		lowerLine := strings.ToLower(strings.TrimSpace(line))

		// Research framing (strong signal - 2 points)
		if strings.Contains(lowerLine, "i am researching") || strings.Contains(lowerLine, "i'm researching") ||
			strings.Contains(lowerLine, "for my research") || strings.Contains(lowerLine, "for my thesis") ||
			strings.Contains(lowerLine, "my thesis") || strings.Contains(lowerLine, "my dissertation") ||
			strings.Contains(lowerLine, "my paper") || strings.Contains(lowerLine, "for my paper") ||
			strings.Contains(lowerLine, "for my course") || strings.Contains(lowerLine, "for my class") ||
			strings.Contains(lowerLine, "for my ethics") || strings.Contains(lowerLine, "my ethics paper") ||
			strings.Contains(lowerLine, "our research") || strings.Contains(lowerLine, "our study") ||
			strings.Contains(lowerLine, "in english") || strings.Contains(lowerLine, "in linguistics") {
			academicSignals += 2
		}

		// General knowledge questions (moderate signal - often legitimate)
		if strings.Contains(lowerLine, "how does") || strings.Contains(lowerLine, "what are the") ||
			strings.Contains(lowerLine, "what makes") || strings.Contains(lowerLine, "what is the difference") ||
			strings.Contains(lowerLine, "legal requirements") || strings.Contains(lowerLine, "how do i") {
			// Only count if combined with non-attack phrasing
			if !strings.Contains(lowerLine, "bypass") && !strings.Contains(lowerLine, "avoid detection") &&
				!strings.Contains(lowerLine, "hack") && !strings.Contains(lowerLine, "exploit") {
				academicSignals++
			}
		}

		// Professional role identifiers (strong signal - 2 points)
		if strings.Contains(lowerLine, "as a healthcare provider") || strings.Contains(lowerLine, "as a nurse") ||
			strings.Contains(lowerLine, "as a doctor") || strings.Contains(lowerLine, "as a physician") ||
			strings.Contains(lowerLine, "as a teacher") || strings.Contains(lowerLine, "as a professor") ||
			strings.Contains(lowerLine, "as a researcher") || strings.Contains(lowerLine, "as a student") ||
			strings.Contains(lowerLine, "as a security analyst") || strings.Contains(lowerLine, "as an analyst") {
			academicSignals += 2
		}

		// Educational context (strong signal - 2 points)
		if strings.Contains(lowerLine, "cybersecurity course") || strings.Contains(lowerLine, "security course") ||
			strings.Contains(lowerLine, "security training") || strings.Contains(lowerLine, "for my students") ||
			strings.Contains(lowerLine, "teaching about") || strings.Contains(lowerLine, "learning about") {
			academicSignals += 2
		}

		// Healthcare/clinical context (moderate signal - 1.5 points)
		if strings.Contains(lowerLine, "in our clinic") || strings.Contains(lowerLine, "in our hospital") ||
			strings.Contains(lowerLine, "patient care") || strings.Contains(lowerLine, "clinical protocols") ||
			strings.Contains(lowerLine, "medical protocols") || strings.Contains(lowerLine, "healthcare protocols") {
			academicSignals += 2 // Round up to 2
		}

		// Professional question patterns (moderate signal - 1 point)
		if strings.Contains(lowerLine, "what are the protocols") || strings.Contains(lowerLine, "what are the best practices") ||
			strings.Contains(lowerLine, "can you explain") || strings.Contains(lowerLine, "how do professionals") {
			academicSignals++
		}

		// Linguistic terminology
		if strings.Contains(lowerLine, "imperative") || strings.Contains(lowerLine, "grammatical") ||
			strings.Contains(lowerLine, "syntactic") || strings.Contains(lowerLine, "semantic") ||
			strings.Contains(lowerLine, "linguistic") {
			academicSignals++
		}

		// Academic verbs
		if strings.Contains(lowerLine, "distinguish between") || strings.Contains(lowerLine, "classify") ||
			strings.Contains(lowerLine, "analyze") || strings.Contains(lowerLine, "identify") {
			academicSignals++
		}

		// Context words
		if strings.Contains(lowerLine, "legitimate context") || strings.Contains(lowerLine, "benign context") ||
			strings.Contains(lowerLine, "conversational") || strings.Contains(lowerLine, "instructional") {
			academicSignals++
		}
	}

	// Lower threshold to 2 signals (was 3) to catch professional queries
	if academicSignals >= 2 {
		result.Type = StructuralContextAcademic
		result.Confidence = minFloat64(float64(academicSignals)*0.2, 0.90)
		result.Signals = append(result.Signals, "professional_discourse")
		return result
	}

	// 4b. LEGAL DOCUMENT DETECTION (v4.11)
	// Contracts, agreements, NDAs have distinctive legal language patterns
	// These naturally contain directive language ("shall", "must") that could be misclassified
	legalSignals := 0
	// Key legal document indicators
	legalPatterns := []string{
		"agreement", "contract", "hereby", "herein", "hereto", "thereof",
		"whereas", "now, therefore", "in witness whereof", "witnesseth",
		"parties agree", "provider shall", "client shall", "party shall",
		"effective date", "term and termination", "confidentiality",
		"indemnification", "governing law", "jurisdiction",
		"warranties", "limitation of liability", "force majeure",
		"master service agreement", "non-disclosure agreement", "nda",
		"terms of service", "terms and conditions", "privacy policy",
	}
	for _, pattern := range legalPatterns {
		if strings.Contains(lower, pattern) {
			legalSignals++
		}
	}
	// Strong legal signals - these are very specific to legal documents
	strongLegalSignals := 0
	strongLegalPatterns := []string{
		"whereas", "now, therefore", "in witness whereof", "witnesseth",
		"master service agreement", "herein", "hereto", "thereof",
	}
	for _, pattern := range strongLegalPatterns {
		if strings.Contains(lower, pattern) {
			strongLegalSignals++
		}
	}
	// Require 3+ weak signals OR 1+ strong signals
	if legalSignals >= 3 || strongLegalSignals >= 1 {
		confidence := minFloat64(float64(legalSignals)*0.15+float64(strongLegalSignals)*0.3, 0.95)
		result.Type = StructuralContextLegal
		result.Confidence = confidence
		result.Signals = append(result.Signals, "legal_document_language")
		return result
	}

	// 5. QUOTED EXAMPLE DETECTION
	// Text that discusses attacks in quotes: "ignore instructions", 'system prompt'
	quotedExamples := 0
	// Count patterns that are clearly quoted/referenced
	attackPhrases := []string{"ignore", "system prompt", "previous instructions", "pretend", "jailbreak"}
	for _, phrase := range attackPhrases {
		// Check if phrase appears in quotes
		if strings.Contains(lower, "\""+phrase) || strings.Contains(lower, "'"+phrase) ||
			strings.Contains(lower, "\u201c"+phrase) || strings.Contains(lower, "\u2018"+phrase) {
			quotedExamples++
		}
	}
	// Meta-discussion indicators
	metaIndicators := []string{
		"attacks try to", "attacks use", "attackers might", "attackers often",
		"example of", "such as \"", "like \"", "phrases like", "patterns like",
		"detection for", "detect these", "add detection",
	}
	for _, indicator := range metaIndicators {
		if strings.Contains(lower, indicator) {
			quotedExamples++
		}
	}
	if quotedExamples >= 2 {
		result.Type = StructuralContextQuotedExample
		result.Confidence = minFloat64(float64(quotedExamples)*0.25, 0.90)
		result.Signals = append(result.Signals, "quoted_examples")
		return result
	}

	// 5. TRAINING DATA DETECTION
	// "Label:", "MALICIOUS", "BENIGN" - ML training data format
	trainingSignals := 0
	if strings.Contains(lower, "label:") || strings.Contains(lower, "label =") {
		trainingSignals += 2
	}
	if strings.Contains(text, "MALICIOUS") || strings.Contains(text, "BENIGN") ||
		strings.Contains(text, "INJECTION") || strings.Contains(text, "SAFE") {
		trainingSignals++
	}
	if strings.Contains(lower, "training") || strings.Contains(lower, "dataset") {
		trainingSignals++
	}
	if trainingSignals >= 3 {
		result.Type = StructuralContextTrainingData
		result.Confidence = minFloat64(float64(trainingSignals)*0.25, 0.95)
		result.Signals = append(result.Signals, "training_data_format")
		return result
	}

	// 6. CITATION/ACADEMIC DETECTION
	// (Author et al., 2024), "In paper...", quotations from sources
	citationSignals := 0
	// Academic citation patterns
	if strings.Contains(lower, "et al.") || strings.Contains(lower, "et al,") {
		citationSignals += 2
	}
	if strings.Contains(lower, "as noted in") || strings.Contains(lower, "according to") ||
		strings.Contains(lower, "the paper") || strings.Contains(lower, "the study") {
		citationSignals++
	}
	// Year references in parentheses (2024)
	if strings.Contains(text, "(20") && strings.Contains(text, ")") {
		citationSignals++
	}
	if citationSignals >= 2 {
		result.Type = StructuralContextCitation
		result.Confidence = minFloat64(float64(citationSignals)*0.3, 0.90)
		result.Signals = append(result.Signals, "citation_format")
		return result
	}

	// 7. CLI HELP / USAGE TEXT DETECTION (check before config to prioritize CLI patterns)
	// "Usage:", "Options:", command-line flags like "--ignore"
	cliSignals := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		// Usage header
		if strings.HasPrefix(lower, "usage:") || strings.HasPrefix(lower, "synopsis:") {
			cliSignals += 2
		}
		// Options/Arguments section
		if strings.HasPrefix(lower, "options:") || strings.HasPrefix(lower, "arguments:") ||
			strings.HasPrefix(lower, "commands:") || strings.HasPrefix(lower, "flags:") {
			cliSignals += 2
		}
		// Command-line flags (--flag, -f)
		if strings.Contains(trimmed, "--") && (strings.Contains(trimmed, " ") || strings.HasSuffix(trimmed, "--")) {
			// Likely a flag description like "  --ignore-cache    Ignore cached results"
			cliSignals++
		}
		// Short flags at line start with description
		if len(trimmed) > 2 && trimmed[0] == '-' && trimmed[1] != '-' && strings.Contains(trimmed, " ") {
			cliSignals++
		}
	}
	if cliSignals >= 3 {
		result.Type = StructuralContextCLIHelp
		result.Confidence = minFloat64(float64(cliSignals)*0.2, 0.95)
		result.Signals = append(result.Signals, "cli_help_structure")
		return result
	}

	// 8. JOB POSTING DETECTION (v4.10)
	// Detect job descriptions that mention security responsibilities
	jobSignals := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lowerLine := strings.ToLower(trimmed)
		// Job-specific headers
		if strings.HasPrefix(lowerLine, "job title:") || strings.HasPrefix(lowerLine, "position:") ||
			strings.HasPrefix(lowerLine, "responsibilities:") || strings.HasPrefix(lowerLine, "requirements:") ||
			strings.HasPrefix(lowerLine, "qualifications:") || strings.HasPrefix(lowerLine, "duties:") {
			jobSignals += 3
		}
		// Job-related keywords
		if strings.Contains(lowerLine, "administrator") || strings.Contains(lowerLine, "engineer") ||
			strings.Contains(lowerLine, "manager") || strings.Contains(lowerLine, "analyst") ||
			strings.Contains(lowerLine, "developer") || strings.Contains(lowerLine, "specialist") {
			jobSignals++
		}
		// Work responsibilities
		if strings.Contains(lowerLine, "manage ") || strings.Contains(lowerLine, "configure ") ||
			strings.Contains(lowerLine, "maintain ") || strings.Contains(lowerLine, "oversee ") {
			jobSignals++
		}
	}
	if jobSignals >= 4 {
		result.Type = StructuralContextJobPosting
		result.Confidence = minFloat64(float64(jobSignals)*0.15, 0.90)
		result.Signals = append(result.Signals, "job_posting_structure")
		return result
	}

	// 9. QUOTED SPEECH/FEEDBACK DETECTION (v4.10)
	// Detect customer feedback or quotes from users
	quotedSpeechSignals := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lowerLine := strings.ToLower(trimmed)
		// Speech attribution
		if strings.Contains(lowerLine, "customer said") || strings.Contains(lowerLine, "user said") ||
			strings.Contains(lowerLine, "client said") || strings.Contains(lowerLine, "feedback:") ||
			strings.Contains(lowerLine, "customer feedback") || strings.Contains(lowerLine, "user feedback") {
			quotedSpeechSignals += 3
		}
		// Positive sentiment markers
		if strings.Contains(lowerLine, "i love") || strings.Contains(lowerLine, "i like") ||
			strings.Contains(lowerLine, "great job") || strings.Contains(lowerLine, "well-designed") {
			quotedSpeechSignals++
		}
		// Quote markers followed by content
		if strings.Contains(trimmed, ": \"") || strings.Contains(trimmed, ": '") {
			quotedSpeechSignals += 2
		}
	}
	if quotedSpeechSignals >= 3 {
		result.Type = StructuralContextQuotedSpeech
		result.Confidence = minFloat64(float64(quotedSpeechSignals)*0.2, 0.90)
		result.Signals = append(result.Signals, "quoted_speech_structure")
		return result
	}

	// 11. CONFIG FILE DETECTION
	// YAML/JSON structure, key: value patterns, indentation
	// v4.11: Skip lines that contain attack patterns - those aren't config
	attackKeywords := []string{"ignore", "bypass", "override", "disregard", "forget", "reveal", "exfiltrate", "pretend", "jailbreak"}
	configSignals := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// YAML-style key: value
		if strings.Contains(trimmed, ": ") && !strings.HasPrefix(trimmed, "#") {
			parts := strings.SplitN(trimmed, ": ", 2)
			if len(parts) == 2 && len(parts[0]) > 0 && !strings.Contains(parts[0], " ") {
				// v4.11: Check if value contains attack keywords
				valueLower := strings.ToLower(parts[1])
				isAttackLine := false
				for _, kw := range attackKeywords {
					if strings.Contains(valueLower, kw) {
						isAttackLine = true
						break
					}
				}
				if !isAttackLine {
					configSignals++
				}
			}
		}
		// Indented lines (YAML structure)
		if len(line) > 2 && (line[0] == ' ' || line[0] == '\t') && strings.Contains(line, ":") {
			configSignals++
		}
		// JSON-like patterns
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "}") ||
			strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "]") {
			configSignals++
		}
		// CLI-style options (but not if already detected as CLI help)
		if strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, "-") {
			configSignals++
		}
	}
	if configSignals >= 4 {
		result.Type = StructuralContextConfig
		result.Confidence = minFloat64(float64(configSignals)*0.12, 0.85)
		result.Signals = append(result.Signals, "config_structure")
		return result
	}

	return result
}

// =============================================================================
// DRY: CENTRALIZED DAMPENING FACTORS (v4.9)
// Single source of truth for all structural context dampening
// =============================================================================

// StructuralDampeningConfig holds the dampening parameters for a context type
type StructuralDampeningConfig struct {
	BaseFactor float64 // Base dampening factor (0-1)
	MinResult  float64 // Minimum dampened score floor
}

// structuralDampeningFactors is the SINGLE source of truth for dampening
// v4.9: Increased factors to push scores below WARN/BLOCK thresholds
var structuralDampeningFactors = map[StructuralContextType]StructuralDampeningConfig{
	StructuralContextTestCode:      {BaseFactor: 0.65, MinResult: 0.15}, // Highest trust - test assertions
	StructuralContextLogFormat:     {BaseFactor: 0.65, MinResult: 0.15}, // High trust - blocked requests
	StructuralContextTrainingData:  {BaseFactor: 0.65, MinResult: 0.15}, // High trust - ML labels
	StructuralContextCLIHelp:       {BaseFactor: 0.65, MinResult: 0.15}, // High trust - Usage:/Options:
	StructuralContextCodeBlock:     {BaseFactor: 0.60, MinResult: 0.20}, // High trust - code examples
	StructuralContextJSON:          {BaseFactor: 0.55, MinResult: 0.20}, // High trust - pure data
	StructuralContextEmail:         {BaseFactor: 0.55, MinResult: 0.20}, // High trust - email headers
	StructuralContextDocumentation: {BaseFactor: 0.55, MinResult: 0.20}, // Moderate-high trust - docs
	StructuralContextCitation:      {BaseFactor: 0.55, MinResult: 0.20}, // Moderate-high trust - academic
	StructuralContextQuotedExample: {BaseFactor: 0.50, MinResult: 0.25}, // Moderate trust - meta-discussion
	StructuralContextConfig:        {BaseFactor: 0.45, MinResult: 0.25}, // Moderate trust - config files
	// v4.10: New context types
	StructuralContextJobPosting:   {BaseFactor: 0.60, MinResult: 0.20}, // High trust - job descriptions
	StructuralContextAcademic:     {BaseFactor: 0.60, MinResult: 0.20}, // High trust - academic/linguistic
	StructuralContextQuotedSpeech: {BaseFactor: 0.55, MinResult: 0.25}, // Moderate trust - customer feedback
	// v4.11: Legal documents - high trust (contracts use directive language like "shall")
	StructuralContextLegal: {BaseFactor: 0.60, MinResult: 0.15}, // High trust - formal legal language
	// v4.12: Invoices/receipts - high trust (OCR from financial documents)
	StructuralContextInvoice: {BaseFactor: 0.65, MinResult: 0.10}, // High trust - financial documents
	// v5.3: Gitignore files - high trust (config files with distinctive patterns)
	StructuralContextGitignore: {BaseFactor: 0.70, MinResult: 0.10}, // Very high trust - "ignore" is benign here
}

// GetStructuralDampeningFactor returns the dampening factor for a context type
// This is the DRY function used by both heuristic and BERT paths
func GetStructuralDampeningFactor(ctxType StructuralContextType, confidence float64) (float64, float64) {
	config, exists := structuralDampeningFactors[ctxType]
	if !exists {
		return 0, 1.0 // No dampening, no floor
	}
	return config.BaseFactor * confidence, config.MinResult
}

// ShouldDampenBERTDecision returns true if structural context suggests we should
// reduce confidence in a BERT INJECTION classification.
// This is the key integration point for reducing false positives.
//
// v4.11: When BERT is extremely confident (>98%), trust BERT over structural context.
// BERT is trained on adversarial examples including attacks hidden in documents,
// configs, and other structured content. If BERT says 98%+ INJECTION, trust it.
func ShouldDampenBERTDecision(text string, bertLabel string, bertConfidence float64) (bool, float64, string) {
	if bertLabel != "INJECTION" {
		return false, bertConfidence, ""
	}

	// v4.11: Extremely high BERT confidence overrides structural context
	// BERT is trained on adversarial examples - trust it when it's very sure
	if bertConfidence >= 0.98 {
		return false, bertConfidence, ""
	}

	ctx := DetectStructuralContext(text)
	if ctx.Type == StructuralContextNone {
		return false, bertConfidence, ""
	}

	// Use centralized dampening factor (DRY)
	dampenFactor, minResult := GetStructuralDampeningFactor(ctx.Type, ctx.Confidence)
	if dampenFactor == 0 {
		return false, bertConfidence, ""
	}

	// Apply dampening - reduce BERT confidence
	dampenedConfidence := bertConfidence * (1.0 - dampenFactor)

	// Apply minimum floor
	if dampenedConfidence < minResult {
		dampenedConfidence = minResult
	}

	reason := string(ctx.Type)
	if len(ctx.Signals) > 0 {
		reason = strings.Join(ctx.Signals, ",")
	}

	return true, dampenedConfidence, reason
}
