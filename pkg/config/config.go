package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// LLMProvider defines the backend LLM service type
type LLMProvider string

const (
	ProviderNone       LLMProvider = "none"       // No LLM, heuristics only
	ProviderOllama     LLMProvider = "ollama"     // Local Ollama server
	ProviderOpenRouter LLMProvider = "openrouter" // OpenRouter (default, has free tier)
	ProviderGroq       LLMProvider = "groq"       // Groq (High-speed inference)
	ProviderOpenAI     LLMProvider = "openai"     // Direct OpenAI API
	ProviderAnthropic  LLMProvider = "anthropic"  // Direct Anthropic API
	ProviderAzure      LLMProvider = "azure"      // Azure OpenAI
	ProviderCustom     LLMProvider = "custom"     // Custom OpenAI-compatible endpoint
)

// FallbackBehavior defines what to do when LLM is unavailable
type FallbackBehavior string

const (
	FallbackBlock     FallbackBehavior = "block"     // Fail-secure: block on error
	FallbackAllow     FallbackBehavior = "allow"     // Fail-open: allow on error
	FallbackHeuristic FallbackBehavior = "heuristic" // Use heuristic-only scoring (default)
)

// FileSystemPolicy defines the access rules for the agent
type FileSystemPolicy struct {
	DeniedPaths    []string // Glob patterns to strictly BLOCK (e.g. "/etc/shadow", "**/.ssh/*")
	ProtectedPaths []string // Glob patterns to ALWAYS ASK (e.g. "/Users/*/Documents/*")
}

// Config holds global settings for Citadel Gateway
// All settings can be configured via environment variables or programmatically
type Config struct {
	// === Core Settings ===
	AuditLogPath        string // Path to audit log file (default: "audit_events.jsonl")
	VisionInternalToken string // Internal token for Go->Python auth (optional)
	EnableHumanApproval bool   // Require human approval for high-risk actions (default: false)

	// === LLM Provider Configuration ===
	// These settings control the Tier 1 Intent Classifier for accurate detection
	LLMProvider LLMProvider // Which LLM service to use: "ollama", "openrouter", "openai", "anthropic", "custom", "none"
	LLMAPIKey   string      // API key for cloud providers (env: CITADEL_LLM_API_KEY or provider-specific)
	LLMModel    string      // Model identifier (e.g., "nvidia/nemotron-3-nano-30b-a3b:free")
	LLMBaseURL  string      // Custom base URL for self-hosted or custom providers

	// === Detection Thresholds (0.0 - 1.0) ===
	// Tune these to balance security vs. usability
	BlockThreshold float64 // Score above this = BLOCK (default: 0.55)
	WarnThreshold  float64 // Score above this = WARN (default: 0.35)

	// === Feature Flags ===
	EnableLLMTier      bool // Enable LLM-based intent classification (Tier 1) - reduces false positives
	EnableSemantics    bool // Enable embedding similarity detection (requires Ollama)
	EnablePsychHooks   bool // Enable psychological profiling hooks
	EnableCanaryTokens bool // Enable canary token detection for data leakage

	// === Fallback & Error Handling ===
	FallbackBehavior FallbackBehavior // What to do when LLM is down: "block", "allow", "heuristic"
	LLMTimeoutMs     int              // Timeout for LLM calls in milliseconds (default: 30000)

	// === Access Control ===
	FileSystem FileSystemPolicy


	// === Context Tracking Configuration ===
	EnableContextTracking bool // Enable multi-turn context tracking
	ContextWindowSize     int  // Hot window size (default: 15)

	// === Session Management ===
	SessionSecret     string        // HMAC secret for session tokens (REQUIRED in production)
	SessionDefaultTTL time.Duration // Default session TTL (default: 1 hour)

	// === Legacy Fields (for backward compatibility) ===
	OpenRouterAPIKey string // Deprecated: use LLMAPIKey instead
	OpenRouterModel  string // Deprecated: use LLMModel instead
}

// NewDefaultConfig creates a Config with sensible defaults
// All settings can be overridden via environment variables
func NewDefaultConfig() *Config {

	cfg := &Config{
		// Core
		AuditLogPath:        GetEnv("CITADEL_AUDIT_LOG", "audit_events.jsonl"),
		VisionInternalToken: GetEnv("CITADEL_VISION_INTERNAL_TOKEN", ""),
		EnableHumanApproval: GetEnvBool("CITADEL_HUMAN_APPROVAL", false),

		// LLM Provider - defaults to OpenRouter if key is set, otherwise Ollama if available, else none
		LLMProvider: detectLLMProvider(),
		LLMAPIKey:   GetEnv("CITADEL_LLM_API_KEY", GetEnv("GROQ_API_KEY", os.Getenv("OPENROUTER_API_KEY"))),
		LLMModel:    GetEnv("CITADEL_LLM_MODEL", "nvidia/nemotron-3-nano-30b-a3b:free"),
		LLMBaseURL:  GetEnv("CITADEL_LLM_BASE_URL", ""),

		// Thresholds - tune these based on your false positive tolerance
		BlockThreshold: GetEnvFloat("CITADEL_BLOCK_THRESHOLD", 0.55),
		WarnThreshold:  GetEnvFloat("CITADEL_WARN_THRESHOLD", 0.35),

		// Feature flags - enable by default for full protection
		EnableLLMTier:      GetEnvBool("CITADEL_ENABLE_LLM", true),
		EnableSemantics:    GetEnvBool("CITADEL_ENABLE_SEMANTICS", true),
		EnablePsychHooks:   GetEnvBool("CITADEL_ENABLE_PSYCH", true),
		EnableCanaryTokens: GetEnvBool("CITADEL_ENABLE_CANARY", true),

		// Fallback behavior
		FallbackBehavior: FallbackBehavior(GetEnv("CITADEL_FALLBACK", "heuristic")),
		LLMTimeoutMs:     GetEnvInt("CITADEL_LLM_TIMEOUT_MS", 30000),

		// Legacy (backward compatibility)
		OpenRouterAPIKey: os.Getenv("OPENROUTER_API_KEY"),
		OpenRouterModel:  "nvidia/nemotron-3-nano-30b-a3b:free",

		// File System Policy Defaults
		FileSystem: FileSystemPolicy{
			DeniedPaths: []string{
				"/etc/shadow", "/etc/passwd", "/etc/sudoers",
				"**/.ssh/*", "**/.aws/*", "**/.kube/*", "**/id_rsa*",
				"/var/log/*",
			},
			ProtectedPaths: []string{
				"/Users/*/Documents/*", "/Users/*/Desktop/*",
				"**/*.env", "**/*.pem", "**/*.key",
			},
		},


		// Context Tracking
		EnableContextTracking: GetEnvBool("CITADEL_ENABLE_CONTEXT", true),
		ContextWindowSize:     clampInt(GetEnvInt("CITADEL_CONTEXT_WINDOW", 15), 1, 1000),

		// Session Management
		SessionSecret:     getSessionSecret(),
		SessionDefaultTTL: time.Duration(GetEnvInt("CITADEL_SESSION_TTL_SECONDS", 3600)) * time.Second,
	}

	return cfg
}

// getSessionSecret returns the session secret from env, or generates a random one for development.
// In production, CITADEL_SESSION_SECRET MUST be set to a secure random value.
func getSessionSecret() string {
	if secret := os.Getenv("CITADEL_SESSION_SECRET"); secret != "" {
		return secret
	}

	// Check if we're in production mode
	env := strings.ToLower(os.Getenv("CITADEL_ENV"))
	isProduction := env == "production" || env == "prod"

	// Generate a random secret for development (not recommended for production)
	log.Printf("[WARN] CITADEL_SESSION_SECRET not set - using ephemeral secret. Session tokens will NOT survive restarts. Set CITADEL_SESSION_SECRET in production!")

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// SECURITY: In production, crypto/rand failure is a critical error - do not start with weak secret
		if isProduction {
			log.Fatalf("[FATAL] crypto/rand failure in production - cannot generate secure session secret: %v", err)
		}
		// Development only: Log critical warning but allow startup for local testing
		log.Printf("[CRITICAL] crypto/rand failure - session security severely compromised! This should NEVER happen: %v", err)
		// Use multiple entropy sources to make the fallback less predictable
		// Still weak, but better than just time.Now()
		fallback := make([]byte, 32)
		for i := range fallback {
			// Mix process ID, time nanoseconds, and loop counter
			fallback[i] = byte((os.Getpid() + time.Now().Nanosecond() + i*31) & 0xFF)
		}
		return hex.EncodeToString(fallback)
	}
	return hex.EncodeToString(b)
}

// clampInt ensures a value is within bounds
func clampInt(val, min, max int) int {
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}

// NewLocalConfig creates a Config optimized for local-only operation (no API calls)
// Use this for development, air-gapped environments, or privacy-first deployments
func NewLocalConfig() *Config {
	cfg := NewDefaultConfig()
	cfg.LLMProvider = ProviderOllama
	cfg.LLMBaseURL = "http://localhost:11434/v1"
	cfg.LLMModel = "qwen2.5:7b" // Good local model
	cfg.LLMAPIKey = ""          // Not needed for Ollama
	cfg.EnableLLMTier = true
	return cfg
}

// NewHighSecurityConfig creates a Config for maximum security (may have more false positives)
func NewHighSecurityConfig() *Config {
	cfg := NewDefaultConfig()
	cfg.BlockThreshold = 0.40            // Lower threshold = more aggressive blocking
	cfg.WarnThreshold = 0.20             // Lower warn threshold
	cfg.FallbackBehavior = FallbackBlock // Block if LLM fails
	cfg.EnableHumanApproval = true
	return cfg
}

// NewHighUsabilityConfig creates a Config that minimizes false positives
func NewHighUsabilityConfig() *Config {
	cfg := NewDefaultConfig()
	cfg.BlockThreshold = 0.70 // Higher threshold = fewer false positives
	cfg.WarnThreshold = 0.50  // Higher warn threshold
	cfg.FallbackBehavior = FallbackHeuristic
	cfg.EnableLLMTier = true // LLM is critical for reducing false positives
	return cfg
}

// Helper functions for environment variable parsing
// These are exported for use by other packages (e.g., pkg/ml)

func detectLLMProvider() LLMProvider {
	// Check explicit provider setting first
	if p := os.Getenv("CITADEL_LLM_PROVIDER"); p != "" {
		return LLMProvider(p)
	}
	// Auto-detect based on available keys
	if os.Getenv("GROQ_API_KEY") != "" {
		return ProviderGroq
	}
	if os.Getenv("OPENROUTER_API_KEY") != "" || os.Getenv("CITADEL_LLM_API_KEY") != "" {
		return ProviderOpenRouter
	}
	if os.Getenv("OPENAI_API_KEY") != "" {
		return ProviderOpenAI
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return ProviderAnthropic
	}
	// Default to Ollama (local) if no cloud keys found
	return ProviderOllama
}

// GetEnv returns the value of an environment variable or a default value.
func GetEnv(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// GetEnvBool returns the boolean value of an environment variable or a default value.
func GetEnvBool(key string, defaultValue bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return defaultValue
}

// GetEnvFloat returns the float64 value of an environment variable or a default value.
func GetEnvFloat(key string, defaultValue float64) float64 {
	if v := os.Getenv(key); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err == nil {
			return f
		}
	}
	return defaultValue
}

// GetEnvInt returns the integer value of an environment variable or a default value.
func GetEnvInt(key string, defaultValue int) int {
	if v := os.Getenv(key); v != "" {
		i, err := strconv.Atoi(v)
		if err == nil {
			return i
		}
	}
	return defaultValue
}

// GetEnvSlice returns a comma-separated list from an environment variable or a default value.
func GetEnvSlice(key string, defaultValue []string) []string {
	if v := os.Getenv(key); v != "" {
		var parts []string
		for _, p := range strings.Split(v, ",") {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" {
				parts = append(parts, trimmed)
			}
		}
		if len(parts) > 0 {
			return parts
		}
	}
	return defaultValue
}

// RequiredSecret defines a required environment variable for startup validation
type RequiredSecret struct {
	Name        string // Environment variable name
	Description string // Human-readable description
	Production  bool   // Required in production only (false = required always)
}

// CriticalSecrets returns the list of secrets required for the gateway to operate
func CriticalSecrets() []RequiredSecret {
	return []RequiredSecret{
		// Required in production for session security
		{Name: "CITADEL_SESSION_SECRET", Description: "HMAC secret for session tokens (32+ bytes)", Production: true},
		// Required in production for API authentication
		{Name: "CITADEL_API_KEY", Description: "API key for gateway authentication", Production: true},
	}
}

// Validate checks that all required configuration is present.
// In production mode, this will return an error if critical secrets are missing.
// In development mode, it logs warnings but allows startup for local testing.
func (c *Config) Validate() error {
	isProduction := strings.ToLower(os.Getenv("CITADEL_ENV")) == "production" ||
		strings.ToLower(os.Getenv("CITADEL_ENV")) == "prod"

	var missing []string
	var warnings []string

	for _, secret := range CriticalSecrets() {
		value := os.Getenv(secret.Name)
		if value == "" {
			if secret.Production && !isProduction {
				// Only required in production, we're in dev - warn only
				warnings = append(warnings, secret.Name+" ("+secret.Description+")")
			} else if !secret.Production {
				// Always required
				missing = append(missing, secret.Name+" ("+secret.Description+")")
			} else if secret.Production && isProduction {
				// Required in production and we ARE in production
				missing = append(missing, secret.Name+" ("+secret.Description+")")
			}
		}
	}

	// Additional validation: session secret should be at least 32 bytes in production
	if isProduction {
		if secret := c.SessionSecret; len(secret) < 32 {
			missing = append(missing, "CITADEL_SESSION_SECRET (must be at least 32 characters)")
		}
	}

	// Log warnings for missing optional secrets
	for _, w := range warnings {
		log.Printf("[STARTUP] Warning: Missing optional secret: %s", w)
	}

	// Fail if critical secrets are missing
	if len(missing) > 0 {
		return fmt.Errorf("missing required secrets: %s", strings.Join(missing, ", "))
	}

	return nil
}

// MustValidate calls Validate and fatally exits if validation fails.
// Call this at startup before starting the server.
func (c *Config) MustValidate() {
	if err := c.Validate(); err != nil {
		log.Fatalf("[STARTUP] FATAL: Configuration validation failed: %v", err)
	}
	log.Println("[STARTUP] Configuration validated successfully")
}
