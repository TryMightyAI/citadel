// Package patterns provides a centralized, high-performance pattern registry
// for security detection. All regex patterns are compiled once at package init
// and shared across all hooks and scanners.
//
// Design principles:
// - COMPILE ONCE: All patterns compiled at init, not per-request
// - DRY: Single source of truth for all security patterns
// - CATEGORIZED: Patterns organized by security category for targeted scans
// - EXTENSIBLE: Easy to add new patterns without modifying hook code
package patterns

import (
	"regexp"
	"sync"
)

// Category represents a security pattern category
type Category string

const (
	// Input-side categories (pre-hooks)
	CategorySSRF         Category = "ssrf"
	CategorySQLInjection Category = "sql_injection"
	CategoryCommandInj   Category = "command_injection"
	CategoryPathInput    Category = "path_input"

	// Output-side categories (post-hooks)
	CategoryCredential      Category = "credential"
	CategoryPathTraversal   Category = "path_traversal"
	CategoryNetworkRecon    Category = "network_recon"
	CategoryPrivilegeEsc    Category = "privilege_escalation"
	CategoryDeserialization Category = "deserialization"
	CategoryIndirectInj     Category = "indirect_injection"
	CategoryExfiltration    Category = "exfiltration"
	CategoryCanary          Category = "canary"

	// ML/Scoring categories
	CategoryInjectionAttack  Category = "injection_attack"
	CategoryJailbreak        Category = "jailbreak"
	CategoryPromptExtraction Category = "prompt_extraction"
)

// Pattern holds a compiled regex with metadata
type Pattern struct {
	Name        string         // Human-readable name for logging
	Regex       *regexp.Regexp // Compiled regex (never nil after init)
	Category    Category       // Security category
	Severity    int            // Risk score contribution (0-100)
	Description string         // What this pattern detects
}

// Registry holds all compiled patterns, organized by category
type Registry struct {
	mu         sync.RWMutex
	byCategory map[Category][]*Pattern
	all        []*Pattern
}

// global singleton - initialized once at package load
var (
	globalRegistry *Registry
	initOnce       sync.Once
)

// Get returns the global pattern registry (singleton)
// Thread-safe and guaranteed to be initialized
func Get() *Registry {
	initOnce.Do(func() {
		globalRegistry = newRegistry()
	})
	return globalRegistry
}

// newRegistry creates and populates the pattern registry
func newRegistry() *Registry {
	r := &Registry{
		byCategory: make(map[Category][]*Pattern),
		all:        make([]*Pattern, 0, 256), // Pre-allocate for ~256 patterns
	}

	// Register all pattern categories
	r.registerCredentialPatterns()
	r.registerPathTraversalPatterns()
	r.registerNetworkReconPatterns()
	r.registerPrivilegeEscPatterns()
	r.registerDeserializationPatterns()
	r.registerSSRFPatterns()
	r.registerIndirectInjectionPatterns()
	r.registerExfiltrationPatterns()
	r.registerInjectionAttackPatterns()
	r.registerJailbreakPatterns()
	r.registerPromptExtractionPatterns()

	return r
}

// register adds a pattern to the registry (internal use only)
func (r *Registry) register(name string, pattern string, category Category, severity int, description string) {
	compiled := regexp.MustCompile(pattern)
	p := &Pattern{
		Name:        name,
		Regex:       compiled,
		Category:    category,
		Severity:    severity,
		Description: description,
	}

	r.byCategory[category] = append(r.byCategory[category], p)
	r.all = append(r.all, p)
}

// GetByCategory returns all patterns for a specific category
// Returns empty slice if category not found (never nil)
func (r *Registry) GetByCategory(cat Category) []*Pattern {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if patterns, ok := r.byCategory[cat]; ok {
		return patterns
	}
	return []*Pattern{}
}

// GetMultipleCategories returns patterns from multiple categories
// Useful for hooks that check multiple pattern types
func (r *Registry) GetMultipleCategories(cats ...Category) []*Pattern {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*Pattern
	for _, cat := range cats {
		if patterns, ok := r.byCategory[cat]; ok {
			result = append(result, patterns...)
		}
	}
	return result
}

// MatchAny checks if text matches any pattern in the given categories
// Returns the first matching pattern or nil
// This is optimized for early exit on first match
func (r *Registry) MatchAny(text string, cats ...Category) *Pattern {
	patterns := r.GetMultipleCategories(cats...)
	for _, p := range patterns {
		if p.Regex.MatchString(text) {
			return p
		}
	}
	return nil
}

// MatchAll returns all patterns that match the text in given categories
// Use when you need to know ALL matches (for comprehensive scoring)
func (r *Registry) MatchAll(text string, cats ...Category) []*Pattern {
	patterns := r.GetMultipleCategories(cats...)
	var matches []*Pattern
	for _, p := range patterns {
		if p.Regex.MatchString(text) {
			matches = append(matches, p)
		}
	}
	return matches
}

// TotalPatterns returns the total count of registered patterns
func (r *Registry) TotalPatterns() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.all)
}

// CategoryCount returns the number of patterns in a category
func (r *Registry) CategoryCount(cat Category) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byCategory[cat])
}
