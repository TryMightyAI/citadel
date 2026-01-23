package patterns

import (
	"testing"
)

func TestRegistryInit(t *testing.T) {
	// Get should return a singleton registry
	r1 := Get()
	r2 := Get()

	if r1 != r2 {
		t.Error("Get() should return the same registry instance")
	}
}

func TestRegistryHasPatterns(t *testing.T) {
	r := Get()

	// Verify registry has patterns
	total := r.TotalPatterns()
	if total < 50 {
		t.Errorf("expected at least 50 patterns, got %d", total)
	}

	t.Logf("Registry loaded %d patterns", total)
}

func TestCategoryPatterns(t *testing.T) {
	r := Get()

	testCases := []struct {
		category    Category
		minPatterns int
	}{
		{CategoryCredential, 10},
		{CategoryPathTraversal, 5},
		{CategoryNetworkRecon, 10},
		{CategoryPrivilegeEsc, 15},
		{CategoryDeserialization, 10},
		{CategorySSRF, 8},
		{CategoryExfiltration, 5},
		{CategoryInjectionAttack, 10},
		{CategoryJailbreak, 5},
		{CategoryPromptExtraction, 3},
	}

	for _, tc := range testCases {
		t.Run(string(tc.category), func(t *testing.T) {
			patterns := r.GetByCategory(tc.category)
			if len(patterns) < tc.minPatterns {
				t.Errorf("category %s: expected at least %d patterns, got %d",
					tc.category, tc.minPatterns, len(patterns))
			}
			t.Logf("Category %s: %d patterns", tc.category, len(patterns))
		})
	}
}

func TestMatchAny(t *testing.T) {
	r := Get()

	testCases := []struct {
		name       string
		text       string
		categories []Category
		wantMatch  bool
	}{
		{
			name:       "AWS key",
			text:       "Found key AKIAIOSFODNN7EXAMPLE",
			categories: []Category{CategoryCredential},
			wantMatch:  true,
		},
		{
			name:       "GitHub PAT",
			text:       "Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
			categories: []Category{CategoryCredential},
			wantMatch:  true,
		},
		{
			name:       "Path traversal",
			text:       "Reading ../../etc/passwd",
			categories: []Category{CategoryPathTraversal},
			wantMatch:  true,
		},
		{
			name:       "SSRF localhost",
			text:       "Fetching http://localhost:8080/admin",
			categories: []Category{CategorySSRF},
			wantMatch:  true,
		},
		{
			name:       "SSRF metadata",
			text:       "Fetching http://169.254.169.254/latest/meta-data/",
			categories: []Category{CategorySSRF},
			wantMatch:  true,
		},
		{
			name:       "Normal text",
			text:       "Hello world, this is a normal message",
			categories: []Category{CategoryCredential, CategorySSRF},
			wantMatch:  false,
		},
		{
			name:       "Nmap scan",
			text:       "Run nmap -sV 192.168.1.0/24",
			categories: []Category{CategoryNetworkRecon},
			wantMatch:  true,
		},
		{
			name:       "Pickle deserialization",
			text:       "data = pickle.loads(user_input)",
			categories: []Category{CategoryDeserialization},
			wantMatch:  true,
		},
		{
			name:       "SQL injection",
			text:       "'; DROP TABLE users--",
			categories: []Category{CategoryInjectionAttack},
			wantMatch:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			match := r.MatchAny(tc.text, tc.categories...)
			gotMatch := match != nil

			if gotMatch != tc.wantMatch {
				if tc.wantMatch {
					t.Errorf("expected match for %q, got none", tc.text)
				} else {
					t.Errorf("expected no match for %q, got %s", tc.text, match.Name)
				}
			}

			if match != nil {
				t.Logf("Matched pattern: %s - %s", match.Name, match.Description)
			}
		})
	}
}

func TestMatchAll(t *testing.T) {
	r := Get()

	// Text with multiple credential types
	text := `
		AWS Key: AKIAIOSFODNN7EXAMPLE
		GitHub Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789
		Password: password = 'MySecretPassword123'
	`

	matches := r.MatchAll(text, CategoryCredential)

	if len(matches) < 3 {
		t.Errorf("expected at least 3 matches, got %d", len(matches))
	}

	t.Logf("Found %d credential matches", len(matches))
	for _, m := range matches {
		t.Logf("  - %s: %s", m.Name, m.Description)
	}
}

func TestGetMultipleCategories(t *testing.T) {
	r := Get()

	// Get patterns from multiple categories
	patterns := r.GetMultipleCategories(CategoryCredential, CategorySSRF)

	credCount := r.CategoryCount(CategoryCredential)
	ssrfCount := r.CategoryCount(CategorySSRF)
	expectedMin := credCount + ssrfCount

	if len(patterns) < expectedMin {
		t.Errorf("expected at least %d patterns, got %d", expectedMin, len(patterns))
	}
}

// Benchmark for pattern matching performance
func BenchmarkMatchAny(b *testing.B) {
	r := Get()
	text := "Found key AKIAIOSFODNN7EXAMPLE in config file"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.MatchAny(text, CategoryCredential)
	}
}

func BenchmarkMatchAll(b *testing.B) {
	r := Get()
	text := `
		AWS Key: AKIAIOSFODNN7EXAMPLE
		GitHub Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789
		Password: password = 'MySecretPassword123'
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.MatchAll(text, CategoryCredential)
	}
}

func BenchmarkMatchComprehensive(b *testing.B) {
	r := Get()
	text := `
		User requested: nmap -sV 192.168.1.0/24
		Found credentials: AKIAIOSFODNN7EXAMPLE
		Path traversal: ../../etc/passwd
	`

	allCategories := []Category{
		CategoryCredential,
		CategoryPathTraversal,
		CategoryNetworkRecon,
		CategoryPrivilegeEsc,
		CategoryDeserialization,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.MatchAll(text, allCategories...)
	}
}
