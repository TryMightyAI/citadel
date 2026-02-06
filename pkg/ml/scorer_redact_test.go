package ml

import (
	"strings"
	"testing"
)

func TestRedactSecrets_IPv4(t *testing.T) {
	scorer := &ThreatScorer{}

	tests := []struct {
		name         string
		input        string
		shouldRedact bool
		description  string
	}{
		// Should redact - real IPs
		{"public_ip", "Server at 8.8.8.8 is down", true, "Public DNS IP"},
		{"private_ip", "Connect to 192.168.1.1", true, "Private network IP"},
		{"localhost", "Running on 127.0.0.1:8080", true, "Localhost IP"},
		{"ip_in_url", "http://10.0.0.1/api", true, "IP in URL"},

		// Should NOT redact - version numbers
		{"version_v_prefix", "Using v1.2.3.4 of the app", false, "Version with v prefix"},
		{"version_word", "version 1.0.0.1 released", false, "Version with word"},
		{"version_ver", "ver. 2.3.4.5 available", false, "Version with ver."},
		{"release_version", "release 1.0.0.0", false, "Release version"},
		{"build_version", "build 1.2.3.4", false, "Build version"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, wasRedacted := scorer.RedactSecrets(tt.input)

			if tt.shouldRedact {
				if !wasRedacted {
					t.Errorf("%s: expected redaction but got none. Input: %q", tt.description, tt.input)
				}
				if !strings.Contains(result, "[IP_ADDRESS_REDACTED]") {
					t.Errorf("%s: expected [IP_ADDRESS_REDACTED] in result. Got: %q", tt.description, result)
				}
			} else {
				// For version patterns, we should NOT redact
				if strings.Contains(result, "[IP_ADDRESS_REDACTED]") {
					t.Errorf("%s: should NOT redact version number. Input: %q, Got: %q", tt.description, tt.input, result)
				}
			}
		})
	}
}

func TestRedactSecrets_IPv4_Octet_Validation(t *testing.T) {
	scorer := &ThreatScorer{}

	tests := []struct {
		name         string
		input        string
		shouldRedact bool
	}{
		{"valid_max", "IP is 255.255.255.255", true},
		{"valid_min", "IP is 0.0.0.0", true},
		{"invalid_octet", "IP is 999.999.999.999", false}, // Invalid octets
		{"invalid_256", "IP is 256.1.1.1", false},         // 256 is invalid
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := scorer.RedactSecrets(tt.input)

			hasRedaction := strings.Contains(result, "[IP_ADDRESS_REDACTED]")
			if tt.shouldRedact && !hasRedaction {
				t.Errorf("Expected redaction for valid IP: %q", tt.input)
			}
			if !tt.shouldRedact && hasRedaction {
				t.Errorf("Should NOT redact invalid IP: %q", tt.input)
			}
		})
	}
}

func TestRedactSecrets_OtherPatterns(t *testing.T) {
	scorer := &ThreatScorer{}

	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{"aws_key", "Key is AKIAIOSFODNN7EXAMPLE", "[AWS_KEY_REDACTED_BY_CITADEL]"},
		{"stripe_live", "Using sk_live_4eC39HqLyjWDarjtT1zdp7dc", "[STRIPE_KEY_REDACTED_BY_CITADEL]"},
		{"github_pat", "Token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "[GITHUB_TOKEN_REDACTED_BY_CITADEL]"},
		{"email", "Contact admin@example.com for help", "[EMAIL_REDACTED]"},
		{"ssn", "SSN: 123-45-6789", "[SSN_REDACTED]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, wasRedacted := scorer.RedactSecrets(tt.input)
			if !wasRedacted {
				t.Errorf("Expected redaction for %s", tt.name)
			}
			if !strings.Contains(result, tt.contains) {
				t.Errorf("Expected %q in result. Got: %q", tt.contains, result)
			}
		})
	}
}
