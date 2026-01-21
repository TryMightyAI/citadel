package ml

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TryMightyAI/citadel/pkg/config"
)

func TestDetectCryptoPatterns(t *testing.T) {
	// Load test configuration
	wd, _ := os.Getwd()
	testConfigDir := filepath.Join(wd, "testdata")
	if err := LoadScorerConfig(testConfigDir); err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	tests := []struct {
		name       string
		input      string
		minScore   float64
		maxScore   float64
		isCritical bool
	}{
		// Private Keys (CRITICAL - 50 points)
		{
			name:       "rsa_private_key",
			input:      "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...\n-----END RSA PRIVATE KEY-----",
			minScore:   50.0,
			isCritical: true,
		},
		{
			name:       "openssh_private_key",
			input:      "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz...\n-----END OPENSSH PRIVATE KEY-----",
			minScore:   50.0,
			isCritical: true,
		},
		{
			name:       "ec_private_key",
			input:      "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEE...\n-----END EC PRIVATE KEY-----",
			minScore:   50.0,
			isCritical: true,
		},
		{
			name:       "encrypted_private_key",
			input:      "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFDjBA...\n-----END ENCRYPTED PRIVATE KEY-----",
			minScore:   50.0,
			isCritical: true,
		},
		{
			name:       "pgp_private_key",
			input:      "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: ...\n-----END PGP PRIVATE KEY BLOCK-----",
			minScore:   50.0,
			isCritical: true,
		},

		// SSH Public Keys (HIGH - 40 points)
		{
			name:     "ssh_rsa_pubkey",
			input:    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...",
			minScore: 40.0,
			maxScore: 45.0,
		},
		{
			name:     "ssh_ed25519_pubkey",
			input:    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGit...",
			minScore: 40.0,
			maxScore: 45.0,
		},
		{
			name:     "ecdsa_pubkey",
			input:    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTIt...",
			minScore: 40.0,
			maxScore: 45.0,
		},

		// Certificates (MEDIUM - 35 points + "-----BEGIN" = 50, capped at 50)
		{
			name:     "x509_certificate",
			input:    "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
			minScore: 50.0, // 35 + 15 (BEGIN) = 50 (capped)
			maxScore: 50.0,
		},
		{
			name:     "certificate_request",
			input:    "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----",
			minScore: 45.0, // 30 + 15 (BEGIN) = 45
			maxScore: 50.0,
		},

		// PGP Public (MEDIUM - 25 points + "-----BEGIN" = 40)
		{
			name:     "pgp_public_key",
			input:    "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: ...\n-----END PGP PUBLIC KEY BLOCK-----",
			minScore: 40.0, // 25 + 15 (BEGIN) = 40
			maxScore: 50.0,
		},
		{
			name:     "pgp_message",
			input:    "-----BEGIN PGP MESSAGE-----\nwcFMA...\n-----END PGP MESSAGE-----",
			minScore: 35.0, // 20 + 15 (BEGIN) = 35
			maxScore: 50.0,
		},

		// Partial headers
		{
			name:     "partial_private_key_end",
			input:    "...truncated... PRIVATE KEY-----",
			minScore: 35.0,
			maxScore: 40.0,
		},
		{
			name:     "generic_begin_only",
			input:    "-----BEGIN something",
			minScore: 15.0,
			maxScore: 20.0,
		},

		// Benign (should score 0)
		{
			name:     "plain_text",
			input:    "Hello, this is a normal message",
			minScore: 0.0,
			maxScore: 0.0,
		},
		{
			name:     "code_with_dashes",
			input:    "func main() { fmt.Println(\"---test---\") }",
			minScore: 0.0,
			maxScore: 0.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			score := detectCryptoPatterns(tc.input)

			if score < tc.minScore {
				t.Errorf("detectCryptoPatterns(%q) = %v, want >= %v", tc.input[:min(len(tc.input), 50)], score, tc.minScore)
			}

			if tc.maxScore > 0 && score > tc.maxScore {
				t.Errorf("detectCryptoPatterns(%q) = %v, want <= %v", tc.input[:min(len(tc.input), 50)], score, tc.maxScore)
			}

			if tc.isCritical && score < 50.0 {
				t.Errorf("Expected critical score (50+) for %s, got %v", tc.name, score)
			}
		})
	}
}

func TestRedactSecrets_Crypto(t *testing.T) {
	scorer := NewThreatScorer(&config.Config{})

	tests := []struct {
		name         string
		input        string
		shouldRedact bool
		redactMarker string
	}{
		{
			name: "rsa_private_key",
			input: `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2mKqH...
-----END RSA PRIVATE KEY-----`,
			shouldRedact: true,
			redactMarker: "[PRIVATE_KEY_BLOCK_REDACTED_BY_CITADEL]",
		},
		{
			name: "certificate",
			input: `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0Gcz...
-----END CERTIFICATE-----`,
			shouldRedact: true,
			redactMarker: "[CERTIFICATE_REDACTED_BY_CITADEL]",
		},
		{
			name: "pgp_private",
			input: `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1
...
-----END PGP PRIVATE KEY BLOCK-----`,
			shouldRedact: true,
			redactMarker: "[PGP_BLOCK_REDACTED_BY_CITADEL]", // PGP regex catches this
		},
		{
			name: "pgp_public",
			input: `-----BEGIN PGP PUBLIC KEY BLOCK-----
mQINBF...
-----END PGP PUBLIC KEY BLOCK-----`,
			shouldRedact: true,
			redactMarker: "[PGP_BLOCK_REDACTED_BY_CITADEL]",
		},
		{
			name:         "ssh_pubkey",
			input:        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDZcZs8Ry9vfj7j user@host",
			shouldRedact: true,
			redactMarker: "[SSH_PUBKEY_REDACTED_BY_CITADEL]",
		},
		{
			name:         "plain_text",
			input:        "Hello world, this is normal text",
			shouldRedact: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, wasRedacted := scorer.RedactSecrets(tc.input)

			if wasRedacted != tc.shouldRedact {
				t.Errorf("RedactSecrets wasRedacted = %v, want %v", wasRedacted, tc.shouldRedact)
			}

			if tc.shouldRedact && tc.redactMarker != "" {
				if !strings.Contains(result, tc.redactMarker) {
					t.Errorf("Expected result to contain %q, got: %s", tc.redactMarker, result)
				}
			}

			if tc.shouldRedact && strings.Contains(result, "-----BEGIN") {
				t.Errorf("Crypto material not fully redacted: %s", result)
			}
		})
	}
}

func TestCryptoPatternScores_Coverage(t *testing.T) {
	// Verify we have patterns for all major crypto formats
	expectedPatterns := []string{
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN DSA PRIVATE KEY-----",
		"-----BEGIN ED25519 PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----",
		"-----BEGIN PGP PRIVATE KEY BLOCK-----",
		"ssh-rsa ",
		"ssh-ed25519 ",
		"-----BEGIN CERTIFICATE-----",
	}

	patterns := GetCryptoPatterns()
	for _, pattern := range expectedPatterns {
		if _, ok := patterns[pattern]; !ok {
			t.Errorf("Missing crypto pattern: %s", pattern)
		}
	}

	// Verify all private key patterns have critical score
	privateKeyPatterns := []string{
		"-----BEGIN PRIVATE KEY-----",
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----",
		"-----BEGIN OPENSSH PRIVATE KEY-----",
	}

	for _, pattern := range privateKeyPatterns {
		if score := patterns[pattern]; score < 50.0 {
			t.Errorf("Private key pattern %s should have score >= 50, got %v", pattern, score)
		}
	}
}

func TestEvaluate_CryptoDetection(t *testing.T) {
	scorer := NewThreatScorer(&config.Config{})

	tests := []struct {
		name     string
		input    string
		minScore float64
	}{
		{
			name: "private_key_block",
			input: `Here's my server key:
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2mKqH...
-----END RSA PRIVATE KEY-----`,
			minScore: 0.9, // Should be blocked (normalized score)
		},
		{
			name:     "ssh_pubkey",
			input:    "My SSH key: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDZcZs8Ry9vfj7j user@host",
			minScore: 0.5, // Should be warned
		},
		{
			name:     "benign_text",
			input:    "Hello, please help me write a function",
			minScore: 0.0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			score := scorer.Evaluate(tc.input)

			if score < tc.minScore {
				t.Errorf("Evaluate(%q) = %v, want >= %v", tc.name, score, tc.minScore)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
