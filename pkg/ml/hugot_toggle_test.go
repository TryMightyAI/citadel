package ml

import (
	"os"
	"testing"
)

func TestHugotEnabled(t *testing.T) {
	origA := os.Getenv("CITADEL_ENABLE_HUGOT")
	origB := os.Getenv("HUGOT_ENABLED")
	t.Cleanup(func() {
		_ = os.Setenv("CITADEL_ENABLE_HUGOT", origA)
		_ = os.Setenv("HUGOT_ENABLED", origB)
	})

	_ = os.Setenv("CITADEL_ENABLE_HUGOT", "")
	_ = os.Setenv("HUGOT_ENABLED", "")
	if HugotEnabled() {
		t.Fatalf("expected hugot disabled by default")
	}

	_ = os.Setenv("CITADEL_ENABLE_HUGOT", "true")
	if !HugotEnabled() {
		t.Fatalf("expected hugot enabled via CITADEL_ENABLE_HUGOT")
	}

	_ = os.Setenv("CITADEL_ENABLE_HUGOT", "")
	_ = os.Setenv("HUGOT_ENABLED", "YES")
	if !HugotEnabled() {
		t.Fatalf("expected hugot enabled via HUGOT_ENABLED")
	}
}

func TestIsTrue(t *testing.T) {
	truthy := []string{"1", "true", "TRUE", "yes", "YES", "on", "ON"}
	for _, v := range truthy {
		if !isTrue(v) {
			t.Fatalf("expected %s to be true", v)
		}
	}
	if isTrue("nope") {
		t.Fatalf("expected nope to be false")
	}
}
