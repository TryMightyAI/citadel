package ml

import "os"

func init() {
	// Avoid ORT session conflicts in general test runs.
	// Hugot integration tests create their own detector explicitly.
	if os.Getenv("CITADEL_TEST_HUGOT") == "true" {
		return
	}
	_ = os.Setenv("CITADEL_ENABLE_HUGOT", "")
	_ = os.Setenv("HUGOT_ENABLED", "")
}
