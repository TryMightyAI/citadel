package ml

import "os"

// HugotEnabled reports whether local Hugot/ONNX detection should be enabled.
// Default is disabled; set CITADEL_ENABLE_HUGOT=true (or HUGOT_ENABLED=true)
// to opt-in. This keeps OSS installs quiet unless explicitly enabled.
func HugotEnabled() bool {
	if isTrue(os.Getenv("CITADEL_ENABLE_HUGOT")) {
		return true
	}
	if isTrue(os.Getenv("HUGOT_ENABLED")) {
		return true
	}
	return false
}

func isTrue(v string) bool {
	switch v {
	case "1", "true", "TRUE", "yes", "YES", "on", "ON":
		return true
	default:
		return false
	}
}
