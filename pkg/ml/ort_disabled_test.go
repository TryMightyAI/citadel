//go:build !ORT

package ml

func ortEnabled() bool {
	return false
}
