package ml

import "testing"

func TestDetectionSignalHelpers(t *testing.T) {
	s := NewDetectionSignal(SignalSourceHeuristic)
	if s.Confidence != 0.5 {
		t.Fatalf("expected default confidence 0.5, got %f", s.Confidence)
	}
	if s.Weight != 0.4 {
		t.Fatalf("expected heuristic weight 0.4, got %f", s.Weight)
	}

	s.Confidence = 0.9
	if !s.IsHighConfidence() || s.IsMediumConfidence() || s.IsLowConfidence() {
		t.Fatalf("expected high confidence classification")
	}
	s.Confidence = 0.7
	if !s.IsMediumConfidence() || s.IsHighConfidence() || s.IsLowConfidence() {
		t.Fatalf("expected medium confidence classification")
	}
	s.Confidence = 0.2
	if !s.IsLowConfidence() || s.IsHighConfidence() || s.IsMediumConfidence() {
		t.Fatalf("expected low confidence classification")
	}

	s.Label = "INJECTION"
	if !s.IsMalicious() || s.IsSafe() {
		t.Fatalf("expected malicious label detection")
	}
	s.Label = "SAFE"
	if !s.IsSafe() || s.IsMalicious() {
		t.Fatalf("expected safe label detection")
	}
}

func TestDetectionSignalObfuscation(t *testing.T) {
	s := NewDetectionSignal(SignalSourceContext)
	if s.HasObfuscation() {
		t.Fatalf("expected no obfuscation initially")
	}

	s.AddObfuscationType(ObfuscationUnicodeTags)
	if !s.HasObfuscation() || !s.WasDeobfuscated {
		t.Fatalf("expected obfuscation to be recorded")
	}
	if len(s.ObfuscationTypes) != 1 {
		t.Fatalf("expected 1 obfuscation type, got %d", len(s.ObfuscationTypes))
	}

	// Duplicate should not be added
	s.AddObfuscationType(ObfuscationUnicodeTags)
	if len(s.ObfuscationTypes) != 1 {
		t.Fatalf("expected no duplicates")
	}
}

func TestDetectionSignalMetadata(t *testing.T) {
	s := DetectionSignal{}
	s.SetMetadata("k", "v")
	if s.Metadata["k"] != "v" {
		t.Fatalf("expected metadata to be set")
	}
}

func TestDefaultWeights(t *testing.T) {
	if getDefaultWeight(SignalSourceSemantic) != 0.6 {
		t.Fatalf("expected semantic weight 0.6")
	}
	if getDefaultWeight(SignalSource("unknown")) != 0.5 {
		t.Fatalf("expected default weight 0.5")
	}
}
