# ML Detection Layer

This package provides machine learning-based prompt injection detection for Citadel.

## Quick Start

```bash
# From repo root
make setup-ml    # Download model, ONNX Runtime, tokenizers
make build-ml    # Build with ML support
make test-ml     # Run ML tests
```

## Architecture

```
Input Text
    │
    ▼
┌─────────────────────────────────────────────────┐
│  1. Text Normalization (transform.go)           │
│     • Unicode NFKC normalization                │
│     • Base64/Hex/ROT13 decoding                 │
│     • Zero-width character removal              │
├─────────────────────────────────────────────────┤
│  2. Heuristic Scoring (scorer.go)               │
│     • Pattern matching (90+ signatures)         │
│     • Keyword scoring                           │
│     • PII/secrets detection                     │
├─────────────────────────────────────────────────┤
│  3. ML Classification (hugot_detector.go)       │
│     • ONNX model inference                      │
│     • Intent-based detection                    │
│     • Local, no API calls                       │
└─────────────────────────────────────────────────┘
    │
    ▼
Risk Score (0.0 - 1.0)
```

## Supported Models

| Model | License | Size | Use Case |
|-------|---------|------|----------|
| [tihilya ModernBERT-base](https://huggingface.co/tihilya/modernbert-base-prompt-injection-detection) | **Apache 2.0** | 149M | **Recommended** - bundleable |
| [ProtectAI DeBERTa-v3-base](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) | Apache 2.0 | 200M | Production use |
| [Qualifire Sentinel](https://huggingface.co/qualifire/prompt-injection-sentinel) | Elastic 2.0 | 400M | Highest accuracy |

## Model Auto-Detection

The detector automatically finds models in priority order (Apache 2.0 first):

```go
detector := ml.NewAutoDetectedHugotDetector()
if detector != nil {
    result, _ := detector.ClassifySingle(ctx, "user input")
    if result.IsThreat && result.Confidence > 0.9 {
        // High confidence threat
    }
}
```

## Manual Setup

If `make setup-ml` doesn't work for your environment:

### 1. Download Model

```bash
# Option A: HuggingFace CLI
huggingface-cli download tihilya/modernbert-base-prompt-injection-detection \
    --local-dir ./models/modernbert-base

# Option B: Manual download
mkdir -p ./models/modernbert-base
cd ./models/modernbert-base
curl -LO https://huggingface.co/tihilya/modernbert-base-prompt-injection-detection/resolve/main/model.onnx
curl -LO https://huggingface.co/tihilya/modernbert-base-prompt-injection-detection/resolve/main/tokenizer.json
curl -LO https://huggingface.co/tihilya/modernbert-base-prompt-injection-detection/resolve/main/config.json
```

### 2. Download ONNX Runtime

```bash
# macOS ARM64
curl -LO https://github.com/microsoft/onnxruntime/releases/download/v1.23.2/onnxruntime-osx-arm64-1.23.2.tgz
tar -xzf onnxruntime-osx-arm64-1.23.2.tgz -C ~/

# Linux x64
curl -LO https://github.com/microsoft/onnxruntime/releases/download/v1.23.2/onnxruntime-linux-x64-1.23.2.tgz
tar -xzf onnxruntime-linux-x64-1.23.2.tgz -C ~/
```

### 3. Build Tokenizers (macOS only)

```bash
# Install Rust if needed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build tokenizers
git clone --depth 1 https://github.com/daulet/tokenizers.git ~/tokenizers
cd ~/tokenizers && make build
```

### 4. Set Environment Variables

```bash
# macOS ARM64
export CGO_LDFLAGS="-L$HOME/onnxruntime-osx-arm64-1.23.2/lib -L$HOME/tokenizers"
export DYLD_LIBRARY_PATH="$HOME/onnxruntime-osx-arm64-1.23.2/lib:$DYLD_LIBRARY_PATH"
export CITADEL_ENABLE_HUGOT=true
export HUGOT_MODEL_PATH="$(pwd)/models/modernbert-base"

# Linux x64
export CGO_LDFLAGS="-L$HOME/onnxruntime-linux-x64-1.23.2/lib -L/usr/local/lib"
export LD_LIBRARY_PATH="$HOME/onnxruntime-linux-x64-1.23.2/lib:$LD_LIBRARY_PATH"
export CITADEL_ENABLE_HUGOT=true
export HUGOT_MODEL_PATH="$(pwd)/models/modernbert-base"
```

### 5. Build and Test

```bash
go build -tags ORT -o citadel ./cmd/gateway
go test -tags ORT -v ./pkg/ml/... -run Integration
```

## API Reference

### HugotDetector

```go
// Create with auto-detection
detector := ml.NewAutoDetectedHugotDetector()

// Or create with specific config
config := &ml.HugotConfig{
    ModelPath:      "./models/modernbert-base",
    Model:          ml.ModelModernBERTBase,
    DeviceID:       -1,  // CPU
    MaxBatchSize:   32,
    MaxTokenLength: 512,
}
detector, err := ml.NewHugotDetector(config)

// Classify text
result, err := detector.ClassifySingle(ctx, "input text")
// result.Label: "INJECTION" or "SAFE"
// result.Confidence: 0.0-1.0
// result.IsThreat: true/false

// Batch classification
results, err := detector.ClassifyBatch(ctx, []string{"text1", "text2"})

// List available models
models := ml.ListAvailableModels()
for _, m := range models {
    fmt.Printf("%s (%s) - %s\n", m.Name, m.License, m.Path)
}
```

### ThreatScorer

```go
scorer := ml.NewThreatScorer(config)
score := scorer.Evaluate("user input")
// score: 0.0-1.0 (higher = more likely threat)
```

## Build Tags

- No tags: Heuristic detection only (no ONNX dependency)
- `-tags ORT`: Enable ONNX-based ML detection

## Troubleshooting

### "library not found for -lonnxruntime"

ONNX Runtime not in library path. Run `make setup-ml` or set `CGO_LDFLAGS`.

### "tokenizers.h: No such file"

Tokenizers library not built. Run `make setup-ml` or build manually.

### "model.onnx not found"

Model not downloaded. Run `make setup-ml-model`.

### Model returns wrong predictions

Check model compatibility. The tihilya model returns:
- Label 0 = SAFE
- Label 1 = INJECTION

Verify with: `go test -tags ORT -v ./pkg/ml/... -run TestHugotBasic`
