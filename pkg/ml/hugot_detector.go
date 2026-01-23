package ml

// hugot_detector.go - Local ML-based prompt injection detection using Hugot/ONNX
//
// This provides intent-based detection using the Sentinel model (ModernBERT-large),
// which achieves 93.86% F1 score on prompt injection detection.
//
// Architecture:
// - Uses ONNX Runtime for fast inference (~38ms per classification)
// - Runs fully local - no external API calls required
// - Gracefully degrades if ONNX Runtime is unavailable
//
// Models:
// - OSS: qualifire/prompt-injection-sentinel (public HuggingFace model)
//
// Build:
// - Standard: go build (uses Go backend, slower but no dependencies)
// - With ORT: go build -tags ORT (uses ONNX Runtime, faster)

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/knights-analytics/hugot"
	"github.com/knights-analytics/hugot/options"
	"github.com/knights-analytics/hugot/pipelines"
)

// HugotDetector provides local ML-based intent classification for prompt injection detection.
// It uses the Sentinel model (ModernBERT-large fine-tuned for jailbreak detection).
type HugotDetector struct {
	session  *hugot.Session
	pipeline *pipelines.TextClassificationPipeline
	mu       sync.RWMutex
	config   HugotConfig
	ready    bool
}

// HugotConfig configures the Hugot detector.
type HugotConfig struct {
	// ModelPath is the local path to the ONNX model directory.
	// If empty and ModelName is set, the model will be downloaded.
	ModelPath string

	// ModelName is the HuggingFace model name (e.g., "qualifire/prompt-injection-sentinel").
	// Used to download the model if ModelPath is empty.
	ModelName string

	// OnnxLibraryPath is the path to libonnxruntime.so.
	// Default: /usr/lib/libonnxruntime.so (Linux) or system default (macOS).
	OnnxLibraryPath string

	// UseGPU enables CUDA acceleration if available.
	UseGPU bool

	// DeviceID specifies which GPU to use (default: 0).
	DeviceID int

	// BatchSize is the maximum batch size for inference (default: 32).
	BatchSize int

	// Timeout is the maximum time for a single inference call.
	Timeout time.Duration

	// Performance tuning options (from Hugot docs)
	// OptimizeForThroughput enables settings for maximum throughput when
	// using multiple goroutines. Increases throughput but may increase latency.
	OptimizeForThroughput bool

	// InterOpNumThreads controls parallelism between independent operations.
	// Set to 1 for high-throughput multi-goroutine scenarios.
	InterOpNumThreads int

	// IntraOpNumThreads controls parallelism within a single operation.
	// Set to 1 for high-throughput multi-goroutine scenarios.
	IntraOpNumThreads int
}

// Model presets - users can choose based on their license and performance requirements.
// See pkg/ml/README.md for detailed comparison.
const (
	// ModelSentinel is the Qualifire Sentinel model (ModernBERT-large, 400M params).
	// Highest accuracy (93.86% F1) but Elastic v2 license - must download from HuggingFace.
	ModelSentinel = "qualifire/prompt-injection-sentinel"

	// ModelDeBERTaBase is the ProtectAI DeBERTa-v3-base model (200M params).
	// Apache 2.0 license - can bundle and redistribute freely. Good balance of speed/accuracy.
	ModelDeBERTaBase = "protectai/deberta-v3-base-prompt-injection-v2"

	// ModelDeBERTaSmall is the ProtectAI DeBERTa-v3-small model (100M params).
	// Apache 2.0 license - fastest inference, ideal for edge devices or high-volume.
	ModelDeBERTaSmall = "protectai/deberta-v3-small-prompt-injection-v2"

	// ModelModernBERTBase is the tihilya ModernBERT-base model (149M params).
	// Apache 2.0 license - can bundle and redistribute freely. Lightweight and fast.
	// Recommended for bundling due to permissive license and small size.
	ModelModernBERTBase = "tihilya/modernbert-base-prompt-injection-detection"

	// ModelModernBERTLarge is the ccss17 ModernBERT-large model (395M params).
	// License not specified - verify before commercial use. Uses LoRA adapter.
	// Requires BF16 support for optimal performance.
	ModelModernBERTLarge = "ccss17/modernbert-prompt-injection-detector"
)

// DefaultOSSConfig returns the default configuration for OSS using the public Sentinel model.
// For Apache 2.0 licensed alternatives, use DeBERTaBaseConfig() or DeBERTaSmallConfig().
func DefaultOSSConfig() HugotConfig {
	return HugotConfig{
		ModelName:       ModelSentinel,
		ModelPath:       "./models/sentinel",
		OnnxLibraryPath: getDefaultOnnxPath(),
		UseGPU:          false,
		DeviceID:        0,
		BatchSize:       32,
		Timeout:         30 * time.Second,
	}
}

// DeBERTaBaseConfig returns configuration using the ProtectAI DeBERTa-v3-base model.
// Apache 2.0 license - can be bundled and redistributed freely.
// 200M params, ~15ms inference, good balance of speed and accuracy.
func DeBERTaBaseConfig() HugotConfig {
	return HugotConfig{
		ModelName:       ModelDeBERTaBase,
		ModelPath:       "./models/deberta-base",
		OnnxLibraryPath: getDefaultOnnxPath(),
		UseGPU:          false,
		DeviceID:        0,
		BatchSize:       32,
		Timeout:         30 * time.Second,
	}
}

// DeBERTaSmallConfig returns configuration using the ProtectAI DeBERTa-v3-small model.
// Apache 2.0 license - can be bundled and redistributed freely.
// 100M params, ~8ms inference - fastest option for high-volume or edge deployments.
func DeBERTaSmallConfig() HugotConfig {
	return HugotConfig{
		ModelName:       ModelDeBERTaSmall,
		ModelPath:       "./models/deberta-small",
		OnnxLibraryPath: getDefaultOnnxPath(),
		UseGPU:          false,
		DeviceID:        0,
		BatchSize:       32,
		Timeout:         30 * time.Second,
	}
}

// ModernBERTBaseConfig returns configuration using the tihilya ModernBERT-base model.
// Apache 2.0 license - RECOMMENDED FOR BUNDLING due to permissive license.
// 149M params, lightweight - ideal for embedding in your application distribution.
func ModernBERTBaseConfig() HugotConfig {
	return HugotConfig{
		ModelName:       ModelModernBERTBase,
		ModelPath:       "./models/modernbert-base",
		OnnxLibraryPath: getDefaultOnnxPath(),
		UseGPU:          false,
		DeviceID:        0,
		BatchSize:       32,
		Timeout:         30 * time.Second,
	}
}

// ModernBERTLargeConfig returns configuration using the ccss17 ModernBERT-large model.
// WARNING: License not specified on HuggingFace - verify before commercial use.
// 395M params with LoRA adapter, requires BF16 support for optimal performance.
func ModernBERTLargeConfig() HugotConfig {
	return HugotConfig{
		ModelName:       ModelModernBERTLarge,
		ModelPath:       "./models/modernbert-large",
		OnnxLibraryPath: getDefaultOnnxPath(),
		UseGPU:          false,
		DeviceID:        0,
		BatchSize:       32,
		Timeout:         30 * time.Second,
	}
}

// HighThroughputConfig returns a configuration optimized for maximum throughput.
// Use this when calling from multiple goroutines with high request volume.
// Trade-off: slightly higher latency per request, but better total throughput.
func HighThroughputConfig() HugotConfig {
	cfg := DefaultOSSConfig()
	cfg.OptimizeForThroughput = true
	cfg.InterOpNumThreads = 1
	cfg.IntraOpNumThreads = 1
	return cfg
}

// ModelInfo describes an available model with its properties.
type ModelInfo struct {
	Name    string // HuggingFace model name
	Path    string // Local path where model is stored
	License string // License type (e.g., "Apache-2.0", "Elastic-2.0")
	Size    string // Approximate model size
}

// modelSearchPaths defines the paths to search for models in priority order.
// Priority: tihilya (Apache 2.0) > deberta-base > deberta-small > sentinel > modernbert-large
var modelSearchPaths = []struct {
	path    string
	model   string
	license string
	size    string
}{
	{"./models/modernbert-base", ModelModernBERTBase, "Apache-2.0", "149M"},
	{"./models/deberta-base", ModelDeBERTaBase, "Apache-2.0", "200M"},
	{"./models/deberta-small", ModelDeBERTaSmall, "Apache-2.0", "100M"},
	{"./models/sentinel", ModelSentinel, "Elastic-2.0", "400M"},
	{"./models/modernbert-large", ModelModernBERTLarge, "Unknown", "395M"},
}

// AutoDetectConfig automatically detects available models and returns appropriate config.
// Model priority (Apache 2.0 licensed models preferred):
//  1. tihilya/modernbert-base (Apache 2.0, recommended for bundling)
//  2. protectai/deberta-v3-base (Apache 2.0)
//  3. protectai/deberta-v3-small (Apache 2.0)
//  4. qualifire/sentinel (Elastic 2.0)
//  5. ccss17/modernbert-large (Unknown license)
//
// If autoDownload is enabled (CITADEL_AUTO_DOWNLOAD_MODEL=true), will automatically
// download the tihilya ModernBERT model on first use (~605MB download).
//
// Returns nil config if no models are found and auto-download is disabled.
func AutoDetectConfig() *HugotConfig {
	// Check HUGOT_MODEL_PATH environment variable first
	if envPath := os.Getenv("HUGOT_MODEL_PATH"); envPath != "" {
		if _, err := os.Stat(filepath.Join(envPath, "model.onnx")); err == nil {
			log.Printf("Using model from HUGOT_MODEL_PATH: %s", envPath)
			return &HugotConfig{
				ModelPath:       envPath,
				OnnxLibraryPath: getDefaultOnnxPath(),
				UseGPU:          false,
				DeviceID:        0,
				BatchSize:       32,
				Timeout:         30 * time.Second,
			}
		}
	}

	// Search for models in priority order
	for _, m := range modelSearchPaths {
		modelOnnx := filepath.Join(m.path, "model.onnx")
		if _, err := os.Stat(modelOnnx); err == nil {
			log.Printf("Auto-detected model: %s (%s, %s)", m.model, m.license, m.size)
			return &HugotConfig{
				ModelName:       m.model,
				ModelPath:       m.path,
				OnnxLibraryPath: getDefaultOnnxPath(),
				UseGPU:          false,
				DeviceID:        0,
				BatchSize:       32,
				Timeout:         30 * time.Second,
			}
		}
	}

	// No local models found - try auto-download if enabled
	autoDownload := os.Getenv("CITADEL_AUTO_DOWNLOAD_MODEL")
	if autoDownload == "true" || autoDownload == "1" {
		log.Printf("No ML models found. Auto-downloading tihilya ModernBERT model (~605MB)...")
		if err := EnsureModelDownloaded(DefaultModelPath); err != nil {
			log.Printf("Auto-download failed: %v", err)
			return nil
		}
		return &HugotConfig{
			ModelName:       ModelModernBERTBase,
			ModelPath:       DefaultModelPath,
			OnnxLibraryPath: getDefaultOnnxPath(),
			UseGPU:          false,
			DeviceID:        0,
			BatchSize:       32,
			Timeout:         30 * time.Second,
		}
	}

	// Log detailed information about why no models were found
	log.Printf("[ML] No ML models found in any of the following locations:")
	for _, m := range modelSearchPaths {
		log.Printf("[ML]   - %s (looking for %s)", m.path, m.model)
	}
	if envPath := os.Getenv("HUGOT_MODEL_PATH"); envPath != "" {
		log.Printf("[ML]   - %s (from HUGOT_MODEL_PATH env var)", envPath)
	}
	log.Printf("[ML] To enable ML detection, either:")
	log.Printf("[ML]   1. Run 'make setup-ml' to download tihilya ModernBERT model")
	log.Printf("[ML]   2. Set CITADEL_AUTO_DOWNLOAD_MODEL=true for auto-download on first use")
	log.Printf("[ML]   3. Set HUGOT_MODEL_PATH to point to a custom ONNX model directory")
	return nil
}

// ListAvailableModels returns information about all detected models.
func ListAvailableModels() []ModelInfo {
	var available []ModelInfo

	// Check environment variable path
	if envPath := os.Getenv("HUGOT_MODEL_PATH"); envPath != "" {
		if _, err := os.Stat(filepath.Join(envPath, "model.onnx")); err == nil {
			available = append(available, ModelInfo{
				Name:    "custom",
				Path:    envPath,
				License: "Unknown",
				Size:    "Unknown",
			})
		}
	}

	// Check standard paths
	for _, m := range modelSearchPaths {
		modelOnnx := filepath.Join(m.path, "model.onnx")
		if _, err := os.Stat(modelOnnx); err == nil {
			available = append(available, ModelInfo{
				Name:    m.model,
				Path:    m.path,
				License: m.license,
				Size:    m.size,
			})
		}
	}

	return available
}

// NewAutoDetectedHugotDetector creates a detector using auto-detected models.
// Returns nil if no models are available.
func NewAutoDetectedHugotDetector() *HugotDetector {
	if !HugotEnabled() {
		return nil
	}
	cfg := AutoDetectConfig()
	if cfg == nil {
		return nil
	}
	return NewHugotDetectorWithFallback(*cfg)
}

// getDefaultOnnxPath returns the default ONNX Runtime library path for the current platform.
func getDefaultOnnxPath() string {
	// Check common locations
	paths := []string{
		"/usr/lib/libonnxruntime.so",
		"/usr/local/lib/libonnxruntime.so",
		"/opt/homebrew/lib/libonnxruntime.dylib",
		"/usr/local/lib/libonnxruntime.dylib",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return filepath.Dir(p)
		}
	}
	return ""
}

// NewHugotDetector creates a new detector with the specified configuration.
// Returns nil and logs a warning if initialization fails (graceful degradation).
func NewHugotDetector(cfg HugotConfig) (*HugotDetector, error) {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 32
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	detector := &HugotDetector{
		config: cfg,
		ready:  false,
	}

	// Try to initialize
	if err := detector.initialize(); err != nil {
		return nil, fmt.Errorf("hugot initialization failed: %w", err)
	}

	return detector, nil
}

// NewHugotDetectorWithFallback creates a detector that gracefully degrades on failure.
// Returns a detector instance even if initialization fails (ready=false).
func NewHugotDetectorWithFallback(cfg HugotConfig) *HugotDetector {
	detector, err := NewHugotDetector(cfg)
	if err != nil {
		log.Printf("WARNING: Hugot detector initialization failed (graceful degradation): %v", err)
		return &HugotDetector{
			config: cfg,
			ready:  false,
		}
	}
	return detector
}

// initialize sets up the ONNX session and pipeline.
func (h *HugotDetector) initialize() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Create session - try ORT first, fall back to Go backend
	session, err := h.createSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	h.session = session

	// Resolve model path
	modelPath, err := h.resolveModelPath()
	if err != nil {
		_ = h.session.Destroy() // Cleanup on error; error ignored as we're already returning an error
		return fmt.Errorf("failed to resolve model path: %w", err)
	}

	// Create text classification pipeline
	config := hugot.TextClassificationConfig{
		ModelPath: modelPath,
		Name:      "prompt-injection-detector",
	}

	pipeline, err := hugot.NewPipeline(session, config)
	if err != nil {
		_ = h.session.Destroy() // Cleanup on error; error ignored as we're already returning an error
		return fmt.Errorf("failed to create pipeline: %w", err)
	}

	h.pipeline = pipeline
	h.ready = true
	log.Printf("Hugot detector initialized successfully (model: %s)", modelPath)

	return nil
}

// createSession creates the Hugot session with appropriate backend.
func (h *HugotDetector) createSession() (*hugot.Session, error) {
	// Try ONNX Runtime backend first (fastest)
	if h.config.OnnxLibraryPath != "" {
		opts := []options.WithOption{
			options.WithOnnxLibraryPath(h.config.OnnxLibraryPath),
		}

		// GPU acceleration
		if h.config.UseGPU {
			opts = append(opts, options.WithCuda(map[string]string{
				"device_id": fmt.Sprintf("%d", h.config.DeviceID),
			}))
		}

		// Performance tuning for high-throughput scenarios
		// See: https://github.com/knights-analytics/hugot#performance-tuning
		if h.config.OptimizeForThroughput {
			// Constrain each goroutine to single core, reduces locking/cache penalties
			interOp := h.config.InterOpNumThreads
			if interOp == 0 {
				interOp = 1
			}
			intraOp := h.config.IntraOpNumThreads
			if intraOp == 0 {
				intraOp = 1
			}
			opts = append(opts,
				options.WithInterOpNumThreads(interOp),
				options.WithIntraOpNumThreads(intraOp),
				options.WithCPUMemArena(false), // Skip pre-allocation for throughput
				options.WithMemPattern(false),  // Skip memory pattern optimization
			)
			log.Printf("Hugot optimized for throughput (interOp=%d, intraOp=%d)", interOp, intraOp)
		}

		session, err := hugot.NewORTSession(opts...)
		if err == nil {
			log.Printf("Hugot using ONNX Runtime backend (GPU: %v)", h.config.UseGPU)
			return session, nil
		}
		log.Printf("ONNX Runtime unavailable, falling back to Go backend: %v", err)
	}

	// Fall back to pure Go backend (slower but no dependencies)
	session, err := hugot.NewGoSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create Go session: %w", err)
	}
	log.Printf("Hugot using pure Go backend (slower, consider installing ONNX Runtime)")
	return session, nil
}

// resolveModelPath ensures the model is available locally.
func (h *HugotDetector) resolveModelPath() (string, error) {
	// If model path exists, use it
	if h.config.ModelPath != "" {
		if _, err := os.Stat(h.config.ModelPath); err == nil {
			return h.config.ModelPath, nil
		}
	}

	// Try to download model
	if h.config.ModelName == "" {
		return "", fmt.Errorf("no model path or name specified")
	}

	// Ensure models directory exists
	modelsDir := "./models"
	if err := os.MkdirAll(modelsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create models directory: %w", err)
	}

	log.Printf("Downloading model %s...", h.config.ModelName)
	modelPath, err := hugot.DownloadModel(
		h.config.ModelName,
		modelsDir,
		hugot.NewDownloadOptions(),
	)
	if err != nil {
		return "", fmt.Errorf("failed to download model: %w", err)
	}

	log.Printf("Model downloaded to %s", modelPath)
	return modelPath, nil
}

// IsReady returns true if the detector is initialized and ready for inference.
func (h *HugotDetector) IsReady() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ready
}

// isThreatLabel returns true if the label indicates a threat/injection.
// Different models use different label conventions:
// - Sentinel: "jailbreak" vs "benign"
// - tihilya/modernbert: "INJECTION" vs "LEGITIMATE"
// - ProtectAI/DeBERTa: "INJECTION" vs "SAFE"
// - Generic: "LABEL_1" (threat) vs "LABEL_0" (safe)
func isThreatLabel(label string) bool {
	switch label {
	case "jailbreak", "INJECTION", "malicious", "LABEL_1":
		return true
	default:
		return false
	}
}

// HugotResult contains the classification result from prompt injection models.
type HugotResult struct {
	// Label is the classification label (varies by model):
	// - Sentinel: "benign" or "jailbreak"
	// - tihilya: "LEGITIMATE" or "INJECTION"
	// - ProtectAI: "SAFE" or "INJECTION"
	Label string `json:"label"`

	// Confidence is the model's confidence score (0.0-1.0)
	Confidence float64 `json:"confidence"`

	// IsThreat is true if the label indicates a threat/injection
	IsThreat bool `json:"is_threat"`

	// LatencyMs is the inference time in milliseconds
	LatencyMs float64 `json:"latency_ms"`
}

// Classify performs batch classification on multiple texts.
// Returns results in the same order as inputs.
func (h *HugotDetector) Classify(ctx context.Context, texts []string) ([]HugotResult, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.ready || h.pipeline == nil {
		return nil, fmt.Errorf("hugot detector not ready")
	}

	if len(texts) == 0 {
		return []HugotResult{}, nil
	}

	start := time.Now()

	// Run inference
	result, err := h.pipeline.RunPipeline(texts)
	if err != nil {
		return nil, fmt.Errorf("classification failed: %w", err)
	}

	latency := float64(time.Since(start).Milliseconds())

	// Convert results
	outputs := make([]HugotResult, len(texts))
	for i := range texts {
		if i < len(result.ClassificationOutputs) && len(result.ClassificationOutputs[i]) > 0 {
			out := result.ClassificationOutputs[i][0]
			outputs[i] = HugotResult{
				Label:      out.Label,
				Confidence: float64(out.Score),
				IsThreat:   isThreatLabel(out.Label),
				LatencyMs:  latency / float64(len(texts)), // Amortized per-item latency
			}
		} else {
			// Fallback for missing results
			outputs[i] = HugotResult{
				Label:      "unknown",
				Confidence: 0.0,
				IsThreat:   false,
				LatencyMs:  latency / float64(len(texts)),
			}
		}
	}

	return outputs, nil
}

// ClassifySingle is a convenience method for single-text classification.
func (h *HugotDetector) ClassifySingle(ctx context.Context, text string) (HugotResult, error) {
	results, err := h.Classify(ctx, []string{text})
	if err != nil {
		return HugotResult{}, err
	}
	if len(results) == 0 {
		return HugotResult{}, fmt.Errorf("no results returned")
	}
	return results[0], nil
}

// ClassifyWithThreshold returns a decision based on confidence thresholds.
// Returns: "ALLOW", "BLOCK", or "UNCERTAIN" (needs further analysis).
func (h *HugotDetector) ClassifyWithThreshold(ctx context.Context, text string, blockThreshold, allowThreshold float64) (string, HugotResult, error) {
	result, err := h.ClassifySingle(ctx, text)
	if err != nil {
		return "UNCERTAIN", result, err
	}

	if result.IsThreat && result.Confidence >= blockThreshold {
		return "BLOCK", result, nil
	}

	if !result.IsThreat && result.Confidence >= allowThreshold {
		return "ALLOW", result, nil
	}

	return "UNCERTAIN", result, nil
}

// Close releases resources held by the detector.
func (h *HugotDetector) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.ready = false

	if h.session != nil {
		if err := h.session.Destroy(); err != nil {
			return fmt.Errorf("failed to destroy session: %w", err)
		}
	}

	return nil
}

// GetStatistics returns pipeline statistics if available.
func (h *HugotDetector) GetStatistics() map[string]interface{} {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.session == nil {
		return nil
	}

	stats := h.session.GetStatistics()
	result := make(map[string]interface{})
	for name, stat := range stats {
		result[name] = map[string]interface{}{
			"tokenizer_total_time":      stat.TokenizerTotalTime.String(),
			"tokenizer_execution_count": stat.TokenizerExecutionCount,
			"tokenizer_avg_query_time":  stat.TokenizerAvgQueryTime.String(),
			"onnx_total_time":           stat.OnnxTotalTime.String(),
			"onnx_execution_count":      stat.OnnxExecutionCount,
			"onnx_avg_query_time":       stat.OnnxAvgQueryTime.String(),
			"total_queries":             stat.TotalQueries,
			"total_documents":           stat.TotalDocuments,
			"average_latency":           stat.AverageLatency.String(),
			"average_batch_size":        stat.AverageBatchSize,
		}
	}
	return result
}
