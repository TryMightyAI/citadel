package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/TryMightyAI/citadel/pkg/config"
	"github.com/TryMightyAI/citadel/pkg/mcp"
	"github.com/TryMightyAI/citadel/pkg/ml"
)

const Version = "0.1.0"

// Scanner holds the detection components
// All components are optional and gracefully degrade if unavailable
type Scanner struct {
	scorer      *ml.ThreatScorer      // Always available (heuristic patterns)
	hugot       *ml.HugotDetector     // Optional: requires ONNX model
	semantic    *ml.SemanticDetector  // Optional: requires Ollama for embeddings
	llm         *ml.LLMClassifier     // Optional: requires LLM API key
	safeguard   *ml.SafeguardClient   // Optional: external safeguard service
	config      *config.Config
	blockThresh float64
	warnThresh  float64
}

// ScanResult represents the result of scanning text
type ScanResult struct {
	Text             string  `json:"text,omitempty"`
	Decision         string  `json:"decision"`
	HeuristicScore   float64 `json:"heuristic_score"`
	MLLabel          string  `json:"ml_label,omitempty"`
	MLConfidence     float64 `json:"ml_confidence,omitempty"`
	MLIsThreat       bool    `json:"ml_is_threat,omitempty"`
	SemanticScore    float32 `json:"semantic_score,omitempty"`
	SemanticCategory string  `json:"semantic_category,omitempty"`
	SemanticIsThreat bool    `json:"semantic_is_threat,omitempty"`
	LLMClass         string  `json:"llm_class,omitempty"`
	LLMConfidence    float64 `json:"llm_confidence,omitempty"`
	Reason           string  `json:"reason,omitempty"`
	LatencyMs        float64 `json:"latency_ms,omitempty"`
}

func NewScanner(cfg *config.Config) *Scanner {
	if cfg == nil {
		cfg = config.NewDefaultConfig()
	}

	s := &Scanner{
		scorer:      ml.NewThreatScorer(cfg),
		config:      cfg,
		blockThresh: cfg.BlockThreshold,
		warnThresh:  cfg.WarnThreshold,
	}

	// Try to initialize ML detector (ONNX/BERT) - optional
	s.hugot = ml.NewAutoDetectedHugotDetector()
	if s.hugot != nil && s.hugot.IsReady() {
		log.Println("✓ ML detection enabled (hugot/ONNX)")
	} else {
		log.Println("○ ML detection disabled (no ONNX model found)")
	}

	// Try to initialize semantic detector (chromem-go + Ollama embeddings) - optional
	ollamaURL := cfg.LLMBaseURL
	if ollamaURL == "" {
		ollamaURL = "http://localhost:11434"
	}
	if cfg.EnableSemantics {
		semantic, err := ml.NewSemanticDetector(ollamaURL)
		if err != nil {
			log.Printf("○ Semantic detection disabled (init failed: %v)", err)
		} else {
			// Try to load patterns - this requires Ollama to be running
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			if err := semantic.LoadPatterns(ctx); err != nil {
				log.Printf("○ Semantic detection disabled (pattern load failed: %v)", err)
				cancel()
			} else {
				s.semantic = semantic
				log.Println("✓ Semantic detection enabled (chromem-go + Ollama embeddings)")
				cancel()
			}
		}
	}

	// Initialize LLM classifier if API key available - optional
	if cfg.LLMAPIKey != "" {
		s.llm = ml.NewLLMClassifier(ml.ClassifierConfig{
			Provider: ml.LLMProvider(cfg.LLMProvider),
			APIKey:   cfg.LLMAPIKey,
			Model:    cfg.LLMModel,
			BaseURL:  cfg.LLMBaseURL,
		})
		log.Printf("✓ LLM classifier enabled (provider: %s)", cfg.LLMProvider)
	} else {
		log.Println("○ LLM classifier disabled (no API key)")
	}

	return s
}

func (s *Scanner) Scan(ctx context.Context, text string) *ScanResult {
	start := time.Now()
	result := &ScanResult{
		Text:     text,
		Decision: "ALLOW",
	}

	// Layer 1: Heuristic scoring (fast)
	result.HeuristicScore = s.scorer.Evaluate(text)

	// Fast path: obvious block/allow
	if result.HeuristicScore >= 0.85 {
		result.Decision = "BLOCK"
		result.Reason = "High heuristic score"
		result.LatencyMs = float64(time.Since(start).Milliseconds())
		return result
	}

	// Layer 2: ML detection (BERT/ONNX - if available)
	if s.hugot != nil && s.hugot.IsReady() {
		mlResult, err := s.hugot.ClassifySingle(ctx, text)
		if err == nil {
			result.MLLabel = mlResult.Label
			result.MLConfidence = mlResult.Confidence
			result.MLIsThreat = mlResult.IsThreat

			if mlResult.IsThreat && mlResult.Confidence > 0.9 {
				result.Decision = "BLOCK"
				result.Reason = "ML classifier detected threat"
				result.LatencyMs = float64(time.Since(start).Milliseconds())
				return result
			}
		}
	}

	// Layer 3: Semantic similarity (chromem-go vector DB - if available)
	if s.semantic != nil && s.semantic.IsReady() {
		semResult, err := s.semantic.Detect(ctx, text)
		if err == nil && semResult != nil {
			result.SemanticScore = semResult.Score
			result.SemanticCategory = semResult.Category
			result.SemanticIsThreat = semResult.IsThreat

			if semResult.IsThreat && semResult.Score > 0.85 {
				result.Decision = "BLOCK"
				result.Reason = fmt.Sprintf("Semantic match: %s (%.0f%%)", semResult.Category, semResult.Score*100)
				result.LatencyMs = float64(time.Since(start).Milliseconds())
				return result
			}
		}
	}

	// Layer 4: LLM classification (if configured and score is ambiguous)
	if s.llm != nil && result.HeuristicScore >= 0.3 && result.HeuristicScore < 0.85 {
		llmResult, err := s.llm.ClassifyIntent(ctx, text)
		if err == nil && llmResult != nil {
			result.LLMClass = llmResult.Class
			result.LLMConfidence = llmResult.Confidence

			if llmResult.Class == "MALICIOUS" && llmResult.Confidence > 0.8 {
				result.Decision = "BLOCK"
				result.Reason = llmResult.Reason
			} else if llmResult.Class == "SUSPICIOUS" {
				result.Decision = "WARN"
				result.Reason = llmResult.Reason
			}
		}
	}

	// Final decision based on thresholds
	if result.Decision == "ALLOW" {
		if result.HeuristicScore >= s.blockThresh {
			result.Decision = "BLOCK"
		} else if result.HeuristicScore >= s.warnThresh {
			result.Decision = "WARN"
		}
	}

	result.LatencyMs = float64(time.Since(start).Milliseconds())
	return result
}

func main() {
	// Setup logging
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "--proxy":
		if len(os.Args) < 3 {
			fmt.Println("Usage: citadel --proxy <command> [args...]")
			os.Exit(1)
		}
		runStdioProxy(os.Args[2:])
	case "serve":
		port := "3000"
		if len(os.Args) > 2 {
			port = os.Args[2]
		}
		runHTTPServer(port)
	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("Usage: citadel scan <text>")
			os.Exit(1)
		}
		text := strings.Join(os.Args[2:], " ")
		runCLIScan(text)
	case "version":
		fmt.Printf("Citadel OSS v%s\n", Version)
		fmt.Println("AI Security Scanner - Open Source Edition")
	case "models":
		listModels()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf("Citadel OSS v%s - AI Security Scanner\n\n", Version)
	fmt.Println("Usage:")
	fmt.Println("  citadel --proxy <cmd> [args]  Run as MCP proxy (wraps another MCP server)")
	fmt.Println("  citadel serve [port]          Start HTTP server (default: 3000)")
	fmt.Println("  citadel scan <text>           Scan text for prompt injection")
	fmt.Println("  citadel models                List available ML models")
	fmt.Println("  citadel version               Show version")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  citadel --proxy npx -y @modelcontextprotocol/server-filesystem /path")
	fmt.Println("  citadel serve 8080")
	fmt.Println("  citadel scan \"Ignore previous instructions\"")
	fmt.Println("")
	fmt.Println("Environment Variables:")
	fmt.Println("  HUGOT_MODEL_PATH     Path to ONNX model directory")
	fmt.Println("  CITADEL_LLM_API_KEY  API key for LLM classification")
	fmt.Println("  CITADEL_LLM_PROVIDER Provider: ollama, openrouter, groq (default: ollama)")
}

// ============================================================================
// HTTP Server Mode
// ============================================================================

func runHTTPServer(port string) {
	cfg := config.NewDefaultConfig()
	scanner := NewScanner(cfg)

	app := fiber.New(fiber.Config{
		AppName: "Citadel OSS",
	})

	// Health check
	app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "version": Version})
	})

	// Unified /scan endpoint with mode parameter
	// mode: "input" (default) | "output" | "both"
	//
	// INPUT MODE: Full ML pipeline for user prompts (heuristics + BERT + semantic + LLM)
	// OUTPUT MODE: Pattern-based scanning for LLM responses (credentials, injections, etc.)
	// BOTH MODE: Run both input and output scanning in one call
	app.Post("/scan", func(c fiber.Ctx) error {
		var req struct {
			Text string `json:"text"`
			Mode string `json:"mode"` // "input" (default), "output", or "both"
		}
		if err := c.Bind().Body(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
		}

		if req.Text == "" {
			return c.Status(400).JSON(fiber.Map{"error": "text field is required"})
		}

		// Default to input mode
		if req.Mode == "" {
			req.Mode = "input"
		}

		switch req.Mode {
		case "input":
			// Full ML pipeline for user input protection
			result := scanner.Scan(c.Context(), req.Text)
			return c.JSON(result)

		case "output":
			// Pattern-based output scanning (fast, <1ms)
			result := ml.ScanOutput(req.Text)
			return c.JSON(result)

		case "both":
			// Run both input and output scanning
			inputResult := scanner.Scan(c.Context(), req.Text)
			outputResult := ml.ScanOutput(req.Text)

			// Merge results - block if either blocks
			decision := inputResult.Decision
			if outputResult.RiskLevel == "CRITICAL" || outputResult.RiskLevel == "HIGH" {
				if decision == "ALLOW" {
					decision = "WARN"
				}
				if outputResult.RiskLevel == "CRITICAL" {
					decision = "BLOCK"
				}
			}

			return c.JSON(fiber.Map{
				"decision":       decision,
				"input_result":   inputResult,
				"output_result":  outputResult,
				"mode":           "both",
			})

		default:
			return c.Status(400).JSON(fiber.Map{
				"error": "invalid mode, must be: input, output, or both",
			})
		}
	})

	// Dedicated input scanning endpoint (convenience alias)
	// Same as POST /scan with mode: "input"
	app.Post("/scan/input", func(c fiber.Ctx) error {
		var req struct {
			Text string `json:"text"`
		}
		if err := c.Bind().Body(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
		}
		if req.Text == "" {
			return c.Status(400).JSON(fiber.Map{"error": "text field is required"})
		}
		result := scanner.Scan(c.Context(), req.Text)
		return c.JSON(result)
	})

	// Dedicated output scanning endpoint (convenience alias)
	// Same as POST /scan with mode: "output"
	app.Post("/scan/output", func(c fiber.Ctx) error {
		var req struct {
			Text string `json:"text"`
		}
		if err := c.Bind().Body(&req); err != nil {
			return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
		}
		if req.Text == "" {
			return c.Status(400).JSON(fiber.Map{"error": "text field is required"})
		}
		result := ml.ScanOutput(req.Text)
		return c.JSON(result)
	})

	// MCP endpoint (for HTTP-based MCP)
	app.Post("/mcp", func(c fiber.Ctx) error {
		var req mcp.JSONRPCRequest
		if err := c.Bind().Body(&req); err != nil {
			return c.Status(400).JSON(mcp.JSONRPCError{Code: -32700, Message: "Parse error"})
		}

		// Scan the request params
		paramsText := string(req.Params)
		result := scanner.Scan(c.Context(), paramsText)

		if result.Decision == "BLOCK" {
			return c.JSON(mcp.JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error: &mcp.JSONRPCError{
					Code:    -32000,
					Message: "Request blocked by Citadel security scanner",
					Data:    result,
				},
			})
		}

		// For ALLOW/WARN, return success with scan info
		return c.JSON(mcp.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: fiber.Map{
				"scan_result": result,
				"note":        "Request passed security scan. Forward to actual MCP server.",
			},
		})
	})

	log.Printf("Citadel OSS HTTP server starting on :%s", port)
	log.Printf("Endpoints:")
	log.Printf("  GET  /health       - Health check")
	log.Printf("  POST /scan         - Unified scanning (mode: input|output|both)")
	log.Printf("  POST /scan/input   - Input protection (prompt injection)")
	log.Printf("  POST /scan/output  - Output protection (credential leaks)")
	log.Printf("  POST /mcp          - MCP JSON-RPC proxy")

	if err := app.Listen(":" + port); err != nil {
		log.Fatal(err)
	}
}

// ============================================================================
// STDIO Proxy Mode (MCP Proxy)
// ============================================================================

func runStdioProxy(command []string) {
	if len(command) == 0 {
		log.Fatal("No command provided for proxy mode")
	}

	cfg := config.NewDefaultConfig()
	scanner := NewScanner(cfg)

	// Start child process
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Env = append(os.Environ(),
		"NODE_NO_WARNINGS=1",
		"NPM_CONFIG_UPDATE_NOTIFIER=false",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal(err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start child process: %v", err)
	}

	log.Printf("Citadel proxy started, wrapping: %v", command)

	var wg sync.WaitGroup
	ctx := context.Background()

	// Child stdout -> scan -> real stdout
	wg.Add(1)
	go func() {
		defer wg.Done()
		reader := bufio.NewReaderSize(stdout, 1024*1024)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading child stdout: %v", err)
				}
				break
			}

			// Scan responses for data leakage
			cleanLine := strings.TrimSpace(line)
			if strings.HasPrefix(cleanLine, "{") {
				result := scanner.Scan(ctx, cleanLine)
				if result.Decision == "BLOCK" {
					log.Printf("[BLOCKED RESPONSE] score=%.2f reason=%s",
						result.HeuristicScore, result.Reason)
					// Send error response instead
					errResp := mcp.JSONRPCResponse{
						JSONRPC: "2.0",
						Error: &mcp.JSONRPCError{
							Code:    -32000,
							Message: "Response blocked by Citadel",
						},
					}
					errJSON, _ := json.Marshal(errResp)
					fmt.Println(string(errJSON))
					continue
				}
			}

			// Forward to real stdout
			fmt.Print(line)
		}
	}()

	// Real stdin -> scan -> child stdin
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer stdin.Close()

		reader := bufio.NewReaderSize(os.Stdin, 1024*1024)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					log.Printf("Error reading stdin: %v", err)
				}
				break
			}

			// Scan requests for injection
			cleanLine := strings.TrimSpace(line)
			if strings.HasPrefix(cleanLine, "{") {
				var req mcp.JSONRPCRequest
				if json.Unmarshal([]byte(cleanLine), &req) == nil {
					// Scan params
					result := scanner.Scan(ctx, string(req.Params))
					if result.Decision == "BLOCK" {
						log.Printf("[BLOCKED REQUEST] method=%s score=%.2f",
							req.Method, result.HeuristicScore)
						// Send error response
						errResp := mcp.JSONRPCResponse{
							JSONRPC: "2.0",
							ID:      req.ID,
							Error: &mcp.JSONRPCError{
								Code:    -32000,
								Message: "Request blocked by Citadel security scanner",
							},
						}
						errJSON, _ := json.Marshal(errResp)
						fmt.Println(string(errJSON))
						continue
					}
				}
			}

			// Forward to child
			stdin.Write([]byte(line))
		}
	}()

	wg.Wait()
	cmd.Wait()
}

// ============================================================================
// CLI Mode
// ============================================================================

func runCLIScan(text string) {
	cfg := config.NewDefaultConfig()
	scanner := NewScanner(cfg)

	result := scanner.Scan(context.Background(), text)

	output, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(output))
}

func listModels() {
	models := ml.ListAvailableModels()
	if len(models) == 0 {
		fmt.Println("No ML models found.")
		fmt.Println("")
		fmt.Println("To enable ML detection:")
		fmt.Println("  make setup-ml")
		return
	}

	fmt.Println("Available ML Models:")
	fmt.Println("")
	for _, m := range models {
		fmt.Printf("  %s\n", m.Name)
		fmt.Printf("    Path: %s\n", m.Path)
		fmt.Printf("    License: %s\n", m.License)
		fmt.Printf("    Size: %s\n", m.Size)
		fmt.Println()
	}
}
