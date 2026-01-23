# Citadel OSS Makefile
# AI Security Scanner - Open Source Edition

.PHONY: build test clean setup-ml build-ml test-ml

# Default target
all: build

# ==================== Build ====================

build:
	go build -o citadel ./cmd/gateway

# Build with ML detection (requires setup-ml first)
build-ml:
	@platform=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	arch=$$(uname -m); \
	if [ "$$platform" = "darwin" ]; then \
		if [ "$$arch" = "arm64" ]; then \
			onnx_lib="$${HOME}/onnxruntime-osx-arm64-1.23.2/lib"; \
		else \
			onnx_lib="$${HOME}/onnxruntime-osx-x64-1.23.2/lib"; \
		fi; \
		tok_lib="$${HOME}/tokenizers"; \
		export CGO_LDFLAGS="-L$$onnx_lib -L$$tok_lib"; \
		export DYLD_LIBRARY_PATH="$$onnx_lib:$$DYLD_LIBRARY_PATH"; \
	else \
		if [ "$$arch" = "aarch64" ]; then \
			onnx_lib="$${HOME}/onnxruntime-linux-aarch64-1.23.2/lib"; \
		else \
			onnx_lib="$${HOME}/onnxruntime-linux-x64-1.23.2/lib"; \
		fi; \
		tok_lib="/usr/local/lib"; \
		export CGO_LDFLAGS="-L$$onnx_lib -L$$tok_lib"; \
		export LD_LIBRARY_PATH="$$onnx_lib:$$LD_LIBRARY_PATH"; \
	fi; \
	go build -tags ORT -o citadel ./cmd/gateway

# ==================== Testing ====================

test:
	go test ./...

test-v:
	go test -v ./...

# Test with ML detection
test-ml:
	@platform=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	arch=$$(uname -m); \
	if [ "$$platform" = "darwin" ]; then \
		if [ "$$arch" = "arm64" ]; then \
			onnx_lib="$${HOME}/onnxruntime-osx-arm64-1.23.2/lib"; \
		else \
			onnx_lib="$${HOME}/onnxruntime-osx-x64-1.23.2/lib"; \
		fi; \
		tok_lib="$${HOME}/tokenizers"; \
		export CGO_LDFLAGS="-L$$onnx_lib -L$$tok_lib"; \
		export DYLD_LIBRARY_PATH="$$onnx_lib:$$DYLD_LIBRARY_PATH"; \
	else \
		if [ "$$arch" = "aarch64" ]; then \
			onnx_lib="$${HOME}/onnxruntime-linux-aarch64-1.23.2/lib"; \
		else \
			onnx_lib="$${HOME}/onnxruntime-linux-x64-1.23.2/lib"; \
		fi; \
		tok_lib="/usr/local/lib"; \
		export CGO_LDFLAGS="-L$$onnx_lib -L$$tok_lib"; \
		export LD_LIBRARY_PATH="$$onnx_lib:$$LD_LIBRARY_PATH"; \
	fi; \
	export CITADEL_ENABLE_HUGOT=true; \
	export HUGOT_MODEL_PATH="$$(pwd)/models/modernbert-base"; \
	go test -tags ORT -v ./pkg/ml/... -run Integration

# ==================== ML Setup ====================

setup-ml:
	./scripts/setup-ml.sh

setup-ml-model:
	./scripts/setup-ml.sh model

setup-ml-onnx:
	./scripts/setup-ml.sh onnx

setup-ml-verify:
	./scripts/setup-ml.sh verify

setup-ml-clean:
	./scripts/setup-ml.sh clean

# ==================== Utilities ====================

clean:
	rm -f citadel
	go clean

fmt:
	go fmt ./...

lint:
	@if command -v golangci-lint &> /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Run: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

# ==================== Help ====================

help:
	@echo "Citadel OSS - AI Security Scanner"
	@echo ""
	@echo "Build:"
	@echo "  make build      Build scanner (heuristic detection only)"
	@echo "  make build-ml   Build scanner with ML detection"
	@echo ""
	@echo "Test:"
	@echo "  make test       Run all tests"
	@echo "  make test-ml    Run ML integration tests"
	@echo ""
	@echo "ML Setup:"
	@echo "  make setup-ml   Download model + ONNX Runtime + tokenizers"
	@echo "  make setup-ml-model   Download tihilya model only"
	@echo "  make setup-ml-verify  Verify ML installation"
	@echo ""
	@echo "Utilities:"
	@echo "  make clean      Clean build artifacts"
	@echo "  make fmt        Format code"
	@echo "  make lint       Run linter"
