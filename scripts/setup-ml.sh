#!/bin/bash
# Setup ML detection layer with tihilya ModernBERT model
#
# This script downloads and configures everything needed for ML-based
# prompt injection detection using the Apache 2.0 licensed tihilya model.
#
# Usage:
#   ./scripts/setup-ml.sh              # Full setup (model + ONNX Runtime)
#   ./scripts/setup-ml.sh model        # Download model only
#   ./scripts/setup-ml.sh onnx         # Download ONNX Runtime only
#   ./scripts/setup-ml.sh tokenizers   # Build tokenizers library only
#   ./scripts/setup-ml.sh verify       # Verify installation
#   ./scripts/setup-ml.sh clean        # Remove downloaded files

set -euo pipefail

# Configuration
MODEL_NAME="tihilya/modernbert-base-prompt-injection-detection"
# ONNX Runtime version - must match the model's ONNX opset requirements
# The tihilya ModernBERT model requires ONNX API v23 (ONNX Runtime 1.23.x)
ONNX_VERSION="1.23.2"
ONNX_DIR="${HOME}/onnxruntime"

# Get absolute path for model directory (resolve relative path from script location)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MODEL_DIR="${REPO_ROOT}/models/modernbert-base"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Minimum required versions
MIN_PYTHON_VERSION="3.9"
MIN_GO_VERSION="1.21"

# Detect platform (must be defined early, used by prerequisite checks)
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)

    case "$os" in
        darwin)
            if [[ "$arch" == "arm64" ]]; then
                echo "osx-arm64"
            else
                echo "osx-x64"
            fi
            ;;
        linux)
            if [[ "$arch" == "aarch64" ]]; then
                echo "linux-aarch64"
            else
                echo "linux-x64"
            fi
            ;;
        mingw*|msys*|cygwin*)
            # Windows via Git Bash, MSYS2, or Cygwin
            if [[ "$arch" == "x86_64" ]]; then
                echo "win-x64"
            else
                echo "win-x86"
            fi
            ;;
        *)
            # Check if running in WSL
            if grep -qi microsoft /proc/version 2>/dev/null; then
                if [[ "$arch" == "aarch64" ]]; then
                    echo "linux-aarch64"
                else
                    echo "linux-x64"
                fi
            else
                error "Unsupported platform: $os-$arch"
            fi
            ;;
    esac
}

# Check if running on Windows
is_windows() {
    local platform=$(detect_platform)
    [[ "$platform" == win-* ]]
}

# ============================================================================
# PREREQUISITE CHECKS
# ============================================================================

# Compare version strings (returns 0 if $1 >= $2)
version_gte() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# Check if Go is installed and version is sufficient
check_go() {
    if ! command -v go &> /dev/null; then
        warn "Go is not installed."
        echo ""
        echo "  Install Go ${MIN_GO_VERSION}+ from https://go.dev/dl/"
        echo ""
        echo "  Quick install:"
        local platform=$(detect_platform)
        case "$platform" in
            osx-*)
                echo "    brew install go"
                echo "    # or download from https://go.dev/dl/"
                ;;
            linux-*)
                echo "    sudo snap install go --classic"
                echo "    # or: sudo apt install golang-go"
                echo "    # or download from https://go.dev/dl/"
                ;;
            win-*)
                echo "    # Download installer from https://go.dev/dl/"
                echo "    # Or use Chocolatey: choco install golang"
                echo "    # Or use Scoop: scoop install go"
                ;;
        esac
        echo ""
        return 1
    fi

    local go_version=$(go version | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    if ! version_gte "$go_version" "$MIN_GO_VERSION"; then
        warn "Go version $go_version is too old. Minimum required: $MIN_GO_VERSION"
        echo "  Please upgrade Go: https://go.dev/dl/"
        return 1
    fi

    info "  Go: OK (v$go_version)"
    return 0
}

# Check if Python is installed and version is sufficient
check_python() {
    # On Windows, python3 might not exist, try python instead
    local python_cmd="python3"
    if ! command -v python3 &> /dev/null; then
        if command -v python &> /dev/null; then
            # Check if it's Python 3
            if python -c "import sys; sys.exit(0 if sys.version_info.major >= 3 else 1)" 2>/dev/null; then
                python_cmd="python"
            fi
        fi
    fi

    if ! command -v "$python_cmd" &> /dev/null; then
        warn "Python 3 is not installed."
        echo ""
        echo "  Install Python ${MIN_PYTHON_VERSION}+ from https://python.org/"
        echo ""
        echo "  Quick install:"
        local platform=$(detect_platform)
        case "$platform" in
            osx-*)
                echo "    brew install python@3.12"
                ;;
            linux-*)
                echo "    sudo apt install python3 python3-pip python3-venv"
                echo "    # or: sudo dnf install python3 python3-pip"
                ;;
            win-*)
                echo "    # Download from https://python.org/downloads/"
                echo "    # Or use Chocolatey: choco install python"
                echo "    # Or use Scoop: scoop install python"
                echo "    # IMPORTANT: Check 'Add Python to PATH' during install"
                ;;
        esac
        echo ""
        return 1
    fi

    local py_version=$($python_cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    if ! version_gte "$py_version" "$MIN_PYTHON_VERSION"; then
        warn "Python version $py_version is too old. Minimum required: $MIN_PYTHON_VERSION"
        echo ""
        echo "  Please upgrade Python:"
        local platform=$(detect_platform)
        case "$platform" in
            osx-*)
                echo "    brew install python@3.12"
                ;;
            linux-*)
                echo "    sudo apt install python3.12 python3.12-venv"
                ;;
            win-*)
                echo "    # Download from https://python.org/downloads/"
                ;;
        esac
        echo ""
        return 1
    fi

    info "  Python: OK (v$py_version)"
    return 0
}

# Check if pip/venv is available
check_pip_venv() {
    # Check for pip
    if ! python3 -m pip --version &> /dev/null; then
        warn "pip is not available."
        echo ""
        echo "  Install pip:"
        local platform=$(detect_platform)
        case "$platform" in
            osx-*)
                echo "    python3 -m ensurepip --upgrade"
                ;;
            linux-*)
                echo "    sudo apt install python3-pip"
                echo "    # or: python3 -m ensurepip --upgrade"
                ;;
        esac
        echo ""
        return 1
    fi

    # Check for venv
    if ! python3 -m venv --help &> /dev/null; then
        warn "venv module is not available."
        echo ""
        echo "  Install venv:"
        local platform=$(detect_platform)
        case "$platform" in
            linux-*)
                echo "    sudo apt install python3-venv"
                ;;
            *)
                echo "    venv should be included with Python 3.3+"
                ;;
        esac
        echo ""
        return 1
    fi

    info "  pip/venv: OK"
    return 0
}

# Check if Rust is installed (needed for tokenizers on macOS and Windows)
check_rust() {
    local platform=$(detect_platform)

    # Rust is only required on macOS and Windows for building tokenizers
    # Linux has pre-built tokenizers available
    if [[ "$platform" == linux-* ]]; then
        info "  Rust: Not required (Linux uses pre-built tokenizers)"
        return 0
    fi

    if ! command -v cargo &> /dev/null; then
        warn "Rust is not installed (required for building tokenizers)."
        echo ""
        echo "  Install Rust:"
        case "$platform" in
            win-*)
                echo "    # Download from https://rustup.rs/"
                echo "    # Or use Chocolatey: choco install rust"
                ;;
            *)
                echo "    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
                echo "    source \"\$HOME/.cargo/env\""
                ;;
        esac
        echo ""
        echo "  Or skip this check - the script will auto-install Rust if needed."
        echo ""
        return 1
    fi

    local rust_version=$(cargo --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    info "  Rust: OK (v$rust_version)"
    return 0
}

# Check if huggingface_hub is installed
check_huggingface() {
    if ! python3 -c "import huggingface_hub" 2>/dev/null; then
        warn "huggingface_hub Python package not installed."
        echo ""
        echo "  We recommend using a virtual environment:"
        echo ""
        echo "    cd $(pwd)"
        echo "    python3 -m venv .venv"
        echo "    source .venv/bin/activate"
        echo "    pip install huggingface_hub"
        echo ""
        echo "  Or install globally (not recommended):"
        echo "    pip install --user huggingface_hub"
        echo ""
        return 1
    fi

    local hf_version=$(python3 -c "import huggingface_hub; print(huggingface_hub.__version__)")
    info "  huggingface_hub: OK (v$hf_version)"
    return 0
}

# Run all prerequisite checks
check_all_prerequisites() {
    info "Checking prerequisites..."
    echo ""

    local errors=0

    check_go || errors=$((errors + 1))
    check_python || errors=$((errors + 1))
    check_pip_venv || errors=$((errors + 1))
    check_rust || true  # Rust is optional, will be auto-installed
    check_huggingface || errors=$((errors + 1))

    echo ""

    if [[ $errors -gt 0 ]]; then
        echo "═══════════════════════════════════════════════════════════"
        warn "$errors prerequisite(s) missing. Please install them first."
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        echo "Quick setup guide:"
        echo ""
        echo "  # 1. Create virtual environment"
        echo "  python3 -m venv .venv"
        echo "  source .venv/bin/activate"
        echo ""
        echo "  # 2. Install huggingface_hub"
        echo "  pip install huggingface_hub"
        echo ""
        echo "  # 3. Run setup again"
        echo "  ./scripts/setup-ml.sh"
        echo ""
        exit 1
    fi

    info "All prerequisites satisfied!"
    echo ""
}

# Check Python prerequisites for model download (legacy, kept for compatibility)
check_python_prereqs() {
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is required. Please install Python 3.9+ first."
    fi

    # Check if huggingface_hub is installed
    if ! python3 -c "import huggingface_hub" 2>/dev/null; then
        warn "huggingface_hub not found. Installing..."
        python3 -m pip install --quiet huggingface_hub
        if ! python3 -c "import huggingface_hub" 2>/dev/null; then
            error "Failed to install huggingface_hub. Please install manually:\n  pip install huggingface_hub"
        fi
        info "huggingface_hub installed successfully"
    fi
}

# Download model from HuggingFace
download_model() {
    info "Downloading tihilya ModernBERT model..."
    info "Target directory: $MODEL_DIR"

    # Ensure model directory exists
    mkdir -p "$MODEL_DIR"

    # Check if huggingface-cli is available (preferred method)
    if command -v huggingface-cli &> /dev/null; then
        info "Using huggingface-cli..."
        # Note: --local-dir-use-symlinks is deprecated in newer versions, omitting it
        huggingface-cli download "$MODEL_NAME" --local-dir "$MODEL_DIR"
    elif command -v python3 &> /dev/null; then
        # Check and install huggingface_hub if needed
        check_python_prereqs

        info "Using Python huggingface_hub..."
        # Note: local_dir_use_symlinks is deprecated in newer huggingface_hub versions
        # The library no longer uses symlinks by default when local_dir is specified
        python3 << EOF
import warnings
warnings.filterwarnings("ignore", message=".*local_dir_use_symlinks.*")

from huggingface_hub import snapshot_download
import os

model_dir = "$MODEL_DIR"
print(f"Downloading to: {model_dir}")

snapshot_download(
    repo_id="$MODEL_NAME",
    local_dir=model_dir
)
print("Model downloaded successfully!")
EOF
    else
        # Manual download with curl (fallback)
        info "Downloading model files with curl..."

        BASE_URL="https://huggingface.co/$MODEL_NAME/resolve/main"
        FILES=(
            "config.json"
            "model.onnx"
            "special_tokens_map.json"
            "tokenizer_config.json"
            "tokenizer.json"
        )

        for file in "${FILES[@]}"; do
            info "  Downloading $file..."
            curl -sL "$BASE_URL/$file" -o "$MODEL_DIR/$file"
        done
    fi

    # Verify model files exist
    if [[ -f "$MODEL_DIR/model.onnx" ]] && [[ -f "$MODEL_DIR/tokenizer.json" ]]; then
        local size=$(du -sh "$MODEL_DIR" | cut -f1)
        info "Model downloaded successfully ($size)"
        info "Model location: $MODEL_DIR"
    else
        error "Model download failed - missing required files.\n  Expected: $MODEL_DIR/model.onnx\n  Please check your internet connection and try again."
    fi
}

# Download ONNX Runtime
download_onnx() {
    local platform=$(detect_platform)
    local onnx_extract_dir="${ONNX_DIR}-${platform}-${ONNX_VERSION}"

    # Windows uses .zip, others use .tgz
    local onnx_file=""
    local onnx_url=""
    case "$platform" in
        win-x64)
            onnx_file="onnxruntime-win-x64-${ONNX_VERSION}.zip"
            onnx_url="https://github.com/microsoft/onnxruntime/releases/download/v${ONNX_VERSION}/${onnx_file}"
            ;;
        win-x86)
            onnx_file="onnxruntime-win-x86-${ONNX_VERSION}.zip"
            onnx_url="https://github.com/microsoft/onnxruntime/releases/download/v${ONNX_VERSION}/${onnx_file}"
            ;;
        *)
            onnx_file="onnxruntime-${platform}-${ONNX_VERSION}.tgz"
            onnx_url="https://github.com/microsoft/onnxruntime/releases/download/v${ONNX_VERSION}/${onnx_file}"
            ;;
    esac

    info "Downloading ONNX Runtime ${ONNX_VERSION} for ${platform}..."

    if [[ -d "$onnx_extract_dir" ]]; then
        info "ONNX Runtime already exists at $onnx_extract_dir"
        return 0
    fi

    # Download and extract in subshell to avoid changing parent's cwd
    (
        cd "$HOME"
        if [[ ! -f "$onnx_file" ]]; then
            curl -sLO "$onnx_url"
        fi

        # Extract based on file type
        case "$onnx_file" in
            *.zip)
                unzip -q "$onnx_file"
                ;;
            *.tgz)
                tar -xzf "$onnx_file"
                ;;
        esac
        rm -f "$onnx_file"
    )

    info "ONNX Runtime extracted to: $onnx_extract_dir"

    # Print library path for export
    echo ""
    case "$platform" in
        win-*)
            echo "Add to your environment (PowerShell):"
            echo "  \$env:CGO_LDFLAGS = \"-L${onnx_extract_dir}/lib\""
            echo "  \$env:PATH = \"${onnx_extract_dir}/lib;\$env:PATH\""
            echo ""
            echo "Or add to system PATH via Settings > Environment Variables"
            ;;
        osx-*)
            echo "Add to your shell profile (~/.zshrc or ~/.bashrc):"
            echo "  export CGO_LDFLAGS=\"-L${onnx_extract_dir}/lib\""
            echo "  export DYLD_LIBRARY_PATH=\"${onnx_extract_dir}/lib:\$DYLD_LIBRARY_PATH\""
            ;;
        linux-*)
            echo "Add to your shell profile (~/.bashrc):"
            echo "  export CGO_LDFLAGS=\"-L${onnx_extract_dir}/lib\""
            echo "  export LD_LIBRARY_PATH=\"${onnx_extract_dir}/lib:\$LD_LIBRARY_PATH\""
            ;;
    esac
}

# Build tokenizers library (macOS/Windows build, Linux pre-built)
build_tokenizers() {
    local platform=$(detect_platform)

    if [[ "$platform" == linux-* ]]; then
        info "Downloading pre-built tokenizers for Linux..."
        sudo curl -sL "https://github.com/knights-analytics/hugot/releases/latest/download/libtokenizers.a" \
            -o /usr/local/lib/libtokenizers.a
        info "Tokenizers installed to /usr/local/lib/libtokenizers.a"
        return 0
    fi

    local tokenizers_dir="${HOME}/tokenizers"

    case "$platform" in
        osx-*)
            info "Building tokenizers library for macOS..."
            ;;
        win-*)
            info "Building tokenizers library for Windows..."
            ;;
    esac

    # Check for Rust
    if ! command -v cargo &> /dev/null; then
        warn "Rust not found. Installing via rustup..."
        case "$platform" in
            win-*)
                error "Please install Rust manually from https://rustup.rs/ then re-run this script."
                ;;
            *)
                curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
                source "$HOME/.cargo/env"
                ;;
        esac
    fi

    # Clone if not exists
    if [[ ! -d "$tokenizers_dir" ]]; then
        git clone --depth 1 https://github.com/daulet/tokenizers.git "$tokenizers_dir"
    fi

    # Build in subshell to avoid changing parent's cwd
    (
        cd "$tokenizers_dir"
        case "$platform" in
            win-*)
                # Windows build
                cargo build --release
                ;;
            *)
                # macOS build
                make build
                ;;
        esac
    )

    case "$platform" in
        win-*)
            info "Tokenizers built at: ${tokenizers_dir}/target/release/tokenizers.lib"
            echo ""
            echo "Add to environment (PowerShell):"
            echo "  \$env:CGO_LDFLAGS = \"\$env:CGO_LDFLAGS -L${tokenizers_dir}/target/release\""
            ;;
        *)
            info "Tokenizers built at: ${tokenizers_dir}/libtokenizers.a"
            echo ""
            echo "Add to CGO_LDFLAGS:"
            echo "  export CGO_LDFLAGS=\"\$CGO_LDFLAGS -L${tokenizers_dir}\""
            ;;
    esac
}

# Verify installation
verify_install() {
    info "Verifying ML setup..."
    local errors=0
    local platform=$(detect_platform)

    # Check model
    if [[ -f "$MODEL_DIR/model.onnx" ]]; then
        local model_size=$(du -h "$MODEL_DIR/model.onnx" 2>/dev/null | cut -f1 || echo "unknown")
        info "  Model: OK ($model_size)"
    else
        warn "  Model: NOT FOUND at $MODEL_DIR"
        errors=$((errors + 1))
    fi

    # Check ONNX Runtime
    local onnx_lib="${ONNX_DIR}-${platform}-${ONNX_VERSION}/lib"
    if [[ -d "$onnx_lib" ]]; then
        info "  ONNX Runtime: OK ($onnx_lib)"
    else
        warn "  ONNX Runtime: NOT FOUND at $onnx_lib"
        errors=$((errors + 1))
    fi

    # Check tokenizers
    local tokenizers_path=""
    case "$platform" in
        win-*)
            if [[ -f "${HOME}/tokenizers/target/release/tokenizers.lib" ]]; then
                tokenizers_path="${HOME}/tokenizers/target/release/tokenizers.lib"
            fi
            ;;
        linux-*)
            if [[ -f "/usr/local/lib/libtokenizers.a" ]]; then
                tokenizers_path="/usr/local/lib/libtokenizers.a"
            fi
            ;;
        osx-*)
            if [[ -f "${HOME}/tokenizers/libtokenizers.a" ]]; then
                tokenizers_path="${HOME}/tokenizers/libtokenizers.a"
            fi
            ;;
    esac

    if [[ -n "$tokenizers_path" ]]; then
        info "  Tokenizers: OK ($tokenizers_path)"
    else
        warn "  Tokenizers: NOT FOUND"
        errors=$((errors + 1))
    fi

    echo ""
    if [[ $errors -eq 0 ]]; then
        info "All components verified!"
        print_env_setup
        return 0
    else
        error "Missing $errors component(s). Run './scripts/setup-ml.sh' to install."
    fi
}

# Print environment setup
print_env_setup() {
    local platform=$(detect_platform)
    local onnx_lib="${ONNX_DIR}-${platform}-${ONNX_VERSION}/lib"
    local tokenizers_lib=""

    case "$platform" in
        win-*)
            if [[ -f "${HOME}/tokenizers/target/release/tokenizers.lib" ]]; then
                tokenizers_lib="${HOME}/tokenizers/target/release"
            fi
            ;;
        linux-*)
            if [[ -f "/usr/local/lib/libtokenizers.a" ]]; then
                tokenizers_lib="/usr/local/lib"
            fi
            ;;
        osx-*)
            if [[ -f "${HOME}/tokenizers/libtokenizers.a" ]]; then
                tokenizers_lib="${HOME}/tokenizers"
            fi
            ;;
    esac

    echo ""
    case "$platform" in
        win-*)
            echo "Environment setup (PowerShell):"
            echo "─────────────────────────────────────────────────"
            echo "\$env:CGO_LDFLAGS = \"-L${onnx_lib} -L${tokenizers_lib}\""
            echo "\$env:PATH = \"${onnx_lib};\$env:PATH\""
            echo "\$env:HUGOT_MODEL_PATH = \"${MODEL_DIR}\""
            echo "\$env:CITADEL_ENABLE_HUGOT = \"true\""
            echo ""
            echo "Or set as system environment variables via Settings."
            echo ""
            echo "Then build and test:"
            echo "  go build -tags ORT -o citadel.exe ./cmd/gateway"
            echo "  go test -tags ORT ./pkg/ml/... -v -run Integration"
            ;;
        osx-*)
            echo "Environment setup (add to ~/.zshrc):"
            echo "─────────────────────────────────────────────────"
            echo "export CGO_LDFLAGS=\"-L${onnx_lib} -L${tokenizers_lib}\""
            echo "export DYLD_LIBRARY_PATH=\"${onnx_lib}:\$DYLD_LIBRARY_PATH\""
            echo "export HUGOT_MODEL_PATH=\"${MODEL_DIR}\""
            echo "export CITADEL_ENABLE_HUGOT=true"
            echo ""
            echo "Then build and test:"
            echo "  go build -tags ORT -o citadel ./cmd/gateway"
            echo "  go test -tags ORT ./pkg/ml/... -v -run Integration"
            ;;
        linux-*)
            echo "Environment setup (add to ~/.bashrc):"
            echo "─────────────────────────────────────────────────"
            echo "export CGO_LDFLAGS=\"-L${onnx_lib} -L${tokenizers_lib}\""
            echo "export LD_LIBRARY_PATH=\"${onnx_lib}:\$LD_LIBRARY_PATH\""
            echo "export HUGOT_MODEL_PATH=\"${MODEL_DIR}\""
            echo "export CITADEL_ENABLE_HUGOT=true"
            echo ""
            echo "Then build and test:"
            echo "  go build -tags ORT -o citadel ./cmd/gateway"
            echo "  go test -tags ORT ./pkg/ml/... -v -run Integration"
            ;;
    esac
}

# Clean downloaded files
clean() {
    info "Cleaning ML assets..."

    if [[ -d "$MODEL_DIR" ]]; then
        rm -rf "$MODEL_DIR"
        info "Removed model directory"
    fi

    local platform=$(detect_platform)
    local onnx_extract_dir="${ONNX_DIR}-${platform}-${ONNX_VERSION}"
    if [[ -d "$onnx_extract_dir" ]]; then
        rm -rf "$onnx_extract_dir"
        info "Removed ONNX Runtime"
    fi

    info "Clean complete"
}

# Full setup
full_setup() {
    echo "═══════════════════════════════════════════════════════════"
    echo "  Citadel ML Detection Layer Setup"
    echo "  Model: tihilya ModernBERT-base (Apache 2.0)"
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    # Check all prerequisites first
    check_all_prerequisites

    info "Step 1/4: Downloading BERT model from HuggingFace..."
    download_model
    echo ""

    info "Step 2/4: Downloading ONNX Runtime..."
    download_onnx
    echo ""

    info "Step 3/4: Building tokenizers library..."
    build_tokenizers
    echo ""

    info "Step 4/4: Verifying installation..."
    verify_install
}

# Main
case "${1:-full}" in
    full|"")
        full_setup
        ;;
    prereqs|prerequisites|check)
        check_all_prerequisites
        ;;
    model)
        check_python
        check_huggingface || {
            warn "huggingface_hub required for model download."
            echo "  pip install huggingface_hub"
            exit 1
        }
        download_model
        ;;
    onnx)
        download_onnx
        ;;
    tokenizers)
        build_tokenizers
        ;;
    verify)
        verify_install
        ;;
    clean)
        clean
        ;;
    help|--help|-h)
        echo "Citadel ML Detection Layer Setup"
        echo ""
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  full        Full setup (prereqs + model + ONNX + tokenizers) [default]"
        echo "  prereqs     Check prerequisites only (Go, Python, Rust, huggingface_hub)"
        echo "  model       Download tihilya BERT model from HuggingFace (~600MB)"
        echo "  onnx        Download ONNX Runtime ${ONNX_VERSION} (~100MB)"
        echo "  tokenizers  Build tokenizers library (macOS) or download (Linux)"
        echo "  verify      Verify all components are installed correctly"
        echo "  clean       Remove downloaded files"
        echo "  help        Show this help"
        echo ""
        echo "Prerequisites:"
        echo "  • Go ${MIN_GO_VERSION}+        Required for building Citadel"
        echo "  • Python ${MIN_PYTHON_VERSION}+     Required for model download"
        echo "  • huggingface_hub  Python package for HuggingFace downloads"
        echo "  • Rust            Required on macOS for tokenizers (auto-installed)"
        echo ""
        echo "Quick start:"
        echo "  # 1. Set up Python environment"
        echo "  python3 -m venv .venv && source .venv/bin/activate"
        echo "  pip install huggingface_hub"
        echo ""
        echo "  # 2. Run full setup"
        echo "  ./scripts/setup-ml.sh"
        echo ""
        echo "  # 3. Build with ML support"
        echo "  go build -tags ORT -o citadel ./cmd/gateway"
        ;;
    *)
        error "Unknown command: $1. Use '$0 help' for usage."
        ;;
esac
