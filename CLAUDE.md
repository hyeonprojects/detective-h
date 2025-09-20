# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Detective-H is a comprehensive security analysis and vulnerability detection tool designed for developers. It provides malware detection, code security analysis, dependency scanning, and infrastructure security checks. The project is organized into multiple modules:

- **CLI Module** (`cli/`): Python-based command-line interface for virus detection and analysis
- **Core Module** (`core/`): C/C++ implementation of cryptographic functions (Blake3 hashing)
- **Server Module** (`server/`): Web interface and API backend (under development)

## Development Commands

### Python CLI Development
```bash
# Navigate to CLI directory
cd cli

# Install the package in development mode
pip install -e .

# Run the virus tracker CLI
python -m virus_tracker --help

# Available CLI commands:
virus-tracker analyze <file> --threshold 0.85    # Analyze file for viruses
virus-tracker add <file> --name <virus_name>     # Add virus sample to database
virus-tracker list                                # List all virus samples
virus-tracker hash <file> --size 32              # Calculate Blake3 hash
virus-tracker compare <file1> <file2>            # Compare two files using Hamming distance
```

### C Library Development
```bash
# Navigate to core directory
cd core/clang_module

# Build the Blake3 library
mkdir build && cd build
cmake ..
cmake --build .

# This generates blake3.dll (Windows) or libblake3.so (Linux/macOS)
# The Python wrapper expects the library at: core/build/blake3.dll
```

### Testing
No formal test framework is currently configured. Testing is performed manually using the CLI commands.

## Code Architecture

### High-Level Structure

```
detective-h/
├── cli/virus_tracker/          # Python malware detection engine
│   ├── __main__.py            # CLI entry point and command parsing
│   ├── virus_analyzer.py      # Core analysis engine with database management
│   ├── virus_comparator.py    # File comparison using Blake3 and Hamming distance
│   └── blake3_wrapper.py      # Python ctypes wrapper for C Blake3 library
├── core/clang_module/         # C implementation of cryptographic functions
│   ├── src/internal/blake3.c  # Blake3 hash algorithm implementation
│   └── include/blake3.h       # Blake3 header definitions
└── server/                    # Web interface (future development)
```

### Key Components

**Virus Analysis Engine** (`virus_analyzer.py`):
- Manages virus sample database with JSON metadata storage
- Handles file analysis using similarity thresholds
- Supports adding new virus samples with automatic hash calculation
- Database location: `data/virus_db/` (auto-created)

**File Comparison System** (`virus_comparator.py`):
- Uses Blake3 cryptographic hashing for file fingerprinting
- Implements Hamming distance calculation for similarity analysis
- Provides both byte-level and bit-level comparison methods
- Default similarity threshold: 85% for virus detection

**Blake3 Integration**:
- C library provides high-performance cryptographic hashing with parallel processing support
- Python wrapper uses ctypes for seamless integration
- Supports configurable digest sizes (any size, default: 32 bytes)
- Optimized for large file processing with chunked reading and better performance than Blake2b

### Key Design Patterns

**Database Management**: JSON-based metadata storage with automatic hash caching and file copying to isolated virus database directory.

**Modular CLI**: Command-based interface using argparse with subcommands for different operations (analyze, add, list, hash, compare).

**Cross-Platform Support**: Conditional library loading for Windows (.dll), Linux (.so), and macOS (.dylib) with automatic path detection.

**Error Handling**: Comprehensive exception handling with user-friendly Korean error messages and graceful degradation when C library is unavailable.

## Development Notes

### Dependencies
- **Python**: Requires Python 3.6+ with ctypes (standard library)
- **C Compiler**: CMake 3.30+ and C11-compatible compiler for Blake2b library
- **Optional**: LLVM for advanced analysis features (configured in CMakeLists.txt)

### Language Support
The codebase is bilingual (Korean/English) with Korean used for user-facing messages and English for code comments and technical documentation.

### Security Considerations
- Virus samples are isolated in dedicated database directory
- Hash-based identification prevents execution of malicious code
- File copying ensures original samples remain untouched
- Configurable similarity thresholds prevent false positives

### Future Development
The project roadmap includes web interface development, MCP (Model Context Protocol) integration, and expanded language support for static analysis beyond the current malware detection capabilities.