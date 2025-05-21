# Detective-H

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Language](https://img.shields.io/badge/language-C%20%7C%20Python-orange.svg)

> A robust virus tracking and analysis system using BLAKE2b hash algorithm for virus comparison and identification.

## 📋 Overview

Detective-H is a powerful system designed to track and analyze virus files. By leveraging advanced hash algorithms like BLAKE2b, it provides reliable methods for virus file comparison and identification. The system combines C language efficiency with Python's ease of use and flexibility.

## 🚀 Features

- **BLAKE2b Hash Algorithm** - Utilizes BLAKE2b for secure and fast virus file signature generation
- **Virus Database Management** - Maintains a database of known virus samples with metadata
- **Similarity Analysis** - Calculates similarity between files to detect virus variants
- **Cross-Platform Support** - Works across multiple operating systems and environments

## 🔧 Installation

### Building the C Library

```bash
# Navigate to the core build directory
mkdir -p core/build && cd core/build

# Build using CMake
cmake ../clang_module
cmake --build . --config Release
```

### Installing the Python Package

```bash
# Navigate to the python directory
cd python

# Install the package
pip install -e .
```

## 📖 Usage

### Command Line Interface (CLI)

```bash
# Analyze a file for virus matches
virus-tracker analyze <file-path> [--threshold similarity-threshold] [--db database-path]

# Add a virus sample to the database
virus-tracker add <file-path> [--name virus-name] [--type virus-type] [--description description]

# List all registered virus samples
virus-tracker list

# Calculate the Blake2b hash of a file
virus-tracker hash <file-path> [--size hash-size]

# Compare two files
virus-tracker compare <file1> <file2>
```

### Using in Python

```python
from virus_tracker.virus_analyzer import VirusAnalyzer
from virus_tracker.virus_comparator import hex_hash, compare_virus_with_hamming

# Initialize the analyzer
analyzer = VirusAnalyzer()

# Add a virus sample
analyzer.add_virus_sample('malware.exe', 'Malware.Win32.Example')

# Analyze a file
results = analyzer.analyze_file('suspicious.exe')
for virus_name, similarity in results:
    print(f"- {virus_name}: {similarity:.2%} match")

# Calculate file hash
hash_val = hex_hash('file.exe')
print(f"File hash: {hash_val}")

# Compare files
distance, similarity = compare_virus_with_hamming('file1.exe', 'file2.exe')
print(f"Similarity: {similarity:.2%}")
```

## 🗂️ Project Structure

```
detective-h/
├── core/
│   ├── clang_module/            # C code implementation
│   │   ├── include/             # Header files
│   │   │   ├── blake2b.h
│   │   │   └── hash.h
│   │   ├── src/                 # Source files
│   │   │   ├── hash.c
│   │   │   └── internal/
│   │   │       └── blake2b.c
│   │   └── CMakeLists.txt       # C module build script
│   │
│   └── build/                   # Compiled binaries (created during build)
│
├── python/
│   ├── virus_tracker/           # Main Python package
│   │   ├── __init__.py
│   │   ├── __main__.py          # CLI entry point
│   │   ├── blake2b_wrapper.py   # C library wrapper
│   │   ├── virus_analyzer.py    # Virus analysis logic
│   │   └── virus_comparator.py  # Virus comparison logic
│   │
│   └── setup.py                 # Python package setup script
│
└── data/                        # Data storage (automatically created)
    └── virus_db/                # Virus sample database (automatically created)
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Author

- **Hyeon** - [hyeonprojects](https://github.com/hyeonprojects)

---

Made with ❤️ in Seoul, Korea
