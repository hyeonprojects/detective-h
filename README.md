# Detective-H

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Language](https://img.shields.io/badge/language-C%20%7C%20Python%20%7C%20JavaScript-orange.svg)
![Status](https://img.shields.io/badge/status-Development-yellow.svg)

> Comprehensive security analysis and vulnerability detection tool for developers

## 📋 Overview

Detective-H is an integrated security tool that helps developers proactively identify and resolve security issues during the coding process. It provides security checks across the entire development lifecycle, from code analysis to package vulnerability scanning and configuration file security verification.

## 🚀 Core Features

### 🔍 Code Security Analysis
- **Static Code Analysis** - Automatic detection of security vulnerabilities in source code
- **LLM-based Analysis** - Advanced code pattern and logic vulnerability analysis using AI

### 🦠 Malware Detection
- **BLAKE2b Hash Analysis** - High-performance malicious file identification using hash algorithms
- **Virus Signature Matching** - Comparative analysis with known malicious code patterns
- **Variant Detection** - Malware variant identification through similarity analysis

### 📦 Dependency Security Scanning
- **Package Vulnerability Scan** - Vulnerability checks for package managers like npm, pip, maven
- **License Compatibility Verification** - Analysis of open source license conflicts and security risks (Optional)
- **Update Recommendations** - Upgrade guides to versions with security patches applied

### ⚙️ Configuration File Security Verification (Currently undecided)
- **Environment Configuration Analysis** - Check for sensitive information exposure in .env, config files
- **Cloud Configuration Verification** - Security checks for AWS, GCP, Azure cloud resource configurations
- **DevOps Security** - Verification of security best practices compliance for Docker, Kubernetes configurations

### 📊 Reports and Dashboard
- **Detailed Security Reports** - Detailed analysis and solutions for discovered vulnerabilities
- **Risk Assessment** - Severity classification and prioritization by vulnerability
- **Fix Guide** - Specific code modification examples and best practices

## 📊 Development Progress

### Overall Project Progress
![Progress](https://img.shields.io/badge/Overall_Progress-25%25-orange.svg)

### Module Development Status

#### 🔍 Code Security Analysis Module
![Code Analysis](https://img.shields.io/badge/Progress-15%25-red.svg)
- [x] Basic project structure design
- [ ] Static analysis engine development `In Progress`
- [ ] LLM API integration
- [ ] Vulnerability pattern database construction
- [ ] Real-time analysis system

#### 🦠 Malware Detection Module
![Malware Detection](https://img.shields.io/badge/Progress-60%25-yellow.svg)
- [x] BLAKE2b hash algorithm implementation
- [x] Basic C library structure
- [x] Python wrapper development
- [x] Basic CLI commands
- [ ] Virus signature database
- [ ] Similarity analysis algorithm optimization

#### 📦 Dependency Security Scanning Module
![Dependency Check](https://img.shields.io/badge/Progress-5%25-red.svg)
- [x] Module design completed
- [ ] Package manager-specific parser development
- [ ] Vulnerability database integration
- [ ] License compatibility verification logic
- [ ] Update recommendation system

#### ⚙️ Configuration File Security Verification Module
![Config Security](https://img.shields.io/badge/Progress-10%25-red.svg)
- [x] Requirements analysis completed
- [ ] Environment configuration file parser
- [ ] Sensitive information detection rules
- [ ] Cloud configuration verification logic
- [ ] DevOps security check functionality

#### 🌐 Web Interface
![Web Interface](https://img.shields.io/badge/Progress-0%25-lightgrey.svg)
- [ ] UI/UX design
- [ ] Frontend framework setup
- [ ] API server development
- [ ] Dashboard implementation
- [ ] Report generation system

#### 🔌 MCP (Model Context Protocol)
![MCP](https://img.shields.io/badge/Progress-0%25-lightgrey.svg)
- [ ] MCP specification analysis
- [ ] Protocol implementation
- [ ] AI tool integration testing
- [ ] Documentation

## 🛠️ Supported Platforms and Tools

### 💻 Integrated Development Environment
- **Web Interface** - Browser-based comprehensive security analysis dashboard
- **CLI Tool** - Lightweight analysis tool available from command line
- **MCP (Model Context Protocol)** - Protocol support for seamless integration with AI tools

### 🔧 Language and Framework Support
- **Programming Languages**: Python, JavaScript/TypeScript, Java, C/C++, Go, Rust
- **Web Frameworks**: React, Vue.js, Angular, Django, Flask, Express.js
- **Mobile**: React Native, Flutter
- **DevOps**: Docker, Kubernetes, Terraform


## 📋 License

This project is distributed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 👨‍💻 Developer

**Hyeon** - [hyeonprojects](https://github.com/hyeonprojects)

---

> 🔒 **Security is not an option, it's a necessity**  
> Write secure code with Detective-H.

---

*Made with ❤️ in Seoul, Korea*