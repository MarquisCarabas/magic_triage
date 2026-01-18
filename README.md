# 🔍 File Triage Tool

**Automated Malware Detection Using Magic Byte Analysis**

[![Python](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Educational-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://remnux.org/)

---

## 📋 Overview

A Python-based security tool that automates malware triage by analyzing files based on their magic bytes rather than trusting file extensions.

> **Why Magic Bytes?** Attackers rename `malware.exe` to `document.pdf` to bypass basic security filters. This tool examines the file's actual header structure, which cannot be faked by simple renaming.

---

## ✨ Key Features

- 🔎 **Magic Byte Validation** - Identifies true file types by reading binary signatures
- 🚨 **Extension Spoofing Detection** - Flags files where extension doesn't match content
- 🔐 **Cryptographic Hashing** - Generates MD5 and SHA256 for threat intelligence correlation
- 📁 **Automated Categorization** - Sorts files by true type (executables, scripts, documents, etc.)
- 📊 **CSV Report Generation** - Produces SOC-ready reports for incident response
- ⚡ **Fast Processing** - Analyzes 88 files in ~2 minutes

---

## 🎯 What It Does
```
┌─────────────────────┐
│  Suspicious Files   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   Scan Directory    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  For Each File:     │
│  • Read magic bytes │
│  • Generate hashes  │
│  • Detect mismatches│
│  • Categorize       │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Sorted Folders +   │
│  CSV Report         │
└─────────────────────┘
```

**Detects:**
- Executables disguised as images (`.jpg`, `.gif`, `.png`)
- Executables disguised as documents (`.pdf`, `.docx`)
- Scripts with incorrect extensions
- Empty decoy files
- Obfuscated malware samples

---

## 🚀 Quick Start

### Prerequisites
```bash
# Linux (tested on REMnux)
# Python 3.6+
```

### Installation
```bash
# Clone the repository
git clone https://github.com/MarquisCarabas/file_triage.git
cd file_triage

# Install dependencies
pip install python-magic --break-system-packages
```

### Usage
```bash
python3 file_triage.py <source_directory> <output_directory>
```

**Example:**
```bash
python3 file_triage.py ~/suspicious_files ~/triage_results
```

**With logging:**
```bash
python3 file_triage.py ~/suspicious_files ~/triage_results | tee analysis.log
```

---

## 📂 Output Structure

### Sorted Folders
```
output_directory/
├── executables/       # PE32, PE32+, ELF binaries
├── scripts/          # Python, PowerShell, Bash
├── text_documents/   # ASCII text, CSV, JSON
├── archives/         # ZIP, RAR, compressed files
├── images/           # JPEG, PNG, BMP, GIF
├── documents/        # PDF, Word documents
└── other/            # Unknown or empty files
```

### CSV Report
```csv
Original Filename,True File Type,Hash (SHA256),Notes
vacation.jpg,PE32 executable,a1b2c3d4...,Mismatched extension
invoice.pdf,PDF document,e5f6g7h8...,
UpdateDriver.exe,PGP Secret Key,f9g0h1i2...,Mismatched extension
```

---

## 🔬 How It Works

### Magic Bytes Explained

The tool identifies files by reading their binary signatures:

| File Type | Magic Bytes | Hex | Can't Be Spoofed |
|-----------|-------------|-----|------------------|
| PE Executable | `MZ` | `4D 5A` | ✅ |
| PNG Image | `.PNG` | `89 50 4E 47` | ✅ |
| PDF Document | `%PDF` | `25 50 44 46` | ✅ |
| ZIP Archive | `PK` | `50 4B 03 04` | ✅ |

### Detection Logic

1. **Scan** - Recursively walk through target directory
2. **Hash** - Generate MD5 and SHA256 for each file
3. **Validate** - Read magic bytes to determine true file type
4. **Compare** - Check if extension matches true type
5. **Sort** - Copy files to category folders
6. **Report** - Generate CSV with all findings

---

## 📊 Example Results

**Terminal Output:**
```
============================================================
FILE TRIAGE TOOL
============================================================
Source: /home/remnux/suspicious_files
Output: /home/remnux/triage_results
============================================================

Scanning directory...
Found 88 files to process

Processing: UnrealEngine.gif
  Type: PE32+ executable (console) x86-64
  Category: executables
  Notes: Mismatched extension ⚠️

Processing: printerUpdate_2023.pdf
  Type: PE32+ executable (stripped)
  Category: executables
  Notes: Mismatched extension ⚠️

[...]

============================================================
TRIAGE COMPLETE
============================================================
Total files processed: 88
Mismatched extensions: 15
Report: /home/remnux/triage_report.csv
============================================================
```

---

## 💡 Use Cases

- 🛡️ **SOC Operations** - First-pass automated triage before Tier 2/3 escalation
- 🔍 **Incident Response** - Rapid analysis of files from compromised systems
- 🧪 **Malware Analysis Labs** - Automated processing of sample collections
- 🏆 **CTF Competitions** - Quick file identification in forensics challenges
- 📚 **Security Training** - Teaching proper file validation techniques

---

**Time Savings:**
- Manual analysis: 20+ hours
- Automated triage: ~2-3 minutes
- **ROI: 400x faster** ⚡

---

## 🛠️ Technical Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3 |
| Magic Bytes | python-magic library |
| Hashing | hashlib (MD5, SHA256) |
| Environment | REMnux Linux |
| Methodology | File forensics & static analysis |

---

## 🔐 Security Notes

**Safe Operation:**
- ✅ Read-only analysis (never executes files)
- ✅ Files are copied, not moved (preserves originals)
- ✅ No network connections made
- ✅ All analysis is static

**Best Practices:**
- Use in isolated VM (REMnux recommended)
- Don't run on production systems
- Keep malware samples quarantined
- Use host-only networking for analysis VMs

---

## 🐛 Troubleshooting

<details>
<summary><b>ModuleNotFoundError: No module named 'magic'</b></summary>
```bash
pip install python-magic --break-system-packages
```
Make sure to install `python-magic`, not `filemagic`.
</details>

<details>
<summary><b>Permission denied errors</b></summary>
```bash
chmod +x file_triage.py
# Or run with python3 explicitly
python3 file_triage.py <source> <output>
```
</details>

<details>
<summary><b>Empty file types in CSV</b></summary>

File is either truly empty (0 bytes) or couldn't be read.
```bash
ls -lh <file>
file <file>
```
</details>

---

## 📈 Real-World Results

**From Lab 2 Analysis:**
- ✅ Detected 15 extension spoofing attempts
- ✅ Identified executables disguised as images, PDFs, and system files
- ✅ Found PGP secret key masquerading as `.exe` (credential theft indicator)
- ✅ Flagged 18 empty decoy files
- ✅ Successfully triaged 88 files with 100% accuracy

---

**⭐ If you found this tool useful, please star the repository!**
