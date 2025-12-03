# Ghidra Anonymization Scripts

A collection of Python scripts for anonymizing metadata in Ghidra server repositories, designed to remove identifying information from binary analysis projects.

## Overview

When files are uploaded to a Ghidra server, they retain metadata including local file paths, usernames, and other identifying information. These scripts help sanitize Ghidra projects for sharing or publication by removing or replacing such details.

## Scripts

### Core Anonymization

- **`anonymizeFile.py`** - Scrubs executable paths and FSRL metadata from a single program, replacing local paths with server-relative paths
- **`anonymizeFiles.py`** - Applies anonymization across all files in a Ghidra server repository
- **`anonymizeCommentHistory.py`** - Replaces usernames in comment history with an anonymous identifier.  Requires our Ghidra fork (for now)
- **`anonymizeLabelHistory.py`** - Replaces usernames in label history with an anonymous identifier.  Requires our Ghidra fork (for now)

### Utilities

- **`traverseServer.py`** - Provides recursive traversal functionality for operating on all files or a subset of files in a Ghidra server
- **`terminateCheckouts.py`** - Forcibly removes checkouts from files on the Ghidra server

## Usage

These scripts are designed to run within Ghidra's script environment:

1. Open your Ghidra project
2. Navigate to **Window → Script Manager**
3. Run the desired script from the Scripts menu

### Cloning this repository

- **Without our Ghidra fork** - Clone as normal
- **With our Ghidra fork** - Use `git clone --recursive` if cloning fresh, or `git submodule update --init` if previously cloned without the `--recursive` flag

### Example Workflows

**Anonymize a single file:**
```
Scripts → anonymizeFile
```

**Anonymize entire repository:**
```
Scripts → anonymizeFiles
```

**Anonymize user history:**
```
Scripts → anonymizeCommentHistory
Scripts → anonymizeLabelHistory
```

## Requirements

- Ghidra (with Python scripting support)
- Active Ghidra server connection (for multi-file operations)

