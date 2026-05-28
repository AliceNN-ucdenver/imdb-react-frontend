#!/usr/bin/env bash
# The Red Queen's Court — PreToolUse Hook Validator (shell wrapper)
#
# Shared entry point for both Claude Code and Copilot hooks.
# Delegates to the Node.js validator for platform-independent logic.
#
# Usage: Invoked automatically by Claude/Copilot preToolUse hooks.
# Input: JSON on stdin    Output: JSON on stdout

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec node "${SCRIPT_DIR}/validate-tool.js"
