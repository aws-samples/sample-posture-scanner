#!/usr/bin/env bash
# install-prerequisites.sh — one-step prerequisite installer for aws-posture (macOS/Linux).
#
# Installs, in isolated pipx environments:
#   - the aws-posture CLI wheel
#   - Prowler 5.36.0        (AWS posture scans)
#   - Semgrep CE 1.171.0    (SAST)
# and installs Gitleaks 8.30.1 + Trivy 0.72.0 via Homebrew when available.
#
# Usage:
#   ./scripts/install-prerequisites.sh [path-to-wheel]
#
# Defaults to the current repository folder (install from source).
# Re-run "aws-posture check" and "aws-posture check --code" afterwards.

set -euo pipefail

WHEEL="${1:-.}"

# Prowler and Semgrep require Python 3.10-3.13 (not 3.14+). Auto-detect the best
# available interpreter unless the caller overrides PYTHON_FOR_ENGINES.
detect_engine_python() {
  for candidate in python3.13 python3.12 python3.11 python3.10; do
    if command -v "$candidate" >/dev/null 2>&1; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}
PYTHON_FOR_ENGINES="${PYTHON_FOR_ENGINES:-$(detect_engine_python || true)}"

echo "==> aws-posture prerequisite installer"

# 1. Ensure pipx is available.
if ! command -v pipx >/dev/null 2>&1; then
  echo "==> Installing pipx"
  python3 -m pip install --user pipx
  python3 -m pipx ensurepath
  echo "    Open a new terminal if 'pipx' is not yet on PATH, then re-run this script."
fi

# 2. Install the aws-posture CLI.
if [ -f "$WHEEL" ] || [ -f "$WHEEL/pyproject.toml" ]; then
  echo "==> Installing aws-posture from $WHEEL"
  pipx install --force "$WHEEL"
else
  echo "!! Wheel not found: $WHEEL"
  echo "   Pass the wheel path explicitly, e.g. ./scripts/install-prerequisites.sh /path/to/sample-aws-posture-scanner"
  exit 1
fi

# 3. Install the pinned Python engines.
if [ -n "$PYTHON_FOR_ENGINES" ] && command -v "$PYTHON_FOR_ENGINES" >/dev/null 2>&1; then
  echo "==> Installing Prowler 5.36.0 and Semgrep CE 1.171.0 (via $PYTHON_FOR_ENGINES)"
  pipx install --force --python "$PYTHON_FOR_ENGINES" prowler==5.36.0
  pipx install --force --python "$PYTHON_FOR_ENGINES" semgrep==1.171.0
else
  echo "!! No supported Python found (need 3.10-3.13; looked for python3.13/3.12/3.11/3.10)."
  echo "   Install one (e.g. 'brew install python@3.13') and re-run, or set PYTHON_FOR_ENGINES."
  echo "   Prowler/Semgrep do not support Python 3.14+."
fi

# 4. Install Gitleaks + Trivy.
if command -v brew >/dev/null 2>&1; then
  echo "==> Installing Gitleaks and Trivy via Homebrew"
  brew install gitleaks trivy
else
  echo "!! Homebrew not found. Install the pinned binaries manually:"
  echo "   - Gitleaks 8.30.1: https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1"
  echo "   - Trivy   0.72.0 : https://github.com/aquasecurity/trivy/releases/tag/v0.72.0"
  echo "   Verify the published SHA-256/signature and place each binary on PATH."
fi

echo
echo "==> Verifying prerequisites"
aws-posture check || true
aws-posture check --code || true

echo
echo "Done. Fix any MISS items above (version must match exactly), then run a scan."
