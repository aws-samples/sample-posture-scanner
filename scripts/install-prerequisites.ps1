# install-prerequisites.ps1 — one-step prerequisite installer for aws-posture (Windows PowerShell).
#
# Installs the aws-posture CLI, Prowler 5.36.0, and Semgrep CE 1.171.0 via pipx.
# Gitleaks 8.30.1 and Trivy 0.72.0 must be downloaded from their official releases,
# checksum-verified, and placed on PATH (a link is printed below).
#
# Usage:
#   .\scripts\install-prerequisites.ps1 [-Wheel <path-to-wheel>]

param(
    [string]$Wheel = ".",
    [string]$PythonForEngines = ""
)

$ErrorActionPreference = "Stop"
Write-Host "==> aws-posture prerequisite installer"

# Prowler/Semgrep require Python 3.10-3.13 (not 3.14+). Auto-detect via the py
# launcher unless -PythonForEngines was given.
if (-not $PythonForEngines) {
    foreach ($v in @("3.13", "3.12", "3.11", "3.10")) {
        py -$v -c "1" 2>$null
        if ($LASTEXITCODE -eq 0) { $PythonForEngines = $v; break }
    }
}
if (-not $PythonForEngines) {
    Write-Host "!! No supported Python found (need 3.10-3.13; Prowler/Semgrep do not support 3.14+)."
    Write-Host "   Install Python 3.13 from python.org, then re-run."
    exit 1
}
Write-Host "==> Using Python $PythonForEngines for scanner engines"

# 1. Ensure pipx.
if (-not (Get-Command pipx -ErrorAction SilentlyContinue)) {
    Write-Host "==> Installing pipx"
    py -m pip install pipx
    py -m pipx ensurepath
    Write-Host "    Open a NEW PowerShell if 'pipx' is not yet on PATH, then re-run this script."
}

# 2. Install the aws-posture CLI.
if (Test-Path $Wheel) {
    Write-Host "==> Installing aws-posture from $Wheel"
    pipx install --force $Wheel
} else {
    Write-Host "!! Wheel not found: $Wheel"
    Write-Host "   Pass -Wheel <path> pointing to the repository folder or a built wheel"
    exit 1
}

# 3. Install the pinned Python engines.
Write-Host "==> Installing Prowler 5.36.0 and Semgrep CE 1.171.0 (Python $PythonForEngines)"
pipx install --force --python $PythonForEngines prowler==5.36.0
pipx install --force --python $PythonForEngines semgrep==1.171.0

# 4. Gitleaks + Trivy guidance.
Write-Host "!! Install the pinned binaries manually and add them to PATH:"
Write-Host "   - Gitleaks 8.30.1: https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1"
Write-Host "   - Trivy   0.72.0 : https://github.com/aquasecurity/trivy/releases/tag/v0.72.0"
Write-Host "   Verify the published SHA-256/signature before use."

Write-Host ""
Write-Host "==> Verifying prerequisites"
aws-posture check
aws-posture check --code

Write-Host ""
Write-Host "Done. Fix any MISS items above (version must match exactly), then run a scan."
