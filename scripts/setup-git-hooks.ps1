# Enable version-controlled git hooks for this repository (auto-push on commit).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

git config core.hooksPath .githooks
Write-Host "core.hooksPath = .githooks (this repo only)"

if (git ls-files --error-unmatch .githooks/post-commit 2>$null) {
  git update-index --chmod=+x .githooks/post-commit 2>$null
}
if (git ls-files --error-unmatch .cursor/hooks/auto-push.sh 2>$null) {
  git update-index --chmod=+x .cursor/hooks/auto-push.sh 2>$null
}
Write-Host "Git hooks ready. Commits on main will auto-push to origin."
