param(
    [string]$RepoName = "whyward",
    [ValidateSet("private", "public")]
    [string]$Visibility = "private",
    [string]$Owner = ""
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git is required"
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI (gh) is required"
}
if (-not (Test-Path "pyproject.toml") -or -not (Test-Path "src/whyward")) {
    throw "Run this script from the WhyWard repository root"
}

Get-ChildItem -Recurse -Directory -Filter "__pycache__" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
foreach ($runtimeDir in @(".whyward-demo", ".whyward-runtime")) {
    if (Test-Path $runtimeDir) {
        Remove-Item $runtimeDir -Recurse -Force
    }
}

if (-not (Test-Path ".git")) {
    git init -b main
}

git add .
$changes = git status --porcelain
if ($changes) {
    git commit -m "Initial WhyWard boundary control plane"
}

$repo = if ($Owner) { "$Owner/$RepoName" } else { $RepoName }
$visibilityFlag = "--$Visibility"
$hasOrigin = $false
try {
    git remote get-url origin *> $null
    $hasOrigin = $true
} catch {
    $hasOrigin = $false
}

if ($hasOrigin) {
    git push -u origin main
} else {
    gh repo create $repo $visibilityFlag --source=. --remote=origin --push --description "WhyWard — an evidence-gated boundary control plane for AI workers"
}

gh repo view $repo --web
