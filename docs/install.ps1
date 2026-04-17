# RustyMap installer (Windows PowerShell)
# Usage:
#   iwr -useb https://sal1699.github.io/RustyMap/install.ps1 | iex
#   & ([scriptblock]::Create((iwr -useb https://sal1699.github.io/RustyMap/install.ps1))) -Version v0.1.0
#   & ([scriptblock]::Create((iwr -useb https://sal1699.github.io/RustyMap/install.ps1))) -Prefix "$env:USERPROFILE\bin"

param(
    [string]$Version = "latest",
    [string]$Prefix  = "",
    [switch]$InstallNpcap
)

$ErrorActionPreference = "Stop"
$Repo = "Sal1699/RustyMap"

# ── colors ─────────────────────────────────────────────
$O = [char]27 + "[38;2;247;129;0m"
$A = [char]27 + "[38;2;255;176;0m"
$Y = [char]27 + "[38;2;245;232;46m"
$D = [char]27 + "[38;2;140;90;20m"
$R = [char]27 + "[0m"

function Say($msg)  { Write-Host "$O`λ$R $msg" }
function Warn($msg) { Write-Host "$Y!$R $msg" -ForegroundColor Yellow }
function Die($msg)  { Write-Host "$A`x$R $msg" -ForegroundColor Red; exit 1 }

# ── detect arch ────────────────────────────────────────
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne "AMD64") {
    Die "Architettura non supportata: $arch (serve x86_64). Compila da sorgente: https://github.com/$Repo"
}
$Asset = "rustymap-windows-x86_64.zip"

# ── pick prefix ────────────────────────────────────────
if (-not $Prefix) {
    $Prefix = Join-Path $env:LOCALAPPDATA "Programs\RustyMap"
}
New-Item -ItemType Directory -Path $Prefix -Force | Out-Null

# ── url ────────────────────────────────────────────────
if ($Version -eq "latest") {
    $Url = "https://github.com/$Repo/releases/latest/download/$Asset"
} else {
    $Url = "https://github.com/$Repo/releases/download/$Version/$Asset"
}

$Tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "rustymap-install-$(Get-Random)") -Force
$Zip = Join-Path $Tmp $Asset

Say "detected: ${A}windows/x86_64${R} · version: ${A}${Version}${R}"
Say "download: ${D}${Url}${R}"

try {
    Invoke-WebRequest -Uri $Url -OutFile $Zip -UseBasicParsing
} catch {
    Die "download fallito: $($_.Exception.Message)"
}

Say "estrazione..."
Expand-Archive -Path $Zip -DestinationPath $Tmp -Force

$BinSrc = Get-ChildItem -Path $Tmp -Recurse -Filter "rustymap.exe" | Select-Object -First 1
if (-not $BinSrc) { Die "binario rustymap.exe non trovato nell'archivio" }

$BinDst = Join-Path $Prefix "rustymap.exe"
Copy-Item $BinSrc.FullName $BinDst -Force

# ── cleanup ────────────────────────────────────────────
Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue

Say "installato in ${A}${BinDst}${R}"

# ── PATH ───────────────────────────────────────────────
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$Prefix*") {
    Say "aggiungo $Prefix al PATH utente"
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $Prefix } else { "$userPath;$Prefix" }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Warn "riapri il terminale perché la modifica al PATH abbia effetto"
}

# ── Npcap check ────────────────────────────────────────
$npcap = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
if (-not $npcap) {
    Warn "Npcap non installato. Per scan SYN/raw lancia (come admin):"
    Warn "  rustymap.exe --install-npcap"
    if ($InstallNpcap) {
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Warn "--InstallNpcap richiede PowerShell admin — salto"
        } else {
            Say "installo Npcap tramite rustymap..."
            & $BinDst --install-npcap
        }
    }
}

Write-Host ""
Write-Host "$O`λ$R Rise and shine, Mr. Freeman..."
Write-Host "  ${Y}rustymap --guide${R}"
Write-Host ""
