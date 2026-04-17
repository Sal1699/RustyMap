# RustyMap installer (Windows PowerShell)
# Usage:
#   iwr -useb https://sal1699.github.io/RustyMap/install.ps1 | iex
#   & ([scriptblock]::Create((iwr -useb https://sal1699.github.io/RustyMap/install.ps1))) -Version v0.1.0
#   & ([scriptblock]::Create((iwr -useb https://sal1699.github.io/RustyMap/install.ps1))) -Prefix "$env:USERPROFILE\bin"
#
# NOTE: uses `return` (not `exit`) so that a failure inside `iex` doesn't
#       close the host PowerShell window.

param(
    [string]$Version = "latest",
    [string]$Prefix  = "",
    [switch]$InstallNpcap
)

$ErrorActionPreference = "Stop"
$Repo = "Sal1699/RustyMap"

# ── colors ───────────────────────────────────────────
$esc = [char]27
$O = "$esc[38;2;247;129;0m"
$A = "$esc[38;2;255;176;0m"
$Y = "$esc[38;2;245;232;46m"
$D = "$esc[38;2;140;90;20m"
$R = "$esc[0m"

function Say  { Write-Host "$O`λ$R $($args[0])" }
function Warn { Write-Host "$Y`!$R $($args[0])" }
function Err  { Write-Host "$A`x$R $($args[0])" -ForegroundColor Red }

# ── detect arch ──────────────────────────────────────
$arch = $env:PROCESSOR_ARCHITECTURE
if ($arch -ne "AMD64") {
    Err "Architettura non supportata: $arch (serve x86_64)."
    Err "Compila da sorgente: https://github.com/$Repo"
    return
}
$Asset = "rustymap-windows-x86_64.zip"

# ── pick prefix ──────────────────────────────────────
if (-not $Prefix) {
    $Prefix = Join-Path $env:LOCALAPPDATA "Programs\RustyMap"
}
New-Item -ItemType Directory -Path $Prefix -Force | Out-Null

# ── resolve release via API (clearer error if none) ──
if ($Version -eq "latest") {
    $ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
} else {
    $ApiUrl = "https://api.github.com/repos/$Repo/releases/tags/$Version"
}

Say "controllo release: ${D}${ApiUrl}${R}"
try {
    $rel = Invoke-RestMethod -Uri $ApiUrl -Headers @{ "User-Agent" = "rustymap-installer" } -UseBasicParsing
} catch {
    Err "Nessuna release trovata ($Version)."
    Err "Verifica su https://github.com/$Repo/releases"
    Err "Se sei il maintainer, pubblicane una: git tag v0.1.0; git push origin v0.1.0"
    return
}

$assetObj = $rel.assets | Where-Object { $_.name -eq $Asset } | Select-Object -First 1
if (-not $assetObj) {
    Err "La release $($rel.tag_name) non contiene l'asset $Asset."
    Err "Attendi che il workflow di build abbia caricato tutti i binari."
    return
}
$Url = $assetObj.browser_download_url

# ── download ─────────────────────────────────────────
$Tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "rustymap-install-$(Get-Random)") -Force
$Zip = Join-Path $Tmp $Asset

Say "detected: ${A}windows/x86_64${R} · version: ${A}$($rel.tag_name)${R}"
Say "download: ${D}${Url}${R}"

try {
    Invoke-WebRequest -Uri $Url -OutFile $Zip -UseBasicParsing
} catch {
    Err "Download fallito: $($_.Exception.Message)"
    Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue
    return
}

Say "estrazione..."
try {
    Expand-Archive -Path $Zip -DestinationPath $Tmp -Force
} catch {
    Err "Estrazione fallita: $($_.Exception.Message)"
    Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue
    return
}

$BinSrc = Get-ChildItem -Path $Tmp -Recurse -Filter "rustymap.exe" | Select-Object -First 1
if (-not $BinSrc) {
    Err "Binario rustymap.exe non trovato nell'archivio."
    Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue
    return
}

$BinDst = Join-Path $Prefix "rustymap.exe"
try {
    Copy-Item $BinSrc.FullName $BinDst -Force
} catch {
    Err "Copia fallita: $($_.Exception.Message)"
    Err "Prefix: $Prefix"
    Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue
    return
}

Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue
Say "installato in ${A}${BinDst}${R}"

# ── PATH ─────────────────────────────────────────────
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$Prefix*") {
    Say "aggiungo $Prefix al PATH utente"
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $Prefix } else { "$userPath;$Prefix" }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Warn "riapri il terminale perché la modifica al PATH abbia effetto"
}

# ── Npcap check ──────────────────────────────────────
$npcap = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
if (-not $npcap) {
    Warn "Npcap non installato. Per scan SYN/raw lancia (come admin):"
    Warn "  rustymap.exe --install-npcap"
    if ($InstallNpcap) {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Warn "-InstallNpcap richiede PowerShell admin — salto"
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
