<#
.SYNOPSIS
    Install socks5-ss-proxy on Windows
.DESCRIPTION
    Downloads the latest socks5-ss-proxy.exe from GitHub Actions,
    installs keys.json, and optionally registers as a Windows service.
.USAGE
    # Basic install (run as Administrator):
    irm https://raw.githubusercontent.com/DmitrySorda/envoy-socks5-ss/master/scripts/install-windows.ps1 | iex

    # Or run locally with pre-downloaded binary:
    .\install-windows.ps1 -BinaryPath .\socks5-ss-proxy.exe -KeysFile .\keys.json

    # Specify listen address:
    .\install-windows.ps1 -ListenAddr "127.0.0.1:1080" -KeysFile "C:\path\to\keys.json"
#>

param(
    [string]$InstallDir   = "C:\socks5-ss",
    [string]$ListenAddr   = "127.0.0.1:1080",
    [string]$BinaryPath   = "",
    [string]$KeysFile     = "",
    [string]$LbPolicy     = "round_robin",
    [switch]$AsService,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$RepoOwner = "DmitrySorda"
$RepoName  = "envoy-socks5-ss"
$ArtifactName = "socks5-ss-proxy-windows-amd64"
$ServiceName  = "Socks5SSProxy"

# ============================================================================
# Helpers
# ============================================================================

function Write-Step($msg) { Write-Host ">> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "   OK: $msg" -ForegroundColor Green }
function Write-Err($msg)  { Write-Host "   ERROR: $msg" -ForegroundColor Red }

# ============================================================================
# Uninstall
# ============================================================================

if ($Uninstall) {
    Write-Step "Uninstalling socks5-ss-proxy..."

    # Stop and remove service
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        Write-Ok "Service removed"
    }

    # Kill process
    Get-Process -Name "socks5-ss-proxy" -ErrorAction SilentlyContinue | Stop-Process -Force

    # Remove files
    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force
        Write-Ok "Removed $InstallDir"
    }

    # Remove firewall rule
    Remove-NetFirewallRule -DisplayName "SOCKS5-SS Proxy" -ErrorAction SilentlyContinue

    Write-Host "`nUninstalled successfully." -ForegroundColor Green
    exit 0
}

# ============================================================================
# Install
# ============================================================================

Write-Host @"

  ╔══════════════════════════════════════╗
  ║   SOCKS5-SS Proxy Installer (Win)   ║
  ╚══════════════════════════════════════╝

"@ -ForegroundColor Yellow

# --- Step 1: Create install directory ---
Write-Step "Creating install directory: $InstallDir"
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Write-Ok "Directory ready"

# --- Step 2: Get binary ---
$destExe = Join-Path $InstallDir "socks5-ss-proxy.exe"
if ($BinaryPath -and (Test-Path $BinaryPath)) {
    $srcFull = (Resolve-Path $BinaryPath).Path
    $dstFull = if (Test-Path $destExe) { (Resolve-Path $destExe).Path } else { $destExe }
    if ($srcFull -eq $dstFull) {
        Write-Step "Binary already at $InstallDir"
        Write-Ok "Binary in place"
    } else {
        Write-Step "Copying binary from $BinaryPath..."
        Copy-Item -Path $BinaryPath -Destination $destExe -Force
        Write-Ok "Binary copied from local path"
    }
} elseif (Test-Path $destExe) {
    Write-Step "Using existing binary in $InstallDir"
    Write-Ok "Binary already present"
} else {
    Write-Step "Downloading socks5-ss-proxy.exe..."

    # Check if gh CLI is available
    $ghAvailable = Get-Command gh -ErrorAction SilentlyContinue

    if ($ghAvailable) {
        Write-Host "   Using GitHub CLI..." -ForegroundColor Gray
        Push-Location $InstallDir
        gh run download --repo "$RepoOwner/$RepoName" `
            --name $ArtifactName `
            --dir . 2>&1 | Out-Null

        if ($LASTEXITCODE -ne 0) {
            Write-Err "gh download failed. Trying direct download..."
            $ghAvailable = $false
        }
        Pop-Location
    }

    if (-not $ghAvailable) {
        Write-Host "   GitHub CLI not found. Trying latest release..." -ForegroundColor Gray

        $releaseUrl = "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
        try {
            $release = Invoke-RestMethod -Uri $releaseUrl -Headers @{"Accept"="application/vnd.github.v3+json"}
            $asset = $release.assets | Where-Object { $_.name -like "*windows*" } | Select-Object -First 1

            if ($asset) {
                $zipPath = Join-Path $env:TEMP "socks5-ss-proxy-win.zip"
                Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath
                Expand-Archive -Path $zipPath -DestinationPath $InstallDir -Force
                Remove-Item $zipPath -Force
            } else {
                throw "No Windows asset in latest release"
            }
        } catch {
            Write-Err "Could not download binary automatically."
            Write-Host @"

   Please download manually:
   1. Go to https://github.com/$RepoOwner/$RepoName/actions
   2. Open latest 'Build SOCKS5-SS Proxy' run
   3. Download '$ArtifactName' artifact
   4. Extract socks5-ss-proxy.exe to: $InstallDir

"@ -ForegroundColor Yellow
            Read-Host "Press Enter after placing the binary..."
        }
    }
}

$exePath = Join-Path $InstallDir "socks5-ss-proxy.exe"
if (-not (Test-Path $exePath)) {
    Write-Err "Binary not found at $exePath"
    exit 1
}
Write-Ok "Binary: $exePath"

# --- Step 3: Keys configuration ---
Write-Step "Setting up keys.json..."

$keysDestPath = Join-Path $InstallDir "keys.json"

if ($KeysFile -and (Test-Path $KeysFile)) {
    $srcKeys = (Resolve-Path $KeysFile).Path
    $dstKeys = if (Test-Path $keysDestPath) { (Resolve-Path $keysDestPath).Path } else { $keysDestPath }
    if ($srcKeys -ne $dstKeys) {
        Copy-Item -Path $KeysFile -Destination $keysDestPath -Force
        Write-Ok "Copied keys from $KeysFile"
    } else {
        Write-Ok "Keys already in place"
    }
} elseif (Test-Path $keysDestPath) {
    Write-Ok "Using existing keys.json"
} else {
    # Create a template
    $template = @'
{
  "keys": [
    {
      "method": "chacha20-ietf-poly1305",
      "password": "YOUR_PASSWORD_HERE",
      "host": "YOUR_SERVER_IP",
      "port": 8080,
      "tag": "My SS Server",
      "country": "US"
    }
  ]
}
'@
    Set-Content -Path $keysDestPath -Value $template -Encoding UTF8
    Write-Host "   Created template at: $keysDestPath" -ForegroundColor Yellow
    Write-Host "   EDIT THIS FILE with your Shadowsocks server details!" -ForegroundColor Yellow
}

# Count servers
try {
    $keysData = Get-Content $keysDestPath -Raw | ConvertFrom-Json
    $serverCount = $keysData.keys.Count
    Write-Ok "$serverCount Shadowsocks servers configured"
} catch {
    Write-Err "Could not parse keys.json"
}

# --- Step 4: Firewall rule ---
Write-Step "Adding firewall rule..."
$port = ($ListenAddr -split ':')[-1]
try {
    Remove-NetFirewallRule -DisplayName "SOCKS5-SS Proxy" -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "SOCKS5-SS Proxy" `
        -Direction Inbound -Protocol TCP -LocalPort $port `
        -Action Allow -Profile Private | Out-Null
    Write-Ok "Firewall rule added for port $port"
} catch {
    Write-Host "   WARN: Could not add firewall rule (need admin). Add manually if needed." -ForegroundColor Yellow
}

# --- Step 5: Create launcher script ---
Write-Step "Creating launcher..."

$launcherPath = Join-Path $InstallDir "start-proxy.cmd"
$launcherContent = @"
@echo off
title SOCKS5-SS Proxy [$ListenAddr]
echo Starting SOCKS5-SS Proxy on $ListenAddr ...
echo Press Ctrl+C to stop.
echo.
"$exePath" --listen $ListenAddr --keys "$keysDestPath" --lb $LbPolicy
pause
"@
Set-Content -Path $launcherPath -Value $launcherContent -Encoding ASCII
Write-Ok "Launcher: $launcherPath"

# --- Step 6 (optional): Install as Windows service ---
if ($AsService) {
    Write-Step "Installing as Windows service..."

    # Use NSSM if available, otherwise sc.exe
    $nssmPath = Get-Command nssm -ErrorAction SilentlyContinue

    if ($nssmPath) {
        nssm install $ServiceName "$exePath"
        nssm set $ServiceName AppParameters "--listen $ListenAddr --keys `"$keysDestPath`" --lb $LbPolicy"
        nssm set $ServiceName DisplayName "SOCKS5-SS Proxy"
        nssm set $ServiceName Description "SOCKS5 to Shadowsocks proxy with load balancing"
        nssm set $ServiceName Start SERVICE_AUTO_START
        nssm start $ServiceName
        Write-Ok "Service installed and started via NSSM"
    } else {
        sc.exe create $ServiceName `
            binpath= "`"$exePath`" --listen $ListenAddr --keys `"$keysDestPath`" --lb $LbPolicy" `
            start= auto `
            displayname= "SOCKS5-SS Proxy" | Out-Null
        Start-Service -Name $ServiceName
        Write-Ok "Service installed and started"
    }
} else {
    Write-Host "`n   To install as a service later, run:" -ForegroundColor Gray
    Write-Host "   .\install-windows.ps1 -AsService" -ForegroundColor Gray
}

# --- Step 7: Add to PATH ---
Write-Step "Adding to PATH..."
try {
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($currentPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallDir", "Machine")
        Write-Ok "Added $InstallDir to system PATH"
    } else {
        Write-Ok "Already in PATH"
    }
} catch {
    Write-Host "   WARN: Could not modify PATH (need admin)." -ForegroundColor Yellow
}

# ============================================================================
# Done!
# ============================================================================

Write-Host @"

  ╔══════════════════════════════════════════════════════╗
  ║             Installation Complete!                   ║
  ╠══════════════════════════════════════════════════════╣
  ║                                                      ║
  ║  Binary:  $($exePath.PadRight(40))║
  ║  Keys:    $($keysDestPath.PadRight(40))║
  ║  Listen:  $($ListenAddr.PadRight(40))║
  ║                                                      ║
  ║  Quick start:                                        ║
  ║    $($launcherPath.PadRight(50))║
  ║                                                      ║
  ║  Browser proxy settings:                             ║
  ║    Type:    SOCKS5                                   ║
  ║    Host:    $($ListenAddr.Split(':')[0].PadRight(40))║
  ║    Port:    $($port.PadRight(40))║
  ║                                                      ║
  ║  Chrome shortcut:                                    ║
  ║    chrome.exe --proxy-server="socks5://$ListenAddr"  ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝

"@ -ForegroundColor Green
