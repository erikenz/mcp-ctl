# Install mcp-ctl on Windows.
#
#   irm https://raw.githubusercontent.com/erikenz/mcp-ctl/main/install/install.ps1 | iex
#
# With options:
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/erikenz/mcp-ctl/main/install/install.ps1))) -Version 0.1.0
#
# The download is verified against the release's .sha256 before anything is installed.
param(
    [string]$Version = "",
    [string]$To = "$env:LOCALAPPDATA\mcp-ctl\bin"
)

$ErrorActionPreference = "Stop"
$repo = "erikenz/mcp-ctl"

if (-not $Version) {
    $latest = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
    $Version = $latest.tag_name.TrimStart("v")
} else {
    $Version = $Version.TrimStart("v")
}

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "invalid version '$Version': expected a release version such as 1.2.3"
}

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "x86_64" }
    # No aarch64 Windows build is published; the x64 binary runs under the
    # emulation Windows 11 on ARM ships with.
    "ARM64" {
        Write-Host "No ARM64 build yet; installing the x64 binary, which runs under emulation."
        "x86_64"
    }
    default { throw "unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
}

$archive = "mcp-ctl-$Version-$arch-pc-windows-msvc.zip"
$url = "https://github.com/$repo/releases/download/v$Version/$archive"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    Write-Host "Downloading $archive"
    Invoke-WebRequest -Uri $url -OutFile (Join-Path $tmp $archive)
    Invoke-WebRequest -Uri "$url.sha256" -OutFile (Join-Path $tmp "$archive.sha256")

    $expected = ((Get-Content (Join-Path $tmp "$archive.sha256") -Raw).Trim() -split '\s+')[0].ToLower()
    $actual = (Get-FileHash (Join-Path $tmp $archive) -Algorithm SHA256).Hash.ToLower()
    if ($expected -ne $actual) { throw "checksum mismatch for $archive" }

    Expand-Archive -Path (Join-Path $tmp $archive) -DestinationPath $tmp
    $binary = Join-Path $tmp "mcp-ctl.exe"
    if (-not (Test-Path $binary)) { throw "the archive does not contain mcp-ctl.exe" }

    New-Item -ItemType Directory -Force -Path $To | Out-Null
    Copy-Item $binary (Join-Path $To "mcp-ctl.exe") -Force
    Write-Host "Installed to $(Join-Path $To 'mcp-ctl.exe')"

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (($userPath -split ';') -notcontains $To) {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$To", "User")
        Write-Host "Added $To to your user PATH. Open a new terminal to use mcp-ctl."
    }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
