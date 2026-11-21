# SPDX-License-Identifier: GPL-2.0-or-later
#
# Builds the Windows zip to share: Remule.exe (the launcher, remule-app),
# remuled.exe, remule-gui.exe, a README for the people it is shared with,
# and the license. The C runtime is linked in (.cargo/config.toml), so
# nothing else needs installing.
#
# Usage: powershell -File scripts\package-windows.ps1
# Output: dist\remule-<version>-windows-x64.zip

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$version = (Select-String -Path "remuled\Cargo.toml" -Pattern '^version = "(.*)"').Matches[0].Groups[1].Value
$name = "remule-$version-windows-x64"
$stage = Join-Path $root "dist\$name"

cargo build --release -p remuled -p remule-gui -p remule-app
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force $stage | Out-Null
Copy-Item "target\release\remule-app.exe" (Join-Path $stage "Remule.exe")
Copy-Item "target\release\remuled.exe" $stage
Copy-Item "target\release\remule-gui.exe" $stage
Copy-Item "packaging\windows\README.txt" $stage
Copy-Item "LICENSE.md" $stage

$zip = Join-Path $root "dist\$name.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path $stage -DestinationPath $zip
$size = [math]::Round((Get-Item $zip).Length / 1MB, 1)
Write-Output "$zip ($size MB)"
