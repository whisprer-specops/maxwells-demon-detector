# Copyright (C) 2026 whispr.dev
# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
function Invoke-Cargo {
    param([Parameter(Mandatory)][string[]]$CargoArguments)
    & cargo @CargoArguments
    if ($LASTEXITCODE -ne 0) {
        throw "cargo $($CargoArguments -join ' ') failed with exit code $LASTEXITCODE"
    }
}
Push-Location (Join-Path $PSScriptRoot '..')
try {
    Invoke-Cargo -CargoArguments @('fmt', '--all', '--check')
    Invoke-Cargo -CargoArguments @('test', '--locked', '--all-targets')
    Invoke-Cargo -CargoArguments @('test', '--locked', '--doc')
    Invoke-Cargo -CargoArguments @('clippy', '--locked', '--all-targets', '--', '-D', 'warnings')
    Invoke-Cargo -CargoArguments @('build', '--locked', '--release')
    # The built-in demo, headless and as fast as it can go: frames as plain text, then the alert log.
    $frame = & cargo run --locked --release -- --headless --fast --frames 480 --width 120 --height 36
    if ($LASTEXITCODE -ne 0) { throw "the headless demo failed with exit code $LASTEXITCODE" }
    New-Item -ItemType Directory -Force 'target' | Out-Null
    $frame | Set-Content -Encoding utf8 'target\demo-frame.txt'
    if (-not (Select-String -Path 'target\demo-frame.txt' -Pattern 'MAXWELL' -Quiet)) {
        throw 'the headless demo printed no frame'
    }
    Write-Host 'Demo frame written to target\demo-frame.txt.'
    Write-Host "Maxwell's Demon Detector validation passed."
}
finally {
    Pop-Location
}
