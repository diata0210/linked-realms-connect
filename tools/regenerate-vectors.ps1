$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('connect-vectors-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $scratch | Out-Null
$original = (Get-FileHash -LiteralPath (Join-Path $repo 'protocol/vectors/v1.json') -Algorithm SHA256).Hash
$savedWorkspace = $env:GOWORK
try {
    $env:GOWORK = 'off'
    foreach ($pass in @('first', 'second')) {
        $run = Join-Path $scratch $pass
        New-Item -ItemType Directory -Path (Join-Path $run 'protocol'), (Join-Path $run 'tools') | Out-Null
        Copy-Item -LiteralPath (Join-Path $repo 'protocol/v1.md') -Destination (Join-Path $run 'protocol/v1.md')
        Copy-Item -LiteralPath (Join-Path $repo 'tools/vectorgen') -Destination (Join-Path $run 'tools/vectorgen') -Recurse
        Push-Location (Join-Path $run 'tools/vectorgen')
        try { & go run .; if ($LASTEXITCODE -ne 0) { throw 'Vector generator failed' } }
        finally { Pop-Location }
        $actual = (Get-FileHash -LiteralPath (Join-Path $run 'protocol/vectors/v1.json') -Algorithm SHA256).Hash
        if ($actual -ne $original) { throw "Vector regeneration differs: $pass" }
    }
    Write-Output 'Both independent vector regenerations are byte-identical to the frozen file.'
}
finally { $env:GOWORK = $savedWorkspace }
# Keep scratch output for diagnosis. Never recursively delete a computed path.
