$ErrorActionPreference = 'Stop'

function Invoke-Git {
    param([Parameter(Mandatory)][string[]]$GitArgs)

    & git @GitArgs
    if ($LASTEXITCODE -ne 0) {
        throw "git $($GitArgs -join ' ') failed with exit code $LASTEXITCODE"
    }
}

Push-Location $PSScriptRoot
try {
    $changes = & git status --porcelain
    if ($LASTEXITCODE -ne 0) { throw 'Could not read git status.' }
    if ($changes) { throw 'Commit or stash all changes before releasing.' }

    $branch = ((& git branch --show-current) -join '').Trim()
    if ($LASTEXITCODE -ne 0 -or -not $branch) { throw 'Check out a branch before releasing.' }

    $packagePath = Join-Path $PSScriptRoot 'vscode-extension/package.json'
    $package = [System.IO.File]::ReadAllText($packagePath)
    $versionPattern = '(?m)(^\s*"version"\s*:\s*")([0-9]+)\.([0-9]+)\.([0-9]+)("\s*,?\s*$)'
    $matches = [regex]::Matches($package, $versionPattern)
    if ($matches.Count -ne 1) { throw 'Could not find exactly one stable semver version in vscode-extension/package.json.' }

    $current = $matches[0]
    $major = [int]$current.Groups[2].Value
    $minor = [int]$current.Groups[3].Value + 1
    $version = "$major.$minor.0"
    $tag = "vscode-v$version"

    $existingTag = ((& git tag --list $tag) -join '').Trim()
    if ($LASTEXITCODE -ne 0) { throw 'Could not check existing git tags.' }
    if ($existingTag) { throw "Tag $tag already exists." }

    $replacement = $current.Groups[1].Value + $version + $current.Groups[5].Value
    $updated = $package.Remove($current.Index, $current.Length).Insert($current.Index, $replacement)
    [System.IO.File]::WriteAllText($packagePath, $updated, [System.Text.UTF8Encoding]::new($false))

    Invoke-Git -GitArgs @('add', '--', 'vscode-extension/package.json')
    Invoke-Git -GitArgs @('commit', '-m', "Release VS Code extension $version")
    Invoke-Git -GitArgs @('push', 'origin', $branch)
    Invoke-Git -GitArgs @('tag', $tag)
    Invoke-Git -GitArgs @('push', 'origin', $tag)

    Write-Host "Pushed $tag. GitHub Actions will build and publish the VS Code release."
}
finally {
    Pop-Location
}
