param(
    [string]$Output = "dirtysepbypass-kpm-loader.zip"
)

$ErrorActionPreference = "Stop"

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
$moduleDir = (Resolve-Path (Join-Path $repo "module-kpm")).Path.TrimEnd("\")
$outPath = Join-Path (Split-Path $repo -Parent) $Output

if (Test-Path -LiteralPath $outPath) {
    Remove-Item -LiteralPath $outPath -Force
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$zip = [System.IO.Compression.ZipFile]::Open($outPath, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    Get-ChildItem -LiteralPath $moduleDir -Recurse -File -Force |
        Where-Object { $_.Name -notlike ".fuse_hidden*" -and $_.Name -notlike "*.tmp*" } |
        ForEach-Object {
            $rel = $_.FullName.Substring($moduleDir.Length + 1).Replace("\", "/")
            [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $zip,
                $_.FullName,
                $rel,
                [System.IO.Compression.CompressionLevel]::Optimal
            ) | Out-Null
        }
}
finally {
    if ($zip) { $zip.Dispose() }
}

Write-Host "Wrote $outPath"

$zipRead = [System.IO.Compression.ZipFile]::OpenRead($outPath)
try {
    $zipRead.Entries |
        Sort-Object FullName |
        Select-Object FullName, Length |
        Format-Table -AutoSize
}
finally {
    $zipRead.Dispose()
}
