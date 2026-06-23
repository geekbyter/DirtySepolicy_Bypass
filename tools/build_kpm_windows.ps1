param(
    [ValidateSet("smoke", "dirtyduck", "all")]
    [string]$Target = "all",
    [string]$NdkRoot = "$env:LOCALAPPDATA\Android\Sdk\ndk\29.0.14206865",
    [string]$KpDir = ""
)

$ErrorActionPreference = "Stop"

$repo = Resolve-Path (Join-Path $PSScriptRoot "..")
if (-not $KpDir) {
    $KpDir = (Resolve-Path (Join-Path $repo "..\_refs\selinux_hook\KernelPatch")).Path
}

$cc = Join-Path $NdkRoot "toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android31-clang.cmd"
if (-not (Test-Path -LiteralPath $cc)) {
    throw "Cannot find NDK clang: $cc"
}

$includeDirs = @(
    ".",
    "include",
    "patch/include",
    "linux",
    "linux/include",
    "linux/security/selinux/include",
    "linux/arch/arm64/include",
    "linux/tools/arch/arm64/include"
) | ForEach-Object {
    "-I" + (Join-Path (Join-Path $KpDir "kernel") $_)
}

function Build-Kpm {
    param(
        [string]$Dir,
        [string]$Source,
        [string]$Object,
        [string]$Output
    )

    $src = Join-Path $Dir $Source
    $obj = Join-Path $Dir $Object
    $out = Join-Path $Dir $Output

    $cflags = @(
        "-Wall",
        "-O2",
        "-fno-PIC",
        "-fno-asynchronous-unwind-tables",
        "-fno-stack-protector",
        "-fno-common",
        "-Wno-typedef-redefinition",
        "-std=gnu99"
    )

    & $cc @cflags @includeDirs "-c" $src "-o" $obj
    if ($LASTEXITCODE -ne 0) {
        throw "compile failed: $Source"
    }

    & $cc "-r" "-nostdlib" "-o" $out $obj
    if ($LASTEXITCODE -ne 0) {
        throw "link failed: $Output"
    }

    Get-Item -LiteralPath $out
}

$built = @()
if ($Target -eq "smoke" -or $Target -eq "all") {
    $dir = Join-Path $repo "kpm\smoke"
    $built += Build-Kpm $dir "dirtyduck_smoke.c" "dirtyduck_smoke.o" "dirtyduck_smoke_0.1.0.kpm"
}

if ($Target -eq "dirtyduck" -or $Target -eq "all") {
    $dir = Join-Path $repo "kpm\dirtyduck"
    $built += Build-Kpm $dir "dirtyduck_selinux.c" "dirtyduck_selinux.o" "dirtyduck_selinux_0.1.2.kpm"
}

$built | Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize
