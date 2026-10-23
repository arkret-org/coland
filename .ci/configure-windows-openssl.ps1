param(
    [string] $OpenSSLRoot = (Join-Path $env:ProgramFiles 'OpenSSL'),
    [string] $EnvironmentFile = $env:GITHUB_ENV
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($EnvironmentFile)) {
    throw 'An environment output file is required.'
}

$root = (Resolve-Path -LiteralPath $OpenSSLRoot).Path
if ($root -match "[`r`n]") {
    throw 'OpenSSL root must not contain line breaks.'
}
$include = Join-Path $root 'include'
$lib = Join-Path $root 'lib\VC\x64\MD'
$openssl = Join-Path $root 'bin\openssl.exe'
foreach ($required in @(
    (Join-Path $include 'openssl\ssl.h'),
    (Join-Path $lib 'libssl_static.lib'),
    (Join-Path $lib 'libcrypto_static.lib'),
    $openssl
)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required OpenSSL development file is missing: $required"
    }
}

& $openssl version
if ($LASTEXITCODE -ne 0) {
    throw "OpenSSL version probe failed with exit code $LASTEXITCODE."
}

# Use the static libraries with the dynamic MSVC runtime, not DLL import libraries.
$settings = [ordered]@{
    OPENSSL_DIR = $root
    OPENSSL_INCLUDE_DIR = $include
    OPENSSL_LIB_DIR = $lib
    OPENSSL_LIBS = 'libssl_static:libcrypto_static'
    OPENSSL_STATIC = '1'
    OPENSSL_NO_VENDOR = '1'
}
foreach ($entry in $settings.GetEnumerator()) {
    Add-Content -LiteralPath $EnvironmentFile -Encoding utf8 -Value "$($entry.Key)=$($entry.Value)"
}
