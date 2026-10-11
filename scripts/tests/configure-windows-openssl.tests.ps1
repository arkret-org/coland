param(
    [string] $OpenSSLRoot = (Join-Path $env:ProgramFiles 'OpenSSL')
)

$ErrorActionPreference = 'Stop'
$configure = Join-Path $PSScriptRoot '..\configure-windows-openssl.ps1'
$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ('coland-openssl-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null

function Assert-Refusal([scriptblock] $Action, [string] $Message, [string] $OutputFile) {
    $refused = $false
    try {
        & $Action
    } catch {
        if ($_.Exception.Message -notlike $Message) {
            throw
        }
        $refused = $true
    }
    if (-not $refused) {
        throw 'Invalid OpenSSL configuration was accepted.'
    }
    if (Test-Path -LiteralPath $OutputFile) {
        if ((Get-Item -LiteralPath $OutputFile).Length -ne 0) {
            throw 'Refused configuration emitted environment settings.'
        }
    }
}

try {
    $output = Join-Path $temporary 'environment.txt'
    & $configure -OpenSSLRoot $OpenSSLRoot -EnvironmentFile $output
    $settings = @{}
    foreach ($line in Get-Content -LiteralPath $output) {
        $parts = $line.Split('=', 2)
        $settings.Add($parts[0], $parts[1])
    }
    if ($settings.Count -ne 6 -or
        $settings.OPENSSL_DIR -ne (Resolve-Path -LiteralPath $OpenSSLRoot).Path -or
        $settings.OPENSSL_INCLUDE_DIR -ne (Join-Path $settings.OPENSSL_DIR 'include') -or
        $settings.OPENSSL_LIB_DIR -ne (Join-Path $settings.OPENSSL_DIR 'lib\VC\x64\MD') -or
        $settings.OPENSSL_LIBS -ne 'libssl_static:libcrypto_static' -or
        $settings.OPENSSL_STATIC -ne '1' -or $settings.OPENSSL_NO_VENDOR -ne '1') {
        throw 'Incorrect OpenSSL environment output.'
    }

    $refusalOutput = Join-Path $temporary 'refused.txt'
    Assert-Refusal { & $configure -OpenSSLRoot $temporary -EnvironmentFile $refusalOutput } `
        'Required OpenSSL development file is missing:*ssl.h' $refusalOutput

    New-Item -ItemType Directory -Path (Join-Path $temporary 'include\openssl') -Force | Out-Null
    New-Item -ItemType File -Path (Join-Path $temporary 'include\openssl\ssl.h') | Out-Null
    Assert-Refusal { & $configure -OpenSSLRoot $temporary -EnvironmentFile $refusalOutput } `
        'Required OpenSSL development file is missing:*libssl_static.lib' $refusalOutput

    New-Item -ItemType Directory -Path (Join-Path $temporary 'lib\VC\x64\MD') -Force | Out-Null
    New-Item -ItemType File -Path (Join-Path $temporary 'lib\VC\x64\MD\libssl_static.lib') | Out-Null
    Assert-Refusal { & $configure -OpenSSLRoot $temporary -EnvironmentFile $refusalOutput } `
        'Required OpenSSL development file is missing:*libcrypto_static.lib' $refusalOutput
    Assert-Refusal { & $configure -OpenSSLRoot $OpenSSLRoot -EnvironmentFile '' } `
        'An environment output file is required.' $refusalOutput

    Write-Output 'Windows OpenSSL configuration: 5 checks passed.'
} finally {
    if ((Resolve-Path -LiteralPath $temporary).Path -ne [System.IO.Path]::GetFullPath($temporary)) {
        throw 'Unexpected cleanup target.'
    }
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
