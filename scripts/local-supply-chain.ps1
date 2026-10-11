param(
    [string] $ImageTag = "coland:local",
    [string] $OutDir = "target/supply-chain"
)

$ErrorActionPreference = "Stop"

function Require-Command([string] $Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name is required but was not found on PATH"
    }
}

Require-Command "docker"
Require-Command "syft"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$metadataPath = Join-Path $OutDir "coland-build-metadata.json"
$sbomPath = Join-Path $OutDir "coland.spdx.json"

docker buildx build `
    --load `
    --tag $ImageTag `
    --metadata-file $metadataPath `
    --build-context arkret-rust-sdk=../arkret-rust-sdk `
    --build-context arkret-spec=../arkret-spec `
    --build-context floria=../floria `
    .

syft $ImageTag -o "spdx-json=$sbomPath"

Write-Host "Wrote build metadata: $metadataPath"
Write-Host "Wrote SBOM: $sbomPath"
Write-Host "Optional signing:"
Write-Host "  cosign attest-blob --key <key> --type slsaprovenance --predicate $metadataPath $metadataPath"
