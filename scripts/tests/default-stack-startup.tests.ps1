param(
    [Parameter(Mandatory=$true)][string]$BinaryPath,
    [Parameter(Mandatory=$true)][string]$ConfigPath,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [Parameter(Mandatory=$true)][string]$EmbeddedLocalId,
    [int]$TimeoutSeconds = 120,
    [switch]$FirstProvisioning
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$evidence = [IO.Path]::GetFullPath($EvidenceDirectory)
if ($IsWindows -and -not $evidence.StartsWith('D:\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Startup regression artifacts must be on D' }
if (Test-Path -LiteralPath $evidence) { throw 'Use a fresh evidence directory for each real binary run' }
$binary = (Resolve-Path -LiteralPath $BinaryPath).Path
$config = (Resolve-Path -LiteralPath $ConfigPath).Path
$null = New-Item -ItemType Directory -Path $evidence

# Read the real executable's PE header rather than assuming the linker stack.
$stream = [IO.File]::OpenRead($binary)
$reader = [IO.BinaryReader]::new($stream)
try {
    $stream.Position = 0x3c
    $pe = $reader.ReadUInt32()
    $stream.Position = $pe
    if ($reader.ReadUInt32() -ne 0x4550) { throw 'Default-stack regression requires the real Windows PE binary' }
    $optional = $pe + 24
    $stream.Position = $optional
    if ($reader.ReadUInt16() -ne 0x20b) { throw 'Expected a PE32+ server binary' }
    $stream.Position = $optional + 72
    $reserve = $reader.ReadUInt64()
    $commit = $reader.ReadUInt64()
    if ($reserve -gt 1048576) { throw "Binary enlarged its main stack: $reserve bytes" }
} finally { $reader.Dispose(); $stream.Dispose() }

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
try { $port = $listener.LocalEndpoint.Port } finally { $listener.Stop() }
$base = "http://127.0.0.1:$port"
$start = [Diagnostics.ProcessStartInfo]::new($binary)
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
foreach ($argument in @('--config', $config, '--no-env-overrides', '--bind', "127.0.0.1:$port")) { $start.ArgumentList.Add($argument) }
if ($FirstProvisioning) { $start.ArgumentList.Add('--first-provisioning') }
# Apply only to this child: never change the calling harness or OS stack.
$null = $start.Environment.Remove('RUST_MIN_STACK')
$process = [Diagnostics.Process]::new()
$process.StartInfo = $start
$result = [ordered]@{
    passed = $false
    binary_sha256 = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
    config_sha256 = (Get-FileHash -LiteralPath $config -Algorithm SHA256).Hash.ToLowerInvariant()
    main_stack_reserve = $reserve
    main_stack_commit = $commit
    rust_min_stack_present = $start.Environment.ContainsKey('RUST_MIN_STACK')
    health_status = $null
    openapi_paths = 0
    schema_count = 0
    process_id = $null
    process_started_at = $null
    executable = $null
    arguments = @($start.ArgumentList)
    process_exit = $null
    checked_operations = @()
    checked_schemas = @()
    embedded_document_id = $null
    embedded_log_version = $null
    alive_after_hold_seconds = 0
    cleanup_identity_verified = $false
    cleanup_exited = $false
}
$stdout = $null; $stderr = $null
try {
    if (-not $process.Start()) { throw 'Server process did not start' }
    $result.process_id = $process.Id
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $ownedStartedAt = $process.StartTime.ToUniversalTime()
    $result.process_started_at = $ownedStartedAt.ToString('o')
    if (-not $process.HasExited) {
        $result.executable = $process.MainModule.FileName
        if ([IO.Path]::GetFullPath($result.executable) -ine $binary) { throw 'Started process executable differs from the verified binary' }
    }
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if ($process.HasExited) { throw "Default-stack binary exited before readiness: $($process.ExitCode)" }
        try {
            $health = Invoke-WebRequest -Uri "$base/health" -NoProxy -TimeoutSec 2 -SkipHttpErrorCheck
            if ($health.StatusCode -eq 200) { $result.health_status = 200; break }
        } catch { }
        Start-Sleep -Milliseconds 100
    }
    if ($result.health_status -ne 200) { throw 'Default-stack binary did not reach real serving health (waiting-only 503 gives no credit)' }
    # This is the production document from the full live router, not a reduced
    # test router or static schema. Health alone must not mask skipped OAPI.
    $document = Invoke-RestMethod -Uri "$base/.well-known/arkret/openapi.json" -NoProxy -TimeoutSec 15
    $result.openapi_paths = @($document.paths.PSObject.Properties).Count
    $result.schema_count = @($document.components.schemas.PSObject.Properties).Count
    if (-not $result.openapi_paths -or -not $result.schema_count) { throw 'Full production OpenAPI document is missing paths or schemas' }
    # These exact live endpoint declarations are in system/describe.rs,
    # events/peer.rs and identity/account.rs; operation IDs omit only .v1 in OAPI.
    foreach ($required in @(
        @('/_arkret/describe', 'get', 'ak.server.read.describe'),
        @('/_arkret/peer/events', 'post', 'ak.peer.events.command.submit'),
        @('/_arkret/self/direct-conversations/resolve', 'post', 'ak.self.direct_conversation.read.resolve')
    )) {
        $pathItem = $document.paths.PSObject.Properties[$required[0]]
        if ($null -eq $pathItem) { throw "Missing production OpenAPI path $($required[0])" }
        $operation = $pathItem.Value.PSObject.Properties[$required[1]]
        if ($null -eq $operation -or $operation.Value.operationId -cne $required[2]) { throw "Missing exact production operation $($required[2])" }
        $result.checked_operations += $required[2]
    }
    # SDK authority_commit/tests.rs fixes these component names and the flat
    # CurrentSelector policy_action branch. Require definitions, not just refs
    # or arbitrary counts that a one-path reduced router could satisfy.
    foreach ($name in @('arkret_wire.authority_commit.CurrentSelector', 'arkret_wire.authority_commit.PolicyActionSelector')) {
        $component = $document.components.schemas.PSObject.Properties[$name]
        if ($null -eq $component -or $null -eq $component.Value.PSObject.Properties['oneOf'] -or @($component.Value.oneOf).Count -eq 0) { throw "Missing deep AuthorityCommit union definition $name" }
        $result.checked_schemas += $name
    }
    $selector = $document.components.schemas.PSObject.Properties['arkret_wire.authority_commit.CurrentSelector'].Value
    $policyAction = @($selector.oneOf | Where-Object {
        $allOf = $_.PSObject.Properties['allOf']
        $null -ne $allOf -and @($allOf.Value).Count -gt 2 -and
        $null -ne $allOf.Value[2].PSObject.Properties['properties'] -and
        $null -ne $allOf.Value[2].properties.PSObject.Properties['kind'] -and
        $allOf.Value[2].properties.kind.enum[0] -ceq 'policy_action'
    })
    if ($policyAction.Count -ne 1 -or ($policyAction[0] | ConvertTo-Json -Depth 100 -Compress) -notmatch 'PolicyActionSelector') { throw 'Deep CurrentSelector policy_action definition was reduced or disconnected' }
    # submit_self is intentionally a #[handler] rather than an OAPI endpoint.
    # Probe its real registered path with an invalid, credential-free body;
    # it must reject, rather than disappear or accept a write.
    $rejected = Invoke-WebRequest -Uri "$base/_arkret/self/events" -Method Post -Headers @{ 'Arkret-Operation' = 'ak.self.events.command.submit.v1' } -ContentType 'application/json' -Body '{}' -NoProxy -TimeoutSec 10 -SkipHttpErrorCheck
    if ($rejected.StatusCode -notin @(400, 401, 403)) { throw "Production authority submit rejection route missing: $($rejected.StatusCode)" }
    if ([string]::IsNullOrWhiteSpace($EmbeddedLocalId)) { throw 'EmbeddedLocalId must come from the restored real WebVH record' }
    $encodedLocalId = [Uri]::EscapeDataString($EmbeddedLocalId)
    $didDocument = Invoke-RestMethod -Uri "$base/webvh/$encodedLocalId/did.json" -NoProxy -TimeoutSec 10
    $logResponse = Invoke-WebRequest -Uri "$base/webvh/$encodedLocalId/did.jsonl" -NoProxy -TimeoutSec 10
    $logText = if ($logResponse.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($logResponse.Content) } else { [string]$logResponse.Content }
    $entries = @($logText -split '\r?\n' | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
    if (-not $didDocument.id.StartsWith('did:webvh:') -or -not $entries.Count -or $entries[-1].state.id -cne $didDocument.id -or [string]::IsNullOrWhiteSpace($entries[-1].versionId)) { throw 'Real embedded WebVH document/log do not agree' }
    $result.embedded_document_id = $didDocument.id
    $result.embedded_log_version = $entries[-1].versionId
    if ($process.HasExited) { throw 'Server exited after OpenAPI readiness' }
    Start-Sleep -Seconds 5
    if ($process.HasExited) { throw 'Server exited during the default-stack hold' }
    $heldHealth = Invoke-WebRequest -Uri "$base/health" -NoProxy -TimeoutSec 2 -SkipHttpErrorCheck
    if ($heldHealth.StatusCode -ne 200) { throw 'Server lost health during the default-stack hold' }
    $result.alive_after_hold_seconds = 5
    $result.passed = $true
    Write-Host 'PASS default main stack: serving health and complete live OpenAPI'
} finally {
    if ($result.process_id) {
        if ($process.StartTime.ToUniversalTime() -ne $ownedStartedAt) { throw 'Owned process start identity changed before cleanup' }
        if (-not $process.HasExited -and [IO.Path]::GetFullPath($process.MainModule.FileName) -ine $binary) { throw 'Owned process executable changed before cleanup' }
        $result.cleanup_identity_verified = $true
        if (-not $process.HasExited) { $process.Kill(); $null = $process.WaitForExit(10000) }
        $result.cleanup_exited = $process.HasExited
        if ($process.HasExited) { $result.process_exit = $process.ExitCode }
    }
    if ($stdout) { [IO.File]::WriteAllText((Join-Path $evidence 'stdout.log'), $stdout.GetAwaiter().GetResult()) }
    if ($stderr) { [IO.File]::WriteAllText((Join-Path $evidence 'stderr.log'), $stderr.GetAwaiter().GetResult()) }
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'result.json') -Encoding utf8NoBOM
    $process.Dispose()
}
