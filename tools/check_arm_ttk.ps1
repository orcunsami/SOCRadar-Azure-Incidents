param(
    [string]$TemplatePath = (Split-Path $PSScriptRoot -Parent),
    [Parameter(Mandatory=$true)][string]$ModulePath,
    [string]$ReportPath,
    [switch]$Single
)
$ErrorActionPreference = 'Continue'
$started = [DateTime]::UtcNow.ToString('o')
$ModulePath = (Resolve-Path -LiteralPath $ModulePath -ErrorAction Stop).Path
if ($Single) {
    Import-Module $ModulePath -Force -ErrorAction Stop
    $toolErrors = @()
    $results = @(Test-AzTemplate -TemplatePath $TemplatePath -ErrorAction SilentlyContinue -ErrorVariable +toolErrors)
    $tests = @($results | Where-Object {$_.PSObject.Properties.Name -contains 'Passed'})
    $failed = @($tests | Where-Object {-not $_.Passed})
    $trueErrors = @($toolErrors | Where-Object {$_ -is [System.Management.Automation.ErrorRecord]})
    $result = @{
        startedUtc=$started; finishedUtc=[DateTime]::UtcNow.ToString('o');
        records=$tests.Count; fail=$failed.Count; trueErrorRecords=$trueErrors.Count;
        errorIds=@($trueErrors | ForEach-Object FullyQualifiedErrorId);
        tests=@($tests | ForEach-Object {
            @{Name=$_.Name; Passed=$_.Passed; File="$($_.File)";
              Errors=@($_.Errors | ForEach-Object {$_ | Out-String});
              Warnings=@($_.Warnings | ForEach-Object {$_ | Out-String})}
        })
    }
    $result | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $ReportPath
    if ($tests.Count -eq 0 -or $failed.Count -gt 0 -or $trueErrors.Count -gt 0) {exit 1}
    exit 0
}

$paths = @('azuredeploy.json',
    'Playbooks/SOCRadar-Alarm-Import/azuredeploy.json',
    'Playbooks/SOCRadar-Alarm-Sync/azuredeploy.json',
    'Playbooks/SOCRadar-Alarms-Infrastructure/azuredeploy.json',
    'Playbooks/SOCRadar-Audit-Infrastructure/azuredeploy.json',
    'Playbooks/SOCRadar-IOC-Enrichment/azuredeploy.json',
    'Playbooks/SOCRadar-Workbook/azuredeploy.json')
$root = (Resolve-Path -LiteralPath $TemplatePath -ErrorAction Stop).Path
$actual = @(Get-ChildItem -LiteralPath $root -Recurse -Filter azuredeploy.json -File)
$expected = @($paths | ForEach-Object {(Resolve-Path -LiteralPath (Join-Path $root $_) -ErrorAction Stop).Path})
if ($actual.Count -ne 7 -or @(Compare-Object @($actual.FullName | Sort-Object) @($expected | Sort-Object)).Count -gt 0) {
    throw 'Published template inventory differs from the seven-template contract'
}
$rows = @()
$bad = $false
foreach ($relative in $paths) {
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('socradar-ttk-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($directory)
    try {
        $source = Join-Path $root $relative
        $copy = Join-Path $directory 'azuredeploy.json'
        Copy-Item -LiteralPath $source -Destination $copy -ErrorAction Stop
        $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
        $copyHash = (Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($sourceHash -ne $copyHash) {throw 'Template copy hash mismatch'}
        $report = Join-Path $directory 'result.json'
        & (Get-Command pwsh -ErrorAction Stop).Source -NoProfile -File $PSCommandPath -Single -TemplatePath $directory -ModulePath $ModulePath -ReportPath $report
        $childExit = $LASTEXITCODE
        if (-not (Test-Path -LiteralPath $report)) {throw 'Child produced no ARM-TTK evidence'}
        $row = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json -AsHashtable
        $row.source=$relative; $row.sourceSHA256=$sourceHash; $row.copySHA256=$copyHash; $row.processExit=$childExit
        $rows += $row
        if ($childExit -ne 0 -or $row.records -eq 0 -or $row.fail -ne 0 -or $row.trueErrorRecords -ne 0) {$bad=$true}
        Write-Output "$relative RECORDS=$($row.records) FAIL=$($row.fail) TRUE_ERRORS=$($row.trueErrorRecords) EXIT=$childExit"
    } finally {
        [IO.Directory]::Delete($directory, $true)
    }
}
$manifest = @{
    startedUtc=$started; finishedUtc=[DateTime]::UtcNow.ToString('o');
    powershell=$PSVersionTable.PSVersion.ToString(); moduleSHA256=(Get-FileHash -LiteralPath $ModulePath -Algorithm SHA256).Hash.ToLowerInvariant();
    templates=$rows; records=($rows.records | Measure-Object -Sum).Sum;
    fail=($rows.fail | Measure-Object -Sum).Sum; trueErrorRecords=($rows.trueErrorRecords | Measure-Object -Sum).Sum
}
if ($ReportPath) {$manifest | ConvertTo-Json -Depth 60 | Set-Content -LiteralPath $ReportPath}
Write-Output "TEMPLATES=$($rows.Count) TOTAL=$($manifest.records) FAIL=$($manifest.fail) TRUE_ERRORS=$($manifest.trueErrorRecords)"
if ($bad -or $rows.Count -ne 7) {exit 1}
exit 0
