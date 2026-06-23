[CmdletBinding()]
param(
    [Parameter()]
    [string]$SearchBase,

    [Parameter()]
    [int]$LdapPageSize = 1000,

    [Parameter()]
    [int]$PingTimeoutSeconds = 1,

    [Parameter()]
    [int]$ShareProbeTimeoutSeconds = 3,

    [Parameter()]
    [int]$ThrottleLimit = 64,

    [Parameter()]
    [int]$MaxHosts,

    [Parameter()]
    [string]$OutputDirectory = (Get-Location).Path,

    [Parameter()]
    [string]$FullResultsPath,

    [Parameter()]
    [string]$ReadableSharesPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Section {
    param(
        [string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Cyan
    )
    Write-Host "`n=== $Text ===" -ForegroundColor $Color
}

function Initialize-OutputPaths {
    [CmdletBinding()]
    param(
        [string]$OutputDirectory,
        [string]$FullResultsPath,
        [string]$ReadableSharesPath
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        [void](New-Item -Path $OutputDirectory -ItemType Directory -Force)
    }

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    if (-not $FullResultsPath) {
        $FullResultsPath = Join-Path -Path $OutputDirectory -ChildPath ("smb_share_rights_full_{0}.txt" -f $timestamp)
    }
    if (-not $ReadableSharesPath) {
        $ReadableSharesPath = Join-Path -Path $OutputDirectory -ChildPath ("smb_readable_shares_{0}.txt" -f $timestamp)
    }

    [pscustomobject]@{
        FullResultsPath    = $FullResultsPath
        ReadableSharesPath = $ReadableSharesPath
    }
}

function Get-LdapComputerNames {
    [CmdletBinding()]
    param(
        [string]$SearchBase,
        [int]$PageSize = 1000
    )

    Add-Type -AssemblyName System.DirectoryServices

    $root = [ADSI]'LDAP://RootDSE'
    $defaultNc = [string]$root.defaultNamingContext

    if (-not $SearchBase) {
        $SearchBase = $defaultNc
    }

    $searchRoot = [ADSI]("LDAP://{0}" -f $SearchBase)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($searchRoot)
    $searcher.PageSize = $PageSize
    $searcher.Filter = '(&(objectCategory=computer)(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    [void]$searcher.PropertiesToLoad.Add('name')

    $results = $searcher.FindAll()
    try {
        $names = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($result in $results) {
            if ($result.Properties['name'] -and $result.Properties['name'].Count -gt 0) {
                [void]$names.Add([string]$result.Properties['name'][0])
            }
        }
        return $names
    }
    finally {
        $results.Dispose()
        $searcher.Dispose()
    }
}

$workerScript = {
    param(
        [string]$ComputerName,
        [int]$PingTimeoutSeconds,
        [int]$ShareProbeTimeoutSeconds
    )

    function Get-DiskSharesFromNetView {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$ComputerName
        )

        try {
            # net.exe uses the current user's token and requires no RSAT, WMI, WinRM,
            # admin rights, or remote code execution. /all includes hidden shares.
            $cmdOutput = & cmd.exe /d /c "net view \\$ComputerName /all 2>nul"
        }
        catch {
            return @()
        }

        if (-not $cmdOutput) {
            return @()
        }

        $joinedOutput = $cmdOutput -join [Environment]::NewLine
        if ($joinedOutput -match 'System error \d+ has occurred') {
            return @()
        }

        $shares = New-Object 'System.Collections.Generic.List[string]'
        foreach ($line in $cmdOutput) {
            # Matches: SHARENAME   Disk   optional-comment
            if ($line -match '^\s*([^\s]+)\s+Disk\s+.*$') {
                $shareName = $Matches[1].Trim()
                if ($shareName -and $shareName -notin @('ADMIN$', 'IPC$', 'print$')) {
                    [void]$shares.Add($shareName)
                }
            }
        }

        return $shares
    }

    function Test-ShareRights {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Path
        )

        $rights = New-Object 'System.Collections.Generic.List[string]'
        $readError = $null

        try {
            # Enumerate at most one child. This verifies listing/read access without
            # reading file contents, writing data, changing ACLs, or modifying timestamps.
            $null = Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop | Select-Object -First 1
            [void]$rights.Add('Read')
        }
        catch {
            $readError = $_.Exception.Message
        }

        [pscustomobject]@{
            CanRead = $rights.Contains('Read')
            Rights  = if ($rights.Count -gt 0) { ($rights -join ',') } else { 'NoneConfirmed' }
            Error   = $readError
        }
    }

    $hostOnline = $false
    $pingParams = @{
        ComputerName = $ComputerName
        Count        = 1
        Quiet        = $true
        ErrorAction  = 'SilentlyContinue'
    }
    if ((Get-Command Test-Connection).Parameters.ContainsKey('TimeoutSeconds')) {
        $pingParams.TimeoutSeconds = $PingTimeoutSeconds
    }

    try {
        $hostOnline = [bool](Test-Connection @pingParams)
    }
    catch {
        $hostOnline = $false
    }

    if (-not $hostOnline) {
        return [pscustomobject]@{
            Computer = $ComputerName
            Online   = $false
            Results  = @()
        }
    }

    $shareResults = New-Object 'System.Collections.Generic.List[psobject]'
    foreach ($share in (Get-DiskSharesFromNetView -ComputerName $ComputerName)) {
        $path = "\\$ComputerName\$share"
        $job = Start-Job -ScriptBlock ${function:Test-ShareRights} -ArgumentList $path
        $completed = Wait-Job -Job $job -Timeout $ShareProbeTimeoutSeconds

        if ($completed) {
            $probe = Receive-Job -Job $job
        }
        else {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            $probe = [pscustomobject]@{
                CanRead = $false
                Rights  = 'ProbeTimedOut'
                Error   = 'Share probe timed out.'
            }
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue

        [void]$shareResults.Add([pscustomobject]@{
            Computer = $ComputerName
            Share    = $share
            Path     = $path
            CanRead  = [bool]$probe.CanRead
            Rights   = [string]$probe.Rights
            Error    = [string]$probe.Error
        })
    }

    [pscustomobject]@{
        Computer = $ComputerName
        Online   = $true
        Results  = @($shareResults)
    }
}

function Invoke-ParallelShareAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerName,
        [int]$ThrottleLimit = 64,
        [int]$PingTimeoutSeconds = 1,
        [int]$ShareProbeTimeoutSeconds = 3
    )

    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $sessionState, $Host)
    $pool.Open()

    $jobs = New-Object 'System.Collections.Generic.List[psobject]'
    try {
        foreach ($computer in $ComputerName) {
            $ps = [System.Management.Automation.PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript($workerScript).AddArgument($computer).AddArgument($PingTimeoutSeconds).AddArgument($ShareProbeTimeoutSeconds)
            [void]$jobs.Add([pscustomobject]@{
                Computer = $computer
                Pipeline = $ps
                Handle   = $ps.BeginInvoke()
            })
        }

        foreach ($job in $jobs) {
            try {
                $job.Pipeline.EndInvoke($job.Handle)
            }
            finally {
                $job.Pipeline.Dispose()
            }
        }
    }
    finally {
        $pool.Close()
        $pool.Dispose()
    }
}

$outputPaths = Initialize-OutputPaths -OutputDirectory $OutputDirectory -FullResultsPath $FullResultsPath -ReadableSharesPath $ReadableSharesPath

Write-Section -Text 'LDAP SMB Share Rights Audit' -Color Green
Write-Host ("Start Time          : {0}" -f (Get-Date)) -ForegroundColor DarkGray
Write-Host ("SearchBase          : {0}" -f ($(if ($SearchBase) { $SearchBase } else { 'DefaultNamingContext' }))) -ForegroundColor DarkGray
Write-Host ("ThrottleLimit       : {0}" -f $ThrottleLimit) -ForegroundColor DarkGray
Write-Host ("Share Probe Timeout : {0}s" -f $ShareProbeTimeoutSeconds) -ForegroundColor DarkGray
Write-Host ("Full Results        : {0}" -f $outputPaths.FullResultsPath) -ForegroundColor DarkGray
Write-Host ("Readable Shares     : {0}" -f $outputPaths.ReadableSharesPath) -ForegroundColor DarkGray

$computerNames = @(Get-LdapComputerNames -SearchBase $SearchBase -PageSize $LdapPageSize | Sort-Object -Unique)
if ($MaxHosts -and $MaxHosts -gt 0) {
    $computerNames = @($computerNames | Select-Object -First $MaxHosts)
}

Write-Host ("Discovered {0} enabled computer account(s)." -f $computerNames.Count) -ForegroundColor Cyan

$hostResults = @(Invoke-ParallelShareAudit -ComputerName $computerNames -ThrottleLimit $ThrottleLimit -PingTimeoutSeconds $PingTimeoutSeconds -ShareProbeTimeoutSeconds $ShareProbeTimeoutSeconds)
$scanResults = @($hostResults | ForEach-Object { $_.Results } | Where-Object { $null -ne $_ })

foreach ($item in ($scanResults | Sort-Object Computer, Share)) {
    $color = if ($item.CanRead) { [ConsoleColor]::Green } else { [ConsoleColor]::DarkGray }
    Write-Host ("{0,-45} {1,-13} {2}" -f $item.Path, $item.Rights, $item.Error) -ForegroundColor $color
}

$readable = @($scanResults | Where-Object { $_.CanRead } | Sort-Object Computer, Share)

Write-Section -Text 'Readable Shares' -Color Green
if ($readable.Count -gt 0) {
    $readable | Format-Table Computer, Share, Path, Rights -AutoSize
}
else {
    Write-Host 'No readable shares discovered.' -ForegroundColor DarkYellow
}

$fullReport = New-Object 'System.Collections.Generic.List[string]'
[void]$fullReport.Add(('SMB share rights audit - {0}' -f (Get-Date)))
[void]$fullReport.Add(('Current user: {0}\{1}' -f $env:USERDOMAIN, $env:USERNAME))
[void]$fullReport.Add(('Hosts evaluated: {0}' -f $computerNames.Count))
[void]$fullReport.Add(('Online hosts: {0}' -f @($hostResults | Where-Object { $_.Online }).Count))
[void]$fullReport.Add(('Shares discovered: {0}' -f $scanResults.Count))
[void]$fullReport.Add('')
[void]$fullReport.Add('Computer`tShare`tPath`tRights`tError')
foreach ($item in ($scanResults | Sort-Object Computer, Share)) {
    [void]$fullReport.Add(("{0}`t{1}`t{2}`t{3}`t{4}" -f $item.Computer, $item.Share, $item.Path, $item.Rights, $item.Error))
}
$fullReport | Set-Content -Path $outputPaths.FullResultsPath -Encoding UTF8

$readable |
    Select-Object -ExpandProperty Path -Unique |
    Sort-Object -Unique |
    Set-Content -Path $outputPaths.ReadableSharesPath -Encoding UTF8

Write-Host ("`nSaved full results to: {0}" -f $outputPaths.FullResultsPath) -ForegroundColor Green
Write-Host ("Saved readable shares to: {0}" -f $outputPaths.ReadableSharesPath) -ForegroundColor Green
Write-Host ("End Time: {0}" -f (Get-Date)) -ForegroundColor DarkGray
