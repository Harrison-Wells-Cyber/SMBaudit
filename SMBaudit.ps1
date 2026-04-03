[CmdletBinding()]
param(
    [Parameter()]
    [string]$SearchBase,

    [Parameter()]
    [int]$LdapPageSize = 1000,

    [Parameter()]
    [int]$PingTimeoutSeconds = 1,

    [Parameter()]
    [int]$MaxHosts,

    [Parameter()]
    [string]$OutputPath = (Join-Path -Path (Get-Location) -ChildPath ("accessible_shares_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss')))
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

function Get-DiskSharesFromNetView {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName
    )

    $cmdOutput = & cmd.exe /c "net view \\$ComputerName /all" 2>$null
    if (-not $cmdOutput) {
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

Write-Section -Text 'LDAP SMB Share Accessibility Scan' -Color Green
Write-Host ("Start Time : {0}" -f (Get-Date)) -ForegroundColor DarkGray
Write-Host ("SearchBase : {0}" -f ($(if ($SearchBase) { $SearchBase } else { 'DefaultNamingContext' }))) -ForegroundColor DarkGray
Write-Host ("OutputPath : {0}" -f $OutputPath) -ForegroundColor DarkGray

$computerNames = Get-LdapComputerNames -SearchBase $SearchBase -PageSize $LdapPageSize
if ($MaxHosts -and $MaxHosts -gt 0) {
    $computerNames = $computerNames | Select-Object -First $MaxHosts
}

$scanResults = New-Object 'System.Collections.Generic.List[psobject]'
$accessiblePaths = New-Object 'System.Collections.Generic.List[string]'

$hostCount = 0
foreach ($computer in $computerNames) {
    $hostCount++

    $pingParams = @{
        ComputerName = $computer
        Count        = 1
        Quiet        = $true
        ErrorAction  = 'SilentlyContinue'
    }
    if ((Get-Command Test-Connection).Parameters.ContainsKey('TimeoutSeconds')) {
        $pingParams.TimeoutSeconds = $PingTimeoutSeconds
    }

    $online = Test-Connection @pingParams
    if (-not $online) {
        continue
    }

    $shares = Get-DiskSharesFromNetView -ComputerName $computer
    if (-not $shares -or @($shares).Count -eq 0) {
        continue
    }

    $printedHostHeader = $false
    foreach ($share in $shares) {
        $path = "\\$computer\$share"
        $canAccess = Test-Path -LiteralPath $path -ErrorAction SilentlyContinue

        $item = [pscustomobject]@{
            Computer     = $computer
            Share        = $share
            Path         = $path
            AccessResult = $canAccess
        }

        [void]$scanResults.Add($item)

        if ($canAccess) {
            [void]$accessiblePaths.Add($path)
            if (-not $printedHostHeader) {
                Write-Host ''
                Write-Host ('┌──────────────────────────────────────────────┐') -ForegroundColor DarkCyan
                Write-Host ("│ HOST: {0,-37}│" -f $computer) -ForegroundColor Cyan
                Write-Host ('└──────────────────────────────────────────────┘') -ForegroundColor DarkCyan
                $printedHostHeader = $true
            }
            Write-Host ("  [FOUND] {0}" -f $path) -ForegroundColor Yellow
        }
    }
}

$accessible = $scanResults | Where-Object { $_.AccessResult }

$accessibleCount = @($accessible).Count
if ($accessibleCount -gt 0) {
    Write-Section -Text 'Accessible Shares' -Color Green
    $accessible | Sort-Object Computer, Share | Format-Table -AutoSize

    $uniquePaths = @($accessible | Select-Object -ExpandProperty Path -Unique)
    $uniquePaths |
        Sort-Object -Unique |
        ForEach-Object { $_ } |
        Set-Content -Path $OutputPath -Encoding UTF8

    Write-Host ("`nSaved {0} accessible share path(s) to: {1}" -f @($uniquePaths).Count, $OutputPath) -ForegroundColor Green
}
else {
    Write-Section -Text 'Accessible Shares' -Color DarkYellow
    Write-Host 'No accessible shares discovered.' -ForegroundColor DarkYellow

    Set-Content -Path $OutputPath -Value @() -Encoding UTF8
    Write-Host ("Created empty output file: {0}" -f $OutputPath) -ForegroundColor DarkYellow
}

Write-Host ("`nHosts Evaluated: {0}" -f $hostCount) -ForegroundColor Cyan
Write-Host ("End Time      : {0}" -f (Get-Date)) -ForegroundColor DarkGray
