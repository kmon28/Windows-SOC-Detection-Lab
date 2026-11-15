<#
.SYNOPSIS
    Reference implementation for IR-006 failed-logon triage.
.DESCRIPTION
    Uses native Windows Security Event 4625 records and named XML fields.
    Newly authored from the documented workflow; NOT the original lab-tested file.
    This reference has not been executed against the original VM.
.EXAMPLE
    .\Detect-FailedLogins-Reference.ps1 -LookbackMinutes 5 -Threshold 5
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 1440)]
    [int]$LookbackMinutes = 5,

    [ValidateRange(1, 10000)]
    [int]$Threshold = 5
)

$start = (Get-Date).AddMinutes(-$LookbackMinutes)

try {
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4625
        StartTime = $start
    } -ErrorAction Stop)
} catch {
    # Get-WinEvent reports 'No events were found' as an error.
    if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') {
        Write-Output 'OK: No threshold reached'
        exit 0
    }
    Write-Error "Unable to query Security log: $($_.Exception.Message)"
    exit 2
}

$rows = foreach ($event in $events) {
    try {
        [xml]$xml = $event.ToXml()
        $fields = @{}
        foreach ($item in $xml.Event.EventData.Data) {
            if ($item.Name) { $fields[[string]$item.Name] = [string]$item.'#text' }
        }
        if ([string]::IsNullOrWhiteSpace($fields['TargetUserName'])) { continue }
        [pscustomobject]@{
            Account = $fields['TargetUserName']
            SourceIP = if ($fields['IpAddress']) { $fields['IpAddress'] } else { 'Unknown' }
            Host = $event.MachineName
            TimeCreated = $event.TimeCreated
        }
    } catch {
        Write-Warning "Skipping event $($event.RecordId): XML parse error"
    }
}

$alerts = @($rows | Group-Object Account, SourceIP, Host |
    Where-Object { $_.Count -ge $Threshold } |
    ForEach-Object {
        [pscustomobject]@{
            Count = $_.Count
            Account = $_.Group[0].Account
            SourceIP = $_.Group[0].SourceIP
            Host = $_.Group[0].Host
            FirstSeen = ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated
            LastSeen = ($_.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated
        }
    })

if ($alerts.Count -eq 0) {
    Write-Output 'OK: No threshold reached'
} else {
    $alerts | Sort-Object Count -Descending
}
