Write-Host "Looking for computers vulnerable to KDC Spoofing"

$lastTGSTimes = @{}
$possible_targets = @{}

$filter = @{
    LogName="Security"
    ProviderName="Microsoft-Windows-Security-Auditing"
    ID=@(4768,4769)}

$numEventsPerPage = 10000

$startTime = Get-Date
$gap_allowed = 40 #in seconds

$event4768Selector = New-Object System.Diagnostics.Eventing.Reader.EventLogPropertySelector -ArgumentList  @(,[string[]]@(
    "Event/EventData/Data[@Name='TargetSid']",
    "Event/EventData/Data[@Name='IpAddress']",
    "Event/EventData/Data[@Name='Status']"
    ))

$event4769Selector = New-Object System.Diagnostics.Eventing.Reader.EventLogPropertySelector -ArgumentList  @(,[string[]]@(
    "Event/EventData/Data[@Name='TargetUserName']",
    "Event/EventData/Data[@Name='IpAddress']",
    "Event/EventData/Data[@Name='Status']"
    ))

try {
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $numEventsPerPage -ErrorAction Stop
} catch {
    $error_msg = $_.Exception.Message
    if ($error_msg -eq "No events were found that match the specified selection criteria.") {
        Write-Host "No 4768/4769 logs found. Are the relevant audit log settings enabled?"
        Exit 1 
    } elseif ($error_msg -eq "Could not retrieve information about the Security log. Error: Attempted to perform an unauthorized operation..") {
        Write-Host "Unauthorized to read from the Security log. The script must be run as administrator."
        Exit 1
    } else {
        Write-Host "Unknown error: $error_msg"
        Exit 1
    }
}


 while ($events.Count -gt 0) {
    foreach ($event in $events) {
        if ($event.Id -eq 4768) {
            $sid, $ip, $status = $event.GetPropertyValues($event4768Selector)
            try {
                $user = (Get-ADUser -Identity $sid).SamAccountName
            } catch {
                continue
            }
        } elseif ($event.Id -eq 4769) {
            $user, $ip, $status = $event.GetPropertyValues($event4769Selector)
            #https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769
            # Accoridng to this page, this field is SamAccountName@DomainName
            $user = $user.split("@")[0] 
        }

        # We only want to look at successful logins
        if ($status -ne 0) {continue}

        # Normalize the IP Address
        $ip = [IPAddress]$ip
        if ($ip.IsIPv4MappedToIPv6) {
            $ip = $ip.MapToIPv4()
        }
        $ip_string = $ip.IPAddressToString

        $key = $ip_string + "_" + $user.ToLower()

        # Continue if we have already found this target
        if ($possible_targets.Contains($key)) {continue}

        if ($event.Id -eq 4768) {
            $last_time = $lastTGSTimes[$key]
            
            if (($last_time -eq $null -or $event.TimeCreated -lt $last_time.AddSeconds(-$gap_allowed)) -and ($event.TimeCreated -lt $startTime.AddSeconds(-$gap_allowed))) {
                Write-Host "Found possibly vulnerable computer. From IP address: $ip_string with user: $user at time: $($event.TimeCreated.ToString("yyyy-MM-dd hh:mm:ss"))"
                $possible_targets[$key] = $true
            }  
            
        } elseif ($event.Id -eq 4769) {
            $lastTGSTimes[$key] = $event.TimeCreated
        }
    }
    
    $last_event = $events[-1]
    $filter['EndTime'] = $last_event.TimeCreated
    try {
        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $numEventsPerPage -ErrorAction Stop
    } catch {
        $error_msg = $_.Exception.Message
        if ($error_msg -eq "No events were found that match the specified selection criteria.") {
            break
        } else {
            Write-Host "Unknown error: $error_msg"
            Exit 1
        }
    }
    
    # Just in case we are always getting the same events from the same EndTime
    if ($last_event.RecordId -eq $events[-1]) {
        break
    }
}
