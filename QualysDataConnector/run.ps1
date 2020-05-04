# Input bindings are passed in via param block

param($Timer)

 

# Get the current Universal Time

$currentUTCtime = (Get-Date).ToUniversalTime()

 

# The 'IsPastDue' property is 'true' when the current function invocation is later than was originally scheduled

if ($Timer.IsPastDue) {

    Write-Host "PowerShell timer is running late!"

}

 

# Define the Log Analytics Workspace ID and Key

$CustomerId = $env:workspaceId

$SharedKey = $env:workspaceKey

$TimeStampField = "DateValue"

 

# Build the headers for the ProofPoint API request

$username = $env:apiuserName

$password = $env:apipassword

$hdrs = @{"X-Requested-With"="PowerShell"}

$base = "$env:uri" 

Write-Host $base

$body = "action=login&username=$($username)&password=$($password)" 

Invoke-RestMethod -Headers $hdrs -Uri "$base/session/" -Method Post -Body $body -SessionVariable LogonSession

 

# ISO:8601-compliant DateTime required.

$startDate = [System.DateTime]::UtcNow.AddMinutes(-5)

 

# Invoke the API Request and assign the response to a variable ($response)

$response = (Invoke-RestMethod -Headers $hdrs -Uri "$($base)$($startDate.ToString("yyyy-MM-ddTHH:mm:ssZ"))" -WebSession $LogonSession)

 

# Iterate through each detection recieved from the API call and assign the variables (Column Names in LA) to each XML variable

if (-not ($response.HOST_LIST_VM_DETECTION_OUTPUT.RESPONSE.HOST_LIST -eq $null))

{

    $customObjects = @()

    $response.HOST_LIST_VM_DETECTION_OUTPUT.RESPONSE.HOST_LIST.HOST | ForEach-Object {

        $customObject = New-Object -TypeName PSObject

        Add-Member -InputObject $customObject -MemberType NoteProperty -Name "Id" -Value $_.ID

        Add-Member -InputObject $customObject -MemberType NoteProperty -Name "IpAddress" -Value $_.IP

        Add-Member -InputObject $customObject -MemberType NoteProperty -Name "TrackingMethod" -Value $_.TRACKING_METHOD

        Add-Member -InputObject $customObject -MemberType NoteProperty -Name "OperatingSystem" -Value $_.OS."#cdata-section"

        Add-Member -InputObject $customObject -MemberType NoteProperty -Name "DnsName" -Value $_.DNS."#cdata-section"

        Add-Member -InputObject $customObject -MemberType NoteProperty -Name "NetBios" -Value $_.NETBIOS."#cdata-section"

        Add-Member -InputObject $customObject -MemberType NoteProperty -Name "QGHostId" -Value $_.QG_HOSTID."#cdata-section"

        Add-Member -InputObject $customObject -MemberType NoteProperty -Name "LastScanDateTime" -Value $_.LAST_SCAN_DATETIME

        Add-Member -InputObject $customObject -MemberType NoteProperty -Name "LastVMScannedDateTime" -Value $_.LAST_VM_SCANNED_DATE

        Add-Member -InputObject $customObject -MemberType NoteProperty -Name "LastVMAuthScannedDateTime" -Value $_.LAST_VM_AUTH_SCANNED_DATE

        $detections = @()

        foreach($detection in $_.DETECTION_LIST.DETECTION)

        {

            $customSubObject = New-Object -TypeName PSObject

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "QID" -Value $detection.QID

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "Type" -Value $detection.TYPE

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "Severity" -Value $detection.SEVERITY

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "SSL" -Value $detection.SSL

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "Results" -Value $detection.RESULTS.'#cdata-section'

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "Status" -Value $detection.STATUS

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "TimesFound" -Value $detection.TIMES_FOUND

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "FirstFound" -Value $detection.FIRST_FOUND_DATETIME

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "LastFixed" -Value $detection.LAST_FIXED_DATETIME

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "LastFound" -Value $detection.LAST_FOUND_DATETIME

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "LastProcessed" -Value $detection.LAST_PROCESSED_DATETIME

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "LastUpdate" -Value $detection.LAST_UPDATE_DATETIME

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "Ignored" -Value $detection.IS_IGNORED

            Add-Member -InputObject $customSubObject -MemberType NoteProperty -Name "Disabled" -Value $detection.IS_DISABLED

            $detections += $customSubObject

        }

 

        # Add the custom object as a child object to the parent

        Add-Member -InputObject $customObject -MemberType NoteProperty -Name "Detections" -Value $detections

 

    $customObjects += $customObject

    }

 

    # Dispose of the session before we make another HTTP call to LA

    Invoke-RestMethod -Headers $hdrs -Uri "$($base)/session/" -Method Post -Body "action=logout" -WebSession $LogonSession

 

    # Function to build the Authorization signature for the Log Analytics Data Connector API

    Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)

    {

        $xHeaders = "x-ms-date:" + $date

        $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

 

        $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)

        $keyBytes = [Convert]::FromBase64String($sharedKey)

 

        $sha256 = New-Object System.Security.Cryptography.HMACSHA256

        $sha256.Key = $keyBytes

        $calculatedHash = $sha256.ComputeHash($bytesToHash)

        $encodedHash = [Convert]::ToBase64String($calculatedHash)

        $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash

       

        # Dispose SHA256 from heap before return

        $sha256.Dispose()

 

        return $authorization

    }

 

    # Function to create and invoke an API POST request to the Log Analytics Data Connector API

    Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)

    {

        $method = "POST"

        $contentType = "application/json"

        $resource = "/api/logs"

        $rfc1123date = [DateTime]::UtcNow.ToString("r")

        $contentLength = $body.Length

        $signature = Build-Signature `

            -customerId $customerId `

            -sharedKey $sharedKey `

            -date $rfc1123date `

            -contentLength $contentLength `

            -method $method `

            -contentType $contentType `

            -resource $resource

        $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

 

        $headers = @{

            "Authorization" = $signature;

            "Log-Type" = $logType;

            "x-ms-date" = $rfc1123date;

            "time-generated-field" = $TimeStampField;

    }

 

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing

    return $response.StatusCode

 

    }

 

    # Convert to JSON and API POST to Log Analytics Workspace

    $json = $customObjects | ConvertTo-Json -Depth 3        

    Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType "QualysVMScans"

}

else

{

    # Dispose of the session before we make another HTTP call

    Invoke-RestMethod -Headers $hdrs -Uri "$($base)/session/" -Method Post -Body "action=logout" -WebSession $LogonSession

    Write-Host "No new results found for this interval"

}

 

# Write an information log with the current time.

Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"

 