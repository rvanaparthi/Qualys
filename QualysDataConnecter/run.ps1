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
Write-Host $username
Write-Host $password
Write-Host $CustomerId
Write-Host $SharedKey
Write-Host $base

