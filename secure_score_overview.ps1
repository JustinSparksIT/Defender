function Get-AccessTokenApp {

    # Define your Azure AD and application details
    $appSecret = ""
    $appId = ""
    $tenantId = ""

    # Define the resource URI and OAuth token endpoint
    $resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
    $oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"

    # Prepare the body for the OAuth token request
    $authBody = [Ordered] @{
         resource = "$resourceAppIdUri"
         client_id = "$appId"
         client_secret = "$appSecret"
         grant_type = 'client_credentials'
    }


    try {
        # Make the OAuth token request
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
        $token = $authResponse.access_token
        Write-Output $token

    } catch {
    }

}

function Get-GraphAccessToken{
    $appSecret = ""
    $appId = ""
    $tenantId = ""
    $GraphScope = "https://graph.microsoft.com/.default"

    # Define the resource URI and OAuth token endpoint
    $oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    # Prepare the body for the OAuth token request
    $authBody = [Ordered] @{
         client_id = "$appId"
         client_secret = "$appSecret"
         grant_type = 'client_credentials'
         scope = $GraphScope
    }

    #Write-Log -Message "Retrieving Token for $resourceAppIdUri"

    try {
        # Make the OAuth token request
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
        $token = $authResponse.access_token
        Write-Output $token
        #Write-Log -Message "Successfully retrieved access token" 

    } catch {
        #Write-Log -Message "An error occurred: $_" 
    }
}

function Get-DefenderMachines {
    param (
        [string]$AccessToken
    )

    # Define the initial API request URL with the filter for osPlatform
    $apiUrl = "https://api.security.microsoft.com/api/machines?`$Select=id,computerDnsName,aadDeviceId,healthStatus,osPlatform,lastSeen"
    #$apiUrl = "https://api.security.microsoft.com/api/machines?`$Select=id,computerDnsName,aadDeviceId,healthStatus,osPlatform"
    $allMachines = @()

    do {
        try {
            # Make the API request
            $response = Invoke-RestMethod -Method Get -Uri $apiUrl -Headers @{ Authorization = "Bearer $AccessToken" } -ErrorAction Stop
            $allMachines += $response.value

            # Check if there is a next page
            $apiUrl = $response.'@odata.nextLink'
        } catch {
            throw $_
        }
    } while ($apiUrl)

    Write-Output $allMachines
}


function Get-GraphSecureScores {

    $apiUrl = "https://graph.microsoft.com/v1.0/security/secureScores"

    
    # Set up the headers with the authorization token
    $headers = @{
        "Authorization" = "Bearer $graphaccessToken"
        "Content-Type"  = "application/json"
    }

    $array = @()

    # Make the API request
    $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get

    # Output the list of machines
    $array += $response.value

    return $array

}

function Get-DefenderSecureRecommendationMachines{
    [CmdletBinding()]
    param (
        [string]$accessToken,
        $id
    )

    $apiUrl = "https://api-us.securitycenter.microsoft.com/api/recommendations/$id/machineReferences"

    
    # Set up the headers with the authorization token
    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
    }
    $array = @()

    do {
        # Make the API request
        $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get

        # Output the list of machines
        $array += $response.value

        # Check if there is a next page
        $apiUrl = $response.'@odata.nextLink'
    } while ($apiUrl)

    return $array
}

function Get-DefenderSecureRecommendations{
    [CmdletBinding()]
    param (
        [string]$accessToken
    )

    $apiUrl = "https://api-us.securitycenter.microsoft.com/api/recommendations"

    
    # Set up the headers with the authorization token
    $headers = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type"  = "application/json"
    }
    $array = @()

    do {
        # Make the API request
        $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get

        # Output the list of machines
        $array += $response.value

        # Check if there is a next page
        $apiUrl = $response.'@odata.nextLink'
    } while ($apiUrl)

    return $array
}
$startDate = Get-Date -Format "yyyy-MM-dd_HH:mm:ss"
Write-Host "Start Time: $startDate"


$graphaccessToken = Get-GraphAccessToken
$defenderAccessToken = Get-AccessTokenApp

$DefenderMachines = Get-DefenderMachines -AccessToken $defenderAccessToken

$secureScores = Get-GraphSecureScores 

$latestSecureScores = $secureScores | Sort-Object createdDateTime | Select -Last 2

$deviceRecommendations = $latestSecureScores[1].controlScores | Where-Object {$_.ControlCategory -match "Device"}

$reference = Import-Csv -Path "c:\users\justinsparks\downloads\recommendations_reference.csv"



foreach($deviceRecommendation in $deviceRecommendations){
    $pointsPossible = [math]::Round($deviceRecommendation.Score / ($deviceRecommendation.scoreInPercentage / 100), 0)
    $pointsRemaining = [math]::Round($pointsPossible - $deviceRecommendation.Score, 2)
    $id = $deviceRecommendation.controlName -replace "_","-"
    $id = "sca-_-$id"
    $deviceRecommendation | Add-Member -MemberType NoteProperty -Name "Points Remaining" -Value $pointsRemaining -Force
    $deviceRecommendation | Add-Member -MemberType NoteProperty -Name "URL" -Value "https://security.microsoft.com/security-recommendations?recommendationId=$id" -Force
    $deviceRecommendation | Add-Member -MemberType NoteProperty -Name "ID" -Value $id -Force
    $deviceRecommendation.scoreInPercentage = [math]::Round($deviceRecommendation.scoreInPercentage / 100, 4)
    
    $recommendationName = $reference | where id -eq $id | Select -ExpandProperty "Recommendation Name"
    $pointsPossible = $reference | where id -eq $id | Select -ExpandProperty "Total Points Possible"

    $deviceRecommendation | Add-Member -MemberType NoteProperty -Name "Recommendation Name" -Value $recommendationName -Force
    $deviceRecommendation | Add-Member -MemberType NoteProperty -Name "Total Points Possible" -Value $pointsPossible -Force
}


#$deviceRecommendations | export-csv -path "c:\users\justinsparks\downloads\recommendations_reference.csv" -NoTypeInformation -Encoding UTF8
$overview = @()

foreach($deviceRecommendation in $deviceRecommendations){
    $machines = Get-DefenderSecureRecommendationMachines -accessToken $defenderAccessToken -id $deviceRecommendation.id

    $matchingMachines = $DefenderMachines | Where-Object { $machines.id -contains $_.id }
    #add matching machines to excel spreadsheet

    $recommendationName = $deviceRecommendation."Recommendation Name"
    $recommendationID = $deviceRecommendation.ID
    $totalPointsPossible = $deviceRecommendation."Total Points Possible"
    $totalPointsAchieved = $deviceRecommendation.Score
    $pointsPerMachine = ($totalPointsPossible / $deviceRecommendation.total)
    $pointsRemaining = $deviceRecommendation."Points Remaining"
    $totalMachines = $deviceRecommendation.total
    $totalExposed = $deviceRecommendation.count
    $totalCompliant = ($deviceRecommendation.total - $deviceRecommendation.count)
    $windows = $matchingMachines | Where-Object {$_.osPlatform -eq "Windows10" -or $_.osPlatform -eq "Windows11"} | Measure-Object | Select -ExpandProperty Count
    $windowsPoints = $windows * $pointsPerMachine
    $macOS = $matchingMachines | Where-Object {$_.osPlatform -eq "macOS"} | Measure-Object | Select -ExpandProperty Count 
    $macOSPoints = $macOS * $pointsPerMachine
    $servers = $matchingMachines | Where-Object {$_.osPlatform -eq "WindowsServer2022" -or $_.osPlatform -eq "WindowsServer2019" -or $_.osPlatform -eq "WindowsServer2016" -or $_.osPlatform -eq "Linux" -or $_.osPlatform -eq "Ubuntu"} | Measure-Object | Select -ExpandProperty Count
    $serverPoints = $servers * $pointsPerMachine
    $activeMachines = $matchingMachines | Where-Object {$_.healthStatus -eq "Active"} | Measure-Object | Select -ExpandProperty Count
    $activeMachinesPoints = $activeMachines * $pointsPerMachine
    $inactiveMachines = $matchingMachines | Where-Object {$_.healthStatus -ne "Active"} | Measure-Object | Select -ExpandProperty Count
    $inactiveMachinesPoints = $inactiveMachines * $pointsPerMachine

    $overview += [PSCustomObject]@{
        "Recommendation Name" = $recommendationName
        "Recommendation ID" = $recommendationID
        "Total Points Possible" = $totalPointsPossible
        "Total Points Achieved" = $totalPointsAchieved
        "Total Percentage Achieved" = $totalPointsAchieved / $totalPointsPossible
        "Points Per Machine" = $pointsPerMachine
        "Points Remaining" = $pointsRemaining
        "Total Machines" = $totalMachines
        "Total Exposed" = $totalExposed
        "Total Compliant" = $totalCompliant
        "Windows Exposed" = $windows
        "Windows Points" = $windowsPoints
        "Windows Percentage" = $windows / $totalMachines
        "macOS Exposed" = $macOS
        "macOS Exposed Points" = $macOSPoints
        "macOS Percentage" = $macOS / $totalMachines
        "Servers Exposed" = $servers
        "Servers Exposed Points" = $serverPoints
        "Servers Percentage" = $servers / $totalMachines
        "Active Exposed" = $activeMachines
        "Active Exposed Points" = $activeMachinesPoints
        "Active Percentage" = $activeMachines / $totalMachines
        "Inactive Exposed" = $inactiveMachines
        "Inactive Exposed Points" = $inactiveMachinesPoints
        "Inactive Percentage" = $inactiveMachines / $totalMachines
    }

   
}

$shortDate = $(Get-Date -Format "yyyy-MM-dd-hh-mm")
$overview | export-csv -path "$ENV:USERPROFILE\downloads\recommendations_overview_$shortDate.csv" -NoTypeInformation -Encoding UTF8

$totalAchievedDevicePoints = $overview | Measure-Object -Property "Total Points" -Sum | Select -ExpandProperty Sum
$totalPointsPossible = $overview | Measure-Object -Property "Total Points Possible" -Sum | Select -ExpandProperty Sum
$deviceSecureScore = [math]::Round(($totalAchievedDevicePoints / $totalPointsPossible) * 100, 2)

$windowsPointsRemaining = $overview | Measure-Object -Property "Windows Points" -Sum | Select -ExpandProperty Sum
$macOSPointsRemaining = $overview | Measure-Object -Property "macOS Points" -Sum | Select -ExpandProperty Sum
$azureVmsPointsRemaining = $overview | Measure-Object -Property "Azure VMs Points" -Sum | Select -ExpandProperty Sum
$activeMachinesPointsRemaining = $overview | Measure-Object -Property "Active Machines Points" -Sum | Select -ExpandProperty Sum
$inactiveMachinesPointsRemaining = $overview | Measure-Object -Property "Inactive Machines Points" -Sum | Select -ExpandProperty Sum


$totalWindowsCompliance = [math]::round((($windowsPointsRemaining + $totalAchievedDevicePoints) / $totalPointsPossible) * 100, 2)
$totalMacOSCompliance = [math]::round((($macOSPointsRemaining + $totalAchievedDevicePoints) / $totalPointsPossible) * 100, 2)
$totalAzureVmsCompliance = [math]::round((($azureVmsPointsRemaining + $totalAchievedDevicePoints) / $totalPointsPossible) * 100, 2)
$totalActiveMachinesCompliance = [math]::round((($activeMachinesPointsRemaining + $totalAchievedDevicePoints) / $totalPointsPossible) * 100, 2)
$totalInactiveMachinesCompliance = [math]::round((($inactiveMachinesPointsRemaining + $totalAchievedDevicePoints) / $totalPointsPossible) * 100, 2)

Write-Host "Total Device Secure Score: $deviceSecureScore"
Write-Host "Total Device Compliance not including Windows: $totalWindowsCompliance"
Write-Host "Total Device Compliance not including macOS: $totalMacOSCompliance"
Write-Host "Total Device Compliance not including Azure VMs: $totalAzureVmsCompliance"
Write-Host "Total Device Compliance not including Active Machines: $totalActiveMachinesCompliance"
Write-Host "Total Device Compliance not including Inactive Machines: $totalInactiveMachinesCompliance"


$endDate = Get-Date -Format "yyyy-MM-dd_HH:mm:ss"
Write-Host "End Time: $endDate"
