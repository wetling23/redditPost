[string]$RmmPublicKey
[securestring]$RmmPrivateKey
[string]$AntiVirusAccessToken,
[securestring]$AntiVirusSecretKey,
[string[]]$Exclusion,
[string]$LogPath

start-transcript
$message = ("{0}: Beginning {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
Write-Host $message

#region setup
# Initialize variables.
$timer = [system.diagnostics.stopwatch]::startNew()
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$timeSpan = New-TimeSpan -Minutes 1 -Seconds 30
$progressCounter = 0
$reportedDevices = @()

If (Test-Path -Path "$(Split-Path -parent $MyInvocation.MyCommand.Definition)\Join.ps1") {
    $message = ("{0}: Attempting to import the Join script." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    Write-Host $message

    . "$(Split-Path -parent $MyInvocation.MyCommand.Definition)\Join.ps1"

    Try {
        $null = Get-Command -Name Join-Object -ErrorAction Stop

        $message = ("{0}: Successfully imported the Join script." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
        Write-Host $message
    }
    Catch {
        $message = ("{0}: Importing Join failed. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
        Write-Host $message

        Exit 1
    }
}
Else {
    $message = ("{0}: Unable to locate Join.ps1. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    Write-Host $message

    Exit 1
}

If ($PSBoundParameters['Verbose']) {
    $commandParams = @{
        Verbose = $true
    }

    If ($LogPath) {
        $CommandParams.Add('LogPath', $LogPath)
    }
}
Else {
    If ($LogPath) {
        $commandParams = @{
            LogPath = $LogPath
        }
    }
}

# If the exclusions.txt file is present, use it unless -Exclusion parameter is also defined. The parameter overrides the file.
If (-NOT($Exclusion) -and (Test-Path -Path "$(Split-Path -parent $MyInvocation.MyCommand.Definition)\exclusions.txt")) {
    $message = ("{0}: Found an exclusions file in the script directory, reading it." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    Write-Host $message

    [string[]]$exclusion = Get-Content -Path "$(Split-Path -parent $MyInvocation.MyCommand.Definition)\exclusions.txt"
}
ElseIf ($Exclusion -and (Test-Path -Path "$(Split-Path -parent $MyInvocation.MyCommand.Definition)\exclusions.txt")) {
    $message = ("{0}: Both the -Exclusion parameter and exclusions.txt file were found. Using the parameter values." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    Write-Host $message
}
#endregion Setup

#region Jobs
$message = ("{0}: Attempting to get RMM sites." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
Write-Host $message

$allRmmSites = Get-RmmSite -AccessToken (New-RmmApiAccessToken -ApiKey $RmmPublicKey -ApiSecretKey $RmmPrivateKey @commandParams) @commandParams | Where-Object { $_.siteName -ne 'Deleted Devices' }

$message = ("{0}: Attempting to get AntiVirus customers (that are not expired)." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
Write-Host $message

$allAntiVirusCustomers = Get-AntiVirusCustomer -AccessToken $AntiVirusAccessToken -SecretKey $AntiVirusSecretKey @commandParams

$message = ("{0}: Found the following:`r`n`tRMM sites: {1}`r`n`tTM AntiVirus Customers: {2}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $allRmmSites.Count, $allAntiVirusCustomers.Count)
Write-Host $message

If (-NOT($allRmmSites) -or -NOT($allAntiVirusCustomers)) {
    $message = ("{0}: Too few sites/customers returned. To prevent errors, {1} will exit." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand)
    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

    $timer.Stop()

    Exit 1
}
#endregion Jobs

#region Main
# Removing special characters: "\\|\/|\.|&|\s|\(|\)|-|,|'|`"|_" = back slash, forward slash, dot, ampersand, space, open paren, close paren, dash, comma, single quote, double quote, underscore.
$message = ("{0}: Removing special characters to normalize the site names." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
Write-Host $message

$allRmmSites | ForEach-Object {
    $_ | Add-Member -MemberType NoteProperty -Name normalizedName -Value (($_.name).Trim() -replace "\/|\.|&|\s|\(|\)|-|,|'|`"|_", '') -Force
}

$message = ("{0}: Removing special characters to normalize the customer names." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
Write-Host $message

$allAntiVirusCustomers | ForEach-Object {
    $_ | Add-Member -MemberType NoteProperty -Name normalizedName -Value (($_.name).Trim() -replace "\/|\.|&|\s|\(|\)|-|,|'|`"|_", '') -Force
}

$siteList = $allRmmSites | Join-Object -RightObject $allAntiVirusCustomers -JoinType Full -On normalizedName

$Exclusion | ForEach-Object {
    $exclusionList += [PSCustomObject]@{
        customer       = $_
        normalizedName = ($_ -replace "\/|\.|&|\s|\(|\)|-|,|'|`"|_", '')
    }
}

$reportedDevices += Foreach ($site in $siteList) {
    $customerRmmDevices = $null
    $customerAntiVirusDevices = $null
    $progressCounter++
    $continue = $false

    $message = ("{0}: ===============================================" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    Write-Host $message

    $stopWatch.Start()
    Do {
        # Ignore deleted devices.
        If (($site.normalizedName -eq "DeletedDevices") -or ($site.normalizedName -in $exclusionList.normalizedName)) {
            $message = ("{0}: Skipping {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $site.normalizedName)
            Write-Host $message

            Continue
        }
        Else {
            $message = ("{0}: Working on {1}. This is customer {2} of {3}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $site.normalizedName, $progressCounter, $siteList.Count)
            Write-Host $message
        }

        Try {
            If ($site.uid) {
                $message = ("{0}: Attempting to get RMM devices for {1} (uid: {2})." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), ($site.name[0]).Trim(), $site.uid)
                Write-Host $message

                $customerRmmDevices = Get-RmmDevice -RmmAccessToken (New-RmmApiAccessToken -ApiKey $RmmPublicKey -ApiSecretKey $RmmPrivateKey @commandParams) -SiteUID $site.uid @commandParams
            }
            Else {
                $message = ("{0}: No RMM site found, equal to {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), ($site.name[1]).Trim())
                Write-Host $message
            }

            If ($site.id[1]) {
                $message = ("{0}: Attempting to get AntiVirus devices for {1} (id: {2})." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), ($site.name[1]).Trim(), ($site.id[1]).Trim())
                Write-Host $message

                $customerAntiVirusDevices = (Get-AntiVirusComputer -AccessToken $AntiVirusAccessToken -SecretKey $AntiVirusSecretKey -CustomerId ($site.id[1]).Trim() @commandParams).computers
            }
            Else {
                $message = ("{0}: No AntiVirus customer found matching {1}." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $site.normalizedName)
                Write-Host $message
            }

            If ($customerRmmDevices -and $customerAntiVirusDevices) {
                $message = ("{0}: Found {1} devices in RMM." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $customerRmmDevices.Count)
                Write-Host $message

                $message = ("{0}: Found {1} devices in AntiVirus. Adding the `"hostname`" properties." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $customerAntiVirusDevices.Count)
                Write-Host $message

                $customerAntiVirusDevices | ForEach-Object {
                    $_ | Add-Member -MemberType NoteProperty -Name hostname -Value $_.name -Force
                }

                $message = ("{0}: Joining RMM and AntiVirus device lists and returning the combined objects." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                Write-Host $message

                $customerRmmDevices | Join-Object -RightObject $customerAntiVirusDevices -On hostname -JoinType Full
            }
            ElseIf ($customerRmmDevices) {
                $message = ("{0}: Found {1} devices in RMM. No AntiVirus devices." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $customerRmmDevices.Count)
                Write-Host $message

                $message = ("{0}: Returning RMM device list." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                Write-Host $message

                $customerRmmDevices
            }
            ElseIf ($customerAntiVirusDevices) {
                $message = ("{0}: Found {1} devices in AntiVirus. Adding the `"hostname`" properties. No RMM devices." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $customerAntiVirusDevices.Count)
                Write-Host $message

                $customerAntiVirusDevices | ForEach-Object {
                    $_ | Add-Member -MemberType NoteProperty -Name hostname -Value $_.name -Force
                }

                $message = ("{0}: Returning AntiVirus device list." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
                Write-Host $message

                $customerAntiVirusDevices
            }
        }
        Catch {
            $message = ("{0}: Error: {1}" -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $_.Exception.Message)
            If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }
        }
        $continue = $true
    }
    Until (($stopWatch.Elapsed -ge $timeSpan) -or ($continue -eq $true))
    $stopWatch.Reset()
}
#endregion Main

If ($reportedDevices) {
    $message = ("{0}: Returning {1} reported devices." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $reportedDevices.Count)
    Write-Host $message

    $reportedDevices | Select-Object -Property hostname, @{ Name = "InRmm"; Expression = { If ($_.siteId) { "True" } Else { "False" } } }, @{ Name = "InAntiVirus"; Expression = { If ($_.aa) { "True" } Else { "False" } } }, @{ Name = "DeviceType"; Expression = { If ($_.deviceType.Category) { $_.deviceType.Category } Else { "Unknown" } } }, @{ Name = "OS"; Expression = { If ($_.operatingSystem) { $_.operatingSystem } Else { $_.platform } } }, @{ Name = "CustomerName"; Expression = { If ($_.siteName) { $_.siteName } Else { $_.CustomerName } } } | Export-Csv -Path "$(Split-Path -parent $MyInvocation.MyCommand.Definition)\report.csv" -NoTypeInformation

    $timer.Stop()

    $message = ("{0}: {1} completed. The script took {2} minutes to run." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"), $MyInvocation.MyCommand, $timer.Elapsed.TotalMinutes)
    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Info -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Info -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Info -Message $message }

    Exit 0
}
Else {
    $timer.Stop()

    $message = ("{0}: No devices returned...that can't be good." -f ([datetime]::Now).ToString("yyyy-MM-dd`THH:mm:ss"))
    If ($EventLogSource -and (-NOT $LogPath)) { Out-PsLogging -EventLogSource $EventLogSource -MessageType Error -Message $message } ElseIf ($LogPath -and (-NOT $EventLogSource)) { Out-PsLogging -LogPath $LogPath -MessageType Error -Message $message } Else { Out-PsLogging -ScreenOnly -MessageType Error -Message $message }

    Exit 1
}
stop-transcript
