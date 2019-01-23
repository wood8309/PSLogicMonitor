function set-requestHeader {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$accessId,

        [Parameter()]
        [string]$accessKey,

        [Parameter()]
        [string]$httpverb,

        [Parameter()]
        [string]$resourcepath,

        [Parameter()]
        [string]$requestdata
    )

    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)

    $requestVars = $httpVerb + $epoch + $data + $resourcePath

    <# Construct Signature #>
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($accessKey)
    $signatureBytes = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($requestVars))
    $signatureHex = [System.BitConverter]::ToString($signatureBytes) -replace '-'
    $signature = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($signatureHex.ToLower()))

    <# Construct Headers #>
    $auth = 'LMv1 ' + $accessId + ':' + $signature + ':' + $epoch
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization",$auth)
    $headers.Add("Content-Type",'application/json')

    return $headers
}
function Connect-LMapi {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $accessId,

        [Parameter(Mandatory)]
        [string]
        $accessKey,

        [Parameter()]
        [string]
        $company
    )
    $secureAccessKey = ConvertTo-SecureString -AsPlainText $accessKey -Force

    $global:LMtoken = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $accessId,$secureAccessKey

    $global:baseURL = 'https://' + $company + '.logicmonitor.com/santaba/rest'

    $error = $false

    try {
        <# Use TLS 1.2 #>
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $request = Get-LMdevices -token $global:LMtoken 
    }
    catch {
        Write-Host 'Unable to connect'
        $error = $true
    }
    if (-not $error){
        Write-Host 'Successfully Connected'
    }

}

<# Ops Notes #>

<# Alert Rules #>

<# Alerts #>

<# API Tokens #>

<# Audit Logs #>

<# Collectors #>

<# Collector Groups #>

<# Dashboards and Widgets #>

<# Dashboard Groups #>

<# Data #>

<# Datasources #>

<# Datasource Instances #>

<# Devices #>
function Add-LMdevice {
    [CmdletBinding()]
    param (
        
        [Parameter()]
        $token=$LMtoken,
        
        # Devices to be added
        [Parameter(Mandatory)]
        [string[]]
        $DeviceName,

        # Device Display Name
        [Parameter()]
        [string]
        $DisplayName,

        # Preferred Collector Id
        [Parameter(Mandatory)]
        [int]
        $PreferredColletorId,

        # Host Group Id
        [Parameter(Mandatory)]
        [string[]]
        $HostGroupIds

    )
        
        <# request details #>
        $resourcePath = '/device/devices'
        $data = '{"name":"'+$DeviceName+'","displayName":"'+$DisplayName+'","preferredCollectorId":"'+$PreferredColletorId+'","hostGroupIds":"'+$HostGroupIds+'"}'

        <# Construct URL #>
        $url = $global:baseURL + $resourcePath

        $headers = set-requestHeader -httpverb 'POST' -requestdata $data -resourcepath $resourcePath -accessId $token.UserName -accessKey $token.GetNetworkCredential().password

        $response = Invoke-RestMethod -Uri $url -Method 'POST' -Header $headers -Body $data

        $status = $response.status
        $body = $response.data| ConvertTo-Json -Depth 5

        return $status
        return $body
}
function Get-LMdevices {
    [CmdletBinding()]
    param (
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        $token=$LMtoken,

        # Device Id
        [Parameter()]
        [string]
        $deviceId,

        # Results Size
        [Parameter()]
        [string]
        $resultsize='',

        # Filter On
        [Parameter()]
        [string]
        $filter='',

        # Fields to return
        [Parameter()]
        [string[]]
        $fields='',

        [switch] $unmonitored
    )
       
    if ($unmonitored){
        $resourcePath = '/device/unmonitoreddevices'
    }
    else{
        $resourcePath = "/device/devices"
    }
    $error = $false
    try {
        $headers = set-requestHeader -httpverb 'GET' -resourcepath $resourcePath -accessId $token.UserName -accessKey $token.GetNetworkCredential().password
    }
    catch {
        Write-Host 'Unable to set headers. Make sure you have successfully connected to LogicMonitor using the Connect-LMapi first.'
        $error = $true
    }
    if(-not $error){

    $url = $global:baseURL + $resourcePath

        if ($resultsize -like "*") {
            $url += "?size="+$resultsize
        }

    $response = Invoke-RestMethod -Uri $url -Method 'GET' -Header $headers

    return $response
    }
}

<# Device Groups #>

<# Escalation Chains #>

<# Reports #>

<# Report Groups #>

<# Roles #>

<# SDTs #>
function Add-LMsdt {
    [CmdletBinding()]
    param (
        
        [Parameter()]
        $token=$LMtoken,
        
        [Parameter(Mandatory)]
        [string]
        $deviceId,

        # Length of SDT in minutes
        [Parameter]
        [int]
        $duration=60
    )

    <# Get current time in milliseconds #>
    $epoch = [Math]::Round((New-TimeSpan -start (Get-Date -Date "1/1/1970") -end (Get-Date).ToUniversalTime()).TotalMilliseconds)
    $duration * 60000
    $endSDT = $epoch + $duration
    
    <# request details #>
    $resourcePath = "/sdt/sdts"
    $data = '{"sdtType":1,"type":"DeviceSDT","deviceId":398,"startDateTime":'+$epoch+',"endDateTime":'+$endSDT+'}'
    
    <# Construct URL #>
    $url = $global:baseURL + $resourcePath

    $headers = set-requestHeader -httpverb 'POST' -requestdata $data -resourcepath $resourcePath -accessId $token.UserName -accessKey $token.GetNetworkCredential().password
    
    $response = Invoke-RestMethod -Uri $url -Method 'POST' -Header $headers -Body $data

    $status = $response.status
    $body = $response.data| ConvertTo-Json -Depth 5

    return $status
    return $body
}

<# Websites #>

<# Website Groups #>

<# Service Test Locations #>

<# Thresholds #>

<# Users #>

Export-ModuleMember Connect-LMapi
Export-ModuleMember Add-LMdevice
Export-ModuleMember Get-LMdevices
Export-ModuleMember Set-LMsdt
