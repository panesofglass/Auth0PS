<#
.SYNOPSIS
        Auth0.psm1 - PowerShell client for the Auth0 Management API
.DESCRIPTION
        Auth0.psm1 - PowerShell client for the Auth0 Management API
#>

#Requires -Version 5

class Auth0Token
{
    [ValidateNotNullOrEmpty()][string]$access_token
    [ValidateNotNullOrEmpty()][string]$token_type
    [int]$expires_in
    [string[]]$scope
}

class Auth0Context
{
    [ValidateNotNullOrEmpty()][string]$Domain
    [ValidateNotNullOrEmpty()][Auth0Token]$Token
}

function Get-Auth0Context
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=1)] [string] $Domain,
        [Parameter(Mandatory=$true, Position=2)] [string] $ClientId,
        [Parameter(Mandatory=$true, Position=3)] [string] $ClientSecret
    )

    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add('Content-Type', 'application/json')
    $json = @{
        'client_id' = $ClientId
        'client_secret' = $ClientSecret
        'audience' = "https://$Domain/api/v2/"
        'grant_type' = 'client_credentials'
    } | ConvertTo-Json

    $result = $webClient.UploadString("https://$Domain/oauth/token", $json) | ConvertFrom-Json
    return [Auth0Context]@{
        Domain = $Domain
        Token = [Auth0Token]$result
    }
}

function Get-Auth0Clients
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=1)] [Auth0Context] $Context
    )

    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add('Authorization', $Context.Token.token_type + ' ' + $Context.Token.access_token)
    return $webClient.DownloadString('https://' + $Context.Domain + '/api/v2/clients') | ConvertFrom-Json
}

function Get-Auth0Client
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=1)] [Auth0Context] $Context,
        [Parameter(Mandatory=$true, Position=2, ValueFromPipelineByPropertyName)]
        [Alias('client_id')] [string] $ClientId
    )

    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add('Authorization', $Context.Token.token_type + ' ' + $Context.Token.access_token)
    return $webClient.DownloadString('https://' + $Context.Domain + '/api/v2/clients/' + $ClientId) | ConvertFrom-Json
}

function New-Auth0Client
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=1)] [Auth0Context] $Context,
        [Parameter(Mandatory=$true, Position=2)] [string] $Name,
        [Parameter(Mandatory=$false)] [ValidateSet('native','spa','regular_web','non_interactive')] [string] $AppType,
        [Parameter(Mandatory=$false)] [string[]] $Callbacks,
        [Parameter(Mandatory=$false)] [string[]] $AllowedLogoutUrls,
        [Parameter(Mandatory=$false)] [switch] $UseAuth0ForSSO,
        [Parameter(Mandatory=$false)] [switch] $OidcConformant,
        [Parameter(Mandatory=$false)] [Hashtable] $JwtConfiguration
    )

    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add('Authorization', $Context.Token.token_type + ' ' + $Context.Token.access_token)
    $webClient.Headers.Add('Content-Type', 'application/json')
    $config = @{
        'name' = $Name
        'sso' = [boolean]$UseAuth0ForSSO
        'oidc_conformant' = [boolean]$OidcConformant
    }
    if ($AppType) {
        $config.Add('app_type', $AppType)
    }
    if ($Callbacks) {
        $config.Add('callbacks', $Callbacks)
    }
    if ($AllowedLogoutUrls) {
        $config.Add('allowed_logout_urls', $AllowedLogoutUrls)
    }
    if ($JwtConfiguration) {
        $config.Add('jwt_configuration', $JwtConfiguration)
    }
    $json = $config | ConvertTo-Json

    return $webClient.UploadString('https://' + $Context.Domain + '/api/v2/clients', $json) | ConvertFrom-Json
}

function Remove-Auth0Client
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=1)] [Auth0Context] $Context,
        [Parameter(Mandatory=$true, Position=2, ValueFromPipelineByPropertyName)]
        [Alias('client_id')] [string] $ClientId
    )

    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add('Authorization', $Context.Token.token_type + ' ' + $Context.Token.access_token)
    $content = New-Object System.Collections.Specialized.NameValueCollection
    return $webClient.UploadValues('https://' + $Context.Domain + '/api/v2/clients/' + $ClientId, 'DELETE', $content) | ConvertFrom-Json
}

function New-Auth0Connection
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=1)] [Auth0Context] $Context,
        [Parameter(Mandatory=$true, Position=2)] [string] $Name,
        [Parameter(Mandatory=$true, Position=3)] [string] $Strategy,
        [Parameter(Mandatory=$false)] [switch] $DisableSignup
    )

    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add('Authorization', $Context.Token.token_type + ' ' + $Context.Token.access_token)
    $webClient.Headers.Add('Content-Type', 'application/json')

    $config = @{
        'name' = $Name
        'strategy' = $Strategy
    }

    if ($DisableSignup) {
        $config.Add('options',  @{ 'disable_signup' = [boolean]$DisableSignup })
    }

    $json = $config | ConvertTo-Json
    return $webClient.UploadString('https://' + $Context.Domain + '/api/v2/connections', $json) | ConvertFrom-Json
}

function Get-Auth0Connections
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=1)] [Auth0Context] $Context
    )

    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add('Authorization', $Context.Token.token_type + ' ' + $Context.Token.access_token)
    return $webClient.DownloadString('https://' + $Context.Domain + '/api/v2/connections') | ConvertFrom-Json
}

function Get-Auth0Connection
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=1)] [Auth0Context] $Context,
        [Parameter(Mandatory=$true, Position=2, ValueFromPipelineByPropertyName)]
        [Alias('id')] [string] $ConnectionId
    )

    $webClient = New-Object System.Net.WebClient
    $webClient.Headers.Add('Authorization', $Context.Token.token_type + ' ' + $Context.Token.access_token)
    return $webClient.DownloadString('https://' + $Context.Domain + '/api/v2/connections/' + $ConnectionId) | ConvertFrom-Json
}

function Add-Auth0ClientToConnection
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=1)] [Auth0Context] $Context,
        [Parameter(Mandatory=$true, Position=2)] [string] $ConnectionId,
        [Parameter(Mandatory=$true, Position=3)] [string] $ClientId
    )

    $auth0Connection = Get-Auth0Connection $context $ConnectionId

    if ($auth0Connection -eq $null) {
        throw "Auth0 connection with $ConnectionId not found."
    }

    $auth0Client = Get-Auth0Client $context $ClientId

    if ($auth0Client -eq $null) {
        throw "Auth0 client with $ClientId not found."
    }

    $clientExists = $auth0Connection.enabled_clients -contains $ClientId

    if (-not $clientExists) {
        Write-Host Adding $auth0Client.name to $auth0Connection.name...

        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add('Authorization', $Context.Token.token_type + ' ' + $Context.Token.access_token)
        $webClient.Headers.Add('Content-Type', 'application/json')
        
        $new_enabled_clients = $auth0Connection.enabled_clients + $ClientId
        
        $config = @{
            'enabled_clients' = $new_enabled_clients
        }

        $json = $config | ConvertTo-Json
        return $webClient.UploadString('https://' + $Context.Domain + '/api/v2/connections/' + $ConnectionId, 'PATCH', $json) | ConvertFrom-Json
    } else {
        Write-Host $auth0Client.name already exists "in" $auth0Connection.name
    }
}

function Remove-Auth0ClientFromConnection
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=1)] [Auth0Context] $Context,
        [Parameter(Mandatory=$true, Position=2)] [string] $ConnectionId,
        [Parameter(Mandatory=$true, Position=3)] [string] $ClientId
    )

    $auth0Connection = Get-Auth0Connection $context $ConnectionId

    if ($auth0Connection -eq $null) {
        throw "Auth0 connection with $ConnectionId not found."
    }

    $auth0Client = Get-Auth0Client $context $ClientId

    if ($auth0Client -eq $null) {
        throw "Auth0 client with $ClientId not found."
    }

    $clientExists = $auth0Connection.enabled_clients -contains $ClientId

    if (-not $clientExists) {
        Write-Host $auth0Client.name does not exists "in" $auth0Connection.name
    } else {
        Write-Host Removing $auth0Client.name from $auth0Connection.name...

        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add('Authorization', $Context.Token.token_type + ' ' + $Context.Token.access_token)
        $webClient.Headers.Add('Content-Type', 'application/json')

        $new_enabled_clients = New-Object System.Collections.ArrayList
        ($auth0Connection.enabled_clients) | ? { $_ -ne $ClientId } | % { $new_enabled_clients.Add($_) }

        $config = @{
            'enabled_clients' = $new_enabled_clients
        }   

        $json = $config | ConvertTo-Json
        return $webClient.UploadString('https://' + $Context.Domain + '/api/v2/connections/' + $ConnectionId, 'PATCH', $json) | ConvertFrom-Json
    }
}


Export-ModuleMember -Function Get-Auth0Context, Get-Auth0Clients, Get-Auth0Client, New-Auth0Client, Remove-Auth0Client,
    New-Auth0Connection, Get-Auth0Connections, Get-Auth0Connection, Add-Auth0ClientToConnection, Remove-Auth0ClientFromConnection
