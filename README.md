# Auth0PS

PowerShell client for the Auth0 Management API

## Installation

``` powershell
Install-Module Auth0PS -Scope CurrentUser
```

## Available Commands

### Get-Auth0Context

Retrieves an access token for use with the management API.

``` powershell
Get-Auth0Context -Domain 'your-domain.auth0.com' -ClientId 'your-client-id' -ClientSecret 'your-client-secret'
```

### Get-Auth0Clients

Lists all clients in the Auth0 domain provided by the context.

``` powershell
Get-Auth0Clients -Context
```

### Get-Auth0Client

Retrieves details about the specified client.

``` powershell
Get-Auth0Client -Context -ClientId
```

### New-Auth0Client

Creates a new Auth0 client based on [this API](https://auth0.com/docs/api/management/v2#!/Clients/post_clients) and returns the response.

``` powershell
New-Auth0Client -Context -Name [-AppType] [-Callbacks] [-AllowedLogoutUrls] [-UseAuth0ForSSO]
```

### Remove-Auth0Client

Removes an Auth0 client based on [this API](https://auth0.com/docs/api/management/v2#!/Clients/delete_clients_by_id).

``` powershell
Remove-Auth0Client -Context -ClientId
```

## Issues and Contributing

Please log [issues](https://github.com/panesofglass/Auth0PS/issues) and submit new features via [pull requests](https://github.com/panesofglass/Auth0PS/pulls).
