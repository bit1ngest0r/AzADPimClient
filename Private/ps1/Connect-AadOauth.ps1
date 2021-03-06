function Connect-AadOauth {
    
    [CmdletBinding()]
    Param()
    begin {
        
        $authTokenCacheFile = "$AzureADPIMModuleCache\AuthToken.clixml"
        if (-not (Test-Path $authTokenCacheFile)) {
            
            New-Item $authTokenCacheFile -Force | Out-Null
            $noCacheFile = $true

        }
        else {

            try {
                $hashedCacheToken = Import-Clixml -Path $authTokenCacheFile -ErrorAction Stop # Token will have been converted to JSON, then hashed and stored in clixml file
                $secureStringBytes = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($hashedCacheToken) # Cast to Binary String
                $jsonClearText = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($secureStringBytes) # Convert to Unicode
                $cachedAuthToken = $jsonClearText | ConvertFrom-Json # Convert back to object PowerShell object notation
            }
            catch {
                $cachedAuthToken = $null
            }

        }

        # If the token has expired or there is no cached token, prompt for new token and store as encrypted JSON
        if (($noCacheFile) -or (-not $cachedAuthToken) -or ($cachedAuthToken.ExpiresOn.ToLocalTime() -lt (Get-Date))) {

            if ($noCacheFile -or -not $cachedAuthToken) {
                Write-Host "No session cache detected. Login using username and password.`nPrompting for credentials. Please check for hidden window behind other processes." -ForegroundColor Yellow
            }
            else {
                Write-Host "Cached session expired. Prompting for credentials. Please check for hidden window behind other processes." -ForegroundColor Yellow
            }
            try {
                
                $authToken = Get-MsalToken `
                -Interactive `
                -Prompt SelectAccount `
                -Scopes @("https://graph.microsoft.com/.default") `
                -Authority "https://login.microsoftonline.com/common" `
                -ClientId '1b730954-1685-4b74-9bfd-dac224a7b894' `
                -RedirectUri 'urn:ietf:wg:oauth:2.0:oob' `
                -ExtraQueryParameters @{claims='{"access_token" : {"amr": { "values": ["mfa"] }}}'}
                    
                $authTokenJson = $authToken | ConvertTo-Json
                $encryptedData = $authTokenJson | ConvertTo-SecureString -AsPlainText -Force
                $encryptedData | Export-Clixml -Path $authTokenCacheFile -Force # Update the cache file

            }
            catch {

                throw $_

            }
    
        }
        else {
            $authToken = $cachedAuthToken
        }

    }
    process {

        Connect-AzureAD `
        -AadAccessToken $authToken.AccessToken `
        -MsAccessToken $authToken.AccessToken `
        -AccountId $authToken.Account.Username `
        -tenantId $authToken.TenantId | Out-Null

    }
    end {

        if ($authToken) { return $authToken }

    }

}
