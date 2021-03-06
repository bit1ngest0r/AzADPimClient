$powershellGetCheck = Get-Module PowerShellGet -ListAvailable
if (-not $powershellGetCheck.RepositorySourceLocation) {
    try {
        Install-Module PowerShellGet -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        New-Variable -Name PowerShellGetRestartRequired -Value $true -Option Constant -Scope Global
        do 
        {
            $prompt = Read-Host 'A new version of PowerShellGet was installed and PowerShell must be restarted. Enter YES to exit'
        }
        until ($prompt -ceq 'YES')
    }
    catch {
        throw $_
    }
}
if ($PowerShellGetRestartRequired) {
    throw 'A new version of PowerShellGet was installed and PowerShell must be restarted.'
}

if (-not (Get-Module -ListAvailable -Name AzureADPreview)) { 
    
    Install-Module AzureADPreview -Scope CurrentUser -AllowClobber -Force # Install AzureADPreview

}
else {

    if (Get-Module AzureAD) { Remove-Module AzureAD -Force } # We only want the cmdlets from AzureADPreview
    if (-not (Get-Module AzureADPreview)) { Import-Module AzureADPreview }

}

$publicFunctions = Get-ChildItem -Path "$PSScriptRoot\Public\ps1"
$privateFunctions = Get-ChildItem -Path "$PSScriptRoot\Private\ps1"
$publicFunctions | ForEach-Object { . $_.FullName }
$privateFunctions | ForEach-Object { . $_.FullName }

$aliases = @()
$publicFunctions | ForEach-Object { # Export all of the public functions from this module
    
    # The command has already been sourced in above. Query any defined aliases.
    $alias = Get-Alias -Definition (Get-Command $_.BaseName) -ErrorAction SilentlyContinue 
    if ($alias) { # If alias string found (see example above)
        $aliases += $alias
        Export-ModuleMember -Function $_.BaseName -Alias $alias
    }
    else {
        Export-ModuleMember -Function $_.BaseName        
    }

}

$moduleName = $PSScriptRoot.Split([System.IO.Path]::DirectorySeparatorChar)[-1]
$moduleManifest = "$PSScriptRoot\$moduleName.psd1"
$currentManifest = powershell -NoProfile -Command "Test-ModuleManifest '$moduleManifest' | ConvertTo-Json" | ConvertFrom-Json # Unfortunate hack to test the module manifest for changes without having to reload PowerShell
$functionsAdded = $publicFunctions | Where-Object {$_.BaseName -notin $currentManifest.ExportedFunctions.PSObject.Properties.Name}
$functionsRemoved = $currentManifest.ExportedFunctions.PSObject.Properties.Name | Where-Object {$_ -notin $publicFunctions.BaseName}
$aliasesAdded = $aliases | Where-Object {$_ -notin $currentManifest.ExportedAliases.PSObject.Properties.Name}
$aliasesRemoved = $currentManifest.ExportedAliases.PSObject.Properties.Name | Where-Object {$_ -notin $aliases}
if ($functionsAdded -or $functionsRemoved -or $aliasesAdded -or $aliasesRemoved) { 
    try {

        if ($aliasesAdded) {
            Update-ModuleManifest -Path $moduleManifest -FunctionsToExport $publicFunctions.BaseName -AliasesToExport $aliases -ErrorAction Stop
        }
        else {
            Update-ModuleManifest -Path $moduleManifest -FunctionsToExport $publicFunctions.BaseName -AliasesToExport @() -ErrorAction Stop
        }
        
    }
    catch {
        # Empty to silence errors
    }
}

# Module data cache   
$moduleDataCachePath = "~/Documents/WindowsPowerShell/Cache/$moduleName"
Set-Variable `
-Name AzureADPIMModuleCache `
-Scope Script `
-Option Constant `
-Value $moduleDataCachePath `
-Description "Base path for storing cache files used by this module" `
-ErrorAction SilentlyContinue

if (-not (Test-Path $moduleDataCachePath)) { 
    New-Item `
    -ItemType Directory `
    -Path $moduleDataCachePath `
    -Force | 
    Out-Null
}
