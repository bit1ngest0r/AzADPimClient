function Disable-PimRoles {

    [CmdletBinding()]
    Param (

        [Parameter(
            ValueFromPipeline = $true,
            Position = 0
        )]
        [Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedRoleAssignment[]]
        $PimRoleObject = (Get-PimRoles)
    )
    process {     
        
        $session = Connect-AadOauth -WarningAction SilentlyContinue # Get an OAuth token for the user
        $scope = 'aadRoles' # Graph API scope
        $aadResource = Get-AzureADMSPrivilegedResource -ProviderId $scope # Get the Azure AD tenant info
        # $currentUserObjectId = $session.Account.HomeAccountId.Identifier.Split('.')[0] # MSAL. Commenting out for now. See JIra ticket ITSEA-635
        $currentUserObjectId = $session.Account.HomeAccountId.ObjectId # Extract the user's ObjectId from the string

        $PimRoleObject | ForEach-Object {

            $role = $_

            if ($role.AssignmentState -eq 'Eligible') {

                Write-Host "Role: $($role.RoleName) has already been deactivated." -ForegroundColor Yellow

            }
            else {

                $schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule # Null schedule object needed to fill mandatory parameter

                try {
                    Open-AzureADMSPrivilegedRoleAssignmentRequest `
                    -ProviderId $scope `
                    -Schedule $schedule `
                    -ResourceId $aadResource.Id `
                    -RoleDefinitionId $role.RoleDefinitionId `
                    -SubjectId $currentUserObjectId `
                    -AssignmentState "Active" `
                    -Type "UserRemove" `
                    -Reason $(whoami) | Out-Null

                    Write-Host "Successfully deactivated role: $($role.RoleName)" -ForegroundColor Green 
                }
                catch {
                    Write-Error -Exception $_.Exception
                }
            
            }

        }
        
    }
    end {
        Disconnect-AzureAD -ErrorAction SilentlyContinue | Out-Null # Prefer the user connects with regular auth rather than OAuth token used in this module
    }

}