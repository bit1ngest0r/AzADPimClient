function Get-PimRoles {

    [CmdletBinding()]
    Param ()
    begin {

        $session = Connect-AadOauth -WarningAction SilentlyContinue # Get an OAuth token for the user

    }
    process {

        try {
            $scope = 'aadRoles' # Graph API scope
            $aadResource = Get-AzureADMSPrivilegedResource -ProviderId $scope # Get the Azure AD tenant info
            $allRoles = Get-AzureADMSPrivilegedRoleDefinition -ProviderId $scope -ResourceId $aadResource.Id # Get all PIM roles from the tenant
            # $currentUserObjectId = $session.Account.HomeAccountId.Identifier.Split('.')[0] # MSAL. Commenting out for now. See Jira ticket ITSEA-635
            $currentUserObjectId = $session.Account.HomeAccountId.ObjectId # Extract the user's ObjectId from the string
            # Get any PIM role assigned to the user
            $currentUserPimRoles = Get-AzureADMSPrivilegedRoleAssignment `
                -ProviderId $scope `
                -ResourceId $aadResource.Id `
                -Filter "subjectId eq '$currentUserObjectId'" 
            if ($currentUserPimRoles) {

                $currentUserPimRoles | ForEach-Object { 
                    
                    # Add a friendly name for the role, as it's not part of the object properties when calling role assignments
                    $role = $_ 
                    $roleDefinition = $allRoles | Where-Object { $_.Id -eq $role.RoleDefinitionId }
                    $role | Add-Member -MemberType NoteProperty -Name RoleName -Value $roleDefinition.DisplayName
                    if ($role.StartDateTime) { $role.StartDateTime = $role.StartDateTime.ToLocalTime() }
                    if ($role.EndDateTime) { $role.EndDateTime = $role.EndDateTime.ToLocalTime() }

                }

                # $currentUserPimRoles = $currentUserPimRoles | Sort-Object RoleDefinitionId -Unique
                $activeRoles = $currentUserPimRoles | Where-Object {$_.AssignmentState -eq 'Active'} # First get an array of active roles and prefer theese
                $inactiveRoles = $currentUserPimRoles | Where-Object {$_.RoleName -notin $activeRoles.RoleName}
                return @($activeRoles) + @($inactiveRoles)

            }
            else {

                throw "You have not been assigned any PIM roles."

            }

        }
        catch {
            
            throw $_
            
        }

    }
    end {

        Disconnect-AzureAD -ErrorAction SilentlyContinue | Out-Null # Prefer the user connects with regular auth rather than OAuth token used in this module

    }

}