function Enable-PimRoles {

    [CmdletBinding()]
    Param (
        [Parameter(
            ValueFromPipeline = $true,
            Position = 0
        )]
        [Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedRoleAssignment[]]
        $PimRoleObject = (Get-PimRoles)
    )
    begin {
        $duration = 8
        $shorterDuration = 4 # Use this if first activation fails due to exceeding allowable timespan
    }
    process {     
        
        $session = Connect-AadOauth -WarningAction SilentlyContinue # Get an OAuth token for the user
        $scope = 'aadRoles' # Graph API scope
        $aadResource = Get-AzureADMSPrivilegedResource -ProviderId $scope # Get the Azure AD tenant info
        # $currentUserObjectId = $session.Account.HomeAccountId.Identifier.Split('.')[0] # MSAL. Commenting out for now. See JIra ticket ITSEA-635
        $currentUserObjectId = $session.Account.HomeAccountId.ObjectId # Extract the user's ObjectId from the string

        $PimRoleObject | ForEach-Object {

            $role = $_

            if ($role.AssignmentState -eq 'Active') {

                Write-Host "Role: $($role.RoleName) has already been activated." -ForegroundColor Yellow

            }
            else {

                try { # First activation attempt
                    $currentDateTime = Get-Date
                    $startDateTime = $currentDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    $endDateTime = $currentDateTime.AddHours($duration)
                    $endDateTime = $endDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

                    $schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
                    $schedule.Type = "Once"
                    $schedule.StartDateTime = $startDateTime
                    $schedule.EndDateTime = $endDateTime

                    Open-AzureADMSPrivilegedRoleAssignmentRequest `
                    -ProviderId $scope `
                    -Schedule $schedule `
                    -ResourceId $aadResource.Id `
                    -RoleDefinitionId $role.RoleDefinitionId `
                    -SubjectId $currentUserObjectId `
                    -AssignmentState "Active" `
                    -Type "UserAdd" `
                    -Reason $(whoami) | Out-Null

                    Write-Host "Successfully activated role: $($role.RoleName)" -ForegroundColor Green
                }
                catch {
                    
                    try { # Second activation attempt with shorter duration
                        $currentDateTime = Get-Date
                        $startDateTime = $currentDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        $endDateTime = $currentDateTime.AddHours($shorterDuration)
                        $endDateTime = $endDateTime.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

                        $schedule = New-Object Microsoft.Open.MSGraph.Model.AzureADMSPrivilegedSchedule
                        $schedule.Type = "Once"
                        $schedule.StartDateTime = $startDateTime
                        $schedule.EndDateTime = $endDateTime

                        Open-AzureADMSPrivilegedRoleAssignmentRequest `
                        -ProviderId $scope `
                        -Schedule $schedule `
                        -ResourceId $aadResource.Id `
                        -RoleDefinitionId $role.RoleDefinitionId `
                        -SubjectId $currentUserObjectId `
                        -AssignmentState "Active" `
                        -Type "UserAdd" `
                        -Reason $(whoami) | Out-Null

                        Write-Host "Successfully activated role: $($role.RoleName)" -ForegroundColor Green
                    }
                    catch {
                        Write-Error -Exception $_.Exception
                    }

                }
            
            }

        }

    }
    end { 
        Disconnect-AzureAD -ErrorAction SilentlyContinue | Out-Null # Prefer the user connects with regular auth rather than OAuth token used in this module
    }

}