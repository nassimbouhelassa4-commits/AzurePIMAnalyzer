#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources
<#
.SYNOPSIS
  Read-only Azure RBAC PIM eligibility and policy audit at selected scope levels.
.DESCRIPTION
  Each -Add* switch is independent. Only assignments made DIRECTLY at
  the selected scope levels are exported (not inherited copies).
  Azure RBAC PIM only: excludes Microsoft Entra directory roles/PIM for Groups.
.EXAMPLE
  .\Export-AzurePIM.ps1 -AddManagementGroup -AddSubscription
.EXAMPLE
  .\Export-AzurePIM.ps1 -AddResourceGroup -AddResource -SubscriptionIds 'guid' -OutputPath 'C:\PIM-Audit'
#>
[CmdletBinding()]
param(
    [switch]$AddManagementGroup,
    [switch]$AddSubscription,
    [switch]$AddResourceGroup,
    [switch]$AddResource,
    [string]$TenantId,
    [string[]]$SubscriptionIds,
    [string]$OutputPath = '.\AzurePIM-Audit'
)

$ErrorActionPreference = 'Stop'
$apiVersion = '2020-10-01'

if (-not ($AddManagementGroup -or $AddSubscription -or $AddResourceGroup -or $AddResource)) {
    throw 'Select at least one: -AddManagementGroup, -AddSubscription, -AddResourceGroup, -AddResource.'
}

function Invoke-PimGet {
    param([Parameter(Mandatory)][string]$Path)

    $uri = $Path
    $values = [System.Collections.Generic.List[object]]::new()
    do {
        if ($uri -match '^https://') {
            $response = Invoke-AzRestMethod -Method GET -Uri ([uri]$uri) -ErrorAction Stop
        }
        else {
            $response = Invoke-AzRestMethod -Method GET -Path $uri -ErrorAction Stop
        }

        if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300) {
            throw "ARM HTTP $($response.StatusCode): $($response.Content)"
        }
        $data = $response.Content | ConvertFrom-Json -Depth 100
        if ($null -eq $data.PSObject.Properties['value']) {
            return $data
        }
        foreach ($value in @($data.value)) {
            if ($null -ne $value) { $values.Add($value) }
        }
        $uri = [string]$data.nextLink
    } while (-not [string]::IsNullOrWhiteSpace($uri))

    return $values.ToArray()
}

function Get-PimRule {
    param([array]$Rules, [string]$Id)
    return $Rules | Where-Object { $_.id -eq $Id } | Select-Object -First 1
}

function Get-Flag {
    param($Rule, [string]$Name)
    if ($null -eq $Rule) { return $null }  # Unknown is not False
    return [bool](@($Rule.enabledRules) -contains $Name)
}

function Join-Values {
    param($Values)
    return (@($Values) | Where-Object {
        $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_)
    }) -join '; '
}

function To-CompactJson {
    param($Value)
    if ($null -eq $Value) { return '' }
    return ConvertTo-Json -InputObject $Value -Depth 100 -Compress
}

function To-Hours {
    param([string]$Duration)
    if ([string]::IsNullOrWhiteSpace($Duration)) { return $null }
    try {
        return [Math]::Round([System.Xml.XmlConvert]::ToTimeSpan($Duration).TotalHours, 2)
    }
    catch { return $null }
}

function Get-PimSettings {
    param([array]$Rules)

    $activation = Get-PimRule $Rules 'Enablement_EndUser_Assignment'
    $duration = Get-PimRule $Rules 'Expiration_EndUser_Assignment'
    $approval = Get-PimRule $Rules 'Approval_EndUser_Assignment'
    $authContext = Get-PimRule $Rules 'AuthenticationContext_EndUser_Assignment'
    $eligibleExpiration = Get-PimRule $Rules 'Expiration_Admin_Eligibility'
    $eligibleEnablement = Get-PimRule $Rules 'Enablement_Admin_Eligibility'
    $activeExpiration = Get-PimRule $Rules 'Expiration_Admin_Assignment'
    $activeEnablement = Get-PimRule $Rules 'Enablement_Admin_Assignment'

    $primary = @()
    $escalation = @()
    $stages = @()
    if ($null -ne $approval) {
        foreach ($stage in @($approval.setting.approvalStages)) {
            if ($null -eq $stage) { continue }
            $stages += $stage
            foreach ($person in @($stage.primaryApprovers)) {
                if ($null -ne $person) {
                    $primary += "$($person.userType):$($person.id):$($person.description)"
                }
            }
            foreach ($person in @($stage.escalationApprovers)) {
                if ($null -ne $person) {
                    $escalation += "$($person.userType):$($person.id):$($person.description)"
                }
            }
        }
    }

    $notifications = @($Rules | Where-Object {
        $_.ruleType -eq 'RoleManagementPolicyNotificationRule'
    })

    return [PSCustomObject]@{
        MaxActivationDuration = $duration.maximumDuration
        MaxActivationHours = To-Hours $duration.maximumDuration
        ActivationExpirationRequired = $duration.isExpirationRequired
        RequireMFA = Get-Flag $activation 'MultiFactorAuthentication'
        RequireJustification = Get-Flag $activation 'Justification'
        RequireTicket = Get-Flag $activation 'Ticketing'
        RequireApproval = $approval.setting.isApprovalRequired
        ApprovalMode = $approval.setting.approvalMode
        RequestorJustificationRequired = $approval.setting.isRequestorJustificationRequired
        ExtensionApprovalRequired = $approval.setting.isApprovalRequiredForExtension
        PrimaryApprovers = Join-Values $primary
        EscalationApprovers = Join-Values $escalation
        ApprovalStages = $stages
        AuthenticationContextEnabled = $authContext.isEnabled
        AuthenticationContextId = $authContext.claimValue
        EligibleExpirationRequired = $eligibleExpiration.isExpirationRequired
        MaxEligibleDuration = $eligibleExpiration.maximumDuration
        EligibleRequireMFA = Get-Flag $eligibleEnablement 'MultiFactorAuthentication'
        EligibleRequireJustification = Get-Flag $eligibleEnablement 'Justification'
        EligibleRequireTicket = Get-Flag $eligibleEnablement 'Ticketing'
        ActiveExpirationRequired = $activeExpiration.isExpirationRequired
        MaxActiveDuration = $activeExpiration.maximumDuration
        ActiveRequireMFA = Get-Flag $activeEnablement 'MultiFactorAuthentication'
        ActiveRequireJustification = Get-Flag $activeEnablement 'Justification'
        ActiveRequireTicket = Get-Flag $activeEnablement 'Ticketing'
        Notifications = $notifications
        AllRules = $Rules
    }
}

# ----- Authentication -----
$ctx = Get-AzContext -ErrorAction SilentlyContinue
if (-not $ctx -or ($TenantId -and [string]$ctx.Tenant.Id -ne $TenantId)) {
    if ($TenantId) { Connect-AzAccount -Tenant $TenantId | Out-Null }
    else { Connect-AzAccount | Out-Null }
    $ctx = Get-AzContext
}
if (-not $ctx) { throw 'No Azure authentication context found.' }
if (-not $TenantId) { $TenantId = [string]$ctx.Tenant.Id }

New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$scopes = [System.Collections.Generic.List[object]]::new()
$seenScopes = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
$errors = [System.Collections.Generic.List[object]]::new()

function Add-AuditScope {
    param(
        [string]$Id,
        [string]$Type,
        [string]$Name,
        [string]$SubscriptionId,
        [string]$SubscriptionName,
        [string]$ResourceType
    )
    $cleanId = $Id.TrimEnd('/')
    if ($seenScopes.Add($cleanId)) {
        $scopes.Add([PSCustomObject]@{
            ScopeId = $cleanId
            ScopeType = $Type
            ScopeName = $Name
            SubscriptionId = $SubscriptionId
            SubscriptionName = $SubscriptionName
            ResourceType = $ResourceType
        })
    }
}

function Add-AuditError {
    param([string]$Scope, [string]$Operation, [string]$Message)
    $errors.Add([PSCustomObject]@{
        Scope = $Scope
        Operation = $Operation
        Error = $Message
    })
    Write-Warning "[$Operation] $Scope : $Message"
}

# ----- Discover only the requested scope levels -----
if ($AddManagementGroup) {
    Write-Host 'Discovering Management Groups...' -ForegroundColor Cyan
    try {
        foreach ($mg in @(Get-AzManagementGroup -ErrorAction Stop)) {
            if ($mg.TenantId -and [string]$mg.TenantId -ne $TenantId) { continue }
            Add-AuditScope -Id "/providers/Microsoft.Management/managementGroups/$($mg.Name)" `
                -Type 'ManagementGroup' -Name $mg.DisplayName -SubscriptionId $null
        }
    }
    catch { Add-AuditError -Scope $TenantId -Operation 'DiscoverManagementGroups' -Message $_.Exception.Message }
}

$needSubscriptions = $AddSubscription -or $AddResourceGroup -or $AddResource
if ($needSubscriptions) {
    Write-Host 'Discovering subscriptions...' -ForegroundColor Cyan
    try {
        $subscriptions = @(Get-AzSubscription -TenantId $TenantId -ErrorAction Stop |
            Where-Object { $_.State -eq 'Enabled' -and (
                -not $SubscriptionIds -or $_.Id -in $SubscriptionIds
            ) })
    }
    catch {
        Add-AuditError -Scope $TenantId -Operation 'DiscoverSubscriptions' -Message $_.Exception.Message
        $subscriptions = @()
    }

    foreach ($sub in $subscriptions) {
        $subScope = "/subscriptions/$($sub.Id)"
        try {
            Set-AzContext -TenantId $TenantId -SubscriptionId $sub.Id -ErrorAction Stop | Out-Null
        }
        catch {
            Add-AuditError -Scope $subScope -Operation 'SetContext' -Message $_.Exception.Message
            continue
        }

        if ($AddSubscription) {
            Add-AuditScope -Id $subScope -Type 'Subscription' `
                -Name $sub.Name -SubscriptionId $sub.Id -SubscriptionName $sub.Name
        }

        if ($AddResourceGroup) {
            try {
                foreach ($rg in @(Get-AzResourceGroup -ErrorAction Stop)) {
                    $rgScope = "/subscriptions/$($sub.Id)/resourceGroups/$($rg.ResourceGroupName)"
                    Add-AuditScope -Id $rgScope -Type 'ResourceGroup' `
                        -Name $rg.ResourceGroupName -SubscriptionId $sub.Id -SubscriptionName $sub.Name
                }
            }
            catch {
                Add-AuditError -Scope $subScope -Operation 'DiscoverResourceGroups' -Message $_.Exception.Message
            }
        }

        if ($AddResource) {
            try {
                foreach ($resource in @(Get-AzResource -ErrorAction Stop)) {
                    if ([string]::IsNullOrWhiteSpace([string]$resource.ResourceId)) { continue }
                    $resId = [string]$resource.ResourceId
                    # Only actual resource IDs, not a subscription or RG ID.
                    if ($resId -notmatch '/providers/[^/]+/[^/]+/[^/]+' ) { continue }
                    Add-AuditScope -Id $resId -Type 'Resource' `
                        -Name $resource.Name -SubscriptionId $sub.Id -SubscriptionName $sub.Name `
                        -ResourceType $resource.ResourceType
                }
            }
            catch {
                Add-AuditError -Scope $subScope -Operation 'DiscoverResources' -Message $_.Exception.Message
            }
        }
    }
}

Write-Host "Scopes queued: $($scopes.Count)" -ForegroundColor Cyan

# ----- Read eligible assignments, policy assignment and policy -----
$records = [System.Collections.Generic.List[object]]::new()
$flat = [System.Collections.Generic.List[object]]::new()
$notificationRows = [System.Collections.Generic.List[object]]::new()
$seenInstances = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
$policyCache = @{}
$roleNames = @{}
$currentSubscriptionId = [string](Get-AzContext).Subscription.Id

foreach ($scope in $scopes) {
    $scopeId = $scope.ScopeId
    Write-Host "Scanning [$($scope.ScopeType)] $scopeId"

    if ($scope.SubscriptionId -and $currentSubscriptionId -ne $scope.SubscriptionId) {
        try {
            Set-AzContext -TenantId $TenantId -SubscriptionId $scope.SubscriptionId `
                -ErrorAction Stop | Out-Null
            $currentSubscriptionId = $scope.SubscriptionId
        }
        catch {
            Add-AuditError -Scope $scopeId -Operation 'SetContext' -Message $_.Exception.Message
            continue
        }
    }

    # atScope() includes assignments above the scope; equality check below excludes them.
    $uri = "$scopeId/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=$apiVersion" + '&$filter=atScope()'
    try { $instances = @(Invoke-PimGet -Path $uri) }
    catch {
        Add-AuditError -Scope $scopeId -Operation 'ListEligibleInstances' -Message $_.Exception.Message
        continue
    }

    $direct = @($instances | Where-Object {
        ([string]$_.properties.scope).TrimEnd('/') -ieq $scopeId
    })
    if ($direct.Count -eq 0) { continue }

    $policyAssignmentError = $null
    $policyAssignments = @()
    $uri = "$scopeId/providers/Microsoft.Authorization/roleManagementPolicyAssignments?api-version=$apiVersion"
    try { $policyAssignments = @(Invoke-PimGet -Path $uri) }
    catch {
        $policyAssignmentError = $_.Exception.Message
        Add-AuditError -Scope $scopeId -Operation 'ListPolicyAssignments' -Message $policyAssignmentError
    }

    foreach ($instance in $direct) {
        $p = $instance.properties
        $instanceKey = [string]$instance.id
        if (-not $instanceKey) {
            $instanceKey = "$scopeId|$($p.roleEligibilityScheduleId)|$($p.principalId)|$($p.roleDefinitionId)|$($p.startDateTime)"
        }
        if (-not $seenInstances.Add($instanceKey)) { continue }

        $roleId = [string]$p.roleDefinitionId
        $roleGuid = ($roleId -split '/')[-1]
        $matching = @($policyAssignments | Where-Object {
            ([string]$_.properties.scope).TrimEnd('/') -ieq $scopeId -and
            (([string]$_.properties.roleDefinitionId -split '/')[-1] -ieq $roleGuid)
        }) | Select-Object -First 1

        $policy = $null
        $policyId = $null
        $policyError = $policyAssignmentError
        if ($matching) {
            $policyId = [string]$matching.properties.policyId
            if ($policyId) {
                if (-not $policyCache.ContainsKey($policyId)) {
                    try {
                        $uri = "$policyId" + "?api-version=$apiVersion"
                        $policyCache[$policyId] = [PSCustomObject]@{
                            Policy = Invoke-PimGet -Path $uri
                            Error = $null
                        }
                    }
                    catch {
                        $policyCache[$policyId] = [PSCustomObject]@{
                            Policy = $null
                            Error = $_.Exception.Message
                        }
                    }
                }
                $policy = $policyCache[$policyId].Policy
                $policyError = $policyCache[$policyId].Error
            }
            else { $policyError = 'Policy assignment has no policyId.' }
        }
        elseif (-not $policyError) {
            $policyError = 'No policy assignment matched this role at the exact scope.'
        }
        if ($policyError) {
            Add-AuditError -Scope $scopeId -Operation 'GetPolicy' `
                -Message "Role $roleGuid, principal $($p.principalId): $policyError"
        }

        $settings = $null
        if ($policy) {
            $rules = @($policy.properties.rules)
            # Preserve the server policy as-is in JSON; summarize returned rules.
            $settings = Get-PimSettings -Rules $rules
        }

        $expanded = $p.expandedProperties
        $roleName = [string]$expanded.roleDefinition.displayName
        if (-not $roleName) {
            if (-not $roleNames.ContainsKey($roleId)) {
                try { $roleNames[$roleId] = (Get-AzRoleDefinition -Id $roleGuid -ErrorAction Stop).Name }
                catch { $roleNames[$roleId] = $roleGuid }
            }
            $roleName = $roleNames[$roleId]
        }
        $principalName = [string]$expanded.principal.displayName
        if (-not $principalName) { $principalName = [string]$p.principalId }
        $principalEmail = [string]$expanded.principal.email
        if (-not $principalEmail) { $principalEmail = [string]$expanded.principal.userPrincipalName }

        $records.Add([PSCustomObject]@{
            TenantId = $TenantId
            ScopeType = $scope.ScopeType
            ScopeName = $scope.ScopeName
            ScopeId = $scopeId
            SubscriptionId = $scope.SubscriptionId
            SubscriptionName = $scope.SubscriptionName
            ResourceType = $scope.ResourceType
            PrincipalId = $p.principalId
            PrincipalName = $principalName
            PrincipalEmail = $principalEmail
            PrincipalType = $p.principalType
            RoleName = $roleName
            RoleDefinitionId = $roleId
            EligibilityInstanceId = $instance.id
            EligibilityScheduleId = $p.roleEligibilityScheduleId
            Status = $p.status
            MemberType = $p.memberType
            StartDateTime = $p.startDateTime
            EndDateTime = $p.endDateTime
            Condition = $p.condition
            ConditionVersion = $p.conditionVersion
            PimPolicyId = $policyId
            PimPolicyAssignmentId = $matching.id
            PolicyError = $policyError
            PimSettings = $settings
            RawEligibility = $instance
            RawPolicyAssignment = $matching
            RawPolicy = $policy
        })

        $flat.Add([PSCustomObject]@{
            TenantId = $TenantId
            ScopeType = $scope.ScopeType
            ScopeName = $scope.ScopeName
            ScopeId = $scopeId
            SubscriptionId = $scope.SubscriptionId
            SubscriptionName = $scope.SubscriptionName
            ResourceType = $scope.ResourceType
            PrincipalName = $principalName
            PrincipalEmail = $principalEmail
            PrincipalId = $p.principalId
            PrincipalType = $p.principalType
            RoleName = $roleName
            RoleDefinitionId = $roleId
            EligibilityInstanceId = $instance.id
            EligibilityScheduleId = $p.roleEligibilityScheduleId
            EligibilityStatus = $p.status
            MemberType = $p.memberType
            EligibleStart = $p.startDateTime
            EligibleEnd = $p.endDateTime
            MaxActivationDuration = $settings.MaxActivationDuration
            MaxActivationHours = $settings.MaxActivationHours
            ActivationExpirationRequired = $settings.ActivationExpirationRequired
            RequireMFA = $settings.RequireMFA
            RequireJustification = $settings.RequireJustification
            RequireTicket = $settings.RequireTicket
            RequireApproval = $settings.RequireApproval
            ApprovalMode = $settings.ApprovalMode
            RequestorJustificationRequired = $settings.RequestorJustificationRequired
            ExtensionApprovalRequired = $settings.ExtensionApprovalRequired
            PrimaryApprovers = $settings.PrimaryApprovers
            EscalationApprovers = $settings.EscalationApprovers
            ApprovalStagesJson = To-CompactJson $settings.ApprovalStages
            AuthenticationContextEnabled = $settings.AuthenticationContextEnabled
            AuthenticationContextId = $settings.AuthenticationContextId
            EligibleExpirationRequired = $settings.EligibleExpirationRequired
            MaxEligibleDuration = $settings.MaxEligibleDuration
            EligibleRequireMFA = $settings.EligibleRequireMFA
            EligibleRequireJustification = $settings.EligibleRequireJustification
            EligibleRequireTicket = $settings.EligibleRequireTicket
            ActiveExpirationRequired = $settings.ActiveExpirationRequired
            MaxActiveDuration = $settings.MaxActiveDuration
            ActiveRequireMFA = $settings.ActiveRequireMFA
            ActiveRequireJustification = $settings.ActiveRequireJustification
            ActiveRequireTicket = $settings.ActiveRequireTicket
            NotificationsJson = To-CompactJson $settings.Notifications
            Condition = $p.condition
            ConditionVersion = $p.conditionVersion
            PimPolicyId = $policyId
            PimPolicyAssignmentId = $matching.id
            PolicyError = $policyError
        })

        if ($settings) {
            foreach ($notification in @($settings.Notifications)) {
                $notificationRows.Add([PSCustomObject]@{
                    ScopeType = $scope.ScopeType
                    ScopeName = $scope.ScopeName
                    ScopeId = $scopeId
                    RoleName = $roleName
                    RoleDefinitionId = $roleId
                    PrincipalId = $p.principalId
                    EligibilityInstanceId = $instance.id
                    PimPolicyId = $policyId
                    RuleId = $notification.id
                    NotificationType = $notification.notificationType
                    RecipientType = $notification.recipientType
                    NotificationLevel = $notification.notificationLevel
                    DefaultRecipientsEnabled = $notification.isDefaultRecipientsEnabled
                    CustomRecipients = Join-Values $notification.notificationRecipients
                    TargetCaller = $notification.target.caller
                    TargetLevel = $notification.target.level
                    TargetOperations = Join-Values $notification.target.operations
                })
            }
        }
    }
}

# ----- Export -----
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$assignmentFile = Join-Path $OutputPath "AzurePIM-EligibleAssignments-$stamp.csv"
$notificationFile = Join-Path $OutputPath "AzurePIM-NotificationRules-$stamp.csv"
$jsonFile = Join-Path $OutputPath "AzurePIM-FullDetails-$stamp.json"
$errorFile = Join-Path $OutputPath "AzurePIM-Errors-$stamp.csv"

if ($flat.Count) {
    $flat.ToArray() | Export-Csv -Path $assignmentFile -NoTypeInformation -Encoding utf8
}
if ($notificationRows.Count) {
    $notificationRows.ToArray() | Export-Csv -Path $notificationFile -NoTypeInformation -Encoding utf8
}
ConvertTo-Json -InputObject $records.ToArray() -Depth 100 |
    Set-Content -Path $jsonFile -Encoding utf8
if ($errors.Count) {
    $errors.ToArray() | Export-Csv -Path $errorFile -NoTypeInformation -Encoding utf8
}

Write-Host "`nAzure PIM audit complete." -ForegroundColor Green
Write-Host "Scopes selected: $($scopes.Count); eligible assignments: $($records.Count); errors: $($errors.Count)"
foreach ($kind in @('ManagementGroup','Subscription','ResourceGroup','Resource')) {
    $count = @($records | Where-Object { $_.ScopeType -eq $kind }).Count
    Write-Host "  ${kind}: $count"
}
if ($flat.Count) { Write-Host "Assignments: $assignmentFile" }
if ($notificationRows.Count) { Write-Host "Notifications: $notificationFile" }
Write-Host "Full JSON: $jsonFile"
if ($errors.Count) { Write-Host "Errors: $errorFile" -ForegroundColor Yellow }
