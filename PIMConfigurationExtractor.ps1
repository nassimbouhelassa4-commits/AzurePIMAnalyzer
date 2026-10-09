
#Requires -Version 7.0
#Requires -Modules Az.Accounts, Az.Resources

<#
.SYNOPSIS
    Export Azure RBAC PIM eligible assignments and configuration.

.DESCRIPTION
    Inventories eligible assignments configured directly at:
      - Management Group level
      - Subscription level

    Retrieves associated PIM policies including activation,
    approval, MFA, justification, ticketing, expiration,
    Conditional Access authentication context and notifications.

    Excludes Resource Group and individual Resource scopes.

    Uses Az PowerShell and Azure Resource Manager REST APIs.

    IMPORTANT:
      - Runs against one Azure tenant per execution.
      - Requires sufficient PIM/RBAC read permissions.
      - This is a read-only audit script.

.EXAMPLE
    .\Export-AzurePIM.ps1

.EXAMPLE
    .\Export-AzurePIM.ps1 `
       -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
       -OutputPath "C:\PIM-Audit"

.EXAMPLE
    .\Export-AzurePIM.ps1 `
       -SubscriptionIds @("subscription-guid-1") `
       -OutputPath "C:\PIM-Audit"
#>

[CmdletBinding()]
param(
    [string]$TenantId,

    [string[]]$SubscriptionIds,

    [string]$OutputPath = ".\AzurePIM-Audit"
)

$ErrorActionPreference = "Stop"
$ApiVersion = "2020-10-01"

# ============================================================
# HELPERS
# ============================================================

function Invoke-PimGet {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    # Accept either a relative ARM path or nextLink URL.
    $uri = $Path
    $results = [System.Collections.Generic.List[object]]::new()
    $isCollection = $false

    do {
        # Invoke-AzRestMethod supports ARM-relative paths and URLs.
        $response = Invoke-AzRestMethod `
            -Method GET `
            -Path $uri `
            -ErrorAction Stop

        if ([int]$response.StatusCode -lt 200 -or
            [int]$response.StatusCode -ge 300) {
            throw "HTTP $($response.StatusCode): $($response.Content)"
        }

        $data = $response.Content | ConvertFrom-Json -Depth 100

        if ($null -ne $data.PSObject.Properties["value"]) {
            $isCollection = $true

            foreach ($item in @($data.value)) {
                if ($null -ne $item) {
                    $results.Add($item)
                }
            }

            $uri = $data.nextLink
        }
        else {
            return $data
        }

    } while (-not [string]::IsNullOrWhiteSpace($uri))

    if ($isCollection) {
        return $results.ToArray()
    }
}

function Get-PimRule {
    param(
        [array]$Rules,
        [string]$RuleId
    )

    return $Rules |
        Where-Object { $_.id -eq $RuleId } |
        Select-Object -First 1
}

function Join-Text {
    param($Items)

    return (@($Items) |
        Where-Object {
            $null -ne $_ -and
            -not [string]::IsNullOrWhiteSpace([string]$_)
        }) -join "; "
}

function Convert-ToJsonText {
    param($Value)

    if ($null -eq $Value) {
        return ""
    }

    return ConvertTo-Json `
        -InputObject $Value `
        -Depth 100 `
        -Compress
}

function Convert-DurationToHours {
    param([string]$Duration)

    if ([string]::IsNullOrWhiteSpace($Duration)) {
        return $null
    }

    try {
        $span = [System.Xml.XmlConvert]::ToTimeSpan($Duration)
        return [Math]::Round($span.TotalHours, 2)
    }
    catch {
        return $null
    }
}

function Get-RequiredFlag {
    param(
        $Rule,
        [string]$Flag
    )

    if ($null -eq $Rule) {
        return $null
    }

    return [bool](@($Rule.enabledRules) -contains $Flag)
}

function Get-PimScopeType {
    param([string]$Scope)

    if ($Scope -match '^/providers/Microsoft\.Management/managementGroups/[^/]+/?$') {
        return "ManagementGroup"
    }

    if ($Scope -match '^/subscriptions/[^/]+/?$') {
        return "Subscription"
    }

    return $null
}

function Get-ApproverInfo {
    param($ApprovalRule)

    $primary = @()
    $escalation = @()
    $stages = @()

    if ($null -eq $ApprovalRule) {
        return [PSCustomObject]@{
            Required = $null
            Primary = ""
            Escalation = ""
            Stages = @()
            ExtensionApprovalRequired = $null
            RenewalApprovalRequired = $null
            RequestorJustificationRequired = $null
        }
    }

    foreach ($stage in @($ApprovalRule.setting.approvalStages)) {

        if ($null -eq $stage) { continue }

        foreach ($person in @($stage.primaryApprovers)) {
            if ($null -eq $person) { continue }

            $primary += "$($person.userType):$($person.id):$($person.description)"
        }

        foreach ($person in @($stage.escalationApprovers)) {
            if ($null -eq $person) { continue }

            $escalation += "$($person.userType):$($person.id):$($person.description)"
        }

        $stages += $stage
    }

    return [PSCustomObject]@{
        Required = $ApprovalRule.setting.isApprovalRequired
        Primary = Join-Text $primary
        Escalation = Join-Text $escalation
        Stages = $stages
        ExtensionApprovalRequired =
            $ApprovalRule.setting.isApprovalRequiredForExtension
        RenewalApprovalRequired =
            $ApprovalRule.setting.isApprovalRequiredForRenewal
        RequestorJustificationRequired =
            $ApprovalRule.setting.isRequestorJustificationRequired
    }
}

function Get-PimPolicySummary {
    param([array]$Rules)

    $activationEnablement = Get-PimRule `
        $Rules "Enablement_EndUser_Assignment"

    $activationExpiration = Get-PimRule `
        $Rules "Expiration_EndUser_Assignment"

    $activationApproval = Get-PimRule `
        $Rules "Approval_EndUser_Assignment"

    $activationAuth = Get-PimRule `
        $Rules "AuthenticationContext_EndUser_Assignment"

    $eligibleExpiration = Get-PimRule `
        $Rules "Expiration_Admin_Eligibility"

    $activeExpiration = Get-PimRule `
        $Rules "Expiration_Admin_Assignment"

    $activeEnablement = Get-PimRule `
        $Rules "Enablement_Admin_Assignment"

    $eligibleEnablement = Get-PimRule `
        $Rules "Enablement_Admin_Eligibility"

    $approvers = Get-ApproverInfo $activationApproval

    $notificationRules = @(
        $Rules | Where-Object {
            $_.ruleType -eq "RoleManagementPolicyNotificationRule"
        }
    )

    return [PSCustomObject]@{

        # Activation settings
        MaxActivationDuration =
            $activationExpiration.maximumDuration

        MaxActivationHours =
            Convert-DurationToHours $activationExpiration.maximumDuration

        ActivationExpirationRequired =
            $activationExpiration.isExpirationRequired

        RequireMFA =
            Get-RequiredFlag $activationEnablement "MultiFactorAuthentication"

        RequireJustification =
            Get-RequiredFlag $activationEnablement "Justification"

        RequireTicket =
            Get-RequiredFlag $activationEnablement "Ticketing"

        # Approval
        RequireApproval = $approvers.Required
        PrimaryApprovers = $approvers.Primary
        EscalationApprovers = $approvers.Escalation
        ApprovalStages = $approvers.Stages

        ExtensionApprovalRequired =
            $approvers.ExtensionApprovalRequired

        RenewalApprovalRequired =
            $approvers.RenewalApprovalRequired

        RequestorJustificationRequired =
            $approvers.RequestorJustificationRequired

        # Authentication context
        AuthenticationContextEnabled =
            $activationAuth.isEnabled

        AuthenticationContextId =
            $activationAuth.claimValue

        # Eligible assignment configuration
        EligibleExpirationRequired =
            $eligibleExpiration.isExpirationRequired

        MaxEligibleDuration =
            $eligibleExpiration.maximumDuration

        EligibleRequireMFA =
            Get-RequiredFlag $eligibleEnablement "MultiFactorAuthentication"

        EligibleRequireJustification =
            Get-RequiredFlag $eligibleEnablement "Justification"

        EligibleRequireTicket =
            Get-RequiredFlag $eligibleEnablement "Ticketing"

        # Active assignment configuration
        ActiveExpirationRequired =
            $activeExpiration.isExpirationRequired

        MaxActiveDuration =
            $activeExpiration.maximumDuration

        ActiveRequireMFA =
            Get-RequiredFlag $activeEnablement "MultiFactorAuthentication"

        ActiveRequireJustification =
            Get-RequiredFlag $activeEnablement "Justification"

        ActiveRequireTicket =
            Get-RequiredFlag $activeEnablement "Ticketing"

        # Notifications
        Notifications = $notificationRules

        # Preserve every policy rule including future rule types
        AllRules = $Rules
    }
}

# ============================================================
# AUTHENTICATION AND TENANT SELECTION
# ============================================================

Write-Host "Starting Azure PIM audit..." -ForegroundColor Cyan

$context = Get-AzContext -ErrorAction SilentlyContinue

if (-not $context) {
    if ($TenantId) {
        Connect-AzAccount -Tenant $TenantId | Out-Null
    }
    else {
        Connect-AzAccount | Out-Null
    }
}

$context = Get-AzContext

if (-not $TenantId) {
    $TenantId = [string]$context.Tenant.Id
}

if ([string]$context.Tenant.Id -ne $TenantId) {
    Connect-AzAccount -Tenant $TenantId | Out-Null
}

New-Item -ItemType Directory -Path $OutputPath -Force |
    Out-Null

# ============================================================
# DISCOVER SUBSCRIPTIONS
# ============================================================

Write-Host "Discovering subscriptions..." -ForegroundColor Cyan

$subscriptions = @(
    Get-AzSubscription -TenantId $TenantId |
        Where-Object {
            $_.State -eq "Enabled" -and
            (
                -not $SubscriptionIds -or
                $_.Id -in $SubscriptionIds
            )
        }
)

if ($SubscriptionIds) {
    foreach ($requestedId in $SubscriptionIds) {
        if ($requestedId -notin $subscriptions.Id) {
            Write-Warning "Subscription unavailable or not enabled: $requestedId"
        }
    }
}

Write-Host "Subscriptions discovered: $($subscriptions.Count)"

# ============================================================
# DISCOVER MANAGEMENT GROUPS
# ============================================================

Write-Host "Discovering Management Groups..." -ForegroundColor Cyan

# Establish an ARM context in the requested tenant.
if ($subscriptions.Count -gt 0) {
    Set-AzContext `
        -TenantId $TenantId `
        -SubscriptionId $subscriptions[0].Id | Out-Null
}

try {
    $managementGroups = @(
        Get-AzManagementGroup |
            Where-Object {
                -not $_.TenantId -or
                [string]$_.TenantId -eq $TenantId
            }
    )
}
catch {
    Write-Warning "Management Group discovery failed: $_"
    $managementGroups = @()
}

Write-Host "Management Groups discovered: $($managementGroups.Count)"

# ============================================================
# BUILD TARGET SCOPES
# ============================================================

$scopes = [System.Collections.Generic.List[object]]::new()

foreach ($mg in $managementGroups) {
    $scopes.Add([PSCustomObject]@{
        TenantId = $TenantId
        ScopeType = "ManagementGroup"
        ScopeName = $mg.DisplayName
        ScopeId = "/providers/Microsoft.Management/managementGroups/$($mg.Name)"
        SubscriptionId = $null
    })
}

foreach ($sub in $subscriptions) {
    $scopes.Add([PSCustomObject]@{
        TenantId = $TenantId
        ScopeType = "Subscription"
        ScopeName = $sub.Name
        ScopeId = "/subscriptions/$($sub.Id)"
        SubscriptionId = $sub.Id
    })
}

# ============================================================
# DATA COLLECTION
# ============================================================

$fullResults = [System.Collections.Generic.List[object]]::new()
$csvRows = [System.Collections.Generic.List[object]]::new()
$notificationRows = [System.Collections.Generic.List[object]]::new()
$errorRows = [System.Collections.Generic.List[object]]::new()

$seenAssignments = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

$policyCache = @{}

foreach ($scope in $scopes) {

    Write-Host ""
    Write-Host "=========================================="
    Write-Host "Scope: $($scope.ScopeName)" -ForegroundColor Yellow
    Write-Host "Type:  $($scope.ScopeType)"
    Write-Host "ID:    $($scope.ScopeId)"
    Write-Host "=========================================="

    # Select subscription context for its scope.
    if ($scope.SubscriptionId) {
        try {
            Set-AzContext `
                -TenantId $TenantId `
                -SubscriptionId $scope.SubscriptionId | Out-Null
        }
        catch {
            Write-Warning "Context failure: $_"

            $errorRows.Add([PSCustomObject]@{
                Scope = $scope.ScopeId
                Operation = "SetContext"
                Error = "$_"
            })

            continue
        }
    }

    $baseScope = $scope.ScopeId.TrimEnd("/")

    # --------------------------------------------------------
    # STEP 1 - Retrieve eligible role assignments
    # --------------------------------------------------------

    $eligibilityUrl = (
        "$baseScope/providers/Microsoft.Authorization/" +
        "roleEligibilityScheduleInstances?api-version=$ApiVersion"
    )

    try {
        $eligible = @(
            Invoke-PimGet -Path $eligibilityUrl
        )
    }
    catch {
        Write-Warning "Eligibility discovery failed: $_"

        $errorRows.Add([PSCustomObject]@{
            Scope = $baseScope
            Operation = "ListEligibility"
            Error = "$_"
        })

        continue
    }

    # Keep ONLY assignments originating at this exact scope.
    # Prevent duplicates caused by inherited visibility.
    $eligible = @(
        $eligible | Where-Object {
            $assignmentScope = [string]$_.properties.scope

            $assignmentScope.TrimEnd("/") -ieq $baseScope
        }
    )

    Write-Host "Direct eligible assignments: $($eligible.Count)"

    if ($eligible.Count -eq 0) {
        continue
    }

    # --------------------------------------------------------
    # STEP 2 - Retrieve policy assignments for this scope
    # --------------------------------------------------------

    $policyAssignmentUrl = (
        "$baseScope/providers/Microsoft.Authorization/" +
        "roleManagementPolicyAssignments?api-version=$ApiVersion"
    )

    $policyAssignments = @()
    $policyListError = $null

    try {
        $policyAssignments = @(
            Invoke-PimGet -Path $policyAssignmentUrl
        )
    }
    catch {
        $policyListError = "$_"
        Write-Warning "Policy assignment discovery failed: $_"

        $errorRows.Add([PSCustomObject]@{
            Scope = $baseScope
            Operation = "ListPolicyAssignments"
            Error = $policyListError
        })
    }

    # --------------------------------------------------------
    # STEP 3 - Process every eligible assignment
    # --------------------------------------------------------

    foreach ($assignment in $eligible) {

        $p = $assignment.properties
        $expanded = $p.expandedProperties

        $uniqueKey = [string]$assignment.id

        if ([string]::IsNullOrWhiteSpace($uniqueKey)) {
            $uniqueKey = (
                "$baseScope|$($p.roleEligibilityScheduleId)|" +
                "$($p.principalId)|$($p.roleDefinitionId)|" +
                "$($p.startDateTime)|$($p.endDateTime)"
            )
        }

        if (-not $seenAssignments.Add($uniqueKey)) {
            continue
        }

        $roleDefinitionId = [string]$p.roleDefinitionId
        $roleGuid = ($roleDefinitionId -split "/")[-1]

        $roleName = $expanded.roleDefinition.displayName

        if (-not $roleName) {
            # Fallback for unexpanded ARM responses
            try {
                $definition = Get-AzRoleDefinition `
                    -Id $roleGuid `
                    -ErrorAction Stop

                $roleName = $definition.Name
            }
            catch {
                $roleName = $roleGuid
            }
        }

        $principalName = $expanded.principal.displayName
        if (-not $principalName) {
            $principalName = $p.principalId
        }

        Write-Host "  Processing: $roleName / $principalName"

        # ----------------------------------------------------
        # Match the role management policy assignment
        # ----------------------------------------------------

        $matchingPolicyAssignment = @(
            $policyAssignments | Where-Object {

                $candidateScope = (
                    [string]$_.properties.scope
                ).TrimEnd("/")

                $candidateRole = (
                    [string]$_.properties.roleDefinitionId -split "/"
                )[-1]

                $candidateScope -ieq $baseScope -and
                $candidateRole -ieq $roleGuid
            }
        ) | Select-Object -First 1

        $policy = $null
        $summary = $null
        $policyError = $policyListError
        $policyId = $null

        if ($matchingPolicyAssignment) {

            $policyId = [string]$matchingPolicyAssignment.properties.policyId

            if ($policyId) {

                $cacheKey = $policyId.ToLowerInvariant()

                if (-not $policyCache.ContainsKey($cacheKey)) {

                    try {
                        $policyUrl = "$policyId" +
                            "?api-version=$ApiVersion"

                        $policyCache[$cacheKey] = [PSCustomObject]@{
                            Policy = Invoke-PimGet -Path $policyUrl
                            Error = $null
                        }
                    }
                    catch {
                        $policyCache[$cacheKey] = [PSCustomObject]@{
                            Policy = $null
                            Error = "$_"
                        }
                    }
                }

                $policy = $policyCache[$cacheKey].Policy
                $policyError = $policyCache[$cacheKey].Error
            }
            else {
                $policyError = "Policy assignment has no policyId"
            }
        }
        elseif (-not $policyError) {
            $policyError = "No matching policy assignment at exact scope"
        }

        if ($null -ne $policy) {

            # Prefer effectiveRules if supplied; otherwise rules.
            $rules = @($policy.properties.rules)

            if ($null -ne $policy.properties.effectiveRules -and
                @($policy.properties.effectiveRules).Count -gt 0) {
                $rules = @($policy.properties.effectiveRules)
            }

            $summary = Get-PimPolicySummary -Rules $rules
        }

        if ($policyError) {
            $errorRows.Add([PSCustomObject]@{
                Scope = $baseScope
                Operation = "GetPolicy"
                Error = "$roleGuid / $($p.principalId): $policyError"
            })
        }

        # ----------------------------------------------------
        # Complete record for JSON
        # ----------------------------------------------------

        $record = [PSCustomObject]@{
            TenantId = $TenantId
            ScopeType = $scope.ScopeType
            ScopeName = $scope.ScopeName
            ScopeId = $baseScope

            PrincipalId = $p.principalId
            PrincipalName = $principalName
            PrincipalEmail = $expanded.principal.email
            PrincipalType = $p.principalType

            RoleName = $roleName
            RoleDefinitionId = $roleDefinitionId

            EligibilityInstanceId = $assignment.id
            EligibilityScheduleId = $p.roleEligibilityScheduleId
            Status = $p.status
            MemberType = $p.memberType
            StartDateTime = $p.startDateTime
            EndDateTime = $p.endDateTime
            CreatedOn = $p.createdOn

            Condition = $p.condition
            ConditionVersion = $p.conditionVersion

            PimPolicyId = $policyId
            PimPolicyAssignmentId = $matchingPolicyAssignment.id
            PolicyError = $policyError

            PimSettings = $summary

            RawEligibility = $assignment
            RawPolicyAssignment = $matchingPolicyAssignment
            RawPolicy = $policy
        }

        $fullResults.Add($record)

        # ----------------------------------------------------
        # Flat CSV record
        # ----------------------------------------------------

        $csvRows.Add([PSCustomObject]@{
            TenantId = $TenantId
            ScopeType = $scope.ScopeType
            ScopeName = $scope.ScopeName
            ScopeId = $baseScope

            PrincipalName = $principalName
            PrincipalEmail = $expanded.principal.email
            PrincipalId = $p.principalId
            PrincipalType = $p.principalType

            RoleName = $roleName
            RoleDefinitionId = $roleDefinitionId

            EligibilityInstanceId = $assignment.id
            EligibilityScheduleId = $p.roleEligibilityScheduleId

            EligibilityStatus = $p.status
            MemberType = $p.memberType
            EligibleStart = $p.startDateTime
            EligibleEnd = $p.endDateTime
            CreatedOn = $p.createdOn

            MaxActivationDuration = $summary.MaxActivationDuration
            MaxActivationHours = $summary.MaxActivationHours
            ActivationExpirationRequired = $summary.ActivationExpirationRequired

            RequireMFA = $summary.RequireMFA
            RequireJustification = $summary.RequireJustification
            RequireTicket = $summary.RequireTicket

            RequireApproval = $summary.RequireApproval
            PrimaryApprovers = $summary.PrimaryApprovers
            EscalationApprovers = $summary.EscalationApprovers

            ExtensionApprovalRequired = $summary.ExtensionApprovalRequired
            RenewalApprovalRequired = $summary.RenewalApprovalRequired
            RequestorJustificationRequired =
                $summary.RequestorJustificationRequired

            ApprovalStagesJson =
                Convert-ToJsonText $summary.ApprovalStages

            AuthenticationContextEnabled =
                $summary.AuthenticationContextEnabled
            AuthenticationContextId =
                $summary.AuthenticationContextId

            EligibleExpirationRequired =
                $summary.EligibleExpirationRequired
            MaxEligibleDuration =
                $summary.MaxEligibleDuration
            EligibleRequireMFA =
                $summary.EligibleRequireMFA
            EligibleRequireJustification =
                $summary.EligibleRequireJustification
            EligibleRequireTicket =
                $summary.EligibleRequireTicket

            ActiveExpirationRequired =
                $summary.ActiveExpirationRequired
            MaxActiveDuration =
                $summary.MaxActiveDuration
            ActiveRequireMFA =
                $summary.ActiveRequireMFA
            ActiveRequireJustification =
                $summary.ActiveRequireJustification
            ActiveRequireTicket =
                $summary.ActiveRequireTicket

            NotificationsJson =
                Convert-ToJsonText $summary.Notifications

            Condition = $p.condition
            ConditionVersion = $p.conditionVersion

            PimPolicyId = $policyId
            PimPolicyAssignmentId = $matchingPolicyAssignment.id
            PolicyError = $policyError
        })

        # ----------------------------------------------------
        # Detailed notification export
        # ----------------------------------------------------

        if ($null -ne $summary) {

            foreach ($notification in @($summary.Notifications)) {

                $notificationRows.Add([PSCustomObject]@{
                    ScopeType = $scope.ScopeType
                    ScopeName = $scope.ScopeName
                    ScopeId = $baseScope
                    PrincipalId = $p.principalId
                    RoleName = $roleName
                    RoleDefinitionId = $roleDefinitionId
                    EligibilityInstanceId = $assignment.id
                    PimPolicyId = $policyId

                    RuleId = $notification.id
                    NotificationType = $notification.notificationType
                    RecipientType = $notification.recipientType
                    NotificationLevel = $notification.notificationLevel
                    DefaultRecipientsEnabled =
                        $notification.isDefaultRecipientsEnabled

                    CustomRecipients =
                        Join-Text $notification.notificationRecipients

                    TargetCaller = $notification.target.caller
                    TargetLevel = $notification.target.level
                    TargetOperations =
                        Join-Text $notification.target.operations
                })
            }
        }
    }
}

# ============================================================
# EXPORT RESULTS
# ============================================================

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$csvFile = Join-Path $OutputPath `
    "AzurePIM-EligibleAssignments-$timestamp.csv"

$notificationFile = Join-Path $OutputPath `
    "AzurePIM-NotificationRules-$timestamp.csv"

$jsonFile = Join-Path $OutputPath `
    "AzurePIM-FullDetails-$timestamp.json"

$errorFile = Join-Path $OutputPath `
    "AzurePIM-Errors-$timestamp.csv"

if ($csvRows.Count -gt 0) {
    $csvRows.ToArray() |
        Export-Csv -Path $csvFile `
            -NoTypeInformation -Encoding utf8
}

if ($notificationRows.Count -gt 0) {
    $notificationRows.ToArray() |
        Export-Csv -Path $notificationFile `
            -NoTypeInformation -Encoding utf8
}

# Important: serialize the array itself, even for one record.
ConvertTo-Json -InputObject $fullResults.ToArray() -Depth 100 |
    Set-Content -Path $jsonFile -Encoding utf8

if ($errorRows.Count -gt 0) {
    $errorRows.ToArray() |
        Export-Csv -Path $errorFile `
            -NoTypeInformation -Encoding utf8
}

# ============================================================
# COMPLETION SUMMARY
# ============================================================

$mgCount = @(
    $fullResults | Where-Object {
        $_.ScopeType -eq "ManagementGroup"
    }
).Count

$subCount = @(
    $fullResults | Where-Object {
        $_.ScopeType -eq "Subscription"
    }
).Count

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "Azure PIM audit completed"
Write-Host "==================================================" -ForegroundColor Green

Write-Host "Management Groups scanned : $($managementGroups.Count)"
Write-Host "Subscriptions scanned     : $($subscriptions.Count)"
Write-Host ""
Write-Host "MG eligible assignments   : $mgCount"
Write-Host "Sub eligible assignments  : $subCount"
Write-Host "Total eligible assignments: $($fullResults.Count)"
Write-Host "Errors recorded           : $($errorRows.Count)"
Write-Host ""
Write-Host "Assignments CSV : $csvFile"
Write-Host "Notifications   : $notificationFile"
Write-Host "Full JSON       : $jsonFile"

if ($errorRows.Count -gt 0) {
    Write-Host "Errors          : $errorFile" -ForegroundColor Yellow
}

Write-Host "==================================================" -ForegroundColor Green
