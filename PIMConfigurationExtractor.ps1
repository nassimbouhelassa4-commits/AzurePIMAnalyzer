#requires -Version 7.2
#requires -Modules Az.Accounts, Az.Resources
<#
.SYNOPSIS
Exports Azure resource PIM eligibility and complete role policy configuration.
.DESCRIPTION
Read-only. Uses the signed-in tenant and an explicit Az context on every request.
The four scope switches are independent. Assignments inherited from other scopes
are excluded. SubscriptionIds limits subscription/RG/resource discovery only;
management groups are discovered separately in the current tenant.
ForEach-Object -Parallel uses in-process runspaces, not separate login processes.
Policies are cached per scope/role; all JSON rules and approval stages are retained.
Resource discovery uses ARM's subscription resource inventory. Child resources
not present in that inventory require explicit resource IDs via AdditionalResourceIds.
.EXAMPLE
Connect-AzAccount -Tenant '<tenant-id>'
./Export-AzurePIM-Parallel.ps1 -AddManagementGroup -AddSubscription -ThrottleLimit 8
.EXAMPLE
./Export-AzurePIM-Parallel.ps1 -AddResourceGroup -AddResource -SubscriptionIds '<id>'
#>
[CmdletBinding()]
param(
    [switch]$AddManagementGroup,
    [switch]$AddSubscription,
    [switch]$AddResourceGroup,
    [switch]$AddResource,
    [string[]]$SubscriptionIds,
    [string[]]$AdditionalResourceIds,
    [ValidateRange(1, 32)][int]$ThrottleLimit = 8,
    [ValidateRange(0, 10)][int]$MaxRetries = 5,
    [string]$OutputDirectory = (Join-Path (Get-Location) 'AzurePIMReport')
)

$ErrorActionPreference = 'Stop'
if (-not ($AddManagementGroup -or $AddSubscription -or $AddResourceGroup -or $AddResource)) {
    throw 'Select at least one scope switch: -AddManagementGroup, -AddSubscription, -AddResourceGroup, or -AddResource.'
}
if ($AdditionalResourceIds -and -not $AddResource) {
    throw 'AdditionalResourceIds requires -AddResource.'
}
Import-Module Az.Accounts, Az.Resources -ErrorAction Stop
$pimContext = Get-AzContext -ErrorAction Stop
if (-not $pimContext -or -not $pimContext.Account -or -not $pimContext.Tenant.Id) {
    throw 'Run Connect-AzAccount -Tenant <tenant-id> before running this script.'
}
$retryCount = $MaxRetries
$tenantId = [string]$pimContext.Tenant.Id
$started = [DateTimeOffset]::UtcNow

# Functions are passed as TEXT and created inside each worker's own runspace.
# The context is shared read-only. No worker calls Set-AzContext or Connect-AzAccount.
$workerFunctions = @'
function Get-PimHeader {
    param($Headers, [string]$Name)
    if ($null -eq $Headers) { return $null }
    if ($Headers -is [System.Collections.IDictionary]) {
        return (@($Headers[$Name]) -join ',')
    }
    foreach ($header in $Headers) {
        if ($header.Key -ieq $Name) { return (@($header.Value) -join ',') }
    }
    return $null
}

function Invoke-PimGet {
    param([Parameter(Mandatory)][string]$Path)
    for ($attempt = 0; $attempt -le $retryCount; $attempt++) {
        $response = $null
        $httpResponse = $null
        $status = 0
        try {
            $requestParameters = @{ Method = 'GET'; DefaultProfile = $pimContext; ErrorAction = 'Stop' }
            if ($Path -match '^https://') { $requestParameters.Uri = $Path }
            else { $requestParameters.Path = $Path }
            $response = Invoke-AzRestMethod @requestParameters
            $status = [int]$response.StatusCode
            if ($status -ge 200 -and $status -lt 300) {
                if ([string]::IsNullOrWhiteSpace($response.Content)) { return $null }
                return ($response.Content | ConvertFrom-Json -Depth 100)
            }
            throw "HTTP $status while reading $Path : $($response.Content)"
        }
        catch {
            $failure = $_
            if ($null -ne $_.Exception.Response) {
                $httpResponse = $_.Exception.Response
                if ($null -ne $httpResponse.StatusCode) { $status = [int]$httpResponse.StatusCode }
            }
            if ($status -notin @(408, 429, 500, 502, 503, 504) -or $attempt -ge $retryCount) {
                throw $failure
            }
            $headers = if ($null -ne $response) { $response.Headers } else { $httpResponse.Headers }
            $retryAfter = Get-PimHeader $headers 'Retry-After'
            $seconds = 0.0
            $retryDate = [DateTimeOffset]::MinValue
            if ([double]::TryParse($retryAfter, [ref]$seconds)) {
                $seconds = [Math]::Max(0, $seconds)
            }
            elseif ([DateTimeOffset]::TryParse($retryAfter, [ref]$retryDate)) {
                $seconds = [Math]::Max(0, ($retryDate - [DateTimeOffset]::UtcNow).TotalSeconds)
            }
            else { $seconds = [Math]::Min(60, [Math]::Pow(2, $attempt + 1)) }
            $milliseconds = [int][Math]::Ceiling(1000 * $seconds) + (Get-Random -Minimum 50 -Maximum 500)
            Write-Verbose "HTTP $status; retry $($attempt + 1)/$retryCount after $milliseconds ms: $Path"
            Start-Sleep -Milliseconds $milliseconds
        }
    }
}

function Get-PimList {
    param([Parameter(Mandatory)][string]$Path)
    # Buffer all pages; a later-page failure must never look like a complete list.
    $items = [System.Collections.Generic.List[object]]::new()
    $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    do {
        if (-not $visited.Add($Path)) { throw "Repeated pagination link: $Path" }
        $page = Invoke-PimGet $Path
        if ($null -eq $page -or $null -eq $page.PSObject.Properties['value']) {
            throw "Expected an ARM list response at $Path"
        }
        foreach ($item in @($page.value)) { if ($null -ne $item) { $items.Add($item) } }
        $Path = [string]$page.nextLink
    } while ($Path)
    return $items.ToArray()
}

function New-PimError {
    param([string]$Scope, [string]$Operation, [string]$Message)
    [pscustomobject]@{ Scope = $Scope; Operation = $Operation; Message = $Message }
}

function Get-PimRule {
    param([object[]]$Rules, [string]$Id)
    return ($Rules | Where-Object { $_.id -ieq $Id } | Select-Object -First 1)
}

function Test-PimEnabled {
    param($Rule, [string]$Name)
    if ($null -eq $Rule) { return $null }
    return (@($Rule.enabledRules) -contains $Name)
}

function ConvertTo-PimJson {
    param($Value)
    ConvertTo-Json -InputObject $Value -Depth 100 -Compress
}
'@
. ([scriptblock]::Create($workerFunctions))

$scopes = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()
$discoveryTasks = [System.Collections.Generic.List[object]]::new()

if ($AddManagementGroup) {
    try {
        foreach ($mg in @(Get-AzManagementGroup -DefaultProfile $pimContext -ErrorAction Stop)) {
            $scopeId = if ($mg.Id) { [string]$mg.Id } else { "/providers/Microsoft.Management/managementGroups/$($mg.Name)" }
            $scopes.Add([pscustomobject]@{ Scope = $scopeId.TrimEnd('/'); ScopeType = 'ManagementGroup'; ScopeName = $mg.DisplayName })
        }
    }
    catch { $errors.Add((New-PimError '/providers/Microsoft.Management/managementGroups' 'DiscoverManagementGroups' $_.Exception.Message)) }
}

if ($AddSubscription -or $AddResourceGroup -or $AddResource) {
    # Keep this run in one tenant. Each request carries the same tenant's profile;
    # absolute ARM paths specify the target subscription without changing context.
    $subscriptions = @(Get-AzSubscription -TenantId $tenantId -DefaultProfile $pimContext -ErrorAction Stop |
        Where-Object { $_.State -eq 'Enabled' })
    if ($SubscriptionIds) {
        foreach ($requested in $SubscriptionIds) {
            if ($requested -notin $subscriptions.Id) { throw "Subscription $requested is not accessible and enabled in tenant $tenantId." }
        }
        $subscriptions = @($subscriptions | Where-Object { $_.Id -in $SubscriptionIds })
    }
    foreach ($sub in $subscriptions) {
        $subScope = "/subscriptions/$($sub.Id)"
        if ($AddSubscription) {
            $scopes.Add([pscustomobject]@{ Scope = $subScope; ScopeType = 'Subscription'; ScopeName = $sub.Name })
        }
        if ($AddResourceGroup) {
            $discoveryTasks.Add([pscustomobject]@{ Scope = $subScope; ScopeType = 'ResourceGroup'; Path = "$subScope/resourcegroups?api-version=2021-04-01" })
        }
        if ($AddResource) {
            $discoveryTasks.Add([pscustomobject]@{ Scope = $subScope; ScopeType = 'Resource'; Path = "$subScope/resources?api-version=2021-04-01" })
        }
    }
    if ($AdditionalResourceIds) {
        foreach ($id in $AdditionalResourceIds) {
            if ($id -notmatch '^/subscriptions/([^/]+)/resourceGroups/[^/]+/providers/.+') {
                throw "AdditionalResourceIds contains an invalid resource scope: $id"
            }
            if ($Matches[1] -notin $subscriptions.Id) { throw "Resource $id is outside the selected subscriptions." }
            $scopes.Add([pscustomobject]@{ Scope = $id.TrimEnd('/'); ScopeType = 'Resource'; ScopeName = ($id.TrimEnd('/').Split('/')[-1]) })
        }
    }
}

Write-Host "Discovering selected scopes (up to $ThrottleLimit workers)..."
$discovered = @($discoveryTasks | ForEach-Object -Parallel {
    $task = $_
    $pimContext = $using:pimContext
    $retryCount = $using:MaxRetries
    . ([scriptblock]::Create($using:workerFunctions))
    try {
        Import-Module Az.Accounts -ErrorAction Stop
        foreach ($item in @(Get-PimList $task.Path)) {
            [pscustomobject]@{ Kind = 'Scope'; Data = [pscustomobject]@{
                Scope = ([string]$item.id).TrimEnd('/'); ScopeType = $task.ScopeType; ScopeName = $item.name
            } }
        }
    }
    catch {
        [pscustomobject]@{ Kind = 'Error'; Data = (New-PimError $task.Scope 'DiscoverScopes' $_.Exception.Message) }
    }
} -ThrottleLimit $ThrottleLimit)
foreach ($item in $discovered) {
    if ($item.Kind -eq 'Scope') { $scopes.Add($item.Data) } else { $errors.Add($item.Data) }
}
$selectedScopes = @($scopes | Sort-Object Scope -Unique)
Write-Host "Querying $($selectedScopes.Count) scopes (up to $ThrottleLimit workers)..."

# Each worker owns its lists and cache. Files are exported only by the main runspace.
$scopeResults = @($selectedScopes | ForEach-Object -Parallel {
    $task = $_
    $pimContext = $using:pimContext
    $retryCount = $using:MaxRetries
    . ([scriptblock]::Create($using:workerFunctions))
    $rows = [System.Collections.Generic.List[object]]::new()
    $notifications = [System.Collections.Generic.List[object]]::new()
    $raw = [System.Collections.Generic.List[object]]::new()
    $failures = [System.Collections.Generic.List[object]]::new()
    $policyCache = @{}
    $scope = [string]$task.Scope
    try {
        Import-Module Az.Accounts -ErrorAction Stop
        $base = "$scope/providers/Microsoft.Authorization"
        # atScope() includes ancestors: always apply the exact-scope check below.
        $eligible = @(Get-PimList ($base + '/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=atScope%28%29') |
            Where-Object { ([string]$_.properties.scope).TrimEnd('/') -ieq $scope })
        if ($eligible.Count -gt 0) {
            $policyAssignments = @()
            $assignmentQueryError = $null
            try { $policyAssignments = @(Get-PimList "$base/roleManagementPolicyAssignments?api-version=2020-10-01") }
            catch {
                $assignmentQueryError = $_.Exception.Message
                $failures.Add((New-PimError $scope 'GetPolicyAssignments' $assignmentQueryError))
            }
            foreach ($group in @($eligible | Group-Object { ([string]$_.properties.roleDefinitionId).TrimEnd('/').Split('/')[-1] })) {
                $roleId = [string]$group.Name
                $candidates = @($policyAssignments | Where-Object {
                    ([string]$_.properties.roleDefinitionId).TrimEnd('/').Split('/')[-1] -ieq $roleId -and
                    ([string]$_.properties.scope).TrimEnd('/') -ieq $scope
                })
                $assignment = $null
                $policy = $null
                $rules = @()
                $ruleSource = $null
                $policyStatus = 'Unavailable'
                $policyError = $assignmentQueryError
                if (-not $assignmentQueryError) {
                    if ($candidates.Count -ne 1) {
                        $policyError = "Expected one policy assignment for role $roleId; found $($candidates.Count)."
                        $failures.Add((New-PimError $scope 'MatchPolicyAssignment' $policyError))
                    }
                    else {
                        $assignment = $candidates[0]
                        $policyId = [string]$assignment.properties.policyId
                        try {
                            if ([string]::IsNullOrWhiteSpace($policyId)) { throw 'Policy assignment contains no policyId.' }
                            if (-not $policyCache.ContainsKey($policyId)) {
                                $policyCache[$policyId] = Invoke-PimGet ($policyId.TrimEnd('/') + '?api-version=2020-10-01')
                            }
                            $policy = $policyCache[$policyId]
                            if ($null -eq $policy) { throw 'Policy response is empty.' }
                            $policyStatus = 'Available'
                        }
                        catch {
                            $policyError = $_.Exception.Message
                            $failures.Add((New-PimError $scope 'GetPolicy' $policyError))
                        }
                        # Assignment-level effective rules take precedence over policy rules.
                        if (@($assignment.properties.effectiveRules).Where({ $null -ne $_ }).Count -gt 0) {
                            $rules = @($assignment.properties.effectiveRules)
                            $ruleSource = 'PolicyAssignment.effectiveRules'
                            if ($null -eq $policy) { $policyStatus = 'EffectiveRulesAvailablePolicyReadFailed' }
                        }
                        elseif (@($policy.properties.effectiveRules).Where({ $null -ne $_ }).Count -gt 0) {
                            $rules = @($policy.properties.effectiveRules); $ruleSource = 'Policy.effectiveRules'
                        }
                        elseif (@($policy.properties.rules).Where({ $null -ne $_ }).Count -gt 0) {
                            $rules = @($policy.properties.rules); $ruleSource = 'Policy.rules'
                        }
                        else {
                            $policyStatus = 'NoRulesReturned'
                            if (-not $policyError) {
                                $policyError = "No policy rules returned for role $roleId."
                                $failures.Add((New-PimError $scope 'ReadPolicyRules' $policyError))
                            }
                        }
                    }
                }
                $enable = Get-PimRule $rules 'Enablement_EndUser_Assignment'
                $expire = Get-PimRule $rules 'Expiration_EndUser_Assignment'
                $approve = Get-PimRule $rules 'Approval_EndUser_Assignment'
                $auth = Get-PimRule $rules 'AuthenticationContext_EndUser_Assignment'
                $eligibleExpire = Get-PimRule $rules 'Expiration_Admin_Eligibility'
                $activeExpire = Get-PimRule $rules 'Expiration_Admin_Assignment'
                $eligibleEnable = Get-PimRule $rules 'Enablement_Admin_Eligibility'
                $activeEnable = Get-PimRule $rules 'Enablement_Admin_Assignment'
                $stages = @($approve.setting.approvalStages | Where-Object { $null -ne $_ })
                foreach ($rule in @($rules | Where-Object { $_.ruleType -eq 'RoleManagementPolicyNotificationRule' })) {
                    $notifications.Add([pscustomobject]@{
                        ScopeType = $task.ScopeType; Scope = $scope; RoleDefinitionId = $group.Group[0].properties.roleDefinitionId
                        PolicyId = $assignment.properties.policyId; RuleSource = $ruleSource; RuleId = $rule.id
                        Caller = $rule.target.caller; Level = $rule.target.level; Operations = (@($rule.target.operations) -join ';')
                        NotificationType = $rule.notificationType; RecipientType = $rule.recipientType
                        NotificationLevel = $rule.notificationLevel; DefaultRecipientsEnabled = $rule.isDefaultRecipientsEnabled
                        Recipients = (@($rule.notificationRecipients) -join ';'); RuleJson = ConvertTo-PimJson $rule
                    })
                }
                foreach ($instance in $group.Group) {
                    $p = $instance.properties
                    $rows.Add([pscustomobject]@{
                        ScopeType = $task.ScopeType; Scope = $scope; ScopeName = $task.ScopeName
                        PrincipalId = $p.principalId; PrincipalDisplayName = $p.expandedProperties.principal.displayName
                        PrincipalType = $p.principalType; PrincipalEmail = $p.expandedProperties.principal.email
                        RoleName = $p.expandedProperties.roleDefinition.displayName; RoleDefinitionId = $p.roleDefinitionId
                        EligibilityInstanceId = $instance.id; EligibilityScheduleId = $p.roleEligibilityScheduleId
                        MemberType = $p.memberType; Status = $p.status; StartDateTime = $p.startDateTime; EndDateTime = $p.endDateTime
                        Condition = $p.condition; ConditionVersion = $p.conditionVersion
                        PolicyStatus = $policyStatus; PolicyError = $policyError; PolicyId = $assignment.properties.policyId
                        PolicyAssignmentId = $assignment.id; RuleSource = $ruleSource
                        MaximumActivationDuration = $expire.maximumDuration; ActivationExpirationRequired = $expire.isExpirationRequired
                        ActivationMFARequired = Test-PimEnabled $enable 'MultiFactorAuthentication'
                        ActivationJustificationRequired = Test-PimEnabled $enable 'Justification'
                        ActivationTicketRequired = Test-PimEnabled $enable 'Ticketing'
                        ApprovalRequired = $approve.setting.isApprovalRequired
                        ApprovalForExtensionRequired = $approve.setting.isApprovalRequiredForExtension
                        ApprovalRequestorJustificationRequired = $approve.setting.isRequestorJustificationRequired
                        ApprovalMode = $approve.setting.approvalMode
                        PrimaryApproversJson = ConvertTo-PimJson @($stages | ForEach-Object { $_.primaryApprovers } | Where-Object { $null -ne $_ })
                        EscalationApproversJson = ConvertTo-PimJson @($stages | ForEach-Object { $_.escalationApprovers } | Where-Object { $null -ne $_ })
                        ApprovalStagesJson = ConvertTo-PimJson $stages
                        AuthenticationContextEnabled = $auth.isEnabled; AuthenticationContextClaim = $auth.claimValue
                        EligibilityExpirationRequired = $eligibleExpire.isExpirationRequired
                        MaximumEligibilityDuration = $eligibleExpire.maximumDuration
                        ActiveAssignmentExpirationRequired = $activeExpire.isExpirationRequired
                        MaximumActiveAssignmentDuration = $activeExpire.maximumDuration
                        EligibilityAssignmentMFARequired = Test-PimEnabled $eligibleEnable 'MultiFactorAuthentication'
                        EligibilityAssignmentJustificationRequired = Test-PimEnabled $eligibleEnable 'Justification'
                        ActiveAssignmentMFARequired = Test-PimEnabled $activeEnable 'MultiFactorAuthentication'
                        ActiveAssignmentJustificationRequired = Test-PimEnabled $activeEnable 'Justification'
                        AllRulesJson = ConvertTo-PimJson $rules
                    })
                    # The complete ARM objects retain all configuration, including
                    # future rule types, enforcement targets and policy metadata.
                    $raw.Add([pscustomobject]@{
                        ScopeType = $task.ScopeType; Scope = $scope; PolicyStatus = $policyStatus; PolicyError = $policyError
                        RuleSource = $ruleSource; EligibilityInstance = $instance
                        PolicyAssignment = $assignment; Policy = $policy; ReportedRules = $rules
                    })
                }
            }
        }
    }
    catch { $failures.Add((New-PimError $scope 'QueryScope' $_.Exception.Message)) }
    [pscustomobject]@{ Scope = $scope; Rows = $rows.ToArray(); Notifications = $notifications.ToArray(); Raw = $raw.ToArray(); Errors = $failures.ToArray() }
} -ThrottleLimit $ThrottleLimit)

if ($scopeResults.Count -ne $selectedScopes.Count) {
    $errors.Add((New-PimError '' 'WorkerCompletion' "Expected $($selectedScopes.Count) worker results; received $($scopeResults.Count)."))
}
$report = @($scopeResults | ForEach-Object { $_.Rows } | Sort-Object Scope, RoleDefinitionId, PrincipalId, EligibilityInstanceId)
$notificationReport = @($scopeResults | ForEach-Object { $_.Notifications } | Sort-Object Scope, RoleDefinitionId, RuleId)
$fullReport = @($scopeResults | ForEach-Object { $_.Raw } | Sort-Object Scope)
foreach ($result in $scopeResults) { foreach ($failure in $result.Errors) { $errors.Add($failure) } }
$errorReport = @($errors | Sort-Object Scope, Operation)

# A unique run directory avoids overwriting earlier reports.
$runDirectory = Join-Path $OutputDirectory ("{0}-{1}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8)))
$null = New-Item -ItemType Directory -Path $runDirectory -Force
$runDirectory = (Resolve-Path $runDirectory).Path

function Export-PimCsv {
    param([object[]]$Data, [string]$Path, [string[]]$EmptyColumns)
    if ($Data.Count -gt 0) { $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding utf8 }
    else {
        # Header-only CSVs are valid even when a selected level contains no eligibility.
        $header = ($EmptyColumns | ForEach-Object { '"' + $_.Replace('"', '""') + '"' }) -join ','
        Set-Content -LiteralPath $Path -Value $header -Encoding utf8
    }
}
Export-PimCsv $report (Join-Path $runDirectory 'EligibleRoles.csv') @('ScopeType', 'Scope', 'PrincipalId', 'RoleDefinitionId', 'PolicyStatus')
Export-PimCsv $notificationReport (Join-Path $runDirectory 'Notifications.csv') @('ScopeType', 'Scope', 'RoleDefinitionId', 'RuleId', 'Recipients')
Export-PimCsv $errorReport (Join-Path $runDirectory 'Errors.csv') @('Scope', 'Operation', 'Message')
$document = [ordered]@{
    TenantId = $tenantId; StartedUtc = $started.ToString('o'); FinishedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    ThrottleLimit = $ThrottleLimit; Complete = ($errorReport.Count -eq 0)
    SelectedLevels = [ordered]@{ ManagementGroup = [bool]$AddManagementGroup; Subscription = [bool]$AddSubscription; ResourceGroup = [bool]$AddResourceGroup; Resource = [bool]$AddResource }
    QueriedScopes = $selectedScopes; Assignments = $fullReport; Errors = $errorReport
}
ConvertTo-Json -InputObject $document -Depth 100 | Set-Content -LiteralPath (Join-Path $runDirectory 'FullReport.json') -Encoding utf8
Write-Host "Exported $($report.Count) eligible assignments and $($notificationReport.Count) notification rules to $runDirectory"
if ($errorReport.Count -gt 0) { Write-Warning "The report is incomplete: $($errorReport.Count) errors. Check Errors.csv and PolicyStatus before interpreting missing settings." }
[pscustomobject]@{
    OutputDirectory = $runDirectory; QueriedScopeCount = $selectedScopes.Count
    EligibleAssignmentCount = $report.Count; ErrorCount = $errorReport.Count; Complete = ($errorReport.Count -eq 0)
}
