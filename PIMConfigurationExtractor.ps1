#requires -Version 7.2
#requires -Modules Az.Accounts, Az.Resources
<#
.SYNOPSIS
Exports Azure resource PIM eligibility and complete role policy configuration.
.DESCRIPTION
Read-only. Uses TenantId when supplied, otherwise the signed-in tenant, and an
explicit Az context on every request. An existing context for TenantId is reused;
if none is available, interactive authentication is requested before workers start.
The four scope switches are independent. Assignments inherited from other scopes
are excluded. SubscriptionIds limits subscription/RG/resource discovery only;
management groups are discovered separately in the selected tenant.
ForEach-Object -Parallel uses in-process runspaces, not separate login processes.
Policies are cached per scope/role; all JSON rules and approval stages are retained.
Resource discovery uses ARM's subscription resource inventory. Child resources
not present in that inventory require explicit resource IDs via AdditionalResourceIds.
.EXAMPLE
./Export-AzurePIM-Parallel.ps1 -TenantId '<tenant-guid>' -AddManagementGroup -AddSubscription -ThrottleLimit 8
.EXAMPLE
./Export-AzurePIM-Parallel.ps1 -AddResourceGroup -AddResource -SubscriptionIds '<id>'
.NOTES
Timestamped console messages show discovery, each scope's eligibility count,
role-policy retrieval, retries, failures, completion counts and elapsed time.
The main runspace owns the progress bars. Use -Verbose for each ARM request/page.
Concurrent scope messages may appear in completion order rather than input order.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$TenantId,
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
if ($TenantId -and (-not $pimContext.Account -or ([string]$pimContext.Tenant.Id -ine $TenantId))) {
    $availableContexts = @(Get-AzContext -ListAvailable -ErrorAction Stop |
        Where-Object { $_.Account -and ([string]$_.Tenant.Id -ieq $TenantId) })
    # Prefer the current account when several accounts have contexts in the tenant.
    $currentAccountId = [string]$pimContext.Account.Id
    $pimContext = $availableContexts | Where-Object { $_.Account.Id -eq $currentAccountId } | Select-Object -First 1
    if (-not $pimContext) { $pimContext = $availableContexts | Select-Object -First 1 }
    if (-not $pimContext) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] [INFO] Connecting to tenant $TenantId..."
        $null = Connect-AzAccount -Tenant $TenantId -Scope Process -ErrorAction Stop
        $pimContext = Get-AzContext -ErrorAction Stop
    }
}
if (-not $pimContext -or -not $pimContext.Account -or -not $pimContext.Tenant.Id) {
    throw 'Specify -TenantId <tenant-guid> to connect, or run Connect-AzAccount before running this script.'
}
if ($TenantId -and ([string]$pimContext.Tenant.Id -ine $TenantId)) {
    throw "The selected Azure context does not match requested tenant $TenantId."
}
$retryCount = $MaxRetries
$selectedTenantId = [string]$pimContext.Tenant.Id
$started = [DateTimeOffset]::UtcNow

# Functions are passed as TEXT and created inside each worker's own runspace.
# The context is shared read-only. No worker calls Set-AzContext or Connect-AzAccount.
$workerFunctions = @'
function Write-PimLog {
    param([string]$Message, [ValidateSet('INFO', 'WARN')][string]$Level = 'INFO')
    $color = if ($Level -eq 'WARN') { 'Yellow' } else { 'Cyan' }
    Write-Host ("[{0:HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Message) -ForegroundColor $color
}

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
            Write-Verbose "GET $Path (attempt $($attempt + 1))"
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
            Write-PimLog "HTTP $status; retry $($attempt + 1)/$retryCount after $milliseconds ms: $Path" 'WARN'
            Start-Sleep -Milliseconds $milliseconds
        }
    }
}

function Get-PimList {
    param([Parameter(Mandatory)][string]$Path)
    # Buffer all pages; a later-page failure must never look like a complete list.
    $items = [System.Collections.Generic.List[object]]::new()
    $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $pageNumber = 0
    do {
        if (-not $visited.Add($Path)) { throw "Repeated pagination link: $Path" }
        $page = Invoke-PimGet $Path
        if ($null -eq $page -or $null -eq $page.PSObject.Properties['value']) {
            throw "Expected an ARM list response at $Path"
        }
        foreach ($item in @($page.value)) { if ($null -ne $item) { $items.Add($item) } }
        $pageNumber++
        Write-Verbose "Read page $pageNumber : $($items.Count) items so far from $Path"
        $Path = [string]$page.nextLink
    } while ($Path)
    return $items.ToArray()
}

function New-PimError {
    param([string]$Scope, [string]$Operation, [string]$Message)
    Write-PimLog "$Operation failed at $Scope : $Message" 'WARN'
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
Write-PimLog "Tenant: $selectedTenantId | Account: $($pimContext.Account.Id) | Parallel workers: $ThrottleLimit"

$scopes = [System.Collections.Generic.List[object]]::new()
$errors = [System.Collections.Generic.List[object]]::new()
$discoveryTasks = [System.Collections.Generic.List[object]]::new()

if ($AddManagementGroup) {
    Write-PimLog 'Discovering management groups...'
    try {
        $managementGroupCount = 0
        foreach ($mg in @(Get-AzManagementGroup -DefaultProfile $pimContext -ErrorAction Stop)) {
            $scopeId = if ($mg.Id) { [string]$mg.Id } else { "/providers/Microsoft.Management/managementGroups/$($mg.Name)" }
            $scopes.Add([pscustomobject]@{ Scope = $scopeId.TrimEnd('/'); ScopeType = 'ManagementGroup'; ScopeName = $mg.DisplayName })
            $managementGroupCount++
        }
        Write-PimLog "Discovered $managementGroupCount management groups."
    }
    catch { $errors.Add((New-PimError '/providers/Microsoft.Management/managementGroups' 'DiscoverManagementGroups' $_.Exception.Message)) }
}

if ($AddSubscription -or $AddResourceGroup -or $AddResource) {
    # Keep this run in one tenant. Each request carries the same tenant's profile;
    # absolute ARM paths specify the target subscription without changing context.
    Write-PimLog 'Discovering subscriptions...'
    $subscriptions = @(Get-AzSubscription -TenantId $selectedTenantId -DefaultProfile $pimContext -ErrorAction Stop |
        Where-Object { $_.State -eq 'Enabled' })
    if ($SubscriptionIds) {
        foreach ($requested in $SubscriptionIds) {
            if ($requested -notin $subscriptions.Id) { throw "Subscription $requested is not accessible and enabled in tenant $selectedTenantId." }
        }
        $subscriptions = @($subscriptions | Where-Object { $_.Id -in $SubscriptionIds })
    }
    Write-PimLog "Selected $($subscriptions.Count) enabled subscriptions."
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

Write-PimLog "Discovering selected scopes: $($discoveryTasks.Count) inventory queries (up to $ThrottleLimit workers)..."
$completedDiscoveryCount = 0
$discoveryTotal = $discoveryTasks.Count
if ($discoveryTotal -gt 0) {
    Write-Progress -Id 1 -Activity 'Discovering Azure scopes' -Status "0 / $discoveryTotal inventory queries completed" -PercentComplete 0
}
$discovered = @($discoveryTasks | ForEach-Object -Parallel {
    $task = $_
    $pimContext = $using:pimContext
    $retryCount = $using:MaxRetries
    $VerbosePreference = $using:VerbosePreference
    . ([scriptblock]::Create($using:workerFunctions))
    try {
        Import-Module Az.Accounts -ErrorAction Stop
        Write-PimLog "DISCOVERY START [$($task.ScopeType)] $($task.Scope)"
        $inventory = @(Get-PimList $task.Path)
        foreach ($item in $inventory) {
            [pscustomobject]@{ Kind = 'Scope'; Data = [pscustomobject]@{
                Scope = ([string]$item.id).TrimEnd('/'); ScopeType = $task.ScopeType; ScopeName = $item.name
            } }
        }
        Write-PimLog "DISCOVERY FOUND [$($task.ScopeType)] $($task.Scope) : $($inventory.Count) scopes"
    }
    catch {
        [pscustomobject]@{ Kind = 'Error'; Data = (New-PimError $task.Scope 'DiscoverScopes' $_.Exception.Message) }
    }
    [pscustomobject]@{ Kind = 'DiscoveryComplete'; Data = $task }
} -ThrottleLimit $ThrottleLimit | ForEach-Object {
    if ($_.Kind -eq 'DiscoveryComplete') {
        $completedDiscoveryCount++
        Write-Progress -Id 1 -Activity 'Discovering Azure scopes' -Status "$completedDiscoveryCount / $discoveryTotal inventory queries completed" -CurrentOperation $_.Data.Scope -PercentComplete ([int](100 * $completedDiscoveryCount / [Math]::Max(1, $discoveryTotal)))
    }
    else { $_ }
})
Write-Progress -Id 1 -Activity 'Discovering Azure scopes' -Completed
if ($completedDiscoveryCount -ne $discoveryTotal) {
    $errors.Add((New-PimError '' 'DiscoveryCompletion' "Expected $discoveryTotal inventory completions; received $completedDiscoveryCount."))
}
foreach ($item in $discovered) {
    if ($item.Kind -eq 'Scope') { $scopes.Add($item.Data) } else { $errors.Add($item.Data) }
}
$selectedScopes = @($scopes | Sort-Object Scope -Unique)
foreach ($scopeLevel in @($selectedScopes | Group-Object ScopeType)) {
    Write-PimLog "Selected $($scopeLevel.Count) $($scopeLevel.Name) scopes."
}
Write-PimLog "Querying $($selectedScopes.Count) scopes (up to $ThrottleLimit workers)..."
$completedScopeCount = 0
$retrievedEligibleCount = 0
$reportedEligibleCount = 0
$scopeErrorCount = 0
$scopeTotal = $selectedScopes.Count
if ($scopeTotal -gt 0) {
    Write-Progress -Id 2 -Activity 'Retrieving eligible roles and PIM settings' -Status "0 / $scopeTotal scopes completed" -PercentComplete 0
}

# Each worker owns its lists and cache. Files are exported only by the main runspace.
$scopeResults = @($selectedScopes | ForEach-Object -Parallel {
    $task = $_
    $pimContext = $using:pimContext
    $retryCount = $using:MaxRetries
    $VerbosePreference = $using:VerbosePreference
    . ([scriptblock]::Create($using:workerFunctions))
    $rows = [System.Collections.Generic.List[object]]::new()
    $notifications = [System.Collections.Generic.List[object]]::new()
    $raw = [System.Collections.Generic.List[object]]::new()
    $failures = [System.Collections.Generic.List[object]]::new()
    $policyCache = @{}
    $scope = [string]$task.Scope
    $eligible = @()
    $scopeStarted = [DateTimeOffset]::UtcNow
    try {
        Import-Module Az.Accounts -ErrorAction Stop
        Write-PimLog "ELIGIBILITY START [$($task.ScopeType)] $scope"
        $base = "$scope/providers/Microsoft.Authorization"
        # atScope() includes ancestors: always apply the exact-scope check below.
        $eligible = @(Get-PimList ($base + '/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter=atScope%28%29') |
            Where-Object { ([string]$_.properties.scope).TrimEnd('/') -ieq $scope })
        Write-PimLog "ELIGIBILITY FOUND [$($task.ScopeType)] $scope : $($eligible.Count) eligible assignments"
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
                $roleLabel = [string]$group.Group[0].properties.expandedProperties.roleDefinition.displayName
                if (-not $roleLabel) { $roleLabel = $roleId }
                Write-PimLog "POLICY START $scope | $roleLabel | $($group.Count) eligible assignments"
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
                Write-PimLog "POLICY RESULT $scope | $roleLabel | $policyStatus | $($rules.Count) rules"
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
    [pscustomobject]@{
        Scope = $scope; ScopeType = $task.ScopeType; EligibleCount = $eligible.Count
        DurationSeconds = [Math]::Round(([DateTimeOffset]::UtcNow - $scopeStarted).TotalSeconds, 1)
        Rows = $rows.ToArray(); Notifications = $notifications.ToArray(); Raw = $raw.ToArray(); Errors = $failures.ToArray()
    }
} -ThrottleLimit $ThrottleLimit | ForEach-Object {
    # This downstream block runs in the main runspace as each worker finishes.
    # Counters and progress-bar updates cannot race across parallel workers.
    $result = $_
    $completedScopeCount++
    $retrievedEligibleCount += $result.EligibleCount
    $reportedEligibleCount += @($result.Rows).Count
    $scopeErrorCount += @($result.Errors).Count
    $level = if (@($result.Errors).Count -gt 0) { 'WARN' } else { 'INFO' }
    Write-PimLog "SCOPE COMPLETE [$completedScopeCount/$scopeTotal] [$($result.ScopeType)] $($result.Scope) | Found: $($result.EligibleCount) | Reported: $(@($result.Rows).Count) | Errors: $(@($result.Errors).Count) | $($result.DurationSeconds)s | Total found: $retrievedEligibleCount" $level
    Write-Progress -Id 2 -Activity 'Retrieving eligible roles and PIM settings' -Status "$completedScopeCount / $scopeTotal scopes | $retrievedEligibleCount eligible assignments found | $reportedEligibleCount reported | $scopeErrorCount errors" -CurrentOperation $result.Scope -PercentComplete ([int](100 * $completedScopeCount / [Math]::Max(1, $scopeTotal)))
    $result
})
Write-Progress -Id 2 -Activity 'Retrieving eligible roles and PIM settings' -Completed

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
Write-PimLog "Writing reports to $runDirectory..."

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
    TenantId = $selectedTenantId; StartedUtc = $started.ToString('o'); FinishedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    ThrottleLimit = $ThrottleLimit; Complete = ($errorReport.Count -eq 0)
    SelectedLevels = [ordered]@{ ManagementGroup = [bool]$AddManagementGroup; Subscription = [bool]$AddSubscription; ResourceGroup = [bool]$AddResourceGroup; Resource = [bool]$AddResource }
    QueriedScopes = $selectedScopes; Assignments = $fullReport; Errors = $errorReport
}
ConvertTo-Json -InputObject $document -Depth 100 | Set-Content -LiteralPath (Join-Path $runDirectory 'FullReport.json') -Encoding utf8
Write-PimLog "FINISHED | Scopes: $completedScopeCount/$scopeTotal | Eligible assignments found: $retrievedEligibleCount | Exported: $($report.Count) | Notification rules: $($notificationReport.Count) | Errors: $($errorReport.Count) | Elapsed: $([Math]::Round(([DateTimeOffset]::UtcNow - $started).TotalSeconds, 1))s"
Write-PimLog "Reports saved to $runDirectory"
if ($errorReport.Count -gt 0) { Write-Warning "The report is incomplete: $($errorReport.Count) errors. Check Errors.csv and PolicyStatus before interpreting missing settings." }
[pscustomobject]@{
    OutputDirectory = $runDirectory; QueriedScopeCount = $selectedScopes.Count
    EligibleAssignmentCount = $report.Count; ErrorCount = $errorReport.Count; Complete = ($errorReport.Count -eq 0)
}
