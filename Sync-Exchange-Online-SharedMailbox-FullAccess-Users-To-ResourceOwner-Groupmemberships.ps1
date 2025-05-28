#####################################################
# HelloID-Conn-SA-Sync-EXO-SharedMailbox-FullAccess-Users-To-ResourceOwner-Groupmemberships
#
# Version: 1.0.1
#####################################################
# Set to false to acutally perform actions - Only run as DryRun when testing/troubleshooting!
$dryRun = $false
# Set to true to log each individual action - May cause lots of logging, so use with cause, Only run testing/troubleshooting!
$verboseLogging = $false

switch ($verboseLogging) {
    $true { $VerbosePreference = "Continue" }
    $false { $VerbosePreference = "SilentlyContinue" }
}
$informationPreference = "Continue"
$WarningPreference = "Continue"

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Make sure to create the Global variables defined below in HelloID
#HelloID Connection Configuration
# $script:PortalBaseUrl = "" # Set from Global Variable
# $portalApiKey = "" # Set from Global Variable
# $portalApiSecret = "" # Set from Global Variable

# Exchange Online Connection Configuration
# $AzureADOrganization = "" # Set from Global Variable
# $AzureADtenantID = "" # Set from Global Variable
# $AzureADAppId = "" # Set from Global Variable
# $AzureADAppSecret = "" # Set from Global Variable
$exchangeMailboxesFilter = "DisplayName -like 'Shared-*'" # Optional, when no filter is provided ($exchangeMailboxesFilter = $null), all mailboxes will be queried
# $exchangeMailboxesFilter = "DisplayName -eq 'financien de Ark'" # Optional, when no filter is provided ($exchangeMailboxesFilter = $null), all mailboxes will be queried

# PowerShell commands to import
$exchangeOnlineCommands = @(
    "Get-User"
    , "Get-Group"
    , "Get-EXOMailbox"
    , "Get-EXOMailboxPermission"
) # Fixed list of commands required by script - only change when missing commands

#HelloID Configuration
$resourceOwnerGroupSource = "Local" # Specify the source of the groups - if source is any other than "Local", the sync of the target system itself might overwrite the memberships set form this sync
# The HelloID Resource owner group will be queried based on the shared mailbox name and the specified prefix and suffix
$resourceOwnerGroupPrefix = "" # Specify prefix to recognize the resource owner group
$resourceOwnerGroupSuffix = " Resource Owners" # Specify suffix to recognize the resource owner group
$removeMembers = $true # If true, existing members will be removed if they no longer have full access to the corresponding mailbox - This will overwrite manual added users

#region functions

function Remove-StringLatinCharacters {
    PARAM ([string]$String)
    [Text.Encoding]::ASCII.GetString([Text.Encoding]::GetEncoding("Cyrillic").GetBytes($String))
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ""
        }

        if ($ErrorObject.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") {
            # $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message # Does not show the correct error message for the Raet IAM API calls
            $httpErrorObj.ErrorMessage = $ErrorObject.Exception.Message

        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq "System.Net.WebException") {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }

        Write-Output $httpErrorObj
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        if ( $($ErrorObject.Exception.GetType().FullName -eq "Microsoft.PowerShell.Commands.HttpResponseException") -or $($ErrorObject.Exception.GetType().FullName -eq "System.Net.WebException")) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = $httpErrorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}

function Invoke-HIDRestmethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [object]
        $Body,

        [Parameter(Mandatory = $false)]
        $PageSize,

        [string]
        $ContentType = "application/json"
    )

    try {
        Write-Verbose "Switching to TLS 1.2"
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        Write-Verbose "Setting authorization headers"
        $apiKeySecret = "$($portalApiKey):$($portalApiSecret)"
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($apiKeySecret))
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add("Authorization", "Basic $base64")
        $headers.Add("Content-Type", $ContentType)
        $headers.Add("Accept", $ContentType)

        $splatWebRequest = @{
            Uri             = "$($script:PortalBaseUrl)/api/v1/$($Uri)"
            Headers         = $headers
            Method          = $Method
            UseBasicParsing = $true
            ErrorAction     = "Stop"
        }
        
        if (-not[String]::IsNullOrEmpty($PageSize)) {
            $data = [System.Collections.ArrayList]@()

            $skip = 0
            $take = $PageSize
            Do {
                $splatWebRequest["Uri"] = "$($script:PortalBaseUrl)/api/v1/$($Uri)?skip=$($skip)&take=$($take)"

                Write-Verbose "Invoking [$Method] request to [$Uri]"
                $response = $null
                $response = Invoke-RestMethod @splatWebRequest -Verbose:$false
                if (($response.PsObject.Properties.Match("pageData") | Measure-Object).Count -gt 0) {
                    $dataset = $response.pageData
                }
                else {
                    $dataset = $response
                }

                if ($dataset -is [array]) {
                    [void]$data.AddRange($dataset)
                }
                else {
                    [void]$data.Add($dataset)
                }
            
                $skip += $take
            }until(($dataset | Measure-Object).Count -ne $take)

            return $data
        }
        else {
            if ($Body) {
                Write-Verbose "Adding body to request"
                $splatWebRequest["Body"] = ([System.Text.Encoding]::UTF8.GetBytes($body))
            }

            Write-Verbose "Invoking [$Method] request to [$Uri]"
            $response = $null
            $response = Invoke-RestMethod @splatWebRequest -Verbose:$false

            return $response
        }

    }
    catch {
        throw $_
    }
}
#endregion functions

#region script
Hid-Write-Status -Event Information -Message "Starting synchronization of Exchange Online Users with FullAccess to SharedMailboxes to HelloID ResourceOwner Groupmemberships"
Hid-Write-Status -Event Information -Message "------[Exchange Online]-----------"

# Import module
try {
    $moduleName = "ExchangeOnlineManagement"
    $importModule = Import-Module -Name $moduleName -ErrorAction Stop -Verbose:$false
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error importing module [$moduleName]. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Connect to Exchange
try {
    # Create access token
    Write-Verbose "Creating Access Token"

    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AzureADTenantId/oauth2/token"
    
    $body = @{
        grant_type    = "client_credentials"
        client_id     = "$AzureADAppID"
        client_secret = "$AzureADAppSecret"
        resource      = "https://outlook.office365.com"
    }
    
    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType "application/x-www-form-urlencoded" -UseBasicParsing:$true -Verbose:$false
    $accessToken = $Response.access_token

    # Connect to Exchange Online in an unattended scripting scenario using an access token.
    Write-Verbose "Connecting to Exchange Online"

    $exchangeSessionParams = @{
        Organization     = $AzureADOrganization
        AppID            = $AzureADAppID
        AccessToken      = $accessToken
        CommandName      = $exchangeOnlineCommands
        ShowBanner       = $false
        ShowProgress     = $false
        TrackPerformance = $false
        ErrorAction      = "Stop"
    }
    $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams -Verbose:$false
    
    Write-Information "Successfully connected to Exchange Online"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"
    throw "Error connecting to Exchange Online. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Get Exchange Online Shared Mailboxes
try {  
    $properties = @(
        "Guid"
        , "Id"
        , "Identity"
        , "UserPrincipalName"
        , "Name"
        , "DisplayName"
        , "RecipientType"
        , "RecipientTypeDetails"
    )

    $exchangeQuerySplatParams = @{
        Filter               = $exchangeMailboxesFilter
        Properties           = $properties
        RecipientTypeDetails = "SharedMailbox"
        ResultSize           = "Unlimited"
    }

    Write-Verbose "Querying Exchange Online Shared Mailboxes that match filter [$($exchangeQuerySplatParams.Filter)]"
    $exoMailboxes = Get-EXOMailbox @exchangeQuerySplatParams | Select-Object $properties

    if (($exoMailboxes | Measure-Object).Count -eq 0) {
        throw "No Shared Mailboxes have been found"
    }

    Hid-Write-Status -Event Success -Message "Successfully queried Exchange Online Shared Mailboxes. Result count: $(($exoMailboxes | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Exchange Online Shared Mailboxes that match filter [$($exchangeQuerySplatParams.Filter)]. Error Message: $($errorMessage.AuditErrorMessage)"
}

#region Get Exchange online users
# Exchange Online users are needed so all the attributes are available
try {
    Write-Verbose "Querying Exchange users"

    $exoUsers = Get-User -ResultSize Unlimited -Verbose:$false

    if (($exoUsers | Measure-Object).Count -eq 0) {
        throw "No Users have been found"
    }

    $exoUsersGroupedOnUserPrincipalName = $exoUsers | Group-Object UserPrincipalName -AsHashTable

    Hid-Write-Status -Event Success -Message "Successfully queried Exchange Online Users. Result count: $(($exoUsers | Measure-Object).Count)"
}
catch { 
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying all Exchange users. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get Exchange online groups

#region Get Exchange online groups
# Exchange Online groups are needed so all the attributes are available
try {
    Write-Verbose "Querying Exchange groups"

    $exoGroups = Get-Group -ResultSize Unlimited -Verbose:$false

    if (($exoGroups | Measure-Object).Count -eq 0) {
        throw "No Groups have been found"
    }
    
    $exoGroupsGroupedOnDisplayname = $exoGroups | Group-Object Displayname -AsHashTable  

    Hid-Write-Status -Event Success -Message "Successfully queried Exchange Online Groups. Result count: $(($groups | Measure-Object).Count)"
}
catch { 
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying all Exchange groups. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get Exchange online groups

#region Get permissions to Shared Mailbox
try {
    [System.Collections.ArrayList]$exoMailboxesWithFullAccessUsers = @()
    Write-Verbose "Querying Exchange Shared Mailboxes with Users with FullAccess"
    foreach ($exoMailbox in $exoMailboxes) {
        #region Get objects with Full Access to Shared Mailbox
        try {
            $exoMailboxWithFullAccessUsersObject = [PSCustomObject]@{
                DisplayName       = $exoMailbox.DisplayName
                Name              = $exoMailbox.Name
                UserPrincipalName = $exoMailbox.UserPrincipalName
                Id                = $exoMailbox.Id
                Users = [System.Collections.ArrayList]@()
            }

            Write-Verbose "Querying Full Access Permissions to Mailbox [$($exoMailbox.UserPrincipalName)]"

            $fullAccessPermissions = Get-EXOMailboxPermission -Identity $exoMailbox.UserPrincipalName -ResultSize Unlimited -Verbose:$false # Returns UPN of users, DisplayName of groups

            # Filter out "NT AUTHORITY\*" and "Domain Admins" Group
            $fullAccessPermissions = $fullAccessPermissions | Where-Object { ($_.accessRights -like "*fullaccess*") -and -not($_.Deny -eq $true) -and -not($_.User -like "NT AUTHORITY\*") -and -not($_.User -like "*\Domain Admins") }

            foreach ($fullAccessPermission in $fullAccessPermissions) {
                $fullAccessUser = $null
                # list of al the users in the mailbox. This includes the groups member from the mailbox
                if ($null -ne $fullAccessPermission.User) {
                    $fullAccessUser = $null
                    $fullAccessUser = $exoUsersGroupedOnUserPrincipalName[$($fullAccessPermission.user)]
                    if ($null -ne $fullAccessUser) {
                        $userWithFullAccessObject = [PSCustomObject]@{
                            Id                   = $fullAccessUser.id
                            DisplayName          = $fullAccessUser.displayName
                            UserPrincipalName    = $fullAccessUser.userPrincipalName
                        }

                        [void]$exoMailboxWithFullAccessUsersObject.Users.Add($userWithFullAccessObject)
                    }
                }
            }

            [void]$exoMailboxesWithFullAccessUsers.Add($exoMailboxWithFullAccessUsersObject)

            if ($verboseLogging -eq $true) {
                Write-Verbose "Successfully queried Full Access Permissions to Mailbox [$($exoMailbox.UserPrincipalName)]. Result count: $(($fullAccessPermissions | Measure-Object).Count)"
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
            Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
            throw "Error querying Full Access Permissions to Mailbox [$($exoMailbox.UserPrincipalName)] Error Message: $($errorMessage.AuditErrorMessage)"
        }
        #endregion Get objects with Full Access to Shared Mailbox
    }
    Hid-Write-Status -Event Success -Message "Successfully queried Exchange Shared Mailboxes with Users with FullAccess. Result count: $(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Exchange Shared Mailboxes with Users with FullAccess. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get permissions to Shared Mailbox

Hid-Write-Status -Event Information -Message "------[HelloID]------"
#region Get HelloID Users
try {
    Write-Verbose "Querying Users from HelloID"

    $splatWebRequest = @{
        Method   = "GET"
        Uri      = "users"
        PageSize = 1000
    }
    $helloIDUsers = Invoke-HIDRestMethod @splatWebRequest

    $helloIDUsersGroupedOnUserName = $helloIDUsers | Group-Object -Property "userName" -AsHashTable -AsString
    $helloIDUsersGroupedOnUserGUID = $helloIDUsers | Group-Object -Property "userGUID" -AsHashTable -AsString

    Hid-Write-Status -Event Success -Message "Successfully queried Users from HelloID. Result count: $(($helloIDUsers | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Users from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get HelloID Users

#region Get HelloID Groups
try {
    Write-Verbose "Querying Groups from HelloID"

    $splatWebRequest = @{
        Method   = "GET"
        Uri      = "groups"
        PageSize = 1000
    }
    $helloIDGroups = Invoke-HIDRestMethod @splatWebRequest

    Hid-Write-Status -Event Success -Message "Successfully queried Groups from HelloID. Result count: $(($helloIDGroups | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying Groups from HelloID. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregion Get HelloID Groups

#region Get members of HelloID groups
try {
    [System.Collections.ArrayList]$helloIDGroupsWithMembers = @()
    Write-Verbose "Querying HelloID groups with members"
    foreach ($helloIDGroup in $helloIDGroups) {
        #region Get HelloID users that are member of HelloID group
        try {
            Write-Verbose "Querying HelloID group [$($helloIDGroup.name) ($($helloIDGroup.groupGuid))] with members"

            $splatWebRequest = @{
                Method   = "GET"
                Uri      = "groups/$($helloIDGroup.groupGuid)"
                PageSize = 1000
            }
            $helloIDGroup = Invoke-HIDRestMethod @splatWebRequest

            [void]$helloIDGroupsWithMembers.Add($helloIDGroup)

            if ($verboseLogging -eq $true) {
                Write-Verbose "Successfully queried HelloID group [$($helloIDGroup.name) ($($helloIDGroup.groupGuid))] with members. Result count: $(($helloIDGroup.users | Measure-Object).Count)"
            }
        }
        catch {
            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
        
            Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
        
            throw "Error querying HelloID group [$($helloIDGroup.name) ($($helloIDGroup.groupGuid))] with members. Error Message: $($errorMessage.AuditErrorMessage)"
        }
        #endregion Get HelloID users that are member of HelloID group
    }

    $helloIDGroupsWithMembers | Add-Member -MemberType NoteProperty -Name SourceAndName -Value $null
    $helloIDGroupsWithMembers | ForEach-Object {
        if ([string]::IsNullOrEmpty($_.source)) {
            $_.source = "Local"
        }
        $_.SourceAndName = "$($_.source)/$($_.name)"
    }

    $helloIDGroupsWithMembers = $helloIDGroupsWithMembers | Where-Object { $_.SourceAndName -like "$($resourceOwnerGroupSource)/*" }

    $helloIDGroupsWithMembersGroupedBySourceAndName = $helloIDGroupsWithMembers | Group-Object -Property "SourceAndName" -AsHashTable -AsString

    Hid-Write-Status -Event Success -Message "Successfully queried HelloID groups with members. Result count: $(($helloIDGroupsWithMembers.users | Measure-Object).Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error querying HelloID users that are member of HelloID groups. Error Message: $($errorMessage.AuditErrorMessage)"
}
#endregionGet members of HelloID groups

Hid-Write-Status -Event Information -Message "------[Calculations of combined data]------"
# Calculate new and obsolete groupmemberships
try {
    # Define existing & new groupmemberships
    $existingGroupMembershipObjects = [System.Collections.ArrayList]@()
    $newGroupMembershipObjects = [System.Collections.ArrayList]@()
    foreach ($exoMailboxWithFullAccessUsers in $exoMailboxesWithFullAccessUsers) {
        # Define Resource owner Group
        $resourceOwnerGroupName = "$($resourceOwnerGroupSource)/" + "$($resourceOwnerGroupPrefix)" + "$($exoMailboxWithFullAccessUsers.DisplayName)" + "$($resourceOwnerGroupSuffix)"

        # Get HelloID Resource Owner Group
        $helloIDResourceOwnerGroup = $null
        if (-not[string]::IsNullOrEmpty($resourceOwnerGroupName)) {
            $resourceOwnerGroupName = Remove-StringLatinCharacters $resourceOwnerGroupName
            $helloIDResourceOwnerGroup = $helloIDGroupsWithMembersGroupedBySourceAndName["$($resourceOwnerGroupName)"]
            if ($null -eq $helloIDResourceOwnerGroup) {
                if ($verboseLogging -eq $true) {
                    Write-Verbose "Resource owner group [$($resourceOwnerGroupName)] for Shared Mailbox [$($fullAccessUser.DisplayName)] not found in HelloID"
                }

                # Skip further actions for this record
                Continue
            }
        }
        else {
            if ($verboseLogging -eq $true) {
                Write-Verbose "No Resource owner group name provided for Shared Mailbox [$($fullAccessUser.DisplayName)]"
            }
        }

        # Define existing groupmemberships
        foreach ($helloIDResourceOwnerGroupUser in $helloIDResourceOwnerGroup.Users) {
            # Get HelloID User
            $helloIDUser = $null
            $helloIDUser = $helloIDUsersGroupedOnUserGUID["$($helloIDResourceOwnerGroupUser)"]
            if ($null -eq $helloIDUser) {
                if ($verboseLogging -eq $true) {
                    Write-Verbose "No HelloID user found for Exchange User Resource owner group [$($helloIDResourceOwnerGroupUser)]"
                }

                # Skip further actions for this record
                Continue
            }
            
            $existingGroupMembershipObject = [PSCustomObject]@{
                GroupName    = "$($helloIDResourceOwnerGroup.name)"
                GroupId      = "$($helloIDResourceOwnerGroup.groupGuid)"
                UserUsername = "$($helloIDUser.userName)"
                UserId       = "$($helloIDUser.userGUID)"
            }

            [void]$existingGroupMembershipObjects.Add($existingGroupMembershipObject)
        }

        # Define new groupmemberships
        foreach ($exoUserWithFullAcces in $exoMailboxWithFullAccessUsers.Users) {
            # Get HelloID User
            $helloIDUser = $null
            if (-not[string]::IsNullOrEmpty($exoUserWithFullAcces.UserPrincipalName)) {
                $helloIDUser = $helloIDUsersGroupedOnUserName["$($exoUserWithFullAcces.UserPrincipalName)"]
                if ($null -eq $helloIDUser) {
                    if ($verboseLogging -eq $true) {
                        Write-Verbose "No HelloID user found for Exchange User Resource owner group [$($exoUserWithFullAcces.UserPrincipalName)]"
                    }

                    # Skip further actions for this record
                    Continue
                }
            }
            else {
                if ($verboseLogging -eq $true) {
                    Write-Verbose "No UserPrincipalName provided for full access user [$($exoUserWithFullAcces.Id)]"
                }
            }

            $newGroupMembershipObject = [PSCustomObject]@{
                GroupName    = "$($helloIDResourceOwnerGroup.name)"
                GroupId      = "$($helloIDResourceOwnerGroup.groupGuid)"
                UserUsername = "$($helloIDUser.userName)"
                UserId       = "$($helloIDUser.userGUID)"
            }

            [void]$newGroupMembershipObjects.Add($newGroupMembershipObject)
        }
    }

    # Define new groupmemberships
    $newGroupMemberships = [System.Collections.ArrayList]@()
    $newGroupMemberships = $newGroupMembershipObjects | Where-Object { $_ -notin $existingGroupMembershipObjects }

    # Define obsolete groupmemberships
    $obsoleteGroupMemberships = [System.Collections.ArrayList]@()
    $obsoleteGroupMemberships = $existingGroupMembershipObjects | Where-Object { $_ -notin $newGroupMembershipObjects }

    # Define existing groupmemberships
    $existingGroupMemberships = [System.Collections.ArrayList]@()
    $existingGroupMemberships = $existingGroupMembershipObjects | Where-Object { $_ -notin $obsoleteGroupMemberships }

    # Define total groupmemberships (existing + new)
    $totalGroupMemberships = ($(($existingGroupMemberships | Measure-Object).Count) + $(($newGroupMemberships | Measure-Object).Count))
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"

    throw "Error calculating new and obsolete groupmemberships. Error Message: $($errorMessage.AuditErrorMessage)"
}

Hid-Write-Status -Event Information -Message "------[Summary]------"
Hid-Write-Status -Event Information -Message "Total Exchange Online users with full access to mailbox in scope [$(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)]"

Hid-Write-Status -Event Information -Message "New HelloID Resource Owner Groupmembership(s) that will be granted [$(($newGroupMemberships | Measure-Object).Count)]"

if ($removeMembers) {
    Hid-Write-Status -Event Information "Obsolete HelloID Resource Owner Groupmembership(s) that will be revoked [$(($obsoleteGroupMemberships | Measure-Object).Count)]"
}
else {
    Hid-Write-Status -Event Information -Message "Obsolete HelloID Resource Owner Groupmembership(s) that won't be revoked [$(($obsoleteGroupMemberships | Measure-Object).Count)]"
}

Hid-Write-Status -Event Information -Message "------[Processing]------------------"
try {
    $addUserToGroupSuccess = 0
    $addUserToGroupError = 0
    foreach ($newGroupMembership in $newGroupMemberships) {
        # Add HelloID User to HelloID Group
        try {
            if ($verboseLogging -eq $true) {
                Write-Verbose "Adding HelloID user [$($newGroupMembership.UserUsername) ($($newGroupMembership.UserId))] to HelloID group [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))]"
            }

            $addUserToGroupBody = [PSCustomObject]@{
                UserGUID = "$($newGroupMembership.UserId)"
            }
            $body = ($addUserToGroupBody | ConvertTo-Json -Depth 10)
            $splatWebRequest = @{
                Uri    = "groups/$($newGroupMembership.GroupId)/users"
                Method = 'POST'
                Body   = $body
            }

            if ($dryRun -eq $false) {
                $addUserToGroupResult = Invoke-HIDRestMethod @splatWebRequest
                $addUserToGroupSuccess++

                if ($verboseLogging -eq $true) {
                    Write-Verbose "Successfully added HelloID user [$($newGroupMembership.UserUsername) ($($newGroupMembership.UserId))] to HelloID group [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))]"
                }
            }
            else {
                if ($verboseLogging -eq $true) {
                    Write-Verbose "DryRun: Would add HelloID user [$($newGroupMembership.UserUsername) ($($newGroupMembership.UserId))] to HelloID group [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))]"
                }
            }
        }
        catch {
            $addUserToGroupError++

            $ex = $PSItem
            $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
            Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
            
            throw "Error adding HelloID user [$($newGroupMembership.UserUsername) ($($newGroupMembership.UserId))] to HelloID group [$($newGroupMembership.GroupName) ($($newGroupMembership.GroupId))]. Error Message: $($errorMessage.AuditErrorMessage)"
        }
    }
    if ($dryRun -eq $false) {
        if ($addUserToGroupSuccess -ge 1 -or $addUserToGroupError -ge 1) {
            Hid-Write-Status -Event Information -Message "Added HelloID users to HelloID groups. Success: $($addUserToGroupSuccess). Error: $($addUserToGroupError)"
            Hid-Write-Summary -Event Information -Message "Added HelloID users to HelloID groups. Success: $($addUserToGroupSuccess). Error: $($addUserToGroupError)"
        }
    }
    else {
        Hid-Write-Status -Event Warning -Message "DryRun: Would add [$(($newGroupMemberships | Measure-Object).Count)] HelloID users to HelloID groups"
        Hid-Write-Status -Event Warning -Message "DryRun: Would add [$(($newGroupMemberships | Measure-Object).Count)] HelloID users to HelloID groups"
    }

    if ($removeMembers -eq $true) {
        $removeUserFromGroupSuccess = 0
        $removeUserFromGroupError = 0
        foreach ($obsoleteGroupMembership in $obsoleteGroupMemberships) {
            # Remove HelloID User from HelloID Group
            try {
                if ($verboseLogging -eq $true) {
                    Write-Verbose "Removing HelloID user [$($obsoleteGroupMembership.UserUsername) ($($obsoleteGroupMembership.UserId))] to HelloID group [$($obsoleteGroupMembership.GroupName) ($($obsoleteGroupMembership.GroupId))]"
                }

                $splatWebRequest = @{
                    Uri    = "groups/$($obsoleteGroupMembership.GroupId)/users/$($obsoleteGroupMembership.UserId)"
                    Method = 'DELETE'
                }

                if ($dryRun -eq $false) {
                    $removeUserToGroupResult = Invoke-HIDRestMethod @splatWebRequest
                    $removeUserFromGroupSuccess++

                    if ($verboseLogging -eq $true) {
                        Write-Verbose "Successfully removed HelloID user [$($obsoleteGroupMembership.UserUsername) ($($obsoleteGroupMembership.UserId))] to HelloID group [$($obsoleteGroupMembership.GroupName) ($($obsoleteGroupMembership.GroupId))]"
                    }
                }
                else {
                    if ($verboseLogging -eq $true) {
                        Write-Verbose "DryRun: Would remove HelloID user [$($obsoleteGroupMembership.UserUsername) ($($obsoleteGroupMembership.UserId))] to HelloID group [$($obsoleteGroupMembership.GroupName) ($($obsoleteGroupMembership.GroupId))]"
                    }
                }
            }
            catch {
                $removeUserFromGroupError++

                $ex = $PSItem
                $errorMessage = Get-ErrorMessage -ErrorObject $ex
            
                Hid-Write-Status -Event Error -Message "Error at Line [$($ex.InvocationInfo.ScriptLineNumber)]: $($ex.InvocationInfo.Line). Error: $($($errorMessage.VerboseErrorMessage))"
            
                throw "Error removing HelloID user [$($obsoleteGroupMembership.UserUsername) ($($obsoleteGroupMembership.UserId))] to HelloID group [$($obsoleteGroupMembership.GroupName) ($($obsoleteGroupMembership.GroupId))]. Error Message: $($errorMessage.AuditErrorMessage)"
            }
        }
        if ($dryRun -eq $false) {
            if ($removeUserFromGroupSuccess -ge 1 -or $removeUserFromGroupError -ge 1) {
                Hid-Write-Status -Event Information -Message "Removed HelloID users from HelloID groups. Success: $($removeUserFromGroupSuccess). Error: $($removeUserFromGroupError)"
                Hid-Write-Summary -Event Information -Message "Removed HelloID users from HelloID groups. Success: $($removeUserFromGroupSuccess). Error: $($removeUserFromGroupError)"
            }
        }
        else {
            Hid-Write-Status -Event Warning -Message "DryRun: Would remove [$(($obsoleteGroupMemberships | Measure-Object).Count)] HelloID users from HelloID groups"
            Hid-Write-Status -Event Warning -Message "DryRun: Would remove [$(($obsoleteProducts | Measure-Object).Count)] HelloID users from HelloID groups"
        }
    }
    else {
        Hid-Write-Status -Event Warning -Message "Option to remove members is set to [$removeMembers]. Skipped removing [$(($obsoleteGroupMemberships | Measure-Object).Count)] HelloID users to HelloID groups"
    }

    if ($dryRun -eq $false) {
        Hid-Write-Status -Event Success -Message "Successfully synchronized [$(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)] Exchange Online Users with FullAccess to SharedMailboxes to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
        Hid-Write-Summary -Event Success -Message "Successfully synchronized [$(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)] Exchange Online Users with FullAccess to SharedMailboxes to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
    }
    else {
        Hid-Write-Status -Event Success -Message "DryRun: Would synchronize [$(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)] Exchange Online Users with FullAccess to SharedMailboxes to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
        Hid-Write-Summary -Event Success -Message "DryRun: Would synchronize [$(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)] Exchange Online Users with FullAccess to SharedMailboxes to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
    }
}
catch {
    Hid-Write-Status -Event Error -Message "Error synchronization of [$(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)] Exchange Online Users with FullAccess to SharedMailboxes to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
    Hid-Write-Status -Event Error -Message "Error at Line [$($_.InvocationInfo.ScriptLineNumber)]: $($_.InvocationInfo.Line)."
    Hid-Write-Status -Event Error -Message "Exception message: $($_.Exception.Message)"
    Hid-Write-Status -Event Error -Message "Exception details: $($_.errordetails)"
    Hid-Write-Summary -Event Failed -Message "Error synchronization of [$(($exoMailboxesWithFullAccessUsers.Users | Measure-Object).Count)] Exchange Online Users with FullAccess to SharedMailboxes to [$totalGroupMemberships] HelloID ResourceOwner Groupmemberships"
}
#endregion
