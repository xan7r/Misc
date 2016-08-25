<#
Note: All AD helper functions used in this module (i.e. everything except Find-LastLogonLocation and List-LastLogonTime) were copied from Powerview.ps1 found at https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

Instructions:
1 - Identify the last time a user or group of users last logged on by running:
    List-LastLogonTimes -GroupName "SQL Admins"
    List-LastLogonTimes -UserName John.Smith

    ex:
    beacon> powershell List-LastLogonTime user*
        TESTLAB.LOCAL\user1:
        DC1.TESTLAB.LOCAL: 06/18/2016 03:53:26
        DC2.TESTLAB.LOCAL: 

        TESTLAB.LOCAL\user2:
        DC1.TESTLAB.LOCAL: 06/17/2016 23:09:13
        DC2.TESTLAB.LOCAL: 06/18/2016 09:11:20


2 - Identify the IP Address of domain computer the user recently logged into by running:
    Find-LastLogonLocation user2
    Find-LastLogonLocation -Domain dev.lab.local -UserName john.Smith.dev
    Find-LastLogonLocation -UserName john.Smith -DomainController DC2.TESTLAB.LOCAL
 
    ex:
    beacon> powershell Find-LastLogonLocation user2
        DC1.TESTLAB.LOCAL:
        IP        : 172.20.200.112
        Domain    : TESTLAB
        User_SID  : S-1-5-21-845331989-3518299402-266290621-1106
        LogonType : 3
        Username  : user2
        Time      : 6/17/2016 11:09:14 PM


        DC2.TESTLAB.LOCAL:
        IP        : 172.20.200.112
        Domain    : TESTLAB
        User_SID  : S-1-5-21-845331989-3518299402-266290621-1106
        LogonType : 3
        Username  : user2
        Time      : 6/18/2016 9:11:21 AM
#>


function Find-LastLogonLocation
{
<#
    .SYNOPSIS
        Find the last computer that a user logged into by parsing Windows Event logs.
        NOTE: This Requires DA/EA privileges.

    .PARAMETER UserName
        Username of account being searched

    .PARAMETER GroupName
        Search for all users in a given group instead of single user

    .PARAMETER Domain
        Domain to search for user in, if blank then defaults to current domain.
        NOTE: Requires DA privileges within target domain

    .PARAMETER FullData
        Switch to display entire event log data instead of summary.  Useful if there are any issues with parsing event summary.

    .PARAMETER DomainController
        Switch to query only a SINGLE DC, rather than default mode of ALL DCs in target User's Domain.
        Note: This parameter accepts a FQDN or IP address. "127.0.0.1" is also accepted

    .PARAMETER SearchWindow
        Integer specifying how many minutes around reported last logon time to query.
        Ex. If User's LastLogon was 08:46:13, then a 5 minute SearchWindow will query events from 08:41:13 to 08:51:13
        Default: 2 minutes

    .EXAMPLE
        Find-LastLogonLocation -UserName john.Smith
        Find-LastLogonLocation -GroupName "Domain Admins"
        Find-LastLogonLocation -Domain dev.lab.local -UserName john.Smith.dev
        Find-LastLogonLocation -UserName john.Smith -DomainController 127.0.0.1
        Find-LastLogonLocation -UserName john.Smith -SearchWindow 5
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False, Position=1)]
        [String]
        $UserName,

        [Parameter(Mandatory=$False)]
        [String]
        $GroupName,

        [Parameter(Mandatory=$False)]
        [String]
        $Domain,

        [Parameter(Mandatory=$False)]
        [Switch]
        $FullData,

        [Parameter(Mandatory=$False)]
        [String]
        $DomainController,

        [Parameter(Mandatory=$False)]
        [Int]
        $SearchWindow = 2
    )

    $DClist = New-Object System.Collections.ArrayList
    $LogonTimesList = New-Object System.Collections.ArrayList
    $UserList = New-Object System.Collections.ArrayList

    if ( ! $GroupName -and ! $UserName )
    {
        Write-Output "ERROR: Must specify either UserName or GroupName parameter"
        exit
    }

    if ( ! $Domain )
    {
        $Domain = (Get-Netdomain).Name
    }

    if ( $DomainController )
    {
        [void]$DClist.add(@{'Name' = $DomainController})
    }
    else 
    {
        try 
        {
            Get-NetDomainController -Domain $Domain| % { [void]$DClist.add($_)}
        }
        catch 
        {
            Write-Output "Unable to find any DCs.  Make sure you are in a Domain Context"
            exit
        }
    }
    
    if ( $UserName )
    {
        Get-NetUser -UserName $UserName -Domain $Domain | % { [Void]$UserList.add($_.SamAccountName) }
    }
    elseif ( $GroupName )
    {
        Get-NetGroupMember -GroupName $GroupName -Domain $Domain | % { [Void]$UserList.add($_.MemberName) }
    }

    ForEach ($DC in $DClist)
    {
        $temp = New-Object System.Collections.ArrayList
        
        ForEach ( $UserName in $UserList )
        {
            $timestamp = Get-NetUser -UserName $UserName -Domain $Domain -DomainController $DC.Name
            [void]$temp.add($timestamp.LastLogon)
        }

        [void]$LogonTimesList.add($temp)

    }

    for ( $i=0; $i -lt $DClist.count; $i++ )
    {
        $DC = $DClist[$i].Name
        $time = $LogonTimesList[$i]

        Write-Output "`n$DC`:"

        # Loop through all users in the group
        for ( $i2=0; $i2 -lt $UserList.count; $i2++ )
        {
            $UserName = $UserList[$i2]
            $UserTime = $time[$i2]
        
            Write-Output "`n$UserName`:"

            if ( $UserTime )
            {
                $startT = (Get-Date $UserTime).AddMinutes(-$SearchWindow).toString()
                $endT = (Get-Date $UserTime).AddMinutes($SearchWindow).toString()

                try 
                {
                    $LogonEventsArray = Get-WinEvent -FilterHashTable @{logname='security'; id=@(4624,4768); StartTime=$startT; EndTime=$endT} -ComputerName $DC -ErrorAction SilentlyContinue | Where { ($_.Properties[5].value -match $UserName) -or ($_.Properties[0].value -match $UserName) }
                }
                catch
                {
                    Write-Output "[!] Warning: Error while reaching RPC server, either you don't have access or  Remote Event Log Management is blocked by firewall.`n[!] Recommend elevating privleges or running function on DC directly with parameter -DomainController 127.0.0.1"
                    continue
                }

                if ( $LogonEventsArray )
                {
                    ForEach ( $LogonEvent in $LogonEventsArray )
                    {
                        if ( $FullData )
                        {
                            $LogonEvent.Message
                        }
                        # Format Logon Event Data
                        elseif ( $LogonEvent.Properties[5].value -match $UserName )
                        {
                            $LogonEventProperties = @{
                                'Domain' = $LogonEvent.Properties[6].value
                                'Username' = $LogonEvent.Properties[5].value
                                'User_SID' = $LogonEvent.Properties[4].value
                                'IP' = $LogonEvent.Properties[18].value
                                'LogonType' = $LogonEvent.Properties[8].value
                                'Time' = $LogonEvent.TimeCreated
                            }
                            New-Object -TypeName PSObject -Property $LogonEventProperties
                        }
                        # Format TGT Event Data
                        else
                        {
                            $LogonEventProperties = @{
                                'Domain' = $LogonEvent.Properties[1].value
                                'Username' = $LogonEvent.Properties[0].value
                                'User_SID' = $LogonEvent.Properties[2].value
                                'IP' = $LogonEvent.Properties[9].value
                                'Time' = $LogonEvent.TimeCreated
                            }
                            New-Object -TypeName PSObject -Property $LogonEventProperties
                        } 
                    }
                }
                else
                {
                    Write-Output "[!] WARNING: User $UserName last logged in via this DC on $UserTime, but no associated events were found"
                }
            }
            else 
            {
                Write-Output "[!] WARNING: No Recent logon events recorded for User $Username on this DC"
            }
        }
    }
}


function List-LastLogonTime
{
    <#
    .SYNOPSIS
        List the LastLogOn property of a user for all DCs in the target user's domain.
        NOTE: This only requires domain user privileges.

    .PARAMETER UserName
        Username of account being searched.  Wildcards are accepted

    .PARAMETER GroupName
        Get LastLogon time of all users in a domain group.  Wildcards are accepted

    .PARAMETER SearchForest
        Switch to query ALL DCs in the forest, instead of just the user's domain

    .PARAMETER Domain
        Domain to search for user in, if blank then defaults to current domain.

    .PARAMETER LastDay
        Switch to only display LastLogon Times within the past 24 hours.

    .EXAMPLE
        List-LastLogonTimes -UserName john.Smith
        List-LastLogonTimes -GroupName john.Smith
        List-LastLogonTimes -Domain dev.lab.local -UserName john.Smith.dev
        List-LastLogonTimes -UserName john.Smith -SearchForest
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False, Position=1)]
        [String]
        $UserName,

        [Parameter(Mandatory=$False)]
        [String]
        $GroupName,

        [Parameter(Mandatory=$False)]
        [Switch]
        $SearchForest,

        [Parameter(Mandatory=$False)]
        [String]
        $Domain,

        [Parameter(Mandatory=$False)]
        [Switch]
        $LastDay
    )

    $DClist = New-Object System.Collections.ArrayList
    $UserList = New-Object System.Collections.ArrayList

    # Sanity check input parameters
    if ( (! $UserName -and ! $GroupName) -or ($UserName -and $GroupName) )
    {
        Write-Output "[!] ERROR: You must specify either a username or groupname to search"
        exit
    }

    # Set the $Domain Variable
    if ( ! $Domain )
    {
        $Domain = (Get-Netdomain).Name
    }

    try 
    {
        if ( $SearchForest )
        {
            forEach ($dom in Get-NetForestDomain) 
            {
                Get-NetDomainController -Domain $dom | % { [void]$DClist.add($_)}
            }
        }
        else 
        {
            Get-NetDomainController -Domain $Domain | % { [void]$DClist.add($_)}
        }
    }
    catch 
    {
        Write-Output "[!] ERROR: Unable to find any DCs.  Make sure you are in a Domain Context"
        exit
    }

    # Get List of UserNames to query
    if ( $UserName )
    {
        Get-NetUser -UserName $UserName -Domain $Domain | % { [Void]$userList.add($_.SamAccountName) }
    }
    elseif ( $GroupName )
    {
        Get-NetGroupMember -GroupName $UserName -Domain $Domain | % { [Void]$userList.add($_.MemberName) }
    }

    if ( $UserList.count -eq 0 )
    {
        Write-Output "[!] ERROR: No valid domain user found"
        exit
    }
    
    ForEach ($user in $UserList)
    {
        Write-Output "`n$Domain\$user`:"
        ForEach ($DC in $DClist)
        {
            $DCName = $DC.Name
            $timestamp = Get-NetUser -UserName $user -Domain $Domain -DomainController $DCName
            $LastLogon = $timestamp.LastLogon

            if ( $LastDay )
            {
                try 
                {
                    $timeDiffDays = ((Get-Date) - $LastLogon).Days
                    $timeDiffHours = ((Get-Date) - $LastLogon).Hours

                    # unused code that further restricts $LastDay paremeter to only show the last 8 hours.  Uncomment if needed
                    #if ( ($timeDiffDays -eq 0) -and ($timeDiffHours -le 8) )

                    if ($timeDiffDays -lt 1)
                    {
                        Write-Output "$DCName`: $LastLogon"
                    }
                }
                catch 
                {
                    continue
                }
                
                
            }
            else
            {
                Write-Output "$DCName`: $LastLogon"
            }
            
        }
    }
}


function Get-NetUser {
<#
    .SYNOPSIS

        Query information for a given user or users in the domain
        using ADSI and LDAP. Another -Domain can be specified to
        query for users across a trust.
        Replacement for "net users /domain"

    .PARAMETER UserName

        Username filter string, wildcards accepted.

    .PARAMETER Domain

        The domain to query for users, defaults to the current domain.

    .PARAMETER DomainController

        Domain controller to reflect LDAP queries through.

    .PARAMETER ADSpath

        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.

    .PARAMETER Filter

        A customized ldap filter string to use, e.g. "(description=*admin*)"

    .PARAMETER AdminCount

        Switch. Return users with adminCount=1.

    .PARAMETER SPN

        Switch. Only return user objects with non-null service principal names.

    .PARAMETER Unconstrained

        Switch. Return users that have unconstrained delegation.

    .PARAMETER AllowDelegation

        Switch. Return user accounts that are not marked as 'sensitive and not allowed for delegation'

    .PARAMETER PageSize

        The PageSize to set for the LDAP searcher object.

    .EXAMPLE

        PS C:\> Get-NetUser -Domain testing

    .EXAMPLE

        PS C:\> Get-NetUser -ADSpath "LDAP://OU=secret,DC=testlab,DC=local"
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $UserName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Switch]
        $Unconstrained,

        [Switch]
        $AllowDelegation,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        # so this isn't repeated if users are passed on the pipeline
        $UserSearcher = Get-DomainSearcher -Domain $Domain -ADSpath $ADSpath -DomainController $DomainController -PageSize $PageSize
    }

    process {
        if($UserSearcher) {

            # if we're checking for unconstrained delegation
            if($Unconstrained) {
                Write-Verbose "Checking for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            if($AllowDelegation) {
                Write-Verbose "Checking for users who can be delegated"
                # negation of "Accounts that are sensitive and not trusted for delegation"
                $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))"
            }
            if($AdminCount) {
                Write-Verbose "Checking for adminCount=1"
                $Filter += "(admincount=1)"
            }

            # check if we're using a username filter or not
            if($UserName) {
                # samAccountType=805306368 indicates user objects
                $UserSearcher.filter="(&(samAccountType=805306368)(samAccountName=$UserName)$Filter)"
            }
            elseif($SPN) {
                $UserSearcher.filter="(&(samAccountType=805306368)(servicePrincipalName=*)$Filter)"
            }
            else {
                # filter is something like "(samAccountName=*blah*)" if specified
                $UserSearcher.filter="(&(samAccountType=805306368)$Filter)"
            }

            $UserSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                # convert/process the LDAP fields for each result
                Convert-LDAPProperty -Properties $_.Properties
            }
        }
    }
}



function Get-NetDomainController {
<#
    .SYNOPSIS

        Return the current domain controllers for the active domain.

    .PARAMETER Domain

        The domain to query for domain controllers, defaults to the current domain.

    .PARAMETER DomainController

        Domain controller to reflect LDAP queries through.

    .PARAMETER LDAP

        Switch. Use LDAP queries to determine the domain controllers.

    .EXAMPLE

        PS C:\> Get-NetDomainController -Domain test
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [Switch]
        $LDAP
    )

    process {
        if($LDAP -or $DomainController) {
            # filter string to return all domain controllers
            Get-NetComputer -Domain $Domain -DomainController $DomainController -FullData -Filter '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
        }
        else {
            $FoundDomain = Get-NetDomain -Domain $Domain
            
            if($FoundDomain) {
                $Founddomain.DomainControllers
            }
        }
    }
}


function Get-NetComputer {
<#
    .SYNOPSIS

        This function utilizes adsisearcher to query the current AD context
        for current computer objects. Based off of Carlos Perez's Audit.psm1
        script in Posh-SecMod (link below).

    .PARAMETER ComputerName

        Return computers with a specific name, wildcards accepted.

    .PARAMETER SPN

        Return computers with a specific service principal name, wildcards accepted.

    .PARAMETER OperatingSystem

        Return computers with a specific operating system, wildcards accepted.

    .PARAMETER ServicePack

        Return computers with a specific service pack, wildcards accepted.

    .PARAMETER Filter

        A customized ldap filter string to use, e.g. "(description=*admin*)"

    .PARAMETER Printers

        Switch. Return only printers.

    .PARAMETER Ping

        Switch. Ping each host to ensure it's up before enumerating.

    .PARAMETER FullData

        Switch. Return full computer objects instead of just system names (the default).

    .PARAMETER Domain

        The domain to query for computers, defaults to the current domain.

    .PARAMETER DomainController

        Domain controller to reflect LDAP queries through.

    .PARAMETER ADSpath

        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.

    .PARAMETER Unconstrained

        Switch. Return computer objects that have unconstrained delegation.

    .PARAMETER PageSize

        The PageSize to set for the LDAP searcher object.

    .EXAMPLE

        PS C:\> Get-NetComputer
        
        Returns the current computers in current domain.

    .EXAMPLE

        PS C:\> Get-NetComputer -SPN mssql*
        
        Returns all MS SQL servers on the domain.

    .EXAMPLE

        PS C:\> Get-NetComputer -Domain testing
        
        Returns the current computers in 'testing' domain.

    .EXAMPLE

        PS C:\> Get-NetComputer -Domain testing -FullData
        
        Returns full computer objects in the 'testing' domain.

    .LINK

        https://github.com/darkoperator/Posh-SecMod/blob/master/Audit/Audit.psm1
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [String]
        $ComputerName = '*',

        [String]
        $SPN,

        [String]
        $OperatingSystem,

        [String]
        $ServicePack,

        [String]
        $Filter,

        [Switch]
        $Printers,

        [Switch]
        $Ping,

        [Switch]
        $FullData,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $Unconstrained,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        # so this isn't repeated if users are passed on the pipeline
        $CompSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }

    process {

        if ($CompSearcher) {

            # if we're checking for unconstrained delegation
            if($Unconstrained) {
                Write-Verbose "Searching for computers with for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            # set the filters for the seracher if it exists
            if($Printers) {
                Write-Verbose "Searching for printers"
                # $CompSearcher.filter="(&(objectCategory=printQueue)$Filter)"
                $Filter += "(objectCategory=printQueue)"
            }
            if($SPN) {
                Write-Verbose "Searching for computers with SPN: $SPN"
                $Filter += "(servicePrincipalName=$SPN)"
            }
            if($OperatingSystem) {
                $Filter += "(operatingsystem=$OperatingSystem)"
            }
            if($ServicePack) {
                $Filter += "(operatingsystemservicepack=$ServicePack)"
            }

            $CompSearcher.filter = "(&(sAMAccountType=805306369)(dnshostname=$ComputerName)$Filter)"

            try {

                $CompSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    $Up = $True
                    if($Ping) {
                        # TODO: how can these results be piped to ping for a speedup?
                        $Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
                    }
                    if($Up) {
                        # return full data objects
                        if ($FullData) {
                            # convert/process the LDAP fields for each result
                            Convert-LDAPProperty -Properties $_.Properties
                        }
                        else {
                            # otherwise we're just returning the DNS host name
                            $_.properties.dnshostname
                        }
                    }
                }
            }
            catch {
                Write-Warning "Error: $_"
            }
        }
    }
}



function Get-DomainSearcher {
<#
    .SYNOPSIS

        Helper used by various functions that takes an ADSpath and
        domain specifier and builds the correct ADSI searcher object.

    .PARAMETER Domain

        The domain to use for the query, defaults to the current domain.

    .PARAMETER DomainController

        Domain controller to reflect LDAP queries through.

    .PARAMETER ADSpath

        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.

    .PARAMETER ADSprefix

        Prefix to set for the searcher (like "CN=Sites,CN=Configuration")

    .PARAMETER PageSize

        The PageSize to set for the LDAP searcher object.

    .EXAMPLE

        PS C:\> Get-DomainSearcher -Domain testlab.local

    .EXAMPLE

        PS C:\> Get-DomainSearcher -Domain testlab.local -DomainController SECONDARY.dev.testlab.local
#>

    [CmdletBinding()]
    param(
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    if(!$Domain) {
        $Domain = (Get-NetDomain).name
    }
    else {
        if(!$DomainController) {
            try {
                # if there's no -DomainController specified, try to pull the primary DC
                #   to reflect queries through
                $DomainController = ((Get-NetDomain).PdcRoleOwner).Name
            }
            catch {
                throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
            }
        }
    }

    $SearchString = "LDAP://"

    if($DomainController) {
        $SearchString += $DomainController + "/"
    }
    if($ADSprefix) {
        $SearchString += $ADSprefix + ","
    }

    if($ADSpath) {
        if($ADSpath -like "GC://*") {
            # if we're searching the global catalog
            $DistinguishedName = $AdsPath
            $SearchString = ""
        }
        else {
            if($ADSpath -like "LDAP://*") {
                $ADSpath = $ADSpath.Substring(7)
            }
            $DistinguishedName = $ADSpath
        }
    }
    else {
        $DistinguishedName = "DC=$($Domain.Replace('.', ',DC='))"
    }

    $SearchString += $DistinguishedName
    Write-Verbose "Get-DomainSearcher search string: $SearchString"

    $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    $Searcher.PageSize = $PageSize
    $Searcher
}


function Get-NetDomain {
<#
    .SYNOPSIS

        Returns a given domain object.

    .PARAMETER Domain

        The domain name to query for, defaults to the current domain.

    .EXAMPLE

        PS C:\> Get-NetDomain -Domain testlab.local

    .LINK

        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain
    )

    process {
        if($Domain) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
                $Null
            }
        }
        else {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
    }
}



function Convert-LDAPProperty {
    # helper to convert specific LDAP property result fields
    param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if (($_ -eq "objectsid") -or ($_ -eq "sidhistory")) {
            # convert the SID to a string
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0],0)).Value
        }
        elseif($_ -eq "objectguid") {
            # convert the GUID to a string
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lastlogoff") -or ($_ -eq "badPasswordTime") ) {
            # convert timestamps
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # if we have a System.__ComObject
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif($Properties[$_][0] -is [System.MarshalByRefObject]) {
            # convert misc com objects
            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }

    New-Object -TypeName PSObject -Property $ObjectProperties
}

function Get-NetGroup {
<#
    .SYNOPSIS

        Gets a list of all current groups in a domain, or all
        the groups a given user/group object belongs to.

    .PARAMETER GroupName

        The group name to query for, wildcards accepted.

    .PARAMETER SID

        The group SID to query for.

    .PARAMETER UserName

        The user name (or group name) to query for all effective
        groups of.

    .PARAMETER Filter

        A customized ldap filter string to use, e.g. "(description=*admin*)"

    .PARAMETER Domain

        The domain to query for groups, defaults to the current domain.

    .PARAMETER DomainController

        Domain controller to reflect LDAP queries through.

    .PARAMETER ADSpath

        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.

    .PARAMETER AdminCount

        Switch. Return group with adminCount=1.

    .PARAMETER FullData

        Switch. Return full group objects instead of just object names (the default).

    .PARAMETER RawSids

        Switch. Return raw SIDs when using "Get-NetGroup -UserName X"

    .PARAMETER PageSize

        The PageSize to set for the LDAP searcher object.

    .EXAMPLE

        PS C:\> Get-NetGroup
        
        Returns the current groups in the domain.

    .EXAMPLE

        PS C:\> Get-NetGroup -GroupName *admin*
        
        Returns all groups with "admin" in their group name.

    .EXAMPLE

        PS C:\> Get-NetGroup -Domain testing -FullData
        
        Returns full group data objects in the 'testing' domain
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GroupName = '*',

        [String]
        $SID,

        [String]
        $UserName,

        [String]
        $Filter,

        [String]
        $Domain,
        
        [String]
        $DomainController,
        
        [String]
        $ADSpath,

        [Switch]
        $AdminCount,

        [Switch]
        $FullData,

        [Switch]
        $RawSids,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        $GroupSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize
    }

    process {
        if($GroupSearcher) {

            if($AdminCount) {
                Write-Verbose "Checking for adminCount=1"
                $Filter += "(admincount=1)"
            }

            if ($UserName) {
                # get the raw user object
                $User = Get-ADObject -SamAccountName $UserName -Domain $Domain -DomainController $DomainController -ReturnRaw -PageSize $PageSize

                # convert the user to a directory entry
                $UserDirectoryEntry = $User.GetDirectoryEntry()

                # cause the cache to calculate the token groups for the user
                $UserDirectoryEntry.RefreshCache("tokenGroups")

                $UserDirectoryEntry.TokenGroups | Foreach-Object {
                    # convert the token group sid
                    $GroupSid = (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value
                    
                    # ignore the built in users and default domain user group
                    if(!($GroupSid -match '^S-1-5-32-545|-513$')) {
                        if($FullData) {
                            Get-ADObject -SID $GroupSid -PageSize $PageSize
                        }
                        else {
                            if($RawSids) {
                                $GroupSid
                            }
                            else {
                                Convert-SidToName $GroupSid
                            }
                        }
                    }
                }
            }
            else {
                if ($SID) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }
                else {
                    $GroupSearcher.filter = "(&(objectCategory=group)(name=$GroupName)$Filter)"
                }
            
                $GroupSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                    # if we're returning full data objects
                    if ($FullData) {
                        # convert/process the LDAP fields for each result
                        Convert-LDAPProperty -Properties $_.Properties
                    }
                    else {
                        # otherwise we're just returning the group name
                        $_.properties.samaccountname
                    }
                }
            }
        }
    }
}


function Get-NetGroupMember {
<#
    .SYNOPSIS

        This function users [ADSI] and LDAP to query the current AD context
        or trusted domain for users in a specified group. If no GroupName is
        specified, it defaults to querying the "Domain Admins" group.
        This is a replacement for "net group 'name' /domain"

    .PARAMETER GroupName

        The group name to query for users.

    .PARAMETER SID

        The Group SID to query for users. If not given, it defaults to 512 "Domain Admins"

    .PARAMETER Filter

        A customized ldap filter string to use, e.g. "(description=*admin*)"

    .PARAMETER Domain

        The domain to query for group users, defaults to the current domain.

    .PARAMETER DomainController

        Domain controller to reflect LDAP queries through.

    .PARAMETER ADSpath

        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.

    .PARAMETER FullData

        Switch. Returns full data objects instead of just group/users.

    .PARAMETER Recurse

        Switch. If the group member is a group, recursively try to query its members as well.

    .PARAMETER UseMatchingRule

        Switch. Use LDAP_MATCHING_RULE_IN_CHAIN in the LDAP search query when -Recurse is specified.
        Much faster than manual recursion, but doesn't reveal cross-domain groups.

    .PARAMETER PageSize

        The PageSize to set for the LDAP searcher object.

    .EXAMPLE

        PS C:\> Get-NetGroupMember
        
        Returns the usernames that of members of the "Domain Admins" domain group.

    .EXAMPLE

        PS C:\> Get-NetGroupMember -Domain testing -GroupName "Power Users"
        
        Returns the usernames that of members of the "Power Users" group in the 'testing' domain.

    .LINK

        http://www.powershellmagazine.com/2013/05/23/pstip-retrieve-group-membership-of-an-active-directory-group-recursively/
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $GroupName,

        [String]
        $SID,

        [String]
        $Domain = (Get-NetDomain).Name,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [Switch]
        $FullData,

        [Switch]
        $Recurse,

        [Switch]
        $UseMatchingRule,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    begin {
        # so this isn't repeated if users are passed on the pipeline
        $GroupSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize

        if(!$DomainController) {
            $DomainController = ((Get-NetDomain).PdcRoleOwner).Name
        }
    }

    process {

        if ($GroupSearcher) {

            if ($Recurse -and $UseMatchingRule) {
                # resolve the group to a distinguishedname
                if ($GroupName) {
                    $Group = Get-NetGroup -GroupName $GroupName -Domain $Domain -FullData -PageSize $PageSize
                }
                elseif ($SID) {
                    $Group = Get-NetGroup -SID $SID -Domain $Domain -FullData -PageSize $PageSize
                }
                else {
                    # default to domain admins
                    $SID = (Get-DomainSID -Domain $Domain) + "-512"
                    $Group = Get-NetGroup -SID $SID -Domain $Domain -FullData -PageSize $PageSize
                }
                $GroupDN = $Group.distinguishedname
                $GroupFoundName = $Group.name

                if ($GroupDN) {
                    $GroupSearcher.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$GroupDN)$Filter)"
                    $GroupSearcher.PropertiesToLoad.AddRange(('distinguishedName','samaccounttype','lastlogon','lastlogontimestamp','dscorepropagationdata','objectsid','whencreated','badpasswordtime','accountexpires','iscriticalsystemobject','name','usnchanged','objectcategory','description','codepage','instancetype','countrycode','distinguishedname','cn','admincount','logonhours','objectclass','logoncount','usncreated','useraccountcontrol','objectguid','primarygroupid','lastlogoff','samaccountname','badpwdcount','whenchanged','memberof','pwdlastset','adspath'))

                    $Members = $GroupSearcher.FindAll()
                    $GroupFoundName = $GroupName
                }
                else {
                    Write-Error "Unable to find Group"
                }
            }
            else {
                if ($GroupName) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(name=$GroupName)$Filter)"
                }
                elseif ($SID) {
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }
                else {
                    # default to domain admins
                    $SID = (Get-DomainSID -Domain $Domain) + "-512"
                    $GroupSearcher.filter = "(&(objectCategory=group)(objectSID=$SID)$Filter)"
                }

                $GroupSearcher.FindAll() | ForEach-Object {
                    try {
                        if (!($_) -or !($_.properties) -or !($_.properties.name)) { continue }

                        $GroupFoundName = $_.properties.name[0]
                        $Members = @()

                        if ($_.properties.member.Count -eq 0) {
                            $Finished = $False
                            $Bottom = 0
                            $Top = 0
                            while(!$Finished) {
                                $Top = $Bottom + 1499
                                $MemberRange="member;range=$Bottom-$Top"
                                $Bottom += 1500
                                $GroupSearcher.PropertiesToLoad.Clear()
                                [void]$GroupSearcher.PropertiesToLoad.Add("$MemberRange")
                                try {
                                    $Result = $GroupSearcher.FindOne()
                                    if ($Result) {
                                        $RangedProperty = $_.Properties.PropertyNames -like "member;range=*"
                                        $Results = $_.Properties.item($RangedProperty)
                                        if ($Results.count -eq 0) {
                                            $Finished = $True
                                        }
                                        else {
                                            $Results | ForEach-Object {
                                                $Members += $_
                                            }
                                        }
                                    }
                                    else {
                                        $Finished = $True
                                    }
                                } 
                                catch [System.Management.Automation.MethodInvocationException] {
                                    $Finished = $True
                                }
                            }
                        } 
                        else {
                            $Members = $_.properties.member
                        }
                    } 
                    catch {
                        Write-Verbose $_
                    }
                }
            }

            $Members | Where-Object {$_} | ForEach-Object {
                # if we're doing the LDAP_MATCHING_RULE_IN_CHAIN recursion
                if ($Recurse -and $UseMatchingRule) {
                    $Properties = $_.Properties
                } 
                else {
                    if($DomainController) {
                        $Result = [adsi]"LDAP://$DomainController/$_"
                    }
                    else {
                        $Result = [adsi]"LDAP://$_"
                    }
                    if($Result){
                        $Properties = $Result.Properties
                    }
                }

                if($Properties) {

                    if($Properties.samaccounttype -notmatch '805306368') {
                        $IsGroup = $True
                    }
                    else {
                        $IsGroup = $False
                    }

                    if ($FullData) {
                        $GroupMember = Convert-LDAPProperty -Properties $Properties
                    }
                    else {
                        $GroupMember = New-Object PSObject
                    }

                    $GroupMember | Add-Member Noteproperty 'GroupDomain' $Domain
                    $GroupMember | Add-Member Noteproperty 'GroupName' $GroupFoundName

                    try {
                        $MemberDN = $Properties.distinguishedname[0]
                        
                        # extract the FQDN from the Distinguished Name
                        $MemberDomain = $MemberDN.subString($MemberDN.IndexOf("DC=")) -replace 'DC=','' -replace ',','.'
                    }
                    catch {
                        $MemberDN = $Null
                        $MemberDomain = $Null
                    }

                    if ($Properties.samaccountname) {
                        # forest users have the samAccountName set
                        $MemberName = $Properties.samaccountname[0]
                    } 
                    else {
                        # external trust users have a SID, so convert it
                        try {
                            $MemberName = Convert-SidToName $Properties.cn[0]
                        }
                        catch {
                            # if there's a problem contacting the domain to resolve the SID
                            $MemberName = $Properties.cn
                        }
                    }
                    
                    if($Properties.objectSid) {
                        $MemberSid = ((New-Object System.Security.Principal.SecurityIdentifier $Properties.objectSid[0],0).Value)
                    }
                    else {
                        $MemberSid = $Null
                    }

                    $GroupMember | Add-Member Noteproperty 'MemberDomain' $MemberDomain
                    $GroupMember | Add-Member Noteproperty 'MemberName' $MemberName
                    $GroupMember | Add-Member Noteproperty 'MemberSid' $MemberSid
                    $GroupMember | Add-Member Noteproperty 'IsGroup' $IsGroup
                    $GroupMember | Add-Member Noteproperty 'MemberDN' $MemberDN
                    $GroupMember

                    # if we're doing manual recursion
                    if ($Recurse -and !$UseMatchingRule -and $IsGroup -and $MemberName) {
                        Get-NetGroupMember -FullData -Domain $MemberDomain -DomainController $DomainController -GroupName $MemberName -Recurse -PageSize $PageSize
                    }
                }

            }
        }
    }
}

function Get-DomainSID {
<#
    .SYNOPSIS

        Gets the SID for the domain.

    .PARAMETER Domain

        The domain to query, defaults to the current domain.

    .EXAMPLE

        C:\> Get-DomainSID -Domain TEST
        
        Returns SID for the domain 'TEST'
#>

    param(
        [String]
        $Domain
    )

    $FoundDomain = Get-NetDomain -Domain $Domain
    
    if($FoundDomain) {
        # query for the primary domain controller so we can extract the domain SID for filtering
        $PrimaryDC = $FoundDomain.PdcRoleOwner
        $PrimaryDCSID = (Get-NetComputer -Domain $Domain -ComputerName $PrimaryDC -FullData).objectsid
        $Parts = $PrimaryDCSID.split("-")
        $Parts[0..($Parts.length -2)] -join "-"
    }
}

function Get-ADObject {
<#
    .SYNOPSIS

        Takes a domain SID and returns the user, group, or computer object
        associated with it.

    .PARAMETER SID

        The SID of the domain object you're querying for.

    .PARAMETER Name

        The Name of the domain object you're querying for.

    .PARAMETER SamAccountName

        The SamAccountName of the domain object you're querying for. 

    .PARAMETER Domain

        The domain to query for objects, defaults to the current domain.

    .PARAMETER DomainController

        Domain controller to reflect LDAP queries through.

    .PARAMETER ADSpath

        The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
        Useful for OU queries.

    .PARAMETER Filter

        Additional LDAP filter string for the query.

    .PARAMETER ReturnRaw

        Switch. Return the raw object instead of translating its properties.
        Used by Set-ADObject to modify object properties.

    .PARAMETER PageSize

        The PageSize to set for the LDAP searcher object.

    .EXAMPLE

        PS C:\> Get-ADObject -SID "S-1-5-21-2620891829-2411261497-1773853088-1110"
        
        Get the domain object associated with the specified SID.
        
    .EXAMPLE

        PS C:\> Get-ADObject -ADSpath "CN=AdminSDHolder,CN=System,DC=testlab,DC=local"
        
        Get the AdminSDHolder object for the testlab.local domain.
#>

    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $SID,

        [String]
        $Name,

        [String]
        $SamAccountName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $ReturnRaw,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )
    process {
        if($SID) {
            # if a SID is passed, try to resolve it to a reachable domain name for the searcher
            try {
                $Name = Convert-SidToName $SID
                if($Name) {
                    $Canonical = Convert-NT4toCanonical -ObjectName $Name
                    if($Canonical) {
                        $Domain = $Canonical.split("/")[0]
                    }
                    else {
                        Write-Warning "Error resolving SID '$SID'"
                        return $Null
                    }
                }
            }
            catch {
                Write-Warning "Error resolving SID '$SID' : $_"
                return $Null
            }
        }

        $ObjectSearcher = Get-DomainSearcher -Domain $Domain -DomainController $DomainController -ADSpath $ADSpath -PageSize $PageSize

        if($ObjectSearcher) {

            if($SID) {
                $ObjectSearcher.filter = "(&(objectsid=$SID)$Filter)"
            }
            elseif($Name) {
                $ObjectSearcher.filter = "(&(name=$Name)$Filter)"
            }
            elseif($SamAccountName) {
                $ObjectSearcher.filter = "(&(samAccountName=$SamAccountName)$Filter)"
            }

            $ObjectSearcher.FindAll() | Where-Object {$_} | ForEach-Object {
                if($ReturnRaw) {
                    $_
                }
                else {
                    # convert/process the LDAP fields for each result
                    Convert-LDAPProperty -Properties $_.Properties
                }
            }
        }
    }
}

function Get-NetForestDomain {
<#
    .SYNOPSIS

        Return all domains for a given forest.

    .PARAMETER Forest

        The forest name to query domain for.

    .PARAMETER Domain

        Return domains that match this term/wildcard.

    .EXAMPLE

        PS C:\> Get-NetForestDomain

    .EXAMPLE

        PS C:\> Get-NetForestDomain -Forest external.local
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest,

        [String]
        $Domain
    )

    process {
        if($Domain) {
            # try to detect a wild card so we use -like
            if($Domain.Contains('*')) {
                (Get-NetForest -Forest $Forest).Domains | Where-Object {$_.Name -like $Domain}
            }
            else {
                # match the exact domain name if there's not a wildcard
                (Get-NetForest -Forest $Forest).Domains | Where-Object {$_.Name.ToLower() -eq $Domain.ToLower()}
            }
        }
        else {
            # return all domains
            $ForestObject = Get-NetForest -Forest $Forest
            if($ForestObject) {
                $ForestObject.Domains
            }
        }
    }
}

function Get-NetForest {
<#
    .SYNOPSIS

        Returns a given forest object.

    .PARAMETER Forest

        The forest name to query for, defaults to the current domain.

    .EXAMPLE
    
        PS C:\> Get-NetForest -Forest external.domain
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Forest
    )

    process {
        if($Forest) {
            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Forest', $Forest)
            try {
                $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            catch {
                Write-Debug "The specified forest $Forest does not exist, could not be contacted, or there isn't an existing trust."
                $Null
            }
        }
        else {
            # otherwise use the current forest
            $ForestObject = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

        if($ForestObject) {
            # get the SID of the forest root
            $ForestSid = (New-Object System.Security.Principal.NTAccount($ForestObject.RootDomain,"krbtgt")).Translate([System.Security.Principal.SecurityIdentifier]).Value
            $Parts = $ForestSid -Split "-"
            $ForestSid = $Parts[0..$($Parts.length-2)] -join "-"
            $ForestObject | Add-Member NoteProperty 'RootDomainSid' $ForestSid
            $ForestObject
        }
    }
}

