# Miscellaneous Pen Testing Scripts

## Invoke-Mimikatz.ps1
Small modifications so its compatible with Cobalt Strike's Beacon. 

Original source: https://github.com/PowerShellEmpire/Empire/blob/master/data/module_source/credentials/Invoke-Mimikatz.ps1
* Removed Architecture mismatch error
* Removed 32/64-bit Mimikatz code in order to get around Cobalt Strike's 1MB upload size limitation with powershell-import


## FindLastLogon.ps1
Identifies last location that user has logged in via Windows Event Logs.  Requires DA privileges.

All AD helper functions used in this module were copied from Powerview.ps1 found at https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1


## WMILogonBackdoor.ps1
Creates a persistent backdoor using WMI subscriptions.  Backdoor payload can be either stageless (stored in registry) or staged (HTTP(s) download cradle).  Payload will be executed whenever any user logs in or when process svchost.exe starts. Requires high integrity context to run.

This module was heavily based on the code from https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Persistence/Persistence.psm1 and https://raw.githubusercontent.com/xorrior/RandomPS-Scripts/master/WMIBackdoor.ps1


## alwaysInstallElevated.wxs
Template that can be used for abusing window's AlwaysInstallElevated Policy

Instructions:  
1. Change the first "ExeCommand" variable to desired command  
2. Download the WiX Toolset Binaries  
3. Compile alwaysInstallElevated.msi by running:  
&nbsp;&nbsp;&nbsp;&nbsp;`candle alwaysInstallElevated.wxs`  
&nbsp;&nbsp;&nbsp;&nbsp;`light alwaysInstallElevated.wixobj`  
4. Execute on target by running:  
&nbsp;&nbsp;&nbsp;&nbsp;`alwaysInstallElevated.msi /q`  


## Export-TGT.cna
Cobalt Strike Aggressor script that automates exporting a user's Ticket Granting Ticket on initial beacon checkin.  All tickets will be saved locally to the operator's workstation in the cobaltstrike directory.  Note: This will not work in all environments since it requires the registry value HKLM:System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\allowtgtsessionkey to be set to 1 on the victim host (registry value does not exist by default).

This script comes in both standalone and PowerShell versions.  The standalone version (recommended) will use Cobalt Strike's built-in mimikatz module to dump tickets, whereas the PowerShell version will load the script Invoke-ExportTGT.ps1 (must be in same directory as Export-TGT_powershell.cna) to run Invoke-Mimikatz and parse the results.

Instructions:  
1. Load either Export-TGT_standalone.cna or Export-TGT_powershell.cna into Cobalt Strike  
2. Receive HTTP(s) beacon callbacks (script purposely will not run over DNS beacons)  
3. Copy valid base64 encoded TGT (found in cobaltstrike directory) into new text file (note time that TGT expires)  
4. Combine base64 encoded ticket into single line (may also need to run `dos2unix`)
5. Base64 decode the ticket:  
&nbsp;&nbsp;&nbsp;&nbsp;`base64 -d ./encodedTicket.txt > ./ticket.kirbi`  
6. Import ticket.kirbi into another beacon if that access is lost:  
&nbsp;&nbsp;&nbsp;&nbsp;`kerberos_ticket_use /opt/cobaltstrike/ticket.kirbi`  
