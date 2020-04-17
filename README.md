# Miscellaneous Pen Testing Scripts


## SaveTickets.cna
Cobalt Strike aggressor script that integrates with [Rubeus](https://github.com/GhostPack/Rubeus), [kekeo](https://github.com/gentilkiwi/kekeo), and [mimikatz](https://github.com/gentilkiwi/mimikatz) to automatically save kerberos tickets and certificate files to operator's workstation.  Currently designed to parse output from the following modules:

**Rubeus:**
* dump
* tgtdeleg
* monitor
* asktgt
* asktgs
* renew
* tgssub
* kerberoast
* asreproast

**kekeo:**
* tgt::asreq
* tgt::ask
* tgt::deleg
* tgs::ask

**mimikatz:**
* crypto::certificates
* crypto::scauth
* kerberos::list
* sekurlsa::tickets

Kerberos tickets from Rubeus will be saved in binary format to /opt/tickets/\<date\>/\<ticketName\>.kirbi and in base64 format to /opt/tickets/\<date\>/tickets.txt.  Kirbi file can be used directly from `kerberos_ticket_use` command.  

All kekeo and mimikatz output (e.g. musti and pfx files) will be saved in binary format to /opt/tickets/\<filename\> and in base64 format to /opt/tickets/\<date\>/tickets.txt.  

This script also adds the following commands to Cobalt Strike:
* saveTGTall - Runs Rubeus command `dump /service:krbtgt`
* saveTGTdeleg - Runs Rubeus command `tgtdeleg`
* monitorTGT - Runs Rubeus command `monitor /interval:1`
* loadTickets - Opens dialog box to select kirbi files.  Runs `kerberos_ticket_purge`, `rev2self`, then `kerberos_ticket_use <selected tickets>`  

**Note:** These commands require a compiled version of Rubeus saved at /opt/Rubeus.exe (or other location if $RUBEUSLOCATION is modified).  

SaveTickets.cna was tested with Rubeus version **1.5.0**, kekeo version **2.2.0-20191201**, and mimikatz version **2.2.0 20200208**.  Use SaveTickets-v1.4.cna for compaitiblity with older versions of Rubeus.  This is due to changes in the output of the dump and monitor modules in Rubeus 1.5.0  


## Export-TGT_Rubeus.cna
Cobalt Strike aggressor script that automates exporting a user's Ticket Granting Ticket on initial beacon checkin.  All tickets will be saved locally to the operator's workstation.  Note: This uses the Rubeus tgtdeleg module, which attempts to obtain usable TGT without elevation by requesting Service Ticket for host with unconstrained delegation enabled (default is domain controller).

Instructions:
1. Compile Rubeus and place at /opt/Rubeus.exe (or other location and modify $RUBEUSLOCATION in Export-TGT_Rubeus.cna)  
2. Load BOTH SaveTickets.cna and Export-TGT_Rubeus.cna  
3. As beacons come in, the Rubeus tgtdeleg command will be run and tickets will be saved to /opt/tickets/ (or other location if $TICKETSFILEPATH in SaveTickets.cna is changed)  
4. Use ticket with either command:  
&nbsp;&nbsp;&nbsp;&nbsp;`loadTickets`  
&nbsp;&nbsp;&nbsp;&nbsp;`kerberos_ticket_use /opt/cobaltstrike/<ticket>.kirbi`   


## alwaysInstallElevated.wxs
Template that can be used for abusing window's AlwaysInstallElevated policy

Instructions:  
1. Change the first "ExeCommand" variable to desired command  
2. Download the WiX Toolset Binaries  
3. Compile alwaysInstallElevated.msi by running:  
&nbsp;&nbsp;&nbsp;&nbsp;`candle alwaysInstallElevated.wxs`  
&nbsp;&nbsp;&nbsp;&nbsp;`light alwaysInstallElevated.wixobj`  
4. Execute on target by running:  
&nbsp;&nbsp;&nbsp;&nbsp;`alwaysInstallElevated.msi /q`  


## FindLastLogon.ps1
Identifies last location that user has logged in via Windows Event Logs.  Requires DA privileges.

All AD helper functions used in this module were copied from Powerview.ps1 found at https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1


## WMILogonBackdoor.ps1
Creates a persistent backdoor using WMI subscriptions.  Backdoor payload can be either stageless (stored in registry) or staged (HTTP(s) download cradle).  Payload will be executed whenever any user logs in or when process svchost.exe starts. Requires high integrity context to run.

This module was heavily based on the code from https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Persistence/Persistence.psm1 and https://raw.githubusercontent.com/xorrior/RandomPS-Scripts/master/WMIBackdoor.ps1


## Invoke-Mimikatz.ps1
Small modifications so its compatible with Cobalt Strike's beacon. 

Original source: https://github.com/PowerShellEmpire/Empire/blob/master/data/module_source/credentials/Invoke-Mimikatz.ps1
* Removed Architecture mismatch error
* Removed 32/64-bit Mimikatz code in order to get around Cobalt Strike's 1MB upload size limitation with powershell-import


## Export-TGT_powershell.cna/Export-TGT_standalone - NOW DEPRECIATED (use Export-TGT_Rubeus.cna instead)
Cobalt Strike aggressor script that automates exporting a user's Ticket Granting Ticket on initial beacon checkin.  All tickets will be saved locally to the operator's workstation in the cobaltstrike directory.  Note: This will not work in all environments since it requires the registry value HKLM:System\CurrentControlSet\Control\Lsa\Kerberos\Parameters\allowtgtsessionkey to be set to 1 on the victim host (registry value does not exist by default).

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
