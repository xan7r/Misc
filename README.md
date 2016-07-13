# Misc

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
