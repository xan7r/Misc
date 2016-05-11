# Misci
Invoke-Mimikatz.ps1 - Small modifications so its compatible with Cobalt Strike's Beacon. Original source: https://github.com/PowerShellEmpire/Empire/blob/master/data/module_source/credentials/Invoke-Mimikatz.ps1
* Removed Architecture mismatch error
* Removed 32/64-bit Mimikatz code in order to get around Cobalt Strike's 1MB upload size limitation with powershell-import
