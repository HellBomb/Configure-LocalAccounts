<#
    .SYNOPSIS
            

    .DESCRIPTION
            
    .PARAMETER 

    .PARAMETER Confirm
        [Int] Determine what type of changes should be prompted before executing.
            0 - Confirm both environment and object changes.
            1 - Confirm only object changes. (Default)
            2 - Confirm nothing!
            Object Changes are changes that are permanent such as file modifications, registry changes, etc.
            Environment changes are changes that can normally be restored via restart, such as opening/closing applications.
        
    .PARAMETER AuditAccounts
        [Switch] Will display a excel like report of users who need additional information because the script can process them.

    .PARAMETER Debugger
        [Int] Used primarily to quickly apply multiple arguments making script development and debugging easier. Useful only for developers.
            1. Incredibly detailed play-by-play execution of the script. Equivilent to '-Change 0',  '-LogLevel Verbose', script wide 'ErrorAction Stop', 'Set-StrictMode -latest', and lastly 'Set-PSDebug -Trace 1'
            2. Equivilent to '-Change 0', '-LogLevel Verbose', and script wide 'ErrorAction Stop'.
            3. Equivilent to '-Change 1', '-LogLevel Info', and enables verbose on PS commands.

    .PARAMETER LogLevel
        [String] Used to display log output with definitive degrees of verboseness. 
            Verbose = Display everything the script is doing with extra verbose messages, helpful for debugging, useless for everything else.
            Debug   = Display all messages at a debug or higher level, useful for debugging.
            Info    = Display all informational messages and higher. (Default)
            Warn    = Display only warning and error messages.
            Error   = Display only error messages.
            None    = Display absolutely nothing.

    .INPUTS
        None

    .OUTPUTS
        None

    .NOTES
    VERSION     DATE			NAME						DESCRIPTION
	___________________________________________________________________________________________________________
	1.0         28 Sept 2020	Warilia, Nicholas R.		Initial version
    2.0         08 Oct 2020 	Warilia, Nicholas R.		Applied standard PS framework, skipped disabled user accounts, added 
                                                            description modification for site 11, and only uses description if it
                                                            starts with "site [0-9]+"
        
    Script tested on the following Powershell Versions
        1.0   2.0   3.0   4.0   5.0   5.1 
    ----- ----- ----- ----- ----- -----
        X    X      X     X     X      v

    Credits:
        (1) Script Template: https://gist.github.com/9to5IT/9620683

    To Do List:
        (1) Get Powershell Path based on version (stock powershell, core, etc.)
#>

[CmdletBinding(
    ConfirmImpact="None",
    DefaultParameterSetName="Default",
    HelpURI="",
    SupportsPaging=$False,
    SupportsShouldProcess=$False,
    PositionalBinding=$True
)] Param (
    [ValidateSet(0,1,2)]
    [Int]$Confim = 1,
    [ValidateSet(0,1,2)]
    [Int]$Debugger = 3,
    [ValidateSet("Verbose","Debug","Info","Warn","Error","Fatal","Off")]
    [String]$LogLevel = "Info",
    [Switch]$WhatIf,
    [String]$LocalAdmin = "CST2Admin"
)

# ---------------------------------------------------- [Manual Configuration] ----------------------------------------------------
#Require Admin Privilages.
New-Variable -Name ScriptConfig -Force -ErrorAction Stop -value @{
    #Should script enforce running as admin.
    RequireAdmin = $False
}

#------------------------------------------------------ [Required Functions] -----------------------------------------------------
#Settting requirements to run the script can help ensure script execution consistency.
#About #Requires: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_requires?view=powershell-5.1
#Requires -Version 5.1
#Requires -PSEdition Desktop

Function New-Password {
    PARAM(
        [Int]$PasswordLength            = 127,
        [Int]$MinUpperCase              = 5,
        [Int]$MinLowerCase              = 5,
        [Int]$MinSpecialCharacters      = 5,
        [Int]$MinNumbers                = 5,
        [Int]$ConsecutiveCharClass      = 0,
        [Int]$ConsecutiveCharCheckCount = 100,
        [String]$LowerCase              = 'abcdefghiklmnoprstuvwxyz',
        [String]$UpperCase              = 'ABCDEFGHKLMNOPRSTUVWXYZ',
        [String]$Numbers                = '1234567890',
        [String]$SpecialCharacters      = '!"$%&/()=?}][{@#*+'
    )

    #Define default special characters
    New-Variable -Name CharacterClasses -Force -Value ([PSCustomObject]@{
        LowerCase         = $LowerCase
        UpperCase         = $UpperCase
        Numbers           = $Numbers
        SpecialCharacters = $SpecialCharacters
        CombinedClasses   = $LowerCase,$UpperCase,$Numbers,$SpecialCharacters -join ''
    })
    
    $CreatePassword = [scriptblock]::Create({
        New-Variable -Name NewPassword -Value ([System.Text.StringBuilder]::new()) -Force

        #Meet the minimum requirements for each character class
        ForEach ($CharacterClass in @("MinUpperCase","MinLowerCase","MinSpecialCharacters","MinNumbers")) {
            New-Variable -name Characters -Force -Value @{
                Class = $CharacterClass.SubString(3) -As [String]
                Characters = $CharacterClasses.($CharacterClass.SubString(3)) -As [String]
                MinCharacters = (Get-Variable $CharacterClass -ValueOnly) -as [Int]
            }
            If (-Not [String]::IsNullOrEmpty($Characters.Characters)) {
                If ($Characters.MinCharacters -gt 0) {
                    $Chars = 1..$($Characters.MinCharacters) | ForEach-Object {Get-Random -Maximum $Characters.Characters.length}
                    [void]$NewPassword.Append(([String]$Characters.Characters[$Chars] -replace " ",""))
                }
            }
        }
    
        #Now meet the minimum length requirements.
        $Chars = 1..($PasswordLength - $NewPassword.Length) |ForEach-Object {Get-Random -Maximum $CharacterClasses.CombinedClasses.length}
        [void]$NewPassword.Append(([String]$CharacterClasses.CombinedClasses[$Chars] -replace " ",""))
        
        $FinalPassword = ([Char[]]$NewPassword.ToString() | Sort-Object {Get-Random}) -join ""
        Return $FinalPassword
    })
    
    Switch ([Int]$ConsecutiveCharClass) {
        '0' { New-Variable -Name NewPassword -Value (& $CreatePassword) -Force }
        '1' { 
            Write-Warning Testing
            Write-Host test
        }
        {$_ -ge 2} {
            New-Variable -Name CheckPass -Value $False -Force
            New-Variable -Name CheckCount -Value ([Int]0) -Force
            While ($CheckCount -lt $ConsecutiveCharCheckCount -AND $CheckPass -eq $False) {
                New-Variable -Name NewPassword -Value (& $CreatePassword) -Force
                ForEach ($CharacterClass in ("LowerCase","UpperCase","Numbers","SpecialCharacters")) {
                    IF (-Not [String]::IsNullOrEmpty($CharacterClasses.$CharacterClass)) {                      
                        #The Actual Check
                        if ($NewPassword -cmatch "([$([Regex]::Escape([char[]]($CharacterClasses.$CharacterClass) -join ","))]{$ConsecutiveCharClass,})" -eq $True) {
                            $CheckCount++
                            break
                        }
                        $CheckPass = $True
                    }
                }
            }
            If ($CheckPass -eq $False) {
                Write-Warning -Message "Unable to find a password combination that meets ConsecutiveCharCheck requirements."
                Remove-Variable -Name NewPassword -Force
            }
        }
        Default {Write-Warning -Message "This shouldn't be possible, how did you get here?!"}
    }
    Return $NewPassword
}
Function Add-LocalGroup {
    Param(
        [String]$user,
        [String]$Group
    )

    New-Variable -name ADSI -value (([ADSI]"WinNT://$($ENV:ComputerName),computer").psbase.children) -Force -ErrorAction Stop

    #Get Local Accounts
    New-Variable -Name LocalAccounts -Value (New-Object System.Collections.ArrayList) -Force -ErrorAction Stop
    $ADSI | Where-Object {$_.schemaClassName -match "user"} | foreach-object {
        [Void]$LocalAccounts.add([PSCustomObject]@{
            Name                       = $_.name.value -as [string]
            FullName                   = $_.fullName.value -as [string]
            Description                = $_.Description.value -as [string]
            PasswordAge                = $_.PasswordAge.value -as [string]
            BadPasswordAttempts        = $_.BadPasswordAttempts.value -as [int]
            HomeDirectory              = $_.HomeDirectory.value -as [System.IO.DirectoryInfo]
            LoginScript                = $_.LoginScript.value -as [System.IO.fileInfo]
            Profile                    = $_.Profile.value -as [System.IO.DirectoryInfo]
            HomeDirDrive               = $_.HomeDirDrive.value -as [System.IO.DirectoryInfo]
            PrimaryGroupID             = $_.PrimaryGroupID.value -as [Int]
            MinPasswordLength          = $_.MinPasswordLength.value -as [Int]
            MaxPasswordAge             = "$((New-TimeSpan -Seconds ([Int]$_.MaxPasswordAge.Value)).days) Days"
            MinPasswordAge             = "$((New-TimeSpan -Seconds ([Int]$_.MinPasswordAge.Value)).days) Days"
            PasswordHistoryLength      = $_.PasswordHistoryLength.value -as [Int]
            AutoUnlockInterval         = "$((New-TimeSpan -Seconds ([Int]$_.AutoUnlockInterval.Value)).days) Minutes"
            LockoutObservationInterval = "$((New-TimeSpan -Seconds ([Int]$_.LockoutObservationInterval.Value)).days) Minutes"
            MaxBadPasswordsAllowed     = $_.MaxBadPasswordsAllowed.value -as [Int]
            SID                        = (New-Object System.Security.Principal.SecurityIdentifier($_.objectSid.value,0)).Value -as [String]
        })
    }
    
    #Get target user object.
    New-Variable -Name TargetUser -value ($LocalAccounts.Where({$_.name -eq $user})) -Force
    
    #If the user doesn't exist throw an error.
    If ([String]::IsNullOrEmpty($TargetUser.name) -eq $True) {
        Write-Warning -Message "Error: User doesn't exist."
        break
    }

    #Get list of local accounts.
    New-Variable -Name LocalGroups   -Force -Value (New-Object System.Collections.ArrayList) -ErrorAction Stop
    New-Variable -Name GroupTypes    -Force -Value @{"2" = "Global";"4" = "DomainLocal";"8" = "Universal"}
    New-Variable -Name GroupLocation -Force -Value @{"$env:USERDOMAIN" = "Domain";"NT AUTHORITY" = "Local";"$ENV:COMPUTERNAME" = "Local"}
    $ADSI | Where-Object {$_.schemaClassName -match "group"} |select -Skip 1 | foreach-object {
        New-Variable -Name CurrentGroup -Force -Value ([PSCustomObject]@{
            Name                       = $_.name.value -as [string]
            GroupType                  = $GroupTypes["$($_.GroupType.value)"] -As [String]
            Description                = $_.Description.value -as [string]
            SID                        = (New-Object System.Security.Principal.SecurityIdentifier($_.objectSid.value,0)).Value -as [String]            
            Members                    = New-Object System.Collections.ArrayList
        })
        ([ADSI]$_.psbase.Path).psbase.Invoke("Members") | ForEach-Object {
            [void]$CurrentGroup.Members.Add([PSCustomObject]@{
                Name      = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                SID       = (New-Object System.Security.Principal.SecurityIdentifier($_.GetType().InvokeMember("ObjectSID", 'GetProperty', $null, $_, $null),0)).value
                ADsPath   = $_.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $_, $null)
                GroupType = $GroupLocation["$($_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null).split('/')[2])"]
            })
        }
        [Void]$LocalGroups.Add($CurrentGroup)
    }

    #Get target group object.
    New-Variable -Name TargetGroup -value ($LocalGroups.where({$_.name -eq $Group})) -Force

    #If the group doesn't exist throw an error.
    If ([String]::IsNullOrEmpty($LocalGroups.name) -eq $True) {
        Write-Warning -Message "Error: Group doesn't exist."
        break
    } ElseIF ($TargetGroup.Members.count -gt 0 -and $TargetGroup.Members.sid.Contains($TargetUser.sid) -eq $True) {
        Write-information -MessageData "User already a member of this group."
        break
    } Else {
        ([ADSI]"WinNT://$($ENV:ComputerName)/$($TargetGroup.Name),group").psbase.Invoke("Add",([ADSI]"WinNT://$($ENV:ComputerName)/$($TargetUser.Name),User").path)
    }
    Remove-Variable -name @("$user","$Group","ADSI","LocalAccounts","TargetUser","LocalGroups","GroupTypes","GroupLocation","CurrentGroup","TargetGroup") -Force -ErrorAction SilentlyContinue
}

Function Update-User {
    PARAM(
        [String]$Username,
        $RemoveFlags,
        $AddFlags,
        [String]$Description,
        [String]$Name,
        [String]$FullName,
        [Switch]$SetRandomPassword,
        [Switch]$CreateIfNot,
        [Switch]$BuiltInAdmin,
        [Switch]$BuiltInGuest
    )
 
    <#
        $SCRIPT=1
        $ACCOUNTDISABLE=2
        $HOMEDIR_REQUIRED=8
        $LOCKOUT=16
        $PASSWD_NOTREQD=32
        $PASSWD_CANT_CHANGE=64
        $ENCRYPTED_TEXT_PASSWORD_ALLOWED=128
        $TEMP_DUPLICATE_ACCOUNT=256
        $NORMAL_ACCOUNT=512
        $INTERDOMAIN_TRUST_ACCOUNT=2048
        $WORKSTATION_TRUST_ACCOUNT=4096
        $SERVER_TRUST_ACCOUNT=8192
        $DONT_EXPIRE_PASSWD=65536
        $MNS_LOGON_ACCOUNT=131072
        $SMARTCARD_REQUIRED=262144
        $TRUSTED_FOR_DELEGATION=524288
        $NOT_DELEGATED=1048576
        $USE_DES_KEY_ONLY=2097152
        $DONT_REQUIRE_PREAUTH=4194304
        $PASSWORD_EXPIRED=8388608
        $TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION=16777216
    #>
    
    New-Variable -name ADSI -value ([ADSI]"WinNT://$($ENV:ComputerName),computer") -Force -ErrorAction Stop
    New-Variable -Name LocalAccounts -Value (New-Object System.Collections.ArrayList) -Force -ErrorAction Stop
    $ADSI.psbase.children | Where-Object {$_.schemaClassName -match "user"} | foreach-object {
        [Void]$LocalAccounts.add([PSCustomObject]@{
            Name                       = $_.name.value -as [string]
            FullName                   = $_.fullName.value -as [string]
            Description                = $_.Description.value -as [string]
            PasswordAge                = $_.PasswordAge.value -as [string]
            BadPasswordAttempts        = $_.BadPasswordAttempts.value -as [int]
            HomeDirectory              = $_.HomeDirectory.value -as [System.IO.DirectoryInfo]
            LoginScript                = $_.LoginScript.value -as [System.IO.fileInfo]
            Profile                    = $_.Profile.value -as [System.IO.DirectoryInfo]
            HomeDirDrive               = $_.HomeDirDrive.value -as [System.IO.DirectoryInfo]
            PrimaryGroupID             = $_.PrimaryGroupID.value -as [Int]
            MinPasswordLength          = $_.MinPasswordLength.value -as [Int]
            MaxPasswordAge             = "$((New-TimeSpan -Seconds ([Int]$_.MaxPasswordAge.Value)).days) Days"
            MinPasswordAge             = "$((New-TimeSpan -Seconds ([Int]$_.MinPasswordAge.Value)).days) Days"
            PasswordHistoryLength      = $_.PasswordHistoryLength.value -as [Int]
            AutoUnlockInterval         = "$((New-TimeSpan -Seconds ([Int]$_.AutoUnlockInterval.Value)).days) Minutes"
            LockoutObservationInterval = "$((New-TimeSpan -Seconds ([Int]$_.LockoutObservationInterval.Value)).days) Minutes"
            MaxBadPasswordsAllowed     = $_.MaxBadPasswordsAllowed.value -as [Int]
            SID                        = (New-Object System.Security.Principal.SecurityIdentifier($_.objectSid.value,0)).Value -as [String]
        })
    }
    
    #Check to ensure that one of the required variables has a usable value.
    If ($BuiltInAdmin -eq $False -and $BuildInGuest -and [String]::IsNullOrWhiteSpace($Username)) {
        Write-Warning -Message 'Need to select either $BuildInAdmin or provide a username.'
        Break
    }

    #If user selected '-BuiltInAdmin' argument, set target user to the local built-in administrator.
    If ($BuiltInAdmin -eq $True) {
        Set-Variable -Name Username -Value ($LocalAccounts.where({$_.SID -like "S-1-5-*-500"})).name -Force
    }

    #If user selected '-BuiltInAdmin' argument, set target user to the local built-in administrator.
    If ($BuiltInGuest -eq $True) {
        Set-Variable -Name Username -Value ($LocalAccounts.where({$_.SID -like "S-1-5-*-501"})).name -Force
    }

    #Determine if the account exists and determine what actions to take from there.
    $TargetAccount = $LocalAccounts.Where({$_.Name -eq $Username})
    IF ([String]::IsNullOrEmpty($TargetAccount.name)) {
        IF ($CreateIfNot) {
            $User = $ADSI.Create("User",$Username)
            [Bool]$SetRandomPassword = $True
        } Else {
            Write-Warning -Message 'User, $username, does not exist. Use -CreateIfNot switch to create new accounts.'
        }
    } Else {
        $User = [ADSI]"WinNT://$env:computername/$($TargetAccount.name),user"
    }

    #Set NonFlag based options.
    IF ($Description) {$User.Description=$Description}
    IF ($FullName) {$User.FullName=$FullName}
    IF ($Name) {$User.Name=$Name}
    IF ($SetRandomPassword) {$User.SetPassword((New-Password))}

    #Commit non-flag based changes
    $User.SetInfo()

    #Add Flags
    ForEach ($Flag in $AddFlags) {
        $User.invokeSet("userFlags", ($User.userFlags[0] -BOR $flag))
    }

    #Remove Flag Attributes
    ForEach ($Flag in $RemoveFlags) {
        $FlagInt = [int]$Flag
        if ($User.UserFlags[0] -BAND $FlagInt) {
            $User.invokeSet("userFlags", ($User.userFlags[0] -BXOR $FlagInt))
        }
    }

    #Commit flag based changes
    $User.commitChanges()
}

#----------------------------------------------- [Initializations & Prerequisites] -----------------------------------------------

#Determine the Log Output Level
Switch ($LogLevel) {
    "Verbose" {$DebugPreference = 'Continue'        ; $VerbosePreference = 'Continue'        ; $InformationPreference = 'Continue'        ; $WarningPreference = 'Continue'        ; $ErrorPreference = 'Continue'        }
    "Debug"   {$DebugPreference = 'Continue'        ; $VerbosePreference = 'SilentlyContinue'; $InformationPreference = 'Continue'        ; $WarningPreference = 'Continue'        ; $ErrorPreference = 'Continue'        }
    "Info"    {$DebugPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue'; $InformationPreference = 'Continue'        ; $WarningPreference = 'Continue'        ; $ErrorPreference = 'Continue'        }
    "Warn"    {$DebugPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue'; $InformationPreference = 'SilentlyContinue'; $WarningPreference = 'Continue'        ; $ErrorPreference = 'Continue'        }
    "Error"   {$DebugPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue'; $InformationPreference = 'SilentlyContinue'; $WarningPreference = 'SilentlyContinue'; $ErrorPreference = 'Continue'        }
    "Off"     {$DebugPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue'; $InformationPreference = 'SilentlyContinue'; $WarningPreference = 'SilentlyContinue'; $ErrorPreference = 'SilentlyContinue'}
}

#Converts Verbose Prefernce to bool so it can be used in "-Verbose:" arguments.
$Verbose = ($VerbosePreference -eq 'Continue')

#Set Set Debug Level
Switch ($Debugger) {
    0 { $ConfimEnv = $True ;  $ConfirmChg = $True;  $Verbose = $True; $InformationPreference = 'Continue'; $ErrorActionPreference = 'Stop'; $VerbosePreference = 'Continue'; $DebugPreference = 'Continue'; Set-StrictMode -Version Latest; Set-PsDebug -Trace 1}
    1 { $ConfimEnv = $True ;  $ConfirmChg = $True;  $Verbose = $True; $InformationPreference = 'Continue'; $ErrorActionPreference = 'Stop'; $VerbosePreference = 'Continue'}
    2 { $ConfimEnv = $False ; $ConfirmChg = $False; $Verbose = $True; $InformationPreference = 'Continue'}
}

Switch ($Confirm) {
    0 {$ConfimEnv = $True;  $ConfirmChg = $True}
    1 {$ConfimEnv = $False; $ConfirmChg = $True}
    2 {$ConfimEnv = $False; $ConfirmChg = $False}
}

#Variable used to store certain sometimes useful script related information.
New-Variable -Name ScriptEnv -Force -ErrorAction Stop -Verbose:$Verbose -value @{
    RunMethod      = [String]::Empty
    Interactive    = [Bool]$([Environment]::GetCommandLineArgs().Contains('-NonInteractive') -or ([Environment]::UserInteractive -EQ $False))
    IsAdmin        = [Bool]$((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    Parameters     = New-Object -TypeName "System.Text.StringBuilder"
    ScriptDir      = [String]::Empty
    ScriptFullName = [String]::Empty
    Powershellpath = "$($env:windir)\System32\WindowsPowerShell\v1.0\powershell.exe"
}
    
#Create a proper parameter string.
ForEach ($Parameter in $Script:PSBoundParameters.GetEnumerator()) {
    [void]$ScriptEnv.Parameters.Append(" -$($Parameter.key): ""$($Parameter.Value)""")
}

#Determine The Environment The Script is Running in.
IF (Test-Path Variable:PSise) {
    #Running as PSISE
    [String]$ScriptEnv.RunMethod = 'ISE'
    [System.IO.DirectoryInfo]$ScriptEnv.ScriptDir = Split-Path $psISE.CurrentFile.FullPath
    [System.IO.DirectoryInfo]$ScriptEnv.ScriptFullName = $psISE.CurrentFile.FullPath
} ElseIF (Test-Path -Path Variable:pseditor) {
    #Running as VSCode
    [String]$ScriptEnv.RunMethod = 'VSCode'
    [System.IO.DirectoryInfo]$ScriptEnv.ScriptDir = Split-Path $pseditor.GetEditorContext().CurrentFile.Path
    [System.IO.DirectoryInfo]$ScriptEnv.ScriptFullName = $pseditor.GetEditorContext().CurrentFile.Path
} Else {
    #Running as AzureDevOps or Powershell
    [String]$ScriptEnv.RunMethod = 'ADPS'
    IF ($Host.Version.Major -GE 3) {
        [System.IO.DirectoryInfo]$ScriptEnv.ScriptDir = $PSScriptRoot
        [System.IO.DirectoryInfo]$ScriptEnv.ScriptFullName = $PSCommandPath
    } Else {
        [System.IO.DirectoryInfo]$ScriptEnv.ScriptDir = split-path -parent $MyInvocation.MyCommand.Definition
        [System.IO.DirectoryInfo]$ScriptEnv.ScriptFullName = $MyInvocation.MyCommand.Definition
    }
}
    
#Check if administrator
IF ($ScriptConfig.RequreAdmin -eq $True) {
    IF ($ScriptEnv.IsAdmin -eq $False) {
        Write-Warning -Message 'Warning: Script not running as administrator, relaunching as administrator.'
        IF ($ScriptEnv.RunMethod -eq 'ISE') {
            IF ($psISE.CurrentFile.IsUntitled-eq $True) {
                Write-Error -Message 'Unable to elevate script, please save script before attempting to run.'
                break
            } Else {
                IF ($psISE.CurrentFile.IsSaved -eq $False) {
                    Write-Warning 'ISE Script unsaved, unexpected results may occur.'
                }
            }
        }
        $Process = [System.Diagnostics.Process]::new()
        $Process.StartInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $Process.StartInfo.Arguments = "-NoLogo -ExecutionPolicy Bypass -noprofile -command &{start-process '$($ScriptEnv.Powershellpath)' {$runthis} -verb runas}"
        $Process.StartInfo.FileName = $ScriptEnv.Powershellpath
        $Process.startinfo.WorkingDirectory = $ScriptEnv.ScriptDir
        $Process.StartInfo.UseShellExecute = $False
        $Process.StartInfo.CreateNoWindow  = $True
        $Process.StartInfo.RedirectStandardOutput = $True
        $Process.StartInfo.RedirectStandardError = $False
        $Process.StartInfo.RedirectStandardInput = $False
        $Process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Normal
        $Process.StartInfo.LoadUserProfile = $False
        [Void]$Process.Start()
        [Void]$Process.WaitForExit()
        [Void]$Process.Dispose()
        exit
    }
}

#--------------------------------------------------------- [Main Script] ---------------------------------------------------------
Update-User -BuiltInAdmin -SetRandomPassword -AddFlags "2","16","8388608","262144" -RemoveFlags "32","256","2048","4096","8192","65536","4194304","524288","2097152","16777216"
Update-User -BuiltInGuest -SetRandomPassword -AddFlags "2","16","8388608","262144" -RemoveFlags "32","256","2048","4096","8192","65536","4194304","524288","2097152","16777216"
Update-User -Username $LocalAdmin -RemoveFlags "2","8","16","32","64","65536","262144","8388608" -CreateIfNot
Add-LocalGroup -user $LocalAdmin -Group Administrators
Add-LocalGroup -user $LocalAdmin -Group Users

#-------------------------------------------------------- [End of Script] --------------------------------------------------------
Remove-Variable -Name @("ScriptConfig","ScriptEnv") -ErrorAction SilentlyContinue -Force -Verbose:$Verbose



#------------------------------------------------------ [Notes & Misc Code] ------------------------------------------------------
