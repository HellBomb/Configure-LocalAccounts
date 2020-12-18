Function Configure-LocalAccounts {
    <#
        .SYNOPSIS
            Used in combination with LAPS to ensure the local account is properly configured and available and a system is not rendered inoperable. 

        .DESCRIPTION
            
        .PARAMETER LocalAccount
            [String] The name of the local admin account to be configured.

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
        [Bool]$UpdateDescription,
        [Switch]$AuditAccounts
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

    Function Update-User {
        PARAM(
            [String]$Username,
            $RemoveFlags,
            $AddFlags,
            [String]$Description,
            [String]$Name,
            [String]$FullName,
            [String]$SetPassword,
            [Switch]$SetRandomPassword,
            [Switch]$CreateIfNot
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

        $ADSI = [ADSI]"WinNT://$Env:ComputerName"
        $LocalUsers = ($ADSI.children |Where-Object {$_.schemaclassname -eq 'user'} |Select name).name

        IF ($LocalUsers -contains $Username) {
            $User = [ADSI]"WinNT://$env:computername/$userName,user"
        } ElseIF ($LocalUsers -NotContains $Username -AND $CreateIfNot) {
            $User = $ADSI.Create("User",$Username)
            [Bool]$SetPassword = $True
        }

        If ($SetPassword) {
            $User.SetPassword(([char[]](Get-Random -Input $(33..38 + 48..57 + 65..90 + 97..122) -Count 127)) -join "")
        }

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

        #Set NonFlag based options.
        IF ($Description) {$User.Description=$Description}
        IF ($FullName) {$User.FullName=$FullName}
        IF ($Name) {$User.Name=$Name}
        IF ($SetRandomPassword) {$User.SetPassword(([char[]](Get-Random -Input $(33..38 + 48..57 + 65..90 + 97..122) -Count 127)) -join "")}

        #Commit non-flag based changes
        $User.SetInfo()

        IF ($SetPassword) {
            $User.SetPassword($SetPassword)
            $User.SetInfo()
        }
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
        $ScriptEnv.RunMethod = 'ISE'
        $ScriptEnv.ScriptDir = Split-Path $psISE.CurrentFile.FullPath
        $ScriptEnv.ScriptFullName = $psISE.CurrentFile.FullPath
    } ElseIF (Test-Path -Path Variable:pseditor) {
        #Running as VSCode
        $ScriptEnv.RunMethod = 'VSCode'
        $ScriptEnv.ScriptDir = Split-Path $pseditor.GetEditorContext().CurrentFile.Path
        $ScriptEnv.ScriptFullName = $pseditor.GetEditorContext().CurrentFile.Path
    } Else {
        #Running as AzureDevOps or Powershell
        $ScriptEnv.RunMethod = 'ADPS'
        IF ($Host.Version.Major -GE 3) {
            $ScriptEnv.ScriptDir = $PSScriptRoot
            $ScriptEnv.ScriptFullName = $PSCommandPath
        } Else {
            $ScriptEnv.ScriptDir = split-path -parent $MyInvocation.MyCommand.Definition
            $ScriptEnv.ScriptFullName = $MyInvocation.MyCommand.Definition
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
        }
    }

    #--------------------------------------------------------- [Main Script] ---------------------------------------------------------




    #-------------------------------------------------------- [End of Script] --------------------------------------------------------
    Remove-Variable -Name @("ScriptConfig","ScriptEnv") -ErrorAction SilentlyContinue -Force -Verbose:$Verbose
}
Update-ADUserNames


#------------------------------------------------------ [Notes & Misc Code] ------------------------------------------------------
