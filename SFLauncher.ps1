<#
    .SYNOPSIS
        Launch HDX session to a published resource through StoreFront or NetScaler Gateway (integrated with StoreFront).
    .DESCRIPTION

        This script launches an HDX session to a published resource through StoreFront or NetScaler Gateway (integrated with StoreFront).

        It attempts to closely resemble what an actual user would do by:
        -Opening Internet Explorer.
        -Navigating directly to the Receiver for Web site or NetScaler Gateway portal.
        -Completing the fields.
        -Logging in.
        -Clicking on the resource.
        -Logging off the StoreFront site.

        Requirements:
        -Use an Administrator console of PowerShell.
        -SiteURL should be part of the Intranet Zone (or Internet Zone at Medium-Low security) in order to be able to download AND launch the ICA file. This can be done through a GPO.
        -StoreFront 2.0 or higher.
        -If using NetScaler Gateway, version 9.3 or higher.
        -Changes in web.config under C:\inetpub\wwwroot\Citrix\<storename>Web\: autoLaunchDesktop to false, pluginAssistant to false and logoffAction to none.
        -Currently works for desktops or already subscribed apps only. You can auto subscribe users to apps by setting "KEYWORDS:Auto" in the published app's description.

        By default, the script creates a log file with the username like SFLauncher_username.log.
    .PARAMETER SiteURL
        The complete URL of the StoreFront Receiver for Web site or NetScaler Gateway portal.
    .PARAMETER UserName
        The name of the user which is used to log on. Acceptable forms are down-level logon name or user principal name.
    .PARAMETER Password
        The password of the user which is used to log on.
    .PARAMETER ResourceName
        The display name of the resource to be launched.
    .PARAMETER SleepBeforeLogoff
        The time in seconds to sleep after clicking the resource and before logging off. Default is 5.
    .PARAMETER NumberOfRetries
        The number of retries when retrieving an element. Default is 30.
    .PARAMETER LogFilePath
        Directory path to where the log file will be saved. Default is SystemDrive\Temp.
    .PARAMETER LogFileName
        File name for the log file. Default is SFLauncher_<UserName>.log.
    .PARAMETER NoLogFile
        Specify to disable logging to a file.
    .PARAMETER NoConsoleOutput
        Specify to disable logging to the console.
    .PARAMETER TwoFactorAuth
        The token or password used for two-factor authentication. This is used in the NetScaler Gateway portal.
    .EXAMPLE
        SFLauncher.ps1 -SiteURL "http://storefront.domain.com" -UserName "domain1\User1" -Password "P4ssw0rd" -ResourceName "My Desktop"

        Description
        -----------
        Launches a session to a resource using the parameters provided.
    .LINK
        UserName format used in StoreFront.
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa380525(v=vs.85).aspx#down_level_logon_name
    .LINK
        Change to autoLaunchDesktop.
        http://support.citrix.com/proddocs/topic/dws-storefront-20/dws-configure-wr-view.html
    .LINK
        Change to logoffAction.
        http://support.citrix.com/proddocs/topic/dws-storefront-20/dws-configure-wr-workspace.html
    .NOTES
        Copyright (c) Citrix Systems, Inc. All rights reserved.
        Version 1.2
#>

Param (
    [Parameter(Mandatory=$true,Position=0)] [string]$SiteURL,
    [Parameter(Mandatory=$true,Position=1)] [string]$UserName,
    [Parameter(Mandatory=$true,Position=2)] [string]$Password,
    [Parameter(Mandatory=$true,Position=3)] [string]$ResourceName,
    [Parameter(Mandatory=$false)] [int]$SleepBeforeLogoff = 5,
    [Parameter(Mandatory=$false)] [int]$NumberOfRetries = 30,
    [Parameter(Mandatory=$false)] [string]$LogFilePath = "$env:TEMP",
    [Parameter(Mandatory=$false)] [string]$LogFileName = "SFLauncher_$($UserName.Replace('\','_')).log",
    [Parameter(Mandatory=$false)] [switch]$NoLogFile,
    [Parameter(Mandatory=$false)] [switch]$NoConsoleOutput,
    [Parameter(Mandatory=$false)] [string]$TwoFactorAuth
)

Set-StrictMode -Version 2

Set-Variable -Name NGLoginButtonId -Value "Log_On" -Option Constant -Scope Script
Set-Variable -Name NGUserNameTextBoxName -Value "" -Scope Script
Set-Variable -Name NGPasswordTextBoxName -Value "" -Scope Script
Set-Variable -Name NGTwoFactorTextBoxName -Value "passwd1" -Option Constant -Scope Script

Set-Variable -Name SFLoginButtonId -Value "loginBtn" -Option Constant -Scope Script
Set-Variable -Name SFUsernameTextBoxId -Value "username" -Option Constant -Scope Script
Set-Variable -Name SFPasswordTextBoxId -Value "password" -Option Constant -Scope Script
Set-Variable -Name SFLogOffLinkId -Value "userdetails-logoff" -Option Constant -Scope Script

function Write-SFLauncherHeader {
    $infoMessage = @"

                           *****************************************************
                           *****  Citrix Solutions Lab SF Launcher Script  *****
                           *****        -Console output:     {0,-6}        *****
                           *****        -Log output:         {1,-6}        *****
                           *****************************************************

"@  -f $(-not $NoConsoleOutput),$(-not $NoLogFile)
    Write-Host $infoMessage
}

function Write-ToSFLauncherLog {
    Param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)] [string]$Message,
        [Parameter(Mandatory=$false)] [string]$LogFile=$($LogFilePath.TrimEnd('\') + "\$LogFileName"),
        [Parameter(Mandatory=$false)] [bool]$NoConsoleOutput=$NoConsoleOutput,
        [Parameter(Mandatory=$false)] [bool]$NoLogFile=$NoLogFile
    )
    Begin {
        if(Test-Path $LogFile -IsValid) {
            if(!(Test-Path "$LogFile" -PathType Leaf)) {
                New-Item -Path $LogFile -ItemType "file" -Force -ErrorAction Stop | Out-Null
            }
        } else {
            throw "Log file path is invalid"
        }
    }
    Process {
        $Message = [DateTime]::Now.ToString("[MM/dd/yyy HH:mm:ss.fff]: ") + $Message

        if (-not $NoConsoleOutput) {
            Write-Host $Message
        }

        if (-not $NoLogFile) {
            $Message | Out-File -FilePath $LogFile -Append
        }
    }
}

function Wait-ForPageReady {
    while ($internetExplorer.ReadyState -ne 4) {
        Write-ToSFLauncherLog "Internet Explorer: BUSY"
        Start-Sleep 1
    }
}

function Open-InternetExplorer {
    Param (
        [Parameter(Mandatory=$true)] [string]$SiteURL
    )
    Write-ToSFLauncherLog "Creating Internet Explorer COM object"
    New-Variable -Name internetExplorer -Value (New-Object -ComObject "InternetExplorer.Application") -Scope Script
    Write-ToSFLauncherLog "Setting Internet Explorer visible"
    $internetExplorer.visible = $true
    Write-ToSFLauncherLog "Navigating to '$SiteURL'"
    $internetExplorer.Navigate2($SiteURL)
    Wait-ForPageReady
    Write-ToSFLauncherLog "Accessing DOM"
    New-Variable -Name document -Value $internetExplorer.Document -Scope Script
}

function Test-LoginForm {
    Write-ToSFLauncherLog "Detecting NetScaler Gateway or StoreFront login form..."
    $loginButton = $null
    $try = 1
    do {
        $NGloginButton = [System.__ComObject].InvokeMember(“getElementById”,[System.Reflection.BindingFlags]::InvokeMethod, $null, $document, $NGLoginButtonId)
        $SFloginButton = [System.__ComObject].InvokeMember(“getElementById”,[System.Reflection.BindingFlags]::InvokeMethod, $null, $document, $SFLoginButtonId)
        if ($NGloginButton -ne $null -and $NGloginButton.GetType() -ne [DBNull]) {
            "Try #$try`: SUCCESS","NETSCALER GATEWAY DETECTED" | Write-ToSFLauncherLog
            New-Variable -Name isNG -Value $true -Scope Script
            $loginButton = $NGloginButton
            break
        } elseif ($SFloginButton -ne $null -and $SFloginButton.GetType() -ne [DBNull]) {
            "Try #$try`: SUCCESS","STOREFRONT DETECTED" | Write-ToSFLauncherLog
            New-Variable -Name isNG -Value $false -Scope Script
            $loginButton = $SFloginButton
            break
        } else {
            Write-ToSFLauncherLog "Try #$try`: FAIL"
            Start-Sleep -Seconds 1
            $try++
        }
    } until ($try -gt $NumberOfRetries)
    if ($loginButton -eq $null -or $loginButton.GetType() -eq [DBNull]) {
        throw "Login button not found"
    }
}

function Submit-UserCredentials {
    if ($isNG) {
        Write-ToSFLauncherLog "Getting Login button"
        $loginButton = [System.__ComObject].InvokeMember(“getElementById”,[System.Reflection.BindingFlags]::InvokeMethod, $null, $document, $NGLoginButtonId)

        Write-ToSFLauncherLog "Detecting textbox names"
        $start = 0
        $inputs = @([System.__ComObject].InvokeMember(“getElementsByTagName”,[System.Reflection.BindingFlags]::InvokeMethod, $null, $document, "Input"))
        for($x = 0; $x -le $inputs.Length-1; $x++) {
            if($inputs.GetValue($x).ID -cnotlike "dummy*" -and $inputs.GetValue($x).ID -cnotlike "Log*") {
                switch($start) {
                    0{Set-Variable -Name NGUserNameTextBoxName -Value $inputs.GetValue($x).Name -Scope Script}
                    1{Set-Variable -Name NGPasswordTextBoxName -Value $inputs.GetValue($x).Name -Scope Script}
                }
                $start++
            }
        }
        Write-ToSFLauncherLog "Detected UserName textbox name: $NGUsernameTextBoxName"
        Write-ToSFLauncherLog "Detected Password textbox name: $NGPasswordTextBoxName"

        Write-ToSFLauncherLog "Getting UserName textbox"
        $userNameTextBox = @([System.__ComObject].InvokeMember(“getElementsByName”,[System.Reflection.BindingFlags]::InvokeMethod, $null, $document, $NGUserNameTextBoxName)) | where { $_.name -eq $NGUserNameTextBoxName }
        Write-ToSFLauncherLog "Getting Password textbox"
        $passwordTextBox = @([System.__ComObject].InvokeMember(“getElementsByName”,[System.Reflection.BindingFlags]::InvokeMethod, $null, $document, $NGPasswordTextBoxName)) | where { $_.name -eq $NGPasswordTextBoxName }
        if ($TwoFactorAuth) {
            Write-ToSFLauncherLog "Getting Two Factor Authentication textbox"
            $twoFactorTextBox = @([System.__ComObject].InvokeMember(“getElementsByName”,[System.Reflection.BindingFlags]::InvokeMethod, $null, $document, $NGTwoFactorTextBoxName)) | where { $_.name -eq $NGTwoFactorTextBoxName }
                if ($twoFactorTextBox -ne $null) {
                    Write-ToSFLauncherLog "Setting Two Factor Authentication"
                    $twoFactorTextBox.value = $TwoFactorAuth
                } else {
                    throw "Two-factor authentication textbox not found"
                }
        }
    } else {
        Write-ToSFLauncherLog "Getting Login button"
        $loginButton = [System.__ComObject].InvokeMember(“getElementById”,[System.Reflection.BindingFlags]::InvokeMethod, $null, $document, $SFLoginButtonId)
        Write-ToSFLauncherLog "Getting UserName textbox"
        $userNameTextBox = [System.__ComObject].InvokeMember(“getElementById”,[System.Reflection.BindingFlags]::InvokeMethod, $null, $document, $SFUsernameTextBoxId)
        Write-ToSFLauncherLog "Getting Password textbox"
        $passwordTextBox = [System.__ComObject].InvokeMember(“getElementById”,[System.Reflection.BindingFlags]::InvokeMethod, $null, $document, $SFPasswordTextBoxId)
    }

    if ($userNameTextBox -ne $null -and $userNameTextBox.GetType() -ne [DBNull]) {
        Write-ToSFLauncherLog "Setting UserName '$UserName'"
        $userNameTextBox.Value = $UserName
    } else {
        throw "UserName textbox not found"
    }

    if ($passwordTextBox -ne $null -and $passwordTextBox.GetType() -ne [DBNull]) {
        Write-ToSFLauncherLog "Setting Password"
        $passwordTextBox.Value = $Password
    } else {
        throw "Password textbox not found"
    }

    if ($loginButton -ne $null -and $loginButton.GetType() -ne [DBNull]) {
        Write-ToSFLauncherLog "Clicking login button"
        $loginButton.Click()
    } else {
        throw "Login button not found"
    }
}

function Start-Resource {
    Write-ToSFLauncherLog "Getting SF resources page..."
    $try = 1
    do {
        $logoffLink = [System.__ComObject].InvokeMember(“getElementById”,[System.Reflection.BindingFlags]::InvokeMethod, $null, $document, $SFLogOffLinkId)
        if ($logoffLink -ne $null -and $logoffLink.GetType() -ne [DBNull]) {
            Write-ToSFLauncherLog "Try #$try`: SUCCESS"
            break
        } else {
            Write-ToSFLauncherLog "Try #$try`: FAIL"
            Start-Sleep -Seconds 1
            $try++
        }
    } until ($try -gt $NumberOfRetries)
    if ($logoffLink -eq $null -or $logoffLink.GetType() -eq [DBNull]) {
        throw "SF recources page not found"
    }

    Write-ToSFLauncherLog "Getting resource '$ResourceName'..."
    $try = 1
    do {
        $resource = @([System.__ComObject].InvokeMember(“getElementsByTagName”,[System.Reflection.BindingFlags]::InvokeMethod, $null, $document, "img")) | where { $_.alt -eq $ResourceName }
        if ($resource -ne $null) {
            Write-ToSFLauncherLog "Try #$try`: SUCCESS"
            break
        } else {
            Write-ToSFLauncherLog "Try #$try`: FAIL"
            Start-Sleep -Seconds 1
            $try++
        }
    } until ($try -gt $NumberOfRetries)
    if ($resource -eq $null) {
        throw "Resource '$ResourceName' not found"
    }

    $wficaBefore = @()
    Get-Process wfica32 -ErrorAction SilentlyContinue | select id | % { $wficaBefore += $_.id }
    Write-ToSFLauncherLog "Found $($wficaBefore.Count) session(s) before clicking '$ResourceName'"

    Write-ToSFLauncherLog "Clicking resource '$ResourceName'"
    $resource.Click()

    Write-ToSFLauncherLog "Verifying that session launched..."
    $wficaFound = $false
    $try =1
    do {
        $wficaAfter = @()
        Get-Process wfica32 -ErrorAction SilentlyContinue | select id | % { $wficaAfter += $_.id }
        $wficaComparison = Compare-Object $wficaBefore $wficaAfter -PassThru

        if ($wficaComparison -ne $null) {
            foreach ($wfica in $wficaComparison) {
                if ($wfica.SideIndicator -eq '=>') {
                    $wficaFound = $true
                    "Try #$try`: SUCCESS","Found $($wficaAfter.Count) sessions after clicking '$ResourceName'","Found wfica32.exe with PID $wfica for session launched" | Write-ToSFLauncherLog
                    break
                }
            }
        }
        if ($wficaFound) {
            break
        } else {
            Write-ToSFLauncherLog "Try #$try`: FAIL"
            Start-Sleep -Seconds 1
            $try++
        }
    } until ($try -gt $NumberOfRetries)
    if (-not $wficaFound) {
        Write-ToSFLauncherLog "WARNING: Unable to confirm that session launched"
    }
}

function Disconnect-User {
    Write-ToSFLauncherLog "Sleeping $SleepBeforeLogoff seconds before logging off..."
    Start-Sleep -Seconds $SleepBeforeLogoff

    Write-ToSFLauncherLog "Getting log off link..."
    $try = 1
    do {
        $logoffLink = [System.__ComObject].InvokeMember(“getElementById”,[System.Reflection.BindingFlags]::InvokeMethod, $null, $document, $SFLogOffLinkId)
        if ($logoffLink -ne $null -and $logoffLink.GetType() -ne [DBNull]) {
            Write-ToSFLauncherLog "Try #$try`: SUCCESS"
            break
        } else {
            Write-ToSFLauncherLog "Try #$try`: FAIL"
            Start-Sleep -Seconds 1
            $try++
        }
    } until ($try -gt $NumberOfRetries)
    if ($logoffLink -eq $null -or $logoffLink.GetType() -eq [DBNull]) {
        Write-ToSFLauncherLog "Log off link not found"
    } else {
        Write-ToSFLauncherLog "Clicking log off link"
        $logoffLink.Click()
    }
}

try {
    Write-ToSFLauncherLog "*************** LAUNCHER SCRIPT BEGIN ***************"

    Write-SFLauncherHeader

    Open-InternetExplorer -SiteURL $SiteURL

    Test-LoginForm

    Submit-UserCredentials

    Wait-ForPageReady

    Start-Resource

    Disconnect-User
}
catch {
    Write-ToSFLauncherLog "Exception caught by script"
    $_.ToString() | Write-ToSFLauncherLog
    $_.InvocationInfo.PositionMessage | Write-ToSFLauncherLog
    throw $_
}
finally {
    if ($internetExplorer -is [System.__ComObject]) {
        if ($internetExplorer | Get-Member 'Quit') {
            Write-ToSFLauncherLog "Quitting Internet Explorer"
            $internetExplorer.Quit()
        }
        Write-ToSFLauncherLog "Releasing Internet Explorer COM object"
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($internetExplorer) | Out-Null
        Remove-Variable -Name internetExplorer
    }
    Write-ToSFLauncherLog "***************  LAUNCHER SCRIPT END  ***************"
}
