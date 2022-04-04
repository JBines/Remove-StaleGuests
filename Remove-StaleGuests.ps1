<# 
.SYNOPSIS
This script removes stale Azure AD Guest accounts.  

.DESCRIPTION
Stale guest accounts are a liability and security risk for every organisation utilizing 
guest accounts. This script was designed to remove guest accounts in the following two 
scenario’s: (1) when invitation has not been accepted and has expired (90 days) and (2) 
when an account has become inactive after a user defined period of time. 

## Remove-StaleGuests.ps1 [-InactiveTimeSpan <Integer>] [-ForceRemoval <Boolean>] 
[-RemoveExpiredGuests <Boolean>] [-RemoveInactiveGuests <Boolean>] [-DifferentialScope <Integer>]
[-AppID <String>] [-TenantID <String>] [-CertificatePath <String>] [-ClientSecret <String>] 
[-AutomationPSConnection <String>] [-AutomationPSCertificate <String>] [-ExportCSVPath <String>]

.PARAMETER InactiveTimeSpan
The InactiveTimeSpan parameter defines the number of days that a guest user has not logged 
using the guest account. Please be aware that the signin data . 

.PARAMETER RemoveExpiredGuests
The RemoveExpiredGuests parameter allows the removable of guests who have not accepted
 the invitation for 90 days at which time it expires and needs to be resent. This removal 
 would require the guest account to be recreated. Must be used with the InactiveTimeSpan parameter.

.PARAMETER RemoveInactiveGuests
The RemoveInactiveGuests parameter allows the removable of guests as defined in the 
InactiveTimeSpan. Must be used with the InactiveTimeSpan parameter.

.PARAMETER ForceRemoval
The ForceRemoval parameter allows the removable of guests with default logon information 
older than Apr-2020 or for accounts that have not yet had a signin. The DateTime value 
might be displayed as 01-01-0001. As exact logon details cannot be provided these accounts 
are excluded from remove by default. 

.PARAMETER ExportCSVPath
The ExportCSVPath parameter specifies that all results will be exported to a CSV file. 
Insert the full path such as a string 'c:\temp\guest.csv' or just the file name to output 
the data to current location. 

.PARAMETER DifferentialScope
The DifferentialScope parameter defines how many guests can be removed in a single 
operation of the script. The goal of this setting is throttle bulk changes to limit 
the impact of misconfiguration by an administrator. What value you choose here will 
be dictated by your userbase and your script schedule. The default value is set to 
10 Objects. 

.PARAMETER AppID
 The AppID parameter is used in manual mode and defines Azure AD Application ID. 

.PARAMETER TenantID
 The TenantID parameter is the GUID for the Tenant. 

.PARAMETER CertificatePath
 The CertificatePath parameter is the path for the Cert for example: 
 'Cert:\CurrentUser\My\<ThumbPrint>' or 'cert:\LocalMachine\my\<ThumbPrint>' Must 
 be used with parameters AppID and TenantID.

.PARAMETER ClientSecret
 The ClientSecret parameter is the plain text authenication string. This should be used 
 only for test purposes. Not recommeneded for use in production. Must be used with 
 parameters AppID and TenantID.

.PARAMETER AutomationPSConnection
 The AutomationPSConnection parameter defines the connection details such as AppID, 
 Tenant ID. Parameter must be used with -AutomationPSCertificate

.PARAMETER AutomationPSCertificate
 The AutomationPSCertificate parameter defines the name of the automation certificate 
 that has been loaded in Azure Automation. 

.EXAMPLE
Remove-StaleGuests.ps1 -ExportCSVPath guest.csv -AppID "7af89f06-f1cc-4ff7-aee8-b6a43f6a0ae2" 
-TenantID  "557febb4-aa10-4520-80d1-280058cb8353" -CertificatePath "cert:\LocalMachine\my\303A498735t987876245kjlnsfv3495784"

-- REPORT ONLY AND EXPORT TO CSV --

In this example the script will provide detailed report information on your guest accounts. 

.EXAMPLE
Remove-StaleGuests.ps1 -InactiveTimeSpan 365 -RemoveExpiredGuests:$true -AppID "7af89f06-f1cc-4ff7-aee8-b6a43f6a0ae2" 
-TenantID  "557febb4-aa10-4520-80d1-280058cb8353" -CertificatePath "cert:\LocalMachine\my\303A498735t987876245kjlnsfv3495784"

-- REMOVE EXPIRED GUESTS VIA CERT AUTH --

In this example the script will remove expired guests that have not accepted the invite after 90 days. 

.EXAMPLE
Remove-StaleGuests.ps1 -InactiveTimeSpan 720 -RemoveExpiredGuests:$true -RemoveInactiveGuests:$true -AppID "7af89f06-f1cc-4ff7-aee8-b6a43f6a0ae2" 
-TenantID  "557febb4-aa10-4520-80d1-280058cb8353" -ClientSecret '2pT\H8{u28y^fhG,'

-- REMOVE EXPIRED GUESTS & INACTIVE GUESTS FOR 2 YEARS VIA CLIENT SECRET --

In this example the script will remove guests that have not accepted the invitation after 90 days 
and have been inactive for 2 years. 

.EXAMPLE
Remove-StaleGuests.ps1 -InactiveTimeSpan 365 -RemoveInactiveGuests:$true -AutomationPSConnection AzureAuto-Connect -AutomationPSCertificate AzureAuto-Cert

-- REMOVE INACTIVE GUESTS FOR 1 YEARS USING AZURE AUTOMATION--

In this example the script will remove guests that have been inactive for 1 year. Running this script in Azure Automation 
requires that you enable the use of 

.LINK
Register Azure App - Quickstart: https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app
Create an Azure AD application and service principal https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal

Old School Links! (2019... oh my the world turns fast!) 
Report Old Guest Accounts and Their Membership of Office 365 Groups - https://office365itpros.com/2019/10/15/report-old-guest-accounts-office365-groups/
Identifying Obsolete Guest User Accounts in an Office 365 Tenant - https://www.petri.com/guest-account-obsolete-activity 

.NOTES

NOTE! Script Requires the MSAL.PS Module. Run - Install-Module -Name MSAL.PS - https://www.powershellgallery.com/packages/MSAL.PS

IMPORTANT! Hey! Graph API Beta is used. You must use user creds or an Azure Application which is 
granted the following permissions. 
    
    AuditLog.Read.All  - Access LastLogon information
    Directory.Read.All - Fix auditlog bug
    User.ReadWrite.All - Needed for guest removal (Allow only after extensive testing)
    
    Quickstart: https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app

IMPORTANT! The use of client secret is not recommended in production. It is highly recommended that you use 
Certifcate based authenication. Graph API Beta is also not recommended in production.

ANOTHER NOTE! MSAL.PS Module: 4.37.0.0 was bombing with the Az Module. You may receive the error: 
"The property 'Authority' cannot be found on this object." https://github.com/AzureAD/MSAL.PS/issues/45

AND... ANOTHER NOTE! - Guests changed from the default setting of hidden in the GAL will not be removed. 
You will need to amend the script to allow this if needed. 

#This code-sample is provided "AS IT IS" without warranty of any kind, either expressed or implied, including but not limited to the implied warranties of merchantability and/or fitness for a particular purpose.
#This sample is not supported under any standard support program or service.
#The entire risk arising out of the use or performance of the sample and documentation remains with you. 
#In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of  the use of or inability to use the sample or documentation, even if Microsoft has been advised of the possibility of such damages.

[AUTHOR]
Joshua Bines, Consultant

[CONTRIBUTORS]
Tony Redmond (Tony let's say I took inspiration from your blog post and script! :) )
Nicolas Honsberger - https://techcommunity.microsoft.com/t5/azure-active-directory-identity/list-all-users-last-login-date/m-p/109212/page/2

Find me on:
* Web:     https://theinformationstore.com.au
* LinkedIn:  https://www.linkedin.com/in/joshua-bines-4451534
* Github:    https://github.com/jbines
  
[VERSION HISTORY / UPDATES]
0.0.1 20200421 - JBINES - Created the bare bones
0.0.2 20200423 - JBines - [BUGFIX] Exclude from removal guests if they are enabled in the address book
                        - [Feature] Added RemoveInactiveGuests and ExportCSVPath Switch
1.0.0 20200427 - JBines - [MAJOR RELEASE] Works like a dream as long as you read the notes... 
1.0.1 20200617 - JBines - [Feature] Improved default reporting mode, examples and some extra error checking. 
1.0.2 20200915 - JBines - [Info] Azure Signin Logs are kept for 7-30 days depending on the user Licence. 
2.0.0 20220127 - JBines - [MAJOR RELEASE] Complete script rewrite. 
                        - Added support for App Only Connections with Graph API. Also Started Graph API for the Last Login Date which is vaild back to Apr-2020.  
2.0.1 20220210 - JBines - [BUGFIX] Small issue found with VAR client secret. Line 305 - https://github.com/JBines/Remove-StaleGuests/issues/8 
2.0.2 20220404 - JBines - [BUGFIX] PowerShell v7 has has strict header parsing added switchto bypass -SkipHeaderValidation

[TO DO LIST / PRIORITY]
Support the use of managed identitiy / HIGH
Add Email Notication to Admins for output report / MED
Add Email Notication Prior to Guest Removal / MED
#>

Param 
(
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Int]$InactiveTimeSpan,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Boolean]$RemoveExpiredGuests,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Boolean]$RemoveInactiveGuests,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Boolean]$ForceRemoval,
    [Parameter(Mandatory = $False)]
    [System.String]$ExportCSVPath=$null,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Int]$DifferentialScope = 10,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]$AppID,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]$TenantID,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]$CertificatePath,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]$ClientSecret,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]$AutomationPSConnection,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]$AutomationPSCertificate
)

    #Global Variables 
    $counter = 0

    #Load Functions
    function Write-Log([string[]]$Message, [string]$LogFile = $Script:LogFile, [switch]$ConsoleOutput, [ValidateSet("SUCCESS", "INFO", "WARN", "ERROR", "DEBUG")][string]$LogLevel)
    {
           $Message = $Message + $Input
           If (!$LogLevel) { $LogLevel = "INFO" }
           switch ($LogLevel)
           {
                  SUCCESS { $Color = "Green" }
                  INFO { $Color = "White" }
                  WARN { $Color = "Yellow" }
                  ERROR { $Color = "Red" }
                  DEBUG { $Color = "Gray" }
           }
           if ($Message -ne $null -and $Message.Length -gt 0)
           {
                  $TimeStamp = [System.DateTime]::Now.ToString("yyyy-MM-dd HH:mm:ss")
                  if ($LogFile -ne $null -and $LogFile -ne [System.String]::Empty)
                  {
                         Out-File -Append -FilePath $LogFile -InputObject "[$TimeStamp] [$LogLevel] $Message"
                  }
                  if ($ConsoleOutput -eq $true)
                  {
                         Write-Host "[$TimeStamp] [$LogLevel] :: $Message" -ForegroundColor $Color

                    if($AutomationPSConnection -or $AutomationPSCertificate)
                    {
                         Write-Output "[$TimeStamp] [$LogLevel] :: $Message"
                    }
                  }
                  if($LogLevel -eq "ERROR")
                  {
                          Write-Error "[$TimeStamp] [$LogLevel] :: $Message"
                  }  
           }
    }
    
    Function Test-CommandExists 
    {

     Param ($command)

         $oldPreference = $ErrorActionPreference

         $ErrorActionPreference = 'stop'

         try {if(Get-Command $command){RETURN $true}}

         Catch {Write-Host "$command does not exist"; RETURN $false}

         Finally {$ErrorActionPreference=$oldPreference}

    } #end function test-CommandExists

    Try{
                            
        #Check cred Account has all the required permissions ,Get-MailUser,Set-MailUser
        If(Test-CommandExists Get-Item,Get-MsalToken){
    
            Write-Log -Message "Correct RBAC Access Confirmed" -LogLevel DEBUG -ConsoleOutput

        } 
            
        Else {Write-Log -Message "Script requires a higher level of access! You are missing the MSAL.PS PowerShell Module" -LogLevel ERROR -ConsoleOutput; Break}

        If($RemoveExpiredGuests -or $RemoveInactiveGuests -and (-not $InactiveTimeSpan)){

            Write-Log -Message "InactiveTimeSpan parameter is required when using RemoveExpiredGuests or RemoveInactiveGuests" -LogLevel ERROR -ConsoleOutput; 
            Break
        }

        if($CertificatePath) { 

                If($AppID -and $TenantID){
                    ##Import Certificate
                    $Certificate = Get-Item $certificatePath
                    if($Certificate){
                        $Token = Get-MsalToken -ClientId $AppId -TenantId $TenantId -ClientCertificate $Certificate 
                        if($?){ Write-Log -Message "Authenication via Certificate - Completed!" -LogLevel SUCCESS -ConsoleOutput }
                        else {
                            Write-Log -Message "Authenication via Certificate - Failed!" -LogLevel ERROR -ConsoleOutput;
                            break
                        }
                    }
                    else {
                        Write-Log -Message "No Certificate could be found! Try Get-Item certificatePath. Session will require admin access to get the private key." -LogLevel ERROR -ConsoleOutput; 
                        Break
                    }
                    ##Request Token - Cert
                }
                else {
                    Write-Log -Message "Certificate Auth also requires Switches AppID & TenantID" -LogLevel ERROR -ConsoleOutput; 
                    Break
                }
        }
        if($AppID -and $TenantID -and $ClientSecret) { 
            Write-Log -Message "Using ClientSecret for testing ONLY. Folks - not recommended!" -LogLevel WARN -ConsoleOutput
            ##Request Token - Cert
            $Token = Get-MsalToken -clientID $AppID -ClientSecret (ConvertTo-SecureString $ClientSecret -AsPlainText -Force) -tenantID $tenantID
            if($?){ Write-Log -Message "Authenication via ClientSecret - Completed!" -LogLevel SUCCESS -ConsoleOutput }
            else {
                Write-Log -Message "Authenication via ClientSecret - Failed!" -LogLevel ERROR -ConsoleOutput;
                break
            }
        }
        if($AutomationPSConnection -and $AutomationPSCertificate) { 

            #Azure Automation - Certicate Auth
            $Connection = Get-AutomationConnection -Name $AutomationPSConnection
            $Certificate = Get-AutomationCertificate -Name  $AutomationPSCertificate
            $Token = Get-MsalToken -ClientId $Connection.ApplicationId -TenantId $Connection.TenantId -ClientCertificate $Certificate
            if($?){ Write-Log -Message "Azure AUTOMATION - Authenication via Certificate - Completed!" -LogLevel SUCCESS -ConsoleOutput }
            Else{break}

            }
        Else
        {
            Remove-Variable AutomationPSConnection
            Remove-Variable AutomationPSCertificate
        }


        #Obtain Access Token from $token VAR
        $AccessToken = $Token.AccessToken
        
        #Form request headers with the acquired $AccessToken
        $headers = @{'Content-Type'="application\json";'Authorization'="Bearer $AccessToken"}

        #This request get users list with signInActivity.
        $ApiUrl = "https://graph.microsoft.com/beta/users?`$select=creationType,showInAddressList,externalUserState,displayName,userPrincipalName,signInActivity,userType,assignedLicenses,mail,createdDateTime&`$top=999"

        $Guests = @()

        While ($ApiUrl -ne $Null){ #Perform pagination if next page link (odata.nextlink) returned.
            $Response = Invoke-WebRequest -Method 'GET' -Uri $ApiUrl -Headers $headers -ContentType "application\json" -UseBasicParsing -SkipHeaderValidation  | ConvertFrom-Json

            if($Response.value){
                $Users = $Response.value
                ForEach($User in $Users){
                    #Filter only Guests
                    if ($User.userType -eq 'Guest'){

                        $Guests += New-Object PSObject -property $([ordered]@{
                        userID = $User.id
                        displayName = $User.displayName
                        externalDomain = if ($User.mail) {$User.mail.Split("@")[1]} else {$null}
                        email = $user.mail
                        userPrincipalName = $User.userPrincipalName
                        creationDateTime = if($User.createdDateTime) {[DateTime]$User.createdDateTime} else {$null}
                        lastSignInDateTime = if($User.signInActivity.lastSignInDateTime) { [DateTime]$User.signInActivity.lastSignInDateTime } else {$null}
                        isLicensed = if ($User.assignedLicenses.Count -ne 0) { $true } else { $false }
                        isGuestUser = if ($User.userType -eq 'Guest') { $true } else { $false }
                        externalUserState = $User.externalUserState
                        guestDaysSinceLastLogon = if($User.signInActivity.lastSignInDateTime){([DateTime]$User.signInActivity.lastSignInDateTime | New-TimeSpan).Days} else {$null}
                        guestDaysSinceCreated = if($User.createdDateTime){($User.createdDateTime | New-TimeSpan).Days} else {$null}
                        isExpiredGuestUser = If(($User.externalUserState -eq 'PendingAcceptance') -and (($User.createdDateTime | New-TimeSpan).Days -gt 91)){ $True } Else { $False }
                        showInAddressList = if ($User.showInAddressList -ne $false) { $true } else { $false }
                        creationType = $User.creationType
                            #creationType Explainer == https://docs.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0
                            #As a regular school or work account (null).
                            #As an external account (Invitation).
                            #As a local account for an Azure Active Directory B2C tenant (LocalAccount).
                            #Through self-service sign-up by an internal user using email verification (EmailVerified).
                            #Through self-service sign-up by an external user signing up through a link that is part of a user flow (SelfServiceSignUp).
                        isGuestInactive = if($User.signInActivity.lastSignInDateTime -and ($InactiveTimeSpan.count -gt 0)){ 
                                                if (($InactiveTimeSpan.count -gt 0)-and([DateTime]$User.signInActivity.lastSignInDateTime | New-TimeSpan).Days -gt $InactiveTimeSpan) {
                                                    $true
                                                }
                                                else {
                                                    $false
                                                }
                                            } 
                                            else { 
                                                if(($InactiveTimeSpan.count -gt 0)-and($User.createdDateTime | New-TimeSpan).Days -gt $InactiveTimeSpan){
                                                    $true
                                                } 
                                                else {
                                                    $false
                                                }
                        
                                            }#EndElse
                        })
                    }
                }
            }
        $ApiUrl=$Response.'@odata.nextlink'
        }    
    }
    
    Catch{
    
        $ErrorMessage = $_.Exception.Message
        Write-Log -Message $ErrorMessage -LogLevel Error -ConsoleOutput
        Break

    }

    Write-Log -Message "Processing Guest Users - Total Found: $($guests.count)" -LogLevel DEBUG -ConsoleOutput

    foreach($guest in $guests){
        
        #Null out Var
        $deleteguestApiUrl = $null
        $deleteguestResponse = $null

        #Output guest to screen in report mode
        If(-Not($InactiveTimeSpan)){

            $guest | Select-Object UserID,email,creationDateTime,lastSignInDateTime,guestDaysSinceLastLogon,guestDaysSinceCreated
        }
        
        If($RemoveExpiredGuests -and ($InactiveTimeSpan.count -gt 0) -and (-not($guest.showInAddressList))){

            if($guest.isExpiredGuestUser){
                If($counter -lt $DifferentialScope){
                    $counter++
                    $deleteguestApiUrl = "https://graph.microsoft.com/beta/users/$($guest.userID)"
                    $deleteguestResponse = Invoke-WebRequest -Method 'DELETE' -Uri $deleteguestApiUrl -ContentType "application\json" -Headers $headers -UseBasicParsing -SkipHeaderValidation

                    If($deleteguestResponse.StatusCode -eq 204){Write-Log -Message "REMOVE-ExpiredGuest;UPN:$($Guest.userPrincipalName);ObjectId:$($guest.userID);CreationDate:$($guest.creationDateTime);lastSignInDateTime:$($guest.lastSignInDateTime)" -LogLevel SUCCESS -ConsoleOutput }
                    else{Write-Log -Message "FAILED-REMOVE-ExpiredGuest;UPN:$($Guest.userPrincipalName);ObjectId:$($guest.userID);CreationDate:$($guest.creationDateTime);lastSignInDateTime:$($guest.lastSignInDateTime)" -LogLevel ERROR -ConsoleOutput}
                }
                else {
                    #Exceeded couter limit
                    Write-log -Message "Hey! You hit the -DifferentialScope limit of $DifferentialScope. Let's break out of this loop" -ConsoleOutput -LogLevel ERROR
                    Break
                }
            }
        }

        If($RemoveInactiveGuests -and ($InactiveTimeSpan.count -gt 0) -and (-not($guest.showInAddressList))){

            if(($guest.isGuestInactive) -and (-not($guest.isExpiredGuestUser)) -and (-not($guest.ShowInAddressList))){

                #Skip accounts that have an invaild signin information. It appears alittle random need to ask PG but appears most signin before 2020 but some new accounts also found
                if(($guest.guestDaysSinceLastLogon -lt 700000) -or ($ForceRemoval)) {
                    
                    If($counter -lt $DifferentialScope){
                        $counter++
                        $deleteguestApiUrl = "https://graph.microsoft.com/beta/users/$($guest.userID)"
                        $deleteguestResponse = Invoke-WebRequest -Method 'DELETE' -Uri $deleteguestApiUrl -ContentType "application\json" -Headers $headers -UseBasicParsing -SkipHeaderValidation

                        If($deleteguestResponse.StatusCode -eq 204){Write-Log -Message "REMOVE-InActiveGuest;UPN:$($Guest.userPrincipalName);ObjectId:$($guest.userID);CreationDate:$($guest.creationDateTime);lastSignInDateTime:$($guest.lastSignInDateTime)" -LogLevel SUCCESS -ConsoleOutput }
                        else{Write-Log -Message "FAILED-REMOVE-InActiveGuest;UPN:$($Guest.userPrincipalName);ObjectId:$($guest.userID);CreationDate:$($guest.creationDateTime);lastSignInDateTime:$($guest.lastSignInDateTime)" -LogLevel ERROR -ConsoleOutput}

                    }
                    else {
                        #Exceeded couter limit
                        Write-log -Message "Hey! You hit the -DifferentialScope limit of $DifferentialScope. Let's break out of this loop" -ConsoleOutput -LogLevel ERROR
                        Break
                    }
                }
                else {
                    Write-Log -Message "SKIP-REMOVAL(Last_login_info_Unclear)(Use Switch -ForceRemoval);UPN:$($Guest.userPrincipalName);ObjectId:$($guest.userID);CreationDate:$($guest.creationDateTime);lastSignInDateTime:$($guest.lastSignInDateTime)" -LogLevel WARN -ConsoleOutput
                }
            }
        }
    }

    if($ExportCSVPath -and (-not($AutomationPSConnection))){
        
        Write-Log -Message "Exporting to CSV with path of $ExportCSVPath" -LogLevel INFO -ConsoleOutput
                            
        $Guests | Export-Csv -Path $ExportCSVPath -Encoding UTF8
                        
    }



