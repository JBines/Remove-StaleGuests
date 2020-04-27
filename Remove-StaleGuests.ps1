<# 
.SYNOPSIS
This script removes stale Azure AD Guest accounts.  

.DESCRIPTION
Stale guest accounts are a liability and security risk for every organisation utilizing guest accounts. This script was designed to remove guest accounts in the following two scenario’s: (1) when invitation has not been accepted and has expired (90 days) and (2) when an account has become inactive after a user defined period of time. 

## Remove-StaleGuests.ps1 [-InactiveTimeSpan <Integer>] [-CustomAttributeNumber <Integer[1-14]>] [-RemoveExpiredGuests <Boolean>] [-RemoveInactiveGuests <Boolean>] [-AutomationPSCredential <String>] [-ExportCSVPath <String>]

.PARAMETER InactiveTimeSpan
The InactiveTimeSpan parameter defines the number of days that a guest user has not logged using the guest account. Please be aware that only 90 days of signin logs are kept so you should run this script for the inactive period before setting the remove function. 

.PARAMETER CustomAttributeNumber
The CustomAttributeNumber parameter specifies which Exchange Custom Attribute you would like to place the Last Logon date and time information. The default is CustomAttribute1. Unfortunately, the last login information is only valid for 90 Days for this reason we require another location for storing this information. This will extend our ‘stale’ window to 1 to 2 years if needed. 

.PARAMETER RemoveExpiredGuests
The RemoveExpiredGuests parameter allows the removable of guests who have not accepted the invitation for 90 days at which time it expires and needs to be resent. This removal would require the guest account to be recreated. 

.PARAMETER RemoveInactiveGuests
The RemoveInactiveGuests parameter allows the removable of guests as defined in the InactiveTimeSpan 

.PARAMETER ExportCSVPath
The ExportCSVPath parameter specifies that all results will be exported to a CSV file. This is a switch only and the filename will be set via the script in the format of 20180508T014040Z.csv

.PARAMETER DifferentialScope
The DifferentialScope parameter defines how many guests can be removed in a single operation of the script. The goal of this setting is throttle bulk changes to limit the impact of misconfiguration by an administrator. What value you choose here will be dictated by your userbase and your script schedule. The default value is set to 10 Objects. 

.PARAMETER AutomationPSCredential
The AutomationPSCredential parameter defines which Azure Automation Cred you would like to use. This account must have the access to Read | Write to Mail Users and Remove Guest Accounts 

.EXAMPLE
Remove-StaleGuests.ps1

-- REPORT ONLY --

In this example the script will provide detailed report information on your guest accounts. 

.EXAMPLE
Remove-StaleGuests.ps1 -InactiveTimeSpan 720 -RemoveExpiredGuests:$true -RemoveInactiveGuests:$true

-- REMOVE EXPIRED GUESTS & INACTIVE GUESTS FOR 2 YEARS --

In this example the script will add the login time date to Custom Attribute 1. It will also remove guests that have not accepted the invitation after 90 days and have been inactive for 2 years. 

.EXAMPLE
Remove-StaleGuests.ps1 -InactiveTimeSpan 365 -CustomAttributeNumber 5

-- REMOVE INACTIVE GUESTS FOR 1 YEARS AND STAMP LOGIN DATE OF CUSTOM ATTRIBUTE NUMBER 5 --

In this example the script will add the login time date to Custom Attribute 5. It will also remove guests that have been inactive for 1 year. 

.LINK

Report Old Guest Accounts and Their Membership of Office 365 Groups - https://office365itpros.com/2019/10/15/report-old-guest-accounts-office365-groups/

Identifying Obsolete Guest User Accounts in an Office 365 Tenant - https://www.petri.com/guest-account-obsolete-activity 

.NOTES

VERY IMPORTANT! If you remove guests please run the script first for the inactive period -90 days. This is required so you can have a vaild LastlogonDate beyond the 90 days provided by the Azure Sign Logs

IMPORTANT! Please be aware that this script will overwrite any data listed in the Guest's Custom Attribute with the LoginTimeStamp. If like most Org's you are not changing these value for guest accounts you shouldn't worry. 

If running in a local Shell, you will need to connect your PowerShell session to Exchange Online and Azure Active Directory before running the script.

We used AzureADPreview Version: 2.0.2.89 (Please note that the preview module is not suggested for production use.)

NOTE! AzureADPreview Version: 2.0.2.77 was bombing please make sure you are using the current version. https://github.com/Azure/azure-docs-powershell-azuread/issues/337 

[AUTHOR]
Joshua Bines, Consultant

[CONTRIBUTORS]
Tony Redmond (Tony let's say I took inspiration from your blog post and script! :) )

Find me on:
* Web:     https://theinformationstore.com.au
* LinkedIn:  https://www.linkedin.com/in/joshua-bines-4451534
* Github:    https://github.com/jbines
  
[VERSION HISTORY / UPDATES]
0.0.1 20200421 - JBINES - Created the bare bones
0.0.2 20200423 - JBines - [BUGFIX] Exclude from removal guests if they are enabled in the address book
                        - [Feature] Added RemoveInactiveGuests and ExportCSVPath Switch
1.0.0 20200427 - JBines - [MAJOR RELEASE] Works like a dream as long as you read the notes... 

[TO DO LIST / PRIORITY]

#>

Param 
(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [Int]$InactiveTimeSpan,
    [Parameter(Mandatory = $False)]
    [ValidateRange(0,15)]
    [Int]$CustomAttributeNumber = 1,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Boolean]$RemoveExpiredGuests,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Boolean]$RemoveInactiveGuests,
    [Parameter(Mandatory = $False)]
    [System.String]$ExportCSVPath=$null,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [Int]$DifferentialScope = 10,
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]$AutomationPSCredential
)

    #Global Variables 
    $counter = 0
    
    #Create Report Array
    $Report = [System.Collections.Generic.List[Object]]::new()

    #Invoke CMDLet Switch for CustomAttribute
    switch ($CustomAttributeNumber) {
        1 { $CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute1 $lastLogonDate' }
        2 { $CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute2 $lastLogonDate' }
        3 { $CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute3 $lastLogonDate' }
        4 { $CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute4 $lastLogonDate' }
        5 { $CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute5 $lastLogonDate' }
        6 { $CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute6 $lastLogonDate' }
        7 { $CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute7 $lastLogonDate' }
        8 { $CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute8 $lastLogonDate' }
        9 { $CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute9 $lastLogonDate' }
        10 {$CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute10 $lastLogonDate' }
        11 {$CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute11 $lastLogonDate' }
        12 {$CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute12 $lastLogonDate' }
        13 {$CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute13 $lastLogonDate' }
        14 {$CMDlet_Set_MailUser = 'Set-MailUser -Identity $guestObjectID -CustomAttribute14 $lastLogonDate' }
        Default {Write-Error "Variable $CustomAttributeNumber is unsupported"; Break }
    }


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

                    if($AutomationPSCredential)
                    {
                         Write-Output "[$TimeStamp] [$LogLevel] :: $Message"
                    } 
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

        if ($AutomationPSCredential) {
            
            $Credential = Get-AutomationPSCredential -Name $AutomationPSCredential

            Connect-AzureAD -Credential $Credential
            
            #$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $Credential -Authentication Basic -AllowRedirection
            #Import-PSSession $Session -DisableNameChecking -Name ExSession -AllowClobber:$true | Out-Null

            $ExchangeOnlineSession = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $Credential -Authentication Basic -AllowRedirection -Name $ConnectionName 
            Import-Module (Import-PSSession -Session $ExchangeOnlineSession -AllowClobber -DisableNameChecking) -Global

            }
                            
        #Check cred Account has all the required permissions ,Get-MailUser,Set-MailUser
        If(Test-CommandExists Get-AzureADUser,Get-AzureADAuditDirectoryLogs,Set-MailUser,Get-MailUser){
    
            Write-Log -Message "Correct RBAC Access Confirmed" -LogLevel DEBUG -ConsoleOutput

        } 
            
        Else {Write-Log -Message "Script requires a higher level of access or you are missing the AzureADPreview Module. You are missing access to Get-AzureADUser,Get-MailUser,Set-MailUser,Get-AzureADAuditDirectoryLogs" -LogLevel INFO -ConsoleOutput; Break}
        
        #New Array of all guest users
        $guestUsers = Get-AzureADUser -All $true -Filter "UserType eq 'Guest'"
    
    }
    
    Catch{
    
        $ErrorMessage = $_.Exception.Message
        Write-Error $ErrorMessage

            If($?){Write-Log -Message $ErrorMessage -LogLevel Error -ConsoleOutput}

        Break

    }

    Write-Log -Message "Processing Guest Users - Total Found: $($guestUsers.count)" -LogLevel DEBUG -ConsoleOutput

    foreach($guest in $guestUsers){

        #Null Loop Variable's
        $guestObjectID = $null
        $GuestUserPrincipalName = $null
        $guestCreated = $null
        $guestCreatedDateTime = $null
        $guestCreationType = $null
        $guestUserState =  $null
        $guestShowInAddressList = $null
        $guestMailUser  = $null
        $guestLastLogonDate = $null
        [nullable[datetime]]$lastLogonDate = $null
        $guestOLDLastLogonDate = $null
        $guestDaysSinceLastLogon = $null
        $guestDaysSinceCreated = $null
        $guestExpired = $null
        $guestInactive = $null

        #Set Variables
        $guestObjectID = $guest.ObjectID
        $GuestUserPrincipalName = $Guest.UserPrincipalName
        $guestCreatedDateTime = $guest.ExtensionProperty.createdDateTime
        $guestLastLogonDate = (Get-AzureADAuditSignInLogs -Top 1  -Filter "userid eq '$guestObjectID' and status/errorCode eq 0").CreatedDateTime
        $guestCreationType = $guest.CreationType
        $guestUserState = $guest.UserState
        $guestShowInAddressList = $guest.ShowInAddressList

        #Get Guest as an Exchange Mail User
        $guestMailUser = Get-MailUser -Identity $guestObjectID

        try {
            
            #Get old logon information 
            $stringCustomAttrib = "CustomAttribute" + $CustomAttributeNumber
            [nullable[datetime]]$guestOLDLastLogonDate = If($guestMailUser.$stringCustomAttrib){$guestMailUser.$stringCustomAttrib} Else{$null}
        
        }
        catch {
            
            Write-log -Message $_.Exception.Message -ConsoleOutput -LogLevel ERROR

        }
        
        If($guestLastLogonDate){

            [nullable[datetime]]$lastLogonDate = $guestLastLogonDate
            
            #Check if the custom Attrib needs updating on the Mail User
            If($lastLogonDate.Date -ne $guestOLDLastLogonDate.Date){
            
                #Stamp New Logon Date on Guest Mail User
                Invoke-Expression $CMDlet_Set_MailUser
                If($?){Write-Log -Message "Set-NewTimeStamp;CMDlet:Set-MailUser;UPN:$GuestUserPrincipalName;LastLogonDate:$LastLogonDate;CreatedDateTime:$guestCreatedDateTime" -LogLevel SUCCESS -ConsoleOutput }

            }
            
        }
        Else{
            
            If($guestOLDLastLogonDate){
                
                [nullable[datetime]]$lastLogonDate = $guestOLDLastLogonDate
            
            }
            
        }

        #Count Days since creation & last logon
        $guestDaysSinceLastLogon = if($lastLogonDate){($lastLogonDate | New-TimeSpan).Days}
        $guestDaysSinceCreated = if($guestCreatedDateTime){($guestCreatedDateTime | New-TimeSpan).Days}

        #Confirm if Guest is Expired
        If(($guestUserState -eq 'PendingAcceptance') -and ($guestDaysSinceCreated -gt 91)){

            $guestExpired = $True
        }
        Else {

            $guestExpired = $False
        }

        #Confirm if Guest is Inactive 
        If(($guestDaysSinceLastLogon -gt $InactiveTimeSpan)-or(($LastLogonDate -eq $null)-and($guestDaysSinceCreated -gt $InactiveTimeSpan))){

            $guestInactive = $True
        }
        Else {

            $guestInactive = $False
        }

        $ReportLine = [PSCustomObject]@{
            UPN                = $GuestUserPrincipalName
            ID                 = $guestObjectID
            Name               = $Guest.DisplayName
            CreationType       = $guestCreationType
            CreatedDateTime    = $guestCreatedDateTime
            DaysSinceCreated   = $guestDaysSinceCreated
            LastlogonDate      = $LastLogonDate
            DaysSinceLastLogon = $guestDaysSinceLastLogon
            Expired            = $guestExpired
            Inactive           = $guestInactive
            UserState          = $guestUserState
            ShowInAddressList  = $guestShowInAddressList } 
        
        #Output guest to screen
        #$ReportLine
        
        #Add content to Array
        $Report.Add($ReportLine)
        
        If($RemoveExpiredGuests -and (-not($guestShowInAddressList))){

            if($guestExpired){

                Remove-AzureADUser -ObjectId $guestObjectID
                If($?){Write-Log -Message "REMOVE-ExpiredGuest;UPN:$GuestUserPrincipalName;ObjectId:$guestObjectID;CreationDate:$guestCreatedDateTime;ShowInAddressList:$guestShowInAddressList" -LogLevel SUCCESS -ConsoleOutput }

            }
        }

        If($RemoveInactiveGuests){

            if(($guestInactive) -and (-not($guestExpired)) -and (-not($guestShowInAddressList))){

                Remove-AzureADUser -ObjectId $guestObjectID
                If($?){Write-Log -Message "REMOVE-InActiveGuest;CMDlet:Remove-AzureADUser;UPN:$GuestUserPrincipalName;ObjectId:$guestObjectID;LastLogonDate:$LastLogonDate" -LogLevel SUCCESS -ConsoleOutput }

            }
            Else{

                Write-Log -Message "SKIP-User;Inactive:False;UPN:$GuestUserPrincipalName;CreationDate:$guestCreatedDateTime;DaysSinceCreated:$guestDaysSinceCreated;LastLogonDate:$LastLogonDate;DaysSinceLastLogon:$guestDaysSinceLastLogon;ShowInAddressList:$guestShowInAddressList" -LogLevel INFO -ConsoleOutput
            }
        }
    }

    if($ExportCSVPath -and (-not($AutomationPSCredential))){
        
        Write-Log -Message "Exporting to CSV with path of $($ExportCSVPath)\Remove-StaleGuests$(((get-date).ToUniversalTime()).ToString("yyyyMMddThhmmssZ")).csv" -LogLevel INFO -ConsoleOutput
                            
        $report | Export-Csv -Path "$($ExportCSVPath)\Remove-StaleGuests$(((get-date).ToUniversalTime()).ToString("yyyyMMddThhmmssZ")).csv" -Encoding UTF8
                        
    }


    if ($AutomationPSCredential) {
        
        #Invoke-Command -Session $ExchangeOnlineSession -ScriptBlock {Remove-PSSession -Session $ExchangeOnlineSession}

        Disconnect-AzureAD
    }
