# Remove-StaleGuests
Stale guest accounts are a liability and security risk for every organisation utilizing guest accounts. This script was designed to remove guest accounts in the following two scenario’s: (1) when invitation has not been accepted and has expired (90 days) and (2) when an account has become inactive after a user defined period of time. 

````powershell

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


````
