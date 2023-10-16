# HelloID-Conn-SA-Sync-Sync-EXO-SharedMailbox-FullAccess-Users-To-ResourceOwner-Groupmemberships
Synchronize Exchange Online users with Full Access to Shared Mailboxes to HelloID Resource Owner Groupmemberships

<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-Sync-EXO-SharedMailbox-FullAccess-Users-To-ResourceOwner-Groupmemberships/network/members"><img src="https://img.shields.io/github/forks/Tools4everBV/HelloID-Conn-SA-Sync-Sync-EXO-SharedMailbox-FullAccess-Users-To-ResourceOwner-Groupmemberships" alt="Forks Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-Sync-EXO-SharedMailbox-FullAccess-Users-To-ResourceOwner-Groupmemberships/pulls"><img src="https://img.shields.io/github/issues-pr/Tools4everBV/HelloID-Conn-SA-Sync-Sync-EXO-SharedMailbox-FullAccess-Users-To-ResourceOwner-Groupmemberships" alt="Pull Requests Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-Sync-EXO-SharedMailbox-FullAccess-Users-To-ResourceOwner-Groupmemberships/issues"><img src="https://img.shields.io/github/issues/Tools4everBV/HelloID-Conn-SA-Sync-Sync-EXO-SharedMailbox-FullAccess-Users-To-ResourceOwner-Groupmemberships" alt="Issues Badge"/></a>
<a href="https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-Sync-EXO-SharedMailbox-FullAccess-Users-To-ResourceOwner-Groupmemberships/graphs/contributors"><img alt="GitHub contributors" src="https://img.shields.io/github/contributors/Tools4everBV/HelloID-Conn-SA-Sync-Sync-EXO-SharedMailbox-FullAccess-Users-To-ResourceOwner-Groupmemberships?color=2b9348"></a>

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |

## Table of Contents
- [HelloID-Conn-SA-Sync-Sync-EXO-SharedMailbox-FullAccess-Users-To-ResourceOwner-Groupmemberships](#HelloID-Conn-SA-Sync-Sync-EXO-SharedMailbox-FullAccess-Users-To-ResourceOwner-Groupmemberships)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Introduction](#introduction)
  - [Getting started](#getting-started)
    - [Create an API key and secret for HelloID](#create-an-api-key-and-secret-for-helloid)
    - [Installing the Microsoft Exchange Online PowerShell V3.1 module](#installing-the-microsoft-exchange-online-powershell-v31-module)
    - [Getting the Azure AD graph API access](#getting-the-azure-ad-graph-api-access)
      - [Creating the Azure AD App Registration and certificate](#creating-the-azure-ad-app-registration-and-certificate)
      - [Application Registration](#application-registration)
      - [Configuring App Permissions](#configuring-app-permissions)
      - [Assign Azure AD roles to the application](#assign-azure-ad-roles-to-the-application)
      - [Authentication and Authorization](#authentication-and-authorization)
    - [Synchronization settings](#synchronization-settings)
  - [Remarks](#remarks)
  - [Getting help](#getting-help)
  - [HelloID Docs](#helloid-docs)

## Requirements
- Make sure you have Windows PowerShell 5.1 installed on the server where the HelloID agent and Service Automation agent are running.
- Installed and available **Microsoft Exchange Online PowerShell V3.1 module**. Please see the [Microsoft documentation](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps) for more information. The download [can be found here](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/3.0.0).
- Required to run **On-Premises** since it is not allowed to import a module with the Cloud Agent.
- An **App Registration in Azure AD** is required.
- Make sure the sychronization is configured to meet your requirements.

## Introduction

By using this connector, you will have the ability to create and remove HelloID Groupmemberships based on the users with full access to shared mailboxes in Exchange Online.

The groupmemberships will be granted for each user with full access to a shared mailbox in scope. This way you won't have to manually add the users to the resource owner group for each shared mailbox.

And vice versa for the removing of the groupmemberships. The groupmemberships will be removed when a user no longer has full access to a shared mailbox. The removal of members is optional, as this removes the possibility to manually manage the users of these groups.

This is intended for scenarios where there are (lots of) shared mailboxes that we want to be requestable as a product. Currently, there is no corresponding productassignments sync for this shared mailbox sync.

This is intended for scenarios where the product sync automatically creates the self service products for shared mailboxes and creates a resource owner for these products. This groupmembership sync is desinged to work in combination with the [Exchange Online Shared Mailboxes to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-Exchange-Online-SharedMailbox-To-SelfService-Products) in the scenario where you'd want the users with full access to act as the resource owner.

## Getting started

### Create an API key and secret for HelloID
1. Go to the `Manage portal > Security > API` section.
2. Click on the `Add Api key` button to create a new API key.
3. Optionally, you can add a note that will describe the purpose of this API key
4. Optionally, you can restrict the IP addresses from which this API key can be used.
5. Click on the `Save` button to save the API key.
6. Go to the `Manage portal > Automation > Variable library` section and confim that the auto variables specified in the [connection settings](#connection-settings) are available.


### Installing the Microsoft Exchange Online PowerShell V3.1 module
Since we use the cmdlets from the Microsoft Exchange Online PowerShell module, it is required this module is installed and available for the service account.
Please follow the [Microsoft documentation on how to install the module](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#install-and-maintain-the-exchange-online-powershell-module). 

### Getting the Azure AD graph API access
#### Creating the Azure AD App Registration and certificate
> _The steps below are based on the [Microsoft documentation](https://docs.microsoft.com/en-us/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps) as of the moment of release. The Microsoft documentation should always be leading and is susceptible to change. The steps below might not reflect those changes._
> >**Please note that our steps differ from the current documentation as we use Access Token Based Authentication instead of Certificate Based Authentication**

#### Application Registration
The first step is to register a new **Azure Active Directory Application**. The application is used to connect to Exchange and to manage permissions.

* Navigate to **App Registrations** in Azure, and select “New Registration” (**Azure Portal > Azure Active Directory > App Registration > New Application Registration**).
* Next, give the application a name. In this example we are using “**ExO PowerShell CBA**” as application name.
* Specify who can use this application (**Accounts in this organizational directory only**).
* Specify the Redirect URI. You can enter any url as a redirect URI value. In this example we used http://localhost because it doesn't have to resolve.
* Click the “**Register**” button to finally create your new application.

Some key items regarding the application are the Application ID (which is the Client ID), the Directory ID (which is the Tenant ID) and Client Secret.

#### Configuring App Permissions
The [Microsoft Graph documentation](https://docs.microsoft.com/en-us/graph) provides details on which permission are required for each permission type.

* To assign your application the right permissions, navigate to **Azure Portal > Azure Active Directory > App Registrations**.
* Select the application we created before, and select “**API Permissions**” or “**View API Permissions**”.
* To assign a new permission to your application, click the “**Add a permission**” button.
* From the “**Request API Permissions**” screen click “**Office 365 Exchange Online**”.
  > _The Office 365 Exchange Online might not be a selectable API. In thise case, select "APIs my organization uses" and search here for "Office 365 Exchange Online"__
* For this connector the following permissions are used as **Application permissions**:
  *	Manage Exchange As Application ***Exchange.ManageAsApp***
* To grant admin consent to our application press the “**Grant admin consent for TENANT**” button.

#### Assign Azure AD roles to the application
Azure AD has more than 50 admin roles available. The **Exchange Administrator** role should provide the required permissions for any task in Exchange Online PowerShell. However, some actions may not be allowed, such as managing other admin accounts, for this the Global Administrator would be required. and Exchange Administrator roles. Please note that the required role may vary based on your configuration.
* To assign the role(s) to your application, navigate to **Azure Portal > Azure Active Directory > Roles and administrators**.
* On the Roles and administrators page that opens, find and select one of the supported roles e.g. “**Exchange Administrator**” by clicking on the name of the role (not the check box) in the results.
* On the Assignments page that opens, click the “**Add assignments**” button.
* In the Add assignments flyout that opens, **find and select the app that we created before**.
* When you're finished, click **Add**.
* Back on the Assignments page, **verify that the app has been assigned to the role**.

For more information about the permissions, please see the Microsoft docs:
* [Permissions in Exchange Online](https://learn.microsoft.com/en-us/exchange/permissions-exo/permissions-exo).
* [Find the permissions required to run any Exchange cmdlet](https://learn.microsoft.com/en-us/powershell/exchange/find-exchange-cmdlet-permissions?view=exchange-ps).
* [View and assign administrator roles in Azure Active Directory](https://learn.microsoft.com/en-us/powershell/exchange/find-exchange-cmdlet-permissions?view=exchange-ps).

#### Authentication and Authorization
There are multiple ways to authenticate to the Graph API with each has its own pros and cons, in this example we are using the Authorization Code grant type.

*	First we need to get the **Client ID**, go to the **Azure Portal > Azure Active Directory > App Registrations**.
*	Select your application and copy the Application (client) ID value.
*	After we have the Client ID we also have to create a **Client Secret**.
*	From the Azure Portal, go to **Azure Active Directory > App Registrations**.
*	Select the application we have created before, and select "**Certificates and Secrets**". 
*	Under “Client Secrets” click on the “**New Client Secret**” button to create a new secret.
*	Provide a logical name for your secret in the Description field, and select the expiration date for your secret.
*	It's IMPORTANT to copy the newly generated client secret, because you cannot see the value anymore after you close the page.
*	At last we need to get the **Tenant ID**. This can be found in the Azure Portal by going to **Azure Active Directory > Overview**.

### Synchronization settings
| Variable name | Description   | Notes |
| ------------- | -----------   | ----- |
| $portalBaseUrl    | String value of HelloID Base Url  | (Default Global Variable) |
| $portalApiKey | String value of HelloID Api Key   | (Default Global Variable) |
| $portalApiSecret  | String value of HelloID Api Secret    | (Default Global Variable) |
| $AzureADtenantID    | String value of Azure AD Tenant ID  | Recommended to set as Global Variable |
| $AzureADAppId | String value of Azure AD App ID  | Recommended to set as Global Variable |
| $AzureADAppSecret  | String value of Azure AD App Secret  | Recommended to set as Global Variable |
| $exchangeMailboxesFilter   | String value of seachfilter of which Exchange shared mailboxes to include   | Optional, when no filter is provided ($exchangeMailboxesFilter = $null), all shared mailboxes will be queried. This should match the filter used in the configuration of the [Exchange Online Shared Mailboxes to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-Exchange-Online-SharedMailbox-To-SelfService-Products)  |
| $resourceOwnerGroupSource  | String value of source of the resource groups in HelloID | Ff source is any other than "Local", the sync of the target system itself might overwrite the memberships set form this sync |
| $resourceOwnerGroupPrefix  | String value of prefix to recognize the resource owner group | Optional, the owner group will be queried based on the shared mailbox name and the specified prefix and suffix  |
| $resourceOwnerGroupSuffix  | String value of suffix to recognize the resource owner group | Optional, the owner group will be queried based on the shared mailbox name and the specified prefix and suffix  |
| $removeMembers  | Boolean value of whether to remove the groupmemberships when they are no longer in scope |  |


## Remarks
- The Productassignments are granted and revoked. Make sure your configuration is correct to avoid unwanted revokes
This groupmembership sync is desinged to work in combination with the [Exchange Online Shared Mailboxes to Products Sync](https://github.com/Tools4everBV/HelloID-Conn-SA-Sync-Exchange-Online-SharedMailbox-To-SelfService-Products). If this is not configured, this sync task might not work (as the resource owner groups probably won't exist) and might need changes accordingly.

## Getting help
> _For more information on how to configure a HelloID PowerShell scheduled task, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/115003253294-Create-Custom-Scheduled-Tasks) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
