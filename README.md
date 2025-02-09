# Get-IISCredentials
Gets clear-text credentials by mapping IIS Servers and getting IIS appPools, vDirectories, usernames &amp; passwords.<br>
Requires local admin permissions on the target servers(s), as well as port 135 (rpc) and port 5985 (winrm) accessible on all target hosts.
<br><br>
## Background</b><br>
By default, Microsoft Web Server identities’ passwords (e.g. Application Pools, virtual directories etc.) can be extracted as clear-text by any local admin.<br>
This can be, for example, a developer on an IIS box with RDP access, yet the credentials of the appPool/vDir exposed may be of a 'strong' user account, e.g. privileged service account.<br>
This can make adversaries life easier and leveraged for easy access, rather than “poking around” with NTLM hashes, misconfigurations etc.<br>
This is a quite common finding in enterprise environments, where many organizations (still) do not use MSAs/gMSAs for this purpose.<br><br>
Hence, this tool comes to aid Red/Blue/Purple/SOC/Threat hunting/whatever team to map out those servers and accounts, to help secure those IIS boxes in a better way.<br>
### The following steps include risk reduction and mitigation of this potential exposure.<br><br>

## Step 1: Mapping IIS servers & credentials
Run _Get-IISCredentials.ps1_ powershell script to map all IIS Servers & Credentials.<br>
You can run it for all the servers in the entire Active Directory domain, or target a specific host.<br>
It Uses RPC to detect the w3svc service, and then WinRM to run appcmd.exe and collect the credentials. hence, both port 135 (rpc) and 5985 (winrm) need to be open and accessible.<br>

## Step 2: Secure Service Accounts on IIS boxes
1. Use Managed Service Accounts<br>
MSA/gMSAs are a secure alternative to user service accounts (also for eliminating SPNs, Scheduled Tasks, SQL etc.)<br><br>
2. Consider encrypting sensitive sections of the web.config<br>
You can use ASP.NET RSA to encrypt sections of the configuration. this is also useful for other sensitive data, e.g. database connection strings.<br>
You'll need to grant the ASP.NET identity read access to the default RSA key container.<br>
Then, you can encrypt the section(s) using aspnet_regiis.exe, e.g.<br>
aspnet_regiis -pef "sectionName" "physicalPathToApplication"<br>
For more information, see https://learn.microsoft.com/en-us/previous-versions/aspnet/dtkwfdky(v=vs.100)<br><br>
3. Protect AppPool credentials using Configuration Locks<br>
This can be another option to limit access, e.g.<br>
appcmd lock config -section:system.webServer/security<br>
4. Alternative: Use Secrets Management solutions<br>
Vaults, e.g. Azure Key Vault, AWS Secrets Manager etc.<br>

## Step 3: Map local administrators on IIS boxes
The ultimate goal of this step is to eventually reduce unnecessary admin access from your IIS boxes, so start by mapping the local ADMINISTRATORS on IIS Servers. You can do this by SCCM, PingCastle local admins scanner, any agent on the target, whatever.<br>
If you want to query it remotely using PowerShell, you can try:<br>
<b>$s = 'SRV1','SRV2','SRV3’;<br>
Invoke-Command  -ComputerName $s -Command {$env:COMPUTERNAME; Get-LocalGroupMember administrators}<br></b>
You can also use WinNT provider (rpc) if you don't want/can't use WinRM.<br>

## Step 4: Secure local access on IIS boxes
1. Limit wide-admin access to the IIS box to specific & trusted accounts. Start by removing unnecessary local admins.<br>
2. Limit Access to Application Pool Credentials<br>
Restrict ACL on web.config file only to appPool identity.<br>
3. Leverage JEA (Just Enough Access), which is a Secure constrained Role-Based remote access using PowerShell.<br>
Instead of full local access as admin, you can limit identities to run specific CLI commands and tasks, using PSSession-Configuration settings.<br>
e.g. a developer/QA staff can have only start-stop service permissions, or just ability to run net stop WAS, net start W3SVC, etc.<br>

## Note about detecting this script's execution
Obviously, like many other scripts (especially of mine), it's just a tool.. not bad, nor good. that part is up to you 😄<br>
Red teams can ‘enjoy’ and use this script as well to harvest clear-text credentials, once they have local admin access to host(s).<br>
Keep in mind that you can detect the full domain servers run quite easily by the multiple access requests, both RPC & WinRM, on multiple hosts.<br>
In addition, your EDR/Sysmon/Whatever will log not only wsmprovhost.exe process on the IIS box(es), but also that it executed appcmd.exe (with wsmprovhost.exe as parent process).<br>
This may be a bit unusual for most enviroments.<br><br>
<b>Feedback is always welcome!<br>
