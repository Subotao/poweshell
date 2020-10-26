param(
 [string] $gatewayKey,
 [string]$config
)

<# keys required:
          MONITORING_TENANT
          MONITORING_ROLE
          MONITORING_ROLE_INSTANCE
          MONITORING_DATA_DIRECTORY
          MONITORING_GCS_ACCOUNT
          MONITORING_GCS_NAMESPACE
          MONITORING_GCS_ENVIRONMENT
          MONITORING_GCS_REGION
          MONITORING_CONFIG_VERSION
          // MONITORING_GCS_CERTSTORE - can be ommited as used default
          // MONITORING_GCS_THUMBPRINT - will be passed as CN, then we should get thumbprint via poweshell
          MONITORING_GCS_CN
#>

# required keys for validation object passed as base64
$requiredKeys = @(
'MONITORING_TENANT',
'MONITORING_ROLE',
'MONITORING_ROLE_INSTANCE',
'MONITORING_DATA_DIRECTORY',
'MONITORING_GCS_ACCOUNT',
'MONITORING_GCS_NAMESPACE',
'MONITORING_GCS_ENVIRONMENT',
'MONITORING_GCS_REGION',
'MONITORING_CONFIG_VERSION',
'MONITORING_GCS_CN'
)

# init log setting
$logLoc = "$env:SystemDrive\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\"
if (! (Test-Path($logLoc)))
{
    New-Item -path $logLoc -type directory -Force
}
$logPath = "$logLoc\tracelog.log"
"Start to excute gatewayInstall.ps1. `n" | Out-File $logPath

function Now-Value()
{
    return (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}

function Throw-Error([string] $msg)
{
	try 
	{
		throw $msg
	} 
	catch 
	{
		$stack = $_.ScriptStackTrace
		Trace-Log "DMDTTP is failed: $msg`nStack:`n$stack"
	}

	throw $msg
}

function Trace-Log([string] $msg)
{
    $now = Now-Value
    try
    {
        "${now} $msg`n" | Out-File $logPath -Append
    }
    catch
    {
        #ignore any exception during trace
    }

}

function Run-Process([string] $process, [string] $arguments)
{
	Write-Verbose "Run-Process: $process $arguments"
	
	$errorFile = "$env:tmp\tmp$pid.err"
	$outFile = "$env:tmp\tmp$pid.out"
	"" | Out-File $outFile
	"" | Out-File $errorFile	

	$errVariable = ""

	if ([string]::IsNullOrEmpty($arguments))
	{
		$proc = Start-Process -FilePath $process -Wait -Passthru -NoNewWindow `
			-RedirectStandardError $errorFile -RedirectStandardOutput $outFile -ErrorVariable errVariable
	}
	else
	{
		$proc = Start-Process -FilePath $process -ArgumentList $arguments -Wait -Passthru -NoNewWindow `
			-RedirectStandardError $errorFile -RedirectStandardOutput $outFile -ErrorVariable errVariable
	}
	
	$errContent = [string] (Get-Content -Path $errorFile -Delimiter "!!!DoesNotExist!!!")
	$outContent = [string] (Get-Content -Path $outFile -Delimiter "!!!DoesNotExist!!!")

	Remove-Item $errorFile
	Remove-Item $outFile

	if($proc.ExitCode -ne 0 -or $errVariable -ne "")
	{		
		Throw-Error "Failed to run process: exitCode=$($proc.ExitCode), errVariable=$errVariable, errContent=$errContent, outContent=$outContent."
	}

	Trace-Log "Run-Process: ExitCode=$($proc.ExitCode), output=$outContent"

	if ([string]::IsNullOrEmpty($outContent))
	{
		return $outContent
	}

	return $outContent.Trim()
}

function Download-Gateway([string] $url, [string] $gwPath)
{
    try
    {
        $ErrorActionPreference = "Stop";
        $client = New-Object System.Net.WebClient
        $client.DownloadFile($url, $gwPath)
        Trace-Log "Download gateway successfully. Gateway loc: $gwPath"
    }
    catch
    {
        Trace-Log "Fail to download gateway msi"
        Trace-Log $_.Exception.ToString()
        throw
    }
}

function Install-Gateway([string] $gwPath)
{
	if ([string]::IsNullOrEmpty($gwPath))
    {
		Throw-Error "Gateway path is not specified"
    }

	if (!(Test-Path -Path $gwPath))
	{
		Throw-Error "Invalid gateway path: $gwPath"
	}
	
	Trace-Log "Start Gateway installation"
	Run-Process "msiexec.exe" "/i gateway.msi INSTALLTYPE=AzureTemplate /quiet /norestart"		
	
	Start-Sleep -Seconds 30	

	Trace-Log "Installation of gateway is successful"
}

function Get-RegistryProperty([string] $keyPath, [string] $property)
{
	Trace-Log "Get-RegistryProperty: Get $property from $keyPath"
	if (! (Test-Path $keyPath))
	{
		Trace-Log "Get-RegistryProperty: $keyPath does not exist"
	}

	$keyReg = Get-Item $keyPath
	if (! ($keyReg.Property -contains $property))
	{
		Trace-Log "Get-RegistryProperty: $property does not exist"
		return ""
	}

	return $keyReg.GetValue($property)
}

function Get-InstalledFilePath()
{
	$filePath = Get-RegistryProperty "hklm:\Software\Microsoft\DataTransfer\DataManagementGateway\ConfigurationManager" "DiacmdPath"
	if ([string]::IsNullOrEmpty($filePath))
	{
		Throw-Error "Get-InstalledFilePath: Cannot find installed File Path"
	}
    Trace-Log "Gateway installation file: $filePath"

	return $filePath
}

function Register-Gateway([string] $instanceKey)
{
    Trace-Log "Register Agent"
	$filePath = Get-InstalledFilePath
	Run-Process $filePath "-era 8060"
	Run-Process $filePath "-k $instanceKey"
    Trace-Log "Agent registration is successful!"
}
# convert base64 argument into hash table
function Convert-Config([string] $config)
{
    try
    {
        $ErrorActionPreference = "Stop";
        $json_string = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($config))
        $json_object = ConvertFrom-Json -InputObject $json_string
        $script:config_values = @{}
        foreach ($property in $json_object.PSObject.Properties) {
            $config_values[$property.Name] = $property.Value
        }

        foreach ($item in $requiredKeys) {
            if ($config_values.ContainsKey($item)) {
                Trace-Log "$item : $($config_values[$item])"
            } else {
                throw "$item is not present config"
            }  
        }
    }
    catch
    {
        Trace-Log "Fail to convert config"
        Trace-Log $_.Exception.ToString()
        throw
    }
}

# Create bat file with config for Geneva startup

function Create-Config-In-Bat()
{
    try
    {
        $ErrorActionPreference = "Stop";
        $thumbprint = Get-Cert-Thumbprint-Via-CN($config_values['MONITORING_GCS_CN'])

        $batFileFolder = "C:\GenevaAgent\"
        if (! (Test-Path($batFileFolder)))
        {
            New-Item -path $batFileFolder -type directory -Force
        }
        if (! (Test-Path($($config_values['MONITORING_DATA_DIRECTORY']))))
        {
            New-Item -path $($config_values['MONITORING_DATA_DIRECTORY']) -type directory -Force
        }

        $script:batfile = "C:\GenevaAgent\LaunchAgent.bat"
# ugly here, but pretty in bat file        
        $batFileContent ="set MONITORING_TENANT=$($config_values['MONITORING_TENANT'])
set MONITORING_ROLE=$($config_values['MONITORING_ROLE'])
set MONITORING_ROLE_INSTANCE=$($config_values['MONITORING_ROLE_INSTANCE'])
set MONITORING_DATA_DIRECTORY=$($config_values['MONITORING_DATA_DIRECTORY'])
set MONITORING_GCS_ACCOUNT=$($config_values['MONITORING_GCS_ACCOUNT'])
set MONITORING_GCS_NAMESPACE=$($config_values['MONITORING_GCS_NAMESPACE'])
set MONITORING_GCS_ENVIRONMENT=$($config_values['MONITORING_GCS_ENVIRONMENT'])
set MONITORING_GCS_REGION=$($config_values['MONITORING_GCS_REGION'])
set MONITORING_CONFIG_VERSION=$($config_values['MONITORING_CONFIG_VERSION'])
set MONITORING_GCS_CERTSTORE=LOCAL_MACHINE\MY
set MONITORING_GCS_THUMBPRINT=$($thumbprint)
%MonAgentClientLocation%\MonAgentClient.exe -useenv"

        $batFileContent | Out-File -FilePath $batfile
    }
    catch
    {
        Trace-Log "Fail to create bat file with config"
        Trace-Log $_.Exception.ToString()
        throw
    }
}

#Genevamonaget require certificate thumbprint instead of certficate CN, so here we gathering thumbpring from cert with cn

function Get-Cert-Thumbprint-Via-CN([string] $cn)
{
    try
    {
        $ErrorActionPreference = "Stop";
        $certs = (gci Cert:\LocalMachine\My\ | where { $_.Thumbprint -eq $cn -or $_.Subject -eq "CN="+$cn } | Sort-Object -Property NotAfter -Descending)
        if ($certs.Count -lt 1) {
            throw "Certificate(s) with subject: " + $cn + " does not exist at Cert:\LocalMachine\My\"
        }
        return $certs[0].Thumbprint

    }
    catch
    {
        Trace-Log "Fail to get thumbprint of certificate with $cn name"
        Trace-Log $_.Exception.ToString()
        throw
    }
}

#Create scheduled task which will run Geneva mon on each reboot of VM

function Create-Scheduled-Task()
{
    try
    {
        $ErrorActionPreference = "Stop";
        $taskname = "Run Geneva agent on reboot"

        if ($(Get-ScheduledTask -TaskName $taskname -ErrorAction SilentlyContinue).TaskName -eq $taskname) {
            Unregister-ScheduledTask -TaskName $taskname -Confirm:$False
        }
        
        $A = New-ScheduledTaskAction -Execute "$batfile"
        $T = New-ScheduledTaskTrigger -AtStartup
        $P = New-ScheduledTaskPrincipal -GroupId "SYSTEM"
        $S = New-ScheduledTaskSettingsSet
        $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S
        Register-ScheduledTask -TaskName $taskname -InputObject $D
    }
    catch
    {
        Trace-Log "Fail to create scheduled task"
        Trace-Log $_.Exception.ToString()
        throw
    }
}


Trace-Log "Log file: $logLoc"
$uri = "https://go.microsoft.com/fwlink/?linkid=839822"
Trace-Log "Gateway download fw link: $uri"
$gwPath= "$PWD\gateway.msi"
Trace-Log "Gateway download location: $gwPath"


Download-Gateway $uri $gwPath
Install-Gateway $gwPath

Register-Gateway $gatewayKey

Convert-Config $config

Create-Config-In-Bat

Create-Scheduled-Task

$batfile

