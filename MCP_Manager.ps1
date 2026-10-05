#requires -Version 5.1
<#
.SYNOPSIS
MCP Manager for Windows Server
.DESCRIPTION
Management script to set up the MCP MySQL Server. The
authenticated tunnel launches server.py. Secrets use
current-user DPAPI. Each named instance has separate
settings, secrets and a startup task.
Requires Windows Server 2016 or newer and Windows PowerShell 5.1.

.EXAMPLE
.\MCP_Manager.ps1
.EXAMPLE
.\MCP_Manager.ps1 -Instance production -Action Restart
#>
[CmdletBinding()]
param(
    [ValidateSet('Menu','Setup','ConfigureDatabase','ConfigureTunnel','ExportSql','InstallKey','RemoveKey','Start','Stop','Restart','Status','EnableAutostart','DisableAutostart','Test','Run','SetKey','InstallAutostart','RemoveAutostart')]
    [string]$Action = 'Menu',
    [ValidatePattern('^[A-Za-z][A-Za-z0-9_]{0,19}$')]
    [string]$Instance = 'default',
    [string]$PythonPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This manager requires Windows' }
if ([Environment]::OSVersion.Version.Major -lt 10) { throw 'This manager requires Windows Server 2016 or newer (Windows 10 or newer on desktops)' }
Add-Type -AssemblyName System.Security
$Instance = $Instance.ToLowerInvariant()
if ($Instance -match '^(con|prn|aux|nul|com[1-9]|lpt[1-9])$') { throw 'Choose an instance name that is not a reserved Windows filename' }
$script:Root = $PSScriptRoot
$script:Manager = $PSCommandPath
$script:BaseData = Join-Path $env:LOCALAPPDATA 'MCP-MySQL'
$script:Data = Join-Path $script:BaseData $Instance
$script:Client = Join-Path $script:Root 'tunnel-client.exe'
$script:Profile = $Instance
$script:ApiKeyEnv = 'CONTROL_PLANE_API_KEY'
$script:TunnelConfig = Join-Path $script:Data 'tunnel.json'
$script:TunnelConfigError = $false
$script:StoppedLock = $null
$script:Python = Join-Path $script:Root '.venv\Scripts\python.exe'
$script:Config = Join-Path $script:Data 'mcp-db.json'
$script:Key = Join-Path $script:Data 'runtime-key.dpapi'
$script:DbKey = Join-Path $script:Data 'database-password.dpapi'
$script:State = Join-Path $script:Data 'process.json'
$script:StopFile = Join-Path $script:Data 'stop-requested'
$script:PowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$script:TaskName = 'MCP-MySQL-' + $script:Identity.User.Value + '-' + $Instance
$script:Utf8 = [Text.UTF8Encoding]::new($false)
$script:BootTicks = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().Ticks.ToString()
$hasher = [Security.Cryptography.SHA256]::Create()
try { $rootHash = ([BitConverter]::ToString($hasher.ComputeHash($script:Utf8.GetBytes($script:Root.ToLowerInvariant())))).Replace('-','').Substring(0,16) }
finally { $hasher.Dispose() }
$script:EnvironmentLock = Join-Path $script:BaseData ('environment-' + $rootHash + '.lock')

function Initialize-Data {
    # - prevent another unprivileged account from replacing secrets or process state
    foreach ($directory in @($script:BaseData, $script:Data)) {
        [IO.Directory]::CreateDirectory($directory) | Out-Null
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetOwner($script:Identity.User)
        foreach ($sid in @($script:Identity.User.Value, 'S-1-5-18', 'S-1-5-32-544')) {
            $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                [Security.Principal.SecurityIdentifier]::new($sid), 'FullControl',
                'ContainerInherit,ObjectInherit', 'None', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $directory -AclObject $acl
    }
}

function Write-Atomic([string]$Path, [string]$Text) {
    $temp = Join-Path $script:Data ([IO.Path]::GetRandomFileName())
    try {
        [IO.File]::WriteAllText($temp, $Text, $script:Utf8)
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temp, $Path, [NullString]::Value) }
        else { [IO.File]::Move($temp, $Path) }
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
}

function Save-Secret([string]$Path, [string]$Prompt) {
    $secret = Read-Host $Prompt -AsSecureString
    $pointer = [IntPtr]::Zero
    $bytes = $null
    try {
        if ($secret.Length -eq 0) { throw 'The value is empty' }
        $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        if ($plain.Length -gt 16384 -or $plain.Contains([char]0)) { throw 'The value is too long or invalid' }
        $bytes = [Text.Encoding]::UTF8.GetBytes($plain)
        if ($bytes.Length -gt 16384) { throw 'The encoded value exceeds 16 KiB' }
        $protected = [Security.Cryptography.ProtectedData]::Protect($bytes, $null,
            [Security.Cryptography.DataProtectionScope]::CurrentUser)
        Write-Atomic $Path ([Convert]::ToBase64String($protected))
    } finally {
        $plain = $null
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        if ($pointer -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
        $secret.Dispose()
    }
}

function Read-Secret([string]$Path) {
    if ((Get-Item -LiteralPath $Path).Length -gt 65536) { throw 'Invalid encrypted secret file' }
    $encoded = [IO.File]::ReadAllText($Path).Trim()
    $bytes = [Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($encoded),
        $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    try { return [Text.Encoding]::UTF8.GetString($bytes) }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Get-ManagedState {
    if (!(Test-Path -LiteralPath $script:State)) { return $null }
    try {
        if ((Get-Item -LiteralPath $script:State).Length -gt 16384) { return $null }
        $state = [IO.File]::ReadAllText($script:State) | ConvertFrom-Json
        if ($null -eq $state -or $state -is [array]) { return $null }
        foreach ($name in @('Root','Instance','SupervisorPid','SupervisorTicks','ClientPid')) {
            if ($null -eq $state.PSObject.Properties[$name]) { return $null }
        }
        if ($state.Root -isnot [string] -or [string]::IsNullOrWhiteSpace($state.Root) -or
            $state.Instance -isnot [string] -or $state.Instance -cne $Instance -or
            $state.SupervisorTicks -isnot [string] -or $state.SupervisorTicks -cnotmatch '^[0-9]{1,19}$' -or
            ($state.SupervisorPid -isnot [int] -and $state.SupervisorPid -isnot [long]) -or
            ($state.ClientPid -isnot [int] -and $state.ClientPid -isnot [long]) -or
            $state.SupervisorPid -lt 1 -or $state.SupervisorPid -gt [int]::MaxValue -or
            $state.ClientPid -lt 1 -or $state.ClientPid -gt [int]::MaxValue) { return $null }
        $process = Get-Process -Id ([int]$state.SupervisorPid) -ErrorAction SilentlyContinue
        try {
            if ($null -eq $process -or $process.StartTime.ToUniversalTime().Ticks.ToString() -ne $state.SupervisorTicks -or
                $process.Path -ine $script:PowerShell) { return $null }
        } finally { if ($null -ne $process) { $process.Dispose() } }
    } catch { return $null }
    # - a dead supervisor must not pin an instance to an old installation path
    if ($state.Root -ine $script:Root) { throw 'Another installation uses this account; stop it using its original manager' }
    return $state
}

function Get-OperationLock {
    try { return [IO.File]::Open((Join-Path $script:Data 'manage.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { throw 'Another management command is running; retry shortly' }
}

function Get-EnvironmentReadLock {
    if (!(Test-Path -LiteralPath $script:EnvironmentLock)) {
        $created = [IO.File]::Open($script:EnvironmentLock, 'OpenOrCreate', 'ReadWrite', 'ReadWrite')
        $created.Dispose()
    }
    return [IO.File]::Open($script:EnvironmentLock, 'Open', 'Read', 'Read')
}

function Assert-Stopped {
    if ($null -ne $script:StoppedLock) { return }
    if ($null -ne (Get-ManagedState)) { throw 'Stop the server before changing its configuration or secrets' }
    # - hold the lock until the management action finishes, including all writes
    try { $script:StoppedLock = [IO.File]::Open((Join-Path $script:Data 'run.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { throw 'The server is starting or running; stop it first' }
}

function Get-Task {
    return Get-ScheduledTask -TaskName $script:TaskName -ErrorAction SilentlyContinue
}

function Assert-TaskOwner($Task) {
    if ($null -eq $Task) { return }
    $argsExpected = Get-RunArguments
    if (@($Task.Actions).Count -ne 1 -or $Task.Actions[0].Execute -ine $script:PowerShell -or
        $Task.Actions[0].Arguments -cne $argsExpected) {
        throw 'A startup task belongs to another installation or profile; use its original manager'
    }
    if ($Task.Principal.RunLevel -ne 'Limited' -or $Task.Principal.LogonType -ne 'Password') {
        throw 'The startup task has an unexpected run level or logon type; inspect it before reuse'
    }
    $taskUser = $Task.Principal.UserId
    if ($taskUser -match '^S-1-') { $taskSid = [Security.Principal.SecurityIdentifier]::new($taskUser) }
    else { $taskSid = [Security.Principal.NTAccount]::new($taskUser).Translate([Security.Principal.SecurityIdentifier]) }
    if ($taskSid.Value -ne $script:Identity.User.Value) { throw 'The startup task uses a different Windows account' }
}

function Get-RunArguments {
    if ($script:Manager.Contains('"')) { throw 'Invalid script path' }
    return '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Action Run -Instance "{1}"' -f $script:Manager, $Instance
}

function Assert-Ready {
    if ($script:TunnelConfigError) { throw 'Tunnel settings are invalid; run ConfigureTunnel to repair them' }
    foreach ($path in @($script:Client, $script:Python, (Join-Path $script:Root 'server.py'), $script:Config, $script:Key, $script:DbKey)) {
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing $path. Run Setup, ConfigureDatabase and InstallKey first" }
    }
}

function Invoke-DatabaseTest {
    $environmentLock = $null
    try {
        # - another instance must not replace Python while this check is using it
        $environmentLock = Get-EnvironmentReadLock
        if (!(Test-Path -LiteralPath $script:Python)) { throw 'Run Setup first' }
        if (!(Test-Path -LiteralPath $script:Config)) { throw 'Run ConfigureDatabase first' }
        & $script:Python -I (Join-Path $script:Root 'server.py') --config $script:Config --check
        if ($LASTEXITCODE -ne 0) { throw 'Database check failed; verify grants, metadata views and the saved password' }
    } finally { if ($null -ne $environmentLock) { $environmentLock.Dispose() } }
}

function Start-Server {
    Assert-Ready
    if ($null -ne (Get-ManagedState)) { Write-Host 'Server is already running'; return }
    $task = Get-Task
    Assert-TaskOwner $task
    Remove-Item -LiteralPath $script:StopFile -Force -ErrorAction SilentlyContinue
    if ($null -ne $task) {
        if ($task.State -eq 'Disabled') { throw 'Startup task is disabled; remove it or enable autostart again' }
        Start-ScheduledTask -TaskName $script:TaskName
    } else {
        Start-Process -FilePath $script:PowerShell -ArgumentList (Get-RunArguments) `
            -WorkingDirectory $script:Root -WindowStyle Hidden | Out-Null
    }
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        Start-Sleep -Milliseconds 200
        $state = Get-ManagedState
        if ($null -ne $state -and $state.ClientPid -gt 0) {
            Write-Host "Server started (tunnel PID $($state.ClientPid)). You can close this window"
            return
        }
    } while ($timer.Elapsed.TotalSeconds -lt 12)
    throw "Server did not start. Check $script:Data\supervisor.log and tunnel.stderr.log"
}

function Stop-Server {
    $task = Get-Task
    Assert-TaskOwner $task
    # - every current or delayed supervisor checks this boot-scoped stop request
    # - daily Stop therefore needs no scheduled-task modification privileges
    Write-Atomic $script:StopFile $script:BootTicks
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        $state = Get-ManagedState
        $lock = $null
        try { $lock = [IO.File]::Open((Join-Path $script:Data 'run.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
        catch { }
        if ($null -ne $lock) { $lock.Dispose(); Write-Host 'Server stopped'; return }
        Start-Sleep -Milliseconds 200
    } while ($timer.Elapsed.TotalSeconds -lt 12)
    # - killing the verified supervisor closes its job and kills the entire tunnel tree
    if ($null -ne $state) {
        $process = Get-Process -Id ([int]$state.SupervisorPid) -ErrorAction SilentlyContinue
        if ($null -ne $process -and $process.StartTime.ToUniversalTime().Ticks.ToString() -eq $state.SupervisorTicks -and
            $process.Path -ieq $script:PowerShell) {
            $process.Kill()
            if (!$process.WaitForExit(5000)) { throw 'Supervisor did not stop' }
            Write-Host 'Server stopped'
            return
        }
    }
    throw 'Could not verify the supervisor; no unrelated process was terminated'
}

function Enable-Autostart {
    Assert-Ready
    $principal = [Security.Principal.WindowsPrincipal]::new($script:Identity)
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Open PowerShell as administrator using the same Windows account to configure boot startup'
    }
    $task = Get-Task
    Assert-TaskOwner $task
    if ($null -ne $task) { Enable-ScheduledTask -TaskName $script:TaskName | Out-Null; Write-Host 'Autostart is enabled'; return }
    $credential = Get-Credential -UserName $script:Identity.Name `
        -Message 'Windows stores this account credential so the server can start at boot before login'
    if ($null -eq $credential) { throw 'Credential entry was cancelled' }
    $sid = [Security.Principal.NTAccount]::new($credential.UserName).Translate([Security.Principal.SecurityIdentifier])
    if ($sid.Value -ne $script:Identity.User.Value) { throw 'Use the Windows account that saved the keys' }
    $taskAction = New-ScheduledTaskAction -Execute $script:PowerShell -Argument (Get-RunArguments) -WorkingDirectory $script:Root
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT30S'
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew `
        -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $script:TaskName -Action $taskAction -Trigger $trigger -Settings $settings `
        -User $credential.UserName -Password $credential.GetNetworkCredential().Password -RunLevel Limited `
        -Description ('MCP MySQL Server (' + $Instance + '); current-user DPAPI credentials') | Out-Null
    $credential = $null
    Write-Host 'Autostart installed: starts 30 seconds after boot, before login'
    Write-Host 'After changing this Windows account password, remove and reinstall autostart'
}

function Disable-Autostart {
    $task = Get-Task
    Assert-TaskOwner $task
    # - stop first so unregistering the task cannot leave an unmanaged server
    Stop-Server
    if ($null -eq $task) { Write-Host 'Autostart is already removed'; return }
    Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false
    Write-Host 'Autostart removed. Use Start for manual operation'
}

function Show-Status {
    Write-Host "Instance: $Instance; tunnel profile: $script:Profile"
    $state = Get-ManagedState
    if ($null -eq $state) {
        $runLock = $null
        try {
            $runLock = [IO.File]::Open((Join-Path $script:Data 'run.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
            Write-Host 'Server: stopped'
        } catch { Write-Host 'Server: starting, running or inaccessible; verified process state is unavailable' }
        finally { if ($null -ne $runLock) { $runLock.Dispose() } }
    }
    else { Write-Host "Server: running (tunnel PID $($state.ClientPid))" }
    $task = Get-Task
    Assert-TaskOwner $task
    if ($null -eq $task) { Write-Host 'Boot autostart: off' }
    else {
        Write-Host "Boot autostart: $($task.State)"
        $info = Get-ScheduledTaskInfo -TaskName $script:TaskName
        Write-Host "Last task result: $($info.LastTaskResult)"
    }
    Write-Host ('API key installed: ' + (Test-Path -LiteralPath $script:Key))
    Write-Host ('Database configured: ' + ((Test-Path -LiteralPath $script:Config) -and (Test-Path -LiteralPath $script:DbKey)))
    if ($script:TunnelConfigError) { Write-Host 'Tunnel settings: invalid; run ConfigureTunnel' }
    Write-Host "Logs and settings: $script:Data"
    Write-Host 'Running indicates process status. Use Test to verify database access'
}

function Assert-ApiKeyEnvironment([string]$Name) {
    if ($Name -cnotmatch '^[A-Z_][A-Z0-9_]{0,63}$' -or $Name -match '^(MCP_MYSQL_|PYTHON)' -or
        $Name -in @('PATH','PATHEXT','SYSTEMROOT','COMSPEC','TEMP','TMP','USERPROFILE','LOCALAPPDATA')) {
        throw 'Use an uppercase API-key environment variable, not a system or server setting'
    }
}

function Load-TunnelConfig {
    if (!(Test-Path -LiteralPath $script:TunnelConfig)) { return }
    if ((Get-Item -LiteralPath $script:TunnelConfig).Length -gt 16384) { throw 'Tunnel configuration is too large' }
    $settings = [IO.File]::ReadAllText($script:TunnelConfig) | ConvertFrom-Json
    if (@($settings.PSObject.Properties.Name | Where-Object { $_ -notin @('profile','client_path','api_key_environment') }).Count -gt 0) {
        throw 'Unknown tunnel configuration field; run ConfigureTunnel'
    }
    foreach ($name in @('profile','client_path','api_key_environment')) {
        if ($null -eq $settings.PSObject.Properties[$name] -or $settings.$name -isnot [string]) { throw 'Invalid tunnel configuration; run ConfigureTunnel' }
    }
    if ($settings.profile -cnotmatch '^[A-Za-z0-9_-]{1,64}$' -or $settings.client_path.Contains('"') -or
        ![IO.Path]::IsPathRooted($settings.client_path) -or [IO.Path]::GetExtension($settings.client_path) -ine '.exe') {
        throw 'Invalid tunnel executable or profile; run ConfigureTunnel'
    }
    Assert-ApiKeyEnvironment $settings.api_key_environment
    $script:Profile = $settings.profile
    $script:Client = [IO.Path]::GetFullPath($settings.client_path)
    $script:ApiKeyEnv = $settings.api_key_environment
    $script:TunnelConfigError = $false
}

function Configure-Tunnel {
    Assert-Stopped
    $path = Read-Host "Tunnel executable [$script:Client]"
    if (!$path) { $path = $script:Client }
    $path = $path.Trim().Trim([char]'"')
    if (!(Test-Path -LiteralPath $path -PathType Leaf) -or [IO.Path]::GetExtension($path) -ine '.exe') { throw 'Select an existing tunnel .exe file' }
    $path = (Resolve-Path -LiteralPath $path).Path
    $profileName = Read-Host "Tunnel profile [$script:Profile]"
    if (!$profileName) { $profileName = $script:Profile }
    if ($profileName -cnotmatch '^[A-Za-z0-9_-]{1,64}$') { throw 'Profile names use letters, digits, underscores and hyphens' }
    $keyEnvironment = Read-Host "API-key environment variable [$script:ApiKeyEnv]"
    if (!$keyEnvironment) { $keyEnvironment = $script:ApiKeyEnv }
    Assert-ApiKeyEnvironment $keyEnvironment
    Write-Atomic $script:TunnelConfig (@{ profile=$profileName; client_path=$path; api_key_environment=$keyEnvironment } | ConvertTo-Json)
    Load-TunnelConfig
    Write-Host 'Tunnel settings saved. The manager runs: <executable> run --profile <profile>'
}

function Configure-Database {
    Assert-Stopped
    $hostName = Read-Host 'Database host [127.0.0.1]'
    if (!$hostName) { $hostName = '127.0.0.1' }
    $portText = Read-Host 'Database port [3306]'
    $portNumber = 3306
    if ($portText -and (![int]::TryParse($portText, [ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 65535)) { throw 'Invalid port' }
    if ($hostName.Length -gt 255 -or $hostName.Contains([char]0)) { throw 'Invalid host' }
    $defaultUser = 'mcp_reader_' + $Instance
    $userName = Read-Host "Read-only database user [$defaultUser]"
    if (!$userName) { $userName = $defaultUser }
    if ($userName -cnotmatch '^[A-Za-z0-9_$]{1,32}$') { throw 'Reader usernames use 1-32 letters, digits, underscores or dollar signs' }
    $database = Read-Host 'Application database name (required)'
    if ($database -cnotmatch '^[A-Za-z0-9_$]{1,64}$' -or $database -in @('mysql','sys','information_schema','performance_schema')) { throw 'Invalid application database name' }
    $defaultMetadata = 'mcp_mysql_meta_' + $Instance
    $metadata = Read-Host "Separate metadata schema [$defaultMetadata]"
    if (!$metadata) { $metadata = $defaultMetadata }
    if ($metadata -cnotmatch '^[A-Za-z0-9_$]{1,64}$' -or $metadata -ieq $database -or
        $metadata -in @('mysql','sys','information_schema','performance_schema')) { throw 'Invalid metadata schema' }
    $caPath = $null
    if ($hostName -notin @('127.0.0.1','::1','localhost')) {
        $caPath = Read-Host 'Absolute path to the trusted database TLS CA certificate'
        if (!(Test-Path -LiteralPath $caPath -PathType Leaf)) { throw 'CA certificate file not found' }
        $caPath = (Resolve-Path -LiteralPath $caPath).Path
    }
    Save-Secret $script:DbKey 'Database password (input hidden)'
    $config = [ordered]@{ host=$hostName; port=$portNumber; user=$userName; database=$database; metadata_schema=$metadata;
        password_file=$script:DbKey; ssl_ca=$caPath; rate_per_minute=120; rate_burst=12;
        rate_state_file=(Join-Path $script:BaseData 'rate-limits.sqlite3'); allowed_tables=$null;
        max_rows_per_page=500; statement_timeout_seconds=5; socket_timeout_seconds=10;
        max_result_bytes=262144; max_packet_bytes=1048576; max_concurrent_reads=2 }
    Write-Atomic $script:Config ($config | ConvertTo-Json -Depth 5)
    Write-Host 'Database configuration saved. Use ExportSql, apply the generated SQL as DBA, then run Test'
    Write-Host 'Table allowlists, rate and resource limits can be edited in mcp-db.json while stopped'
}

function Export-DatabaseSql {
    if (!(Test-Path -LiteralPath $script:Config)) { throw 'Run ConfigureDatabase first' }
    $config = [IO.File]::ReadAllText($script:Config) | ConvertFrom-Json
    foreach ($name in @('database','metadata_schema','user')) {
        if ($null -eq $config.PSObject.Properties[$name] -or $config.$name -isnot [string] -or
            $config.$name -cnotmatch '^[A-Za-z0-9_$]{1,64}$') { throw 'Invalid database configuration' }
    }
    if ($config.user.Length -gt 32 -or $config.database -ieq $config.metadata_schema -or
        $config.database -in @('mysql','sys','information_schema','performance_schema') -or
        $config.metadata_schema -in @('mysql','sys','information_schema','performance_schema')) { throw 'Invalid database or account name' }
    $engine = Read-Host 'Database engine: 1 MariaDB 10.4+, 2 MySQL 8.0.20+ [1]'
    if (!$engine) { $engine = '1' }
    if ($engine -notin @('1','2')) { throw 'Choose 1 or 2' }
    $readerHost = Read-Host 'Allowed reader client host as seen by the database [127.0.0.1]'
    if (!$readerHost) { $readerHost = '127.0.0.1' }
    if ($readerHost -cnotmatch '^[A-Za-z0-9._:%/-]{1,255}$') { throw 'Invalid reader client host' }
    $names = if ($engine -eq '1') { @('setup-mariadb.sql') } else { @('setup-mysql8.sql','refresh-mysql8-metadata.sql') }
    $output = Join-Path $script:Data 'sql'
    [IO.Directory]::CreateDirectory($output) | Out-Null
    foreach ($name in $names) {
        $text = [IO.File]::ReadAllText((Join-Path (Join-Path $script:Root 'sql') $name))
        $text = $text.Replace('{{DATABASE}}',$config.database).Replace('{{METADATA_SCHEMA}}',$config.metadata_schema).
            Replace('{{READER_USER}}',$config.user).Replace('{{READER_HOST}}',$readerHost).Replace('{{OWNER_USER}}',('mcp_owner_' + $Instance))
        $text = $text.Replace('{{DATABASE_GRANT}}',$config.database.Replace('_','\_'))
        if ($text.Contains('{{')) { throw 'SQL template contains unresolved placeholders' }
        Write-Atomic (Join-Path $output $name) $text
    }
    Write-Host "SQL exported to $output"
    Write-Host 'Replace the password placeholders and review the grants before running setup as your DBA'
    Write-Host 'ExportSql never connects to the database or writes decrypted secrets into SQL'
}

function Install-Dependencies {
    Assert-Stopped
    $environmentLock = $null
    try {
        try { $environmentLock = [IO.File]::Open($script:EnvironmentLock, 'OpenOrCreate', 'ReadWrite', 'None') }
        catch { throw 'Stop every running instance from this installation before installing dependencies' }
        $requirements = Join-Path $script:Root 'requirements.lock.txt'
        if (!(Test-Path -LiteralPath $requirements -PathType Leaf)) { throw 'requirements.lock.txt is missing; restore the package before running Setup' }
        $environmentPath = Join-Path $script:Root '.venv'
        $backupPath = Join-Path $script:Root '.venv.previous'
        if (Test-Path -LiteralPath $backupPath) {
            throw "A previous setup backup exists at $backupPath. Keep all instances stopped, restore it as .venv if needed, or remove it after verifying .venv, then retry Setup"
        }
        $selector = @()
        if ($PythonPath) {
            if (!(Test-Path -LiteralPath $PythonPath -PathType Leaf)) { throw 'PythonPath must point to python.exe' }
            $executable = (Resolve-Path -LiteralPath $PythonPath).Path
        } else {
            $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
            if ($null -eq $launcher) { throw 'Install 64-bit Python 3.14.8, or use -Action Setup -PythonPath C:\path\python.exe' }
            $executable = $launcher.Source
            $selector = @('-3.14')
        }
        $versionCheck = "import sys,struct,sysconfig; ok=sys.implementation.name=='cpython' and sys.version_info[:2]==(3,14) and sys.version_info>=(3,14,8) and sys.version_info.releaselevel=='final' and struct.calcsize('P')==8 and not sysconfig.get_config_var('Py_GIL_DISABLED'); print(sys.version.split()[0]); sys.exit(0 if ok else 1)"
        & $executable @selector -I -c $versionCheck
        if ($LASTEXITCODE -ne 0) { throw 'Use standard 64-bit CPython 3.14.8 or a newer 3.14 patch; free-threaded builds are not supported by this lock' }
        $backedUp = Test-Path -LiteralPath $environmentPath
        if ($backedUp) { [IO.Directory]::Move($environmentPath, $backupPath) }
        try {
            # - build at the final path because virtual-environment launchers embed it
            & $executable @selector -I -m venv $environmentPath
            if ($LASTEXITCODE -ne 0) { throw 'Could not create the Python 3.14 environment' }
            & $script:Python -I -m pip --isolated install --require-hashes --only-binary=:all: --index-url https://pypi.org/simple -r $requirements
            if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
            & $script:Python -I -m pip --isolated check
            if ($LASTEXITCODE -ne 0) { throw 'Installed dependencies are inconsistent' }
        } catch {
            $setupError = $_
            try {
                if (Test-Path -LiteralPath $environmentPath) { Remove-Item -LiteralPath $environmentPath -Recurse -Force }
                if ($backedUp) { [IO.Directory]::Move($backupPath, $environmentPath) }
            } catch { throw "Setup failed and rollback could not finish. Keep instances stopped and inspect $environmentPath and $backupPath before retrying" }
            throw $setupError
        }
        if ($backedUp) {
            try { Remove-Item -LiteralPath $backupPath -Recurse -Force }
            catch { Write-Warning "Setup succeeded, but its old environment remains at $backupPath; remove that backup before the next Setup" }
        }
        Write-Host 'Python 3.14 environment installed with verified dependency hashes'
        Write-Host 'Next: ConfigureDatabase, ExportSql, ConfigureTunnel, InstallKey, Test, then Start'
    } finally { if ($null -ne $environmentLock) { $environmentLock.Dispose() } }
}

# - keep the native launcher in this script so there is only one management file
# - create suspended inside a kill-on-close job, with only its three standard handles inherited
function Add-TunnelLauncher {
    if ('McpMySql.ManagedTunnel' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace McpMySql {
    public sealed class ManagedTunnel : IDisposable {
        [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES { public int Length; public IntPtr Descriptor; public int Inherit; }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct STARTUPINFO {
            public int Size; public string Reserved; public string Desktop; public string Title;
            public int X,Y,XSize,YSize,XChars,YChars,Fill,Flags; public short Show,ReservedSize;
            public IntPtr ReservedPointer,Input,Output,Error;
        }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct STARTUPINFOEX {
            public STARTUPINFO Startup; public IntPtr Attributes;
        }
        [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr Process,Thread; public int Pid,Tid; }
        [StructLayout(LayoutKind.Sequential)] struct BASIC_LIMIT {
            public long ProcessTime,JobTime; public uint Flags; public UIntPtr Min,Max;
            public uint Active; public UIntPtr Affinity; public uint Priority,Scheduling;
        }
        [StructLayout(LayoutKind.Sequential)] struct IO_COUNTERS { public ulong A,B,C,D,E,F; }
        [StructLayout(LayoutKind.Sequential)] struct EXTENDED_LIMIT {
            public BASIC_LIMIT Basic; public IO_COUNTERS Io;
            public UIntPtr ProcessMemory,JobMemory,PeakProcess,PeakJob;
        }
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref EXTENDED_LIMIT data,int length);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr attributes,int count,uint flags,ref IntPtr size);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr attributes,uint flags,IntPtr attribute,IntPtr value,UIntPtr size,IntPtr previous,IntPtr returned);
        [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr attributes);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder args,IntPtr processAttr,IntPtr threadAttr,bool inherit,uint flags,IntPtr environment,string directory,ref STARTUPINFOEX startup,out PROCESS_INFORMATION result);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFile(string name,uint access,uint sharing,ref SECURITY_ATTRIBUTES security,uint creation,uint flags,IntPtr template);
        [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
        [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint timeout);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr handle,out uint code);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        IntPtr job,process;
        public int Id { get; private set; }
        static void Check(bool ok) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error()); }
        public ManagedTunnel(string executable,string arguments,string directory,string output,string error,string key,string config,string keyEnvironment) {
            IntPtr stdout=IntPtr.Zero,stderr=IntPtr.Zero,stdin=IntPtr.Zero,env=IntPtr.Zero;
            IntPtr attributes=IntPtr.Zero,handles=IntPtr.Zero,jobs=IntPtr.Zero;
            bool attributesReady=false;
            int environmentBytes=0;
            PROCESS_INFORMATION info=new PROCESS_INFORMATION();
            try {
                job=CreateJobObject(IntPtr.Zero,null); Check(job!=IntPtr.Zero);
                EXTENDED_LIMIT limit=new EXTENDED_LIMIT(); limit.Basic.Flags=0x2000;
                Check(SetInformationJobObject(job,9,ref limit,Marshal.SizeOf(typeof(EXTENDED_LIMIT))));
                SECURITY_ATTRIBUTES sa=new SECURITY_ATTRIBUTES(); sa.Length=Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)); sa.Inherit=1;
                stdout=CreateFile(output,0x40000000,3,ref sa,2,0x80,IntPtr.Zero); Check(stdout!=new IntPtr(-1));
                stderr=CreateFile(error,0x40000000,3,ref sa,2,0x80,IntPtr.Zero); Check(stderr!=new IntPtr(-1));
                stdin=CreateFile("NUL",0x80000000,3,ref sa,3,0x80,IntPtr.Zero); Check(stdin!=new IntPtr(-1));
                var vars=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
                foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables()) vars[(string)entry.Key]=(string)entry.Value;
                vars.Remove("CONTROL_PLANE_API_KEY");
                vars[keyEnvironment]=key; vars["MCP_MYSQL_CONFIG"]=config;
                vars["MCP_MYSQL_API_KEY_ENV"]=keyEnvironment;
                // - avoid inheriting a plaintext database-password override from the desktop
                vars.Remove("MCP_MYSQL_DB_PASSWORD");
                var block=new StringBuilder();
                foreach(var entry in vars) block.Append(entry.Key).Append('=').Append(entry.Value).Append('\0');
                block.Append('\0'); environmentBytes=checked((block.Length+1)*2);
                env=Marshal.StringToHGlobalUni(block.ToString());
                IntPtr attributeBytes=IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero,2,0,ref attributeBytes);
                Check(attributeBytes!=IntPtr.Zero);
                attributes=Marshal.AllocHGlobal(attributeBytes);
                Check(InitializeProcThreadAttributeList(attributes,2,0,ref attributeBytes)); attributesReady=true;
                handles=Marshal.AllocHGlobal(IntPtr.Size*3);
                Marshal.WriteIntPtr(handles,0,stdin); Marshal.WriteIntPtr(handles,IntPtr.Size,stdout); Marshal.WriteIntPtr(handles,IntPtr.Size*2,stderr);
                Check(UpdateProcThreadAttribute(attributes,0,new IntPtr(0x20002),handles,new UIntPtr((uint)(IntPtr.Size*3)),IntPtr.Zero,IntPtr.Zero));
                jobs=Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobs,job);
                Check(UpdateProcThreadAttribute(attributes,0,new IntPtr(0x2000d),jobs,new UIntPtr((uint)IntPtr.Size),IntPtr.Zero,IntPtr.Zero));
                STARTUPINFOEX si=new STARTUPINFOEX(); si.Startup.Size=Marshal.SizeOf(typeof(STARTUPINFOEX)); si.Startup.Flags=0x100;
                si.Startup.Input=stdin; si.Startup.Output=stdout; si.Startup.Error=stderr; si.Attributes=attributes;
                // - job assignment is atomic with creation, including if the supervisor dies here
                Check(CreateProcess(executable,new StringBuilder("\""+executable+"\" "+arguments),IntPtr.Zero,IntPtr.Zero,true,0x08080404,env,directory,ref si,out info));
                process=info.Process; Id=info.Pid;
                Check(ResumeThread(info.Thread)!=0xffffffff);
            } catch {
                if(process!=IntPtr.Zero) TerminateJobObject(job,1);
                Dispose(); throw;
            } finally {
                if(attributesReady) DeleteProcThreadAttributeList(attributes);
                foreach(var buffer in new[]{attributes,handles,jobs}) if(buffer!=IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                if(info.Thread!=IntPtr.Zero) CloseHandle(info.Thread);
                foreach(var handle in new[]{stdout,stderr,stdin}) if(handle!=IntPtr.Zero && handle!=new IntPtr(-1)) CloseHandle(handle);
                if(env!=IntPtr.Zero) { // - wipe the native environment buffer before releasing it
                    for(int index=0;index<environmentBytes;index+=2) Marshal.WriteInt16(env,index,0);
                    Marshal.FreeHGlobal(env);
                }
            }
        }
        public bool Wait(int milliseconds) { uint status=WaitForSingleObject(process,(uint)milliseconds); if(status==0xffffffff) throw new Win32Exception(Marshal.GetLastWin32Error()); return status==0; }
        public int ExitCode { get { uint code; Check(GetExitCodeProcess(process,out code)); return unchecked((int)code); } }
        public void Stop() { if(job!=IntPtr.Zero) Check(TerminateJobObject(job,0)); }
        public void Dispose() { if(job!=IntPtr.Zero) { CloseHandle(job); job=IntPtr.Zero; } if(process!=IntPtr.Zero) { CloseHandle(process); process=IntPtr.Zero; } }
    }
}
'@
}

function Write-SupervisorLog([string]$Message) {
    $path = Join-Path $script:Data 'supervisor.log'
    if ((Test-Path -LiteralPath $path) -and (Get-Item -LiteralPath $path).Length -gt 1048576) {
        Move-Item -LiteralPath $path -Destination ($path + '.1') -Force
    }
    [IO.File]::AppendAllText($path, ((Get-Date).ToString('o') + ' ' + $Message + [Environment]::NewLine), $script:Utf8)
}

function Test-StopRequested {
    return (Test-Path -LiteralPath $script:StopFile) -and ([IO.File]::ReadAllText($script:StopFile).Trim() -eq $script:BootTicks)
}

function Run-Supervisor {
    $lock = $null
    $environmentLock = $null
    $profileLock = $null
    $runner = $null
    $keyText = $null
    $ownedState = $false
    $exitCode = 1
    try {
        try { $lock = [IO.File]::Open((Join-Path $script:Data 'run.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
        catch { return 0 }
        if (Test-StopRequested) { return 0 }
        # - read settings only after acquiring the same lock used by configuration writes
        Load-TunnelConfig
        # - shared access keeps setup from replacing a running instance's virtual environment
        $environmentLock = Get-EnvironmentReadLock
        Assert-Ready
        # - different profiles may share an executable; the same profile cannot run twice
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $profileHash = ([BitConverter]::ToString($hasher.ComputeHash($script:Utf8.GetBytes($script:Client.ToLowerInvariant() + '|' + $script:Profile.ToLowerInvariant())))).Replace('-','') }
        finally { $hasher.Dispose() }
        $profileLock = [IO.File]::Open((Join-Path $script:BaseData ('tunnel-' + $profileHash + '.lock')), 'OpenOrCreate', 'ReadWrite', 'None')
        Add-TunnelLauncher
        $restartDelay = 1
        while (!(Test-StopRequested)) {
            $lifetime = [Diagnostics.Stopwatch]::StartNew()
            try {
                # - rotate only after the previous job is closed; retain one bounded backup
                foreach ($name in @('tunnel.stdout.log','tunnel.stderr.log')) {
                    $path = Join-Path $script:Data $name
                    if (Test-Path -LiteralPath $path) { Move-Item -LiteralPath $path -Destination ($path + '.1') -Force }
                }
                $keyText = Read-Secret $script:Key
                $runner = [McpMySql.ManagedTunnel]::new($script:Client, ('run --profile ' + $script:Profile),
                    $script:Root, (Join-Path $script:Data 'tunnel.stdout.log'), (Join-Path $script:Data 'tunnel.stderr.log'), $keyText, $script:Config, $script:ApiKeyEnv)
                $keyText = $null
                $supervisor = Get-Process -Id $PID
                try {
                    Write-Atomic $script:State (@{ Root=$script:Root; Instance=$Instance; Profile=$script:Profile; SupervisorPid=$PID;
                        SupervisorTicks=$supervisor.StartTime.ToUniversalTime().Ticks.ToString(); ClientPid=$runner.Id } | ConvertTo-Json)
                } finally { $supervisor.Dispose() }
                $ownedState = $true
                Write-SupervisorLog ('tunnel started pid=' + $runner.Id)
                while (!$runner.Wait(250)) {
                    if (Test-StopRequested) { $runner.Stop(); break }
                    # - recycle the tunnel at the log limit instead of leaving the instance offline
                    $logLimit = $false
                    foreach ($name in @('tunnel.stdout.log','tunnel.stderr.log')) {
                        if ((Get-Item -LiteralPath (Join-Path $script:Data $name)).Length -gt 10485760) { $logLimit = $true; break }
                    }
                    if ($logLimit) {
                        Write-SupervisorLog 'tunnel log reached 10 MiB; recycling tunnel'
                        $runner.Stop()
                        break
                    }
                }
                if (!$runner.Wait(5000)) { throw 'Tunnel did not exit' }
                $exitCode = $runner.ExitCode
                if (Test-StopRequested) { $exitCode = 0 }
                elseif ($exitCode -eq 0) { $exitCode = 1 }
                Write-SupervisorLog ('tunnel exited code=' + $exitCode)
            } catch {
                # - retry without logging exceptions that might contain credentials
                Write-SupervisorLog 'tunnel failed; verify profile, dependencies, saved keys and tunnel logs'
                $exitCode = 1
            } finally {
                $keyText = $null
                if ($null -ne $runner) { $runner.Dispose(); $runner = $null }
                if ($ownedState) { Remove-Item -LiteralPath $script:State -Force -ErrorAction SilentlyContinue; $ownedState = $false }
            }
            if (Test-StopRequested) { return 0 }
            if ($lifetime.Elapsed.TotalSeconds -ge 60) { $restartDelay = 1 }
            Write-SupervisorLog ('tunnel restart in seconds=' + $restartDelay)
            $delay = [Diagnostics.Stopwatch]::StartNew()
            while ($delay.Elapsed.TotalSeconds -lt $restartDelay) {
                if (Test-StopRequested) { return 0 }
                Start-Sleep -Milliseconds 250
            }
            $restartDelay = [Math]::Min(60, $restartDelay * 2)
        }
        $exitCode = 0
    } catch {
        # - do not copy exception text that could contain the tunnel environment
        Write-SupervisorLog 'supervisor failed; verify profile, dependencies, saved keys and tunnel logs'
        $exitCode = 1
    } finally {
        $keyText = $null
        if ($null -ne $runner) { $runner.Dispose() }
        if ($ownedState) { Remove-Item -LiteralPath $script:State -Force -ErrorAction SilentlyContinue }
        if ($null -ne $profileLock) { $profileLock.Dispose() }
        if ($null -ne $environmentLock) { $environmentLock.Dispose() }
        if ($null -ne $lock) { $lock.Dispose() }
    }
    return $exitCode
}

function Invoke-Action([string]$Choice) {
    if ($Choice -eq 'SetKey') { $Choice = 'InstallKey' }
    if ($Choice -eq 'InstallAutostart') { $Choice = 'EnableAutostart' }
    if ($Choice -eq 'RemoveAutostart') { $Choice = 'DisableAutostart' }
    $lock = Get-OperationLock
    try {
        switch ($Choice) {
            'Setup' { Install-Dependencies }
            'ConfigureDatabase' { Configure-Database }
            'ConfigureTunnel' { Configure-Tunnel }
            'ExportSql' { Export-DatabaseSql }
            'InstallKey' { Assert-Stopped; Save-Secret $script:Key 'Tunnel runtime API key (input hidden)'; Write-Host 'API key installed for this Windows account' }
            'RemoveKey' {
                Disable-Autostart
                Assert-Stopped
                Remove-Item -LiteralPath $script:Key -Force -ErrorAction SilentlyContinue
                Write-Host 'API key removed and server stopped'
            }
            'Start' { Start-Server }
            'Stop' { Stop-Server }
            'Restart' { Stop-Server; Start-Server }
            'Status' { Show-Status }
            'EnableAutostart' { Enable-Autostart }
            'DisableAutostart' { Disable-Autostart }
            'Test' { Invoke-DatabaseTest }
        }
    } finally {
        if ($null -ne $script:StoppedLock) { $script:StoppedLock.Dispose(); $script:StoppedLock = $null }
        $lock.Dispose()
    }
}

Initialize-Data
if ($Action -eq 'Run') { exit (Run-Supervisor) }
try { Load-TunnelConfig }
catch { $script:TunnelConfigError = $true }
if ($Action -ne 'Menu') {
    try { Invoke-Action $Action; exit 0 }
    catch { Write-Error -Message $_.Exception.Message -ErrorAction Continue; exit 1 }
}
$choices = @{
    '1'='Setup'; '2'='ConfigureDatabase'; '3'='InstallKey'; '4'='RemoveKey';
    '5'='Start'; '6'='Stop'; '7'='Restart'; '8'='Status'; '9'='EnableAutostart';
    '10'='DisableAutostart'; '11'='Test'; '12'='ConfigureTunnel'; '13'='ExportSql'
}
while ($true) {
    Write-Host ''
    Write-Host "MCP MySQL Server - instance: $Instance"
    Write-Host ' 1 Install Python dependencies    2 Configure database'
    Write-Host ' 3 Install / replace API key      4 Remove API key'
    Write-Host ' 5 Start                         6 Stop'
    Write-Host ' 7 Restart                       8 Status'
    Write-Host ' 9 Enable boot autostart         10 Remove boot autostart'
    Write-Host '11 Test database access         12 Configure tunnel'
    Write-Host '13 Export database setup SQL     0 Exit'
    $choice = Read-Host 'Choose an option'
    if ($choice -eq '0') { break }
    if (!$choices.ContainsKey($choice)) { Write-Host 'Choose one of the listed numbers'; continue }
    try { Invoke-Action $choices[$choice] }
    catch { Write-Host ('Error: ' + $_.Exception.Message) -ForegroundColor Red }
}
