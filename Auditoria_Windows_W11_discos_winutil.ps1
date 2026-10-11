#requires -Version 5.1
<#
    Auditoria integral de Windows 10/11 - SOLO LECTURA
    Genera un informe TXT en el Escritorio.
    Recomendado: ejecutar PowerShell como Administrador.
    No elimina archivos ni cambia configuraciones.
#>

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$desktop = [Environment]::GetFolderPath('Desktop')
if ([string]::IsNullOrWhiteSpace($desktop) -or -not (Test-Path $desktop)) {
    $desktop = $env:TEMP
}
$reportPath = Join-Path $desktop "Auditoria_Windows_$stamp.txt"
$script:report = New-Object System.Text.StringBuilder
$script:phaseCount = 0
$script:totalPhases = 22

function Add-Line {
    param([AllowNull()][object]$Text = '')
    [void]$script:report.AppendLine([string]$Text)
}

function Add-Section {
    param([string]$Title)
    Add-Line ''
    Add-Line ('=' * 88)
    Add-Line $Title
    Add-Line ('=' * 88)
}

function Add-CommandOutput {
    param(
        [string]$Title,
        [scriptblock]$Command
    )

    $script:phaseCount++
    $percent = [int](($script:phaseCount - 1) * 100 / $script:totalPhases)
    Write-Progress -Activity 'Auditoría integral de Windows (solo lectura)' `
        -Status ('Fase {0}/{1}: {2}' -f $script:phaseCount, $script:totalPhases, $Title) `
        -PercentComplete $percent
    Write-Host ''
    Write-Host ('[{0}/{1}] INICIANDO: {2}' -f $script:phaseCount, $script:totalPhases, $Title) -ForegroundColor Cyan

    Add-Section $Title
    try {
        $result = & $Command 2>&1 | Out-String -Width 240
        if ([string]::IsNullOrWhiteSpace($result)) {
            Add-Line '(Sin datos devueltos)'
        } else {
            Add-Line $result.TrimEnd()
        }
        Write-Host ('[{0}/{1}] COMPLETADA: {2}' -f $script:phaseCount, $script:totalPhases, $Title) -ForegroundColor Green
    } catch {
        Add-Line ("ERROR: " + $_.Exception.Message)
        Write-Host ('[{0}/{1}] COMPLETADA CON ERROR: {2}' -f $script:phaseCount, $script:totalPhases, $Title) -ForegroundColor Yellow
    }
}

function Get-ProcessDetails {
    $procMap = @{}
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | ForEach-Object {
        $procMap[[int]$_.ProcessId] = $_
    }
    return $procMap
}

function Format-ProcessForPid {
    param([int]$ProcessId, [hashtable]$Map)
    if ($Map.ContainsKey($ProcessId)) {
        $p = $Map[$ProcessId]
        return ('{0} | PID={1} | Ruta={2} | Proceso padre PID={3}' -f $p.Name, $p.ProcessId, $p.ExecutablePath, $p.ParentProcessId)
    }
    return '(No se pudo resolver el PID; puede ser un proceso protegido o ya finalizado)'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$procMap = Get-ProcessDetails

Add-Line 'AUDITORIA INTEGRAL DE WINDOWS - SOLO LECTURA'
Add-Line ("Fecha local: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))
Add-Line ("Equipo: " + $env:COMPUTERNAME)
Add-Line ("Usuario actual: " + $env:USERDOMAIN + '\' + $env:USERNAME)
Add-Line ("PowerShell: " + $PSVersionTable.PSVersion.ToString())
Add-Line ("Ejecutado como administrador: " + $isAdmin)
Add-Line 'Nota: un hallazgo aislado no demuestra una intrusión. Revisar contexto, ruta, firma y actividad.'
Add-Line 'Privacidad: el informe puede incluir nombres de usuario, nombres de equipo, IP, rutas y software instalado.'

Add-CommandOutput '1. SISTEMA Y CONFIGURACION BASICA' {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime, InstallDate |
        Format-List
    Get-CimInstance Win32_ComputerSystem |
        Select-Object Manufacturer, Model, Domain, PartOfDomain, TotalPhysicalMemory |
        Format-List
}

Add-CommandOutput '2. ADAPTADORES, IP, DNS Y RUTAS' {
    '--- Adaptadores ---'
    Get-NetAdapter -ErrorAction SilentlyContinue |
        Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed |
        Format-Table -AutoSize
    '--- Direcciones IP ---'
    Get-NetIPConfiguration -ErrorAction SilentlyContinue | Format-List InterfaceAlias, IPv4Address, IPv6Address, IPv4DefaultGateway, DNSServer
    '--- Servidores DNS ---'
    Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, AddressFamily, ServerAddresses | Format-Table -Wrap -AutoSize
    '--- Tabla de rutas ---'
    Get-NetRoute -ErrorAction SilentlyContinue |
        Sort-Object AddressFamily, DestinationPrefix, RouteMetric |
        Select-Object AddressFamily, DestinationPrefix, NextHop, RouteMetric, InterfaceAlias |
        Format-Table -AutoSize
    '--- Cache DNS (puede contener nombres recientes) ---'
    Get-DnsClientCache -ErrorAction SilentlyContinue |
        Select-Object -First 300 Entry, Name, Type, Data, Status, TimeToLive |
        Format-Table -Wrap -AutoSize
}

Add-CommandOutput '3. CONEXIONES TCP ACTIVAS Y PUERTOS EN ESCUCHA' {
    $tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Sort-Object State, LocalPort, RemoteAddress
    foreach ($c in $tcp) {
        $owner = Format-ProcessForPid -ProcessId ([int]$c.OwningProcess) -Map $procMap
        '{0}:{1} -> {2}:{3} | Estado={4} | PID={5} | {6}' -f $c.LocalAddress, $c.LocalPort, $c.RemoteAddress, $c.RemotePort, $c.State, $c.OwningProcess, $owner
    }
    '--- Puertos TCP en escucha (resumen) ---'
    Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, OwningProcess |
        Sort-Object LocalPort | Format-Table -AutoSize
    '--- netstat -abno (puede requerir elevacion) ---'
    cmd.exe /c 'netstat -abno'
}

Add-CommandOutput '4. EXTREMOS UDP' {
    $udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Sort-Object LocalPort
    foreach ($u in $udp) {
        $owner = Format-ProcessForPid -ProcessId ([int]$u.OwningProcess) -Map $procMap
        '{0}:{1} | PID={2} | {3}' -f $u.LocalAddress, $u.LocalPort, $u.OwningProcess, $owner
    }
}

Add-CommandOutput '5. PROCESOS ACTIVOS Y LINEAS DE COMANDO' {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Sort-Object Name |
        Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine |
        Format-List
}

Add-CommandOutput '6. SERVICIOS' {
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Sort-Object State, Name |
        Select-Object Name, DisplayName, State, StartMode, StartName, ProcessId, PathName |
        Format-List
}

Add-CommandOutput '7. INICIO AUTOMATICO: WIN32_STARTUPCOMMAND' {
    Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
        Select-Object Name, Command, Location, User |
        Format-List
}

Add-CommandOutput '8. REGISTRO RUN / RUNONCE (EQUIPO Y USUARIOS)' {
    $regPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($path in $regPaths) {
        "--- $path ---"
        if (Test-Path $path) {
            Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
                Select-Object * -ExcludeProperty PSPath, PSParentPath, PSChildName, PSDrive, PSProvider |
                Format-List
        } else {
            '(Clave ausente o inaccesible)'
        }
    }
    '--- Carpetas Startup ---'
    $startupFolders = @(
        [Environment]::GetFolderPath('Startup'),
        [Environment]::GetFolderPath('CommonStartup')
    ) | Select-Object -Unique
    foreach ($folder in $startupFolders) {
        "--- $folder ---"
        if (Test-Path $folder) {
            Get-ChildItem -Force -ErrorAction SilentlyContinue $folder |
                Select-Object FullName, Length, CreationTime, LastWriteTime |
                Format-Table -AutoSize
        }
    }
}

Add-CommandOutput '9. TAREAS PROGRAMADAS' {
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Sort-Object TaskPath, TaskName |
        ForEach-Object {
            $task = $_
            $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                TaskPath = $task.TaskPath
                TaskName = $task.TaskName
                State = $task.State
                Author = $task.Author
                RunAs = $task.Principal.UserId
                Execute = (($task.Actions | ForEach-Object { $_.Execute }) -join '; ')
                Arguments = (($task.Actions | ForEach-Object { $_.Arguments }) -join '; ')
                LastRunTime = $info.LastRunTime
                LastTaskResult = $info.LastTaskResult
                NextRunTime = $info.NextRunTime
            }
        } | Format-List
}

Add-CommandOutput '10. SUSCRIPCIONES WMI PERSISTENTES' {
    '--- Event consumers ---'
    Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue |
        Select-Object __CLASS, Name, CreatorSID |
        Format-List
    '--- Event filters ---'
    Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction SilentlyContinue |
        Select-Object Name, Query, QueryLanguage, EventNamespace |
        Format-List
    '--- Filter-to-consumer bindings ---'
    Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Select-Object Filter, Consumer |
        Format-List
}

Add-CommandOutput '11. CONTROLADORES / DRIVERS' {
    Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
        Sort-Object State, Name |
        Select-Object Name, DisplayName, State, StartMode, PathName, ServiceType |
        Format-List
}

Add-CommandOutput '12. USUARIOS LOCALES Y ADMINISTRADORES' {
    '--- Usuarios locales ---'
    Get-LocalUser -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet, SID |
        Format-Table -AutoSize
    '--- Grupo Administradores ---'
    Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue |
        Select-Object Name, ObjectClass, PrincipalSource, SID |
        Format-Table -AutoSize
    '--- Sesiones de usuario (quser) ---'
    cmd.exe /c 'quser'
    '--- Sesiones SMB entrantes ---'
    Get-SmbSession -ErrorAction SilentlyContinue |
        Select-Object ClientComputerName, ClientUserName, NumOpens, Dialect, SecondsIdle |
        Format-Table -AutoSize
}

Add-CommandOutput '13. ACCESO REMOTO: RDP, WINRM Y CONFIGURACION RELACIONADA' {
    '--- RDP: valor de registro ---'
    $rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    try {
        $rdp = Get-ItemProperty -LiteralPath $rdpKey -Name fDenyTSConnections -ErrorAction Stop
        $rdpEnabled = ([int]$rdp.fDenyTSConnections -eq 0)
        [PSCustomObject]@{
            fDenyTSConnections = $rdp.fDenyTSConnections
            RDPHabilitadoPorRegistro = $rdpEnabled
            Interpretacion = if ($rdpEnabled) { 'RDP permitido por este valor; revisar firewall y políticas' } else { 'RDP deshabilitado por este valor' }
        } | Format-List
    } catch { 'No se pudo leer el valor de RDP: ' + $_.Exception.Message }

    '--- Puerto RDP configurado ---'
    $configuredRdpPort = $null
    try {
        $rdpPort = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber -ErrorAction Stop
        $configuredRdpPort = [int]$rdpPort.PortNumber
        [PSCustomObject]@{ PortNumber = $configuredRdpPort } | Format-List
        '--- Listener TCP en el puerto RDP configurado ---'
        $rdpListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -eq $configuredRdpPort } | Select-Object LocalAddress, LocalPort, OwningProcess)
        if ($rdpListeners.Count -gt 0) { $rdpListeners | Format-Table -AutoSize }
        else { 'No se encontraron listeners TCP en el puerto RDP configurado.' }
    } catch { 'No se pudo consultar el puerto/listener RDP: ' + $_.Exception.Message }

    '--- Servicios relacionados con RDP ---'
    foreach ($serviceName in @('TermService', 'UmRdpService')) {
        try {
            Get-CimInstance Win32_Service -Filter ("Name='" + $serviceName + "'") -ErrorAction Stop |
                Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
                Format-List
        } catch { ('No se pudo consultar el servicio {0}: {1}' -f $serviceName, $_.Exception.Message) }
    }

    '--- WinRM: servicio ---'
    $winrmService = $null
    try {
        $winrmService = Get-CimInstance Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop
        $winrmService |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
            Format-List
    } catch { 'No se pudo consultar WinRM: ' + $_.Exception.Message }

    '--- WinRM: configuración de listeners ---'
    # No invocar winrm.cmd si el servicio está detenido: genera WSManFault y
    # no aporta información útil. Nunca se inicia ni modifica el servicio.
    $winrmCmd = Join-Path $env:SystemRoot 'System32\winrm.cmd'
    if (-not $winrmService) {
        'No se consultó la configuración de listeners porque no se pudo determinar el estado del servicio WinRM.'
    } elseif ($winrmService.State -ne 'Running') {
        ('No se consultó winrm.cmd porque el servicio WinRM está {0}; no se inicia ni modifica el servicio.' -f $winrmService.State)
    } elseif (Test-Path -LiteralPath $winrmCmd) {
        try {
            $winrmOutput = & $winrmCmd enumerate winrm/config/listener 2>&1
            $winrmExitCode = $LASTEXITCODE
            $winrmOutput
            if ($winrmExitCode -ne 0) {
                ('winrm.cmd terminó con código {0}.' -f $winrmExitCode)
            }
        } catch { 'No se pudo consultar la configuración de listeners WinRM: ' + $_.Exception.Message }
    } else {
        'No se encontró winrm.cmd en System32; se continúa con comprobaciones de registro, servicio y puertos.'
    }

    '--- WinRM: puertos TCP 5985/5986 en escucha ---'
    try {
        $winrmPorts = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $_.LocalPort -in @(5985, 5986) } | Select-Object LocalAddress, LocalPort, OwningProcess)
        if ($winrmPorts.Count -gt 0) { $winrmPorts | Format-Table -AutoSize }
        else { 'No se encontraron listeners TCP en 5985 o 5986.' }
    } catch { 'No se pudieron consultar los puertos WinRM: ' + $_.Exception.Message }

    '--- Reglas de firewall relacionadas con RDP/WinRM ---'
    try {
        $remoteRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
            $_.DisplayName -match 'Remote Desktop|Escritorio remoto|Windows Remote Management|Administración remota|WinRM' -or
            $_.DisplayGroup -match 'Remote Desktop|Escritorio remoto|Windows Remote Management|Administración remota|WinRM'
        } | Select-Object DisplayName, DisplayGroup, Enabled, Direction, Action, Profile)
        if ($remoteRules.Count -gt 0) { $remoteRules | Format-Table -Wrap -AutoSize }
        else { 'No se encontraron reglas de firewall cuyo nombre/grupo coincida con RDP o WinRM.' }
    } catch { 'No se pudieron consultar reglas de firewall para RDP/WinRM: ' + $_.Exception.Message }

    '--- Servicios potencialmente asociados a control remoto (solo listado para investigar) ---'
    Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'AnyDesk|TeamViewer|RustDesk|VNC|Remote|ScreenConnect|Splashtop|Atera|MeshAgent|LogMeIn|DWAgent|ChromeRemote|Parsec|UltraView' -or $_.DisplayName -match 'AnyDesk|TeamViewer|RustDesk|VNC|Remote|ScreenConnect|Splashtop|Atera|MeshAgent|LogMeIn|DWAgent|Chrome Remote|Parsec|UltraViewer' } |
        Select-Object Name, DisplayName, State, StartMode, PathName |
        Format-List

    '--- Procesos potencialmente asociados a control remoto (solo listado para investigar) ---'
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'AnyDesk|TeamViewer|RustDesk|VNC|ScreenConnect|Splashtop|Atera|MeshAgent|LogMeIn|DWAgent|ChromeRemote|Parsec|RemoteUtilities|UltraViewer' } |
        Select-Object Name, ProcessId, ExecutablePath, CommandLine |
        Format-List
}

Add-CommandOutput '14. MICROSOFT DEFENDER' {
    Get-MpComputerStatus -ErrorAction SilentlyContinue |
        Select-Object AMServiceEnabled, AntivirusEnabled, AntispywareEnabled, RealTimeProtectionEnabled,
            BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled, IsTamperProtected,
            AntivirusSignatureLastUpdated, AntivirusSignatureVersion, QuickScanAge, FullScanAge |
        Format-List
    '--- Preferencias y exclusiones configuradas ---'
    Get-MpPreference -ErrorAction SilentlyContinue |
        Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection,
            ExclusionPath, ExclusionProcess, ExclusionExtension, AttackSurfaceReductionOnlyExclusions |
        Format-List
    '--- Detecciones recientes registradas por Defender ---'
    Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Select-Object InitialDetectionTime, LastThreatStatusChangeTime, ThreatID, ThreatStatusID,
            ActionSuccess, Resources |
        Format-List
}

Add-CommandOutput '15. FIREWALL DE WINDOWS' {
    Get-NetFirewallProfile -ErrorAction SilentlyContinue |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen, LogBlocked, LogAllowed, LogFileName |
        Format-List
    '--- Reglas habilitadas de entrada que permiten trafico ---'
    Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue |
        Select-Object DisplayName, Profile, Direction, Action, Enabled, Program, Service |
        Format-Table -Wrap -AutoSize
}

Add-CommandOutput '16. PROXY, HOSTS Y CONFIGURACION DNS' {
    '--- Proxy WinHTTP ---'
    netsh.exe winhttp show proxy
    '--- Proxy del usuario (Internet Settings) ---'
    Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue |
        Select-Object ProxyEnable, ProxyServer, AutoConfigURL, AutoDetect |
        Format-List
    '--- Archivo hosts ---'
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (Test-Path $hostsPath) {
        Get-Content $hostsPath -ErrorAction SilentlyContinue
    } else {
        '(No se pudo leer el archivo hosts)'
    }
    '--- DNS por interfaz ---'
    Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, AddressFamily, ServerAddresses |
        Format-List
}

Add-CommandOutput '17. SOFTWARE INSTALADO (INVENTARIO DE REGISTRO)' {
    # Lectura directa de .NET RegistryKey y captura por valor individual:
    # una entrada o valor problemático no interrumpe el resto del inventario.
    $uninstallRoots = @(
        @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'; Hive = [Microsoft.Win32.RegistryHive]::LocalMachine; View = [Microsoft.Win32.RegistryView]::Registry64; Label = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall' },
        @{ Path = 'Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Hive = [Microsoft.Win32.RegistryHive]::LocalMachine; View = [Microsoft.Win32.RegistryView]::Registry64; Label = 'HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' },
        @{ Path = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'; Hive = [Microsoft.Win32.RegistryHive]::CurrentUser; View = [Microsoft.Win32.RegistryView]::Default; Label = 'HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall' }
    )
    $installedApps = New-Object System.Collections.Generic.List[object]
    foreach ($root in $uninstallRoots) {
        $baseKey = $null
        $rootKey = $null
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey($root.Hive, $root.View)
            $rootKey = $baseKey.OpenSubKey($root.Path, $false)
            if ($null -eq $rootKey) { continue }
            foreach ($subkeyName in $rootKey.GetSubKeyNames()) {
                $appKey = $null
                try {
                    $appKey = $rootKey.OpenSubKey($subkeyName, $false)
                    if ($null -eq $appKey) { continue }

                    $valueErrors = New-Object System.Collections.Generic.List[string]
                    $values = @{}
                    foreach ($valueName in @('DisplayName', 'DisplayVersion', 'Publisher', 'InstallDate', 'InstallLocation')) {
                        try {
                            $values[$valueName] = $appKey.GetValue($valueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        } catch {
                            $values[$valueName] = $null
                            $valueErrors.Add(($valueName + ': ' + $_.Exception.Message))
                        }
                    }

                    $displayName = [string]$values['DisplayName']
                    if ([string]::IsNullOrWhiteSpace($displayName)) {
                        if ($valueErrors.Count -gt 0) {
                            ('Entrada sin DisplayName y con errores de lectura ({0}\{1}): {2}' -f $root.Label, $subkeyName, ($valueErrors -join '; '))
                        }
                        continue
                    }

                    $installedApps.Add([PSCustomObject]@{
                        DisplayName     = $displayName.Trim()
                        DisplayVersion  = [string]$values['DisplayVersion']
                        Publisher       = [string]$values['Publisher']
                        InstallDate     = [string]$values['InstallDate']
                        InstallLocation = [string]$values['InstallLocation']
                        RegistryPath    = ($root.Label + '\' + $subkeyName)
                        ReadWarnings    = ($valueErrors -join '; ')
                    })
                    if ($valueErrors.Count -gt 0) {
                        ('Aviso de lectura en {0}\{1}: {2}' -f $root.Label, $subkeyName, ($valueErrors -join '; '))
                    }
                } catch {
                    ('Entrada omitida por error de lectura ({0}\{1}): {2}' -f $root.Label, $subkeyName, $_.Exception.Message)
                } finally {
                    if ($null -ne $appKey) { $appKey.Dispose() }
                }
            }
        } catch {
            ('No se pudo leer {0}: {1}' -f $root.Label, $_.Exception.Message)
        } finally {
            if ($null -ne $rootKey) { $rootKey.Dispose() }
            if ($null -ne $baseKey) { $baseKey.Dispose() }
        }
    }

    if ($installedApps.Count -eq 0) {
        'No se encontraron entradas de software instalado en las claves consultadas.'
    } else {
        $sortedApps = $installedApps | Sort-Object -Property DisplayName, DisplayVersion, Publisher
        $index = 0
        foreach ($app in $sortedApps) {
            $index++
            ('[{0}] {1}' -f $index, $app.DisplayName)
            ('    Version: {0}' -f $app.DisplayVersion)
            ('    Editor: {0}' -f $app.Publisher)
            ('    Fecha de instalación: {0}' -f $app.InstallDate)
            ('    Ubicación: {0}' -f $app.InstallLocation)
            ('    Clave de registro: {0}' -f $app.RegistryPath)
            if (-not [string]::IsNullOrWhiteSpace($app.ReadWarnings)) {
                ('    Avisos de lectura: {0}' -f $app.ReadWarnings)
            }
        }
        ('Total de entradas encontradas: {0}' -f $installedApps.Count)
    }
}
Add-CommandOutput '18. FIRMA DIGITAL Y SHA256 DE EJECUTABLES ACTIVOS' {
    $paths = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -and (Test-Path -LiteralPath $_.ExecutablePath) } |
        Select-Object -ExpandProperty ExecutablePath -Unique
    $signatureResults = foreach ($path in $paths) {
        try {
            $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
            $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop
            [PSCustomObject]@{
                Path = $path
                SignatureStatus = [string]$sig.Status
                Signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '(sin certificado de firmante)' }
                SHA256 = $hash.Hash
            }
        } catch {
            [PSCustomObject]@{
                Path = $path
                SignatureStatus = 'Error al verificar'
                Signer = $_.Exception.Message
                SHA256 = '(no calculado)'
            }
        }
    }
    $signatureResults | Sort-Object Path | Format-List
}

Add-CommandOutput '19. EVENTOS RECIENTES DE SEGURIDAD (ULTIMOS 3 DIAS)' {
    'Nota: el acceso a ciertos registros puede estar restringido y la ausencia de eventos no prueba que no haya ocurrido nada.'
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = (Get-Date).AddDays(-3) } -MaxEvents 250 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
        Format-List
}

Add-CommandOutput '20. EVENTOS RECIENTES DE WINDOWS DEFENDER (ULTIMOS 7 DIAS)' {
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 150 -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, LevelDisplayName, Message |
        Format-List
}

Add-CommandOutput '21. ARP / VECINOS DE RED' {
    Get-NetNeighbor -ErrorAction SilentlyContinue |
        Sort-Object InterfaceIndex, IPAddress |
        Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State |
        Format-Table -AutoSize
}

Add-CommandOutput '22. DISCOS FISICOS, TIPO Y ESPACIO LIBRE' {
    '--- Discos físicos detectados ---'
    $physical = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue)
    $storageDisks = @()
    if (Get-Command Get-PhysicalDisk -ErrorAction SilentlyContinue) {
        $storageDisks = @(Get-PhysicalDisk -ErrorAction SilentlyContinue)
    }
    ('Cantidad de discos físicos: {0}' -f $physical.Count)
    foreach ($disk in $physical) {
        $type = 'No determinado'
        $match = $storageDisks | Where-Object { $_.DeviceId -eq $disk.Index -or $_.FriendlyName -eq $disk.Model } | Select-Object -First 1
        if ($match -and [string]$match.MediaType -in @('SSD','HDD')) {
            $type = [string]$match.MediaType
        } elseif ($disk.MediaType -match 'Solid State|SSD') {
            $type = 'SSD'
        } elseif ($disk.Model -match '(?i)\bSSD\b|NVMe') {
            $type = 'SSD (inferido del modelo)'
        } elseif ($disk.MediaType -match 'Fixed hard disk' -and $disk.Model -match '(?i)\bHDD\b') {
            $type = 'HDD (inferido del modelo)'
        }
        [PSCustomObject]@{
            Numero = $disk.Index
            Modelo = $disk.Model
            Tipo = $type
            Interfaz = $disk.InterfaceType
            CapacidadGB = [math]::Round([double]$disk.Size / 1GB, 2)
            Estado = $disk.Status
        } | Format-List
    }
    '--- Volúmenes y espacio disponible ---'
    $volumes = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue)
    foreach ($vol in $volumes) {
        [PSCustomObject]@{
            Unidad = $vol.DeviceID
            Etiqueta = $vol.VolumeName
            SistemaArchivos = $vol.FileSystem
            CapacidadGB = if ($null -ne $vol.Size) { [math]::Round([double]$vol.Size / 1GB, 2) } else { $null }
            LibreGB = if ($null -ne $vol.FreeSpace) { [math]::Round([double]$vol.FreeSpace / 1GB, 2) } else { $null }
            LibrePorcentaje = if ($vol.Size -gt 0) { [math]::Round(100 * [double]$vol.FreeSpace / [double]$vol.Size, 1) } else { $null }
        } | Format-List
    }
    'Nota: los volúmenes pueden incluir particiones de un mismo disco; no representan discos físicos adicionales.'
}

Write-Progress -Activity 'Auditoría integral de Windows (solo lectura)' -Completed
Write-Host ''
Write-Host ('[22/22] Todas las fases de recopilación finalizaron. Guardando informe...') -ForegroundColor Cyan

Add-Section 'FIN DEL INFORME'
Add-Line ("Finalizado: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'))
Add-Line 'Interpretacion: revisar los hallazgos en contexto. Puertos abiertos, firmas ausentes o herramientas remotas instaladas no prueban por si solos una intrusión.'
Add-Line 'El informe contiene datos potencialmente sensibles. Revisarlo antes de compartirlo públicamente.'

try {
    [System.IO.File]::WriteAllText($reportPath, $script:report.ToString(), [System.Text.UTF8Encoding]::new($true))
    Write-Host ''
    Write-Host 'Auditoria finalizada.' -ForegroundColor Green
    Write-Host ("Informe: " + $reportPath) -ForegroundColor Cyan
    Write-Host ("Ejecutado como administrador: " + $isAdmin)
    Write-Host 'El script no cambia configuraciones ni elimina archivos.'
    Write-Host ''
    Write-Host ''
    Write-Host 'Opcional: utilidad WinUtil de Chris Titus Tech (script externo).' -ForegroundColor Yellow
    Write-Host 'ATENCION: puede cambiar configuraciones del sistema. No forma parte de la auditoria de solo lectura.' -ForegroundColor Yellow
    $launch = Read-Host '¿Ejecutar ahora irm https://christitus.com/win | iex? (S/N; predeterminado N)'
    if ($launch -match '^(?i:s|si|sí)$') {
        try {
            Write-Host 'Descargando y ejecutando la utilidad externa...' -ForegroundColor Yellow
            irm https://christitus.com/win | iex
        } catch {
            Write-Warning ('No se pudo ejecutar WinUtil: ' + $_.Exception.Message)
        }
    } else {
        Write-Host 'Utilidad externa omitida.'
    }
    Read-Host 'Presiona Enter para cerrar' 
} catch {
    Write-Error ("No se pudo guardar el informe: " + $_.Exception.Message)
}
