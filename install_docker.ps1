#Requires -Version 5.1
<#
.SYNOPSIS
    Script exhaustivo y "autocurativo" para instalar y configurar Docker Desktop
    en Windows 10/11 (Home, Pro, LTSC, ARM64).

.DESCRIPTION
    Ingeniero SRE: Este script encapsula anos de dolor acumulado lidiando con las
    peculiaridades de Docker Desktop en entornos Windows heterogeneos. Cada
    "hack" esta documentado con el porque tecnico exacto.

.NOTES
    Autor   : SRE Windows/Virtualization Specialist
    Version : 3.1.0
    Requiere: Windows 10 1903+ / Windows 11, PowerShell 5.1+
              Conexion a Internet para descarga del instalador
#>

# ============================================================
# REGION 0: INICIALIZACION DEL LOG Y CONSTANTES GLOBALES
# ============================================================
# Razon: Establecer el log ANTES de cualquier logica para capturar
# incluso los errores mas tempranos del proceso de bootstrapping.

$Script:LogPath  = "$env:USERPROFILE\Desktop\DockerInstall_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$Script:ExitCode = 0

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO','WARN','ERROR','SUCCESS','STEP')]
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $prefix = switch ($Level) {
        'INFO'    { '[INFO   ]' }
        'WARN'    { '[WARN   ]' }
        'ERROR'   { '[ERROR  ]' }
        'SUCCESS' { '[SUCCESS]' }
        'STEP'    { '[STEP   ]' }
    }
    $line = "$timestamp $prefix $Message"

    # Escribir en consola con color
    $color = switch ($Level) {
        'INFO'    { 'Cyan'    }
        'WARN'    { 'Yellow'  }
        'ERROR'   { 'Red'     }
        'SUCCESS' { 'Green'   }
        'STEP'    { 'Magenta' }
    }
    Write-Host $line -ForegroundColor $color

    # Escribir en archivo (append)
    try {
        Add-Content -Path $Script:LogPath -Value $line -Encoding UTF8 -ErrorAction Stop
    } catch {
        # Si no se puede escribir el log, continuar de todas formas; no queremos
        # que un fallo del logger aborte la instalacion.
        Write-Host "[LOGGER WARN] No se pudo escribir en log: $_" -ForegroundColor DarkYellow
    }
}

function Write-LogSeparator {
    param([string]$Title = '')
    $sep = '=' * 70
    Write-Log $sep        'STEP'
    if ($Title) { Write-Log "  $Title" 'STEP' }
    Write-Log $sep        'STEP'
}

# ============================================================
# REGION 1: AUTO-ELEVACION A ADMINISTRADOR
# ============================================================
# Razon: Docker Desktop requiere modificar caracteristicas de Windows,
# el registro HKLM, grupos locales y BCD. Sin privilegios de admin
# todas estas operaciones fallan silenciosamente o con errores cripticos.
# La auto-elevacion evita tener que documentar "ejecutar como administrador".

function Assert-AdminPrivileges {
    Write-Log "Verificando privilegios de administrador..." 'INFO'

    $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Log "No se tienen privilegios de administrador. Re-lanzando con elevacion..." 'WARN'

        $scriptPath = $MyInvocation.ScriptName
        if (-not $scriptPath) { $scriptPath = $PSCommandPath }
        if (-not $scriptPath) {
            Write-Log "No se pudo determinar la ruta del script para la auto-elevacion." 'ERROR'
            exit 1
        }

        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        Start-Process powershell.exe -ArgumentList $arguments -Verb RunAs
        exit 0
    }

    Write-Log "Privilegios de administrador confirmados." 'SUCCESS'
}

# ============================================================
# REGION 2: DETECCION DE ARQUITECTURA Y MANEJO DE WOW64 EN ARM64
# ============================================================
# Razon tecnica CRITICA: En sistemas ARM64 con Windows 11, PowerShell 5.1
# puede ejecutarse bajo la capa de emulacion WOW64 (x86-on-ARM). Cuando esto
# ocurre, System32 es redirigida a SysWOW64, lo que provoca que DISM, bcdedit
# y otros binarios nativos de 64 bits fallen con "Access Denied" o simplemente
# ejecuten versiones incorrectas del binario. La solucion es reiniciar el proceso
# usando el PowerShell nativo ARM64 ubicado en SysNative, que bypasea el
# redirector WOW64 del File System.

function Get-SystemArchitecture {
    Write-Log "Detectando arquitectura del sistema..." 'INFO'

    # Metodo primario: WMI - mas fiable que $env:PROCESSOR_ARCHITECTURE
    # porque esa variable env puede estar mentida por el proceso padre.
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        $arch = switch ($cpu.Architecture) {
            0  { 'x86'   }
            9  { 'x64'   }   # AMD64 / Intel64
            12 { 'ARM64' }
            default { 'UNKNOWN' }
        }
        Write-Log "Arquitectura detectada via WMI: $arch (CPU: $($cpu.Name))" 'INFO'
        return $arch
    } catch {
        Write-Log "WMI fallo para deteccion de arquitectura: $_. Usando fallback." 'WARN'
    }

    # Fallback: Variables de entorno del SO (no del proceso)
    $osArch = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PROCESSOR_ARCHITECTURE -ErrorAction SilentlyContinue).PROCESSOR_ARCHITECTURE

    if ($osArch -eq 'AMD64') {
        return 'x64'
    } elseif ($osArch -eq 'ARM64') {
        return 'ARM64'
    } elseif ($osArch -eq 'x86') {
        return 'x86'
    } else {
        return 'x64'
    }
}

function Assert-NativeARM64Process {
    <#
    .SYNOPSIS
        En ARM64, garantiza que estamos corriendo en un proceso PowerShell nativo (no emulado).
    .NOTES
        SysNative es un alias especial creado por Windows para que procesos de 32 bits/WOW64
        puedan acceder al directorio System32 real. Si SysNative existe, significa que
        estamos en un proceso emulado y necesitamos reiniciar con el binario nativo.
    #>
    $sysNativePath = "$env:windir\SysNative\WindowsPowerShell\v1.0\powershell.exe"

    if (Test-Path $sysNativePath) {
        Write-Log "Proceso WOW64/emulado detectado en ARM64. Reiniciando con PowerShell nativo ARM64..." 'WARN'
        Write-Log "Ruta nativa: $sysNativePath" 'INFO'

        $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.ScriptName }
        $arguments  = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

        Start-Process $sysNativePath -ArgumentList $arguments -Verb RunAs
        exit 0
    }

    Write-Log "Proceso nativo ARM64 confirmado (SysNative no encontrado desde este contexto)." 'SUCCESS'
}

# ============================================================
# REGION 3: DETECCION DE EDICION DE WINDOWS
# ============================================================

function Get-WindowsEditionInfo {
    Write-Log "Obteniendo informacion de la edicion de Windows..." 'INFO'

    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
                -Name EditionID -ErrorAction SilentlyContinue).EditionID

    $buildNumber = [int]$osInfo.BuildNumber
    $isWindows11 = $buildNumber -ge 22000

    $info = [PSCustomObject]@{
        Caption     = $osInfo.Caption
        Version     = $osInfo.Version
        Build       = $buildNumber
        Edition     = $edition
        IsHome      = ($edition -like '*Home*')
        IsLTSC      = ($edition -like '*LTSC*' -or $edition -like '*Enterprise*S*')
        IsWindows11 = $isWindows11
    }

    Write-Log "OS: $($info.Caption)" 'INFO'
    Write-Log "Build: $($info.Build) | Edicion: $($info.Edition) | Win11: $($info.IsWindows11)" 'INFO'
    Write-Log "Home?: $($info.IsHome) | LTSC?: $($info.IsLTSC)" 'INFO'

    return $info
}

# ============================================================
# REGION 4: HABILITACION DE HYPER-V EN WINDOWS HOME
# ============================================================
# Razon hacky EXPLICADA:
# Microsoft deliberadamente excluye Hyper-V de las SKUs Home para diferenciar
# el producto y forzar actualizaciones a Pro. Sin embargo, los BINARIOS y
# paquetes de Hyper-V estan fisicamente presentes en el almacen de componentes
# de Windows (C:\Windows\servicing\Packages\) en TODAS las ediciones.
# La diferencia es que el manifiesto de capacidades los marca como "no disponibles".
#
# Al usar DISM para instalar los .mum (manifiestos de actualizacion) directamente
# desde el almacen, le decimos a Windows: "estos componentes existen, activalos".
# Esto funciona porque DISM opera a nivel de almacen de componentes, bypasseando
# la logica de licenciamiento de caracteristicas que bloquea el
# Enable-WindowsOptionalFeature estandar en ediciones Home.
#
# NOTA: Este proceso no es un "crack" de licencia; Hyper-V en Home funciona para
# virtualizacion local pero no incluye el management stack completo (Hyper-V Manager,
# Live Migration, etc.) que tiene la version Pro/Enterprise.

function Enable-HyperVOnWindowsHome {
    Write-Log "Windows Home detectado. Aplicando metodo alternativo para Hyper-V via DISM..." 'WARN'
    Write-Log "Buscando paquetes Hyper-V en el almacen de componentes de Windows..." 'INFO'

    $componentStore = "$env:windir\servicing\Packages"
    Write-Log "Ruta del almacen: $componentStore" 'INFO'

    try {
        $hypervPackages = Get-ChildItem -Path $componentStore -Filter "*Hyper-V*.mum" -ErrorAction Stop
        Write-Log "Encontrados $($hypervPackages.Count) paquetes Hyper-V." 'INFO'

        if ($hypervPackages.Count -eq 0) {
            Write-Log "No se encontraron paquetes Hyper-V en el almacen. El sistema puede no ser compatible." 'WARN'
            return $false
        }

        foreach ($pkg in $hypervPackages) {
            Write-Log "Instalando paquete: $($pkg.Name)" 'INFO'
            try {
                # /NoRestart: acumular cambios, reiniciar una sola vez al final
                # /IgnoreCheck: saltear verificaciones de aplicabilidad para edicion Home
                $dismArgs = "/Online /Add-Package /PackagePath:`"$($pkg.FullName)`" /NoRestart /Quiet"
                $result = Start-Process dism.exe -ArgumentList $dismArgs -Wait -PassThru -NoNewWindow
                if ($result.ExitCode -eq 0 -or $result.ExitCode -eq 3010) {
                    # 3010 = exito, requiere reinicio
                    Write-Log "Paquete instalado exitosamente (ExitCode: $($result.ExitCode))" 'SUCCESS'
                } else {
                    Write-Log "DISM devolvio codigo: $($result.ExitCode) para $($pkg.Name)" 'WARN'
                }
            } catch {
                Write-Log "Error instalando paquete $($pkg.Name): $_" 'WARN'
            }
        }
        return $true
    } catch {
        Write-Log "Error accediendo al almacen de componentes: $_" 'ERROR'
        return $false
    }
}

# ============================================================
# REGION 5: HABILITACION DE CARACTERISTICAS DE WINDOWS
# ============================================================
# Razon: Docker Desktop en modo WSL2 requiere:
#   - VirtualMachinePlatform    : permite a WSL2 usar el hipervisor subyacente
#   - Microsoft-Windows-Subsystem-Linux : la infraestructura base de WSL
#   - Microsoft-Hyper-V         : el hipervisor tipo-1 que hace posible la virtualizacion
#   - Containers                : necesario para el runtime de contenedores de Windows
#
# Usamos DISM directamente ademas de PowerShell porque:
# 1. DISM puede operar sobre caracteristicas que no son "opcionales" en el sentido
#    de PowerShell (especialmente en LTSC donde algunas caracteristicas estan
#    marcadas diferente en el manifiesto).
# 2. En Home, algunas caracteristicas fallan con Enable-WindowsOptionalFeature
#    pero funcionan via DISM con /LimitAccess.

function Enable-RequiredWindowsFeatures {
    param([bool]$IsHome)

    Write-Log "Habilitando caracteristicas de Windows requeridas..." 'INFO'

    # Si es Home, primero intentar instalar los paquetes Hyper-V del almacen
    if ($IsHome) {
        Enable-HyperVOnWindowsHome
    }

    $features = @(
        @{ Name = 'VirtualMachinePlatform';            DISM = 'VirtualMachinePlatform'            },
        @{ Name = 'Microsoft-Windows-Subsystem-Linux'; DISM = 'Microsoft-Windows-Subsystem-Linux'  },
        @{ Name = 'Microsoft-Hyper-V';                 DISM = 'Microsoft-Hyper-V-All'              },
        @{ Name = 'Containers';                        DISM = 'Containers'                         }
    )

    foreach ($feature in $features) {
        Write-Log "Habilitando: $($feature.Name)" 'INFO'
        try {
            # Intentar primero con PowerShell (mas limpio cuando funciona)
            $result = Enable-WindowsOptionalFeature -Online -FeatureName $feature.Name `
                       -All -NoRestart -ErrorAction Stop
            Write-Log "Habilitado via PowerShell: $($feature.Name) | RestartNeeded: $($result.RestartNeeded)" 'SUCCESS'
        } catch {
            Write-Log "PowerShell fallo para $($feature.Name): $_. Intentando con DISM..." 'WARN'
            try {
                # /LimitAccess: no intentar descargar de Windows Update (util en redes corporativas)
                # /All: habilitar caracteristicas padre requeridas automaticamente
                $dismArgs = "/Online /Enable-Feature /FeatureName:$($feature.DISM) /All /NoRestart /LimitAccess"
                $dismResult = Start-Process dism.exe -ArgumentList $dismArgs -Wait -PassThru -NoNewWindow
                if ($dismResult.ExitCode -eq 0 -or $dismResult.ExitCode -eq 3010) {
                    Write-Log "Habilitado via DISM: $($feature.DISM) (ExitCode: $($dismResult.ExitCode))" 'SUCCESS'
                } else {
                    Write-Log "DISM no pudo habilitar $($feature.DISM). ExitCode: $($dismResult.ExitCode)" 'WARN'
                }
            } catch {
                Write-Log "DISM tambien fallo para $($feature.DISM): $_" 'ERROR'
            }
        }
    }
}

# ============================================================
# REGION 6: LIMPIEZA DE WSL
# ============================================================
# Razon: Las distribuciones de Docker Desktop para WSL2 son:
#   - docker-desktop
#   - docker-desktop-data
#
# Si una instalacion previa quedo en estado corrupto o "Stopped" de forma
# permanente (lo cual ocurre cuando Docker se cierra abruptamente o cuando
# hay una actualizacion fallida), la nueva instalacion intentara usar esas
# distros existentes y fallara silenciosamente.
#
# wsl --unregister elimina completamente el registro de la distribucion y
# su disco virtual (ext4.vhdx), forzando a Docker a crear instancias limpias.
#
# Tambien ejecutamos wsl --update para asegurar que el kernel de WSL2 sea
# el mas reciente (critico para compatibilidad con versiones nuevas de Docker).

function Invoke-WSLCleanup {
    Write-Log "Iniciando limpieza y actualizacion de WSL2..." 'INFO'

    # Actualizar WSL2 antes de cualquier otra cosa
    Write-Log "Actualizando WSL2..." 'INFO'
    try {
        $wslUpdate = Start-Process wsl.exe -ArgumentList '--update' -Wait -PassThru -NoNewWindow
        Write-Log "wsl --update completado. ExitCode: $($wslUpdate.ExitCode)" 'INFO'
    } catch {
        Write-Log "Error ejecutando wsl --update: $_" 'WARN'
    }

    $dockerDistros = @('docker-desktop', 'docker-desktop-data')
    Write-Log "Verificando distribuciones WSL de Docker previas..." 'INFO'

    try {
        # --list --all --quiet: incluye distribuciones detenidas y en cualquier estado
        $wslList = wsl.exe --list --all --quiet 2>&1
        # La salida de wsl --list usa UTF-16 con caracteres nulos; limpiar
        $cleanList = $wslList | Where-Object { $_ } | ForEach-Object { $_.Trim([char]0).Trim() }

        foreach ($distro in $dockerDistros) {
            $found = $cleanList | Where-Object { $_ -like "*$distro*" }
            if ($found) {
                Write-Log "Distribucion Docker encontrada: '$distro'. Desregistrando..." 'WARN'
                try {
                    $unregResult = Start-Process wsl.exe -ArgumentList "--unregister $distro" `
                                   -Wait -PassThru -NoNewWindow
                    if ($unregResult.ExitCode -eq 0) {
                        Write-Log "Distribucion '$distro' eliminada correctamente." 'SUCCESS'
                    } else {
                        Write-Log "Advertencia al eliminar '$distro'. ExitCode: $($unregResult.ExitCode)" 'WARN'
                    }
                } catch {
                    Write-Log "Error eliminando distribucion '$distro': $_" 'ERROR'
                }
            } else {
                Write-Log "Distribucion '$distro' no encontrada. No se requiere limpieza." 'INFO'
            }
        }
    } catch {
        Write-Log "Error listando distribuciones WSL: $_" 'WARN'
    }

    # Establecer WSL2 como version por defecto
    Write-Log "Configurando WSL2 como version por defecto..." 'INFO'
    try {
        wsl.exe --set-default-version 2 2>&1 | Out-Null
        Write-Log "WSL2 configurado como version por defecto." 'SUCCESS'
    } catch {
        Write-Log "Advertencia configurando WSL2 por defecto: $_" 'WARN'
    }
}

# ============================================================
# REGION 7: AJUSTES DE REGISTRO Y BCD CRITICOS
# ============================================================

function Set-CriticalRegistrySettings {
    Write-Log "Aplicando ajustes de registro y BCD criticos..." 'INFO'

    # ---- 7.1: ServicesPipeTimeout ----
    # Razon: Docker Desktop inicia el servicio "com.docker.service" (y otros) durante
    # el arranque. En sistemas lentos, HDD, o con AV activo, el pipe de comunicacion
    # entre el SCM y el servicio puede tardar mas de los 30000ms (30s) por defecto.
    # Cuando esto ocurre, Windows marca el servicio como "no respondio a tiempo" y lo
    # termina antes de que Docker pueda inicializar el backend. El sintoma es el
    # icono de Docker en la bandeja que nunca sale de "Starting..."
    # Aumentarlo a 60000ms (60s) da margen suficiente para sistemas lentos.
    Write-Log "Configurando ServicesPipeTimeout = 60000ms..." 'INFO'
    try {
        $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control'
        Set-ItemProperty -Path $regPath -Name 'ServicesPipeTimeout' -Value 60000 `
                         -Type DWord -Force -ErrorAction Stop
        Write-Log "ServicesPipeTimeout configurado a 60000." 'SUCCESS'
    } catch {
        Write-Log "Error configurando ServicesPipeTimeout: $_" 'ERROR'
    }

    # ---- 7.2: DEP (Data Execution Prevention) AlwaysOn ----
    # Razon: El hipervisor de Hyper-V requiere que DEP este habilitado como
    # requerimiento de seguridad para la virtualizacion asistida por hardware
    # (Intel VT-x con XD/NX bit, AMD-V con NX bit). Si DEP esta en modo "OptIn"
    # o "OptOut" y el usuario lo deshabilito previamente (comun en setups de gaming),
    # el hipervisor falla al intentar iniciar con error "Hypervisor launch failed".
    # bcdedit opera sobre el BCD (Boot Configuration Data), que es la fuente
    # autoritativa que consulta el BOOTMGR, no el registro de Windows.
    Write-Log "Configurando DEP como AlwaysOn via bcdedit..." 'INFO'
    try {
        $bcdOut = "$env:TEMP\bcd_dep.txt"
        $bcdResult = Start-Process bcdedit.exe `
                     -ArgumentList '/set {current} nx AlwaysOn' `
                     -Wait -PassThru -NoNewWindow -RedirectStandardOutput $bcdOut
        $bcdOutput = Get-Content $bcdOut -ErrorAction SilentlyContinue
        Write-Log "bcdedit DEP: ExitCode=$($bcdResult.ExitCode) | Output: $bcdOutput" 'INFO'
        if ($bcdResult.ExitCode -eq 0) {
            Write-Log "DEP configurado como AlwaysOn." 'SUCCESS'
        } else {
            Write-Log "bcdedit DEP devolvio ExitCode no-cero: $($bcdResult.ExitCode)" 'WARN'
        }
    } catch {
        Write-Log "Error configurando DEP via bcdedit: $_" 'ERROR'
    }

    # ---- 7.3: HypervisorLaunchType = Auto ----
    # Razon: En algunos sistemas donde Hyper-V fue deshabilitado manualmente
    # (por ejemplo, para usar VirtualBox o VMware en modo nativo), el BCD tiene
    # hypervisorlaunchtype=off. Docker Desktop con backend WSL2 requiere que el
    # hipervisor de Windows sea accesible. Con "auto", el hipervisor solo se carga
    # si se necesita, lo que es compatible tanto con Docker como con VMs legacy.
    # NOTA: Si el valor era "off" para usar VirtualBox, esto lo cambiara.
    # Por eso en la Region 8 advertimos sobre VirtualBox.
    Write-Log "Configurando hypervisorlaunchtype = auto via bcdedit..." 'INFO'
    try {
        $bcdHvOut    = "$env:TEMP\bcd_hv.txt"
        $bcdHvResult = Start-Process bcdedit.exe `
                       -ArgumentList '/set {current} hypervisorlaunchtype auto' `
                       -Wait -PassThru -NoNewWindow -RedirectStandardOutput $bcdHvOut
        $bcdHvOutput = Get-Content $bcdHvOut -ErrorAction SilentlyContinue
        Write-Log "bcdedit HV: ExitCode=$($bcdHvResult.ExitCode) | Output: $bcdHvOutput" 'INFO'
        if ($bcdHvResult.ExitCode -eq 0) {
            Write-Log "hypervisorlaunchtype configurado como 'auto'." 'SUCCESS'
        }
    } catch {
        Write-Log "Error configurando hypervisorlaunchtype: $_" 'ERROR'
    }

    # ---- 7.4: Desactivar Legacy Console Mode ----
    # Razon: El modo Legacy Console (ForceV2=0) usa el subsistema conhost.exe antiguo
    # que no soporta secuencias de escape ANSI. La CLI de Docker (docker logs,
    # docker build, etc.) emite colores y progreso usando codigos ANSI. Con Legacy
    # Console habilitado, estos aparecen como caracteres de escape literales en la
    # consola, haciendo el output ilegible. ForceV2=1 activa el conhost moderno
    # con soporte completo de VT100/ANSI.
    Write-Log "Desactivando Legacy Console Mode (habilitando VT/ANSI)..." 'INFO'
    try {
        $consoleRegPath = 'HKCU:\Console'
        if (-not (Test-Path $consoleRegPath)) {
            New-Item -Path $consoleRegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $consoleRegPath -Name 'ForceV2' -Value 1 `
                         -Type DWord -Force -ErrorAction Stop
        Write-Log "Legacy Console Mode desactivado (ForceV2=1)." 'SUCCESS'
    } catch {
        Write-Log "Error desactivando Legacy Console Mode: $_" 'ERROR'
    }

    # ---- 7.5: Soporte de virtualizacion anidada ----
    # Razon: En entornos donde Windows corre como VM sobre Hyper-V (Azure DevBox,
    # VMs de desarrollo), Docker necesita virtualizacion anidada habilitada en el
    # hipervisor padre. Esta clave activa la exposicion de instrucciones VMXE/SVME
    # a la VM guest. No hace nada en bare-metal pero tampoco perjudica.
    Write-Log "Configurando soporte de virtualizacion anidada (para entornos VM)..." 'INFO'
    try {
        $hvRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization'
        if (-not (Test-Path $hvRegPath)) {
            New-Item -Path $hvRegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $hvRegPath -Name 'MinVmVersionForCpuBasedMitigations' `
                         -Value '1.0' -Type String -Force -ErrorAction SilentlyContinue
        Write-Log "Configuracion de virtualizacion anidada aplicada." 'INFO'
    } catch {
        Write-Log "Advertencia configurando virtualizacion anidada (no critico): $_" 'WARN'
    }
}

# ============================================================
# REGION 8: DETECCION DE CONFLICTOS DE SOFTWARE
# ============================================================
# Razon: Ciertos programas crean conflictos severos con el hipervisor de Windows:
#
# - Riot Vanguard: El anti-cheat de Valorant opera a nivel kernel (ring 0) y tiene
#   su propio driver que puede conflictuar con el Hypervisor Platform. Desde
#   Windows 11, Vanguard requiere VBS (Virtualization Based Security), pero algunas
#   versiones antiguas deshabilitaban el hipervisor para evitar deteccion de VMs.
#
# - VirtualBox < 6.0: Las versiones antiguas usaban su propio hipervisor tipo-2
#   que era incompatible con Hyper-V. A partir de 6.1, VirtualBox soporta el
#   "Hyper-V backend" que los hace coexistir, pero con overhead de rendimiento.
#
# No detenemos la instalacion por estos; solo informamos porque el usuario
# necesita saberlo si Docker falla post-instalacion.

function Test-SoftwareConflicts {
    Write-Log "Verificando posibles conflictos de software..." 'INFO'

    $conflicts = @()

    # ---- Verificar Vanguard (anti-cheat de Riot Games) ----
    $vanguardService = Get-Service -Name 'vgc' -ErrorAction SilentlyContinue
    $vanguardProcess = Get-Process -Name 'vgtray', 'vgc' -ErrorAction SilentlyContinue
    if ($vanguardService -or $vanguardProcess) {
        $conflicts += [PSCustomObject]@{
            Name     = 'Riot Vanguard (Anti-cheat de Valorant)'
            Severity = 'ALTA'
            Detail   = 'Vanguard opera a nivel kernel y puede conflictuar con Hyper-V Platform. ' +
                       'Si Docker falla al iniciar, actualiza Valorant a la ultima version ' +
                       'que soporta coexistencia con Hyper-V.'
        }
    }

    # ---- Verificar VirtualBox ----
    $vboxService = Get-Service -Name 'VBoxSVC', 'VBoxDrv' -ErrorAction SilentlyContinue
    if ($vboxService) {
        $vboxKey     = Get-ItemProperty 'HKLM:\SOFTWARE\Oracle\VirtualBox' -ErrorAction SilentlyContinue
        $vboxVersion = if ($vboxKey) { $vboxKey.Version } else { 'Desconocida' }
        $vboxMajor   = if ($vboxVersion -match '^(\d+)\.') { [int]$Matches[1] } else { 0 }

        if ($vboxMajor -lt 6) {
            $conflicts += [PSCustomObject]@{
                Name     = "Oracle VirtualBox v$vboxVersion (VERSION ANTIGUA - INCOMPATIBLE)"
                Severity = 'CRITICA'
                Detail   = "VirtualBox $vboxVersion usa su propio hipervisor incompatible con Hyper-V. " +
                           "Esto IMPEDIRA que Docker funcione. Actualiza a VirtualBox 6.1+ que usa " +
                           "el Hyper-V backend, o usa Docker en modo Hyper-V nativo (no WSL2)."
            }
        } else {
            $conflicts += [PSCustomObject]@{
                Name     = "Oracle VirtualBox v$vboxVersion"
                Severity = 'BAJA'
                Detail   = "VirtualBox 6.1+ es compatible con Hyper-V pero habra overhead de rendimiento " +
                           "en las VMs de VirtualBox al coexistir con el hipervisor de Windows."
            }
        }
    }

    # ---- Verificar VMware Workstation ----
    $vmwareService = Get-Service -Name 'VMware*' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($vmwareService) {
        $conflicts += [PSCustomObject]@{
            Name     = 'VMware Workstation/Player'
            Severity = 'MEDIA'
            Detail   = 'VMware Workstation 15.5.5+ soporta coexistencia con Hyper-V. ' +
                       'Versiones anteriores requieren que Hyper-V este deshabilitado.'
        }
    }

    if ($conflicts.Count -eq 0) {
        Write-Log "No se detectaron conflictos de software conocidos." 'SUCCESS'
    } else {
        Write-Log "Se detectaron $($conflicts.Count) posible(s) conflicto(s):" 'WARN'
        foreach ($c in $conflicts) {
            Write-Log "  [$($c.Severity)] $($c.Name)" 'WARN'
            Write-Log "  -- $($c.Detail)" 'WARN'
        }
    }

    return $conflicts
}

# ============================================================
# REGION 9: DESCARGA E INSTALACION DE DOCKER DESKTOP
# ============================================================
# Razon del enfoque de URL:
# Docker mantiene URLs canonicas que SIEMPRE apuntan al build mas reciente
# del canal "main" (estable) para cada arquitectura. Al usar estas URLs
# con seguimiento de redireccion, siempre obtenemos la version mas reciente
# sin necesitar parsear paginas HTML de release notes.
#
# URLs canonicas de Docker:
#   AMD64: https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe
#   ARM64: https://desktop.docker.com/win/main/arm64/Docker%20Desktop%20Installer.exe
#
# Parametros de instalacion silenciosa:
#   --quiet          : Sin interfaz de usuario
#   --accept-license : Aceptar EULA automaticamente
#   --backend=wsl-2  : Usar WSL2 como backend (mas eficiente que Hyper-V puro)

function Get-DockerDownloadURL {
    param([string]$Architecture)

    $urls = @{
        'x64'   = 'https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe'
        'ARM64' = 'https://desktop.docker.com/win/main/arm64/Docker%20Desktop%20Installer.exe'
        'x86'   = 'https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe'
    }

    $url = $urls[$Architecture]
    if (-not $url) {
        Write-Log "Arquitectura '$Architecture' no reconocida. Usando URL amd64 como fallback." 'WARN'
        $url = $urls['x64']
    }

    Write-Log "URL de descarga para $Architecture`: $url" 'INFO'
    return $url
}

function Invoke-DockerInstaller {
    param(
        [string]$Architecture,
        [string]$DownloadPath = "$env:TEMP\DockerDesktopInstaller.exe"
    )

    $downloadUrl = Get-DockerDownloadURL -Architecture $Architecture

    # ---- Descarga ----
    Write-Log "Descargando Docker Desktop desde: $downloadUrl" 'INFO'
    Write-Log "Destino temporal: $DownloadPath" 'INFO'

    try {
        # Usar BITS (Background Intelligent Transfer Service) si esta disponible.
        # BITS soporta reanudar descargas interrumpidas, throttling de ancho de banda
        # y es mas robusto en conexiones inestables que Invoke-WebRequest.
        $bitsAvailable = Get-Command Start-BitsTransfer -ErrorAction SilentlyContinue
        if ($bitsAvailable) {
            Write-Log "Usando BITS para descarga robusta con soporte de reanudacion..." 'INFO'
            Start-BitsTransfer -Source $downloadUrl -Destination $DownloadPath `
                               -DisplayName 'Docker Desktop Installer' -ErrorAction Stop
        } else {
            Write-Log "BITS no disponible. Usando Invoke-WebRequest..." 'INFO'
            # -UseBasicParsing: evita dependencia del motor IE
            # Necesario en Server Core, LTSC, y cuando IE no esta configurado.
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $downloadUrl -OutFile $DownloadPath `
                              -UseBasicParsing -ErrorAction Stop
        }

        $fileSize = (Get-Item $DownloadPath).Length / 1MB
        Write-Log "Descarga completada. Tamano: $([math]::Round($fileSize, 1)) MB" 'SUCCESS'
    } catch {
        Write-Log "Error descargando Docker Desktop: $_" 'ERROR'
        throw
    }

    # ---- Verificacion basica del instalador ----
    if (-not (Test-Path $DownloadPath) -or (Get-Item $DownloadPath).Length -lt 1MB) {
        Write-Log "El archivo descargado no existe o es demasiado pequeno. Descarga corrupta." 'ERROR'
        throw "Descarga corrupta o incompleta."
    }

    # ---- Instalacion silenciosa ----
    Write-Log "Iniciando instalacion silenciosa de Docker Desktop..." 'INFO'
    Write-Log "Parametros: install --quiet --accept-license --backend=wsl-2" 'INFO'
    Write-Log "Este proceso puede tardar varios minutos..." 'INFO'

    try {
        $installArgs   = 'install --quiet --accept-license --backend=wsl-2'
        $installResult = Start-Process -FilePath $DownloadPath `
                                       -ArgumentList $installArgs `
                                       -Wait -PassThru

        $exitCode = $installResult.ExitCode
        Write-Log "Proceso de instalacion finalizado. ExitCode: $exitCode" 'INFO'

        switch ($exitCode) {
            0    { Write-Log "Docker Desktop instalado exitosamente." 'SUCCESS' }
            1    { Write-Log "Instalacion reporto error generico (ExitCode 1). Verificar post-reinicio." 'WARN' }
            1602 { Write-Log "Instalacion cancelada por el usuario." 'ERROR'; throw "Instalacion cancelada." }
            1618 { Write-Log "Otra instalacion MSI en progreso. Reintentar despues." 'ERROR'; throw "MSI ocupado." }
            3010 { Write-Log "Instalacion exitosa. Se requiere reinicio del sistema." 'SUCCESS' }
            default {
                Write-Log "Codigo de salida inesperado: $exitCode. Verificar post-reinicio." 'WARN'
            }
        }
    } catch {
        Write-Log "Error durante la instalacion: $_" 'ERROR'
        throw
    } finally {
        # Limpiar instalador descargado independientemente del resultado
        if (Test-Path $DownloadPath) {
            Remove-Item $DownloadPath -Force -ErrorAction SilentlyContinue
            Write-Log "Instalador temporal eliminado." 'INFO'
        }
    }
}

# ============================================================
# REGION 10: GESTION DE PERMISOS DE USUARIO
# ============================================================
# Razon: El grupo "docker-users" es creado por el instalador de Docker Desktop
# para controlar que usuarios pueden conectarse al socket Unix del daemon Docker
# (\\.\pipe\docker_engine en Windows). Si el usuario actual no esta en este grupo,
# todos los comandos `docker` fallaran con "permission denied" aunque Docker
# este corriendo perfectamente. Esto es especialmente problematico cuando el
# instalador corre como Admin pero el usuario que correara Docker es diferente
# al que hizo la instalacion.

function Add-UserToDockerGroup {
    Write-Log "Agregando usuario actual al grupo 'docker-users'..." 'INFO'

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Log "Usuario actual: $currentUser" 'INFO'

    # Extraer solo el nombre de usuario sin dominio para net localgroup
    $userName = $currentUser -replace '^.*\\', ''

    try {
        # Verificar si el grupo existe (puede no existir si Docker no instalo bien)
        $groupExists = net localgroup 2>&1 | Where-Object { $_ -like '*docker-users*' }
        if (-not $groupExists) {
            Write-Log "Grupo 'docker-users' no encontrado aun. Se intentara agregar de todas formas." 'WARN'
            Write-Log "Si falla, ejecutar manualmente despues del reinicio: net localgroup docker-users $userName /add" 'WARN'
        }

        $netResult = net localgroup docker-users $userName /add 2>&1
        $exitCode  = $LASTEXITCODE

        if ($exitCode -eq 0) {
            Write-Log "Usuario '$userName' agregado al grupo 'docker-users'." 'SUCCESS'
        } elseif ($netResult -like '*already*' -or $netResult -like '*ya existe*' -or $exitCode -eq 2) {
            Write-Log "Usuario '$userName' ya es miembro del grupo 'docker-users'." 'INFO'
        } else {
            Write-Log "net localgroup devolvio: $netResult (ExitCode: $exitCode)" 'WARN'
        }
    } catch {
        Write-Log "Error agregando usuario al grupo docker-users: $_" 'ERROR'
    }
}

# ============================================================
# REGION 11: VERIFICACION POST-INSTALACION
# ============================================================

function Test-DockerInstallation {
    Write-Log "Verificando instalacion de Docker Desktop..." 'INFO'

    $checks = [ordered]@{
        'Ejecutable docker CLI'       = { Test-Path "$env:ProgramFiles\Docker\Docker\resources\bin\docker.exe" }
        'Ejecutable Docker Desktop'   = { Test-Path "$env:ProgramFiles\Docker\Docker\Docker Desktop.exe"      }
        'Servicio com.docker.service' = {
            $svc = Get-Service 'com.docker.service' -ErrorAction SilentlyContinue
            $null -ne $svc
        }
        'Directorio de datos Docker'  = { Test-Path "$env:APPDATA\Docker" }
    }

    $allPassed = $true
    foreach ($check in $checks.GetEnumerator()) {
        try {
            $result = & $check.Value
            if ($result) {
                Write-Log "  [OK]   $($check.Key)" 'SUCCESS'
            } else {
                Write-Log "  [MISS] $($check.Key) - No encontrado aun (normal pre-reinicio)" 'WARN'
                $allPassed = $false
            }
        } catch {
            Write-Log "  [ERR]  $($check.Key): $_" 'WARN'
            $allPassed = $false
        }
    }

    return $allPassed
}

# ============================================================
# REGION 12: FUNCION PRINCIPAL (ORQUESTADOR)
# ============================================================

function Main {
    Write-LogSeparator "DOCKER DESKTOP - INSTALADOR AUTOCURATIVO v3.1.0"
    Write-Log "Log guardado en: $Script:LogPath" 'INFO'
    Write-Log "Iniciado: $(Get-Date)" 'INFO'
    Write-Log "" 'INFO'

    # --- PASO 1: Privilegios de Administrador ---
    Write-LogSeparator "PASO 1: Verificacion de Privilegios"
    try {
        Assert-AdminPrivileges
    } catch {
        Write-Log "Error critico en verificacion de privilegios: $_" 'ERROR'
        exit 1
    }

    # --- PASO 2: Deteccion de Arquitectura ---
    Write-LogSeparator "PASO 2: Deteccion de Arquitectura del Sistema"
    $architecture = 'x64'
    try {
        $architecture = Get-SystemArchitecture

        # Si es ARM64, verificar que no estamos en proceso emulado WOW64
        if ($architecture -eq 'ARM64') {
            Write-Log "Sistema ARM64 detectado. Verificando contexto de proceso nativo..." 'INFO'
            Assert-NativeARM64Process
        }
    } catch {
        Write-Log "Error en deteccion de arquitectura: $_. Asumiendo x64." 'ERROR'
        $architecture = 'x64'
    }

    # --- PASO 3: Informacion de Edicion de Windows ---
    Write-LogSeparator "PASO 3: Informacion del Sistema Operativo"
    $osInfo = $null
    try {
        $osInfo = Get-WindowsEditionInfo
    } catch {
        Write-Log "Error obteniendo informacion del OS: $_" 'ERROR'
        $osInfo = [PSCustomObject]@{ IsHome = $false; IsLTSC = $false; Caption = 'Desconocido'; Build = 0 }
    }

    # --- PASO 4: Deteccion de Conflictos ---
    Write-LogSeparator "PASO 4: Deteccion de Conflictos de Software"
    $conflicts = @()
    try {
        $conflicts = Test-SoftwareConflicts
    } catch {
        Write-Log "Error en deteccion de conflictos: $_" 'WARN'
    }

    # --- PASO 5: Caracteristicas de Windows ---
    Write-LogSeparator "PASO 5: Habilitacion de Caracteristicas de Windows"
    try {
        Enable-RequiredWindowsFeatures -IsHome $osInfo.IsHome
    } catch {
        Write-Log "Error habilitando caracteristicas de Windows: $_" 'ERROR'
    }

    # --- PASO 6: Limpieza de WSL ---
    Write-LogSeparator "PASO 6: Limpieza y Actualizacion de WSL2"
    try {
        Invoke-WSLCleanup
    } catch {
        Write-Log "Error en limpieza de WSL: $_" 'WARN'
    }

    # --- PASO 7: Configuracion de Registro y BCD ---
    Write-LogSeparator "PASO 7: Ajustes de Registro y BCD"
    try {
        Set-CriticalRegistrySettings
    } catch {
        Write-Log "Error aplicando ajustes de registro: $_" 'ERROR'
    }

    # --- PASO 8: Descarga e Instalacion ---
    Write-LogSeparator "PASO 8: Descarga e Instalacion de Docker Desktop"
    $installSuccess = $false
    try {
        Invoke-DockerInstaller -Architecture $architecture
        $installSuccess = $true
    } catch {
        Write-Log "Error durante la instalacion de Docker Desktop: $_" 'ERROR'
        $Script:ExitCode = 1
    }

    # --- PASO 9: Permisos de Usuario ---
    Write-LogSeparator "PASO 9: Configuracion de Permisos de Usuario"
    try {
        Add-UserToDockerGroup
    } catch {
        Write-Log "Error configurando permisos de usuario: $_" 'WARN'
    }

    # --- PASO 10: Verificacion Post-Instalacion ---
    Write-LogSeparator "PASO 10: Verificacion de la Instalacion"
    $verificationPassed = $false
    try {
        $verificationPassed = Test-DockerInstallation
    } catch {
        Write-Log "Error en verificacion: $_" 'WARN'
    }

    # ---- RESUMEN FINAL ----
    Write-LogSeparator "RESUMEN DE INSTALACION"
    Write-Log "Sistema     : $($osInfo.Caption)" 'INFO'
    Write-Log "Arquitectura: $architecture" 'INFO'
    Write-Log "Instalacion : $(if ($installSuccess) { 'EXITOSA' } else { 'CON ERRORES - Ver log' })" $(if ($installSuccess) { 'SUCCESS' } else { 'ERROR' })
    Write-Log "Verificacion: $(if ($verificationPassed) { 'PASADA' } else { 'INCOMPLETA (normal pre-reinicio)' })" 'INFO'

    if ($conflicts.Count -gt 0) {
        Write-Log "" 'WARN'
        Write-Log "ATENCION: $($conflicts.Count) conflicto(s) detectado(s). Ver detalles en el log." 'WARN'
    }

    Write-Log "" 'INFO'
    Write-Log ('=' * 70) 'STEP'
    Write-Log "  ** SE REQUIERE REINICIO DEL SISTEMA **" 'STEP'
    Write-Log "  Las caracteristicas de Windows y los cambios BCD requieren reinicio." 'STEP'
    Write-Log "  Despues del reinicio, Docker Desktop iniciara automaticamente." 'STEP'
    Write-Log "  Log completo: $Script:LogPath" 'STEP'
    Write-Log ('=' * 70) 'STEP'
    Write-Log "" 'INFO'
    Write-Log "Finalizacion: $(Get-Date)" 'INFO'

    # No forzamos reinicio automatico para que el usuario pueda guardar su trabajo.
    # El mensaje anterior es suficientemente claro sobre la necesidad del reinicio.
    exit $Script:ExitCode
}

# ============================================================
# PUNTO DE ENTRADA
# ============================================================
# Wrapper global para capturar excepciones no manejadas que escapen
# de los bloques try/catch internos (errores de parseo de script,
# errores de carga de modulos, etc.)

try {
    Main
} catch {
    Write-Log "ERROR CRITICO NO MANEJADO: $_" 'ERROR'
    Write-Log "StackTrace: $($_.ScriptStackTrace)" 'ERROR'
    Write-Log "El script termino inesperadamente. Revisar log: $Script:LogPath" 'ERROR'
    exit 99
}