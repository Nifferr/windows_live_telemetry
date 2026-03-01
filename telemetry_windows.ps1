param(
    [ValidateSet('FullExact', 'HeaderHeroOnly', 'HeaderHeroSummaryOnly', 'HeaderHeroSummaryHardwareOnly', 'HeaderHeroSummaryHardwareDiskOnly', 'HeaderHeroSummaryHardwareDiskUsbOnly', 'HeaderHeroSummaryHardwareDiskUsbSystemOnly', 'HeaderHeroSummaryHardwareDiskUsbSystemIdentityOnly', 'HeaderHeroSummaryHardwareDiskUsbSystemIdentityFoldersOnly', 'HeaderHeroSummaryHardwareDiskUsbSystemIdentityInfraOnly', 'HeaderHeroSummaryHardwareDiskUsbSystemIdentityInfraServicesOnly', 'HeaderHeroSummaryHardwareDiskUsbSystemIdentityInfraServicesCisOnly')]
    [string]$Stage = 'FullExact',
    [string]$OutputFile,
    [string]$ComputerNameOverride,
    [string]$UserDomainOverride,
    [string]$UserNameOverride,
    [string]$StartTimeOverride,
    [datetime]$NowOverride,
    [int]$SummaryProcCountOverride = -1,
    [int]$BatteryEstimatedChargeOverride = -1,
    [string]$TrimInfoOverride,
    [string]$VolumeInfoOverride,
    [string]$DefragInfoOverride,
    [string]$StorageOptInfoOverride,
    [switch]$SuppressFinalEcho,
    [switch]$VerboseProgress,
    [int]$DefaultCommandTimeoutSecs = 45,
    [bool]$ContinueOnSectionError = $true,
    [int]$MinFreeSpaceMB = 1024,
    [bool]$SkipHeavyExportsWhenLowDisk = $true,
    [ValidateSet('Basic', 'Verbose')]
    [string]$AuditLevel = 'Basic'
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

function Write-ProgressLog {
    param(
        [string]$Message,
        [switch]$Force
    )

    if (-not $Force -and -not $script:VerboseProgressEnabled) {
        return
    }

    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host ('[' + $ts + '] ' + [string](Nz $Message ''))
}

function Invoke-SectionStep {
    param(
        [string]$SectionName,
        [scriptblock]$Action
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-ProgressLog -Message ('START: ' + $SectionName) -Force
    if (Get-Command -Name LogCustody -ErrorAction SilentlyContinue) {
        try { LogCustody -Etapa $SectionName -Status 'START' -Detalhes 'Inicio da etapa' } catch {}
    }
    Write-AuditEvent -Stage $SectionName -Action 'START' -Detail 'Inicio da etapa'

    try {
        & $Action
        $sw.Stop()
        $durationMs = [long]$sw.Elapsed.TotalMilliseconds
        Write-ProgressLog -Message ('END: ' + $SectionName + ' (' + [int]$sw.Elapsed.TotalSeconds + 's)') -Force
        if (Get-Command -Name LogCustody -ErrorAction SilentlyContinue) {
            try { LogCustody -Etapa $SectionName -Status 'END' -Detalhes 'Etapa concluida' } catch {}
        }
        Write-AuditEvent -Stage $SectionName -Action 'END' -Detail 'Etapa concluida' -DurationMs $durationMs
    }
    catch {
        $sw.Stop()
        $durationMs = [long]$sw.Elapsed.TotalMilliseconds
        $errMsg = [string](Nz $_.Exception.Message 'Falha na etapa')
        $errStack = ''
        $errInner = ''
        try { $errStack = [string](Nz $_.ScriptStackTrace '') } catch {}
        try { if ($null -ne $_.Exception.InnerException) { $errInner = [string](Nz $_.Exception.InnerException.Message '') } } catch {}
        Write-ProgressLog -Message ('ERROR: ' + $SectionName + ' (' + [int]$sw.Elapsed.TotalSeconds + 's) -> ' + $errMsg) -Force
        if (Get-Command -Name LogCustody -ErrorAction SilentlyContinue) {
            try { LogCustody -Etapa $SectionName -Status 'BAD' -Detalhes $errMsg } catch {}
            try { LogCustody -Etapa $SectionName -Status 'END' -Detalhes 'Etapa finalizada com falha' } catch {}
        }
        Write-AuditEvent -Stage $SectionName -Action 'ERROR' -Detail $errMsg -DurationMs $durationMs -ErrorStack $errStack -ErrorInner $errInner
        if (-not $script:ContinueOnSectionErrorFlag) {
            throw
        }
        if ($null -ne $script:CurrentWriter) {
            Write-VbsLine $script:CurrentWriter "<section class='card' style='margin-top:16px'>"
            Write-VbsLine $script:CurrentWriter ("<h2>Falha na secao: " + (HtmlEncode $SectionName) + "</h2>")
            Write-VbsLine $script:CurrentWriter ("<pre>" + (HtmlEncode $errMsg) + "</pre>")
            Write-VbsLine $script:CurrentWriter "</section>"
        }
    }
}

# ---- Structured JSON Audit Engine (EDR-like) ----
$script:AuditJsonPath = ''
$script:AuditJsonWriter = $null
$script:AuditCorrelationId = ''
$script:AuditLevelConfig = 'Basic'
$script:AuditEventSeq = 0

function Open-AuditLog {
    param(
        [string]$BasePath,
        [string]$RunId,
        [string]$Level
    )
    $script:AuditLevelConfig = [string](Nz $Level 'Basic')
    $script:AuditCorrelationId = [string](Nz $RunId ([guid]::NewGuid().ToString('N')))
    $script:AuditEventSeq = 0
    $jsonFile = Join-Path $BasePath ('audit_' + $script:AuditCorrelationId + '.jsonl')
    $script:AuditJsonPath = $jsonFile
    try {
        $script:AuditJsonWriter = [System.IO.StreamWriter]::new($jsonFile, $false, [System.Text.Encoding]::UTF8)
        # Opening event
        Write-AuditEvent -Stage 'SCRIPT' -Action 'INIT' -Detail ('AuditLevel=' + $script:AuditLevelConfig + '; PID=' + $PID)
    }
    catch {
        $script:AuditJsonWriter = $null
        $script:AuditJsonPath = ''
    }
}

function Close-AuditLog {
    Write-AuditEvent -Stage 'SCRIPT' -Action 'FINALIZE' -Detail 'Execution completed'
    if ($null -ne $script:AuditJsonWriter) {
        try { $script:AuditJsonWriter.Flush(); $script:AuditJsonWriter.Close() } catch {}
        $script:AuditJsonWriter = $null
    }
}

function Write-AuditEvent {
    param(
        [string]$Stage,
        [string]$Action,
        [string]$Detail,
        [long]$DurationMs = -1,
        [string]$ErrorStack = '',
        [string]$ErrorInner = ''
    )
    if ($null -eq $script:AuditJsonWriter) { return }
    $script:AuditEventSeq = $script:AuditEventSeq + 1
    $ts = (Get-Date).ToUniversalTime().ToString('o')
    $hostRef = [string](Nz $script:strComputer $env:COMPUTERNAME)
    $userRef = [string](Nz $script:UserDomainText '') + '\' + [string](Nz $script:UserNameText '')
    # Build JSON manually to avoid ConvertTo-Json overhead and PS2 compat
    $json = '{'
    $json += '"seq":' + [string]$script:AuditEventSeq
    $json += ',"ts":"' + $ts + '"'
    $json += ',"correlationId":"' + (JsonEscape $script:AuditCorrelationId) + '"'
    $json += ',"host":"' + (JsonEscape $hostRef) + '"'
    $json += ',"user":"' + (JsonEscape $userRef) + '"'
    $json += ',"pid":' + [string]$PID
    $json += ',"stage":"' + (JsonEscape ([string](Nz $Stage ''))) + '"'
    $json += ',"action":"' + (JsonEscape ([string](Nz $Action ''))) + '"'
    $json += ',"detail":"' + (JsonEscape ([string](Nz $Detail ''))) + '"'
    if ($DurationMs -ge 0) {
        $json += ',"durationMs":' + [string]$DurationMs
    }
    if ($Action -eq 'ERROR' -or $script:AuditLevelConfig -eq 'Verbose') {
        if ([string](Nz $ErrorStack '') -ne '') {
            $json += ',"stackTrace":"' + (JsonEscape $ErrorStack) + '"'
        }
        if ([string](Nz $ErrorInner '') -ne '') {
            $json += ',"innerException":"' + (JsonEscape $ErrorInner) + '"'
        }
    }
    $json += '}'
    try { $script:AuditJsonWriter.WriteLine($json) } catch {}
}

function JsonEscape {
    param([string]$Text)
    $t = [string](Nz $Text '')
    $t = $t.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t')
    return $t
}

function Nz {
    param(
        $Value,
        $Fallback
    )

    if ($null -eq $Value) {
        return $Fallback
    }

    $s = [string]$Value
    if ($s -eq '') {
        return $Fallback
    }

    return $Value
}

function Strip-ControlChars {
    param(
        [string]$Text
    )

    if ($null -eq $Text) {
        return ''
    }

    $out = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int][char]$ch
        if ($code -eq 9 -or $code -eq 10 -or $code -eq 13 -or $code -ge 32) {
            [void]$out.Append($ch)
        }
    }
    return $out.ToString()
}

function StripControlChars {
    param(
        [string]$Text
    )
    return Strip-ControlChars $Text
}

function HtmlAsciiSafe {
    param(
        [string]$Text
    )

    $t = [string](Nz $Text '')
    $out = New-Object System.Text.StringBuilder

    foreach ($ch in $t.ToCharArray()) {
        $code = [int][char]$ch
        if ($code -ge 0xD800 -and $code -le 0xDFFF) {
            [void]$out.Append('&#65533;')
        }
        elseif ($code -gt 126) {
            [void]$out.Append('&#')
            [void]$out.Append([string]$code)
            [void]$out.Append(';')
        }
        else {
            [void]$out.Append($ch)
        }
    }

    return $out.ToString()
}

function HtmlEncode {
    param(
        [string]$Text
    )

    $t = Strip-ControlChars ([string]$Text)
    $t = $t.Replace('&', '&amp;')
    $t = $t.Replace('<', '&lt;')
    $t = $t.Replace('>', '&gt;')
    $t = $t.Replace('"', '&quot;')
    $t = $t.Replace("'", '&#39;')
    return HtmlAsciiSafe $t
}

function TimestampLocalMillis {
    param(
        [datetime]$DateValue
    )

    $ms = '{0:000}' -f [int]$DateValue.Millisecond
    return '{0:dd/MM/yyyy HH:mm:ss}.{1}' -f $DateValue, $ms
}

function To-DoubleSafe {
    param($Value)
    try {
        return [double]$Value
    }
    catch {
        return 0.0
    }
}

function To-LongSafe {
    param($Value)
    try {
        return [long]$Value
    }
    catch {
        return 0
    }
}

function To-VbsTrimUpper {
    param(
        [string]$Text
    )
    return ([string](Nz $Text '')).Trim().ToUpperInvariant()
}

function To-VbsString {
    param($Value)

    if ($null -eq $Value) {
        return ''
    }
    if ($Value -is [System.IFormattable]) {
        return $Value.ToString($null, [System.Globalization.CultureInfo]::CurrentCulture)
    }
    return [string]$Value
}

function FormatNumberVbs {
    param(
        [double]$Value,
        [int]$Decimals
    )

    $v = [double]$Value
    $d = [int]$Decimals
    return $v.ToString(('N' + [string]$d), [System.Globalization.CultureInfo]::InvariantCulture)
}

function FormatBytes {
    param($Value)

    $parsed = 0.0
    if (-not [double]::TryParse((To-VbsString $Value), [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::CurrentCulture, [ref]$parsed)) {
        if (-not [double]::TryParse((To-VbsString $Value), [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
            return '-'
        }
    }

    if ($parsed -le 0) {
        return '0 B'
    }
    elseif ($parsed -lt 1024) {
        return ([long]$parsed).ToString([System.Globalization.CultureInfo]::CurrentCulture) + ' B'
    }
    elseif ($parsed -lt [math]::Pow(1024.0, 2.0)) {
        return (FormatNumberVbs ($parsed / 1024.0) 2) + ' KB'
    }
    elseif ($parsed -lt [math]::Pow(1024.0, 3.0)) {
        return (FormatNumberVbs ($parsed / [math]::Pow(1024.0, 2.0)) 2) + ' MB'
    }
    elseif ($parsed -lt [math]::Pow(1024.0, 4.0)) {
        return (FormatNumberVbs ($parsed / [math]::Pow(1024.0, 3.0)) 2) + ' GB'
    }
    return (FormatNumberVbs ($parsed / [math]::Pow(1024.0, 4.0)) 2) + ' TB'
}

function CpuArch {
    param($Value)

    switch ([int](To-LongSafe $Value)) {
        0 { return 'x86' }
        5 { return 'ARM' }
        6 { return 'Itanium' }
        9 { return 'x64' }
        default { return 'Desconhecida' }
    }
}

function MemoryTypeName {
    param($Value)

    switch ([int](To-LongSafe $Value)) {
        20 { return 'DDR' }
        21 { return 'DDR2' }
        24 { return 'DDR3' }
        26 { return 'DDR4' }
        34 { return 'DDR5' }
        default { return 'Tipo ' + [string]([int](To-LongSafe $Value)) }
    }
}

function BatteryStatusName {
    param($Value)

    switch ([int](To-LongSafe $Value)) {
        1 { return 'Descarregando' }
        2 { return 'Conectado ao carregador / Nao carregando' }
        3 { return 'Completamente carregada' }
        4 { return 'Baixa' }
        5 { return 'Critica' }
        6 { return 'Carregando' }
        7 { return 'Carregamento Alto' }
        8 { return 'Carregamento Baixo' }
        9 { return 'Carregamento Critico' }
        11 { return 'Parcialmente carregada' }
        default { return [string](Nz $Value '-') }
    }
}

function BatteryChemistryName {
    param($Value)

    switch ([int](To-LongSafe $Value)) {
        1 { return 'Outro' }
        2 { return 'Desconhecido' }
        3 { return 'Chumbo Acido' }
        4 { return 'NiCd' }
        5 { return 'NiMH' }
        6 { return 'Li-ion' }
        7 { return 'Zinc Air' }
        8 { return 'Li-Poly' }
        default { return [string](Nz $Value '-') }
    }
}

function DriveTypeName {
    param($Value)

    switch ([int](To-LongSafe $Value)) {
        1 { return 'Sem raiz' }
        2 { return 'Removivel' }
        3 { return 'Local' }
        4 { return 'Rede' }
        5 { return 'CD/DVD' }
        6 { return 'RAM Disk' }
        default { return 'Desconhecido' }
    }
}

function GetMobileDeviceHistory {
    $results = New-Object System.Collections.Generic.List[PSObject]
    $wpdPath = 'HKLM:\SOFTWARE\Microsoft\Windows Portable Devices\Devices'
    if (Test-Path -LiteralPath $wpdPath) {
        Get-ChildItem -LiteralPath $wpdPath | ForEach-Object {
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue } catch {}
            if ($null -ne $props) {
                $friend = $null; try { $friend = $props.FriendlyName } catch {}
                $manuf = $null; try { $manuf = $props.Manufacturer } catch {}
                if ($friend -or $manuf) {
                    [void]$results.Add([PSCustomObject]@{
                        Type = 'WPD (Mobile)'
                        Name = [string](Nz $friend '-')
                        Manufacturer = [string](Nz $manuf '-')
                        Id = $_.PSChildName
                    })
                }
            }
        }
    }
    # Deep USB Enum scan for iPhone/Apple patterns
    $usbEnum = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USB'
    if (Test-Path -LiteralPath $usbEnum) {
        Get-ChildItem -LiteralPath $usbEnum | ForEach-Object {
            $parentPath = $_.PSPath
            Get-ChildItem -LiteralPath $parentPath -ErrorAction SilentlyContinue | ForEach-Object {
                $pnpId = $_.PSChildName
                $props = $null
                try { $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue } catch {}
                if ($null -ne $props) {
                    $desc = ''; try { $desc = [string]$props.DeviceDesc } catch {}
                    $mfn = ''; try { $mfn = [string]$props.Mfg } catch {}
                    if ($pnpId -match 'VID_05AC' -or $desc -match 'Apple|iPhone|iPad|iPod') {
                        $cleanDesc = ($desc.Split(';')[-1] -as [string]).Trim()
                        $cleanMfn = ($mfn.Split(';')[-1] -as [string]).Trim()
                        [void]$results.Add([PSCustomObject]@{
                            Type = 'USB Enum (Apple)'
                            Name = [string](Nz $cleanDesc '-')
                            Manufacturer = [string](Nz $cleanMfn '-')
                            Id = $pnpId
                        })
                    }
                }
            }
        }
    }
    # USBSTOR for generic mobile history if inferred
    $usbStor = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    if (Test-Path -LiteralPath $usbStor) {
        Get-ChildItem -LiteralPath $usbStor | ForEach-Object {
            $id = $_.PSChildName
            if ($id -match 'Android|iPhone|Apple|Samsung|Mobile|Phone|MTP') {
                [void]$results.Add([PSCustomObject]@{
                    Type = 'USBSTOR (Mobile Pattern)'
                    Name = $id
                    Manufacturer = '-'
                    Id = $id
                })
            }
        }
    }
    return $results
}

function ScanUserBackups {
    $userProfile = [System.Environment]::ExpandEnvironmentVariables('%USERPROFILE%')
    $appData = [System.Environment]::ExpandEnvironmentVariables('%APPDATA%')
    $localAppData = [System.Environment]::ExpandEnvironmentVariables('%LOCALAPPDATA%')
    
    $paths = @(
        @{ Name='Apple iTunes/iOS Backup'; Path="$appData\Apple Computer\MobileSync\Backup" },
        @{ Name='Apple iTunes/iOS (Alt)'; Path="$localAppData\Apple\MobileSync\Backup" },
        @{ Name='WhatsApp Desktop'; Path="$localAppData\WhatsApp" },
        @{ Name='Android Backup (ADB/Local)'; Path="$userProfile\Android" },
        @{ Name='Samsung Smart Switch'; Path="$userProfile\Documents\Samsung\SmartSwitch" },
        @{ Name='Google Drive Local Sync'; Path="$userProfile\Google Drive" },
        @{ Name='OneDrive Personal'; Path="$userProfile\OneDrive" },
        @{ Name='Dropbox Local'; Path="$userProfile\Dropbox" },
        @{ Name='Telegram Desktop Cache'; Path="$appData\Telegram Desktop\tdata" }
    )
    
    $found = New-Object System.Collections.Generic.List[PSObject]
    foreach ($p in $paths) {
        if (Test-Path -LiteralPath $p.Path -PathType Container) {
            $f = 0; $d = 0; $b = 0.0
            CountFolderStats -Path $p.Path -TotalFiles ([ref]$f) -TotalDirs ([ref]$d) -TotalBytes ([ref]$b)
            if ($f -gt 0 -or $d -gt 0) {
                $found.Add([PSCustomObject]@{
                    Name = $p.Name
                    Path = $p.Path
                    Size = $b
                    Files = $f
                })
            }
        }
    }
    return $found
}

function InferDiskType {
    param(
        $Model,
        $Media
    )

    $s = (([string](Nz $Model '')) + ' ' + ([string](Nz $Media ''))).ToUpperInvariant()
    if ($s.Contains('SSD') -or $s.Contains('NVME')) {
        return 'Provavel SSD'
    }
    if ($s.Contains('HDD') -or $s.Contains('SATA')) {
        return 'Provavel HDD'
    }
    return 'Nao determinado'
}

function MediaTypeName {
    param($Value)

    switch ([int](To-LongSafe $Value)) {
        3 { return 'HDD' }
        4 { return 'SSD' }
        5 { return 'SCM' }
        default { return ('Desconhecido(' + [int](To-LongSafe $Value) + ')') }
    }
}

function BusTypeName {
    param($Value)

    switch ([int](To-LongSafe $Value)) {
        1 { return 'SCSI' }
        2 { return 'ATAPI' }
        3 { return 'ATA' }
        7 { return 'USB' }
        10 { return 'SAS' }
        11 { return 'SATA' }
        17 { return 'NVMe' }
        default { return ('Bus ' + [int](To-LongSafe $Value)) }
    }
}

function ParseBetween {
    param(
        [string]$Source,
        [string]$Marker,
        [string]$Terminator
    )

    $result = '-'
    $src = [string](Nz $Source '')
    $m = [string](Nz $Marker '')
    $t = [string](Nz $Terminator '')

    if ($m -eq '') {
        return $result
    }

    $p1 = $src.IndexOf($m, [System.StringComparison]::OrdinalIgnoreCase)
    if ($p1 -lt 0) {
        return $result
    }

    $tmp = $src.Substring($p1 + $m.Length)
    $p2 = $tmp.IndexOf($t, [System.StringComparison]::OrdinalIgnoreCase)
    if ($p2 -ge 1) {
        return $tmp.Substring(0, $p2)
    }
    return $tmp
}

function EnsureTelemetryIndexes {
    if ($null -eq $script:WmiQueryIndex) { $script:WmiQueryIndex = @{} }
    if ($null -eq $script:RegistryValueIndex) { $script:RegistryValueIndex = @{} }
    if ($null -eq $script:CommandOutputIndex) { $script:CommandOutputIndex = @{} }
    if ($null -eq $script:ProcessNameByPidIndex) { $script:ProcessNameByPidIndex = @{} }
}

function ReadDWORDValue {
    param(
        [string]$KeyPath,
        [string]$ValueName,
        $DefaultValue
    )

    EnsureTelemetryIndexes
    $regPath = 'Registry::HKEY_LOCAL_MACHINE\' + [string](Nz $KeyPath '')
    $idxKey = 'DWORD|HKLM|' + ([string](Nz $KeyPath '')).ToUpperInvariant() + '|' + ([string](Nz $ValueName '')).ToUpperInvariant()
    if ($script:RegistryValueIndex.ContainsKey($idxKey)) {
        return $script:RegistryValueIndex[$idxKey]
    }

    $result = $DefaultValue
    try {
        $p = Get-ItemProperty -LiteralPath $regPath -Name $ValueName -ErrorAction Stop
        if ($null -eq $p) {
            $result = $DefaultValue
        }
        else {
            $result = [long](To-LongSafe $p.$ValueName)
        }
    }
    catch {
        $result = $DefaultValue
    }
    $script:RegistryValueIndex[$idxKey] = $result
    return $result
}

function ReadStringValue {
    param(
        [string]$KeyPath,
        [string]$ValueName,
        [string]$DefaultValue
    )

    EnsureTelemetryIndexes
    $regPath = 'Registry::HKEY_LOCAL_MACHINE\' + [string](Nz $KeyPath '')
    $idxKey = 'STRING|HKLM|' + ([string](Nz $KeyPath '')).ToUpperInvariant() + '|' + ([string](Nz $ValueName '')).ToUpperInvariant()
    if ($script:RegistryValueIndex.ContainsKey($idxKey)) {
        return [string](Nz $script:RegistryValueIndex[$idxKey] $DefaultValue)
    }

    $result = $DefaultValue
    try {
        $p = Get-ItemProperty -LiteralPath $regPath -Name $ValueName -ErrorAction Stop
        if ($null -eq $p) {
            $result = $DefaultValue
        }
        else {
            $result = [string](Nz $p.$ValueName $DefaultValue)
        }
    }
    catch {
        $result = $DefaultValue
    }
    $script:RegistryValueIndex[$idxKey] = $result
    return [string](Nz $result $DefaultValue)
}

function ParsePnPSerial {
    param(
        [string]$PnPDeviceId
    )

    $result = '-'
    $parts = ([string](Nz $PnPDeviceId '')).Split('\')
    if ($parts.Length -ge 3) {
        $result = $parts[$parts.Length - 1]
    }
    return $result
}

function InferExternalDriveType {
    param(
        [string]$Description
    )

    $desc = ([string](Nz $Description '')).ToUpperInvariant()
    if ($desc.Contains('STICK') -or $desc.Contains('USB STICK')) {
        return 'Pendrive USB'
    }
    elseif ($desc.Contains('EXTERNAL') -or $desc.Contains('EXT')) {
        if ($desc.Contains('SSD')) {
            return 'SSD Externo'
        }
        return 'HDD Externo'
    }
    elseif ($desc.Contains('STORAGE') -or $desc.Contains('DISK') -or $desc.Contains('DRIVE')) {
        return 'HDD Externo'
    }
    return 'Dispositivo USB/Desconhecido'
}

function AppendChartData {
    param(
        $Label,
        $UsedGB,
        $FreeGB
    )

    $safe = ([string](Nz $Label '')).Replace("'", "\'")
    if ([string](Nz $script:diskChartLabels '') -ne '') {
        $script:diskChartLabels = $script:diskChartLabels + ','
        $script:diskChartUsed = $script:diskChartUsed + ','
        $script:diskChartFree = $script:diskChartFree + ','
    }

    $script:diskChartLabels = $script:diskChartLabels + "'" + $safe + "'"
    $used = [math]::Truncate((To-DoubleSafe $UsedGB) * 100.0) / 100.0
    $free = [math]::Truncate((To-DoubleSafe $FreeGB) * 100.0) / 100.0
    $script:diskChartUsed = $script:diskChartUsed + (To-VbsString $used)
    $script:diskChartFree = $script:diskChartFree + (To-VbsString $free)
}

function FormatDateTimeLocal {
    param(
        [datetime]$DateValue
    )

    return '{0:dd/MM/yyyy HH:mm:ss}' -f $DateValue
}

function Get-ReferenceDate {
    if ($null -ne $script:NowReference) {
        return [datetime]$script:NowReference
    }
    return Get-Date
}

function HumanizeDateDistancePt {
    param(
        [datetime]$DateValue
    )

    $deltaDays = [int]((Get-ReferenceDate).Date - [datetime]$DateValue.Date).TotalDays
    switch ($deltaDays) {
        0 { return 'hoje' }
        1 { return 'ontem' }
        -1 { return 'amanha' }
        default {
            if ($deltaDays -gt 1) {
                return ('{0} dias atras' -f $deltaDays)
            }
            return ('{0} dias atras' -f ([Math]::Abs($deltaDays)))
        }
    }
}

function FormatDateTimeHumanized {
    param(
        [datetime]$DateValue
    )

    return (FormatDateTimeLocal $DateValue) + ' (' + (HumanizeDateDistancePt $DateValue) + ')'
}

function FormatDateHumanized {
    param(
        [datetime]$DateValue
    )

    return ('{0:dd/MM/yyyy}' -f $DateValue) + ' (' + (HumanizeDateDistancePt $DateValue) + ')'
}

function IIfBool {
    param(
        [bool]$Condition,
        $TrueValue,
        $FalseValue
    )
    if ($Condition) {
        return $TrueValue
    }
    return $FalseValue
}

function ParseTimeZoneOffset {
    param($Value)

    if ($null -eq $Value -or -not ([string](Nz $Value '')).Trim()) {
        return '-'
    }

    $num = 0
    if (-not [long]::TryParse([string]$Value, [ref]$num)) {
        return [string](Nz $Value '-')
    }

    $sign = '+'
    if ($num -lt 0) { $sign = '-' }
    $absM = [Math]::Abs($num)
    $hh = [Math]::Floor($absM / 60)
    $mm = $absM % 60
    return 'UTC' + $sign + ('{0:00}' -f $hh) + ':' + ('{0:00}' -f $mm) + ' (offset atual: ' + $num + ' min)'
}

function ParseWindowsLanguageCode {
    param($Value)

    $n = 0
    if (-not [long]::TryParse([string](Nz $Value ''), [ref]$n)) {
        return [string](Nz $Value '-')
    }

    $label = 'LCID nao mapeado'
    switch ([int]$n) {
        1046 { $label = 'Portugues (BR)' }
        2070 { $label = 'Portugues (PT)' }
        1033 { $label = 'Ingles (US)' }
        2057 { $label = 'Ingles (UK)' }
        3082 { $label = 'Espanhol (Esp)' }
        1034 { $label = 'Espanhol' }
        1031 { $label = 'Alemao' }
        1036 { $label = 'Frances' }
        1040 { $label = 'Italiano' }
        1041 { $label = 'Japones' }
        1042 { $label = 'Coreano' }
        2052 { $label = 'Chines (Simplificado)' }
        1028 { $label = 'Chines (Tradicional)' }
    }
    return $label + ' [' + $n + ']'
}

function GetLeafNameFromPath {
    param(
        [string]$FullPath
    )

    $s = [string](Nz $FullPath '')
    if ($s -eq '') {
        return '-'
    }

    $p = $s.LastIndexOf('\')
    if ($p -ge 0) {
        return $s.Substring($p + 1)
    }
    return $s
}

function IsRelevantUserProfileName {
    param(
        [string]$ProfileName
    )

    $n = To-VbsTrimUpper ([string](Nz $ProfileName ''))
    if ($n -eq '') {
        return $false
    }

    switch ($n) {
        'PUBLIC' { return $false }
        'DEFAULT' { return $false }
        'DEFAULT USER' { return $false }
        'ALL USERS' { return $false }
        'DEFAULTAPPPOOL' { return $false }
        'DEFAULTUSER0' { return $false }
        'WDAGUTILITYACCOUNT' { return $false }
        default { return $true }
    }
}

function SortKeyFromDateValue {
    param($DateValue)

    if ($null -eq $DateValue) {
        return ''
    }
    if (-not ($DateValue -is [datetime])) {
        try {
            $DateValue = [datetime]$DateValue
        }
        catch {
            return ''
        }
    }

    return '{0:yyyy-MM-dd HH:mm:ss}' -f ([datetime]$DateValue)
}

function SortKeyFromWmiDate {
    param($WmiDate)

    if ($WmiDate -is [datetime]) {
        return '{0:yyyy-MM-dd HH:mm:ss}' -f ([datetime]$WmiDate)
    }

    $d = [string](Nz $WmiDate '')
    if ($d.Length -lt 14) {
        return ''
    }
    return $d.Substring(0, 4) + '-' + $d.Substring(4, 2) + '-' + $d.Substring(6, 2) + ' ' + $d.Substring(8, 2) + ':' + $d.Substring(10, 2) + ':' + $d.Substring(12, 2)
}

function DfirTimelineFieldSafe {
    param($Value)

    $s = [string](Nz $Value '-')
    $sep = [char]30
    $s = $s.Replace([string]$sep, '/')
    $s = $s.Replace("`r`n", ' | ')
    $s = $s.Replace("`r", ' | ')
    $s = $s.Replace("`n", ' | ')
    return $s
}

function AppendDfirTimelineRecordFromDate {
    param(
        $DateValue,
        $CategoryText,
        $ItemText,
        $EventText,
        $ValueText,
        $SourceText,
        $SeverityText
    )

    $sortKey = SortKeyFromDateValue $DateValue
    if ($sortKey -eq '') { return }
    $displayText = FormatDateTimeLocal ([datetime]$DateValue)
    AppendDfirTimelineRecord $sortKey $displayText $CategoryText $ItemText $EventText $ValueText $SourceText $SeverityText
}

function AppendDfirTimelineRecordFromWmi {
    param(
        $WmiDate,
        $CategoryText,
        $ItemText,
        $EventText,
        $ValueText,
        $SourceText,
        $SeverityText
    )

    $sortKey = SortKeyFromWmiDate $WmiDate
    if ($sortKey -eq '') { return }
    $displayText = WmiDateToString $WmiDate
    AppendDfirTimelineRecord $sortKey $displayText $CategoryText $ItemText $EventText $ValueText $SourceText $SeverityText
}

function AppendDfirTimelineRecord {
    param(
        [string]$SortKey,
        [string]$DisplayTime,
        [string]$CategoryText,
        [string]$ItemText,
        [string]$EventText,
        [string]$ValueText,
        [string]$SourceText,
        [string]$SeverityText
    )

    $sep = [char]30
    $line = (DfirTimelineFieldSafe $SortKey) + $sep + (DfirTimelineFieldSafe $DisplayTime) + $sep + (DfirTimelineFieldSafe $CategoryText) + $sep + (DfirTimelineFieldSafe $ItemText) + $sep + (DfirTimelineFieldSafe $EventText) + $sep + (DfirTimelineFieldSafe $ValueText) + $sep + (DfirTimelineFieldSafe $SourceText) + $sep + (DfirTimelineFieldSafe (([string](Nz $SeverityText 'INFO')).ToUpperInvariant()))
    if ([string](Nz $script:strDfirTimelineRecords '') -ne '') {
        $script:strDfirTimelineRecords = $script:strDfirTimelineRecords + "`n"
    }
    $script:strDfirTimelineRecords = [string](Nz $script:strDfirTimelineRecords '') + $line
    $script:dfirTimelineRecordCount = [long](To-LongSafe $script:dfirTimelineRecordCount) + 1
}

function WmiDateToString {
    param(
        $DateText
    )

    if ($DateText -is [datetime]) {
        return FormatDateTimeLocal ([datetime]$DateText)
    }

    $d = [string](Nz $DateText '')
    if ($d.Length -ge 14) {
        return $d.Substring(6, 2) + '/' + $d.Substring(4, 2) + '/' + $d.Substring(0, 4) + ' ' + $d.Substring(8, 2) + ':' + $d.Substring(10, 2) + ':' + $d.Substring(12, 2)
    }
    return [string](Nz $d '-')
}

function TryParseWmiDateValue {
    param(
        $WmiDate,
        [ref]$OutDate
    )

    if ($WmiDate -is [datetime]) {
        $OutDate.Value = [datetime]$WmiDate
        return $true
    }

    $s = [string](Nz $WmiDate '')
    if ($s.Length -lt 14) {
        return $false
    }

    try {
        $year = [int]$s.Substring(0, 4)
        $month = [int]$s.Substring(4, 2)
        $day = [int]$s.Substring(6, 2)
        $hour = [int]$s.Substring(8, 2)
        $minute = [int]$s.Substring(10, 2)
        $second = [int]$s.Substring(12, 2)
        $OutDate.Value = Get-Date -Year $year -Month $month -Day $day -Hour $hour -Minute $minute -Second $second
        return $true
    }
    catch {
        return $false
    }
}

function TryBuildDateYMD {
    param(
        $YearNum,
        $MonthNum,
        $DayNum,
        [ref]$OutDate
    )

    if ($null -eq $YearNum -or $null -eq $MonthNum -or $null -eq $DayNum) {
        return $false
    }
    if (-not ($YearNum -as [int]) -or -not ($MonthNum -as [int]) -or -not ($DayNum -as [int])) {
        return $false
    }

    $y = [int]$YearNum
    $m = [int]$MonthNum
    $d = [int]$DayNum

    if ($y -lt 1900 -or $y -gt 2100) { return $false }
    if ($m -lt 1 -or $m -gt 12) { return $false }
    if ($d -lt 1 -or $d -gt 31) { return $false }

    try {
        $OutDate.Value = Get-Date -Year $y -Month $m -Day $d -Hour 0 -Minute 0 -Second 0
        return $true
    }
    catch {
        return $false
    }
}

function ChooseBestAmbiguousDate {
    param(
        [datetime]$UsDate,
        [bool]$HasUs,
        [datetime]$BrDate,
        [bool]$HasBr,
        [string]$RawText,
        [ref]$OutDate
    )

    $futureLimit = (Get-ReferenceDate).Date.AddDays(2)

    if ($HasUs -and -not $HasBr) {
        $OutDate.Value = $UsDate
        return $true
    }
    if ($HasBr -and -not $HasUs) {
        $OutDate.Value = $BrDate
        return $true
    }
    if (-not $HasUs -and -not $HasBr) {
        return $false
    }

    if ($UsDate -le $futureLimit -and $BrDate -gt $futureLimit) {
        $OutDate.Value = $UsDate
        return $true
    }
    if ($BrDate -le $futureLimit -and $UsDate -gt $futureLimit) {
        $OutDate.Value = $BrDate
        return $true
    }

    try {
        $localeDt = [datetime]::Parse($RawText, [System.Globalization.CultureInfo]::CurrentCulture)
        $OutDate.Value = $localeDt
        return $true
    }
    catch {
    }

    $OutDate.Value = $UsDate
    return $true
}

function TryParseQfeInstalledOnDate {
    param(
        $RawText,
        [ref]$OutDate
    )

    if ($RawText -is [datetime]) {
        $OutDate.Value = [datetime]$RawText
        return $true
    }

    $s = ([string](Nz $RawText '')).Trim()
    if ($s -eq '') {
        return $false
    }

    if ($s.Contains(' ')) {
        $s = $s.Split(' ')[0].Trim()
    }
    $s = $s.Replace('.', '/')
    $s = $s.Replace('-', '/')

    if ($s.Length -eq 8 -and $s -match '^\d+$') {
        $tmp = [datetime]::MinValue
        if (TryBuildDateYMD $s.Substring(0, 4) $s.Substring(4, 2) $s.Substring(6, 2) ([ref]$tmp)) {
            $OutDate.Value = $tmp
            return $true
        }
    }

    $parts = $s.Split('/')
    if ($parts.Count -eq 3) {
        $a = $parts[0].Trim()
        $b = $parts[1].Trim()
        $c = $parts[2].Trim()
        if ($a -match '^\d+$' -and $b -match '^\d+$' -and $c -match '^\d+$') {
            if ($a.Length -eq 4) {
                $tmp = [datetime]::MinValue
                if (TryBuildDateYMD $a $b $c ([ref]$tmp)) {
                    $OutDate.Value = $tmp
                    return $true
                }
            }
            elseif ($c.Length -eq 4) {
                $usDt = [datetime]::MinValue
                $brDt = [datetime]::MinValue
                $hasUs = TryBuildDateYMD $c $a $b ([ref]$usDt)
                $hasBr = TryBuildDateYMD $c $b $a ([ref]$brDt)
                $best = [datetime]::MinValue
                if (ChooseBestAmbiguousDate $usDt $hasUs $brDt $hasBr $s ([ref]$best)) {
                    $OutDate.Value = $best
                    return $true
                }
            }
        }
    }

    try {
        $OutDate.Value = [datetime]$s
        return $true
    }
    catch {
        return $false
    }
}

function Invoke-WmiQueryCompat {
    param(
        [string]$QueryText
    )

    EnsureTelemetryIndexes
    $q = [string](Nz $QueryText '')
    $idxKey = 'WMI|' + $q.Trim().ToUpperInvariant()
    if ($script:WmiQueryIndex.ContainsKey($idxKey)) {
        return @($script:WmiQueryIndex[$idxKey])
    }

    $result = @()
    # CIM first (WS-Man, lower memory, faster) then WMI (DCOM) as fallback
    try {
        if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
            $result = @(Get-CimInstance -Query $QueryText -ErrorAction Stop)
            $script:WmiQueryIndex[$idxKey] = @($result)
            return @($result)
        }
    }
    catch {
    }

    try {
        if (Get-Command -Name Get-WmiObject -ErrorAction SilentlyContinue) {
            $result = @(Get-WmiObject -Query $QueryText -ErrorAction Stop)
            $script:WmiQueryIndex[$idxKey] = @($result)
            return @($result)
        }
    }
    catch {
    }

    $script:WmiQueryIndex[$idxKey] = @()
    return @()
}

function SafeWmiProp {
    param(
        $WmiObj,
        [string]$PropName,
        $Fallback
    )

    try {
        if ($null -eq $WmiObj) {
            return $Fallback
        }

        if ($WmiObj.PSObject -and $WmiObj.PSObject.Properties[$PropName]) {
            return Nz $WmiObj.PSObject.Properties[$PropName].Value $Fallback
        }

        $p = $WmiObj.Properties_.Item($PropName)
        if ($null -ne $p) {
            return Nz $p.Value $Fallback
        }
    }
    catch {
    }

    return $Fallback
}

function HtmlPre {
    param($Value)
    return '<pre>' + (HtmlEncode ([string](Nz $Value '-'))) + '</pre>'
}

function WriteKV {
    param(
        $Key,
        $Value
    )

    Write-VbsLine $script:CurrentWriter ("<tr><td>" + (HtmlEncode ([string]$Key)) + "</td><td>" + (HtmlEncode ([string](Nz $Value '-'))) + "</td></tr>")
}

function WriteKVHtml {
    param(
        $Key,
        $HtmlValue
    )

    Write-VbsLine $script:CurrentWriter ("<tr><td>" + (HtmlEncode ([string]$Key)) + "</td><td>" + ([string](Nz $HtmlValue '-')) + "</td></tr>")
}

function Invoke-ExternalCommandCapture {
    param(
        [string]$CommandText
    )

    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'cmd.exe'
        $psi.Arguments = '/c ' + $CommandText
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true

        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo = $psi
        [void]$proc.Start()
        $out = $proc.StandardOutput.ReadToEnd()
        $err = $proc.StandardError.ReadToEnd()
        $proc.WaitForExit()

        $combined = [string](Nz $out '')
        if ([string](Nz $err '') -ne '') {
            $combined = $combined + $err
        }
        return $combined
    }
    catch {
        return ('Falha ao executar comando: ' + $_.Exception.Message)
    }
}

function GetCommandOutput {
    param(
        [string]$CommandText
    )

    EnsureTelemetryIndexes
    if ($null -ne $script:CommandOutputOverrides -and $script:CommandOutputOverrides.ContainsKey($CommandText)) {
        return [string]$script:CommandOutputOverrides[$CommandText]
    }

    $idxKey = 'CMD|' + ([string](Nz $CommandText '')).Trim().ToUpperInvariant()
    if ($script:CommandOutputIndex.ContainsKey($idxKey)) {
        return [string](Nz $script:CommandOutputIndex[$idxKey] '')
    }

    $defaultTimeout = [int](To-LongSafe $script:DefaultCommandTimeoutSecs)
    $result = ''
    if ($defaultTimeout -gt 0) {
        $result = GetCommandOutputWithTimeout -CommandText $CommandText -TimeoutSecs $defaultTimeout
    }
    else {
        $result = Invoke-ExternalCommandCapture -CommandText $CommandText
    }
    $script:CommandOutputIndex[$idxKey] = [string](Nz $result '')
    return [string](Nz $result '')
}

function SecondsBetweenTicks {
    param(
        [double]$StartTick,
        [double]$EndTick
    )

    $secs = [double](To-DoubleSafe $EndTick) - [double](To-DoubleSafe $StartTick)
    if ($secs -lt 0.0) {
        $secs = [double]($secs + 86400.0)
    }
    return $secs
}

function ShortCommandForLog {
    param(
        [string]$CommandText
    )

    $s = [string](Nz $CommandText '')
    $s = $s.Replace("`r", ' ')
    $s = $s.Replace("`n", ' ')
    $s = $s.Replace("`t", ' ')
    while ($s.Contains('  ')) {
        $s = $s.Replace('  ', ' ')
    }
    $s = $s.Trim()
    if ($s.Length -gt 220) {
        $s = $s.Substring(0, 220) + '...'
    }
    return $s
}

function HasUsefulOutput {
    param($Value)

    $t = ([string](Nz $Value '')).Trim()
    if ($t -eq '') { return $false }
    if ($t.ToUpperInvariant() -eq 'N/A') { return $false }
    if ($t.ToLowerInvariant().Contains('falha ao executar comando:')) { return $false }
    if ($t.ToLowerInvariant().Contains('is not recognized')) { return $false }
    if ($t.ToLowerInvariant().Contains('nao e reconhecido')) { return $false }
    return $true
}

function GetCommandOutputWithTimeout {
    param(
        [string]$CommandText,
        [int]$TimeoutSecs
    )

    if ($null -ne $script:CommandOutputOverrides -and $script:CommandOutputOverrides.ContainsKey($CommandText)) {
        return [string]$script:CommandOutputOverrides[$CommandText]
    }

    $timeoutUse = [int](To-LongSafe $TimeoutSecs)
    if ($timeoutUse -le 0) {
        $timeoutUse = [int](To-LongSafe $script:DefaultCommandTimeoutSecs)
    }
    if ($timeoutUse -le 0) {
        $timeoutUse = 45
    }

    $cmdLabel = ShortCommandForLog $CommandText
    $cmdTickStart = [double](Get-Date).TimeOfDay.TotalSeconds
    $script:cmdExecCount = [long](To-LongSafe $script:cmdExecCount) + 1
    if (Get-Command -Name LogCustody -ErrorAction SilentlyContinue) {
        try {
            LogCustody -Etapa 'PESQUISA' -Status 'START' -Detalhes ('Comando: ' + $cmdLabel)
        }
        catch {
        }
    }

    $outPath = [System.IO.Path]::GetTempFileName()
    $errPath = [System.IO.Path]::GetTempFileName()
    try {
        Write-ProgressLog -Message ('CMD START (' + $timeoutUse + 's): ' + $CommandText)
        $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $CommandText -NoNewWindow -PassThru -RedirectStandardOutput $outPath -RedirectStandardError $errPath
        $completed = $proc.WaitForExit([Math]::Max(1, $timeoutUse) * 1000)
        if (-not $completed) {
            try { $proc.Kill() } catch {}
            Write-ProgressLog -Message ('CMD TIMEOUT: ' + $CommandText) -Force
            $elapsedTimeout = SecondsBetweenTicks -StartTick $cmdTickStart -EndTick ([double](Get-Date).TimeOfDay.TotalSeconds)
            $script:cmdTimeoutCount = [long](To-LongSafe $script:cmdTimeoutCount) + 1
            $script:cmdTotalSecs = [double](To-DoubleSafe $script:cmdTotalSecs) + $elapsedTimeout
            if (Get-Command -Name LogCustody -ErrorAction SilentlyContinue) {
                try {
                    LogCustody -Etapa 'PESQUISA' -Status 'WARN' -Detalhes ('Timeout: ' + $cmdLabel + ' | limite_s: ' + $timeoutUse)
                }
                catch {
                }
                try {
                    LogCustody -Etapa 'PESQUISA' -Status 'END' -Detalhes ('Comando: ' + $cmdLabel + ' | Resultado: TIMEOUT')
                }
                catch {
                }
            }
            return '[TIMEOUT APOS ' + $timeoutUse + 's] Comando interrompido por demora.'
        }

        $out = ''
        $err = ''
        try { $out = [System.IO.File]::ReadAllText($outPath) } catch { $out = '' }
        try { $err = [System.IO.File]::ReadAllText($errPath) } catch { $err = '' }

        $out = [string](Nz $out '')
        $err = [string](Nz $err '')
        $outTrim = $out.Trim()
        $errTrim = $err.Trim()
        if ($outTrim -ne '') {
            if ($errTrim -ne '') {
                Write-ProgressLog -Message ('CMD END (stdout+stderr): ' + $CommandText)
                $ret = $outTrim + "`r`n[stderr]`r`n" + $errTrim
            }
            else {
                Write-ProgressLog -Message ('CMD END (stdout): ' + $CommandText)
                $ret = $outTrim
            }
        }
        else {
            Write-ProgressLog -Message ('CMD END (stderr/empty): ' + $CommandText)
            $ret = $errTrim
        }

        $elapsedOk = SecondsBetweenTicks -StartTick $cmdTickStart -EndTick ([double](Get-Date).TimeOfDay.TotalSeconds)
        $script:cmdTotalSecs = [double](To-DoubleSafe $script:cmdTotalSecs) + $elapsedOk
        $resultTag = 'OK'
        if ([string](Nz $ret '').Trim() -eq '') {
            $resultTag = 'VAZIO'
        }
        if (Get-Command -Name LogCustody -ErrorAction SilentlyContinue) {
            try {
                LogCustody -Etapa 'PESQUISA' -Status 'END' -Detalhes ('Comando: ' + $cmdLabel + ' | Resultado: ' + $resultTag)
            }
            catch {
            }
        }
        return $ret
    }
    catch {
        Write-ProgressLog -Message ('CMD ERROR: ' + $CommandText + ' -> ' + $_.Exception.Message) -Force
        $elapsedErr = SecondsBetweenTicks -StartTick $cmdTickStart -EndTick ([double](Get-Date).TimeOfDay.TotalSeconds)
        $script:cmdTotalSecs = [double](To-DoubleSafe $script:cmdTotalSecs) + $elapsedErr
        $script:cmdFailCount = [long](To-LongSafe $script:cmdFailCount) + 1
        if (Get-Command -Name LogCustody -ErrorAction SilentlyContinue) {
            try {
                LogCustody -Etapa 'PESQUISA' -Status 'BAD' -Detalhes ('Falha ao iniciar comando: ' + $cmdLabel + ' | erro: ' + $_.Exception.Message)
            }
            catch {
            }
            try {
                LogCustody -Etapa 'PESQUISA' -Status 'END' -Detalhes ('Comando: ' + $cmdLabel + ' | Resultado: ERRO_INICIO')
            }
            catch {
            }
        }
        return ('Falha ao executar comando: ' + $_.Exception.Message)
    }
    finally {
        try { Remove-Item -LiteralPath $outPath -Force -ErrorAction SilentlyContinue } catch {}
        try { Remove-Item -LiteralPath $errPath -Force -ErrorAction SilentlyContinue } catch {}
    }
}

function JoinArray {
    param(
        $Arr,
        [string]$Sep
    )

    if ($Arr -is [System.Array]) {
        $parts = @()
        foreach ($item in $Arr) {
            $parts += (HtmlEncode ([string](Nz $item '-')))
        }
        return ($parts -join $Sep)
    }
    return HtmlEncode ([string](Nz $Arr '-'))
}

function HumanSpeed {
    param($Value)

    $n = 0.0
    if (-not [double]::TryParse([string](Nz $Value ''), [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::CurrentCulture, [ref]$n)) {
        if (-not [double]::TryParse([string](Nz $Value ''), [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) {
            return '-'
        }
    }
    if ($n -eq 0.0) {
        return '-'
    }
    return (FormatNumberVbs ($n / 1000000000.0) 2) + ' Gbps'
}

function NetConnectionStatusName {
    param($Value)

    switch ([int](To-LongSafe $Value)) {
        0 { return 'Desconectado' }
        1 { return 'Conectando' }
        2 { return 'Conectado' }
        7 { return 'Midia desconectada' }
        default { return ('Status ' + [int](To-LongSafe $Value)) }
    }
}

function WalkFolderStats {
    param(
        [System.IO.DirectoryInfo]$FolderObj,
        [ref]$TotalFiles,
        [ref]$TotalDirs,
        [ref]$TotalBytes
    )

    if ($null -eq $FolderObj) {
        return
    }

    try {
        foreach ($f in $FolderObj.GetFiles()) {
            $TotalFiles.Value = [long](To-LongSafe $TotalFiles.Value) + 1
            $TotalBytes.Value = [double](To-DoubleSafe $TotalBytes.Value) + [double](To-DoubleSafe $f.Length)
        }
    }
    catch {
    }

    try {
        foreach ($sf in $FolderObj.GetDirectories()) {
            if (($sf.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                continue
            }
            $TotalDirs.Value = [long](To-LongSafe $TotalDirs.Value) + 1
            WalkFolderStats -FolderObj $sf -TotalFiles $TotalFiles -TotalDirs $TotalDirs -TotalBytes $TotalBytes
        }
    }
    catch {
    }
}

function CountFolderStats {
    param(
        [string]$Path,
        [ref]$TotalFiles,
        [ref]$TotalDirs,
        [ref]$TotalBytes
    )

    $TotalFiles.Value = 0
    $TotalDirs.Value = 0
    $TotalBytes.Value = 0

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return
    }
    if (ShouldSkipTelemetryPath -PathValue $Path) {
        return
    }

    try {
        $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
    catch {
        return
    }

    $stack = New-Object System.Collections.Stack
    $stack.Push($root)

    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try {
            foreach ($f in Get-ChildItem -LiteralPath $dir.FullName -File -Force -ErrorAction Stop) {
                $TotalFiles.Value = [long](To-LongSafe $TotalFiles.Value) + 1
                $TotalBytes.Value = [double](To-DoubleSafe $TotalBytes.Value) + [double](To-DoubleSafe $f.Length)
            }
        }
        catch {
        }

        try {
            foreach ($sub in Get-ChildItem -LiteralPath $dir.FullName -Directory -Force -ErrorAction Stop) {
                if (($sub.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                    continue
                }
                if (ShouldSkipTelemetryPath -PathValue $sub.FullName) {
                    continue
                }
                $TotalDirs.Value = [long](To-LongSafe $TotalDirs.Value) + 1
                $stack.Push($sub)
            }
        }
        catch {
        }
    }
}

function Normalize-FullPathSafe {
    param(
        [string]$PathValue
    )

    try {
        $v = [string](Nz $PathValue '')
        if ($v.Trim() -eq '') { return '' }
        return [System.IO.Path]::GetFullPath($v).TrimEnd('\')
    }
    catch {
        return ([string](Nz $PathValue '')).TrimEnd('\')
    }
}

function ShouldSkipTelemetryPath {
    param(
        [string]$PathValue
    )

    $full = Normalize-FullPathSafe $PathValue
    if ($full -eq '') { return $false }

    $skipList = @($script:TelemetrySkipPaths)
    foreach ($s in $skipList) {
        $skipPath = Normalize-FullPathSafe $s
        if ($skipPath -eq '') { continue }
        if ($full.Equals($skipPath, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($full.StartsWith($skipPath + '\', [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function ExtractSensitivePorts {
    param(
        [string]$NetstatOut
    )

    $acc = ''
    $lines = ([string](Nz $NetstatOut '')).Split("`r`n")
    foreach ($line in $lines) {
        if ($line.Contains('LISTENING')) {
            if (
                $line.Contains(':21') -or $line.Contains(':23') -or $line.Contains(':25') -or $line.Contains(':53') -or
                $line.Contains(':69') -or $line.Contains(':80') -or $line.Contains(':110') -or $line.Contains(':135') -or
                $line.Contains(':139') -or $line.Contains(':143') -or $line.Contains(':445') -or $line.Contains(':1433') -or
                $line.Contains(':1521') -or $line.Contains(':3389') -or $line.Contains(':5900')
            ) {
                $acc = $acc + $line + "`r`n"
            }
        }
    }

    if ($acc.Trim() -eq '') {
        return 'Nenhuma porta sensivel comum detectada em estado LISTENING.'
    }
    return $acc
}

function BuildProcessNameByPidIndex {
    EnsureTelemetryIndexes
    if ($script:ProcessNameByPidIndex.Count -gt 0) { return }

    try {
        $allProc = Get-Process -ErrorAction Stop
    }
    catch {
        $allProc = @()
    }
    foreach ($p in $allProc) {
        $pidKey = [string][long](To-LongSafe $p.Id)
        if ($pidKey -ne '0' -and -not $script:ProcessNameByPidIndex.ContainsKey($pidKey)) {
            $script:ProcessNameByPidIndex[$pidKey] = [string](Nz $p.ProcessName '-')
        }
    }
}

function GetProcessNameFromPidIndex {
    param(
        [string]$PidText
    )

    BuildProcessNameByPidIndex
    $pidKey = [string][long](To-LongSafe $PidText)
    if ($script:ProcessNameByPidIndex.ContainsKey($pidKey)) {
        return [string](Nz $script:ProcessNameByPidIndex[$pidKey] '-')
    }
    return '-'
}

function ExtractEndpointPort {
    param(
        [string]$EndpointText
    )

    $ep = ([string](Nz $EndpointText '')).Trim()
    if ($ep -eq '' -or $ep -eq '*:*') { return '' }

    if ($ep.StartsWith('[')) {
        $ipv6Idx = $ep.LastIndexOf(']:')
        if ($ipv6Idx -ge 0 -and $ipv6Idx + 2 -lt $ep.Length) {
            return $ep.Substring($ipv6Idx + 2)
        }
    }

    $idx = $ep.LastIndexOf(':')
    if ($idx -ge 0 -and $idx + 1 -lt $ep.Length) {
        return $ep.Substring($idx + 1)
    }
    return ''
}

function IsSensitiveTcpPort {
    param(
        [string]$PortText
    )

    $p = ([string](Nz $PortText '')).Trim()
    if ($p -eq '') { return $false }
    switch ($p) {
        '21' { return $true }
        '23' { return $true }
        '25' { return $true }
        '53' { return $true }
        '69' { return $true }
        '80' { return $true }
        '110' { return $true }
        '135' { return $true }
        '139' { return $true }
        '143' { return $true }
        '445' { return $true }
        '1433' { return $true }
        '1521' { return $true }
        '3389' { return $true }
        '5900' { return $true }
        default { return $false }
    }
}

function BuildTcpPortTopologySummary {
    param(
        [string]$NetstatOut,
        [int]$MaxRows
    )

    $maxOut = [int](To-LongSafe $MaxRows)
    if ($maxOut -le 0) { $maxOut = 1200 }

    $totalRows = 0
    $listenRows = 0
    $establishedRows = 0
    $sensitiveRows = 0
    $truncated = $false
    $rowsHtml = ''
    $raw = [string](Nz $NetstatOut '')

    $lines = $raw.Replace("`r`n", "`n").Replace("`r", "`n").Split("`n")
    foreach ($line in $lines) {
        $trim = ([string](Nz $line '')).Trim()
        if ($trim -eq '') { continue }
        if ($trim.StartsWith('Proto', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($trim.StartsWith('Conexoes', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($trim.StartsWith('Active', [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if (-not $trim.StartsWith('TCP ', [System.StringComparison]::OrdinalIgnoreCase)) { continue }

        if ($totalRows -ge $maxOut) {
            $truncated = $true
            break
        }

        $parts = @($trim -split '\s+')
        if ($parts.Count -lt 5) { continue }

        $local = [string](Nz $parts[1] '-')
        $remote = [string](Nz $parts[2] '-')
        $state = [string](Nz $parts[3] '-')
        $pidText = [string](Nz $parts[4] '-')
        $procName = GetProcessNameFromPidIndex -PidText $pidText
        $localPort = ExtractEndpointPort -EndpointText $local
        $sensitive = IsSensitiveTcpPort -PortText $localPort
        if ($state.ToUpperInvariant() -eq 'LISTENING') { $listenRows++ }
        if ($state.ToUpperInvariant() -eq 'ESTABLISHED') { $establishedRows++ }
        if ($sensitive) { $sensitiveRows++ }

        $riskTag = if ($sensitive) { "<span class='tag warn'>Porta sensivel</span>" } else { "<span class='tag ok'>Normal</span>" }
        $rowsHtml += "<tr><td>" + (HtmlEncode $local) + "</td><td>" + (HtmlEncode $remote) + "</td><td>" + (HtmlEncode $state) + "</td><td>" + (HtmlEncode $pidText) + "</td><td>" + (HtmlEncode $procName) + "</td><td>" + $riskTag + "</td></tr>"
        $totalRows++
    }

    return [PSCustomObject]@{
        RowsHtml        = $rowsHtml
        TotalRows       = $totalRows
        ListeningRows   = $listenRows
        EstablishedRows = $establishedRows
        SensitiveRows   = $sensitiveRows
        WasTruncated    = $truncated
    }
}

function GetPrinterDriverVersion {
    param($DriverObj)

    $v = [string](Nz (SafeWmiProp $DriverObj 'DriverVersion' '') '')
    if ($v.Trim() -eq '') { $v = [string](Nz (SafeWmiProp $DriverObj 'Version' '') '') }
    if ($v.Trim() -eq '') {
        $dt = [string](Nz (SafeWmiProp $DriverObj 'DriverDate' '') '')
        if ($dt.Length -ge 14) {
            $v = WmiDateToString $dt
        }
        elseif ($dt.Trim() -ne '') {
            $v = $dt
        }
    }
    if ($v.Trim() -eq '') { $v = '-' }
    return [string]$v
}

function ShareTypeToSigned32 {
    param($Value)

    $d = To-DoubleSafe $Value
    if ($d -gt 2147483647.0) {
        $d = $d - 4294967296.0
    }
    return [int](To-LongSafe $d)
}

function ShareTypeName {
    param($Value)

    $n = [int](To-LongSafe $Value)
    switch ($n) {
        0 { return 'Disco' }
        1 { return 'Fila de Impressao' }
        2 { return 'Dispositivo' }
        3 { return 'IPC' }
        2147483644 { return 'IPC (Admin)' }
        1073741824 { return 'Disco (Temporario)' }
        1073741825 { return 'Impressora (Temporario)' }
        1073741826 { return 'Dispositivo (Temporario)' }
        1073741827 { return 'IPC (Temporario)' }
        -2147483648 { return 'Disco (Admin/Oculto)' }
        -2147483647 { return 'Impressora (Admin/Oculto)' }
        -2147483646 { return 'Dispositivo (Admin/Oculto)' }
        -2147483645 { return 'IPC (Admin/Oculto)' }
        default { return ('Tipo ' + [string]$n) }
    }
}

function FormatShareType {
    param($Value)

    $raw = 0.0
    if (-not [double]::TryParse([string](Nz $Value ''), [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::CurrentCulture, [ref]$raw)) {
        if (-not [double]::TryParse([string](Nz $Value ''), [System.Globalization.NumberStyles]::Any, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$raw)) {
            return [string](Nz $Value '-')
        }
    }

    $signed = ShareTypeToSigned32 $raw
    return (ShareTypeName $signed) + ' (' + [string][Math]::Truncate($raw) + ')'
}

function SanitizeFileNameComponent {
    param(
        [string]$Text
    )

    $t = ([string](Nz $Text '')).Trim()
    if ($t -eq '') { $t = 'arquivo' }
    $bad = @('\', '/', ':', '*', '?', '"', '<', '>', '|')
    foreach ($ch in $bad) {
        $t = $t.Replace($ch, '_')
    }
    $t = $t.Replace(' ', '_')
    while ($t.Contains('__')) { $t = $t.Replace('__', '_') }
    if ($t.Length -gt 90) { $t = $t.Substring(0, 90) }
    if ($t.EndsWith('.')) { $t = $t.Substring(0, $t.Length - 1) }
    if ($t -eq '') { $t = 'arquivo' }
    return $t
}

function GetRunExportBaseDir {
    if ([string](Nz $script:strExportBaseDir '') -ne '') {
        return $script:strExportBaseDir
    }

    $baseDir = Join-Path $PSScriptRoot 'export'
    try {
        if (-not (Test-Path -LiteralPath $baseDir -PathType Container)) {
            New-Item -ItemType Directory -Path $baseDir -Force | Out-Null
        }
    }
    catch {
    }

    $hostRef = [string](Nz $script:strComputer $env:COMPUTERNAME)
    $runRef = [string](Nz $script:strRunId '')
    $folderName = SanitizeFileNameComponent ($hostRef + '_' + $runRef + '_exports')
    $path = Join-Path $baseDir $folderName
    try {
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
    catch {
    }

    $script:strExportBaseDir = $path
    return $script:strExportBaseDir
}

function GetRunExportSubDir {
    param(
        [string]$SubName
    )

    $baseDir = GetRunExportBaseDir
    $folderPath = Join-Path $baseDir (SanitizeFileNameComponent $SubName)
    try {
        if (-not (Test-Path -LiteralPath $folderPath -PathType Container)) {
            New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
        }
    }
    catch {
    }
    return $folderPath
}

function GetFileSizeBytesSafe {
    param(
        [string]$FilePath
    )

    try {
        if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
            return [double](Get-Item -LiteralPath $FilePath -Force -ErrorAction Stop).Length
        }
    }
    catch {
    }
    return 0.0
}

function NormalizeInstallDate {
    param(
        [string]$Value
    )

    $v = [string](Nz $Value '')
    if ($v.Length -eq 8 -and $v -match '^\d{8}$') {
        return $v.Substring(6, 2) + '/' + $v.Substring(4, 2) + '/' + $v.Substring(0, 4)
    }
    return [string](Nz $v '-')
}

function PrefetchProgramNameFromPf {
    param(
        [string]$FileName
    )

    $n = [string](Nz $FileName '')
    if ($n.ToUpperInvariant().EndsWith('.PF')) {
        $n = $n.Substring(0, $n.Length - 3)
    }
    $p = $n.LastIndexOf('-')
    $res = if ($p -gt 0) { $n.Substring(0, $p) } else { $n }
    if ($res.Trim() -eq '') { $res = [string](Nz $FileName '(pf)') }
    return $res
}

function SortDictKeysByValueDesc {
    param(
        [hashtable]$DictObj
    )

    if ($null -eq $DictObj) { return @() }
    return @($DictObj.GetEnumerator() | Sort-Object -Property @{Expression = 'Value'; Descending = $true }, @{Expression = 'Key'; Descending = $false } | ForEach-Object { [string]$_.Key })
}

function AppendFolderChartData {
    param(
        $Label,
        $TotalFiles
    )

    $safe = ([string](Nz $Label '')).Replace("'", "\'")
    if ([string](Nz $script:folderChartLabels '') -ne '') {
        $script:folderChartLabels = $script:folderChartLabels + ','
        $script:folderChartFiles = $script:folderChartFiles + ','
    }
    $script:folderChartLabels = $script:folderChartLabels + "'" + $safe + "'"
    $script:folderChartFiles = $script:folderChartFiles + [string][long](To-LongSafe $TotalFiles)
}

function GetForensicCategory {
    param(
        [string]$FolderPath
    )

    $path = ([string](Nz $FolderPath '')).ToUpperInvariant()
    if ($path.Contains('$RECYCLE.BIN')) { return 'Lixeira' }
    if ($path.Contains('PREFETCH')) { return 'Execucao de Programas' }
    if ($path.Contains('WINEVT\LOGS')) { return 'Logs de Eventos' }
    if ($path.Contains('RECENT') -or $path.Contains('AUTOMATICDE') -or $path.Contains('CUSTOMDE')) { return 'Acesso a Arquivos Recentes' }
    if ($path.Contains('CHROME')) { return 'Navegacao Web (Chrome)' }
    if ($path.Contains('EDGE')) { return 'Navegacao Web (Edge)' }
    if ($path.Contains('FIREFOX')) { return 'Navegacao Web (Firefox)' }
    if ($path.Contains('TEMP')) { return 'Arquivos Temporarios' }
    if ($path.Contains('APPCOMPAT')) { return 'Compatibilidade de Aplicativos' }
    if ($path.Contains('CONFIG')) { return 'Configuracoes do Sistema (Registry hives)' }
    if ($path.Contains('\SRU\')) { return 'System Resource Usage (performance)' }
    if ($path.Contains('TASKS')) { return 'Tarefas Agendadas' }
    if ($path.Contains('STARTUP')) { return 'Inicializacao Automatica' }
    if ($path.Contains('WINDOWS DEFENDER')) { return 'Antivirus/Defender' }
    if ($path.Contains('\LOGS\')) { return 'Logs do Sistema' }
    if ($path.Contains('PROGRAMDATA')) { return 'Dados de Aplicativos' }
    return 'Diversos'
}

function SortStringArrayAsc {
    param(
        [string[]]$Arr
    )

    if ($null -eq $Arr) { return @() }
    if ($Arr.Count -le 1) { return $Arr }
    return @($Arr | Sort-Object)
}

# (AppendUserArtifactTimelineRecord functionality removed as requested)
function AppendUserArtifactTimelineRecordFromDate {
    param($DateValue, [string]$EventKind, [string]$ItemName, [string]$SourcePath)
}

function GetVolumeInfoSummary {
    $colVol = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_LogicalDisk'
    $hasRows = $false
    $out = ''

    if (@($colVol).Count -gt 0) {
        $out = "Origem: WMI (Win32_LogicalDisk)`r`n"
        foreach ($ld in $colVol) {
            $hasRows = $true
            $out = $out + ([string](Nz $ld.DeviceID '-')) + ' | ' + (DriveTypeName $ld.DriveType) + ' | FS=' + ([string](Nz $ld.FileSystem '-')) + ' | Livre=' + (FormatBytes $ld.FreeSpace) + ' | Total=' + (FormatBytes $ld.Size) + ' | Label=' + ([string](Nz $ld.VolumeName '-')) + "`r`n"
        }
    }

    if ($hasRows) {
        return $out.Trim()
    }

    $wmicOut = GetCommandOutput 'cmd /c wmic logicaldisk get DeviceID,DriveType,FileSystem,FreeSpace,Size,VolumeName /format:table'
    if (HasUsefulOutput $wmicOut) {
        return "Origem: WMIC fallback`r`n" + $wmicOut
    }

    return 'N/A (falha em WMI/WMIC para Win32_LogicalDisk)'
}

function GetDefragStatusSummary {
    $s = GetCommandOutput 'cmd /c defrag /C /A /V 2>nul | findstr /I /R "Volume Unidade Fragment Fragmenta Average Total Optimization Otimiza Consolidation Consolida"'
    if (HasUsefulOutput $s) {
        return "Origem: defrag /A /V`r`n" + $s
    }

    $s = GetCommandOutput 'cmd /c wevtutil qe Microsoft-Windows-Defrag/Operational /rd:true /c:5 /f:text'
    if (HasUsefulOutput $s) {
        return "Origem: wevtutil (Microsoft-Windows-Defrag/Operational)`r`n" + $s
    }

    return 'N/A (defrag/wevtutil indisponivel)'
}

function GetStorageOptimizationSummary {
    $parts = ''

    $s = GetCommandOutput 'cmd /c schtasks /Query /TN "\Microsoft\Windows\Defrag\ScheduledDefrag" /V /FO LIST'
    if (HasUsefulOutput $s) {
        $parts = $parts + "[ScheduledDefrag]`r`n" + $s + "`r`n`r`n"
    }

    $s = GetCommandOutput 'cmd /c reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"'
    if (HasUsefulOutput $s) {
        $parts = $parts + "[StorageSense]`r`n" + $s + "`r`n`r`n"
    }

    $s = GetCommandOutput 'cmd /c reg query "HKLM\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" /v Enable'
    if (HasUsefulOutput $s) {
        $parts = $parts + "[BootOptimizeFunction]`r`n" + $s + "`r`n"
    }

    if ($parts.Trim() -eq '') {
        return 'N/A (schtasks/reg query sem retorno util)'
    }
    return $parts.Trim()
}

function ResolveCurrentUserSid {
    $qName = ([string](Nz $script:UserNameText '')).Replace("'", "''")
    $qDomain = [string](Nz $script:UserDomainText '')
    $query = "SELECT Name,Domain,SID FROM Win32_UserAccount WHERE Name='" + $qName + "'"
    $colUsers = Invoke-WmiQueryCompat -QueryText $query

    foreach ($u in $colUsers) {
        if ((To-VbsTrimUpper $u.Name) -eq (To-VbsTrimUpper $script:UserNameText)) {
            if ((To-VbsTrimUpper $u.Domain) -eq (To-VbsTrimUpper $qDomain)) {
                $sidOut = ([string](Nz $u.SID '')).Trim()
                if ($sidOut -ne '') {
                    return $sidOut
                }
            }
        }
    }

    try {
        $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        $sid = ([string](Nz $sid '')).Trim()
        if ($sid.ToUpperInvariant().StartsWith('S-')) {
            return $sid
        }
    }
    catch {
    }

    return ''
}

function EnsureHostIdentityContext {
    if (([string](Nz $script:hostServiceTag '')).Trim() -eq '') {
        $colCsp = Invoke-WmiQueryCompat -QueryText 'SELECT IdentifyingNumber FROM Win32_ComputerSystemProduct'
        foreach ($csp in $colCsp) {
            $script:hostServiceTag = ([string](Nz $csp.IdentifyingNumber '')).Trim()
            if ($script:hostServiceTag -ne '') {
                break
            }
        }
        if (([string](Nz $script:hostServiceTag '')).Trim() -eq '') {
            $script:hostServiceTag = '-'
        }
    }

    if (([string](Nz $script:hostLoggedUserSid '')).Trim() -eq '') {
        $script:hostLoggedUserSid = ResolveCurrentUserSid
        if (([string](Nz $script:hostLoggedUserSid '')).Trim() -eq '') {
            $script:hostLoggedUserSid = '-'
        }
    }
}

function GetLatestHotfixInstalledOnText {
    $colQfe = Invoke-WmiQueryCompat -QueryText 'SELECT InstalledOn, HotFixID FROM Win32_QuickFixEngineering'
    $hasDate = $false
    $bestDt = [datetime]::MinValue

    foreach ($qfe in $colQfe) {
        $rawTxt = ([string](Nz $qfe.InstalledOn '')).Trim()
        if ($rawTxt -ne '') {
            $parsed = [datetime]::MinValue
            if (TryParseQfeInstalledOnDate $rawTxt ([ref]$parsed)) {
                if (-not $hasDate) {
                    $bestDt = $parsed
                    $hasDate = $true
                }
                elseif ($parsed -gt $bestDt) {
                    $bestDt = $parsed
                }
            }
        }
    }

    if ($hasDate) {
        return FormatDateHumanized $bestDt
    }

    return '-'
}

function BuildRunId {
    $dt = Get-Date
    $rndPart = Get-Random -Minimum 0 -Maximum 1000000
    return '{0:yyyyMMdd_HHmmss}_{1:000000}' -f $dt, $rndPart
}

function New-Windows1252NoBomEncoding {
    return [System.Text.Encoding]::GetEncoding(1252)
}

function Open-VbsTextWriter {
    param(
        [string]$Path
    )

    $encoding = New-Windows1252NoBomEncoding
    $dirPath = Split-Path -Parent $Path
    if ([string](Nz $dirPath '').Trim() -ne '' -and -not (Test-Path -LiteralPath $dirPath -PathType Container)) {
        New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
    }
    $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
    $fs = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, $share)
    return New-Object System.IO.StreamWriter($fs, $encoding)
}

function Get-FreeSpaceBytesForPath {
    param(
        [string]$Path
    )

    try {
        $fullPath = [System.IO.Path]::GetFullPath([string](Nz $Path '.'))
        $root = [System.IO.Path]::GetPathRoot($fullPath)
        if ([string](Nz $root '').Trim() -eq '') { return -1 }
        $drive = New-Object System.IO.DriveInfo($root)
        return [int64]$drive.AvailableFreeSpace
    }
    catch {
        return -1
    }
}

function Write-VbsLine {
    param(
        [System.IO.StreamWriter]$Writer,
        [string]$Text
    )

    if ([bool](Nz $script:OutputWriteFailed $false)) {
        return
    }

    if ($null -eq $Text) {
        $Text = ''
    }

    try {
        $Writer.Write($Text)
        $Writer.Write("`r`n")
    }
    catch {
        $script:OutputWriteFailed = $true
        $script:OutputWriteError = $_.Exception.Message
        Write-ProgressLog -Message ('ERROR: falha ao escrever HTML: ' + $_.Exception.Message) -Force
        throw
    }
}

function Write-HeaderHeroBlock {
    param(
        [System.IO.StreamWriter]$Writer,
        [string]$ComputerNameText,
        [string]$DomainText,
        [string]$UserText,
        [string]$StartTimeText
    )

    Write-VbsLine $Writer "<!DOCTYPE html>"
    Write-VbsLine $Writer "<html lang='pt-BR'>"
    Write-VbsLine $Writer "<head>"
    Write-VbsLine $Writer "  <meta charset='windows-1252'>"
    Write-VbsLine $Writer "  <meta name='viewport' content='width=device-width, initial-scale=1'>"
    Write-VbsLine $Writer ("  <title>Relatorio Forense - " + (HtmlEncode $ComputerNameText) + "</title>")
    Write-VbsLine $Writer "  <style>"
    Write-VbsLine $Writer "    :root{--bg:#0f172a;--card:#111827;--muted:#94a3b8;--text:#e2e8f0;--accent:#38bdf8;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;}"
    Write-VbsLine $Writer "    *{box-sizing:border-box} body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:linear-gradient(180deg,#020617,#0f172a);color:var(--text);}"
    Write-VbsLine $Writer "    .wrap{max-width:1320px;margin:0 auto;padding:24px} .hero{background:rgba(17,24,39,.85);border:1px solid #1f2937;padding:20px;border-radius:14px;backdrop-filter:blur(4px)}"
    Write-VbsLine $Writer "    h1,h2,h3{margin:.2rem 0 1rem 0} h1{font-size:clamp(1.4rem,5vw,2.2rem)} h2{font-size:1.2rem;border-left:4px solid var(--accent);padding-left:10px}"
    Write-VbsLine $Writer "    .muted{color:var(--muted);font-size:clamp(0.8rem,2vw,0.95rem)} .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-top:16px}"
    Write-VbsLine $Writer "    .card{background:rgba(17,24,39,.9);border:1px solid #1f2937;border-radius:12px;padding:14px;box-shadow:0 8px 20px rgba(0,0,0,.2)}"
    Write-VbsLine $Writer "    .kpi{font-size:clamp(1.3rem,4vw,1.7rem);font-weight:700} .kpi-text{font-size:clamp(.95rem,2.6vw,1.15rem);line-height:1.25;white-space:normal;overflow-wrap:anywhere;word-break:break-word} .kpi-label{font-size:clamp(0.75rem,2vw,0.85rem);color:var(--muted)}"
    Write-VbsLine $Writer "    table{width:100%;border-collapse:collapse;margin:10px 0;background:#0b1220;border-radius:10px;overflow:hidden;table-layout:auto} th,td{padding:clamp(6px,2vw,8px);border-bottom:1px solid #1f2937;vertical-align:top;word-wrap:break-word;word-break:break-word} th{background:#111827;color:#93c5fd;text-align:left;font-size:clamp(0.8rem,2vw,0.95rem)}"
    Write-VbsLine $Writer "    tr:hover td{background:#0f1a2e} .tag{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.75rem} .ok{background:rgba(34,197,94,.2);color:#86efac}.warn{background:rgba(245,158,11,.2);color:#fcd34d}.bad{background:rgba(239,68,68,.2);color:#fca5a5}"
    Write-VbsLine $Writer "    .bar{height:8px;background:#1f2937;border-radius:999px;overflow:hidden}.bar > span{display:block;height:100%;background:linear-gradient(90deg,#06b6d4,#3b82f6)}"
    Write-VbsLine $Writer "    .toc{display:flex;flex-wrap:wrap;gap:clamp(8px,2vw,10px);margin-top:16px} .toc a{color:#7dd3fc;text-decoration:none;font-size:clamp(0.7rem,1.8vw,0.9rem);line-height:1.4;padding:clamp(4px,1vw,6px) clamp(8px,2vw,10px);background:rgba(56,189,248,.1);border-radius:6px;display:inline-block;white-space:nowrap;transition:all .2s ease}.toc a:hover{text-decoration:underline;background:rgba(56,189,248,.2);transform:translateY(-2px)}"
    Write-VbsLine $Writer "    .location-col{white-space:normal;word-break:break-word}"
    Write-VbsLine $Writer "    .filter-container{margin:10px 0;padding:12px;background:rgba(30,41,59,.5);border-radius:8px;border:1px solid #1f2937;display:flex;align-items:center;gap:8px;flex-wrap:wrap}.filter-input{padding:8px 12px;background:#0b1220;border:1px solid #1f2937;border-radius:6px;color:#e2e8f0;font-size:0.9rem;width:100%;max-width:400px;transition:all .2s;flex:1 1 280px}.filter-input:focus{outline:none;border-color:#38bdf8;box-shadow:0 0 8px rgba(56,189,248,.3)}.table-export-btn{padding:8px 12px;border:1px solid #2563eb;border-radius:6px;background:#1d4ed8;color:#eff6ff;cursor:pointer;font-size:.85rem}.table-export-btn:hover{background:#2563eb}"
    Write-VbsLine $Writer "    .scroll-to-top{position:fixed;bottom:30px;right:30px;width:50px;height:50px;background:#38bdf8;color:#0f172a;border:none;border-radius:50%;font-size:24px;cursor:pointer;display:none;align-items:center;justify-content:center;box-shadow:0 4px 12px rgba(56,189,248,.4);z-index:999;transition:all .3s;font-weight:bold}.scroll-to-top:hover{background:#0ea5e9;transform:translateY(-3px);box-shadow:0 6px 16px rgba(56,189,248,.6)}.scroll-to-top.show{display:flex}"
    Write-VbsLine $Writer "    .fab-nav{position:fixed;left:22px;bottom:22px;z-index:1000}"
    Write-VbsLine $Writer "    .fab-main{width:54px;height:54px;border:none;border-radius:50%;background:linear-gradient(135deg,#22d3ee,#3b82f6);color:#03111f;font-weight:700;font-size:22px;cursor:pointer;box-shadow:0 10px 22px rgba(0,0,0,.35)}"
    Write-VbsLine $Writer "    .fab-main:hover{transform:translateY(-2px)}"
    Write-VbsLine $Writer "    .fab-menu{display:none;position:absolute;left:0;bottom:66px;min-width:280px;max-width:min(92vw,420px);max-height:70vh;overflow:auto;padding:10px;border-radius:12px;background:rgba(2,6,23,.96);border:1px solid #1f2937;box-shadow:0 12px 28px rgba(0,0,0,.45)}"
    Write-VbsLine $Writer "    .fab-menu.show{display:block}"
    Write-VbsLine $Writer "    .fab-menu .fab-title{font-size:.78rem;color:#93c5fd;margin:0 0 8px 0;padding-bottom:6px;border-bottom:1px solid #1f2937}"
    Write-VbsLine $Writer "    .fab-menu a{display:block;color:#e2e8f0;text-decoration:none;padding:7px 9px;border-radius:8px;font-size:.85rem}"
    Write-VbsLine $Writer "    .fab-menu a:hover{background:rgba(56,189,248,.12);color:#7dd3fc}"
    Write-VbsLine $Writer "    .fab-group{border:1px solid rgba(31,41,55,.7);border-radius:10px;background:rgba(15,23,42,.35);margin:7px 0;overflow:hidden}"
    Write-VbsLine $Writer "    .fab-group summary{cursor:pointer;list-style:none;padding:8px 10px;color:#bae6fd;font-size:.82rem;font-weight:700;display:flex;align-items:center;gap:8px}"
    Write-VbsLine $Writer "    .fab-group summary::-webkit-details-marker{display:none}"
    Write-VbsLine $Writer "    .fab-group summary::before{content:'+';width:16px;height:16px;display:inline-flex;align-items:center;justify-content:center;border-radius:999px;background:rgba(56,189,248,.1);color:#7dd3fc;font-weight:700;font-size:.8rem}"
    Write-VbsLine $Writer "    .fab-group[open] summary::before{content:'-'}"
    Write-VbsLine $Writer "    .fab-group .fab-submenu{padding:0 6px 6px 6px;border-top:1px solid rgba(31,41,55,.6)}"
    Write-VbsLine $Writer "    .fab-group .fab-submenu a{font-size:.8rem;padding:6px 8px;margin-top:4px;color:#cbd5e1}"
    Write-VbsLine $Writer "    .fab-link-main{font-weight:600}"
    Write-VbsLine $Writer "    .split-2{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,1fr);gap:14px;align-items:start}"
    Write-VbsLine $Writer "    .split-panel{background:rgba(15,23,42,.45);border:1px solid #1f2937;border-radius:12px;padding:12px;min-height:100%;overflow:hidden}.split-panel h3{margin-top:.2rem}.split-panel table{table-layout:auto}.split-panel .scroll-table{margin-top:6px}"
    Write-VbsLine $Writer "    .mini-note{color:#94a3b8;font-size:.8rem;margin:.2rem 0 .8rem 0}"
    Write-VbsLine $Writer "    details.collapsible-card{padding:0;overflow:hidden} details.collapsible-card[open]{padding:14px} details.collapsible-card summary{list-style:none;cursor:pointer;padding:14px 16px;font-weight:700;color:#e2e8f0;display:flex;align-items:center;gap:10px;background:linear-gradient(180deg,rgba(30,41,59,.45),rgba(15,23,42,.3));border-bottom:1px solid rgba(31,41,55,.8)} details.collapsible-card[open] summary{margin:-14px -14px 12px -14px} details.collapsible-card summary::-webkit-details-marker{display:none} details.collapsible-card summary::before{content:'+';display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:rgba(56,189,248,.12);color:#7dd3fc;font-weight:700;flex:0 0 22px} details.collapsible-card[open] summary::before{content:'-'} details.collapsible-card .collapsible-sub{color:#94a3b8;font-size:.78rem;font-weight:400;margin-left:auto;padding-left:8px}"
    Write-VbsLine $Writer "    details.sub-collapsible{margin:10px 0 0 0;border:1px solid rgba(31,41,55,.75);border-radius:10px;background:rgba(2,6,23,.22);overflow:hidden} details.sub-collapsible[open]{padding:10px} details.sub-collapsible > summary{list-style:none;cursor:pointer;padding:10px 12px;color:#cbd5e1;font-weight:600;font-size:.92rem;background:rgba(15,23,42,.45);border-bottom:1px solid rgba(31,41,55,.7)} details.sub-collapsible > summary::-webkit-details-marker{display:none} details.sub-collapsible > summary::before{content:'+';display:inline-block;width:16px;text-align:center;margin-right:8px;color:#7dd3fc} details.sub-collapsible[open] > summary::before{content:'-'} details.sub-collapsible[open] > summary{margin:-10px -10px 10px -10px}"
    Write-VbsLine $Writer "    @media(max-width:1120px){.split-2{grid-template-columns:1fr}.split-panel{padding:10px}}"
    Write-VbsLine $Writer "    footer{margin-top:40px;padding:24px;background:rgba(17,24,39,.9);border:1px solid #1f2937;border-radius:14px;color:var(--muted);font-size:0.85rem;text-align:center;line-height:1.6} footer strong{color:var(--text)} footer a{color:var(--accent);text-decoration:none} footer a:hover{text-decoration:underline} pre{white-space:pre-wrap;word-break:break-word;font-size:clamp(0.7rem,1.5vw,0.85rem)} .snap-pre{white-space:pre;word-break:normal;overflow:auto;display:block} .scroll-table{overflow-x:auto;border-radius:10px;-webkit-overflow-scrolling:touch} .scroll-table table{margin:10px 0;min-width:100%;width:auto} .scroll-table th,.scroll-table td{white-space:nowrap} .snap-no-wrap table{min-width:1100px} .snap-no-wrap pre{white-space:pre;word-break:normal;overflow:auto;max-width:none} @media(max-width:768px){.wrap{padding:16px} h1{font-size:clamp(1.3rem,5vw,1.8rem)} h2{font-size:clamp(1rem,3vw,1.2rem)} .hero{padding:16px} table{font-size:clamp(0.75rem,2vw,0.9rem)} th,td{padding:clamp(4px,1.5vw,6px)} .grid{grid-template-columns:1fr}} @media(max-width:480px){.wrap{padding:12px} .hero{padding:12px} .toc{gap:6px} .toc a{font-size:0.7rem;padding:4px 8px} h2{border-left-width:3px}.scroll-to-top{bottom:20px;right:20px;width:45px;height:45px;font-size:20px}}"
    Write-VbsLine $Writer "  </style>"
    Write-VbsLine $Writer "  <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>"
    Write-VbsLine $Writer "</head><body><main class='wrap'>"
    Write-VbsLine $Writer "  <div class='fab-nav' id='quickNav'>"
    Write-VbsLine $Writer "    <button class='fab-main' id='quickNavBtn' title='Menu rapido de links' aria-label='Menu rapido de links' aria-expanded='false'>+</button>"
    Write-VbsLine $Writer "    <div class='fab-menu' id='quickNavMenu'>"
    Write-VbsLine $Writer "      <div class='fab-title'>Navegacao rapida</div>"
    Write-VbsLine $Writer "      <div id='quickNavDynamic'><a href='#sumario' class='fab-link-main'>Sumario</a></div>"
    Write-VbsLine $Writer "    </div>"
    Write-VbsLine $Writer "  </div>"
    Write-VbsLine $Writer "  <button class='scroll-to-top' id='scrollTopBtn' title='Ir para o topo'>&#8593;</button>"
    Write-VbsLine $Writer "  <section class='hero'>"
    Write-VbsLine $Writer "    <h1>Relatorio de Telemetria Forense</h1>"
    Write-VbsLine $Writer ("    <p class='muted'>Host: <strong>" + (HtmlEncode $ComputerNameText) + "</strong> | Usurio da coleta: <strong>" + (HtmlEncode ($DomainText + "\" + $UserText)) + "</strong> | Inicio da geracao: <strong>" + (HtmlEncode $StartTimeText) + "</strong></p>")
    Write-VbsLine $Writer "    <nav class='toc'>"
    Write-VbsLine $Writer "      <a href='#sumario'>Sumario</a><a href='#hardware'>Hardware</a><a href='#discos'>Volumes/Discos</a><a href='#usb'>Dispositivos Externos</a><a href='#so'>Sistema</a><a href='#identidade'>Usuarios/Contas</a><a href='#pastas'>Pastas Usuario</a><a href='#shares'>Impressao</a><a href='#artefatos'>Artefatos</a><a href='#controladores'>Controladores/Backup</a><a href='#rede'>Rede</a><a href='#redeplus'>Topologia/Portas</a><a href='#cis'>CIS/Hardening</a><a href='#seguranca'>Eventos</a><a href='#ameacas'>Deteccao</a><a href='#servicos'>Servicos</a><a href='#execucao'>Execucao de Software</a><a href='#apps'>Softwares/Persistencia</a>"
    Write-VbsLine $Writer "    </nav>"
    Write-VbsLine $Writer "  </section>"
}

function WriteSummaryDashboardSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $procCount = 0
    $svcCount = 0
    $evtCount = 0
    $errorCount = 0
    $totalCPUs = 0
    $ramGbText = '-'
    $osInstallText = '-'
    $osUpdateText = '-'
    $extDriveRegisteredSummaryCount = 0

    EnsureHostIdentityContext

    Write-VbsLine $Writer "<section id='sumario' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Sumario Executivo</h2>"

    $colOS = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_OperatingSystem'
    $colCS = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_ComputerSystem'
    $colCPU = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_Processor'
    $colProc = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_Process'
    $colSvc = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_Service'
    $colExtDrive = Invoke-WmiQueryCompat -QueryText "SELECT * FROM Win32_PnPEntity WHERE PNPClass='DiskDrive' OR PNPClass='USB' OR (PNPDeviceID LIKE 'USBSTOR%' OR PNPDeviceID LIKE 'USB\\%')"
    $evtCount = 0
    $errorCount = 0

    foreach ($cpu in $colCPU) {
        $totalCPUs = $totalCPUs + 1
    }
    foreach ($proc in $colProc) {
        $procCount = $procCount + 1
    }
    if ((To-LongSafe $script:SummaryProcCountOverride) -ge 0) {
        $procCount = [int](To-LongSafe $script:SummaryProcCountOverride)
    }
    foreach ($svc in $colSvc) {
        $script:serviceTotalCount = [long](To-LongSafe $script:serviceTotalCount) + 1
        $svcCount = $svcCount + 1
    }
    foreach ($extDrive in $colExtDrive) {
        if (([string](Nz $extDrive.PNPDeviceID '')).ToUpperInvariant().Contains('USB')) {
            $extDriveRegisteredSummaryCount = $extDriveRegisteredSummaryCount + 1
        }
    }
    Write-VbsLine $Writer "<div class='grid'>"

    foreach ($os in $colOS) {
        $totalVisibleMemorySize = To-DoubleSafe $os.TotalVisibleMemorySize
        if ($totalVisibleMemorySize -gt 0) {
            $ramVal = [math]::Truncate((($totalVisibleMemorySize * 1024.0) / 1073741824.0) * 10.0) / 10.0
            $ramGbText = (To-VbsString $ramVal) + ' GB'
        }
        $osInstallText = WmiDateToString $os.InstallDate
        $tmpDt = [datetime]::MinValue
        if (TryParseWmiDateValue $os.InstallDate ([ref]$tmpDt)) {
            $osInstallText = FormatDateTimeHumanized $tmpDt
        }
        $osUpdateText = GetLatestHotfixInstalledOnText
        Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + (HtmlEncode ([string](Nz $os.Caption '-'))) + "</div><div class='kpi-label'>Sistema Operacional</div></div>")
        Write-VbsLine $Writer ("<div class='card'><div class='kpi kpi-text'>" + (HtmlEncode $osInstallText) + "</div><div class='kpi-label'>Instalacao do SO</div></div>")
        Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + (HtmlEncode $ramGbText) + "</div><div class='kpi-label'>RAM Total (GB)</div></div>")
    }

    foreach ($cs in $colCS) {
        $script:hostManufacturerName = [string](Nz $cs.Manufacturer '-')
        $script:hostModelName = [string](Nz $cs.Model '-')
        $script:hostCpuLogicalCount = [long](To-LongSafe $cs.NumberOfLogicalProcessors)
        $script:hostRamTotalBytes = [double](To-DoubleSafe $cs.TotalPhysicalMemory)
        Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + (HtmlEncode ([string](Nz $cs.Manufacturer '-'))) + "</div><div class='kpi-label'>Fabricante</div></div>")
        Write-VbsLine $Writer ("<div class='card'><div class='kpi kpi-text'>" + (HtmlEncode ([string](Nz $cs.Model '-'))) + "</div><div class='kpi-label'>Modelo</div></div>")
    }

    Write-VbsLine $Writer ("<div class='card'><div class='kpi kpi-text'>" + (HtmlEncode $osUpdateText) + "</div><div class='kpi-label'>Atualizacao do SO</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + $procCount + "</div><div class='kpi-label'>Processos ativos</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + $svcCount + "</div><div class='kpi-label'>Servicos totais</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi kpi-text'>" + (HtmlEncode ([string](Nz $script:hostLoggedUserSid '-'))) + "</div><div class='kpi-label'>SID usuario logado</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi kpi-text'>" + (HtmlEncode ([string](Nz $script:hostServiceTag '-'))) + "</div><div class='kpi-label'>Service Tag</div></div>")

    Write-VbsLine $Writer "</div>"
    Write-VbsLine $Writer "</section>"
}

function WriteHardwareSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $totalRAM = 0.0
    $slotCount = 0
    $script:hostBatteryCount = 0

    Write-VbsLine $Writer "<section id='hardware' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Hardware</h2>"

    $colCS = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_ComputerSystem'
    foreach ($cs in $colCS) {
        $script:hostManufacturerName = [string](Nz $cs.Manufacturer '-')
        $script:hostModelName = [string](Nz $cs.Model '-')
        $script:hostCpuLogicalCount = [long](To-LongSafe $cs.NumberOfLogicalProcessors)
        $script:hostRamTotalBytes = [double](To-DoubleSafe $cs.TotalPhysicalMemory)
        Write-VbsLine $Writer "<table><tr><th>Campo</th><th>Valor</th></tr>"
        WriteKV 'Fabricante' $cs.Manufacturer
        WriteKV 'Modelo' $cs.Model
        WriteKV 'Familia' $cs.SystemFamily
        WriteKV 'SKU' $cs.SystemSKUNumber
        WriteKV 'Tipo do sistema' $cs.SystemType
        WriteKV 'Dominio' $cs.Domain
        WriteKV 'Funcao no dominio' $cs.DomainRole
        WriteKV 'Usuario logado' $cs.UserName
        WriteKV 'Numero processadores fisicos' $cs.NumberOfProcessors
        WriteKV 'Numero processadores logicos' $cs.NumberOfLogicalProcessors
        WriteKV 'RAM total reportada' (FormatBytes $cs.TotalPhysicalMemory)
        Write-VbsLine $Writer "</table>"
    }

    $colCSP = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_ComputerSystemProduct'
    foreach ($csp in $colCSP) {
        Write-VbsLine $Writer "<table><tr><th colspan='2'>Produto e Service Tag</th></tr>"
        WriteKV 'Nome do Produto' $csp.Name
        WriteKV 'Versao' $csp.Version
        WriteKV 'Service Tag / Serial' $csp.IdentifyingNumber
        WriteKV 'SKU (Produto)' $csp.SKUNumber
        Write-VbsLine $Writer "</table>"
    }

    $colBIOS = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_BIOS'
    foreach ($bios in $colBIOS) {
        Write-VbsLine $Writer "<table><tr><th colspan='2'>BIOS</th></tr>"
        WriteKV 'Fabricante' $bios.Manufacturer
        WriteKV 'Versao SMBIOS' $bios.SMBIOSBIOSVersion
        WriteKV 'Versao' $bios.Version
        WriteKV 'Numero de serie' $bios.SerialNumber
        WriteKV 'Data de release' (WmiDateToString $bios.ReleaseDate)
        Write-VbsLine $Writer "</table>"
    }

    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>CPU</th><th>Detalhes</th></tr>"
    $colCPU = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_Processor'
    foreach ($cpu in $colCPU) {
        $cpuRow = "<tr><td>" + (HtmlEncode ([string]$cpu.DeviceID)) + "</td><td class='location-col'>" + (HtmlEncode ([string]$cpu.Name)) + "<br>Fabricante: " + (HtmlEncode ([string]$cpu.Manufacturer)) + "<br>Nucleos: " + ([string](Nz $cpu.NumberOfCores '-')) + " | Logicos: " + ([string](Nz $cpu.NumberOfLogicalProcessors '-')) + "<br>Clock: " + ([string](Nz $cpu.MaxClockSpeed '-')) + " MHz | Arquitetura: " + (CpuArch $cpu.Architecture) + "<br>L2: " + (FormatBytes ((To-DoubleSafe $cpu.L2CacheSize) * 1024)) + " | L3: " + (FormatBytes ((To-DoubleSafe $cpu.L3CacheSize) * 1024)) + "</td></tr>"
        Write-VbsLine $Writer $cpuRow
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Slot</th><th>Capacidade</th><th>Velocidade</th><th>Tipo</th><th>Fabricante</th><th class='location-col'>Part Number</th><th class='location-col'>Serial</th></tr>"
    $colRAM = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_PhysicalMemory'
    foreach ($ram in $colRAM) {
        $slotCount = $slotCount + 1
        $totalRAM = $totalRAM + (To-DoubleSafe $ram.Capacity)
        $ramRow = "<tr><td>" + (HtmlEncode ([string](Nz $ram.DeviceLocator 'N/A'))) + "</td><td>" + (FormatBytes $ram.Capacity) + "</td><td>" + ([string](Nz $ram.Speed '-')) + " MHz</td><td>" + (MemoryTypeName $ram.MemoryType) + "</td><td>" + (HtmlEncode ([string](Nz $ram.Manufacturer '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz $ram.PartNumber '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz $ram.SerialNumber '-'))) + "</td></tr>"
        Write-VbsLine $Writer $ramRow
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<div class='grid'>"
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + $slotCount + "</div><div class='kpi-label'>Modulos RAM detectados</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + (FormatBytes $totalRAM) + "</div><div class='kpi-label'>Capacidade RAM instalada</div></div>")
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<h3>Bateria</h3>"
    Write-VbsLine $Writer "<table><tr><th>Nome</th><th>Status</th><th>Carga estimada</th><th>Quimica</th></tr>"
    $batteryRows = 0
    $colBatt = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_Battery'
    foreach ($batt in $colBatt) {
        $script:hostBatteryCount = [int](To-LongSafe $script:hostBatteryCount) + 1
        $batteryRows = $batteryRows + 1
        $chargeValue = SafeWmiProp $batt 'EstimatedChargeRemaining' '-'
        if ((To-LongSafe $script:BatteryEstimatedChargeOverride) -ge 0) {
            $chargeValue = $script:BatteryEstimatedChargeOverride
        }
        $bRow = "<tr><td>" + (HtmlEncode ([string](SafeWmiProp $batt 'Name' 'Bateria'))) + "</td><td>" + (HtmlEncode (BatteryStatusName (SafeWmiProp $batt 'BatteryStatus' '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $chargeValue '-'))) + "%</td><td>" + (HtmlEncode (BatteryChemistryName (SafeWmiProp $batt 'Chemistry' '-'))) + "</td></tr>"
        Write-VbsLine $Writer $bRow
    }
    if ($batteryRows -eq 0) {
        Write-VbsLine $Writer "<tr><td colspan='4'>Nenhuma bateria detectada via WMI (desktop/VM ou driver indisponivel).</td></tr>"
    }
    Write-VbsLine $Writer "</table>"

    if ((To-LongSafe $script:hostBatteryCount) -gt 0) {
        $script:hostAssetType = 'Laptop / Portatil'
    }
    elseif (([string](Nz $script:hostModelName '')).ToUpperInvariant().Contains('VIRTUAL') -or ([string](Nz $script:hostModelName '')).ToUpperInvariant().Contains('VMWARE') -or ([string](Nz $script:hostModelName '')).ToUpperInvariant().Contains('VBOX')) {
        $script:hostAssetType = 'VM / virtual'
    }
    else {
        $script:hostAssetType = 'Desktop/Workstation (sem bateria detectada)'
    }

    Write-VbsLine $Writer "</section>"
}

function WritePhysicalDiskMediaTypeSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $colPD = @()
    try {
        if (Get-Command -Name Get-WmiObject -ErrorAction SilentlyContinue) {
            $colPD = @(Get-WmiObject -Namespace 'root\Microsoft\Windows\Storage' -Class 'MSFT_PhysicalDisk' -ErrorAction Stop)
        }
        elseif (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
            $colPD = @(Get-CimInstance -Namespace 'root\Microsoft\Windows\Storage' -ClassName 'MSFT_PhysicalDisk' -ErrorAction Stop)
        }
    }
    catch {
        $colPD = @()
    }

    if (@($colPD).Count -gt 0) {
        Write-VbsLine $Writer "<table><tr><th>Nome amigavel</th><th>Tipo de barramento</th><th>Tipo de midia</th><th>Status de Saude</th><th>Tamanho</th><th>Serial</th></tr>"
        foreach ($p in $colPD) {
            $row = "<tr><td>" + (HtmlEncode ([string](Nz $p.FriendlyName '-'))) + "</td><td>" + (HtmlEncode (BusTypeName $p.BusType)) + "</td><td>" + (HtmlEncode (MediaTypeName $p.MediaType)) + "</td><td>" + (HtmlEncode ([string](Nz $p.HealthStatus '-'))) + "</td><td>" + (FormatBytes $p.Size) + "</td><td>" + (HtmlEncode ([string](Nz $p.SerialNumber '-'))) + "</td></tr>"
            Write-VbsLine $Writer $row
        }
        Write-VbsLine $Writer "</table>"
    }
}

function WriteDiskSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $totalDisks = 0
    $script:diskChartLabels = ''
    $script:diskChartUsed = ''
    $script:diskChartFree = ''
    $script:removableCount = 0
    $script:fixedCount = 0
    $script:CurrentTotalSpaceBytes = 0.0
    $script:CurrentFreeSpaceBytes = 0.0

    Write-VbsLine $Writer "<section id='discos' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Volumes</h2>"

    Write-VbsLine $Writer "<table><tr><th>Volume</th><th>Tipo</th><th>Sistema de Arquivos</th><th>Tamanho</th><th>Livre</th><th>Uso</th><th>Serial</th></tr>"
    $colLogical = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_LogicalDisk'
    foreach ($ld in $colLogical) {
        $totalB = To-DoubleSafe $ld.Size
        $freeB = To-DoubleSafe $ld.FreeSpace
        $usedB = $totalB - $freeB
        if ($totalB -gt 0) {
            $usagePct = [math]::Truncate(($usedB / $totalB) * 100.0)
            $usageBar = "<div class='bar'><span style='width:" + $usagePct + "%'></span></div> " + $usagePct + "%"
        }
        else {
            $usageBar = '-'
        }

        $driveKind = DriveTypeName $ld.DriveType
        if ([int](To-LongSafe $ld.DriveType) -eq 2) { 
            $script:removableCount = [int](To-LongSafe $script:removableCount) + 1 
            $driveKind = "<strong>$driveKind (EXTERNO)</strong>"
        }
        if ([int](To-LongSafe $ld.DriveType) -eq 3) { 
            $script:fixedCount = [int](To-LongSafe $script:fixedCount) + 1 
            $script:CurrentTotalSpaceBytes += $totalB
            $script:CurrentFreeSpaceBytes += $freeB
        }

        if ([int](To-LongSafe $ld.DriveType) -eq 3 -and $totalB -gt 0) {
            AppendChartData (Nz $ld.DeviceID 'SemID') ($usedB / 1024.0 / 1024.0 / 1024.0) ($freeB / 1024.0 / 1024.0 / 1024.0)
        }

        $row = "<tr><td>" + (HtmlEncode ([string](Nz $ld.DeviceID '-'))) + "</td><td>" + (HtmlEncode $driveKind) + "</td><td>" + (HtmlEncode ([string](Nz $ld.FileSystem '-'))) + "</td><td>" + (FormatBytes $ld.Size) + "</td><td>" + (FormatBytes $ld.FreeSpace) + "</td><td>" + $usageBar + "</td><td>" + (HtmlEncode ([string](Nz $ld.VolumeSerialNumber '-'))) + "</td></tr>"
        Write-VbsLine $Writer $row
    }
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<table><tr><th>Disco</th><th>Modelo</th><th>Interface</th><th>Media</th><th>Tipo (HDD/SSD?)</th><th>Tamanho</th><th>Particoes</th><th>Serial/PnP</th></tr>"
    $colPhysical = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_DiskDrive'
    foreach ($pd in $colPhysical) {
        $totalDisks = $totalDisks + 1
        $row = "<tr><td>" + (HtmlEncode ([string](Nz $pd.DeviceID '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $pd.Model '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $pd.InterfaceType '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $pd.MediaType '-'))) + "</td><td>" + (HtmlEncode (InferDiskType $pd.Model $pd.MediaType)) + "</td><td>" + (FormatBytes $pd.Size) + "</td><td>" + ([string](Nz $pd.Partitions '-')) + "</td><td>" + (HtmlEncode ([string](Nz $pd.SerialNumber (Nz $pd.PNPDeviceID '-')))) + "</td></tr>"
        Write-VbsLine $Writer $row
    }
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<table><tr><th colspan='2'>Otimizacao de Disco / TRIM</th></tr>"
    $trimInfo = if ([string](Nz $script:TrimInfoOverride '') -ne '') { $script:TrimInfoOverride } else { GetCommandOutput 'cmd /c fsutil behavior query DisableDeleteNotify' }
    WriteKVHtml 'TRIM (fsutil)' (HtmlPre $trimInfo)

    $trimStatus = if ([string](Nz $script:VolumeInfoOverride '') -ne '') { $script:VolumeInfoOverride } else { GetVolumeInfoSummary }
    WriteKVHtml 'Informacoes de Volume (WMI/CIM)' (HtmlPre $trimStatus)

    $defragInfo = if ([string](Nz $script:DefragInfoOverride '') -ne '') { $script:DefragInfoOverride } else { GetDefragStatusSummary }
    WriteKVHtml 'Status Defragmentacao' (HtmlPre $defragInfo)

    $storageOptInfo = if ([string](Nz $script:StorageOptInfoOverride '') -ne '') { $script:StorageOptInfoOverride } else { GetStorageOptimizationSummary }
    WriteKVHtml 'Otimizacoes de Armazenamento' (HtmlPre $storageOptInfo)
    Write-VbsLine $Writer "</table>"

    $ntfsInfo = GetCommandOutputWithTimeout 'cmd /c fsutil fsinfo ntfsinfo C:' 30
    $bcdEdit = GetCommandOutputWithTimeout 'cmd /c bcdedit /enum' 30
    $biosVer = GetCommandOutputWithTimeout 'cmd /c wmic bios get serialnumber,smbiosbiosversion,manufacturer' 30

    Write-VbsLine $Writer "<h3>Reconhecimento de Boot e NTFS</h3>"
    Write-VbsLine $Writer "<table>"
    Write-VbsLine $Writer ("<tr><th>NTFS Info (Volume C:)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $ntfsInfo ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><th>BCDEdit (Menu de Boot)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $bcdEdit ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><th>WMIC BIOS</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $biosVer ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer "</table>"

    WritePhysicalDiskMediaTypeSection -Writer $Writer

    Write-VbsLine $Writer "<div class='grid'>"
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + $totalDisks + "</div><div class='kpi-label'>Discos fisicos detectados</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + [int](To-LongSafe $script:fixedCount) + "</div><div class='kpi-label'>Volumes fixos</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + [int](To-LongSafe $script:removableCount) + "</div><div class='kpi-label'>Volumes removiveis</div></div>")
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<canvas id='diskChart' height='110'></canvas>"
    Write-VbsLine $Writer "<script>"
    Write-VbsLine $Writer ("const diskLabels=[" + [string](Nz $script:diskChartLabels '') + "];")
    Write-VbsLine $Writer ("const diskUsed=[" + [string](Nz $script:diskChartUsed '') + "];")
    Write-VbsLine $Writer ("const diskFree=[" + [string](Nz $script:diskChartFree '') + "];")
    Write-VbsLine $Writer "if(diskLabels.length){new Chart(document.getElementById('diskChart'),{type:'bar',data:{labels:diskLabels,datasets:[{label:'Usado (GB)',data:diskUsed,backgroundColor:'#ef4444'},{label:'Livre (GB)',data:diskFree,backgroundColor:'#22c55e'}]},options:{responsive:true,plugins:{legend:{labels:{color:'#e2e8f0'}}},scales:{x:{ticks:{color:'#cbd5e1'}},y:{ticks:{color:'#cbd5e1'}}}}});}"
    Write-VbsLine $Writer "</script>"

    Write-VbsLine $Writer "</section>"
}

function WriteExternalDrivesDetailed {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $script:externalDriveRegisteredCount = 0

    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Unidade</th><th>Tipo</th><th>Fabricante</th><th>Modelo</th><th>Marca (VID)</th><th>PID</th><th>Serial/Service Tag</th><th>Ultima conexao</th><th class='location-col'>PNPDeviceID</th></tr>"

    $colDrives = Invoke-WmiQueryCompat -QueryText "SELECT * FROM Win32_PnPEntity WHERE PNPClass='DiskDrive' OR PNPClass='USB' OR (PNPDeviceID LIKE 'USBSTOR%' OR PNPDeviceID LIKE 'USB\\%')"
    foreach ($drive in $colDrives) {
        $pnpDeviceId = [string](Nz (SafeWmiProp $drive 'PNPDeviceID' '') '')
        $vid = ParseBetween (([string](Nz $pnpDeviceId '')).ToUpperInvariant()) 'VID_' '&'
        $pidValue = ParseBetween (([string](Nz $pnpDeviceId '')).ToUpperInvariant()) 'PID_' '&'
        $serialNum = ParsePnPSerial $pnpDeviceId
        $manufacturer = [string](Nz (SafeWmiProp $drive 'Manufacturer' '') '-')
        $model = [string](Nz (SafeWmiProp $drive 'Description' '') '') + ' ' + [string](Nz (SafeWmiProp $drive 'Name' '') '')
        $driveType = InferExternalDriveType ([string](Nz (SafeWmiProp $drive 'Name' '') '') + ' ' + [string](Nz (SafeWmiProp $drive 'Description' '') ''))
        $lastConnection = '-'

        $isExternal = $false
        if ($pnpDeviceId.IndexOf('USB', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $isExternal = $true }
        elseif ($driveType -match 'Externo|Pendrive|Removivel') { $isExternal = $true }
        elseif ($model -match 'USB|External|Portable|SD Card|Flash') { $isExternal = $true }

        if ($isExternal) {
            if ($driveType -ne 'HDD Externo') { continue }
            $script:externalDriveRegisteredCount = [int](To-LongSafe $script:externalDriveRegisteredCount) + 1
            $row = "<tr><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $drive 'Name' '') '-'))) + "</td><td>" + (HtmlEncode $driveType) + "</td><td>" + (HtmlEncode $manufacturer) + "</td><td>" + (HtmlEncode $model) + "</td><td>" + (HtmlEncode ([string](Nz $vid '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $pidValue '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $serialNum '-'))) + "</td><td>" + $lastConnection + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz $pnpDeviceId '-'))) + "</td></tr>"
            Write-VbsLine $Writer $row
        }
    }

    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    $usbStorageInfo = GetCommandOutput 'cmd /c Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=2" 2>nul | Select-Object DeviceID, VolumeName, Size, FreeSpace 2>nul | Out-String 2>nul || echo N/A'
    Write-VbsLine $Writer "<div class='card' style='margin-top:16px;background:rgba(240,249,255,0.4);border:1px solid #bae6fd;padding:12px'><div class='label' style='font-weight:700;color:#0369a1'>Informacoes de Drives Removiveis (tipo=2)</div><div class='value' style='white-space:pre-wrap;font-family:monospace;font-size:0.8rem;margin-top:8px'>" + (HtmlEncode $usbStorageInfo) + "</div></div>"
}

function WriteUSBSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $countUSB = 0
    $usbRows = ''

    Write-VbsLine $Writer "<section id='usb' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Drives Externos (PnP)</h2>"
    Write-VbsLine $Writer "<h3>Celulares</h3>"
    Write-VbsLine $Writer "<div class='mini-note'>Dispositivos moveis (smartphones/tablets) anteriormente ou atualmente conectados. Deteccao via classes WPD, Apple Mobile e Android ADB.</div>"

    # --- Mobile device detection via WPD/Apple/Android PnP classes ---
    $mobileRows = ''
    $mobileCount = 0
    $mobileQuery = "SELECT * FROM Win32_PnPEntity WHERE PNPClass='WPD' OR PNPClass='AndroidUsbDeviceClass' OR PNPClass='AppleDevice' OR PNPDeviceID LIKE '%VID_05AC%' OR PNPDeviceID LIKE '%VID_18D1%' OR PNPDeviceID LIKE '%VID_04E8%' OR PNPDeviceID LIKE '%VID_22B8%' OR PNPDeviceID LIKE '%VID_2717%' OR PNPDeviceID LIKE '%VID_0BB4%' OR Name LIKE '%iPhone%' OR Name LIKE '%iPad%' OR Name LIKE '%Apple%Mobile%' OR Name LIKE '%Android%' OR Name LIKE '%Samsung%' OR Name LIKE '%Motorola%' OR Name LIKE '%MTP%' OR Name LIKE '%Pixel%' OR Description LIKE '%Portable%' OR Description LIKE '%Phone%'"
    $colMobile = Invoke-WmiQueryCompat -QueryText $mobileQuery
    foreach ($mob in $colMobile) {
        $mobileCount = $mobileCount + 1
        $pnpId = [string](Nz (SafeWmiProp $mob 'PNPDeviceID' '') '')
        $devName = [string](Nz (SafeWmiProp $mob 'Name' '') '-')
        $devClass = [string](Nz (SafeWmiProp $mob 'PNPClass' '') '-')
        $devMfg = [string](Nz (SafeWmiProp $mob 'Manufacturer' '') '-')
        $devStatus = [string](Nz (SafeWmiProp $mob 'Status' '') '-')
        $devDesc = [string](Nz (SafeWmiProp $mob 'Description' '') '-')
        # Infer device type from VID or name
        $devType = 'Desconhecido'
        $pnpUp = $pnpId.ToUpperInvariant()
        $nameUp = $devName.ToUpperInvariant()
        if ($pnpUp.Contains('VID_05AC') -or $nameUp.Contains('IPHONE') -or $nameUp.Contains('IPAD') -or $nameUp.Contains('APPLE')) { $devType = 'Apple (iPhone/iPad)' }
        elseif ($pnpUp.Contains('VID_18D1') -or $nameUp.Contains('PIXEL') -or $nameUp.Contains('GOOGLE')) { $devType = 'Google (Pixel/Android)' }
        elseif ($pnpUp.Contains('VID_04E8') -or $nameUp.Contains('SAMSUNG') -or $nameUp.Contains('GALAXY')) { $devType = 'Samsung (Android)' }
        elseif ($pnpUp.Contains('VID_22B8') -or $nameUp.Contains('MOTOROLA') -or $nameUp.Contains('MOTO')) { $devType = 'Motorola (Android)' }
        elseif ($pnpUp.Contains('VID_2717') -or $nameUp.Contains('XIAOMI') -or $nameUp.Contains('REDMI')) { $devType = 'Xiaomi (Android)' }
        elseif ($pnpUp.Contains('VID_0BB4') -or $nameUp.Contains('HTC')) { $devType = 'HTC (Android)' }
        elseif ($nameUp.Contains('ANDROID') -or $nameUp.Contains('MTP') -or $devDesc.ToUpperInvariant().Contains('PORTABLE')) { $devType = 'Android/MTP' }
        $vid = ParseBetween ($pnpUp) 'VID_' '&'
        $pidVal = ParseBetween ($pnpUp) 'PID_' '&'
        $pserial = ParsePnPSerial $pnpId
        $mobileRows += "<tr><td>" + (HtmlEncode $devName) + "</td><td>" + (HtmlEncode $devType) + "</td><td>" + (HtmlEncode $devClass) + "</td><td>" + (HtmlEncode $devMfg) + "</td><td>" + (HtmlEncode $devStatus) + "</td><td>" + (HtmlEncode ('VID=' + [string](Nz $vid '-') + ' PID=' + [string](Nz $pidVal '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $pserial '-'))) + "</td><td class='location-col'>" + (HtmlEncode $pnpId) + "</td></tr>"
    }
    Write-VbsLine $Writer ("<div class='grid'><div class='card'><div class='kpi'>" + $mobileCount + "</div><div class='kpi-label'>Dispositivos moveis detectados</div></div></div>")
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Nome</th><th>Tipo Inferido</th><th>Classe</th><th>Fabricante</th><th>Status</th><th>VID/PID</th><th>Serial</th><th class='location-col'>PNPDeviceID</th></tr>"
    if ($mobileRows.Trim() -eq '') {
        Write-VbsLine $Writer "<tr><td colspan='8'>Nenhum dispositivo movel (celular/tablet) detectado no historico PnP.</td></tr>"
    } else {
        Write-VbsLine $Writer $mobileRows
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<h3>Potenciais Dispositivos USB</h3>"

    $colPnP = Invoke-WmiQueryCompat -QueryText "SELECT * FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%' OR Name LIKE '%USB%' OR Name LIKE '%Mass Storage%' OR Name LIKE '%Storage%'"
    foreach ($dev in $colPnP) {
        $countUSB = $countUSB + 1
        $pnpDeviceId = [string](Nz (SafeWmiProp $dev 'PNPDeviceID' '') '')
        $vid = ParseBetween ($pnpDeviceId.ToUpperInvariant()) 'VID_' '&'
        $pidValue = ParseBetween ($pnpDeviceId.ToUpperInvariant()) 'PID_' '&'
        $pserial = ParsePnPSerial $pnpDeviceId
        $usbRows = $usbRows + "<tr><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $dev 'Name' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $dev 'PNPClass' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $dev 'Manufacturer' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $dev 'Status' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $dev 'Description' '') '-'))) + "</td><td>" + (HtmlEncode ('VID=' + [string](Nz $vid '-') + ' PID=' + [string](Nz $pidValue '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $pserial '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz $pnpDeviceId '-'))) + "</td></tr>"
    }

    Write-VbsLine $Writer ("<div class='grid'><div class='card'><div class='kpi'>" + $countUSB + "</div><div class='kpi-label'>Dispositivos USB/PnP</div></div></div>")
    Write-VbsLine $Writer "<h3>Listagem de dispositivos removiveis</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Nome</th><th>Classe</th><th>Fabricante</th><th>Status</th><th>Modelo</th><th>VID/PID</th><th>Serial parseado</th><th class='location-col'>PNPDeviceID</th></tr>"
    if ($usbRows.Trim() -eq '') {
        Write-VbsLine $Writer "<tr><td colspan='8'>Nenhum dispositivo USB/PnP relevante listado.</td></tr>"
    }
    else {
        Write-VbsLine $Writer $usbRows
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<h3>Drives Externos</h3>"
    WriteExternalDrivesDetailed -Writer $Writer

    Write-VbsLine $Writer "</section>"
}

function WriteSystemSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    Write-VbsLine $Writer "<section id='so' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Sistema Operacional</h2>"

    Write-VbsLine $Writer "<h3>Contexto do Sistema Operacional</h3>"

    $colOS = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_OperatingSystem'
    foreach ($os in $colOS) {
        Write-VbsLine $Writer "<table><tr><th>Campo</th><th>Valor</th></tr>"
        WriteKV 'Nome do SO' (SafeWmiProp $os 'Caption' '')
        WriteKV 'Versao' (SafeWmiProp $os 'Version' '')
        WriteKV 'Build' (SafeWmiProp $os 'BuildNumber' '')
        WriteKV 'Arquitetura' (SafeWmiProp $os 'OSArchitecture' '')
        WriteKV 'Serial do SO' (SafeWmiProp $os 'SerialNumber' '')
        WriteKV 'Idioma/Locale' (SafeWmiProp $os 'Locale' '')
        WriteKV 'Diretorio Windows' (SafeWmiProp $os 'WindowsDirectory' '')
        WriteKV 'Diretorio Sistema' (SafeWmiProp $os 'SystemDirectory' '')
        WriteKV 'Ultimo boot' (WmiDateToString ([string](Nz (SafeWmiProp $os 'LastBootUpTime' '') '')))
        WriteKV 'Data instalacao SO' (WmiDateToString ([string](Nz (SafeWmiProp $os 'InstallDate' '') '')))
        WriteKV 'Memoria fisica total' (FormatBytes ((To-DoubleSafe (SafeWmiProp $os 'TotalVisibleMemorySize' 0)) * 1024.0))
        WriteKV 'Memoria fisica livre' (FormatBytes ((To-DoubleSafe (SafeWmiProp $os 'FreePhysicalMemory' 0)) * 1024.0))
        WriteKV 'Memoria virtual total' (FormatBytes ((To-DoubleSafe (SafeWmiProp $os 'TotalVirtualMemorySize' 0)) * 1024.0))
        WriteKV 'Memoria virtual livre' (FormatBytes ((To-DoubleSafe (SafeWmiProp $os 'FreeVirtualMemory' 0)) * 1024.0))
        WriteKV 'Arquivo paginacao livre' (FormatBytes ((To-DoubleSafe (SafeWmiProp $os 'FreeSpaceInPagingFiles' 0)) * 1024.0))
        WriteKV 'Arquivo paginacao total' (FormatBytes ((To-DoubleSafe (SafeWmiProp $os 'SizeStoredInPagingFiles' 0)) * 1024.0))
        Write-VbsLine $Writer "</table>"
    }

    $colMemPerf = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_PerfFormattedData_PerfOS_Memory'
    foreach ($memPerf in $colMemPerf) {
        Write-VbsLine $Writer "<table><tr><th colspan='2'>Telemetria de memoria e cache (PerfOS)</th></tr>"
        WriteKV 'Cache em uso (bytes)' (FormatBytes (SafeWmiProp $memPerf 'CacheBytes' 0))
        WriteKV 'Pico de cache (maximo observado)' (FormatBytes (SafeWmiProp $memPerf 'CacheBytesPeak' 0))
        WriteKV 'Memoria comprometida (alocada)' (FormatBytes (SafeWmiProp $memPerf 'CommittedBytes' 0))
        WriteKV 'Limite de memoria comprometida' (FormatBytes (SafeWmiProp $memPerf 'CommitLimit' 0))
        WriteKV 'Pool paginado (kernel)' (FormatBytes (SafeWmiProp $memPerf 'PoolPagedBytes' 0))
        WriteKV 'Pool nao paginado (kernel)' (FormatBytes (SafeWmiProp $memPerf 'PoolNonpagedBytes' 0))
        WriteKV 'Falhas de pagina por segundo' (SafeWmiProp $memPerf 'PageFaultsPersec' '')
        Write-VbsLine $Writer "</table>"
    }

    $hiberEnabled = ReadDWORDValue 'SYSTEM\CurrentControlSet\Control\Power' 'HibernateEnabled' -1
    $hiberFilePath = 'C:\hiberfil.sys'
    Write-VbsLine $Writer "<table><tr><th colspan='2'>Hibernacao (artefato forense)</th></tr>"
    WriteKV 'Hibernacao (registro)' $hiberEnabled
    $hiberExists = Test-Path -LiteralPath $hiberFilePath -PathType Leaf
    WriteKV 'Arquivo hiberfil.sys presente' $hiberExists
    if ($hiberExists) {
        $hiberSize = 0
        try {
            $hiberSize = (Get-Item -LiteralPath $hiberFilePath -Force -ErrorAction Stop).Length
        }
        catch {
            $hiberSize = 0
        }
        WriteKV 'Tamanho hiberfil.sys' (FormatBytes $hiberSize)
    }
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "</section>"
}

function WriteIdentityUsersSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    Write-VbsLine $Writer "<section id='identidade' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Identidade do sistema</h2>"
    
    $netUserLocal = GetCommandOutputWithTimeout 'cmd /c net user' 20
    $netUserDomain = ''
    if ([bool](Nz $script:UserDomainText '') -and $script:UserDomainText -ne $script:strComputer) {
        $netUserDomain = GetCommandOutputWithTimeout 'cmd /c net user /domain' 20
    }
    $whoamiPriv = GetCommandOutputWithTimeout 'cmd /c whoami /priv' 20
    $querySession = GetCommandOutputWithTimeout 'cmd /c qwinsta' 20

    Write-VbsLine $Writer "<h3>Sessoes e Privilegios Atuais</h3>"
    Write-VbsLine $Writer "<table>"
    Write-VbsLine $Writer ("<tr><th>Sessoes Ativas (qwinsta / query session)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $querySession ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><th>Privilegios do Token Atual (whoami /priv)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $whoamiPriv ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Net User (Comandos nativos)</h3>"
    Write-VbsLine $Writer "<table>"
    Write-VbsLine $Writer ("<tr><th>Net User (Local)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $netUserLocal ''))) + "</pre></div></td></tr>")
    if ($netUserDomain -ne '') {
        Write-VbsLine $Writer ("<tr><th>Net User (Domain)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $netUserDomain ''))) + "</pre></div></td></tr>")
    }
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Identidade do sistema, contas locais e grupos</h3>"
    Write-VbsLine $Writer "<div class='mini-note'>Bloco orientado a triagem DFIR com foco em cadeia de custodia de identidade, ativos locais e superficie SMB (referencias praticas: ISO/IEC 27037/27043 e NIST SP 800-61/800-86).</div>"


    $colOS = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_OperatingSystem'
    foreach ($os in $colOS) {
        Write-VbsLine $Writer "<table><tr><th>Campo</th><th>Valor</th></tr>"
        WriteKV 'Dispositivo de boot (origem de inicializacao)' (SafeWmiProp $os 'BootDevice' '')
        WriteKV 'Diretorio de instalacao' (SafeWmiProp $os 'WindowsDirectory' '')
        WriteKV 'Fuso horario (offset atual)' (ParseTimeZoneOffset (SafeWmiProp $os 'CurrentTimeZone' ''))
        WriteKV 'Idioma do sistema (LCID)' (ParseWindowsLanguageCode (SafeWmiProp $os 'OSLanguage' ''))
        WriteKV 'Usuario registrado no SO (WMI)' (SafeWmiProp $os 'RegisteredUser' '')
        WriteKV 'Organizacao registrada no SO (WMI)' (SafeWmiProp $os 'Organization' '')
        Write-VbsLine $Writer "</table>"
    }

    $regOwner = ReadStringValue 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'RegisteredOwner' '-'
    $regOrg = ReadStringValue 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'RegisteredOrganization' '-'
    Write-VbsLine $Writer "<table><tr><th>Registro (metadado do SO)</th><th>Valor</th></tr>"
    WriteKV 'Proprietario registrado (Registry)' $regOwner
    WriteKV 'Organizacao registrada (Registry)' $regOrg
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Compartilhamentos locais</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Nome</th><th class='location-col'>Path</th><th class='location-col'>Descricao</th><th>Tipo</th></tr>"
    $colShare = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_Share'
    foreach ($sh in $colShare) {
        $row = "<tr><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $sh 'Name' '') '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $sh 'Path' '') '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $sh 'Description' '') '-'))) + "</td><td>" + (HtmlEncode (FormatShareType (SafeWmiProp $sh 'Type' ''))) + "</td></tr>"
        Write-VbsLine $Writer $row
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    $usersPath = [System.Environment]::ExpandEnvironmentVariables('%SystemDrive%') + '\Users'
    Write-VbsLine $Writer "<h3>Perfis encontrados em C:\Users</h3>"
    Write-VbsLine $Writer "<table><tr><th>Pasta de Perfil</th><th>Data criacao</th><th>Data Ultima modificacao</th></tr>"
    if (Test-Path -LiteralPath $usersPath -PathType Container) {
        try {
            $subFolders = Get-ChildItem -LiteralPath $usersPath -Directory -Force -ErrorAction Stop
        }
        catch {
            $subFolders = @()
        }
        foreach ($sf in $subFolders) {
            $createdText = [string](Nz $sf.CreationTime '-')
            $modifiedText = [string](Nz $sf.LastWriteTime '-')
            Write-VbsLine $Writer ("<tr><td>" + (HtmlEncode ([string](Nz $sf.Name '-'))) + "</td><td>" + (HtmlEncode $createdText) + "</td><td>" + (HtmlEncode $modifiedText) + "</td></tr>")
            if (IsRelevantUserProfileName ([string](Nz $sf.Name ''))) {
                AppendDfirTimelineRecordFromDate $sf.CreationTime 'Usuario criado' ([string](Nz $sf.Name '')) 'Criacao de perfil local' 'Pasta de perfil em C:\\Users' 'FSO:C:\\Users' 'INFO'
            }
        }
    }
    else {
        Write-VbsLine $Writer "<tr><td colspan='3'>Pasta Users nao encontrada.</td></tr>"
    }
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Usuarios locais registrados</h3>"
    Write-VbsLine $Writer "<table><tr><th>Nome</th><th>SID</th><th>Status</th><th>Conta local</th><th>Ultimo logon</th></tr>"
    $colUsers = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_UserAccount WHERE LocalAccount=True'
    foreach ($u in $colUsers) {
        $disabledRaw = SafeWmiProp $u 'Disabled' $false
        $disabled = $false
        try { $disabled = [bool]$disabledRaw } catch { $disabled = $false }
        $statusText = IIfBool $disabled 'Desabilitado' 'Habilitado'
        Write-VbsLine $Writer ("<tr><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $u 'Name' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $u 'SID' '') '-'))) + "</td><td>" + (HtmlEncode $statusText) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $u 'LocalAccount' '') '-'))) + "</td><td>-</td></tr>")
    }
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Perfis de usuario (Win32_UserProfile)</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Perfil</th><th>SID</th><th>Ultimo uso</th><th>Loaded</th><th class='location-col'>LocalPath</th></tr>"
    $colProfiles = Invoke-WmiQueryCompat -QueryText 'SELECT SID,LocalPath,LastUseTime,Loaded,Special FROM Win32_UserProfile'
    foreach ($up in $colProfiles) {
        if ((To-VbsTrimUpper ([string](Nz (SafeWmiProp $up 'Special' 'False') 'False'))) -ne 'TRUE') {
            $profilePath = [string](Nz (SafeWmiProp $up 'LocalPath' '-') '-')
            $profileName = GetLeafNameFromPath $profilePath
            $lastUseRaw = SafeWmiProp $up 'LastUseTime' ''
            $lastUseTxt = WmiDateToString $lastUseRaw
            Write-VbsLine $Writer ("<tr><td>" + (HtmlEncode $profileName) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $up 'SID' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $lastUseTxt '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $up 'Loaded' '') '-'))) + "</td><td class='location-col'>" + (HtmlEncode $profilePath) + "</td></tr>")
            if ($lastUseTxt -ne '-' -and (IsRelevantUserProfileName $profileName)) {
                AppendDfirTimelineRecordFromWmi $lastUseRaw 'Ultimo usuario acessado' $profileName 'Ultimo uso de perfil' ('SID=' + [string](Nz (SafeWmiProp $up 'SID' '') '-') + ' | Loaded=' + [string](Nz (SafeWmiProp $up 'Loaded' '') '-')) 'WMI:Win32_UserProfile' 'WARN'
            }
        }
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<h3>Grupos locais</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Grupo</th><th class='location-col'>SID</th><th class='location-col'>Descricao</th></tr>"
    $colGroups = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_Group WHERE LocalAccount=True'
    foreach ($g in $colGroups) {
        Write-VbsLine $Writer ("<tr><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $g 'Name' '') '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $g 'SID' '') '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $g 'Description' '') '-'))) + "</td></tr>")
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "</section>"
}

function WriteCurrentUserRecentShortcuts {
    param(
        [System.IO.StreamWriter]$Writer,
        [int]$MaxItems
    )

    $recentPath = [System.Environment]::ExpandEnvironmentVariables('%APPDATA%') + '\Microsoft\Windows\Recent'
    $limitN = [long](To-LongSafe $MaxItems)
    if ($limitN -lt 0) { $limitN = 0 }
    $sep = [char]30
    $rowsHtml = ''

    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Atalho</th><th>Ultima modificacao</th><th>Criacao</th><th>Ultimo acesso</th><th>Destino</th><th class='location-col'>Caminho</th><th>Tamanho</th></tr>"

    $records = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath $recentPath -PathType Container) {
        try {
            $files = Get-ChildItem -LiteralPath $recentPath -File -Force -ErrorAction Stop
        }
        catch {
            $files = @()
        }

        $shellCom = $null
        try { $shellCom = New-Object -ComObject WScript.Shell } catch { $shellCom = $null }
        foreach ($f in $files) {
            $ext = ([string](Nz $f.Extension '')).ToLowerInvariant()
            if ($ext -eq '.lnk') {
                $sortKey = SortKeyFromDateValue $f.LastWriteTime
                $targetPath = '-'
                if ($null -ne $shellCom) {
                    try {
                        $sc = $shellCom.CreateShortcut($f.FullName)
                        if ($null -ne $sc) {
                            $targetPath = [string](Nz $sc.TargetPath '-')
                            if ($targetPath.Trim() -eq '') { $targetPath = '-' }
                        }
                    }
                    catch {
                    }
                }

                $line = (DfirTimelineFieldSafe $sortKey) + $sep + (DfirTimelineFieldSafe ([string](Nz $f.Name '-'))) + $sep + (DfirTimelineFieldSafe (FormatDateTimeLocal $f.LastWriteTime)) + $sep + (DfirTimelineFieldSafe (FormatDateTimeLocal $f.CreationTime)) + $sep + (DfirTimelineFieldSafe (FormatDateTimeLocal $f.LastAccessTime)) + $sep + (DfirTimelineFieldSafe $targetPath) + $sep + (DfirTimelineFieldSafe ([string](Nz $f.FullName '-'))) + $sep + (DfirTimelineFieldSafe (FormatBytes $f.Length))
                $records.Add($line)

                # User Artifact Timeline removal
                # AppendUserArtifactTimelineRecordFromDate $f.CreationTime 'Criacao' $f.Name $f.FullName
                # AppendUserArtifactTimelineRecordFromDate $f.LastAccessTime 'Acesso' $f.Name $f.FullName
                # AppendUserArtifactTimelineRecordFromDate $f.LastWriteTime 'Modificacao' $f.Name $f.FullName
            }
        }
    }

    if ($records.Count -gt 0) {
        $sorted = SortStringArrayAsc -Arr $records.ToArray()
        $n = 0
        for ($i = $sorted.Length - 1; $i -ge 0; $i--) {
            if ($limitN -gt 0 -and $n -ge $limitN) { break }
            $parts = ([string](Nz $sorted[$i] '')).Split([char]30)
            if ($parts.Length -ge 8) {
                $rowsHtml = $rowsHtml + "<tr><td>" + (HtmlEncode $parts[1]) + "</td><td>" + (HtmlEncode $parts[2]) + "</td><td>" + (HtmlEncode $parts[3]) + "</td><td>" + (HtmlEncode $parts[4]) + "</td><td class='location-col'>" + (HtmlEncode $parts[5]) + "</td><td class='location-col'>" + (HtmlEncode $parts[6]) + "</td><td>" + (HtmlEncode $parts[7]) + "</td></tr>"
                $n = $n + 1
            }
        }
        if ($rowsHtml.Trim() -ne '') {
            Write-VbsLine $Writer $rowsHtml
        }
        else {
            Write-VbsLine $Writer "<tr><td colspan='7'>Nenhum atalho recente interpretado na pasta Recent.</td></tr>"
        }
    }
    else {
        Write-VbsLine $Writer ("<tr><td colspan='7'>Pasta Recent sem atalhos .lnk, sem acesso ou inexistente: " + (HtmlEncode $recentPath) + "</td></tr>")
    }

    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"
    Write-VbsLine $Writer ("<div class='mini-note'>Origem: coleta direta da pasta <code>" + (HtmlEncode $recentPath) + "</code>; usados os timestamps do sistema de arquivos (Criacao/Acesso/Modificacao) e tentativa de resolucao do alvo do atalho.</div>")
}

function WritePastasTelemetriaForense {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $systemRoot = [System.Environment]::ExpandEnvironmentVariables('%SystemRoot%')
    $userProfile = [System.Environment]::ExpandEnvironmentVariables('%USERPROFILE%')
    $folderPaths = @(
        'C:\$Recycle.Bin\',
        ($systemRoot + '\Prefetch\'),
        ($systemRoot + '\System32\winevt\Logs\'),
        ($userProfile + '\AppData\Roaming\Microsoft\Windows\Recent\'),
        ($userProfile + '\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\'),
        ($userProfile + '\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\'),
        ($userProfile + '\AppData\Local\Google\Chrome\User Data\Default\'),
        ($userProfile + '\AppData\Local\Microsoft\Edge\User Data\Default\'),
        ($userProfile + '\AppData\Roaming\Mozilla\Firefox\Profiles\'),
        ($systemRoot + '\Temp\'),
        ($userProfile + '\AppData\Local\Temp\'),
        ($systemRoot + '\AppCompat\Programs\'),
        ($systemRoot + '\System32\Config\'),
        ($systemRoot + '\System32\sru\'),
        ($systemRoot + '\System32\Tasks\'),
        ($userProfile + '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\'),
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\',
        'C:\ProgramData\Microsoft\Windows Defender\Support\',
        ($systemRoot + '\Logs\'),
        ''
    )

    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Caminho da Pasta</th><th>Categoria Forense</th><th>Arquivos</th><th>Subpastas</th><th>Tamanho Total</th></tr>"
    for ($j = 0; $j -lt $folderPaths.Length; $j++) {
        if ($folderPaths[$j] -ne '') {
            $path = $folderPaths[$j]
            Write-ProgressLog -Message ('Forensic folder scan: ' + $path)
            $fileCount = 0
            $dirCount = 0
            $bytesTotal = 0.0
            CountFolderStats -Path $path -TotalFiles ([ref]$fileCount) -TotalDirs ([ref]$dirCount) -TotalBytes ([ref]$bytesTotal)
            $category = GetForensicCategory $path
            Write-VbsLine $Writer ("<tr><td>" + (HtmlEncode $path) + "</td><td>" + (HtmlEncode $category) + "</td><td>" + $fileCount + "</td><td>" + $dirCount + "</td><td>" + (FormatBytes $bytesTotal) + "</td></tr>")
        }
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"
}

function WriteFolderTelemetrySection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $script:folderChartLabels = ''
    $script:folderChartFiles = ''

    $userProfile = [System.Environment]::ExpandEnvironmentVariables('%USERPROFILE%')
    $desktopPath = $userProfile + '\Desktop'
    $downloadsPath = $userProfile + '\Downloads'
    $documentsPath = $userProfile + '\Documents'

    $dFiles = 0; $dDirs = 0; $dBytes = 0.0
    $dwFiles = 0; $dwDirs = 0; $dwBytes = 0.0
    $docFiles = 0; $docDirs = 0; $docBytes = 0.0
    Write-ProgressLog -Message ('Folder scan: ' + $desktopPath)
    CountFolderStats -Path $desktopPath -TotalFiles ([ref]$dFiles) -TotalDirs ([ref]$dDirs) -TotalBytes ([ref]$dBytes)
    Write-ProgressLog -Message ('Folder scan: ' + $downloadsPath)
    CountFolderStats -Path $downloadsPath -TotalFiles ([ref]$dwFiles) -TotalDirs ([ref]$dwDirs) -TotalBytes ([ref]$dwBytes)
    Write-ProgressLog -Message ('Folder scan: ' + $documentsPath)
    CountFolderStats -Path $documentsPath -TotalFiles ([ref]$docFiles) -TotalDirs ([ref]$docDirs) -TotalBytes ([ref]$docBytes)

    Write-VbsLine $Writer "<section id='pastas' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Pastas do Usuario</h2>"
    Write-VbsLine $Writer "<h3>Telemetria (Desktop/Downloads/Documents)</h3>"
    Write-VbsLine $Writer "<table><tr><th>Pasta</th><th>Caminho</th><th>Total de Arquivos</th><th>Total de Subpastas</th><th>Tamanho estimado</th></tr>"
    Write-VbsLine $Writer ("<tr><td>Desktop</td><td>" + (HtmlEncode $desktopPath) + "</td><td>" + $dFiles + "</td><td>" + $dDirs + "</td><td>" + (FormatBytes $dBytes) + "</td></tr>")
    Write-VbsLine $Writer ("<tr><td>Downloads</td><td>" + (HtmlEncode $downloadsPath) + "</td><td>" + $dwFiles + "</td><td>" + $dwDirs + "</td><td>" + (FormatBytes $dwBytes) + "</td></tr>")
    Write-VbsLine $Writer ("<tr><td>Documents</td><td>" + (HtmlEncode $documentsPath) + "</td><td>" + $docFiles + "</td><td>" + $docDirs + "</td><td>" + (FormatBytes $docBytes) + "</td></tr>")
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Backups e Sincronizacao de Dispositivos Moveis</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'><table><tr><th>Aplicacao / Tipo</th><th>Caminho Verificado</th><th>Status</th><th>Arquivos</th><th>Tamanho Estimado</th></tr>"
    
    $backups = @(ScanUserBackups)
    if ($backups.Count -gt 0) {
        foreach ($b in $backups) {
            Write-VbsLine $Writer ("<tr><td>" + (HtmlEncode $b.Name) + "</td><td class='location-col'>" + (HtmlEncode $b.Path) + "</td><td><span class='ok'>Encontrado</span></td><td>" + $b.Files + "</td><td>" + (FormatBytes $b.Size) + "</td></tr>")
        }
    } else {
        Write-VbsLine $Writer "<tr><td colspan='5'>Nenhum backup conhecido (iTunes, Android, WhatsApp, Cloud Sync) detectado em caminhos padrao.</td></tr>"
    }
    Write-VbsLine $Writer "</table></div>"

    Write-VbsLine $Writer "<h3>Historico de Dispositivos Moveis Conectados (Registro/WPD)</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'><table><tr><th>Origem/Tipo</th><th>Nome Amigavel</th><th>Fabricante</th><th>Identificador (ID)</th></tr>"
    $mobHistory = @(GetMobileDeviceHistory)
    if ($mobHistory.Count -gt 0) {
        foreach ($m in $mobHistory) {
            $mType = '-'
            $mName = '-'
            $mManuf = '-'
            $mId = '-'
            try { $mType = $m.Type } catch {}
            try { $mName = $m.Name } catch {}
            try { $mManuf = $m.Manufacturer } catch {}
            try { $mId = $m.Id } catch {}

            Write-VbsLine $Writer ("<tr><td>" + (HtmlEncode ([string](Nz $mType '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $mName '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $mManuf '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz $mId '-'))) + "</td></tr>")
        }
    } else {
        Write-VbsLine $Writer "<tr><td colspan='4'>Nenhum historico de dispositivo movel (WPD/USBSTOR) interpretado no registro.</td></tr>"
    }
    Write-VbsLine $Writer "</table></div>"

    Write-VbsLine $Writer "<h3>Artefatos Forenses</h3>"
    WritePastasTelemetriaForense -Writer $Writer
    Write-VbsLine $Writer "<h3>Atalhos recentes do usuario atual</h3>"
    WriteCurrentUserRecentShortcuts -Writer $Writer -MaxItems 0
    Write-VbsLine $Writer "</section>"
}

function WriteNetworkSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $script:networkAdapterCount = 0

    Write-VbsLine $Writer "<section id='rede' class='card' style='margin-top:16px'>"

    Write-VbsLine $Writer "<h2>Rede</h2>"
    Write-VbsLine $Writer "<h2>Configuracoes</h2>"

    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Adaptador</th><th>MAC</th><th>Status</th><th>Velocidade</th><th>Fabricante</th><th>Modelo/PNP</th></tr>"
    $colNIC = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter=True'
    foreach ($nic in $colNIC) {
        $script:networkAdapterCount = [long](To-LongSafe $script:networkAdapterCount) + 1
        $adapterName = [string](Nz (SafeWmiProp $nic 'NetConnectionID' (SafeWmiProp $nic 'Name' '-')) '-')
        $mac = [string](Nz (SafeWmiProp $nic 'MACAddress' '-') '-')
        $status = NetConnectionStatusName (SafeWmiProp $nic 'NetConnectionStatus' 0)
        $speed = HumanSpeed (SafeWmiProp $nic 'Speed' '')
        $manufacturer = [string](Nz (SafeWmiProp $nic 'Manufacturer' '-') '-')
        $name = [string](Nz (SafeWmiProp $nic 'Name' '-') '-')
        $pnp = [string](Nz (SafeWmiProp $nic 'PNPDeviceID' '-') '-')
        $row = "<tr><td>" + (HtmlEncode $adapterName) + "</td><td>" + (HtmlEncode $mac) + "</td><td>" + (HtmlEncode $status) + "</td><td>" + $speed + "</td><td>" + (HtmlEncode $manufacturer) + "</td><td class='location-col'>" + (HtmlEncode $name) + "<br>" + (HtmlEncode $pnp) + "</td></tr>"
        Write-VbsLine $Writer $row
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    $colNICCfg = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True'
    foreach ($cfg in $colNICCfg) {
        Write-VbsLine $Writer "<div class='scroll-table'>"
        Write-VbsLine $Writer ("<table><tr><th colspan='2'>" + (HtmlEncode ([string](Nz (SafeWmiProp $cfg 'Description' '') ''))) + "</th></tr>")
        WriteKV 'DHCP' (SafeWmiProp $cfg 'DHCPEnabled' '')
        WriteKV 'DHCP Server' (SafeWmiProp $cfg 'DHCPServer' '')
        WriteKV 'DNS Suffix' (SafeWmiProp $cfg 'DNSDomain' '')
        WriteKVHtml 'IP' (JoinArray (SafeWmiProp $cfg 'IPAddress' '-') '<br>')
        WriteKVHtml 'Mascara' (JoinArray (SafeWmiProp $cfg 'IPSubnet' '-') '<br>')
        WriteKVHtml 'Gateway' (JoinArray (SafeWmiProp $cfg 'DefaultIPGateway' '-') '<br>')
        WriteKVHtml 'DNS' (JoinArray (SafeWmiProp $cfg 'DNSServerSearchOrder' '-') '<br>')
        WriteKV 'WINS Primario' (SafeWmiProp $cfg 'WINSPrimaryServer' '')
        WriteKV 'WINS Secundario' (SafeWmiProp $cfg 'WINSSecondaryServer' '')
        Write-VbsLine $Writer "</table>"
        Write-VbsLine $Writer "</div>"
    }

    Write-VbsLine $Writer ("<div class='grid'><div class='card'><div class='kpi'>" + [long](To-LongSafe $script:networkAdapterCount) + "</div><div class='kpi-label'>Adaptadores fisicos detectados</div></div></div>")
    Write-VbsLine $Writer "</section>"
}

function WriteNetworkDeepSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $ipcfg = GetCommandOutputWithTimeout 'cmd /c ipconfig /all' 60
    $routeOut = GetCommandOutputWithTimeout 'cmd /c route print' 30
    $vpnOut = GetCommandOutputWithTimeout 'cmd /c rasdial' 30
    $portsOut = GetCommandOutputWithTimeout 'cmd /c netstat -ano -p tcp' 60
    $arpOut = GetCommandOutputWithTimeout 'cmd /c arp -a' 30
    $joinsOut = GetCommandOutputWithTimeout 'cmd /c netsh interface ipv4 show joins' 30
    $getmacOut = GetCommandOutputWithTimeout 'cmd /c getmac /v /fo csv' 30
    $tracertOut = GetCommandOutputWithTimeout 'cmd /c tracert -d -h 3 8.8.8.8' 40
    $nslookupOut = GetCommandOutputWithTimeout 'cmd /c nslookup -type=ANY localhost' 20
    $netstatAboOut = GetCommandOutputWithTimeout 'cmd /c netstat -abo' 90
    $nltestOut = ''
    if ([bool](Nz $script:UserDomainText '') -and $script:UserDomainText -ne $script:strComputer) {
        $nltestOut = GetCommandOutputWithTimeout ("cmd /c nltest /sc_query:" + $script:UserDomainText) 20
    }
    
    $portSummary = BuildTcpPortTopologySummary -NetstatOut $portsOut -MaxRows 1800
    $sensitiveOut = ExtractSensitivePorts ([string](Nz $portsOut ''))
    $portsExportPath = ExportTextArtifact -SubDirName 'topologia_rede' -FileBaseName ('netstat_tcp_' + [string](Nz $script:strRunId '')) -FileExt 'txt' -ContentText $portsOut
    $aboExportPath = ExportTextArtifact -SubDirName 'topologia_rede' -FileBaseName ('netstat_abo_' + [string](Nz $script:strRunId '')) -FileExt 'txt' -ContentText $netstatAboOut

    Write-VbsLine $Writer "<section id='redeplus' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Topologia</h2>"
    Write-VbsLine $Writer "<div class='mini-note'>Topologia de rede e portas com foco tecnico para Forense, IR e Analise de Malware (alinhamento operacional com ISO/IEC 27035/27037/27043 e NIST SP 800-61/800-86/800-92).</div>"
    Write-VbsLine $Writer "<table><tr><th>Coleta</th><th>Saida</th></tr>"
    Write-VbsLine $Writer ("<tr><td>Configuracao detalhada de rede (ipconfig /all)</td><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $ipcfg ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><td>Tabela de rotas ativa (route print)</td><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $routeOut ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><td>Conexoes VPN discadas ativas (rasdial)</td><td><pre>" + (HtmlEncode ([string](Nz $vpnOut ''))) + "</pre></td></tr>")
    Write-VbsLine $Writer ("<tr><td>Tabela ARP (arp -a)</td><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $arpOut ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><td>Multicast Joins (netsh interface ipv4 show joins)</td><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $joinsOut ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><td>MAC Address Mapping (getmac /v /fo csv)</td><td><pre>" + (HtmlEncode ([string](Nz $getmacOut ''))) + "</pre></td></tr>")
    Write-VbsLine $Writer ("<tr><td>Traceroute Rapido (tracert -d -h 3)</td><td><pre>" + (HtmlEncode ([string](Nz $tracertOut ''))) + "</pre></td></tr>")
    Write-VbsLine $Writer ("<tr><td>NSLookup (teste dns)</td><td><pre>" + (HtmlEncode ([string](Nz $nslookupOut ''))) + "</pre></td></tr>")
    if ($nltestOut -ne '') {
        Write-VbsLine $Writer ("<tr><td>NLTest Secure Channel</td><td><pre>" + (HtmlEncode ([string](Nz $nltestOut ''))) + "</pre></td></tr>")
    }
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Portas TCP abertas</h3>"
    Write-VbsLine $Writer ("<div class='grid'><div class='card'><div class='kpi'>" + [long](To-LongSafe $portSummary.TotalRows) + "</div><div class='kpi-label'>Entradas TCP analisadas</div></div><div class='card'><div class='kpi'>" + [long](To-LongSafe $portSummary.ListeningRows) + "</div><div class='kpi-label'>LISTENING</div></div><div class='card'><div class='kpi'>" + [long](To-LongSafe $portSummary.EstablishedRows) + "</div><div class='kpi-label'>ESTABLISHED</div></div><div class='card'><div class='kpi'>" + [long](To-LongSafe $portSummary.SensitiveRows) + "</div><div class='kpi-label'>Portas sensiveis</div></div></div>")
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Local</th><th>Remoto</th><th>Estado</th><th>PID</th><th>Processo</th><th>Classificacao</th></tr>"
    if ([string](Nz $portSummary.RowsHtml '').Trim() -eq '') {
        Write-VbsLine $Writer "<tr><td colspan='6'>Sem entradas TCP abertas retornadas pelo netstat.</td></tr>"
    }
    else {
        Write-VbsLine $Writer ([string](Nz $portSummary.RowsHtml ''))
    }
    if ([bool](Nz $portSummary.WasTruncated $false)) {
        Write-VbsLine $Writer "<tr><td colspan='6'><span class='warn'>Exibicao limitada para reduzir custo de renderizacao do HTML.</span></td></tr>"
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"
    Write-VbsLine $Writer ("<table><tr><th>Portas potencialmente sensiveis expostas</th></tr><tr><td><pre>" + (HtmlEncode ([string](Nz $sensitiveOut ''))) + "</pre></td></tr></table>")
    if ([string](Nz $portsExportPath '').Trim() -ne '') {
        Write-VbsLine $Writer ("<div class='mini-note'>Artefato exportado: <a href='" + (HtmlEncode $portsExportPath) + "' style='color:#7dd3fc'>" + (HtmlEncode $portsExportPath) + "</a></div>")
    }
    else {
        Write-VbsLine $Writer "<div class='mini-note'>Falha ao exportar artefato bruto de portas TCP para a pasta de export.</div>"
    }
    Write-VbsLine $Writer ("<table><tr><th>Saida bruta netstat -ano -p tcp</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $portsOut ''))) + "</pre></div></td></tr></table>")
    Write-VbsLine $Writer ("<table style='margin-top:14px'><tr><th>Saida completa netstat -abo</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $netstatAboOut ''))) + "</pre></div></td></tr></table>")
    Write-VbsLine $Writer "</section>"
}

function WritePagingArtifactsSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    Write-VbsLine $Writer "<section id='artefatos' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Artefatos</h2>"

    Write-VbsLine $Writer "<h3>Detalhes de paginacao (Pagefile)</h3>"
    Write-VbsLine $Writer "<table><tr><th>Nome</th><th>Alocado MB</th><th>Uso atual MB</th><th>Pico MB</th><th>Temp MB</th></tr>"
    $colPF = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_PageFileUsage'
    foreach ($pf in $colPF) {
        $name = [string](Nz (SafeWmiProp $pf 'Name' (SafeWmiProp $pf 'Description' '-')) '-')
        $row = "<tr><td>" + (HtmlEncode $name) + "</td><td>" + (SafeWmiProp $pf 'AllocatedBaseSize' '-') + "</td><td>" + (SafeWmiProp $pf 'CurrentUsage' '-') + "</td><td>" + (SafeWmiProp $pf 'PeakUsage' '-') + "</td><td>" + (SafeWmiProp $pf 'TemporaryPageFile' '-') + "</td></tr>"
        Write-VbsLine $Writer $row
    }
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Detalhes de Prefetch</h3>"
    $prefetchPath = [System.Environment]::ExpandEnvironmentVariables('%SystemRoot%') + '\Prefetch'
    $pfCount = 0
    $pfDirs = 0
    $pfBytes = 0.0
    CountFolderStats -Path $prefetchPath -TotalFiles ([ref]$pfCount) -TotalDirs ([ref]$pfDirs) -TotalBytes ([ref]$pfBytes)
    Write-VbsLine $Writer "<table><tr><th colspan='2'>Prefetch</th></tr>"
    WriteKV 'Caminho' $prefetchPath
    WriteKV 'Total de arquivos' $pfCount
    WriteKV 'Total de subpastas' $pfDirs
    WriteKV 'Tamanho total' (FormatBytes $pfBytes)
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Detalhes de Snapshots (vssadmin)</h3>"
    $shadowOut = GetCommandOutput 'cmd /c vssadmin list shadows'
    Write-VbsLine $Writer ("<div class='scroll-table snap-no-wrap'><table><tr><th>Snapshots (VSS)</th></tr><tr><td><pre class='snap-pre'>" + (HtmlEncode ([string](Nz $shadowOut ''))) + "</pre></td></tr></table></div>")
    Write-VbsLine $Writer "</section>"
}

function WriteControllersBackupSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    Write-VbsLine $Writer "<section id='controladores' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Controladores</h2>"

    Write-VbsLine $Writer "<h3>IDE/SCSI</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Tipo</th><th>Nome</th><th>Fabricante</th><th class='location-col'>PNPDeviceID</th></tr>"
    $colIDE = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_IDEController'
    foreach ($ide in $colIDE) {
        Write-VbsLine $Writer ("<tr><td>IDE</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $ide 'Name' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $ide 'Manufacturer' '') '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $ide 'PNPDeviceID' '') '-'))) + "</td></tr>")
    }
    $colSCSI = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_SCSIController'
    foreach ($scsi in $colSCSI) {
        Write-VbsLine $Writer ("<tr><td>SCSI</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $scsi 'Name' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $scsi 'Manufacturer' '') '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $scsi 'PNPDeviceID' '') '-'))) + "</td></tr>")
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<h3>Backup/Tape</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Nome</th><th>Status</th><th class='location-col'>PNPDeviceID</th></tr>"
    $colTape = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_TapeDrive'
    foreach ($tape in $colTape) {
        Write-VbsLine $Writer ("<tr><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $tape 'Name' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $tape 'Status' '') '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $tape 'PNPDeviceID' '') '-'))) + "</td></tr>")
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<h3>Dispositivos de armazenamento conectados (PnP class DiskDrive)</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Nome</th><th>Fabricante</th><th>Service</th><th class='location-col'>PNPDeviceID</th></tr>"
    $colDiskCtl = Invoke-WmiQueryCompat -QueryText "SELECT * FROM Win32_PnPEntity WHERE PNPClass='DiskDrive' OR PNPDeviceID LIKE 'USBSTOR%'"
    foreach ($dc in $colDiskCtl) {
        Write-VbsLine $Writer ("<tr><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $dc 'Name' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $dc 'Manufacturer' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $dc 'Service' '') '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $dc 'PNPDeviceID' '') '-'))) + "</td></tr>")
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "</section>"
}

function WriteSharesPortsPrintersSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    Write-VbsLine $Writer "<section id='shares' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Impressao</h2>"
    Write-VbsLine $Writer "<div class='mini-note'>Sessao dedicada a evidencias de spooler, filas e drivers de impressao para triagem tecnica (uso comum em movimentacao lateral e persistencia em IR/Malware).</div>"

    Write-VbsLine $Writer "<h3>Servico de impressao (Spooler)</h3>"
    Write-VbsLine $Writer "<table><tr><th>Campo</th><th>Valor</th></tr>"
    $colSpooler = Invoke-WmiQueryCompat -QueryText "SELECT Name,DisplayName,State,StartMode,StartName,PathName,ProcessId FROM Win32_Service WHERE Name='Spooler'"
    if (@($colSpooler).Count -gt 0) {
        foreach ($svc in $colSpooler) {
            WriteKV 'Servico' (SafeWmiProp $svc 'DisplayName' (SafeWmiProp $svc 'Name' '-'))
            WriteKV 'Estado' (SafeWmiProp $svc 'State' '-')
            WriteKV 'Inicializacao' (SafeWmiProp $svc 'StartMode' '-')
            WriteKV 'Conta' (SafeWmiProp $svc 'StartName' '-')
            WriteKV 'PID' (SafeWmiProp $svc 'ProcessId' '-')
            WriteKV 'Binario' (SafeWmiProp $svc 'PathName' '-')
        }
    }
    else {
        WriteKV 'Status' 'Servico Spooler nao retornado por WMI'
    }
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Impressoras instaladas</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Nome</th><th>Padrao</th><th>Rede</th><th>Compartilhada</th><th>Porta</th><th>Driver</th><th>Status</th><th class='location-col'>ShareName</th></tr>"
    $colPrinter = Invoke-WmiQueryCompat -QueryText 'SELECT Name,Default,Network,Shared,PortName,DriverName,PrinterStatus,ShareName FROM Win32_Printer'
    foreach ($prn in $colPrinter) {
        $row = "<tr><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $prn 'Name' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $prn 'Default' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $prn 'Network' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $prn 'Shared' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $prn 'PortName' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $prn 'DriverName' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $prn 'PrinterStatus' '') '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $prn 'ShareName' '') '-'))) + "</td></tr>"
        Write-VbsLine $Writer $row
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<h3>Portas de impressao TCP/IP</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Nome</th><th>Host/IP</th><th>Porta</th><th>Protocolo</th><th>SNMP</th><th>Community</th></tr>"
    $colTcpPorts = Invoke-WmiQueryCompat -QueryText 'SELECT Name,HostAddress,PortNumber,Protocol,SNMPEnabled,SNMPCommunity FROM Win32_TCPIPPrinterPort'
    if (@($colTcpPorts).Count -eq 0) {
        Write-VbsLine $Writer "<tr><td colspan='6'>Nenhuma porta TCP/IP de impressao retornada por WMI.</td></tr>"
    }
    else {
        foreach ($tp in $colTcpPorts) {
            $row = "<tr><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $tp 'Name' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $tp 'HostAddress' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $tp 'PortNumber' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $tp 'Protocol' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $tp 'SNMPEnabled' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $tp 'SNMPCommunity' '') '-'))) + "</td></tr>"
            Write-VbsLine $Writer $row
        }
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<h3>Drivers de impressora</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Nome</th><th>Versao</th><th>Fabricante</th><th class='location-col'>Path</th></tr>"
    $colDrv = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_PrinterDriver'
    foreach ($drv in $colDrv) {
        $row = "<tr><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $drv 'Name' '') '-'))) + "</td><td>" + (HtmlEncode (GetPrinterDriverVersion $drv)) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $drv 'Manufacturer' '') '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $drv 'DriverPath' (SafeWmiProp $drv 'InfName' '-')) '-'))) + "</td></tr>"
        Write-VbsLine $Writer $row
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "</section>"
}

function WriteServicesSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $autoCnt = 0
    $manualCnt = 0
    $disabledCnt = 0
    $runningCnt = 0
    $stoppedCnt = 0
    $script:serviceTotalCount = 0
    $script:serviceRunningCount = 0
    $script:serviceStoppedCount = 0

    Write-VbsLine $Writer "<section id='servicos' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Servicos detalhados</h2>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Service</th><th>DisplayName</th><th>Startup</th><th>Status</th><th>Usuario</th><th class='location-col'>Path</th><th>PID</th></tr>"
    $colSvc = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_Service'
    foreach ($svc in $colSvc) {
        $script:serviceTotalCount = [long](To-LongSafe $script:serviceTotalCount) + 1
        $startMode = [string](Nz (SafeWmiProp $svc 'StartMode' '') '')
        $state = [string](Nz (SafeWmiProp $svc 'State' '') '')
        if ($startMode.ToLowerInvariant() -eq 'auto') { $autoCnt = $autoCnt + 1 }
        if ($startMode.ToLowerInvariant() -eq 'manual') { $manualCnt = $manualCnt + 1 }
        if ($startMode.ToLowerInvariant() -eq 'disabled') { $disabledCnt = $disabledCnt + 1 }
        if ($state.ToLowerInvariant() -eq 'running') { $runningCnt = $runningCnt + 1; $script:serviceRunningCount = [long](To-LongSafe $script:serviceRunningCount) + 1 }
        if ($state.ToLowerInvariant() -eq 'stopped') { $stoppedCnt = $stoppedCnt + 1; $script:serviceStoppedCount = [long](To-LongSafe $script:serviceStoppedCount) + 1 }
        $row = "<tr><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $svc 'Name' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $svc 'DisplayName' '') '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $startMode '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $state '-'))) + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $svc 'StartName' '') '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $svc 'PathName' '') '-'))) + "</td><td>" + ([string](Nz (SafeWmiProp $svc 'ProcessId' '') '-')) + "</td></tr>"
        Write-VbsLine $Writer $row
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    $scQuery = GetCommandOutputWithTimeout 'cmd /c sc query type= service state= all' 30
    $dqQuery = GetCommandOutputWithTimeout 'cmd /c driverquery /fo table /si' 30

    Write-VbsLine $Writer "<h3>Diagnostico Adicional (CLI Nativa)</h3>"
    Write-VbsLine $Writer "<table>"
    Write-VbsLine $Writer ("<tr><th>SC Query All Services</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $scQuery ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><th>DriverQuery (Assinaturas)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $dqQuery ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<canvas id='serviceChart' height='90'></canvas>"
    Write-VbsLine $Writer ("<script>new Chart(document.getElementById('serviceChart'),{type:'bar',data:{labels:['Auto','Manual','Disabled','Running','Stopped'],datasets:[{label:'Servicos',data:[" + $autoCnt + "," + $manualCnt + "," + $disabledCnt + "," + $runningCnt + "," + $stoppedCnt + "],backgroundColor:['#38bdf8','#f59e0b','#ef4444','#22c55e','#94a3b8']}]},options:{plugins:{legend:{labels:{color:'#e2e8f0'}}},scales:{x:{ticks:{color:'#cbd5e1'}},y:{ticks:{color:'#cbd5e1'}}}}});</script>")
    Write-VbsLine $Writer "</section>"
}

function IsSeceditInterestingLine {
    param(
        [string]$LineText
    )

    $s = ([string](Nz $LineText '')).Trim().ToUpperInvariant()
    if ($s -eq '') { return $false }
    if ($s.StartsWith(';')) { return $false }
    if ($s -eq '[SYSTEM ACCESS]' -or $s -eq '[EVENT AUDIT]' -or $s -eq '[PRIVILEGE RIGHTS]') { return $true }
    if (
        $s.StartsWith('MINIMUMPASSWORDAGE=') -or $s.StartsWith('MAXIMUMPASSWORDAGE=') -or
        $s.StartsWith('MINIMUMPASSWORDLENGTH=') -or $s.StartsWith('PASSWORDCOMPLEXITY=') -or
        $s.StartsWith('PASSWORDHISTORYSIZE=') -or $s.StartsWith('LOCKOUTBADCOUNT=') -or
        $s.StartsWith('RESETLOCKOUTCOUNT=') -or $s.StartsWith('LOCKOUTDURATION=') -or
        $s.StartsWith('AUDITSYSTEMEVENTS=') -or $s.StartsWith('AUDITLOGONEVENTS=') -or
        $s.StartsWith('AUDITOBJECTACCESS=') -or $s.StartsWith('AUDITPOLICYCHANGE=')
    ) { return $true }
    if (
        $s.StartsWith('SEREMOTEINTERACTIVELOGONRIGHT=') -or $s.StartsWith('SEDENYREMOTEINTERACTIVELOGONRIGHT=') -or
        $s.StartsWith('SEBACKUPPRIVILEGE=') -or $s.StartsWith('SERESTOREPRIVILEGE=') -or
        $s.StartsWith('SEDEBUGPRIVILEGE=') -or $s.StartsWith('SETAKEOWNERSHIPPRIVILEGE=') -or
        $s.StartsWith('SESHUTDOWNPRIVILEGE=')
    ) { return $true }
    return $false
}

function GetSeceditSummary {
    $tempCfg = Join-Path $env:TEMP ('secpol_' + ([DateTime]::Now.ToString('HHmmssfff')) + '_' + ('{0:000000}' -f (Get-Random -Minimum 0 -Maximum 1000000)) + '.cfg')
    $cmd = 'cmd /c secedit /export /areas SECURITYPOLICY USER_RIGHTS /cfg "' + $tempCfg + '" >nul 2>&1'
    $cmdOut = GetCommandOutputWithTimeout $cmd 45

    $preview = ''
    $hits = ''
    $previewCount = 0
    $hitCount = 0

    if (Test-Path -LiteralPath $tempCfg -PathType Leaf) {
        try {
            $allLines = Get-Content -LiteralPath $tempCfg -ErrorAction Stop
            foreach ($lineRaw in $allLines) {
                $line = ([string](Nz $lineRaw '')).Replace([string][char]0, '')
                if ($previewCount -lt 140) {
                    $preview = $preview + $line + "`r`n"
                    $previewCount = $previewCount + 1
                }
                if (IsSeceditInterestingLine $line) {
                    $hits = $hits + $line + "`r`n"
                    $hitCount = $hitCount + 1
                    if ($hitCount -ge 180) { break }
                }
            }
        }
        catch {
        }
        try { Remove-Item -LiteralPath $tempCfg -Force -ErrorAction SilentlyContinue } catch {}
    }

    if ($hits.Trim() -ne '') {
        return 'Resumo filtrado (areas SECURITYPOLICY/USER_RIGHTS):' + "`r`n" + $hits.Trim()
    }
    if ($preview.Trim() -ne '') {
        return 'Preview da exportacao (inicio do arquivo):' + "`r`n" + $preview.Trim()
    }
    if (HasUsefulOutput $cmdOut) {
        return $cmdOut
    }
    return 'Falha ao exportar politica local via secedit ou coleta expirada por timeout.'
}

function GetServiceState {
    param(
        [string]$ServiceName
    )

    $result = 'nao encontrado'
    $safeName = [string](Nz $ServiceName '')
    $query = "SELECT * FROM Win32_Service WHERE Name='" + $safeName.Replace("'", "''") + "'"
    $colSvc = Invoke-WmiQueryCompat -QueryText $query
    foreach ($svc in $colSvc) {
        $script:serviceTotalCount = [long](To-LongSafe $script:serviceTotalCount) + 1
        $result = [string](Nz (SafeWmiProp $svc 'State' '') '-') + ' / StartMode=' + [string](Nz (SafeWmiProp $svc 'StartMode' '') '-')
    }
    return $result
}

function ListLocalAdministrators {
    param(
        [System.IO.StreamWriter]$Writer
    )

    try {
        $hostRef = [string](Nz $script:strComputer $env:COMPUTERNAME)
        $grp = [ADSI]('WinNT://' + $hostRef + '/Administrators,group')
        $members = @($grp.psbase.Invoke('Members'))
        foreach ($member in $members) {
            $name = $member.GetType().InvokeMember('Name', 'GetProperty', $null, $member, $null)
            $adsPath = $member.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $member, $null)
            Write-VbsLine $Writer ("<tr><td>" + (HtmlEncode ([string](Nz $name '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $adsPath '-'))) + "</td></tr>")
        }
    }
    catch {
        Write-VbsLine $Writer ("<tr><td colspan='2'>Nao foi possivel enumerar grupo Administrators: " + (HtmlEncode $_.Exception.Message) + "</td></tr>")
    }
}

function WriteCISSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $rdpDeny = ReadDWORDValue 'SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' -1
    $enableLua = ReadDWORDValue 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' -1
    $consentPrompt = ReadDWORDValue 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' -1
    $smb1 = ReadDWORDValue 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' -1
    $firewallDomain = ReadDWORDValue 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile' 'EnableFirewall' -1
    $firewallPrivate = ReadDWORDValue 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile' 'EnableFirewall' -1
    $firewallPublic = ReadDWORDValue 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile' 'EnableFirewall' -1
    $bitlocker = GetCommandOutput 'cmd /c manage-bde -status'
    $defenderSvc = GetServiceState 'WinDefend'

    Write-VbsLine $Writer "<section id='cis' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Controles Criticos (CIS)</h2>"
    Write-VbsLine $Writer "<table><tr><th>Controle</th><th>Valor coletado</th><th>Observacao Forense</th></tr>"
    Write-VbsLine $Writer ("<tr><td>Acesso remoto (RDP) habilitado/bloqueado</td><td>" + $rdpDeny + "</td><td>Valor de <code>fDenyTSConnections</code>: 0=RDP permitido; 1=RDP bloqueado.</td></tr>")
    Write-VbsLine $Writer ("<tr><td>Controle de Conta de Usuario (UAC) ativo</td><td>" + $enableLua + "</td><td><code>EnableLUA</code>: 1 indica UAC habilitado (recomendado).</td></tr>")
    Write-VbsLine $Writer ("<tr><td>UAC: nivel de prompt para administrador</td><td>" + $consentPrompt + "</td><td><code>ConsentPromptBehaviorAdmin</code>: define o comportamento da elevacao administrativa.</td></tr>")
    Write-VbsLine $Writer ("<tr><td>SMBv1 (servidor) habilitado/desabilitado</td><td>" + $smb1 + "</td><td><code>SMB1</code>: 0/desabilitado e a configuracao recomendada.</td></tr>")
    Write-VbsLine $Writer ("<tr><td>Firewall do Windows (perfil Dominio)</td><td>" + $firewallDomain + "</td><td><code>EnableFirewall</code>: 1=habilitado.</td></tr>")
    Write-VbsLine $Writer ("<tr><td>Firewall do Windows (perfil Privado)</td><td>" + $firewallPrivate + "</td><td><code>EnableFirewall</code> em <code>StandardProfile</code>: 1=habilitado.</td></tr>")
    Write-VbsLine $Writer ("<tr><td>Firewall do Windows (perfil Publico)</td><td>" + $firewallPublic + "</td><td><code>EnableFirewall</code> em <code>PublicProfile</code>: 1=habilitado.</td></tr>")
    Write-VbsLine $Writer ("<tr><td>Antivirus Microsoft Defender (servico WinDefend)</td><td>" + (HtmlEncode $defenderSvc) + "</td><td>Confirme se o servico esta em execucao e o modo de inicializacao.</td></tr>")
    Write-VbsLine $Writer ("<tr><td>Criptografia de disco (BitLocker - manage-bde)</td><td colspan='2'><pre style='white-space:pre-wrap;color:#cbd5e1'>" + (HtmlEncode ([string](Nz $bitlocker ''))) + "</pre></td></tr>")
    Write-VbsLine $Writer "</table>"

    $advFirewall = GetCommandOutputWithTimeout 'cmd /c netsh advfirewall show allprofiles' 45
    $auditPol = GetCommandOutputWithTimeout 'cmd /c auditpol /get /category:*' 45

    Write-VbsLine $Writer "<h3>Politicas locais e GPO (highlight em edicoes locais)</h3>"
    Write-VbsLine $Writer "<table><tr><th>Coleta</th><th>Saida</th></tr>"
    Write-VbsLine $Writer ("<tr><td>Resumo de GPO aplicada (gpresult /r)</td><td><div class='scroll'><pre>" + (HtmlEncode (GetCommandOutputWithTimeout 'cmd /c gpresult /r' 45)) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><td>Auditoria (auditpol /get /category:*)</td><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $auditPol ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><td>Firewall Avancado (netsh advfirewall)</td><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $advFirewall ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><td>Politica de seguranca local (secedit /export, resumo rapido)</td><td><pre><span class='warn'>Exporta apenas politicas e direitos de usuario, com timeout e filtro de linhas para reduzir demora.</span><br>" + (HtmlEncode (GetSeceditSummary)) + "</pre></td></tr>")
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Membros locais do grupo Administrators</h3>"
    Write-VbsLine $Writer "<table><tr><th>Conta</th><th>Fonte</th></tr>"
    ListLocalAdministrators -Writer $Writer
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</section>"
}

function AppendSecurityRecentEventExportRow {
    param(
        [ref]$EventRows,
        [string]$DisplayLabel,
        [string]$ChannelName,
        [string]$XPathQuery,
        [int]$MaxCount,
        [int]$TimeoutSecs,
        [ref]$TotalEvents,
        [ref]$FailCount
    )

    $qPart = ''
    if ([string](Nz $XPathQuery '').Trim() -ne '') {
        $qPart = ' /q:"' + $XPathQuery + '"'
    }
    $fmtLabel = 'TEXT'
    $noteText = 'Canal=' + $ChannelName + ' | c=' + [int](To-LongSafe $MaxCount)
    if ([string](Nz $XPathQuery '').Trim() -ne '') {
        $noteText = $noteText + ' | filtro nivel erro/aviso'
    }

    $exportName = 'recent_' + $DisplayLabel + '_' + [string](Nz $script:strRunId '')
    $filePath = Join-Path (GetRunExportSubDir 'eventos_recentes') ((SanitizeFileNameComponent $exportName) + '.txt')
    $cmdExport = 'cmd /c wevtutil qe "' + $ChannelName + '" /rd:true /c:' + [int](To-LongSafe $MaxCount) + ' /f:text' + $qPart + ' > "' + $filePath + '" 2>&1'
    $cmdOut = GetCommandOutputWithTimeout -CommandText $cmdExport -TimeoutSecs $TimeoutSecs
    $fileHref = HtmlEncode $filePath
    $outBytes = GetFileSizeBytesSafe $filePath
    $sampleInfo = IIfBool ($outBytes -gt 0) 'arquivo gerado' 'sem retorno'

    $hasTimeout = ([string](Nz $cmdOut '')).ToUpperInvariant().Contains('TIMEOUT')
    if ([string](Nz $filePath '').Trim() -ne '' -and $outBytes -gt 0 -and -not $hasTimeout) {
        $TotalEvents.Value = [long](To-LongSafe $TotalEvents.Value) + 1
        $script:securityEventExportCount = [long](To-LongSafe $script:securityEventExportCount) + 1
        $statusTag = "<span class='tag ok'>OK</span>"
        $EventRows.Value = [string](Nz $EventRows.Value '') + "<tr><td>" + (HtmlEncode $DisplayLabel) + "</td><td>" + $statusTag + "</td><td>" + (HtmlEncode $sampleInfo) + "</td><td>" + $fmtLabel + "</td><td class='location-col'><a href='" + $fileHref + "' style='color:#7dd3fc'>" + (HtmlEncode $filePath) + "</a><br><span class='muted'>" + (HtmlEncode (FormatBytes $outBytes)) + "</span></td><td class='location-col'>" + (HtmlEncode $noteText) + "</td></tr>"
    }
    else {
        $FailCount.Value = [long](To-LongSafe $FailCount.Value) + 1
        if ([string](Nz $filePath '').Trim() -ne '' -and $outBytes -gt 0) {
            $script:securityEventExportCount = [long](To-LongSafe $script:securityEventExportCount) + 1
        }
        $fileCell = if ([string](Nz $filePath '').Trim() -ne '') { "<a href='" + (HtmlEncode $filePath) + "' style='color:#7dd3fc'>" + (HtmlEncode $filePath) + "</a>" } else { '-' }
        $EventRows.Value = [string](Nz $EventRows.Value '') + "<tr><td>" + (HtmlEncode $DisplayLabel) + "</td><td><span class='tag warn'>WARN</span></td><td>" + (HtmlEncode $sampleInfo) + "</td><td>" + $fmtLabel + "</td><td class='location-col'>" + $fileCell + "</td><td class='location-col'>" + (HtmlEncode ($noteText + ' | timeout, sem permissao, canal indisponivel ou retorno vazio')) + "</td></tr>"
    }
}

function WriteSecuritySection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $script:processCount = 0
    $script:errorEventCount = 0
    $evtCount = 0
    $eventExportRows = ''
    $script:strSecurityEventExportStatusRows = ''
    $script:securityEventExportCount = 0

    Write-VbsLine $Writer "<section id='seguranca' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Processos</h2>"

    Write-VbsLine $Writer "<h3>Top processos (Working Set)</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Processo</th><th>PID</th><th class='location-col'>Caminho</th><th>Memoria</th><th>Data criacao</th><th class='location-col'>Linha de comando</th></tr>"
    $colProc = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_Process'
    $topCount = 0
    foreach ($proc in $colProc) {
        $script:processCount = [long](To-LongSafe $script:processCount) + 1
        if ($topCount -lt 120) {
            $row = "<tr><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $proc 'Name' '') '-'))) + "</td><td>" + [string](Nz (SafeWmiProp $proc 'ProcessId' '') '-') + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $proc 'ExecutablePath' '') '-'))) + "</td><td>" + (FormatBytes (SafeWmiProp $proc 'WorkingSetSize' 0)) + "</td><td>" + (HtmlEncode (WmiDateToString (SafeWmiProp $proc 'CreationDate' ''))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $proc 'CommandLine' '') '-'))) + "</td></tr>"
            Write-VbsLine $Writer $row
            $topCount = $topCount + 1
        }
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    AppendSecurityRecentEventExportRow -EventRows ([ref]$eventExportRows) -DisplayLabel 'Application' -ChannelName 'Application' -XPathQuery '*[System[(Level=2 or Level=3)]]' -MaxCount 80 -TimeoutSecs 12 -TotalEvents ([ref]$evtCount) -FailCount ([ref]$script:errorEventCount)
    AppendSecurityRecentEventExportRow -EventRows ([ref]$eventExportRows) -DisplayLabel 'System' -ChannelName 'System' -XPathQuery '*[System[(Level=2 or Level=3)]]' -MaxCount 80 -TimeoutSecs 12 -TotalEvents ([ref]$evtCount) -FailCount ([ref]$script:errorEventCount)
    AppendSecurityRecentEventExportRow -EventRows ([ref]$eventExportRows) -DisplayLabel 'Setup (Software/Instalacao)' -ChannelName 'Setup' -XPathQuery '*[System[(Level=2 or Level=3)]]' -MaxCount 60 -TimeoutSecs 10 -TotalEvents ([ref]$evtCount) -FailCount ([ref]$script:errorEventCount)
    AppendSecurityRecentEventExportRow -EventRows ([ref]$eventExportRows) -DisplayLabel 'Security (ultimos eventos)' -ChannelName 'Security' -XPathQuery '' -MaxCount 80 -TimeoutSecs 12 -TotalEvents ([ref]$evtCount) -FailCount ([ref]$script:errorEventCount)
    if ($eventExportRows.Trim() -eq '') { $eventExportRows = "<tr><td colspan='6'>Nenhuma exportacao de eventos realizada.</td></tr>" }
    $script:strSecurityEventExportStatusRows = $eventExportRows

    Write-VbsLine $Writer "<h3>Eventos recentes (wevtutil filtrado)</h3>"
    Write-VbsLine $Writer "<div class='mini-note'>Os eventos foram exportados para arquivos na pasta de resultados da execucao. O HTML exibe apenas status, volume e local do artefato.</div>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer ("<table><tr><th>Canal</th><th>Status</th><th>Amostra</th><th>Formato</th><th>Arquivo</th><th>Observacao</th></tr>" + $eventExportRows + "</table>")
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<div class='grid'>"
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + [long](To-LongSafe $script:processCount) + "</div><div class='kpi-label'>Processos em execucao</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + [long](To-LongSafe $evtCount) + "</div><div class='kpi-label'>Canais de eventos exportados</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + [long](To-LongSafe $script:errorEventCount) + "</div><div class='kpi-label'>Falhas/avisos em exportacao de canais</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + [long](To-LongSafe $script:securityEventExportCount) + "</div><div class='kpi-label'>Arquivos de eventos gerados</div></div>")
    Write-VbsLine $Writer "</div>"
    Write-VbsLine $Writer "</section>"
}

function AbbrevText {
    param(
        [string]$Text,
        [int]$MaxLen
    )

    $n = [int](To-LongSafe $MaxLen)
    if ($n -le 0) { $n = 240 }
    $t = [string](Nz $Text '')
    $t = $t.Replace("`r`n", ' | ').Replace("`r", ' | ').Replace("`n", ' | ')
    while ($t.Contains('  ')) {
        $t = $t.Replace('  ', ' ')
    }
    $t = $t.Trim()
    if ($t.Length -gt $n) { $t = $t.Substring(0, $n) + '...' }
    if ($t -eq '') { $t = '-' }
    return $t
}

function AbbrevTextKeepLines {
    param(
        [string]$Text,
        [int]$MaxLen
    )

    $n = [int](To-LongSafe $MaxLen)
    if ($n -le 0) { $n = 240 }
    $t = [string](Nz $Text '')
    $t = $t.Replace("`r`n", "`n").Replace("`r", "`n")
    if ($t.Length -gt $n) { $t = $t.Substring(0, $n) + "`n..." }
    $trimmedCheck = $t.Replace("`n", '').Replace("`r", '')
    if ($trimmedCheck.Trim() -eq '') { $t = '-' }
    return $t
}

function ConvertRegistryRootToHiveName {
    param(
        $RootKey
    )

    $rk = ([string](Nz $RootKey '')).Trim().ToUpperInvariant()
    switch ($rk) {
        'HKLM' { return 'HKLM' }
        'HKEY_LOCAL_MACHINE' { return 'HKLM' }
        '2147483650' { return 'HKLM' }
        'HKCU' { return 'HKCU' }
        'HKEY_CURRENT_USER' { return 'HKCU' }
        '2147483649' { return 'HKCU' }
        'HKCR' { return 'HKCR' }
        'HKEY_CLASSES_ROOT' { return 'HKCR' }
        '2147483648' { return 'HKCR' }
        'HKU' { return 'HKU' }
        'HKEY_USERS' { return 'HKU' }
        '2147483651' { return 'HKU' }
        'HKCC' { return 'HKCC' }
        'HKEY_CURRENT_CONFIG' { return 'HKCC' }
        '2147483653' { return 'HKCC' }
        default { return 'HKLM' }
    }
}

function BuildRegistryLiteralPath {
    param(
        $RootKey,
        [string]$KeyPath
    )

    $hive = ConvertRegistryRootToHiveName $RootKey
    $sub = [string](Nz $KeyPath '')
    if ($sub.StartsWith('\')) { $sub = $sub.Substring(1) }
    return ('Registry::' + $hive + '\' + $sub)
}

function ReadDWORDValueRoot {
    param(
        $RootKey,
        [string]$KeyPath,
        [string]$ValueName,
        $DefaultValue
    )

    EnsureTelemetryIndexes
    $regPath = BuildRegistryLiteralPath -RootKey $RootKey -KeyPath $KeyPath
    $idxKey = 'DWORD|' + ([string](Nz $RootKey 'HKLM')).ToUpperInvariant() + '|' + ([string](Nz $KeyPath '')).ToUpperInvariant() + '|' + ([string](Nz $ValueName '')).ToUpperInvariant()
    if ($script:RegistryValueIndex.ContainsKey($idxKey)) {
        return $script:RegistryValueIndex[$idxKey]
    }

    $result = $DefaultValue
    try {
        $val = Get-ItemPropertyValue -LiteralPath $regPath -Name $ValueName -ErrorAction Stop
        if ($null -eq $val) {
            $result = $DefaultValue
        }
        else {
            $result = [long](To-LongSafe $val)
        }
    }
    catch {
        $result = $DefaultValue
    }
    $script:RegistryValueIndex[$idxKey] = $result
    return $result
}

function ReadRegistryTextValueRoot {
    param(
        $RootKey,
        [string]$KeyPath,
        [string]$ValueName,
        $DefaultValue
    )

    EnsureTelemetryIndexes
    $regPath = BuildRegistryLiteralPath -RootKey $RootKey -KeyPath $KeyPath
    $idxKey = 'STRING|' + ([string](Nz $RootKey 'HKLM')).ToUpperInvariant() + '|' + ([string](Nz $KeyPath '')).ToUpperInvariant() + '|' + ([string](Nz $ValueName '')).ToUpperInvariant()
    if ($script:RegistryValueIndex.ContainsKey($idxKey)) {
        return [string](Nz $script:RegistryValueIndex[$idxKey] $DefaultValue)
    }

    $result = $DefaultValue
    try {
        $p = Get-ItemProperty -LiteralPath $regPath -ErrorAction Stop
    }
    catch {
        $script:RegistryValueIndex[$idxKey] = $DefaultValue
        return $DefaultValue
    }

    if ($null -eq $p.PSObject -or -not $p.PSObject.Properties[$ValueName]) {
        $script:RegistryValueIndex[$idxKey] = $DefaultValue
        return $DefaultValue
    }

    $v = $p.PSObject.Properties[$ValueName].Value
    if ($null -eq $v) {
        $script:RegistryValueIndex[$idxKey] = $DefaultValue
        return $DefaultValue
    }
    if ($v -is [System.Array]) {
        $result = (($v | ForEach-Object { [string](Nz $_ '') }) -join '; ')
        $script:RegistryValueIndex[$idxKey] = $result
        return $result
    }
    $s = [string](Nz $v '')
    if ($s -eq '') {
        $script:RegistryValueIndex[$idxKey] = $DefaultValue
        return $DefaultValue
    }
    $script:RegistryValueIndex[$idxKey] = $s
    return $s
}

function RegistryKeyExistsRoot {
    param(
        $RootKey,
        [string]$KeyPath
    )
    $regPath = BuildRegistryLiteralPath -RootKey $RootKey -KeyPath $KeyPath
    return (Test-Path -LiteralPath $regPath)
}

function RegistryValueCount {
    param(
        $RootKey,
        [string]$KeyPath
    )

    $regPath = BuildRegistryLiteralPath -RootKey $RootKey -KeyPath $KeyPath
    try {
        $item = Get-Item -LiteralPath $regPath -ErrorAction Stop
        if ($null -eq $item.Property) { return 0 }
        return [int]$item.Property.Count
    }
    catch {
        return 0
    }
}

function RegistrySubKeyCount {
    param(
        $RootKey,
        [string]$KeyPath
    )

    $regPath = BuildRegistryLiteralPath -RootKey $RootKey -KeyPath $KeyPath
    try {
        $subs = Get-ChildItem -LiteralPath $regPath -ErrorAction Stop
        return [int]$subs.Count
    }
    catch {
        return 0
    }
}

function RegistryServiceStartName {
    param(
        $Value
    )

    switch ([long](To-LongSafe $Value)) {
        0 { return 'Boot' }
        1 { return 'System' }
        2 { return 'Auto' }
        3 { return 'Manual' }
        4 { return 'Disabled' }
        default { return [string](Nz $Value '') }
    }
}

function UpdateThreatRegistryBucketCounters {
    param(
        [string]$GroupName
    )

    $g = ([string](Nz $GroupName '')).Trim().ToUpperInvariant()
    switch ($g) {
        'PERSISTENCIA' {
            $script:threatRegistryPersistHits = [long](To-LongSafe $script:threatRegistryPersistHits) + 1
        }
        'PERSISTENCIA/EVASAO' {
            $script:threatRegistryPersistHits = [long](To-LongSafe $script:threatRegistryPersistHits) + 1
        }
        'RDP' {
            $script:threatRegistryAccessHits = [long](To-LongSafe $script:threatRegistryAccessHits) + 1
        }
        'EVENTLOG' {
            $script:threatRegistryTelemetryHits = [long](To-LongSafe $script:threatRegistryTelemetryHits) + 1
        }
        'POWERSHELL' {
            $script:threatRegistryTelemetryHits = [long](To-LongSafe $script:threatRegistryTelemetryHits) + 1
        }
        'SYSMON' {
            $script:threatRegistryTelemetryHits = [long](To-LongSafe $script:threatRegistryTelemetryHits) + 1
        }
        'VSS' {
            $script:threatRegistryTelemetryHits = [long](To-LongSafe $script:threatRegistryTelemetryHits) + 1
        }
        'CREDENCIAIS/LSA' {
            $script:threatRegistryCredHits = [long](To-LongSafe $script:threatRegistryCredHits) + 1
        }
        'FIREWALL' {
            $script:threatRegistryNetworkHits = [long](To-LongSafe $script:threatRegistryNetworkHits) + 1
        }
        'SMB/BITS' {
            $script:threatRegistryNetworkHits = [long](To-LongSafe $script:threatRegistryNetworkHits) + 1
        }
        default {
            $script:threatRegistryAccessHits = [long](To-LongSafe $script:threatRegistryAccessHits) + 1
        }
    }
}

function AddThreatRegistryCheckRow {
    param(
        [ref]$RegistryRows,
        [string]$GroupName,
        [string]$RootName,
        [string]$KeyPath,
        [string]$ValueName,
        [string]$ValueDisplay,
        [string]$SeverityText,
        [string]$NoteText
    )

    $sev = ([string](Nz $SeverityText 'INFO')).ToUpperInvariant()
    $css = 'ok'
    switch ($sev) {
        'ALERTA' {
            $css = 'bad'
            $script:threatRegistryAlertCount = [long](To-LongSafe $script:threatRegistryAlertCount) + 1
        }
        'WARN' {
            $css = 'warn'
            $script:threatRegistryWarnCount = [long](To-LongSafe $script:threatRegistryWarnCount) + 1
        }
        default {
            $css = 'ok'
            $script:threatRegistryInfoCount = [long](To-LongSafe $script:threatRegistryInfoCount) + 1
        }
    }

    $script:threatRegistryChecks = [long](To-LongSafe $script:threatRegistryChecks) + 1
    UpdateThreatRegistryBucketCounters -GroupName $GroupName

    $RegistryRows.Value = [string](Nz $RegistryRows.Value '') + "<tr><td>" + (HtmlEncode $GroupName) + "</td><td>" + (HtmlEncode $RootName) + "</td><td class='location-col'>" + (HtmlEncode $KeyPath) + "</td><td>" + (HtmlEncode $ValueName) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz $ValueDisplay '-'))) + "</td><td><span class='tag " + $css + "'>" + (HtmlEncode $sev) + "</span></td><td class='location-col'>" + (HtmlEncode $NoteText) + "</td></tr>"
}

function ExportTextArtifact {
    param(
        [string]$SubDirName,
        [string]$FileBaseName,
        [string]$FileExt,
        [string]$ContentText
    )

    $folderPath = GetRunExportSubDir $SubDirName
    if ([string](Nz $folderPath '').Trim() -eq '') { return '' }

    $extNorm = ([string](Nz $FileExt '')).Trim().ToLowerInvariant()
    if ($extNorm -eq '') { $extNorm = 'txt' }
    if ($extNorm.StartsWith('.')) { $extNorm = $extNorm.Substring(1) }

    $fullPath = Join-Path $folderPath ((SanitizeFileNameComponent $FileBaseName) + '.' + $extNorm)
    try {
        [System.IO.File]::WriteAllText($fullPath, (HtmlAsciiSafe ([string](Nz $ContentText ''))), (New-Windows1252NoBomEncoding))
        return $fullPath
    }
    catch {
        return ''
    }
}

function AppendThreatRegistrySnapshot {
    param(
        [ref]$RegistrySnapshotRows,
        [string]$GroupName,
        [string]$CommandText
    )

    $outText = GetCommandOutputWithTimeout -CommandText $CommandText -TimeoutSecs 8
    $exportPath = ExportTextArtifact -SubDirName 'ameacas_registro' -FileBaseName ('snapshot_' + $GroupName + '_' + (ShortCommandForLog $CommandText) + '_' + [string](Nz $script:strRunId '')) -FileExt 'txt' -ContentText $outText
    $noteTxt = AbbrevText -Text (([string](Nz $outText '')).Replace("`r`n", ' | ')) -MaxLen 220
    if ([string](Nz $exportPath '').Trim() -ne '') {
        $script:threatRegistrySnapshotExportCount = [long](To-LongSafe $script:threatRegistrySnapshotExportCount) + 1
        $outBytes = GetFileSizeBytesSafe $exportPath
        $statusTag = "<span class='tag ok'>OK</span>"
        $RegistrySnapshotRows.Value = [string](Nz $RegistrySnapshotRows.Value '') + "<tr><td>" + (HtmlEncode $GroupName) + "</td><td><code>" + (HtmlEncode (ShortCommandForLog $CommandText)) + "</code></td><td>" + $statusTag + "</td><td class='location-col'><a href='" + (HtmlEncode $exportPath) + "' style='color:#7dd3fc'>" + (HtmlEncode $exportPath) + "</a></td><td>" + (HtmlEncode (FormatBytes $outBytes)) + "</td><td class='location-col'>" + (HtmlEncode $noteTxt) + "</td></tr>"
        LogCustody -Etapa 'REG_SNAPSHOT_EXPORT' -Status 'OK' -Detalhes ($GroupName + ' | ' + $exportPath)
    }
    else {
        $RegistrySnapshotRows.Value = [string](Nz $RegistrySnapshotRows.Value '') + "<tr><td>" + (HtmlEncode $GroupName) + "</td><td><code>" + (HtmlEncode (ShortCommandForLog $CommandText)) + "</code></td><td><span class='tag warn'>WARN</span></td><td>-</td><td>-</td><td class='location-col'>Falha ao exportar snapshot. " + (HtmlEncode $noteTxt) + "</td></tr>"
        LogCustody -Etapa 'REG_SNAPSHOT_EXPORT' -Status 'WARN' -Detalhes ($GroupName + ' | Falha na exportacao')
    }
}

function CollectThreatRegistryChecks {
    param(
        [ref]$RegistryRows,
        [ref]$RegistrySnapshotRows
    )

    $RegistryRows.Value = ''
    $RegistrySnapshotRows.Value = ''

    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Control\Terminal Server' -ValueName 'fDenyTSConnections' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'RDP' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Control\Terminal Server' -ValueName 'fDenyTSConnections' -ValueDisplay ([string]$vDword) -SeverityText (IIfBool ([long](To-LongSafe $vDword) -eq 0) 'WARN' 'INFO') -NoteText '0 permite RDP; correlacione com 4624 Tipo 10/4778/4779.'
    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ValueName 'PortNumber' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'RDP' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ValueName 'PortNumber' -ValueDisplay ([string]$vDword) -SeverityText (IIfBool (([long](To-LongSafe $vDword) -gt 0) -and ([long](To-LongSafe $vDword) -ne 3389)) 'WARN' 'INFO') -NoteText 'Porta do listener RDP.'
    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ValueName 'UserAuthentication' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'RDP' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ValueName 'UserAuthentication' -ValueDisplay ([string]$vDword) -SeverityText (IIfBool ([long](To-LongSafe $vDword) -eq 0) 'WARN' 'INFO') -NoteText '0 pode indicar NLA desabilitado.'

    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ValueName 'EnableScriptBlockLogging' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'PowerShell' -RootName 'HKLM' -KeyPath 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ValueName 'EnableScriptBlockLogging' -ValueDisplay ([string]$vDword) -SeverityText (IIfBool ([long](To-LongSafe $vDword) -eq 1) 'INFO' 'WARN') -NoteText 'Visibilidade do evento 4104.'
    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ValueName 'EnableModuleLogging' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'PowerShell' -RootName 'HKLM' -KeyPath 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ValueName 'EnableModuleLogging' -ValueDisplay ([string]$vDword) -SeverityText (IIfBool ([long](To-LongSafe $vDword) -eq 1) 'INFO' 'WARN') -NoteText 'Visibilidade do evento 4103.'
    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ValueName 'EnableTranscripting' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'PowerShell' -RootName 'HKLM' -KeyPath 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ValueName 'EnableTranscripting' -ValueDisplay ([string]$vDword) -SeverityText (IIfBool ([long](To-LongSafe $vDword) -eq 1) 'INFO' 'WARN') -NoteText 'Transcricao PowerShell.'

    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\EventLog' -ValueName 'Start' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'EventLog' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\EventLog' -ValueName 'Start' -ValueDisplay (RegistryServiceStartName $vDword) -SeverityText (IIfBool ([long](To-LongSafe $vDword) -eq 4) 'ALERTA' (IIfBool ([long](To-LongSafe $vDword) -eq 2) 'INFO' 'WARN')) -NoteText 'Servico de logs do Windows.'

    $cnt = RegistryValueCount -RootKey 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Persistencia' -RootName 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ValueName '(count)' -ValueDisplay ([string]$cnt) -SeverityText (IIfBool ($cnt -gt 3) 'WARN' 'INFO') -NoteText 'Autostart da maquina.'
    $cnt = RegistryValueCount -RootKey 'HKCU' -KeyPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Persistencia' -RootName 'HKCU' -KeyPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ValueName '(count)' -ValueDisplay ([string]$cnt) -SeverityText (IIfBool ($cnt -gt 4) 'WARN' 'INFO') -NoteText 'Autostart do usuario atual.'
    $cnt = RegistryValueCount -RootKey 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Persistencia' -RootName 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ValueName '(count)' -ValueDisplay ([string]$cnt) -SeverityText (IIfBool ($cnt -gt 0) 'WARN' 'INFO') -NoteText 'Execucao unica pendente.'
    $cnt = RegistryValueCount -RootKey 'HKCU' -KeyPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Persistencia' -RootName 'HKCU' -KeyPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ValueName '(count)' -ValueDisplay ([string]$cnt) -SeverityText (IIfBool ($cnt -gt 0) 'WARN' 'INFO') -NoteText 'Execucao unica (usuario).'

    $vText = ReadRegistryTextValueRoot -RootKey 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ValueName 'Shell' -DefaultValue '-'
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Persistencia' -RootName 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ValueName 'Shell' -ValueDisplay (AbbrevText -Text $vText -MaxLen 180) -SeverityText (IIfBool (([string](Nz $vText '')).Trim().ToUpperInvariant() -ne 'EXPLORER.EXE') 'ALERTA' 'INFO') -NoteText 'Shell padrao esperado: explorer.exe'
    $vText = ReadRegistryTextValueRoot -RootKey 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ValueName 'Userinit' -DefaultValue '-'
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Persistencia' -RootName 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ValueName 'Userinit' -ValueDisplay (AbbrevText -Text $vText -MaxLen 180) -SeverityText (IIfBool (([string](Nz $vText '')).ToUpperInvariant().IndexOf('USERINIT.EXE') -lt 0) 'ALERTA' 'INFO') -NoteText 'Verificar alteracoes em userinit.exe'

    $cnt = RegistrySubKeyCount -RootKey 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Persistencia/Evasao' -RootName 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ValueName '(subkeys)' -ValueDisplay ([string]$cnt) -SeverityText (IIfBool ($cnt -gt 0) 'WARN' 'INFO') -NoteText 'IFEO pode ser usado para hijack/debugger.'

    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ValueName 'LoadAppInit_DLLs' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Persistencia/Evasao' -RootName 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ValueName 'LoadAppInit_DLLs' -ValueDisplay ([string]$vDword) -SeverityText (IIfBool ([long](To-LongSafe $vDword) -eq 1) 'WARN' 'INFO') -NoteText 'Ativa carga de AppInit DLLs.'
    $vText = ReadRegistryTextValueRoot -RootKey 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ValueName 'AppInit_DLLs' -DefaultValue '-'
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Persistencia/Evasao' -RootName 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -ValueName 'AppInit_DLLs' -ValueDisplay (AbbrevText -Text $vText -MaxLen 180) -SeverityText (IIfBool (([string](Nz $vText '')).Trim() -ne '' -and ([string](Nz $vText '')).Trim() -ne '-') 'ALERTA' 'INFO') -NoteText 'DLLs para injecao via AppInit.'

    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ValueName 'UseLogonCredential' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Credenciais/LSA' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ValueName 'UseLogonCredential' -ValueDisplay ([string]$vDword) -SeverityText (IIfBool ([long](To-LongSafe $vDword) -eq 1) 'ALERTA' 'INFO') -NoteText '1 aumenta risco de credenciais em memoria.'
    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'RunAsPPL' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Credenciais/LSA' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'RunAsPPL' -ValueDisplay ([string]$vDword) -SeverityText (IIfBool ([long](To-LongSafe $vDword) -eq 1) 'INFO' 'WARN') -NoteText 'Protecao LSA/PPL.'
    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'LmCompatibilityLevel' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Credenciais/LSA' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'LmCompatibilityLevel' -ValueDisplay ([string]$vDword) -SeverityText (IIfBool (([long](To-LongSafe $vDword) -gt -1) -and ([long](To-LongSafe $vDword) -lt 3)) 'WARN' 'INFO') -NoteText 'Niveis baixos favorecem NTLM legado.'

    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile' -ValueName 'EnableFirewall' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Firewall' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile' -ValueName 'EnableFirewall' -ValueDisplay ([string]$vDword) -SeverityText (IIfBool ([long](To-LongSafe $vDword) -eq 0) 'WARN' 'INFO') -NoteText 'Firewall dominio.'
    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile' -ValueName 'EnableFirewall' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Firewall' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile' -ValueName 'EnableFirewall' -ValueDisplay ([string]$vDword) -SeverityText (IIfBool ([long](To-LongSafe $vDword) -eq 0) 'WARN' 'INFO') -NoteText 'Firewall publico.'
    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ValueName 'SMB1' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'SMB/BITS' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ValueName 'SMB1' -ValueDisplay ([string]$vDword) -SeverityText (IIfBool ([long](To-LongSafe $vDword) -eq 1) 'WARN' 'INFO') -NoteText 'SMBv1 legado.'
    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\BITS' -ValueName 'Start' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'SMB/BITS' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\BITS' -ValueName 'Start' -ValueDisplay (RegistryServiceStartName $vDword) -SeverityText 'INFO' -NoteText 'Servico BITS (correlacionar com 59/60/63).'

    if ((RegistryKeyExistsRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\Sysmon64') -or (RegistryKeyExistsRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\Sysmon')) {
        AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Sysmon' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\Sysmon64|Sysmon' -ValueName '(exist)' -ValueDisplay 'sim' -SeverityText 'INFO' -NoteText 'Servico Sysmon detectado.'
    }
    else {
        AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Sysmon' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\Sysmon64|Sysmon' -ValueName '(exist)' -ValueDisplay 'nao' -SeverityText 'WARN' -NoteText 'Sysmon nao detectado (opcional, mas recomendado).'
    }
    $sysmonChannelExists = RegistryKeyExistsRoot -RootKey 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational'
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'Sysmon' -RootName 'HKLM' -KeyPath 'SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational' -ValueName '(exist)' -ValueDisplay (IIfBool $sysmonChannelExists 'sim' 'nao') -SeverityText (IIfBool $sysmonChannelExists 'INFO' 'WARN') -NoteText 'Canal operacional do Sysmon.'

    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\VSS' -ValueName 'Start' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'VSS' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\VSS' -ValueName 'Start' -ValueDisplay (RegistryServiceStartName $vDword) -SeverityText 'INFO' -NoteText 'Servico VSS.'
    $vDword = ReadDWORDValueRoot -RootKey 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\VolSnap' -ValueName 'Start' -DefaultValue -1
    AddThreatRegistryCheckRow -RegistryRows $RegistryRows -GroupName 'VSS' -RootName 'HKLM' -KeyPath 'SYSTEM\CurrentControlSet\Services\VolSnap' -ValueName 'Start' -ValueDisplay (RegistryServiceStartName $vDword) -SeverityText 'INFO' -NoteText 'Driver VolSnap (shadow copy).'

    AppendThreatRegistrySnapshot -RegistrySnapshotRows $RegistrySnapshotRows -GroupName 'RDP' -CommandText 'cmd /c reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"'
    AppendThreatRegistrySnapshot -RegistrySnapshotRows $RegistrySnapshotRows -GroupName 'PowerShell' -CommandText 'cmd /c reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"'
    AppendThreatRegistrySnapshot -RegistrySnapshotRows $RegistrySnapshotRows -GroupName 'PowerShell' -CommandText 'cmd /c reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"'
    AppendThreatRegistrySnapshot -RegistrySnapshotRows $RegistrySnapshotRows -GroupName 'Run (HKLM)' -CommandText 'cmd /c reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"'
    AppendThreatRegistrySnapshot -RegistrySnapshotRows $RegistrySnapshotRows -GroupName 'Run (HKCU)' -CommandText 'cmd /c reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"'
    AppendThreatRegistrySnapshot -RegistrySnapshotRows $RegistrySnapshotRows -GroupName 'Winlogon' -CommandText 'cmd /c reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell'
    AppendThreatRegistrySnapshot -RegistrySnapshotRows $RegistrySnapshotRows -GroupName 'WDigest' -CommandText 'cmd /c reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"'
}

function GetThreatHuntResultsDir {
    $dirPath = 'resultados_coletados'
    $fullPath = Join-Path $PSScriptRoot $dirPath
    try { [void](New-Item -ItemType Directory -Path $fullPath -Force -ErrorAction Stop) } catch {}
    return $dirPath
}

function ThreatHuntFileStamp {
    $dt = Get-Date
    $msPart = [int]$dt.Millisecond
    if ($msPart -lt 0) { $msPart = 0 }
    return ('{0:yyyyMMdd_HHmmss}_{1:000}' -f $dt, $msPart)
}

function BuildThreatHuntResultadosFilePath {
    param(
        [string]$ToolName,
        [string]$CategoryName,
        [string]$FileExt
    )

    $extNorm = ([string](Nz $FileExt '')).Trim()
    if ($extNorm -eq '') { $extNorm = 'result' }
    if ($extNorm.StartsWith('.')) { $extNorm = $extNorm.Substring(1) }
    return (GetThreatHuntResultsDir) + '\' + (ThreatHuntFileStamp) + '_' + (SanitizeFileNameComponent $ToolName) + '_' + (SanitizeFileNameComponent $CategoryName) + '.' + $extNorm.ToLowerInvariant()
}

function ExportThreatHuntResultFile {
    param(
        [string]$ToolName,
        [string]$CategoryName,
        [string]$ContentText
    )

    $relPath = BuildThreatHuntResultadosFilePath -ToolName $ToolName -CategoryName $CategoryName -FileExt 'result'
    $fullPath = if ([System.IO.Path]::IsPathRooted($relPath)) { $relPath } else { Join-Path $PSScriptRoot $relPath }
    $rawText = [string](Nz $ContentText '')

    try {
        $sw = Open-VbsTextWriter -Path $fullPath
    }
    catch {
        return ''
    }

    try {
        try {
            $sw.Write($rawText)
        }
        catch {
            $sw.Write((HtmlAsciiSafe $rawText))
        }
        $sw.Close()
        return $relPath
    }
    catch {
        try { $sw.Close() } catch {}
        return ''
    }
}

function GetThreatHuntAdDomainName {
    $dom = ([string](Nz $env:USERDNSDOMAIN '')).Trim()
    if ($dom -ne '') { return $dom }

    try {
        $colCs = Invoke-WmiQueryCompat -QueryText 'SELECT Domain,PartOfDomain FROM Win32_ComputerSystem'
        foreach ($cs in $colCs) {
            if ([bool](Nz (SafeWmiProp $cs 'PartOfDomain' $false) $false)) {
                $dom = ([string](Nz (SafeWmiProp $cs 'Domain' '') '')).Trim()
                if ($dom -ne '') { return $dom }
            }
        }
    }
    catch {
    }
    return ''
}

function GetThreatHuntDnsQueryDomain {
    $d = ([string](Nz (GetThreatHuntAdDomainName) '')).Trim()
    if ($d -eq '') { $d = 'google.com' }
    return $d
}

function ExecuteCommandWithLocalTimeoutEx {
    param(
        [string]$CommandText,
        [int]$TimeoutSecs,
        [ref]$OutText,
        [ref]$ExitCodeOut,
        [ref]$TimedOut
    )

    $OutText.Value = ''
    $ExitCodeOut.Value = -1
    $TimedOut.Value = $false

    $outPath = [System.IO.Path]::GetTempFileName()
    $errPath = [System.IO.Path]::GetTempFileName()
    try {
        $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $CommandText -NoNewWindow -PassThru -RedirectStandardOutput $outPath -RedirectStandardError $errPath
    }
    catch {
        $OutText.Value = 'Falha ao executar comando: ' + $_.Exception.Message
        $ExitCodeOut.Value = -2
        try { Remove-Item -LiteralPath $outPath -Force -ErrorAction SilentlyContinue } catch {}
        try { Remove-Item -LiteralPath $errPath -Force -ErrorAction SilentlyContinue } catch {}
        return
    }

    try {
        $limit = [int](To-LongSafe $TimeoutSecs)
        $completed = $true
        if ($limit -gt 0) {
            $completed = $proc.WaitForExit($limit * 1000)
        }
        else {
            [void]$proc.WaitForExit()
        }

        if (-not $completed) {
            try { $proc.Kill() } catch {}
            $TimedOut.Value = $true
            $ExitCodeOut.Value = 124
            $OutText.Value = '[TIMEOUT APOS ' + [int](To-LongSafe $TimeoutSecs) + 's] Comando interrompido por demora.'
            return
        }

        [void]$proc.WaitForExit()
        $out = ''; $errOut = ''
        try { $out = [System.IO.File]::ReadAllText($outPath) } catch { $out = '' }
        try { $errOut = [System.IO.File]::ReadAllText($errPath) } catch { $errOut = '' }

        $outTrim = ([string](Nz $out '')).Trim()
        $errTrim = ([string](Nz $errOut '')).Trim()
        $finalOut = ''
        if ($outTrim -ne '') {
            $finalOut = $outTrim
            if ($errTrim -ne '') {
                $finalOut = $finalOut + "`r`n[stderr]`r`n" + $errTrim
            }
        }
        else {
            $finalOut = $errTrim
        }
        if (([string](Nz $finalOut '')).Trim() -eq '') { $finalOut = '(sem saida)' }

        $ExitCodeOut.Value = [int](To-LongSafe $proc.ExitCode)
        $OutText.Value = $finalOut
    }
    finally {
        try { Remove-Item -LiteralPath $outPath -Force -ErrorAction SilentlyContinue } catch {}
        try { Remove-Item -LiteralPath $errPath -Force -ErrorAction SilentlyContinue } catch {}
    }
}

function RunThreatHuntCommandSnapshot {
    param(
        [string]$DisplayLabel,
        [string]$ToolName,
        [string]$CategoryName,
        [string]$CmdText,
        [int]$TimeoutSecs,
        [ref]$RowsHtml,
        [ref]$OkCount,
        [ref]$FailCount,
        [string]$ExtraNote
    )

    $effectiveTimeout = [int](To-LongSafe $TimeoutSecs)
    $globalDefault = [int](To-LongSafe $script:DefaultCommandTimeoutSecs)
    if ($globalDefault -gt 0 -and ($effectiveTimeout -le 0 -or $effectiveTimeout -gt $globalDefault)) {
        $effectiveTimeout = $globalDefault
    }
    if ($effectiveTimeout -lt 0) { $effectiveTimeout = 0 }

    Write-ProgressLog -Message ('THREAT_CMD START (' + $effectiveTimeout + 's): ' + $ToolName + '/' + $CategoryName) -Force
    $cmdOut = ''
    $exitCode = -1
    $timedOut = $false
    ExecuteCommandWithLocalTimeoutEx -CommandText $CmdText -TimeoutSecs $effectiveTimeout -OutText ([ref]$cmdOut) -ExitCodeOut ([ref]$exitCode) -TimedOut ([ref]$timedOut)

    $stampLocal = TimestampLocalMillis (Get-Date)
    $noteExtra = ([string](Nz $ExtraNote '')).Trim()
    $statusTxt = 'OK'
    $noteTxt = ''

    if ($timedOut) {
        $statusTxt = 'WARN'
        $noteTxt = 'Timeout local apos ' + $effectiveTimeout + 's.'
    }
    elseif ([int](To-LongSafe $exitCode) -ne 0) {
        $statusTxt = 'WARN'
        $noteTxt = 'ExitCode=' + [int](To-LongSafe $exitCode)
    }
    elseif (-not (HasUsefulOutput $cmdOut)) {
        $statusTxt = 'WARN'
        $noteTxt = 'Comando concluiu sem retorno util.'
    }

    if ($noteExtra -ne '') {
        if ($noteTxt -ne '') {
            $noteTxt = $noteTxt + ' | ' + $noteExtra
        }
        else {
            $noteTxt = $noteExtra
        }
    }

    $headerText = 'timestamp_local=' + $stampLocal + "`r`n" +
    'rotulo=' + $DisplayLabel + "`r`n" +
    'tool=' + $ToolName + "`r`n" +
    'categoria=' + $CategoryName + "`r`n" +
    'timeout_s=' + $effectiveTimeout + "`r`n" +
    'exit_code=' + [int](To-LongSafe $exitCode) + "`r`n" +
    'timed_out=' + ([string]$timedOut).ToLowerInvariant() + "`r`n" +
    'comando=' + $CmdText + "`r`n" + ('-' * 72) + "`r`n"
    $resultFile = ExportThreatHuntResultFile -ToolName $ToolName -CategoryName $CategoryName -ContentText ($headerText + [string](Nz $cmdOut ''))

    if ($statusTxt -eq 'OK' -and ([string](Nz $resultFile '')).Trim() -ne '') {
        $OkCount.Value = [long](To-LongSafe $OkCount.Value) + 1
        LogCustody -Etapa 'THREAT_HUNT_CMD' -Status 'OK' -Detalhes ($ToolName + '/' + $CategoryName + ' | arquivo=' + $resultFile)
        $statusHtml = "<span class='tag ok'>OK</span>"
        if ($noteTxt -eq '') { $noteTxt = 'Concluido com sucesso.' }
    }
    else {
        $FailCount.Value = [long](To-LongSafe $FailCount.Value) + 1
        $statusHtml = "<span class='tag warn'>WARN</span>"
        if (([string](Nz $resultFile '')).Trim() -eq '') {
            if ($noteTxt -ne '') { $noteTxt = $noteTxt + ' | ' }
            $noteTxt = $noteTxt + 'Falha ao gravar arquivo .result.'
        }
    }

    $fileCell = IIfBool (([string](Nz $resultFile '')).Trim() -ne '') ("<a href='" + (HtmlEncode $resultFile) + "' style='color:#7dd3fc'>" + (HtmlEncode $resultFile) + '</a>') '-'
    $RowsHtml.Value = [string](Nz $RowsHtml.Value '') + "<tr><td>" + (HtmlEncode $ToolName) + "</td><td>" + (HtmlEncode $CategoryName) + "</td><td>" + $statusHtml + "</td><td>" + (HtmlEncode ([string][int](To-LongSafe $exitCode))) + "</td><td>" + (HtmlEncode ([string]$effectiveTimeout)) + "</td><td class='location-col'>" + $fileCell + "</td><td class='location-col'><code>" + (HtmlEncode (ShortCommandForLog $CmdText)) + "</code></td><td class='location-col'>" + (HtmlEncode $noteTxt) + "</td></tr>"
    Write-ProgressLog -Message ('THREAT_CMD END: ' + $ToolName + '/' + $CategoryName + ' -> ' + $statusTxt) -Force
}

function AppendThreatHuntCommandSkipRow {
    param(
        [ref]$RowsHtml,
        [string]$ToolName,
        [string]$CategoryName,
        [string]$NoteText
    )

    $contentText = 'timestamp_local=' + (TimestampLocalMillis (Get-Date)) + "`r`n" +
    'tool=' + $ToolName + "`r`n" +
    'categoria=' + $CategoryName + "`r`n" +
    'status=SKIPPED' + "`r`n" +
    'motivo=' + [string](Nz $NoteText '-')
    $resultFile = ExportThreatHuntResultFile -ToolName $ToolName -CategoryName $CategoryName -ContentText $contentText
    $fileCell = IIfBool (([string](Nz $resultFile '')).Trim() -ne '') ("<a href='" + (HtmlEncode $resultFile) + "' style='color:#7dd3fc'>" + (HtmlEncode $resultFile) + '</a>') '-'
    $RowsHtml.Value = [string](Nz $RowsHtml.Value '') + "<tr><td>" + (HtmlEncode $ToolName) + "</td><td>" + (HtmlEncode $CategoryName) + "</td><td><span class='tag warn'>SKIP</span></td><td>-</td><td>-</td><td class='location-col'>" + $fileCell + "</td><td class='location-col'>-</td><td class='location-col'>" + (HtmlEncode $NoteText) + "</td></tr>"
}

function CollectThreatHuntCommandSnapshots {
    param(
        [ref]$RowsHtml,
        [ref]$OkCount,
        [ref]$FailCount,
        [ref]$SkipCount
    )

    $RowsHtml.Value = ''
    $OkCount.Value = 0
    $FailCount.Value = 0
    $SkipCount.Value = 0

    $probeHost = ([string](Nz $script:strComputer '')).Trim()
    if ($probeHost -eq '') { $probeHost = 'localhost' }
    $dnsDomain = GetThreatHuntDnsQueryDomain
    $adDomain = GetThreatHuntAdDomainName

    RunThreatHuntCommandSnapshot -DisplayLabel 'PowerShell Test-NetConnection (conectividade)' -ToolName 'powershell' -CategoryName 'conectividade' -CmdText ("powershell -NoProfile -Command ""Test-NetConnection -ComputerName '" + (EscapePsSingleQuoted $probeHost) + "' -Port 445 -InformationLevel Detailed | Format-List * | Out-String -Width 260""") -TimeoutSecs 20 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'getmac /v /fo csv' -ToolName 'getmac' -CategoryName 'interfaces_mac' -CmdText 'cmd /c getmac /v /fo csv 2>&1' -TimeoutSecs 20 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'nslookup -type=ANY dominio' -ToolName 'nslookup' -CategoryName 'dns_any' -CmdText ('cmd /c nslookup -type=ANY "' + $dnsDomain + '" 2>&1') -TimeoutSecs 20 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'systeminfo' -ToolName 'systeminfo' -CategoryName 'inventario_so' -CmdText 'cmd /c systeminfo 2>&1' -TimeoutSecs 90 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'wmic os get ...' -ToolName 'wmic' -CategoryName 'inventario_os_wmic' -CmdText 'cmd /c wmic os get Caption,Version,BuildNumber,OSArchitecture,CSName,LastBootUpTime,InstallDate /format:list 2>&1' -TimeoutSecs 35 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'tasklist /v /fo csv' -ToolName 'tasklist' -CategoryName 'processos_csv' -CmdText 'cmd /c tasklist /v /fo csv 2>&1' -TimeoutSecs 45 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'tasklist /fi imagename=svchost.exe' -ToolName 'tasklist' -CategoryName 'svchost_filtro' -CmdText 'cmd /c tasklist /fi "imagename eq svchost.exe" 2>&1' -TimeoutSecs 20 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'sc query type= service state= all' -ToolName 'sc' -CategoryName 'servicos_enum' -CmdText 'cmd /c sc query type^= service state^= all 2>&1' -TimeoutSecs 35 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'driverquery /fo table /si' -ToolName 'driverquery' -CategoryName 'drivers_assinatura' -CmdText 'cmd /c driverquery /fo table /si 2>&1' -TimeoutSecs 45 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'net user' -ToolName 'net' -CategoryName 'contas_locais' -CmdText 'cmd /c net user 2>&1' -TimeoutSecs 20 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'whoami /priv' -ToolName 'whoami' -CategoryName 'privilegios' -CmdText 'cmd /c whoami /priv 2>&1' -TimeoutSecs 20 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'schtasks /query /fo LIST /v' -ToolName 'schtasks' -CategoryName 'tarefas_schtasks' -CmdText 'cmd /c schtasks /query /fo LIST /v 2>&1' -TimeoutSecs 60 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'PowerShell Get-ScheduledTask' -ToolName 'powershell' -CategoryName 'tarefas_getscheduledtask' -CmdText 'powershell -NoProfile -Command "Get-ScheduledTask | Sort-Object TaskPath,TaskName | Format-Table TaskPath,TaskName,State,Author -AutoSize | Out-String -Width 260"' -TimeoutSecs 45 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'qwinsta / query session' -ToolName 'qwinsta' -CategoryName 'sessoes' -CmdText 'cmd /c qwinsta 2>&1' -TimeoutSecs 20 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''

    if (([string](Nz $adDomain '')).Trim() -ne '') {
        RunThreatHuntCommandSnapshot -DisplayLabel 'nltest /sc_query:DOMINIO' -ToolName 'nltest' -CategoryName 'ad_secure_channel' -CmdText ('cmd /c nltest /sc_query:"' + $adDomain + '" 2>&1') -TimeoutSecs 25 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
        RunThreatHuntCommandSnapshot -DisplayLabel 'net user /domain' -ToolName 'net' -CategoryName 'ad_usuarios' -CmdText 'cmd /c net user /domain 2>&1' -TimeoutSecs 35 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    }
    else {
        AppendThreatHuntCommandSkipRow -RowsHtml $RowsHtml -ToolName 'nltest' -CategoryName 'ad_secure_channel' -NoteText 'Host nao aparenta estar em dominio AD; comando ignorado.'
        $SkipCount.Value = [long](To-LongSafe $SkipCount.Value) + 1
        AppendThreatHuntCommandSkipRow -RowsHtml $RowsHtml -ToolName 'net' -CategoryName 'ad_usuarios' -NoteText 'Host nao aparenta estar em dominio AD; comando ignorado.'
        $SkipCount.Value = [long](To-LongSafe $SkipCount.Value) + 1
    }

    RunThreatHuntCommandSnapshot -DisplayLabel 'wmic process ... commandline' -ToolName 'wmic' -CategoryName 'processo_cmdline' -CmdText "cmd /c wmic process where ""name='svchost.exe'"" get CommandLine,CreationDate,Priority /format:list 2>&1" -TimeoutSecs 45 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'auditpol /get /category:*' -ToolName 'auditpol' -CategoryName 'auditoria_config' -CmdText 'cmd /c auditpol /get /category:* 2>&1' -TimeoutSecs 35 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''

    $gpReportPath = BuildThreatHuntResultadosFilePath -ToolName 'gpresult' -CategoryName 'gpo_html' -FileExt 'html'
    $gpReportNote = 'Relatorio HTML: ' + $gpReportPath
    $gpReportPhysical = if ([System.IO.Path]::IsPathRooted($gpReportPath)) { $gpReportPath } else { Join-Path $PSScriptRoot $gpReportPath }
    RunThreatHuntCommandSnapshot -DisplayLabel 'gpresult /h report.html' -ToolName 'gpresult' -CategoryName 'gpo' -CmdText ('cmd /c gpresult /h "' + $gpReportPhysical + '" /f 2>&1') -TimeoutSecs 120 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote $gpReportNote

    RunThreatHuntCommandSnapshot -DisplayLabel 'certutil -dump' -ToolName 'certutil' -CategoryName 'pki_dump' -CmdText 'cmd /c certutil -dump 2>&1' -TimeoutSecs 35 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'fsutil fsinfo ntfsinfo C:' -ToolName 'fsutil' -CategoryName 'ntfsinfo_c' -CmdText 'cmd /c fsutil fsinfo ntfsinfo C: 2>&1' -TimeoutSecs 25 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'fsutil behavior query DisableDeleteNotify' -ToolName 'fsutil' -CategoryName 'trim_behavior' -CmdText 'cmd /c fsutil behavior query DisableDeleteNotify 2>&1' -TimeoutSecs 20 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'fsutil usn queryjournal C:' -ToolName 'fsutil' -CategoryName 'usn_queryjournal_c' -CmdText 'cmd /c fsutil usn queryjournal C: 2>&1' -TimeoutSecs 25 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
    RunThreatHuntCommandSnapshot -DisplayLabel 'vssadmin list shadows' -ToolName 'vssadmin' -CategoryName 'vss_shadows' -CmdText 'cmd /c vssadmin list shadows 2>&1' -TimeoutSecs 25 -RowsHtml $RowsHtml -OkCount $OkCount -FailCount $FailCount -ExtraNote ''
}

function WriteThreatHuntSection {
    param(
        [System.IO.StreamWriter]$Writer
    )
    $registryRows = ''
    $registrySnapshotRows = ''
    $huntCmdRows = ''
    $huntCmdOkCount = 0
    $huntCmdFailCount = 0
    $huntCmdSkipCount = 0

    $script:threatEventTotalHits = 0
    $script:threatEventAlertCount = 0
    $script:threatEventWarnCount = 0
    $script:threatEventInfoCount = 0
    $script:threatHighPriorityHits = 0
    $script:threatSecurityHits = 0
    $script:threatPowerShellHits = 0
    $script:threatSysmonHits = 0
    $script:threatBitsHits = 0
    $script:threatSystemHits = 0
    $script:threatRedHits = 0
    $script:threatYellowHits = 0
    $script:threatEventExportCount = 0
    $script:strThreatEventExportStatusRows = ''
    $script:strThreatRegistrySnapshotStatusRows = ''

    $script:threatRegistryChecks = 0
    $script:threatRegistryAlertCount = 0
    $script:threatRegistryWarnCount = 0
    $script:threatRegistryInfoCount = 0
    $script:threatRegistryPersistHits = 0
    $script:threatRegistryAccessHits = 0
    $script:threatRegistryTelemetryHits = 0
    $script:threatRegistryCredHits = 0
    $script:threatRegistryNetworkHits = 0
    $script:threatRegistrySnapshotExportCount = 0

    CollectThreatRegistryChecks -RegistryRows ([ref]$registryRows) -RegistrySnapshotRows ([ref]$registrySnapshotRows)
    CollectThreatHuntCommandSnapshots -RowsHtml ([ref]$huntCmdRows) -OkCount ([ref]$huntCmdOkCount) -FailCount ([ref]$huntCmdFailCount) -SkipCount ([ref]$huntCmdSkipCount)

    if ($registryRows.Trim() -eq '') { $registryRows = "<tr><td colspan='7'>Nenhuma checagem de registro retornou dados.</td></tr>" }
    if ($registrySnapshotRows.Trim() -eq '') { $registrySnapshotRows = "<tr><td colspan='6'>Nenhum snapshot de registro exportado.</td></tr>" }
    if ($huntCmdRows.Trim() -eq '') { $huntCmdRows = "<tr><td colspan='8'>Nenhum comando de triagem executado.</td></tr>" }
    $script:strThreatRegistrySnapshotStatusRows = $registrySnapshotRows

    Write-VbsLine $Writer "<section id='ameacas' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Auditoria</h2>"
    Write-VbsLine $Writer "<div class='mini-note'>Bloco simplificado para triagem: mantidas apenas checagens reais de registro e snapshots exportados (sem eventos priorizados/correlacao).</div>"
    Write-VbsLine $Writer "<div class='grid'>"
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + [long](To-LongSafe $script:threatRegistryChecks) + "</div><div class='kpi-label'>Checagens de registro executadas</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'><span class='tag bad'>" + [long](To-LongSafe $script:threatRegistryAlertCount) + "</span> / <span class='tag warn'>" + [long](To-LongSafe $script:threatRegistryWarnCount) + "</span></div><div class='kpi-label'>Achados (alerta/warn)</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + [long](To-LongSafe $script:threatRegistrySnapshotExportCount) + "</div><div class='kpi-label'>Snapshots de registro exportados</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + [long](To-LongSafe $huntCmdOkCount) + " / " + ([long](To-LongSafe $huntCmdOkCount) + [long](To-LongSafe $huntCmdFailCount) + [long](To-LongSafe $huntCmdSkipCount)) + "</div><div class='kpi-label'>Comandos TH (sucesso/total)</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi kpi-text'>" + (HtmlEncode ([string](Nz $script:hostAssetType ''))) + "</div><div class='kpi-label'>Tipo do host</div></div>")
    Write-VbsLine $Writer "</div>"
    Write-VbsLine $Writer "<h3>Comandos de triagem / discovery (saidas em <code>Resultados\\*.result</code>)</h3>"
    Write-VbsLine $Writer "<div class='mini-note'>Comandos de consulta com perfil de discovery (podem gerar telemetria/alerta em EDR). O custody log registra somente os comandos desta lista que finalizam com sucesso.</div>"
    Write-VbsLine $Writer ("<div class='scroll-table'><table><tr><th>Ferramenta</th><th>Categoria</th><th>Status</th><th>ExitCode</th><th>Timeout(s)</th><th>Arquivo .result</th><th class='location-col'>Comando</th><th class='location-col'>Observacao</th></tr>" + $huntCmdRows + "</table></div>")
    Write-VbsLine $Writer "<h3>Snapshots de chaves criticas (reg query) exportados</h3>"
    Write-VbsLine $Writer ("<div class='scroll-table snap-no-wrap'><table><tr><th>Grupo</th><th>Consulta</th><th>Status</th><th>Arquivo</th><th>Tamanho</th><th>Observacao</th></tr>" + $registrySnapshotRows + "</table></div>")
    Write-VbsLine $Writer "<h3>Persistencia</h3>"
    Write-VbsLine $Writer ("<div class='scroll-table'><table><tr><th>Grupo</th><th>Root</th><th>Chave</th><th>Valor</th><th>Conteudo</th><th>Severidade</th><th class='location-col'>Observacao</th></tr>" + $registryRows + "</table></div>")

    if ([long](To-LongSafe $script:threatRegistryAlertCount) -gt 0) {
        LogCustody -Etapa 'THREAT_HUNT' -Status 'WARN' -Detalhes ('Registro alert=' + [long](To-LongSafe $script:threatRegistryAlertCount) + ' warn=' + [long](To-LongSafe $script:threatRegistryWarnCount) + ' | checks=' + [long](To-LongSafe $script:threatRegistryChecks))
    }
    else {
        LogCustody -Etapa 'THREAT_HUNT' -Status 'OK' -Detalhes ('Registro checks=' + [long](To-LongSafe $script:threatRegistryChecks) + ' | snapshots=' + [long](To-LongSafe $script:threatRegistrySnapshotExportCount))
    }

    Write-VbsLine $Writer "</section>"
}

function GetPrefetchTableRowsFromDir {
    param(
        [string]$PrefetchPath,
        [ref]$FileCount,
        [ref]$BytesTotal,
        [ref]$ErrMsg
    )

    $FileCount.Value = 0
    $BytesTotal.Value = 0.0
    $ErrMsg.Value = ''
    $rowsHtml = ''

    if (-not (Test-Path -LiteralPath $PrefetchPath -PathType Container)) {
        $ErrMsg.Value = 'Pasta Prefetch nao encontrada.'
        return ''
    }

    try {
        $files = Get-ChildItem -LiteralPath $PrefetchPath -Filter '*.pf' -File -ErrorAction Stop | Sort-Object Name
    }
    catch {
        $ErrMsg.Value = 'Falha ao listar arquivos .pf: ' + $_.Exception.Message
        return ''
    }

    foreach ($f in $files) {
        $FileCount.Value = [long](To-LongSafe $FileCount.Value) + 1
        $BytesTotal.Value = [double](To-DoubleSafe $BytesTotal.Value) + [double](To-DoubleSafe $f.Length)
        $rowsHtml = $rowsHtml + "<tr><td>" + (HtmlEncode ([string](Nz $f.Name '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $f.CreationTime '-'))) + "</td><td>" + (HtmlEncode ([string](Nz $f.LastWriteTime '-'))) + "</td><td>" + (HtmlEncode (FormatBytes $f.Length)) + "</td></tr>"
    }

    if ([long](To-LongSafe $FileCount.Value) -eq 0 -and $rowsHtml.Trim() -eq '') {
        $ErrMsg.Value = 'Nenhum arquivo .pf foi interpretado a partir do dir.'
    }
    return $rowsHtml
}

function WriteExecutionArtifactHighlights {
    param(
        [System.IO.StreamWriter]$Writer,
        [string]$PrefetchPath
    )

    $hasAny = $false
    $firstWrite = [datetime]::MinValue
    $lastWrite = [datetime]::MinValue
    $progDict = @{}

    if (Test-Path -LiteralPath $PrefetchPath -PathType Container) {
        try {
            $files = Get-ChildItem -LiteralPath $PrefetchPath -Filter '*.pf' -File -ErrorAction Stop
        }
        catch {
            $files = @()
        }
        foreach ($f in $files) {
            $hasAny = $true
            if ($firstWrite -eq [datetime]::MinValue -or $f.LastWriteTime -lt $firstWrite) { $firstWrite = $f.LastWriteTime }
            if ($lastWrite -eq [datetime]::MinValue -or $f.LastWriteTime -gt $lastWrite) { $lastWrite = $f.LastWriteTime }
            $progName = (PrefetchProgramNameFromPf $f.Name).Trim().ToUpperInvariant()
            if ($progName -eq '') { $progName = '(PF)' }
            if ($progDict.ContainsKey($progName)) { $progDict[$progName] = [long](To-LongSafe $progDict[$progName]) + 1 } else { $progDict[$progName] = 1 }
        }
    }

    $recentPath = [System.Environment]::ExpandEnvironmentVariables('%APPDATA%') + '\Microsoft\Windows\Recent'
    $autoDestPath = $recentPath + '\AutomaticDestinations'
    $customDestPath = $recentPath + '\CustomDestinations'
    $recentFiles = 0; $recentDirs = 0; $recentBytes = 0.0
    $autoFiles = 0; $autoDirs = 0; $autoBytes = 0.0
    $customFiles = 0; $customDirs = 0; $customBytes = 0.0
    CountFolderStats -Path $recentPath -TotalFiles ([ref]$recentFiles) -TotalDirs ([ref]$recentDirs) -TotalBytes ([ref]$recentBytes)
    CountFolderStats -Path $autoDestPath -TotalFiles ([ref]$autoFiles) -TotalDirs ([ref]$autoDirs) -TotalBytes ([ref]$autoBytes)
    CountFolderStats -Path $customDestPath -TotalFiles ([ref]$customFiles) -TotalDirs ([ref]$customDirs) -TotalBytes ([ref]$customBytes)

    Write-VbsLine $Writer "<div class='grid'>"
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + (IIfBool $hasAny (HtmlEncode (FormatDateTimeLocal $firstWrite)) '-') + "</div><div class='kpi-label'>Prefetch mais antigo (LastWrite)</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + (IIfBool $hasAny (HtmlEncode (FormatDateTimeLocal $lastWrite)) '-') + "</div><div class='kpi-label'>Prefetch mais recente (LastWrite)</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + $progDict.Count + "</div><div class='kpi-label'>Programas distintos no Prefetch</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + $recentFiles + "</div><div class='kpi-label'>Arquivos em Recent (recursivo)</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + $autoFiles + "</div><div class='kpi-label'>Jump Lists AutoDestinations</div></div>")
    Write-VbsLine $Writer ("<div class='card'><div class='kpi'>" + $customFiles + "</div><div class='kpi-label'>Jump Lists CustomDestinations</div></div>")
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<table><tr><th>Artefato de usuario</th><th>Caminho</th><th>Arquivos</th><th>Subpastas</th><th>Tamanho</th></tr>"
    Write-VbsLine $Writer ("<tr><td>Recent</td><td class='location-col'>" + (HtmlEncode $recentPath) + "</td><td>" + $recentFiles + "</td><td>" + $recentDirs + "</td><td>" + (HtmlEncode (FormatBytes $recentBytes)) + "</td></tr>")
    Write-VbsLine $Writer ("<tr><td>AutomaticDestinations</td><td class='location-col'>" + (HtmlEncode $autoDestPath) + "</td><td>" + $autoFiles + "</td><td>" + $autoDirs + "</td><td>" + (HtmlEncode (FormatBytes $autoBytes)) + "</td></tr>")
    Write-VbsLine $Writer ("<tr><td>CustomDestinations</td><td class='location-col'>" + (HtmlEncode $customDestPath) + "</td><td>" + $customFiles + "</td><td>" + $customDirs + "</td><td>" + (HtmlEncode (FormatBytes $customBytes)) + "</td></tr>")
    Write-VbsLine $Writer "</table>"

    $topRows = ''
    if ($progDict.Count -gt 0) {
        $keys = SortDictKeysByValueDesc $progDict
        for ($i = 0; $i -lt $keys.Length; $i++) {
            if ($i -ge 20) { break }
            $k = [string]$keys[$i]
            $topRows = $topRows + "<tr><td>" + ($i + 1) + "</td><td>" + (HtmlEncode $k) + "</td><td>" + [long](To-LongSafe $progDict[$k]) + "</td></tr>"
        }
    }
    if ($topRows.Trim() -eq '') { $topRows = "<tr><td colspan='3'>Sem arquivos .pf suficientes para agregacao.</td></tr>" }
    Write-VbsLine $Writer ("<div class='scroll-table'><table><tr><th>#</th><th>Programa (nome inferido do .pf)</th><th>Ocorrencias</th></tr>" + $topRows + "</table></div>")
    Write-VbsLine $Writer "<div class='mini-note'>Interpretacao aproximada: recorrencia em Prefetch sugere execucao historica; datas refletem timestamps do arquivo (<em>nao</em> substituem logs completos de processo).</div>"
}

function WriteExecutionArtifactsSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    Write-VbsLine $Writer "<section id='execucao' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Indicadores</h2>"

    $prefetchPath = [System.Environment]::ExpandEnvironmentVariables('%SystemRoot%') + '\Prefetch'
    $fileCount = 0
    $bytesTotal = 0.0
    $errMsg = ''
    $rowsHtml = GetPrefetchTableRowsFromDir -PrefetchPath $prefetchPath -FileCount ([ref]$fileCount) -BytesTotal ([ref]$bytesTotal) -ErrMsg ([ref]$errMsg)

    Write-VbsLine $Writer "<h3>Volumetria da pasta Prefetch</h3>"
    Write-VbsLine $Writer "<table><tr><th>Artefato</th><th>Valor</th></tr>"
    WriteKV 'Caminho da pasta Prefetch' $prefetchPath
    WriteKV 'Quantidade de arquivos .pf' $fileCount
    WriteKV 'Tamanho total dos arquivos .pf' (FormatBytes $bytesTotal)
    if ([string](Nz $errMsg '').Trim() -ne '') {
        WriteKV 'Observacao da coleta' $errMsg
    }
    else {
        WriteKV 'Origem da coleta' 'cmd /c dir (sem PowerShell)'
    }
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Indicadores relevantes de execucao</h3>"
    WriteExecutionArtifactHighlights -Writer $Writer -PrefetchPath $prefetchPath
    Write-VbsLine $Writer "<h3>Arquivos Prefetch (.pf)</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Nome</th><th>Data de criacao</th><th>Ultima gravao (Last Write)</th><th>Tamanho</th></tr>"
    if ([string](Nz $rowsHtml '').Trim() -eq '') {
        Write-VbsLine $Writer "<tr><td colspan='4'>Nenhum arquivo .pf encontrado ou sem permissao de leitura.</td></tr>"
    }
    else {
        Write-VbsLine $Writer $rowsHtml
    }
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    $taskListCsv = GetCommandOutputWithTimeout 'cmd /c tasklist /v /fo csv' 30
    $taskSvcHost = GetCommandOutputWithTimeout 'cmd /c tasklist /fi "imagename eq svchost.exe"' 30
    $wmicPs = GetCommandOutputWithTimeout 'cmd /c wmic process where "name=''powershell.exe''" get commandline,creationdate,priority' 30

    Write-VbsLine $Writer "<h3>Processos em Execucao (telemetria adicional)</h3>"
    Write-VbsLine $Writer "<table>"
    Write-VbsLine $Writer ("<tr><th>Processos e Memorias (svchost.exe)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $taskSvcHost ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><th>Execucoes de powershell.exe passadas/ativas (wmic)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $wmicPs ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><th>Tasklist CSV (Detalhada com Owner)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $taskListCsv ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "</section>"
}

function ListInstalledSoftware {
    param(
        [System.IO.StreamWriter]$Writer,
        [string]$BaseKey
    )

    $regBase = 'Registry::HKEY_LOCAL_MACHINE\' + [string](Nz $BaseKey '')
    try {
        $subKeys = Get-ChildItem -LiteralPath $regBase -ErrorAction Stop
    }
    catch {
        return
    }

    foreach ($sub in $subKeys) {
        try {
            $p = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction Stop
        }
        catch {
            continue
        }
        $displayName = ''
        $displayVersion = '-'
        $publisher = '-'
        $installDateRaw = '-'
        if ($p.PSObject -and $p.PSObject.Properties['DisplayName']) { $displayName = [string](Nz $p.PSObject.Properties['DisplayName'].Value '') }
        if ($p.PSObject -and $p.PSObject.Properties['DisplayVersion']) { $displayVersion = [string](Nz $p.PSObject.Properties['DisplayVersion'].Value '-') }
        if ($p.PSObject -and $p.PSObject.Properties['Publisher']) { $publisher = [string](Nz $p.PSObject.Properties['Publisher'].Value '-') }
        if ($p.PSObject -and $p.PSObject.Properties['InstallDate']) { $installDateRaw = [string](Nz $p.PSObject.Properties['InstallDate'].Value '-') }
        if ($displayName.Trim() -ne '') {
            $installDate = NormalizeInstallDate $installDateRaw
            Write-VbsLine $Writer ("<tr><td class='location-col'>" + (HtmlEncode $displayName) + "</td><td>" + (HtmlEncode $displayVersion) + "</td><td>" + (HtmlEncode $publisher) + "</td><td>" + (HtmlEncode $installDate) + "</td></tr>")
        }
    }
}

function ListCryptoSoftware {
    param(
        [System.IO.StreamWriter]$Writer,
        [string]$BaseKey
    )

    $regBase = 'Registry::HKEY_LOCAL_MACHINE\' + [string](Nz $BaseKey '')
    try {
        $subKeys = Get-ChildItem -LiteralPath $regBase -ErrorAction Stop
    }
    catch {
        return
    }

    foreach ($sub in $subKeys) {
        try {
            $p = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction Stop
        }
        catch {
            continue
        }
        $displayName = ''
        $displayVersion = '-'
        $publisher = '-'
        if ($p.PSObject -and $p.PSObject.Properties['DisplayName']) { $displayName = [string](Nz $p.PSObject.Properties['DisplayName'].Value '') }
        if ($p.PSObject -and $p.PSObject.Properties['DisplayVersion']) { $displayVersion = [string](Nz $p.PSObject.Properties['DisplayVersion'].Value '-') }
        if ($p.PSObject -and $p.PSObject.Properties['Publisher']) { $publisher = [string](Nz $p.PSObject.Properties['Publisher'].Value '-') }
        $n = $displayName.ToUpperInvariant()
        if (
            $n.Contains('BITLOCKER') -or $n.Contains('VERACRYPT') -or $n.Contains('TRUECRYPT') -or
            $n.Contains('SYMANTEC ENCRYPTION') -or $n.Contains('MCAFEE DRIVE ENCRYPTION') -or
            $n.Contains('SOPHOS SAFEGUARD')
        ) {
            Write-VbsLine $Writer ("<tr><td class='location-col'>" + (HtmlEncode $displayName) + "</td><td>" + (HtmlEncode $displayVersion) + "</td><td>" + (HtmlEncode $publisher) + "</td></tr>")
        }
    }
}

function ListStartupCommands {
    param(
        [System.IO.StreamWriter]$Writer
    )

    $colStart = Invoke-WmiQueryCompat -QueryText 'SELECT * FROM Win32_StartupCommand'
    foreach ($st in $colStart) {
        $loc = HtmlEncode ([string](Nz (SafeWmiProp $st 'Location' '') '-'))
        $loc = $loc.Replace(';', ';<br>')
        $loc = $loc.Replace(',', ',<br>')
        $row = "<tr><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $st 'Name' '') '-'))) + "</td><td class='location-col'>" + (HtmlEncode ([string](Nz (SafeWmiProp $st 'Command' '') '-'))) + "</td><td class='location-col'>" + $loc + "</td><td>" + (HtmlEncode ([string](Nz (SafeWmiProp $st 'User' '') '-'))) + "</td></tr>"
        Write-VbsLine $Writer $row
    }
}

function WriteSoftwareSection {
    param(
        [System.IO.StreamWriter]$Writer
    )

    Write-VbsLine $Writer "<section id='apps' class='card' style='margin-top:16px'>"
    Write-VbsLine $Writer "<h2>Detalhes</h2>"

    $sysInfo = GetCommandOutputWithTimeout 'cmd /c systeminfo' 60
    $osGet = GetCommandOutputWithTimeout 'cmd /c wmic os get caption,osarchitecture,version,buildnumber,oslanguage,installdate /format:list' 30
    $schQuery = GetCommandOutputWithTimeout 'cmd /c schtasks /query /fo LIST /v' 60
    $psTask = GetCommandOutputWithTimeout 'powershell -NoProfile -Command "Get-ScheduledTask | Select-Object TaskName,State,TaskPath | Format-Table -AutoSize | Out-String"' 30

    Write-VbsLine $Writer "<h3>Sistema e Patch Level (systeminfo / wmic)</h3>"
    Write-VbsLine $Writer "<table>"
    Write-VbsLine $Writer ("<tr><th>WMIC OS Get</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $osGet ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><th>SystemInfo (Detalhado)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $sysInfo ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Tarefas Agendadas (cron jobs)</h3>"
    Write-VbsLine $Writer "<table>"
    Write-VbsLine $Writer ("<tr><th>PowerShell Get-ScheduledTask (Resumo)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $psTask ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer ("<tr><th>SCHTASKS Query List (Verbose)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $schQuery ''))) + "</pre></div></td></tr>")
    Write-VbsLine $Writer "</table>"

    Write-VbsLine $Writer "<h3>Softwares instalados (Registry)</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th class='location-col'>Nome</th><th>Versao</th><th>Publicador</th><th>Instalacao</th></tr>"
    ListInstalledSoftware -Writer $Writer -BaseKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    ListInstalledSoftware -Writer $Writer -BaseKey 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    Write-VbsLine $Writer "<h3>Deteccao de Softwares de criptografia</h3>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th class='location-col'>Nome</th><th>Versao</th><th>Publisher</th></tr>"
    ListCryptoSoftware -Writer $Writer -BaseKey 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    ListCryptoSoftware -Writer $Writer -BaseKey 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"

    $runKeys = GetCommandOutputWithTimeout 'cmd /c reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /s' 30
    
    Write-VbsLine $Writer "<h3>Entradas de inicializacao automatica (persistencia)</h3>"
    Write-VbsLine $Writer "<table><tr><th>Comandos Run do Registro (HKLM)</th></tr><tr><td><div class='scroll'><pre>" + (HtmlEncode ([string](Nz $runKeys ''))) + "</pre></div></td></tr></table>"
    Write-VbsLine $Writer "<div class='scroll-table'>"
    Write-VbsLine $Writer "<table><tr><th>Nome</th><th>Comando</th><th class='location-col'>Localizacao</th><th>Usuario</th></tr>"
    ListStartupCommands -Writer $Writer
    Write-VbsLine $Writer "</table>"
    Write-VbsLine $Writer "</div>"
    Write-VbsLine $Writer "</section>"
}

function TimestampISO {
    param(
        [datetime]$DateValue
    )

    $ms = '{0:000}' -f (Get-Random -Minimum 0 -Maximum 1000)
    return ('{0:yyyy-MM-ddTHH:mm:ss}.{1}' -f $DateValue, $ms)
}

function LogStatusClass {
    param(
        [string]$StatusText
    )

    $s = ([string](Nz $StatusText '')).Trim().ToUpperInvariant()
    switch ($s) {
        'WARN' { return 'warn' }
        'WARNING' { return 'warn' }
        'ERROR' { return 'bad' }
        'FAIL' { return 'bad' }
        'BAD' { return 'bad' }
        'START' { return 'start' }
        'END' { return 'ok' }
        'OK' { return 'ok' }
        default { return 'neutral' }
    }
}

function FormatDurationFromTicks {
    param(
        [double]$StartTick,
        [double]$EndTick
    )

    $s1 = [double](To-DoubleSafe $StartTick)
    $s2 = [double](To-DoubleSafe $EndTick)
    $secs = $s2 - $s1
    if ($secs -lt 0.0) {
        $secs = $secs + 86400.0
    }

    if ($secs -lt 1.0) {
        $ms = [int]($secs * 1000.0)
        return [string]$ms + ' ms'
    }
    if ($secs -lt 60.0) {
        return (FormatNumberVbs $secs 2) + ' s'
    }
    $minsTotal = [Math]::Floor([double]($secs / 60.0))
    $mins = [int]$minsTotal
    $remSecs = $secs - ([double]$mins * 60.0)
    if ($mins -lt 60) {
        return [string]$mins + ' min ' + ('{0:00}' -f [int][Math]::Floor([double]$remSecs)) + ' s'
    }
    $hrsTotal = [Math]::Floor([double]($mins / 60.0))
    $hrs = [int]$hrsTotal
    $remMins = $mins % 60
    return [string]$hrs + ' h ' + ('{0:00}' -f [int]$remMins) + ' min ' + ('{0:00}' -f [int][Math]::Floor([double]$remSecs)) + ' s'
}

function GetFileDateModifiedSafe {
    param(
        [string]$FilePath
    )

    try {
        if (Test-Path -LiteralPath $FilePath -PathType Leaf) {
            return (Get-Item -LiteralPath $FilePath -Force -ErrorAction Stop).LastWriteTime.ToString()
        }
    }
    catch {
    }
    return '-'
}

function EscapePsSingleQuoted {
    param(
        [string]$Text
    )
    return ([string](Nz $Text '')).Replace("'", "''")
}

function NormalizeHexToken {
    param(
        [string]$Text
    )

    $t = ([string](Nz $Text '')).Trim().ToUpperInvariant()
    $out = New-Object System.Text.StringBuilder
    foreach ($ch in $t.ToCharArray()) {
        if (($ch -ge '0' -and $ch -le '9') -or ($ch -ge 'A' -and $ch -le 'F')) {
            [void]$out.Append($ch)
        }
    }
    return $out.ToString()
}

function LooksLikeMd5Hex {
    param(
        [string]$Text
    )

    $s = ([string](Nz $Text '')).Trim().ToUpperInvariant()
    if ($s.Length -ne 32) {
        return $false
    }
    foreach ($ch in $s.ToCharArray()) {
        if (-not (($ch -ge '0' -and $ch -le '9') -or ($ch -ge 'A' -and $ch -le 'F'))) {
            return $false
        }
    }
    return $true
}

function GetCommandOutputWithLocalTimeoutSilent {
    param(
        [string]$CommandText,
        [int]$TimeoutSecs
    )

    $outPath = [System.IO.Path]::GetTempFileName()
    $errPath = [System.IO.Path]::GetTempFileName()
    try {
        $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $CommandText -NoNewWindow -PassThru -RedirectStandardOutput $outPath -RedirectStandardError $errPath
        $limit = [Math]::Max(1, [int](To-LongSafe $TimeoutSecs))
        $completed = $proc.WaitForExit($limit * 1000)
        if (-not $completed) {
            try { $proc.Kill() } catch {}
            return '[TIMEOUT APOS ' + $limit + 's] Comando interrompido por demora.'
        }
        $out = ''
        $err = ''
        try { $out = [System.IO.File]::ReadAllText($outPath) } catch { $out = '' }
        try { $err = [System.IO.File]::ReadAllText($errPath) } catch { $err = '' }
        $outTrim = ([string](Nz $out '')).Trim()
        $errTrim = ([string](Nz $err '')).Trim()
        if ($outTrim -ne '') {
            if ($errTrim -ne '') {
                return $outTrim + "`r`n[stderr]`r`n" + $errTrim
            }
            return $outTrim
        }
        return $errTrim
    }
    catch {
        return ('Falha ao executar comando: ' + $_.Exception.Message)
    }
    finally {
        try { Remove-Item -LiteralPath $outPath -Force -ErrorAction SilentlyContinue } catch {}
        try { Remove-Item -LiteralPath $errPath -Force -ErrorAction SilentlyContinue } catch {}
    }
}

function GetFileMD5 {
    param(
        [string]$FilePath
    )

    $result = 'N/A'
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        return $result
    }

    try {
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $fs = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        try {
            $md5 = [System.Security.Cryptography.MD5]::Create()
            try {
                $hashBytes = $md5.ComputeHash($fs)
                $hexRaw = [System.BitConverter]::ToString($hashBytes)
                $hex = $hexRaw -replace '-', ''
                $token = NormalizeHexToken ([string]$hex)
                if (LooksLikeMd5Hex $token) {
                    return $token
                }
            }
            finally {
                $md5.Dispose()
            }
        }
        finally {
            $fs.Close()
        }
    }
    catch {
    }

    try {
        $h = (Get-FileHash -LiteralPath $FilePath -Algorithm MD5 -ErrorAction Stop).Hash
        $token = NormalizeHexToken $h
        if (LooksLikeMd5Hex $token) {
            return $token
        }
    }
    catch {
    }

    $certCmd = 'cmd /c certutil -hashfile "' + $FilePath + '" MD5'
    $cmdOut = GetCommandOutputWithLocalTimeoutSilent -CommandText $certCmd -TimeoutSecs 20
    $lines = [string](Nz $cmdOut '').Split(@("`r`n", "`n"), [System.StringSplitOptions]::None)
    foreach ($line in $lines) {
        $token = NormalizeHexToken $line
        if (LooksLikeMd5Hex $token) {
            return $token
        }
    }

    return $result
}

function GetLogDetailField {
    param(
        [string]$DetailText
    )

    $s = ([string](Nz $DetailText '')).Trim()
    if ($s -eq '') {
        return 'detalhes'
    }
    $p = $s.IndexOf(':')
    if ($p -gt 0 -and ($p + 1) -le 60) {
        $left = $s.Substring(0, $p).Trim()
        if ($left -ne '') {
            return $left
        }
    }
    return 'detalhes'
}

function GetLogDetailValue {
    param(
        [string]$DetailText
    )

    $s = ([string](Nz $DetailText '')).Trim()
    if ($s -eq '') {
        return '-'
    }
    $p = $s.IndexOf(':')
    if ($p -gt 0 -and ($p + 1) -lt $s.Length) {
        $right = $s.Substring($p + 1).Trim()
        if ($right -eq '') { return '-' }
        return $right
    }
    return $s
}

function PercentWidthPct {
    param(
        [double]$ValueNum,
        [double]$MaxNum
    )

    $v = [double](To-DoubleSafe $ValueNum)
    $m = [double](To-DoubleSafe $MaxNum)
    if ($m -le 0.0) { return 0 }
    
    $ratio = $v / $m
    $pct = $ratio * 100.0
    
    # Use native casting which rounds, subtract 0.5 to simulate floor for positive numbers
    # or just use explicit double math.
    $p = 0
    try {
        if ($pct -ge 100.0) { $p = 100 }
        elseif ($pct -le 0.0) { $p = 0 }
        else {
            $p = [int][Math]::Floor([double]$pct)
        }
    }
    catch {
        $p = 0
    }
    
    if ($v -gt 0.0 -and $p -lt 2) { $p = 2 }
    if ($p -gt 100) { $p = 100 }
    if ($p -lt 0) { $p = 0 }
    return $p
}

function IsChecklistStageName {
    param(
        [string]$StageName
    )

    $s = [string](Nz $StageName '')
    if ($s.StartsWith('Write') -and $s.IndexOf('Section', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        return $true
    }
    return $false
}

function GetPesquisaCommand {
    param(
        [string]$DetailText
    )

    $s = [string](Nz $DetailText '')
    $p1 = $s.IndexOf('Comando:', [System.StringComparison]::OrdinalIgnoreCase)
    if ($p1 -lt 0) {
        return $s
    }
    $s = $s.Substring($p1 + 'Comando:'.Length).Trim()
    $p2 = $s.IndexOf('| Resultado:', [System.StringComparison]::OrdinalIgnoreCase)
    if ($p2 -gt -1) {
        $s = $s.Substring(0, $p2).Trim()
    }
    if ($s -eq '') { return '-' }
    return $s
}

function GetPesquisaResultado {
    param(
        [string]$DetailText
    )

    $s = [string](Nz $DetailText '')
    $p1 = $s.IndexOf('Resultado:', [System.StringComparison]::OrdinalIgnoreCase)
    if ($p1 -lt 0) {
        return '-'
    }
    $res = $s.Substring($p1 + 'Resultado:'.Length).Trim()
    if ($res -eq '') { return '-' }
    return $res
}

function DfirTimelineSeverityCss {
    param(
        [string]$SevText
    )

    switch (([string](Nz $SevText 'INFO')).Trim().ToUpperInvariant()) {
        'ALERTA' { return 'type1' }
        'BAD' { return 'type1' }
        'WARN' { return 'type2' }
        'WARNING' { return 'type2' }
        default { return 'type3' }
    }
}

function DfirTimelineIcon {
    param([string]$Type)
    switch ($Type) {
        'type1' { return 'lni-warning' }
        'type2' { return 'lni-info' }
        default { return 'lni-checkmark-circle' }
    }
}

function BuildDfirPriorityTimelineHtml {
    $raw = [string](Nz $script:strDfirTimelineRecords '')
    if ($raw.Trim() -eq '') {
        return ''
    }

    $sep = [char]30
    $lines = SortStringArrayAsc (@($raw -split "\r?\n") | Where-Object { ([string](Nz $_ '')).Trim() -ne '' })
    $htmlOut = "<div class='timeline'>"
    $cntUserCreate = 0
    $cntLastUser = 0
    $cntProgram = 0
    $maxUserCreate = 20
    $maxLastUser = 20
    $maxProgram = 30

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = ([string](Nz $lines[$i] '')).Trim()
        if ($line -eq '') { continue }
        $parts = $line -split ([string][char]30)
        if ($parts.Length -lt 8) { continue }

        $displayText = $parts[1]
        $cat = $parts[2]
        $itemText = $parts[3]
        $eventText = $parts[4]
        $valueText = $parts[5]
        $sourceText = $parts[6]
        $sevText = $parts[7]
        $skipItem = $false

        $catUp = ([string](Nz $cat '')).Trim().ToUpperInvariant()
        if ($catUp -eq 'USUARIO CRIADO') {
            if ($cntUserCreate -ge $maxUserCreate) { $skipItem = $true } else { $cntUserCreate++ }
        }
        elseif ($catUp -eq 'ULTIMO USUARIO ACESSADO') {
            if ($cntLastUser -ge $maxLastUser) { $skipItem = $true } else { $cntLastUser++ }
        }
        elseif ($catUp -eq 'PROGRAMAS ULTIMA EXECUCAO') {
            if ($cntProgram -ge $maxProgram) { $skipItem = $true } else { $cntProgram++ }
        }
        else {
            $skipItem = $true
        }

        if (-not $skipItem) {
            $typeClass = DfirTimelineSeverityCss $sevText
            $iconClass = DfirTimelineIcon $typeClass
            
            $htmlOut += "<div class='timeline__event animated fadeInUp timeline__event--" + $typeClass + "'>"
            $htmlOut += "  <div class='timeline__event__icon'><i class='" + $iconClass + "'></i></div>"
            $htmlOut += "  <div class='timeline__event__date'>" + (HtmlEncode $displayText) + "</div>"
            $htmlOut += "  <div class='timeline__event__content'>"
            $htmlOut += "    <div class='timeline__event__title'>" + (HtmlEncode $cat) + "</div>"
            $htmlOut += "    <div class='timeline__event__description'>"
            $htmlOut += "      <p><strong>" + (HtmlEncode $itemText) + "</strong><br>" + (HtmlEncode $eventText) + " | " + (HtmlEncode $sourceText) + "<br><em>" + (HtmlEncode $valueText) + "</em></p>"
            $htmlOut += "    </div>"
            $htmlOut += "  </div>"
            $htmlOut += "</div>"
        }
    }

    $htmlOut += "</div>"
    if ($cntUserCreate -eq 0 -and $cntLastUser -eq 0 -and $cntProgram -eq 0) {
        return ''
    }
    return $htmlOut
}

function BuildUserArtifactTimelineRowsHtml {
    $rows = ''
    $raw = [string](Nz $script:strUserArtifactTimelineRecords '')
    if ($raw.Trim() -eq '') {
        return ''
    }
    $lines = SortStringArrayAsc (@($raw -split "\r?\n") | Where-Object { ([string](Nz $_ '')).Trim() -ne '' })
    $sep = [char]30
    for ($i = $lines.Count - 1; $i -ge 0; $i--) {
        $line = ([string](Nz $lines[$i] '')).Trim()
        if ($line -eq '') { continue }
        $parts = $line -split ([string][char]30)
        if ($parts.Length -ge 5) {
            $rows = $rows + "<tr><td>" + (HtmlEncode $parts[1]) + "</td><td>" + (HtmlEncode $parts[2]) + "</td><td>" + (HtmlEncode $parts[3]) + "</td><td class='path'>" + (HtmlEncode $parts[4]) + "</td></tr>"
        }
    }
    return $rows
}

function GetRunExportNestedSubDir {
    param(
        [string]$RelPath
    )

    $baseDir = GetRunExportBaseDir
    $curPath = $baseDir
    $normRel = [string](Nz $RelPath '')
    $normRel = $normRel.Replace('/', '\')
    $parts = $normRel.Split('\')
    foreach ($part in $parts) {
        $p = [string](Nz $part '').Trim()
        if ($p -ne '') {
            $curPath = Join-Path $curPath (SanitizeFileNameComponent $p)
            try {
                if (-not (Test-Path -LiteralPath $curPath -PathType Container)) {
                    New-Item -ItemType Directory -Path $curPath -Force | Out-Null
                }
            }
            catch {
            }
        }
    }
    return $curPath
}

function CountFilesRecursiveFolderObj {
    param(
        [string]$FolderPath
    )

    $cnt = 0
    try {
        $files = Get-ChildItem -LiteralPath $FolderPath -File -Force -ErrorAction SilentlyContinue
        if ($null -ne $files) { $cnt += @($files).Count }
    }
    catch {
    }
    try {
        $subs = Get-ChildItem -LiteralPath $FolderPath -Directory -Force -ErrorAction SilentlyContinue
        foreach ($sf in $subs) {
            $cnt += [long](To-LongSafe (CountFilesRecursiveFolderObj -FolderPath $sf.FullName))
        }
    }
    catch {
    }
    return $cnt
}

function CountFilesRecursiveSafe {
    param(
        [string]$FolderPath
    )

    if ([string](Nz $FolderPath '').Trim() -eq '') { return 0 }
    if (-not (Test-Path -LiteralPath $FolderPath -PathType Container)) { return 0 }
    return [long](To-LongSafe (CountFilesRecursiveFolderObj -FolderPath $FolderPath))
}

function GetPathSizeBytesSafe {
    param(
        [string]$PathValue
    )

    if ([string](Nz $PathValue '').Trim() -eq '') { return -1 }
    try {
        if (Test-Path -LiteralPath $PathValue -PathType Leaf) {
            return [double](Get-Item -LiteralPath $PathValue -Force -ErrorAction Stop).Length
        }
        if (Test-Path -LiteralPath $PathValue -PathType Container) {
            $m = Get-ChildItem -LiteralPath $PathValue -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum
            return [double](To-DoubleSafe $m.Sum)
        }
    }
    catch {
    }
    return -1
}

function GetPathDateCreatedSafe {
    param(
        [string]$PathValue
    )

    if ([string](Nz $PathValue '').Trim() -eq '') { return '-' }
    try {
        if (Test-Path -LiteralPath $PathValue -PathType Leaf) {
            return (Get-Item -LiteralPath $PathValue -Force -ErrorAction Stop).CreationTime.ToString()
        }
        if (Test-Path -LiteralPath $PathValue -PathType Container) {
            return (Get-Item -LiteralPath $PathValue -Force -ErrorAction Stop).CreationTime.ToString()
        }
    }
    catch {
    }
    return '-'
}

function AppendArtifactExportStatusRow {
    param(
        [ref]$RowsHtml,
        [string]$Categoria,
        [string]$Artefato,
        [string]$StatusText,
        [string]$PathValue,
        [string]$Observacao
    )

    $cssClass = LogStatusClass (([string](Nz $StatusText '')).Trim().ToUpperInvariant())
    if ([string](Nz $cssClass '').Trim() -eq '') { $cssClass = 'neutral' }
    $sizeBytes = GetPathSizeBytesSafe $PathValue
    if ([double](To-DoubleSafe $sizeBytes) -ge 0) {
        $sizeText = FormatBytes $sizeBytes
    }
    else {
        $sizeText = '-'
    }
    $RowsHtml.Value = [string](Nz $RowsHtml.Value '')
    $RowsHtml.Value += "<tr class='row-" + $cssClass + "'><td>" + (HtmlEncode (Nz $Categoria '-')) + "</td><td>" + (HtmlEncode (Nz $Artefato '-')) + "</td><td><span class='chip " + $cssClass + "'>" + (HtmlEncode (Nz $StatusText '-')) + "</span></td><td class='path'>" + (HtmlEncode (Nz $PathValue '-')) + "</td><td>" + (HtmlEncode $sizeText) + "</td><td class='path'>" + (HtmlEncode (Nz $Observacao '-')) + "</td></tr>"
}

function PsQuoteLiteral {
    param(
        [string]$Value
    )
    return "'" + ([string](Nz $Value '')).Replace("'", "''") + "'"
}

function BuildPsCopyPatternPreserveCmd {
    param(
        [string]$SrcDir,
        [string]$FilePattern,
        [bool]$RecurseFlag,
        [string]$DestDir
    )

    $recOpt = ''
    if ($RecurseFlag) { $recOpt = ' -Recurse' }
    return "powershell -NoProfile -Command ""`$ErrorActionPreference='SilentlyContinue'; `$src=" + (PsQuoteLiteral $SrcDir) + "; `$dst=" + (PsQuoteLiteral $DestDir) + "; if(-not (Test-Path -LiteralPath `$src)){ 'NO_SOURCE'; exit 0 }; New-Item -ItemType Directory -Force -Path `$dst | Out-Null; `$n=0; Get-ChildItem -LiteralPath `$src -Filter " + (PsQuoteLiteral $FilePattern) + " -File" + $recOpt + " -ErrorAction SilentlyContinue | ForEach-Object { `$rel=`$_.FullName.Substring(`$src.Length).TrimStart('\'); `$target=Join-Path `$dst `$rel; `$parent=Split-Path -Parent `$target; if(`$parent){ New-Item -ItemType Directory -Force -Path `$parent | Out-Null }; Copy-Item -LiteralPath `$_.FullName -Destination `$target -Force -ErrorAction SilentlyContinue; if(Test-Path -LiteralPath `$target){ try { `$di=Get-Item -LiteralPath `$target -Force; `$di.CreationTime=`$_.CreationTime; `$di.LastWriteTime=`$_.LastWriteTime; `$di.LastAccessTime=`$_.LastAccessTime; `$di.Attributes=`$_.Attributes } catch {}; `$n++ } }; 'COPIED=' + `$n"""
}

function BuildPsCopySingleFilePreserveCmd {
    param(
        [string]$SrcFile,
        [string]$DestDir,
        [string]$DestName
    )

    $targetPath = Join-Path $DestDir (SanitizeFileNameComponent $DestName)
    return "powershell -NoProfile -Command ""`$ErrorActionPreference='SilentlyContinue'; `$src=" + (PsQuoteLiteral $SrcFile) + "; `$dstDir=" + (PsQuoteLiteral $DestDir) + "; `$dst=" + (PsQuoteLiteral $targetPath) + "; if(-not (Test-Path -LiteralPath `$src)){ 'NO_SOURCE'; exit 0 }; New-Item -ItemType Directory -Force -Path `$dstDir | Out-Null; try { Copy-Item -LiteralPath `$src -Destination `$dst -Force -ErrorAction Stop; `$si=Get-Item -LiteralPath `$src -Force; `$di=Get-Item -LiteralPath `$dst -Force; `$di.CreationTime=`$si.CreationTime; `$di.LastWriteTime=`$si.LastWriteTime; `$di.LastAccessTime=`$si.LastAccessTime; `$di.Attributes=`$si.Attributes; 'COPIED=1' } catch { 'ERROR=' + `$_.Exception.Message }"""
}

function ExportPatternArtifactCategory {
    param(
        [string]$CategoryName,
        [string]$DisplayName,
        [string]$SrcDir,
        [string]$FilePattern,
        [bool]$RecurseFlag,
        [int]$TimeoutSecs
    )

    $targetDir = GetRunExportNestedSubDir ('artefatos\' + $CategoryName)
    $beforeCount = CountFilesRecursiveSafe $targetDir
    $cmdOut = GetCommandOutputWithTimeout -CommandText (BuildPsCopyPatternPreserveCmd -SrcDir $SrcDir -FilePattern $FilePattern -RecurseFlag $RecurseFlag -DestDir $targetDir) -TimeoutSecs ([int](To-LongSafe $TimeoutSecs))
    $afterCount = CountFilesRecursiveSafe $targetDir
    $deltaCount = [long](To-LongSafe $afterCount) - [long](To-LongSafe $beforeCount)
    if ($deltaCount -gt 0) {
        $script:smallArtifactExportCount = [long](To-LongSafe $script:smallArtifactExportCount) + $deltaCount
        $statusTxt = 'OK'
        $noteTxt = 'Arquivos copiados: ' + $deltaCount + ' | Origem: ' + $SrcDir + ' | Filtro: ' + $FilePattern
    }
    elseif (([string](Nz $cmdOut '')).ToUpperInvariant().Contains('NO_SOURCE')) {
        $statusTxt = 'WARN'
        $noteTxt = 'Origem nao encontrada: ' + $SrcDir
    }
    else {
        $statusTxt = 'WARN'
        $noteTxt = 'Nenhum arquivo copiado. Origem: ' + $SrcDir + ' | Filtro: ' + $FilePattern
    }
    if ([string](Nz $cmdOut '').Trim() -ne '') { $noteTxt = $noteTxt + ' | Resultado: ' + (ShortCommandForLog $cmdOut) }
    AppendArtifactExportStatusRow -RowsHtml ([ref]$script:strSmallArtifactExportRows) -Categoria 'Pequenos artefatos' -Artefato $DisplayName -StatusText $statusTxt -PathValue $targetDir -Observacao $noteTxt
}

function ExportSingleFileArtifactCategory {
    param(
        [string]$CategoryName,
        [string]$DisplayName,
        [string]$SrcFile,
        [int]$TimeoutSecs
    )

    $targetDir = GetRunExportNestedSubDir ('artefatos\' + $CategoryName)
    $beforeCount = CountFilesRecursiveSafe $targetDir
    $outName = [System.IO.Path]::GetFileName([string](Nz $SrcFile ''))
    if ([string](Nz $outName '').Trim() -eq '') { $outName = SanitizeFileNameComponent $DisplayName }
    $cmdOut = GetCommandOutputWithTimeout -CommandText (BuildPsCopySingleFilePreserveCmd -SrcFile $SrcFile -DestDir $targetDir -DestName $outName) -TimeoutSecs ([int](To-LongSafe $TimeoutSecs))
    $afterCount = CountFilesRecursiveSafe $targetDir
    $deltaCount = [long](To-LongSafe $afterCount) - [long](To-LongSafe $beforeCount)
    if ($deltaCount -gt 0) {
        $script:smallArtifactExportCount = [long](To-LongSafe $script:smallArtifactExportCount) + $deltaCount
        $statusTxt = 'OK'
        $noteTxt = 'Arquivo copiado com preservacao de timestamps/atributos (quando permitido). Origem: ' + $SrcFile
    }
    elseif (([string](Nz $cmdOut '')).ToUpperInvariant().Contains('NO_SOURCE')) {
        $statusTxt = 'WARN'
        $noteTxt = 'Arquivo nao encontrado: ' + $SrcFile
    }
    else {
        $statusTxt = 'WARN'
        $noteTxt = 'Falha/arquivo bloqueado: ' + $SrcFile
    }
    if ([string](Nz $cmdOut '').Trim() -ne '') { $noteTxt = $noteTxt + ' | Resultado: ' + (ShortCommandForLog $cmdOut) }
    AppendArtifactExportStatusRow -RowsHtml ([ref]$script:strSmallArtifactExportRows) -Categoria 'Pequenos artefatos' -Artefato $DisplayName -StatusText $statusTxt -PathValue $targetDir -Observacao $noteTxt
}

function ExportEventLogArtifacts {
    $evtxDir = GetRunExportNestedSubDir 'artefatos\eventos\evtx'
    $channels = @('Application', 'System', 'Security', 'Setup', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational')

    foreach ($ch in $channels) {
        $filePath = Join-Path $evtxDir ((SanitizeFileNameComponent $ch) + '.evtx')
        $cmdOut = GetCommandOutputWithTimeout -CommandText ('cmd /c wevtutil epl "' + $ch + '" "' + $filePath + '" /ow:true 2>&1') -TimeoutSecs 75
        if (Test-Path -LiteralPath $filePath -PathType Leaf) {
            $script:evtxExportCount = [long](To-LongSafe $script:evtxExportCount) + 1
            $statusTxt = 'OK'
            $noteTxt = 'Exportado via wevtutil epl'
        }
        elseif (([string](Nz $cmdOut '')).ToUpperInvariant().Contains('FAILED') -or ([string](Nz $cmdOut '')).ToUpperInvariant().Contains('ERRO')) {
            $statusTxt = 'WARN'
            $noteTxt = 'Falha ao exportar canal via wevtutil'
        }
        else {
            $statusTxt = 'WARN'
            $noteTxt = 'Canal indisponivel ou sem permissao'
        }
        if ([string](Nz $cmdOut '').Trim() -ne '') { $noteTxt = $noteTxt + ' | Resultado: ' + (ShortCommandForLog $cmdOut) }
        AppendArtifactExportStatusRow -RowsHtml ([ref]$script:strEventLogArtifactExportRows) -Categoria 'Eventos' -Artefato ($ch + ' (.evtx)') -StatusText $statusTxt -PathValue $filePath -Observacao $noteTxt
    }

    $legacyEvtDir = GetRunExportNestedSubDir 'artefatos\eventos\evt'
    $legacyCountBefore = CountFilesRecursiveSafe $legacyEvtDir
    $legacyDirs = @((Join-Path $env:WINDIR 'System32\Config'), (Join-Path $env:WINDIR 'System32\winevt\Logs'))
    foreach ($legacySrc in $legacyDirs) {
        try {
            if (Test-Path -LiteralPath $legacySrc -PathType Container) {
                $legacyFiles = Get-ChildItem -LiteralPath $legacySrc -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -ieq '.evt' }
                foreach ($legacyFile in $legacyFiles) {
                    try {
                        Copy-Item -LiteralPath $legacyFile.FullName -Destination (Join-Path $legacyEvtDir $legacyFile.Name) -Force -ErrorAction SilentlyContinue
                    }
                    catch {
                    }
                }
            }
        }
        catch {
        }
    }
    $legacyCountAfter = CountFilesRecursiveSafe $legacyEvtDir
    $copiedLegacy = [long](To-LongSafe $legacyCountAfter) - [long](To-LongSafe $legacyCountBefore)
    if ($copiedLegacy -gt 0) {
        $script:evtExportCount = [long](To-LongSafe $script:evtExportCount) + $copiedLegacy
        AppendArtifactExportStatusRow -RowsHtml ([ref]$script:strEventLogArtifactExportRows) -Categoria 'Eventos' -Artefato 'Arquivos legados .evt' -StatusText 'OK' -PathValue $legacyEvtDir -Observacao ('Arquivos .evt copiados: ' + $copiedLegacy)
    }
    else {
        AppendArtifactExportStatusRow -RowsHtml ([ref]$script:strEventLogArtifactExportRows) -Categoria 'Eventos' -Artefato 'Arquivos legados .evt' -StatusText 'WARN' -PathValue $legacyEvtDir -Observacao 'Nenhum arquivo .evt localizado (comum em Windows modernos).'
    }
}

function ExportRegistryRootArtifacts {
    $regDir = GetRunExportNestedSubDir 'artefatos\originais\registro'
    $roots = @('HKCR', 'HKCU', 'HKLM', 'HKU', 'HKCC')
    $labels = @('HKEY_CLASSES_ROOT', 'HKEY_CURRENT_USER', 'HKEY_LOCAL_MACHINE', 'HKEY_USERS', 'HKEY_CURRENT_CONFIG')
    $files = @('HKEY_CLASSES_ROOT.reg', 'HKEY_CURRENT_USER.reg', 'HKEY_LOCAL_MACHINE.reg', 'HKEY_USERS.reg', 'HKEY_CURRENT_CONFIG.reg')

    for ($i = 0; $i -lt $roots.Count; $i++) {
        $rootKey = [string]$roots[$i]
        $filePath = Join-Path $regDir ([string]$files[$i])
        $timeoutSecs = 240
        if ($rootKey.ToUpperInvariant() -eq 'HKU' -or $rootKey.ToUpperInvariant() -eq 'HKCC') { $timeoutSecs = 420 }
        $cmdOut = GetCommandOutputWithTimeout -CommandText ('cmd /c reg export ' + $rootKey + ' "' + $filePath + '" /y 2>&1') -TimeoutSecs $timeoutSecs
        if (Test-Path -LiteralPath $filePath -PathType Leaf) {
            $script:registryRootExportCount = [long](To-LongSafe $script:registryRootExportCount) + 1
            $statusTxt = 'OK'
            $noteTxt = 'Exportado como .reg'
        }
        else {
            $statusTxt = 'WARN'
            $noteTxt = 'Falha/timeout/permissao insuficiente ao exportar raiz'
        }
        if ($timeoutSecs -ne 240) { $noteTxt = $noteTxt + ' | timeout_s=' + $timeoutSecs }
        if ([string](Nz $cmdOut '').Trim() -ne '') { $noteTxt = $noteTxt + ' | Resultado: ' + (ShortCommandForLog $cmdOut) }
        AppendArtifactExportStatusRow -RowsHtml ([ref]$script:strRegistryRootArtifactExportRows) -Categoria 'Registro' -Artefato ([string]$labels[$i]) -StatusText $statusTxt -PathValue $filePath -Observacao $noteTxt
    }
}

function ExportSmallForensicArtifacts {
    EnsureHostIdentityContext
    $userProfile = [Environment]::GetFolderPath('UserProfile')
    $appDataRoam = [Environment]::GetFolderPath('ApplicationData')
    $localAppData = [Environment]::GetFolderPath('LocalApplicationData')

    ExportSingleFileArtifactCategory -CategoryName 'mft' -DisplayName '$MFT (C:)' -SrcFile 'C:\$MFT' -TimeoutSecs 120
    ExportPatternArtifactCategory -CategoryName 'atalhos\desktop' -DisplayName 'Atalhos (.lnk) - Desktop' -SrcDir (Join-Path $userProfile 'Desktop') -FilePattern '*.lnk' -RecurseFlag $true -TimeoutSecs 120
    ExportPatternArtifactCategory -CategoryName 'atalhos\downloads' -DisplayName 'Atalhos (.lnk) - Downloads' -SrcDir (Join-Path $userProfile 'Downloads') -FilePattern '*.lnk' -RecurseFlag $true -TimeoutSecs 120
    ExportPatternArtifactCategory -CategoryName 'atalhos\recent' -DisplayName 'Atalhos (.lnk) - Recent' -SrcDir (Join-Path $appDataRoam 'Microsoft\Windows\Recent') -FilePattern '*.lnk' -RecurseFlag $true -TimeoutSecs 120
    ExportPatternArtifactCategory -CategoryName 'thumbs\desktop' -DisplayName 'Thumbs.db - Desktop' -SrcDir (Join-Path $userProfile 'Desktop') -FilePattern 'Thumbs.db' -RecurseFlag $true -TimeoutSecs 90
    ExportPatternArtifactCategory -CategoryName 'thumbs\downloads' -DisplayName 'Thumbs.db - Downloads' -SrcDir (Join-Path $userProfile 'Downloads') -FilePattern 'Thumbs.db' -RecurseFlag $true -TimeoutSecs 90

    if ([string](Nz $script:hostLoggedUserSid '').Trim() -ne '' -and [string](Nz $script:hostLoggedUserSid '').Trim() -ne '-') {
        $recyclePath = 'C:\$Recycle.Bin\' + [string]$script:hostLoggedUserSid
        ExportPatternArtifactCategory -CategoryName 'lixeira' -DisplayName 'Lixeira ($I*) - SID atual' -SrcDir $recyclePath -FilePattern '$I*' -RecurseFlag $true -TimeoutSecs 150
    }
    else {
        AppendArtifactExportStatusRow -RowsHtml ([ref]$script:strSmallArtifactExportRows) -Categoria 'Pequenos artefatos' -Artefato 'Lixeira ($I*) - SID atual' -StatusText 'WARN' -PathValue (GetRunExportNestedSubDir 'artefatos\lixeira') -Observacao 'SID do usuario logado indisponivel para montar caminho da lixeira.'
    }

    ExportSingleFileArtifactCategory -CategoryName 'hives' -DisplayName 'NTUSER.DAT (usuario atual)' -SrcFile (Join-Path $userProfile 'NTUSER.DAT') -TimeoutSecs 180
    ExportSingleFileArtifactCategory -CategoryName 'hives' -DisplayName 'USRCLASS.DAT (usuario atual)' -SrcFile (Join-Path $localAppData 'Microsoft\Windows\UsrClass.dat') -TimeoutSecs 180
}

function ExportOriginalArtifactsSection {
    EnsureHostIdentityContext
    ExportEventLogArtifacts
    ExportRegistryRootArtifacts
    ExportSmallForensicArtifacts
}

function GetForensicBundleSourceItems {
    param(
        [string]$MainHtmlFile,
        [bool]$LowDiskMode
    )

    $candidates = @(
        $MainHtmlFile,
        $script:strLogHtmlFilePath,
        (Join-Path $PSScriptRoot 'resultados_coletados'),
        (GetRunExportBaseDir)
    )
    if (-not $LowDiskMode) {
        $candidates += @($script:strCustodyFilePath)
    }

    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $items = @()
    foreach ($c in $candidates) {
        $p = [string](Nz $c '')
        if ($p.Trim() -eq '') { continue }
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $resolved = $p
        try { $resolved = (Resolve-Path -LiteralPath $p -ErrorAction Stop).Path } catch {}
        if ($set.Add($resolved)) {
            $items += $resolved
        }
    }
    return $items
}

function BuildForensicBundleEntries {
    param(
        [string[]]$SourceItems
    )

    $entries = New-Object 'System.Collections.Generic.List[object]'
    $entryNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($src in $SourceItems) {
        $srcNorm = ([string](Nz $src '')).Trim()
        if ($srcNorm -eq '') { continue }
        if (-not (Test-Path -LiteralPath $srcNorm)) { continue }

        if (Test-Path -LiteralPath $srcNorm -PathType Leaf) {
            $entryName = [string](Nz (Split-Path -Leaf $srcNorm) '')
            if ($entryName -ne '' -and $entryNames.Add($entryName)) {
                $entries.Add([PSCustomObject]@{ SourcePath = $srcNorm; EntryName = $entryName })
            }
            continue
        }

        if (Test-Path -LiteralPath $srcNorm -PathType Container) {
            $rootPath = $srcNorm.TrimEnd('\')
            $rootName = [string](Nz (Split-Path -Leaf $rootPath) 'pasta')
            if ($rootName.Trim() -eq '') { $rootName = 'pasta' }

            try {
                $files = Get-ChildItem -LiteralPath $rootPath -File -Recurse -Force -ErrorAction Stop
            }
            catch {
                $files = @()
            }
            foreach ($f in $files) {
                $fullPath = [string](Nz $f.FullName '')
                if ($fullPath -eq '') { continue }
                $rel = ''
                try {
                    $rel = $fullPath.Substring($rootPath.Length).TrimStart('\')
                }
                catch {
                    $rel = [string](Nz $f.Name '')
                }
                if ($rel.Trim() -eq '') { $rel = [string](Nz $f.Name 'arquivo.bin') }
                $entryName = $rootName + '/' + $rel.Replace('\', '/')
                if ($entryNames.Add($entryName)) {
                    $entries.Add([PSCustomObject]@{ SourcePath = $fullPath; EntryName = $entryName })
                }
            }
        }
    }

    return @($entries)
}

function OpenForensicBundleReadableStream {
    param(
        [string]$FilePath,
        [ref]$UsedFallback,
        [ref]$FallbackPath
    )

    $UsedFallback.Value = $false
    $FallbackPath.Value = ''
    $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete

    try {
        return [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
    }
    catch {
    }

    $tmpFile = Join-Path ([System.IO.Path]::GetTempPath()) ('telemetry_bundle_' + [guid]::NewGuid().ToString('N') + [System.IO.Path]::GetExtension($FilePath))
    try {
        Copy-Item -LiteralPath $FilePath -Destination $tmpFile -Force -ErrorAction Stop
        $fsTmp = [System.IO.File]::Open($tmpFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        $UsedFallback.Value = $true
        $FallbackPath.Value = $tmpFile
        return $fsTmp
    }
    catch {
    }

    $srcDir = Split-Path -Parent $FilePath
    $srcName = Split-Path -Leaf $FilePath
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ('telemetry_bundle_dir_' + [guid]::NewGuid().ToString('N'))
    try {
        [void](New-Item -ItemType Directory -Path $tmpDir -Force -ErrorAction Stop)
        $rcCmd = 'cmd /c robocopy "' + $srcDir + '" "' + $tmpDir + '" "' + $srcName + '" /R:1 /W:1 /NFL /NDL /NJH /NJS /NP /COPY:DAT /ZB'
        [void](GetCommandOutputWithLocalTimeoutSilent -CommandText $rcCmd -TimeoutSecs 40)
        $robFile = Join-Path $tmpDir $srcName
        if (Test-Path -LiteralPath $robFile -PathType Leaf) {
            $fsRob = [System.IO.File]::Open($robFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
            $UsedFallback.Value = $true
            $FallbackPath.Value = $tmpDir
            return $fsRob
        }
    }
    catch {
    }

    try {
        if (Test-Path -LiteralPath $tmpDir -PathType Container) {
            Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
    }
    return $null
}

function CreateForensicNoCompressionZip {
    param(
        [string]$DestinationZipPath,
        [object[]]$FileEntries
    )

    $detail = New-Object System.Text.StringBuilder
    $added = 0
    $skipped = 0
    $ok = $false
    $zipFs = $null
    $archive = $null

    try { Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue } catch {}
    try { Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue } catch {}

    try {
        if (Test-Path -LiteralPath $DestinationZipPath -PathType Leaf) {
            Remove-Item -LiteralPath $DestinationZipPath -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
    }

    try {
        $zipFs = [System.IO.File]::Open($DestinationZipPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $archive = New-Object System.IO.Compression.ZipArchive($zipFs, [System.IO.Compression.ZipArchiveMode]::Create, $false)

        foreach ($entryDef in $FileEntries) {
            $src = [string](Nz $entryDef.SourcePath '')
            $entryName = [string](Nz $entryDef.EntryName '')
            if ($src.Trim() -eq '' -or $entryName.Trim() -eq '') { continue }

            $usedFallback = $false
            $fallbackPath = ''
            $inStream = OpenForensicBundleReadableStream -FilePath $src -UsedFallback ([ref]$usedFallback) -FallbackPath ([ref]$fallbackPath)
            if ($null -eq $inStream) {
                $skipped++
                [void]$detail.AppendLine('ZIP_SKIP_IN_USE=' + $src)
                continue
            }

            $entry = $null
            $outStream = $null
            try {
                $entry = $archive.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::NoCompression)
                try {
                    $fi = Get-Item -LiteralPath $src -Force -ErrorAction Stop
                    $ts = $fi.LastWriteTime
                    if ($ts.Year -ge 1980) {
                        $entry.LastWriteTime = [datetimeoffset]$ts
                    }
                }
                catch {
                }
                $outStream = $entry.Open()
                $inStream.CopyTo($outStream)
                $added++
                if ($usedFallback) {
                    [void]$detail.AppendLine('ZIP_FALLBACK_IN_USE_OK=' + $src)
                }
            }
            catch {
                $skipped++
                [void]$detail.AppendLine('ZIP_ERR_ENTRY=' + $src + ' | ' + $_.Exception.Message)
                if ($null -ne $entry) {
                    try { $entry.Delete() } catch {}
                }
            }
            finally {
                if ($null -ne $outStream) { $outStream.Close() }
                $inStream.Close()
                $fb = [string](Nz $fallbackPath '')
                if ($fb.Trim() -ne '') {
                    try {
                        if (Test-Path -LiteralPath $fb -PathType Leaf) {
                            Remove-Item -LiteralPath $fb -Force -ErrorAction SilentlyContinue
                        }
                        elseif (Test-Path -LiteralPath $fb -PathType Container) {
                            Remove-Item -LiteralPath $fb -Recurse -Force -ErrorAction SilentlyContinue
                        }
                    }
                    catch {
                    }
                }
            }
        }
    }
    catch {
        [void]$detail.AppendLine('ZIP_ERROR=' + $_.Exception.Message)
    }
    finally {
        if ($null -ne $archive) { $archive.Dispose() }
        if ($null -ne $zipFs) { $zipFs.Close() }
    }

    if (Test-Path -LiteralPath $DestinationZipPath -PathType Leaf) {
        $ok = $true
    }

    return [PSCustomObject]@{
        Success      = $ok
        AddedCount   = $added
        SkippedCount = $skipped
        Detail       = $detail.ToString()
    }
}

function CreateStatusBundleZip {
    param(
        [string]$MainHtmlFile
    )

    $lowDiskMode = [bool](Nz $script:LowDiskSpaceMode $false)

    EnsureHostIdentityContext
    $zipBaseName = (SanitizeFileNameComponent (IIfBool (([string](Nz $script:hostServiceTag '').Trim() -ne '') -and ([string]$script:hostServiceTag -ne '-')) $script:hostServiceTag $script:strComputer)) + '.zip'
    $script:bundleZipPath = Join-Path $PSScriptRoot $zipBaseName
    $script:bundleZipBytes = 0

    if ($lowDiskMode) {
        LogCustody -Etapa 'BUNDLE' -Status 'WARN' -Detalhes ('Espaco baixo detectado; tentando ZIP forense sem compressao. Livre=' + (FormatBytes $script:CurrentFreeSpaceBytes))
    }

    $sourceItems = GetForensicBundleSourceItems -MainHtmlFile $MainHtmlFile -LowDiskMode $lowDiskMode
    $entryItems = BuildForensicBundleEntries -SourceItems $sourceItems
    $cmdOut = 'ZIP_EMPTY'
    if (@($entryItems).Count -gt 0) {
        $zipResult = CreateForensicNoCompressionZip -DestinationZipPath $script:bundleZipPath -FileEntries $entryItems
        $cmdOut = 'ZIP_NO_COMPRESSION_ADDED=' + [long](To-LongSafe $zipResult.AddedCount) + ' | skipped=' + [long](To-LongSafe $zipResult.SkippedCount)
        if ([string](Nz $zipResult.Detail '').Trim() -ne '') {
            $cmdOut = $cmdOut + ' | detalhe=' + (ShortCommandForLog ([string](Nz $zipResult.Detail '')))
        }
    }

    if (-not (Test-Path -LiteralPath $script:bundleZipPath -PathType Leaf)) {
        $minimalSources = @($MainHtmlFile, $script:strLogHtmlFilePath) | Where-Object { Test-Path -LiteralPath $_ }
        $minimalEntries = BuildForensicBundleEntries -SourceItems $minimalSources
        if (@($minimalEntries).Count -gt 0) {
            $zipRetry = CreateForensicNoCompressionZip -DestinationZipPath $script:bundleZipPath -FileEntries $minimalEntries
            $cmdOut = [string](Nz $cmdOut '') + "`r`nZIP_RETRY_MINIMAL_ADDED=" + [long](To-LongSafe $zipRetry.AddedCount) + ' | skipped=' + [long](To-LongSafe $zipRetry.SkippedCount)
            if ([string](Nz $zipRetry.Detail '').Trim() -ne '') {
                $cmdOut = $cmdOut + ' | detalhe=' + (ShortCommandForLog ([string](Nz $zipRetry.Detail '')))
            }
        }
    }

    if (Test-Path -LiteralPath $script:bundleZipPath -PathType Leaf) {
        $script:bundleZipBytes = GetFileSizeBytesSafe $script:bundleZipPath
        LogCustody -Etapa 'BUNDLE' -Status 'OK' -Detalhes ('Pacote forense sem compressao: ' + $script:bundleZipPath + ' | tamanho=' + (FormatBytes $script:bundleZipBytes) + ' | itens=' + [long](To-LongSafe @($entryItems).Count))
        $zipMd5 = GetFileMD5 $script:bundleZipPath
        if (LooksLikeMd5Hex $zipMd5) {
            LogCustody -Etapa 'INTEGRITY' -Status 'OK' -Detalhes ('MD5 bundle zip forense=' + $zipMd5)
        }
        else {
            LogCustody -Etapa 'INTEGRITY' -Status 'WARN' -Detalhes 'Nao foi possivel calcular MD5 do bundle zip'
        }
    }
    else {
        LogCustody -Etapa 'BUNDLE' -Status 'WARN' -Detalhes ('Falha ao compilar pacote ' + $zipBaseName + ' | ' + (ShortCommandForLog $cmdOut))
    }
}

function ReplaceStatusLogZipPlaceholders {
    param(
        [double]$BaseMaxBytes,
        [string]$FallbackStamp,
        [double]$ReportBytes,
        [double]$CsvBytes,
        [string]$ExportDir
    )

    $zipPathText = '-'
    $zipSizeText = '-'
    $zipMtimeText = HtmlEncode (Nz $FallbackStamp '-')
    $zipMd5Text = '-'
    $zipBarPct = 0
    $reportBarPct = 0
    $csvBarPct = 0
    $logBarPct = 0
    $auditBarPct = 0

    $logFilePath = [string](Nz $script:strLogHtmlFilePath $script:strLogHtmlFile)
    $logSize = GetFileSizeBytesSafe $logFilePath
    $auditSize = 0
    if ($script:AuditJsonPath -and (Test-Path -LiteralPath $script:AuditJsonPath)) {
        $auditSize = (Get-Item -LiteralPath $script:AuditJsonPath).Length
    }

    $finalMaxBytes = [double](To-DoubleSafe $BaseMaxBytes)
    if ([double]$logSize -gt $finalMaxBytes) { $finalMaxBytes = [double]$logSize }
    if ([double]$auditSize -gt $finalMaxBytes) { $finalMaxBytes = [double]$auditSize }
    if ($finalMaxBytes -le 0.0) { $finalMaxBytes = 1.0 }

    if ([string](Nz $script:bundleZipPath '').Trim() -ne '' -and (Test-Path -LiteralPath $script:bundleZipPath -PathType Leaf)) {
        $zipPathText = HtmlEncode $script:bundleZipPath
        $zipSizeText = HtmlEncode (FormatBytes $script:bundleZipBytes)
        $zipMtimeText = HtmlEncode (GetFileDateModifiedSafe $script:bundleZipPath)
        $zipMd5Text = HtmlEncode (GetFileMD5 $script:bundleZipPath)
        if ([double](To-DoubleSafe $script:bundleZipBytes) -gt $finalMaxBytes) { $finalMaxBytes = [double](To-DoubleSafe $script:bundleZipBytes) }
    }
    $finalMaxBytes = [double](To-DoubleSafe $finalMaxBytes)
    $zipBarPct = PercentWidthPct -ValueNum ([double]$script:bundleZipBytes) -MaxNum $finalMaxBytes
    $reportBarPct = PercentWidthPct -ValueNum ([double](To-DoubleSafe $ReportBytes)) -MaxNum $finalMaxBytes
    $csvBarPct = PercentWidthPct -ValueNum ([double](To-DoubleSafe $CsvBytes)) -MaxNum $finalMaxBytes
    $logBarPct = PercentWidthPct -ValueNum ([double](To-DoubleSafe $logSize)) -MaxNum $finalMaxBytes
    $auditBarPct = PercentWidthPct -ValueNum ([double](To-DoubleSafe $auditSize)) -MaxNum $finalMaxBytes

    $exportBytes = 0.0
    if (Test-Path -LiteralPath $ExportDir -PathType Container) {
        $meas = (Get-ChildItem -LiteralPath $ExportDir -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum)
        $exportBytes = [double](To-DoubleSafe $meas.Sum)
    }
    $exportSizeText = 'N/A'
    if ($exportBytes -gt 0) { $exportSizeText = FormatBytes $exportBytes }

    $logFilePath = [string](Nz $script:strLogHtmlFilePath $script:strLogHtmlFile)
    if (-not (Test-Path -LiteralPath $logFilePath -PathType Leaf)) { return }
    try {
        $htmlText = [string](Get-Content -LiteralPath $logFilePath -Raw -Encoding String -ErrorAction Stop)
    }
    catch {
        return
    }

    $logSize = GetFileSizeBytesSafe $logFilePath

    $replacements = @{
        '__ZIP_PATH__'         = [string]$zipPathText
        '__ZIP_SIZE_TEXT__'    = [string]$zipSizeText
        '__ZIP_MTIME__'        = [string]$zipMtimeText
        '__ZIP_MD5__'          = [string]$zipMd5Text
        '__ZIP_BAR_PCT__'      = [string]$zipBarPct
        '__REPORT_BAR_PCT__'   = [string]$reportBarPct
        '__CSV_BAR_PCT__'      = [string]$csvBarPct
        '__LOG_BAR_PCT__'      = [string]$logBarPct
        '__AUDIT_BAR_PCT__'    = [string]$auditBarPct
        '__LOG_SIZE_TEXT__'    = [string](FormatBytes $logSize)
        '__LOG_MD5__'          = [string](GetFileMD5 $logFilePath)
        '__EXPORT_SIZE_TEXT__' = [string]$exportSizeText
    }

    foreach ($key in $replacements.Keys) {
        $val = [string]$replacements[$key]
        # Use native -replace instead of .Replace() for better type stability
        # We escape the key just in case, although these are standard strings
        $escKey = [regex]::Escape($key)
        $htmlText = $htmlText -replace $escKey, $val
    }

    try {
        Set-Content -LiteralPath $logFilePath -Value $htmlText -Encoding String -Force -ErrorAction SilentlyContinue
    }
    catch {
    }
}

function WriteStatusIncidentFocusSection {
    param(
        [System.IO.StreamWriter]$LogFile
    )

    Write-VbsLine $LogFile "<section class='section' style='margin-top:14px'>"
    Write-VbsLine $LogFile "<h2>Foco de triagem (eventos e chaves de registro agrupados)</h2>"
    Write-VbsLine $LogFile "<div class='section-note'>Guia rapido para leitura do status/timeline e correlacao no host. Eventos abaixo refletem grupos priorizados para incidente e praticas de referencia ISO/IEC 27035/27037/27043 e NIST SP 800-61/800-86/800-92.</div>"
    Write-VbsLine $LogFile "<h3>Eventos Windows / PowerShell / Sysmon (grupos priorizados)</h3>"
    Write-VbsLine $LogFile "<div class='scroll'><table><tr><th>Grupo</th><th>Eventos / IDs</th><th>Foco analitico</th></tr>"
    Write-VbsLine $LogFile "<tr><td>Autenticacao / Acesso</td><td>4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4771, 4776, 4740</td><td>Logon sucesso/falha, credenciais explicitas, privilegios especiais, Kerberos/NTLM e bloqueio de conta (spray/bruteforce/movimentacao lateral).</td></tr>"
    Write-VbsLine $LogFile "<tr><td>RDP</td><td>4624 (Logon Type 10), 4778, 4779</td><td>Logon remoto interativo, reconexao e desconexao de sessao. Correlacionar IP/origem/horario.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Contas / Privilegio / Persistencia</td><td>4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4756, 4738, 4767</td><td>Criacao, habilitacao, reset/troca de senha, alteracao de grupos privilegiados e modificacoes de conta.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Execucao de processo / Persistencia</td><td>4688, 4689, 4697, 7045, 7040, 4698, 4702, 4719, 1100, 1102, 104</td><td>Processos, servicos, tarefas agendadas, alteracoes de auditoria e limpeza/parada de logs (defense evasion).</td></tr>"
    Write-VbsLine $LogFile "<tr><td>PowerShell</td><td>4103, 4104, 4105, 4106</td><td>Module logging, script block e pipeline (execucao fileless/ofuscada e trilha de comando).</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Sysmon (se habilitado)</td><td>1, 3, 4, 7, 8, 10, 11, 13</td><td>Processo, rede, estado do servico, DLL load, injecao, acesso a processo, criacao de arquivo e modificacao de registro.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>File system / Delecao em massa</td><td>4656, 4659, 4663, 4660, 4670, 4907</td><td>Handles, delete intent, operacoes em objetos, delecao, ACL e SACL (picos e comportamento destrutivo).</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Rede / Exfiltracao</td><td>5156, 5157, 5158, 5140, 5145, 5142, 5144</td><td>Conexoes permitidas/bloqueadas, bind local, shares SMB e operacoes detalhadas em share.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>BITS (exfiltracao stealth)</td><td>59, 60, 63</td><td>Criacao, transferencia e conclusao de jobs BITS para upload/download discreto.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Credential access / Dump</td><td>4688 (ferramentas dump), 4656/4663 (LSASS), Sysmon 10 (LSASS), Sysmon 11 (.dmp)</td><td>Execucao de utilitarios de dump e acesso/leitura de memoria sensivel (LSASS).</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Compressao / Preparacao para exfil</td><td>4688 (7z/rar/tar/PowerShell), 4663 (leitura massiva), Sysmon 11 (.zip/.7z/.rar)</td><td>Preparacao de lotes para exfiltracao e criacao de artefatos compactados.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Shadow copy / Impacto / Ransomware</td><td>System 25, 8193, 8222, 5038</td><td>VSS/shadow copy, erros de VSS e integridade de codigo (sinais de impacto/evasao).</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Prioridade alta em incidente</td><td>4688, 4663, 4624/4625, 4672, 4769, 7045, 4698, 5156, 1102, 4104, Sysmon 1/3/10/11</td><td>Conjunto minimo de priorizacao para triagem inicial, escopo e contencao.</td></tr>"
    Write-VbsLine $LogFile "</table></div>"
    Write-VbsLine $LogFile "<h3>Chaves de registro para correlacao (persistencia, auditoria e acesso)</h3>"
    Write-VbsLine $LogFile "<div class='section-note'>Lista de referencia para checagem manual/automatizada. Alguns itens podem nao existir conforme versao/politica do Windows.</div>"
    Write-VbsLine $LogFile "<div class='scroll'><table><tr><th>Grupo</th><th>Chaves (HKLM/HKCU)</th><th>Uso forense</th></tr>"
    Write-VbsLine $LogFile "<tr><td>RDP / Terminal Services</td><td><code>HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server</code><br><code>HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp</code><br><code>HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services</code></td><td>Habilitacao de RDP, configuracoes de sessao e politicas de acesso remoto.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>PowerShell Logging</td><td><code>HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging</code><br><code>HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging</code><br><code>HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription</code></td><td>Verifica se 4103/4104 e transcricao estao habilitados e como foram configurados.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Auditoria / Event Log</td><td><code>HKLM\SYSTEM\CurrentControlSet\Services\EventLog</code><br><code>HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog</code><br><code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels</code></td><td>Retencao, canais e parametros de logs (inclui indicios de reducao/alteracao de trilha).</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Persistencia - Run / Winlogon</td><td><code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code><br><code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce</code><br><code>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code><br><code>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce</code><br><code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon</code></td><td>Autostart tradicional, shell/userinit e persistencia no logon.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Persistencia - Services / Tasks</td><td><code>HKLM\SYSTEM\CurrentControlSet\Services</code><br><code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks</code><br><code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree</code></td><td>Correlaciona 4697/7045/7040 e 4698/4702 com registros persistidos.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Persistencia / Evasao avancada</td><td><code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options</code><br><code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs</code><br><code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad</code></td><td>IFEO hijack, AppInit e extensoes de shell usadas em persistencia/evasao.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Credenciais / LSA</td><td><code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa</code><br><code>HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest</code><br><code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters</code></td><td>Hardening/legacy que impacta NTLM/Kerberos e risco de credential access.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Firewall / Rede / SMB / BITS</td><td><code>HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy</code><br><code>HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters</code><br><code>HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters</code><br><code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\BITS</code></td><td>Correlaciona 5156/5157/5158, shares SMB, SMBv1 e comportamento de jobs BITS.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>Sysmon / Telemetria</td><td><code>HKLM\SYSTEM\CurrentControlSet\Services\Sysmon64</code> (ou <code>Sysmon</code>)<br><code>HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv</code><br><code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational</code></td><td>Estado/configuracao do Sysmon e disponibilidade do canal operacional.</td></tr>"
    Write-VbsLine $LogFile "<tr><td>VSS / Shadow Copy</td><td><code>HKLM\SYSTEM\CurrentControlSet\Services\VSS</code><br><code>HKLM\SYSTEM\CurrentControlSet\Services\VolSnap</code></td><td>Referencia para correlacao com eventos VSS (8193/8222) e impacto em recuperacao.</td></tr>"
    Write-VbsLine $LogFile "</table></div>"
    Write-VbsLine $LogFile "</section>"
}

function LogCustody {
    param(
        [string]$Etapa,
        [string]$Status,
        [string]$Detalhes
    )

    $ts = TimestampISO (Get-Date)
    $tsLocal = TimestampLocalMillis (Get-Date)
    $userRef = [string](Nz $script:UserDomainText '') + '\' + [string](Nz $script:UserNameText '')
    $hostRef = [string](Nz $script:strComputer '')
    $d = ([string](Nz $Detalhes '')).Replace('"', "''")
    $sUpper = ([string](Nz $Status '')).Trim().ToUpperInvariant()
    $cssClass = LogStatusClass $sUpper
    $detailField = GetLogDetailField $d
    $detailValue = GetLogDetailValue $d
    $eventCellHtml = "<span class='chip " + $cssClass + "'>" + (HtmlEncode ([string](Nz $Status ''))) + "</span>"
    $isChecklist = IsChecklistStageName $Etapa

    $script:logEventCount = [long](To-LongSafe $script:logEventCount) + 1
    $eventIndex = [long](To-LongSafe $script:logEventCount)
    switch ($cssClass) {
        'start' { $script:logStartCount = [long](To-LongSafe $script:logStartCount) + 1 }
        'ok' { $script:logOkCount = [long](To-LongSafe $script:logOkCount) + 1 }
        'warn' { $script:logWarnCount = [long](To-LongSafe $script:logWarnCount) + 1 }
        'bad' { $script:logErrorCount = [long](To-LongSafe $script:logErrorCount) + 1 }
        default { $script:logNeutralCount = [long](To-LongSafe $script:logNeutralCount) + 1 }
    }
    if ($sUpper -eq 'END') { $script:logEndCount = [long](To-LongSafe $script:logEndCount) + 1 }
    if ($sUpper -eq 'OK') { $script:logPureOkCount = [long](To-LongSafe $script:logPureOkCount) + 1 }
    if ($isChecklist -and $sUpper -eq 'START') { $script:checklistTotalCount = [long](To-LongSafe $script:checklistTotalCount) + 1 }
    if ($isChecklist -and $sUpper -eq 'END') { $script:checklistOkCount = [long](To-LongSafe $script:checklistOkCount) + 1 }

    $script:strLogTimelineRows = [string](Nz $script:strLogTimelineRows '')
    $script:strLogTimelineRows += "<tr class='row-" + $cssClass + "'><td>" + $eventIndex + "</td><td>" + (HtmlEncode $tsLocal) + "</td><td>" + (HtmlEncode ([string](Nz $Etapa ''))) + "</td><td>" + $eventCellHtml + "</td><td>" + (HtmlEncode $detailField) + "</td><td>" + (HtmlEncode $detailValue) + "</td><td>" + (HtmlEncode $cssClass) + "</td></tr>"
    if ($cssClass -eq 'warn' -or $cssClass -eq 'bad') {
        $script:warnErrorDetailCount = [long](To-LongSafe $script:warnErrorDetailCount) + 1
        $script:strWarnErrorDetailRows = [string](Nz $script:strWarnErrorDetailRows '')
        $script:strWarnErrorDetailRows += "<tr class='row-" + $cssClass + "'><td>" + $script:warnErrorDetailCount + "</td><td>" + (HtmlEncode $tsLocal) + "</td><td>" + (HtmlEncode ([string](Nz $Etapa ''))) + "</td><td>" + $eventCellHtml + "</td><td>" + (HtmlEncode $detailField) + "</td><td class='path'>" + (HtmlEncode $detailValue) + "</td></tr>"
    }

    if ($sUpper -eq 'START') {
        $script:objActivityStartStamp[[string]$Etapa] = $tsLocal
        $script:objActivityStartTick[[string]$Etapa] = [string]([double](Get-Date).TimeOfDay.TotalSeconds)
    }
    elseif ($sUpper -eq 'END') {
        if ($script:objActivityStartStamp.ContainsKey([string]$Etapa)) {
            $startStamp = [string](Nz $script:objActivityStartStamp[[string]$Etapa] '')
            $startTick = [double](To-DoubleSafe $script:objActivityStartTick[[string]$Etapa])
            $endTick = [double](Get-Date).TimeOfDay.TotalSeconds
            $durationText = FormatDurationFromTicks -StartTick $startTick -EndTick $endTick
            $script:logActivityCount = [long](To-LongSafe $script:logActivityCount) + 1
            $script:strLogActivityRows = [string](Nz $script:strLogActivityRows '')
            $script:strLogActivityRows += "<tr class='row-" + $cssClass + "'><td>" + $script:logActivityCount + "</td><td>" + (HtmlEncode ([string](Nz $Etapa ''))) + "</td><td>" + (HtmlEncode $startStamp) + "</td><td>" + (HtmlEncode $tsLocal) + "</td><td>" + (HtmlEncode $durationText) + "</td><td>" + (HtmlEncode ([string](Nz $Status ''))) + "</td><td>" + (HtmlEncode $d) + "</td></tr>"
            if (([string](Nz $Etapa '')).Trim().ToUpperInvariant() -eq 'PESQUISA') {
                $script:logQueryCount = [long](To-LongSafe $script:logQueryCount) + 1
                $script:strLogQueryRows = [string](Nz $script:strLogQueryRows '')
                $script:strLogQueryRows += "<tr class='row-" + $cssClass + "'><td>" + $script:logQueryCount + "</td><td class='path'>" + (HtmlEncode (GetPesquisaCommand $d)) + "</td><td>" + (HtmlEncode $startStamp) + "</td><td>" + (HtmlEncode $tsLocal) + "</td><td>" + (HtmlEncode $durationText) + "</td><td>" + (HtmlEncode (GetPesquisaResultado $d)) + "</td></tr>"
            }
            $script:logEndWithStartCount = [long](To-LongSafe $script:logEndWithStartCount) + 1
            [void]$script:objActivityStartStamp.Remove([string]$Etapa)
            [void]$script:objActivityStartTick.Remove([string]$Etapa)
        }
        else {
            $script:logEndWithoutStartCount = [long](To-LongSafe $script:logEndWithoutStartCount) + 1
        }
    }

    if ($null -ne $script:objCustodyFile) {
        try {
            $csvLine = '"' + $ts + '","' + [string](Nz $script:strRunId '') + '","' + [string](Nz $Etapa '') + '","' + [string](Nz $Status '') + '","' + $d + '","' + $userRef + '","' + $hostRef + '"'
            $script:objCustodyFile.WriteLine($csvLine)
        }
        catch {
            $script:objCustodyFile = $null
            $script:threatEventTotalHits = 0
            $script:threatEventAlertCount = 0
            $script:threatEventWarnCount = 0
            $script:threatEventInfoCount = 0
            $script:threatHighPriorityHits = 0
            $script:threatSecurityHits = 0
            $script:threatPowerShellHits = 0
            $script:threatSysmonHits = 0
            $script:threatBitsHits = 0
            $script:threatSystemHits = 0
            $script:threatRegistryChecks = 0
            $script:threatRegistryAlertCount = 0
            $script:threatRegistryWarnCount = 0
            $script:threatRegistryInfoCount = 0
            $script:threatRedHits = 0
            $script:threatYellowHits = 0
            $script:threatRegistryPersistHits = 0
            $script:threatRegistryAccessHits = 0
            $script:threatRegistryTelemetryHits = 0
            $script:threatRegistryCredHits = 0
            $script:threatRegistryNetworkHits = 0
            $script:hostManufacturerName = ''
            $script:hostModelName = ''
            $script:hostAssetType = 'Indeterminado'
            $script:hostBatteryCount = 0
            $script:hostCpuLogicalCount = 0
            $script:hostRamTotalBytes = 0
            $script:serviceTotalCount = 0
            $script:serviceRunningCount = 0
            $script:serviceStoppedCount = 0
            $script:strDfirTimelineRecords = ''
            $script:dfirTimelineRecordCount = 0
            $script:prefetchTimelineCaptured = $false
        }
    }
}

function WriteExecutionLogHtml {
    param(
        [string]$MainHtmlFile,
        [string]$EndStamp
    )

    EnsureHostIdentityContext
    $totalDuration = FormatDurationFromTicks -StartTick ([double](To-DoubleSafe $script:dblScriptStartTick)) -EndTick ([double](Get-Date).TimeOfDay.TotalSeconds)
    $warnBadge = IIfBool (([long](To-LongSafe $script:logWarnCount)) -gt 0) ("<span class='pill warn'>" + [long](To-LongSafe $script:logWarnCount) + " avisos</span>") "<span class='pill ok'>0 avisos</span>"
    $errBadge = IIfBool (([long](To-LongSafe $script:logErrorCount)) -gt 0) ("<span class='pill bad'>" + [long](To-LongSafe $script:logErrorCount) + " erros</span>") "<span class='pill ok'>0 erros</span>"
    $reportBytes = GetFileSizeBytesSafe $MainHtmlFile
    $csvBytes = GetFileSizeBytesSafe $script:strCustodyFilePath
    $reportModified = GetFileDateModifiedSafe $MainHtmlFile
    $csvModified = GetFileDateModifiedSafe $script:strCustodyFilePath
    $reportMd5 = GetFileMD5 $MainHtmlFile
    $csvMd5 = GetFileMD5 $script:strCustodyFilePath
    $zipDisplayName = (SanitizeFileNameComponent (IIfBool (([string](Nz $script:hostServiceTag '').Trim() -ne '') -and ([string]$script:hostServiceTag -ne '-')) $script:hostServiceTag $script:strComputer)) + '.zip'
    $activityHtml = [string](Nz $script:strLogActivityRows '')
    if ($activityHtml.Trim() -eq '') { $activityHtml = "<tr><td colspan='7'>Nenhuma atividade consolidada (START/END) registrada.</td></tr>" }
    $timelineHtml = [string](Nz $script:strLogTimelineRows '')
    if ($timelineHtml.Trim() -eq '') { $timelineHtml = "<tr><td colspan='7'>Nenhum evento de log registrado.</td></tr>" }
    $queryHtml = [string](Nz $script:strLogQueryRows '')
    if ($queryHtml.Trim() -eq '') { $queryHtml = "<tr><td colspan='6'>Nenhuma pesquisa/comando registrada.</td></tr>" }
    $eventExportRowsHtml = [string](Nz $script:strEventLogArtifactExportRows '')
    if ($eventExportRowsHtml.Trim() -eq '') { $eventExportRowsHtml = "<tr><td colspan='6'>Nenhum export de EVT/EVTX registrado.</td></tr>" }
    $registryRootRowsHtml = [string](Nz $script:strRegistryRootArtifactExportRows '')
    if ($registryRootRowsHtml.Trim() -eq '') { $registryRootRowsHtml = "<tr><td colspan='6'>Nenhum export de raiz de registro (.reg) registrado.</td></tr>" }
    $smallArtifactRowsHtml = [string](Nz $script:strSmallArtifactExportRows '')
    if ($smallArtifactRowsHtml.Trim() -eq '') { $smallArtifactRowsHtml = "<tr><td colspan='6'>Nenhum export de pequenos artefatos registrado.</td></tr>" }
    $dfirPriorityTimelineHtml = BuildDfirPriorityTimelineHtml
    $maxFileBytes = [double](To-DoubleSafe $reportBytes)
    if ([double](To-DoubleSafe $csvBytes) -gt $maxFileBytes) { $maxFileBytes = [double](To-DoubleSafe $csvBytes) }
    if ([double]$maxFileBytes -le 0.0) { $maxFileBytes = 1.0 }
    $fileChartHtml = ""
    $fileChartHtml += "<div class='bar-row'><div class='bar-head'><span><i class='lni-layers'></i> Relatorio Inventario (.html)</span><strong>" + (HtmlEncode (FormatBytes $reportBytes)) + "</strong></div><div class='meter'><span class='fill report' style='width:__REPORT_BAR_PCT__%'></span></div></div>"
    $fileChartHtml += "<div class='bar-row'><div class='bar-head'><span><i class='lni-database'></i> Custody Activity (.csv)</span><strong>" + (HtmlEncode (FormatBytes $csvBytes)) + "</strong></div><div class='meter'><span class='fill csv' style='width:__CSV_BAR_PCT__%'></span></div></div>"
    $fileChartHtml += "<div class='bar-row'><div class='bar-head'><span><i class='lni-remove-file'></i> Status Log (.html)</span><strong>__LOG_SIZE_TEXT__</strong></div><div class='meter'><span class='fill warn' style='width:__LOG_BAR_PCT__%'></span></div></div>"
    if ($script:AuditJsonPath -and (Test-Path -LiteralPath $script:AuditJsonPath)) {
        $auditSize = (Get-Item -LiteralPath $script:AuditJsonPath).Length
        $fileChartHtml += "<div class='bar-row'><div class='bar-head'><span><i class='lni-protection'></i> Audit JSON (.jsonl)</span><strong>" + (HtmlEncode (FormatBytes $auditSize)) + "</strong></div><div class='meter'><span class='fill start' style='width:__AUDIT_BAR_PCT__%'></span></div></div>"
    }
    $fileChartHtml += "<div class='bar-row'><div class='bar-head'><span><i class='lni-zip'></i> Pacote ZIP (" + (HtmlEncode $zipDisplayName) + ")</span><strong>__ZIP_SIZE_TEXT__</strong></div><div class='meter'><span class='fill neutral' style='width:__ZIP_BAR_PCT__%'></span></div></div>"
    
    $detailTableHtml = ""
    $detailTableHtml += "<tr><th>Componente</th><th>Caminho</th><th>Tamanho</th><th>Modificacao</th><th>Integridade (MD5)</th></tr>"
    $detailTableHtml += "<tr><td><strong>Inventario</strong></td><td class='path'>" + (HtmlEncode $MainHtmlFile) + "</td><td>" + (HtmlEncode (FormatBytes $reportBytes)) + "</td><td>" + (HtmlEncode $reportModified) + "</td><td><code>" + (HtmlEncode $reportMd5) + "</code></td></tr>"
    $detailTableHtml += "<tr><td><strong>Status Log</strong></td><td class='path'>" + (HtmlEncode $script:strLogHtmlFile) + "</td><td>__LOG_SIZE_TEXT__</td><td>" + (HtmlEncode $EndStamp) + "</td><td><code>__LOG_MD5__</code></td></tr>"
    $detailTableHtml += "<tr><td><strong>Forensic CSV</strong></td><td class='path'>" + (HtmlEncode $script:strCustodyFilePath) + "</td><td>" + (HtmlEncode (FormatBytes $csvBytes)) + "</td><td>" + (HtmlEncode $csvModified) + "</td><td><code>" + (HtmlEncode $csvMd5) + "</code></td></tr>"
    $detailTableHtml += "<tr><td><strong>Export Dir</strong></td><td class='path'>" + (HtmlEncode (GetRunExportBaseDir)) + "</td><td>__EXPORT_SIZE_TEXT__</td><td>-</td><td><code>[DIRETORIO]</code></td></tr>"
    $detailTableHtml += "<tr><td><strong>ZIP Evidence</strong></td><td class='path'>__ZIP_PATH__</td><td>__ZIP_SIZE_TEXT__</td><td>__ZIP_MTIME__</td><td><code>__ZIP_MD5__</code></td></tr>"
    $logPath = [string](Nz $script:strLogHtmlFilePath $script:strLogHtmlFile)
    $logFile = $null

    $indicatorsHtml = "<h3>Indicadores de Sistema (Inventario)</h3><div class='grid'>"
    $indicatorsHtml += "<div class='card'><div class='label'>Processos / Servicos</div><div class='value'>" + [long](To-LongSafe $script:SummaryProcCountOverride) + " proc | " + [long](To-LongSafe $script:serviceTotalCount) + " svc</div></div>"
    $indicatorsHtml += "<div class='card'><div class='label'>Fabricante / Modelo</div><div class='value'>" + (HtmlEncode ($script:hostManufacturerName + " / " + $script:hostModelName)) + "</div></div>"
    $indicatorsHtml += "<div class='card'><div class='label'>Processadores / RAM</div><div class='value'>" + [long](To-LongSafe $script:hostCpuLogicalCount) + " cores | " + (HtmlEncode (FormatBytes $script:hostRamTotalBytes)) + "</div></div>"
    $curFree = [double](To-DoubleSafe $script:CurrentFreeSpaceBytes)
    $curTotal = [double](To-DoubleSafe $script:CurrentTotalSpaceBytes)
    $maxCheck = $curTotal
    if ($maxCheck -lt 1.0) { $maxCheck = 1.0 }

    $indicatorsHtml += "<div class='meter' style='margin-top:8px'><span class='fill report' style='width:" + (PercentWidthPct $curFree $maxCheck) + "%'></span></div></div>"
    $indicatorsHtml += "</div>"
    
    $indicatorsHtml += "<h3>Avisos e Auditoria</h3><div class='grid'>"
    $indicatorsHtml += "<div class='card'><div class='label'>Avisos de Execucao</div><div class='value'>" + [long](To-LongSafe $script:logWarnCount) + "</div></div>"
    $indicatorsHtml += "<div class='card'><div class='label'>Erros de Execucao</div><div class='value'>" + [long](To-LongSafe $script:logErrorCount) + "</div></div>"
    $indicatorsHtml += "<div class='card'><div class='label'>Itens no Custody</div><div class='value'>" + [long](To-LongSafe $script:logEventCount) + "</div></div>"
    $indicatorsHtml += "<div class='card'><div class='label'>Audit JSON</div><div class='value'>" + (IIfBool ([string](Nz $script:AuditJsonPath '') -ne '') 'Gerado' 'Nao Gerado') + "</div></div>"
    $indicatorsHtml += "</div>"

    if (LooksLikeMd5Hex $reportMd5) {
        LogCustody -Etapa 'INTEGRITY' -Status 'OK' -Detalhes ('MD5 relatorio principal=' + $reportMd5)
    }
    else {
        LogCustody -Etapa 'INTEGRITY' -Status 'WARN' -Detalhes 'Nao foi possivel calcular MD5 do relatorio principal'
    }
    if (LooksLikeMd5Hex $csvMd5) {
        LogCustody -Etapa 'INTEGRITY' -Status 'OK' -Detalhes ('MD5 custody (pre-close)=' + $csvMd5)
    }
    else {
        LogCustody -Etapa 'INTEGRITY' -Status 'WARN' -Detalhes 'Nao foi possivel calcular MD5 do custody CSV (pre-close)'
    }

    try {
        $logFile = Open-VbsTextWriter -Path $logPath
    }
    catch {
        return
    }

    try {
        Write-VbsLine $logFile "<!DOCTYPE html>"
        Write-VbsLine $logFile "<html lang='pt-BR'><head><meta charset='windows-1252'><meta name='viewport' content='width=device-width, initial-scale=1'>"
        Write-VbsLine $logFile "<link rel='stylesheet' href='https://cdn.lineicons.com/1.0.1/LineIcons.min.css'>"
        Write-VbsLine $logFile "<link rel='stylesheet' href='https://fonts.googleapis.com/css?family=Open+Sans:100,300,400,600&display=swap'>"
        Write-VbsLine $logFile ("<title>Status Log - " + (HtmlEncode $script:strComputer) + "</title>")
        Write-VbsLine $logFile "<style>:root{--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--start:#2563eb;--neutral:#64748b}body{margin:0;font-family:'Segoe UI',Tahoma,Arial,sans-serif;background:#eef4fb;color:#0f172a}.wrap{max-width:1320px;margin:0 auto;padding:18px}.hero,.section{background:#fff;border:1px solid #dbe5f0;border-radius:16px;padding:14px;box-shadow:0 8px 20px rgba(15,23,42,.05)}.section{margin-top:14px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}.card{background:#fff;border:1px solid #dbe5f0;border-radius:12px;padding:10px;min-width:0}.label{font-size:.74rem;color:#64748b}.value{margin-top:6px;font-weight:700;overflow-wrap:anywhere}.value code{display:block;white-space:normal;word-break:break-all;overflow-wrap:anywhere;font-size:.72rem;line-height:1.25;background:#f8fafc;border:1px solid #e2e8f0;padding:4px 6px;border-radius:8px}.muted{color:#64748b;font-size:.82rem}.pill{display:inline-block;padding:3px 8px;border-radius:999px;font-size:.78rem;font-weight:600}.pill.ok{background:#dcfce7;color:#166534}.pill.warn{background:#fef3c7;color:#92400e}.pill.bad{background:#fee2e2;color:#991b1b}.bar-row{margin:10px 0}.bar-head{display:flex;justify-content:space-between;font-size:.86rem}.meter{height:10px;border-radius:999px;background:#e8eef6;overflow:hidden}.fill{display:block;height:100%}.fill.start{background:#2563eb}.fill.warn{background:#d97706}.fill.ok{background:#16a34a}.fill.bad{background:#dc2626}.fill.report{background:#0ea5e9}.fill.csv{background:#7c3aed}.fill.neutral{background:#64748b}table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #dbe5f0;border-radius:12px;overflow:hidden}th,td{padding:8px;border-bottom:1px solid #e8eef6;text-align:left;vertical-align:top;font-size:.84rem}.scroll{overflow:auto;max-height:440px}.path{word-break:break-all}.chip{display:inline-block;padding:2px 7px;border-radius:999px;font-size:.74rem;font-weight:700}.chip.start{background:#dbeafe;color:#1d4ed8}.chip.ok{background:#dcfce7;color:#166534}.chip.warn{background:#fef3c7;color:#92400e}.chip.bad{background:#fee2e2;color:#991b1b}.chip.neutral{background:#e2e8f0;color:#334155}.timeline{display:flex;flex-direction:column;margin:20px auto;position:relative}.timeline__event{margin-bottom:20px;position:relative;display:flex;margin:20px 0;border-radius:6px;align-self:center;width:100%;max-width:1000px}.timeline__event:nth-child(2n+1){flex-direction:row-reverse}.timeline__event:nth-child(2n+1) .timeline__event__date{border-radius:0 6px 6px 0}.timeline__event:nth-child(2n+1) .timeline__event__content{border-radius:6px 0 0 6px}.timeline__event:nth-child(2n+1) .timeline__event__icon:before{content:'';width:2px;height:100%;background:#f6a4ec;position:absolute;top:0%;left:50%;z-index:-1;transform:translateX(-50%)}.timeline__event:nth-child(2n+1) .timeline__event__icon:after{content:'';width:100%;height:2px;background:#f6a4ec;position:absolute;right:0;z-index:-1;top:50%;transform:translateY(-50%)}.timeline__event__title{font-size:1.1rem;line-height:1.4;text-transform:uppercase;font-weight:600;color:#9251ac;letter-spacing:1px}.timeline__event__content{padding:16px;background:#fff;flex:1;border-radius:0 6px 6px 0;box-shadow:0 10px 25px -5px rgba(50,50,93,0.1),0 8px 16px -8px rgba(0,0,0,0.2);border:1px solid #e2e8f0}.timeline__event__date{color:#fff;font-size:1.1rem;font-weight:600;background:#9251ac;display:flex;align-items:center;justify-content:center;padding:0 20px;border-radius:6px 0 0 6px;min-width:150px;text-align:center}.timeline__event__icon{display:flex;align-items:center;justify-content:center;color:#9251ac;padding:25px;background:#f6a4ec;border-radius:100%;width:32px;height:32px;position:relative;margin:0 20px}.timeline__event__icon i{font-size:24px}.timeline__event__icon:before{content:'';width:2px;height:100%;background:#f6a4ec;position:absolute;top:0%;left:50%;z-index:-1;transform:translateX(-50%)}.timeline__event__icon:after{content:'';width:100%;height:2px;background:#f6a4ec;position:absolute;left:0%;top:50%;z-index:-1;transform:translateY(-50%)}.timeline__event--type1 .timeline__event__date{background:#9251ac;color:#fff}.timeline__event--type1 .timeline__event__icon{background:#f6a4ec;color:#9251ac}.timeline__event--type1 .timeline__event__icon:before,.timeline__event--type1 .timeline__event__icon:after{background:#f6a4ec}.timeline__event--type2 .timeline__event__date{background:#555ac0;color:#fff}.timeline__event--type2 .timeline__event__icon{background:#87bbfe;color:#555ac0}.timeline__event--type2 .timeline__event__icon:before,.timeline__event--type2 .timeline__event__icon:after{background:#87bbfe}.timeline__event--type2 .timeline__event__title{color:#555ac0}.timeline__event--type3 .timeline__event__date{background:#24b47e;color:#fff}.timeline__event--type3 .timeline__event__icon{background:#aff1b6;color:#24b47e}.timeline__event--type3 .timeline__event__icon:before,.timeline__event--type3 .timeline__event__icon:after{background:#aff1b6}.timeline__event--type3 .timeline__event__title{color:#24b47e}@media(max-width:786px){.timeline__event{flex-direction:column;align-items:center}.timeline__event__content{width:100%;border-radius:0 0 6px 6px!important}.timeline__event__icon{border-radius:6px 6px 0 0;width:100%;margin:0;padding:15px;height:auto}.timeline__event__icon:before,.timeline__event__icon:after{display:none}.timeline__event__date{width:100%;border-radius:0!important;padding:10px;font-size:1rem}}</style>"
        Write-VbsLine $logFile "<style>details.status-collapsible{padding:0;overflow:hidden}details.status-collapsible[open]{padding:14px}details.status-collapsible>summary{list-style:none;cursor:pointer;padding:14px 16px;font-weight:700;color:#0f172a;display:flex;align-items:center;gap:10px;background:linear-gradient(180deg,#f8fbff,#eef5ff);border-bottom:1px solid #dbe5f0}details.status-collapsible>summary::-webkit-details-marker{display:none}details.status-collapsible>summary::before{content:'+';width:20px;height:20px;border-radius:999px;display:inline-flex;align-items:center;justify-content:center;background:#dbeafe;color:#1d4ed8;font-weight:700}details.status-collapsible[open]>summary::before{content:'-'}details.status-collapsible[open]>summary{margin:-14px -14px 10px -14px}</style>"
        Write-VbsLine $logFile "</head><body><main class='wrap'>"
        Write-VbsLine $logFile "<section class='hero'>"
        Write-VbsLine $logFile "<h1>Status Log da Coleta</h1>"
        Write-VbsLine $logFile ("<div>Host: <strong>" + (HtmlEncode $script:strComputer) + "</strong> | Usuario: <strong>" + (HtmlEncode ($script:UserDomainText + '\' + $script:UserNameText)) + "</strong> | Run ID: <strong>" + (HtmlEncode $script:strRunId) + "</strong></div>")
        Write-VbsLine $logFile "<div class='grid'>"
        Write-VbsLine $logFile ("<div class='card'><div class='label'>Inicio</div><div class='value'>" + (HtmlEncode $script:strStartTime) + "</div></div>")
        Write-VbsLine $logFile ("<div class='card'><div class='label'>Fim</div><div class='value'>" + (HtmlEncode $EndStamp) + "</div></div>")
        Write-VbsLine $logFile ("<div class='card'><div class='label'>Duracao Total</div><div class='value'>" + (HtmlEncode $totalDuration) + "</div></div>")
        Write-VbsLine $logFile ("<div class='card'><div class='label'>Eventos / Atividades</div><div class='value'>" + [long](To-LongSafe $script:logEventCount) + " eventos | " + [long](To-LongSafe $script:logActivityCount) + " atividades</div></div>")
        Write-VbsLine $logFile ("<div class='card'><div class='label'>Status</div><div class='value'>" + $warnBadge + " " + $errBadge + "</div></div>")
        Write-VbsLine $logFile ("<div class='card'><div class='label'>MD5 principal</div><div class='value'><code>" + (HtmlEncode $reportMd5) + "</code></div></div>")
        Write-VbsLine $logFile ("<div class='card'><div class='label'>MD5 custody</div><div class='value'><code>" + (HtmlEncode $csvMd5) + "</code></div></div>")
        Write-VbsLine $logFile ("<div class='card'><div class='label'>Tamanho principal/csv</div><div class='value'>" + (HtmlEncode (FormatBytes $reportBytes)) + " / " + (HtmlEncode (FormatBytes $csvBytes)) + "</div></div>")
        Write-VbsLine $logFile "</div></section>"
        WriteStatusIncidentFocusSection -LogFile $logFile
        Write-VbsLine $logFile "<section class='section'><h2>Grafico de Volumes de Arquivos Gerados</h2>"
        Write-VbsLine $logFile "<div class='section-note'>Comparativo de tamanho dos artefatos gerados nesta execucao.</div>"
        Write-VbsLine $logFile $fileChartHtml
        Write-VbsLine $logFile "</section>"
        Write-VbsLine $logFile "<section class='section'><h2>Detalhes e Integridade</h2>"
        Write-VbsLine $logFile "<div class='section-note'>Inclui hashes MD5 de artefatos principais (relatorio/custody/zip) e registra integridade adicional no custody CSV, incluindo o hash do StatusLog apos a compactacao.</div>"
        Write-VbsLine $logFile ("<div class='scroll'><table>" + $detailTableHtml + "</table></div>")
        Write-VbsLine $logFile "</section>"
        Write-VbsLine $logFile "<section class='section'><h2>Pesquisas / Comandos</h2>"
        Write-VbsLine $logFile ("<div class='scroll'><table><tr><th>#</th><th>Pesquisa</th><th>Inicio</th><th>Fim</th><th>Duracao</th><th>Resultado</th></tr>" + $queryHtml + "</table></div>")
        Write-VbsLine $logFile "</section>"
        Write-VbsLine $logFile "<section class='section'><h2>Atividades (inicio/fim/duracao)</h2>"
        Write-VbsLine $logFile ("<div class='scroll'><table><tr><th>#</th><th>Atividade</th><th>Inicio</th><th>Fim</th><th>Duracao</th><th>Status final</th><th>Detalhes</th></tr>" + $activityHtml + "</table></div>")
        Write-VbsLine $logFile "</section>"
        Write-VbsLine $logFile "<section class='section'><h2>Timeline DFIR priorizada</h2>"
        if ($dfirPriorityTimelineHtml.Trim() -eq '') { Write-VbsLine $logFile "<div>Sem dados suficientes para timeline DFIR priorizada.</div>" } else { Write-VbsLine $logFile $dfirPriorityTimelineHtml }
        Write-VbsLine $logFile "</section>"
        Write-VbsLine $logFile "</section>"
        Write-VbsLine $logFile "<section class='section'><h2>Indicadores do Inventario (Resumo)</h2>"
        Write-VbsLine $logFile $indicatorsHtml
        Write-VbsLine $logFile "</section>"
        Write-VbsLine $logFile "<section class='section'><h2>Timeline de Eventos</h2>"
        Write-VbsLine $logFile ("<div class='scroll'><table><tr><th>#</th><th>Datetime</th><th>Item</th><th>Evento</th><th>Campo</th><th>Valor</th><th>Classe</th></tr>" + $timelineHtml + "</table></div>")
        Write-VbsLine $logFile "</section>"
        Write-VbsLine $logFile "<section class='section'><h2>Detalhes de EVT/EVTX e Registro</h2>"
        Write-VbsLine $logFile ("<div class='scroll'><table><tr><th>Categoria</th><th>Artefato</th><th>Status</th><th>Caminho</th><th>Tamanho</th><th>Observacao</th></tr>" + $eventExportRowsHtml + "</table></div>")
        Write-VbsLine $logFile ("<div class='scroll' style='margin-top:10px'><table><tr><th>Categoria</th><th>Artefato</th><th>Status</th><th>Caminho</th><th>Tamanho</th><th>Observacao</th></tr>" + $registryRootRowsHtml + "</table></div>")
        Write-VbsLine $logFile ("<div class='scroll' style='margin-top:10px'><table><tr><th>Categoria</th><th>Artefato</th><th>Status</th><th>Caminho</th><th>Tamanho</th><th>Observacao</th></tr>" + $smallArtifactRowsHtml + "</table></div>")
        Write-VbsLine $logFile "</section>"
        Write-VbsLine $logFile "<script>document.addEventListener('DOMContentLoaded',function(){Array.prototype.slice.call(document.querySelectorAll('section.section')).forEach(function(sec){var h2=null;for(var i=0;i<(sec.children||[]).length;i++){var c=sec.children[i];if(c&&c.tagName&&c.tagName.toLowerCase()==='h2'){h2=c;break;}} if(!h2){h2=sec.querySelector('h2');} if(!h2){return;} var d=document.createElement('details'); d.className='section status-collapsible'; d.open=false; var s=document.createElement('summary'); s.textContent=(h2.textContent||'Bloco').replace(/\\s+/g,' ').trim(); d.appendChild(s); if(h2.parentNode===sec){sec.removeChild(h2);} while(sec.firstChild){d.appendChild(sec.firstChild);} sec.parentNode.replaceChild(d,sec);});});</script>"
        Write-VbsLine $logFile "<footer style='margin-top:40px;padding:24px;background:rgba(248,250,252,0.5);border-top:1px solid #e2e8f0;border-radius:12px;font-size:.85rem;color:#64748b;text-align:center;line-height:1.6'>Relatorio de execucao (Status Log) para o host <strong>" + (HtmlEncode $script:strComputer) + "</strong>. Finalizado em " + (HtmlEncode $EndStamp) + ".</footer>"
        Write-VbsLine $logFile "</main></body></html>"
    }
    finally {
        if ($null -ne $logFile) { $logFile.Close() }
    }

    CreateStatusBundleZip -MainHtmlFile $MainHtmlFile
    ReplaceStatusLogZipPlaceholders -BaseMaxBytes $maxFileBytes -FallbackStamp $EndStamp -ReportBytes $reportBytes -CsvBytes $csvBytes -ExportDir (GetRunExportBaseDir)
    $logMd5 = GetFileMD5 $logPath
    if ([string](Nz $logMd5 '').Trim() -ne '' -and ([string](Nz $logMd5 '').Trim().ToUpperInvariant() -ne 'N/A')) {
        LogCustody -Etapa 'INTEGRITY' -Status 'OK' -Detalhes ('MD5 status log=' + $logMd5)
    }
    else {
        LogCustody -Etapa 'INTEGRITY' -Status 'WARN' -Detalhes 'Nao foi possivel calcular MD5 do status log'
    }
}

function Write-FinalFooterAndClose {
    param(
        [System.IO.StreamWriter]$Writer,
        [string]$LogHtmlFile
    )

    $strEndTime = TimestampLocalMillis (Get-Date)
    $auditNote = ''
    if ([string](Nz $script:AuditJsonPath '') -ne '') {
        $auditNote = ' | Audit JSON: <a href="' + (HtmlEncode $script:AuditJsonPath) + '" style="color:#7dd3fc">' + (HtmlEncode $script:AuditJsonPath) + '</a>'
    }
    Write-VbsLine $Writer ("<footer>Relatorio gerado automaticamente via WMI/Registry/CMD. Finalizacao: <strong>" + (HtmlEncode $strEndTime) + "</strong>. Log de execucao: <a href='" + (HtmlEncode $LogHtmlFile) + "' style='color:#7dd3fc'>" + (HtmlEncode $LogHtmlFile) + "</a>. Recomenda-se executar como administrador para maxima cobertura forense.</footer>")
    Write-VbsLine $Writer "</main>"
    Write-VbsLine $Writer "<script>"
    Write-VbsLine $Writer "window.addEventListener('scroll', function(){var btn = document.getElementById('scrollTopBtn'); if(window.pageYOffset > 300) btn.classList.add('show'); else btn.classList.remove('show');});"
    Write-VbsLine $Writer "document.getElementById('scrollTopBtn').addEventListener('click', function(){window.scrollTo({top:0, behavior:'smooth'});});"
    Write-VbsLine $Writer "function csvEscape(v){v=(v==null?'' : String(v));var q=String.fromCharCode(34); if(/[;,\\n]/.test(v)||v.indexOf(q)>-1){return q+v.split(q).join(q+q)+q;} return v;}"
    Write-VbsLine $Writer "function exportTableCsv(table,fileName){var trs=Array.prototype.slice.call(table.querySelectorAll('tr'));var lines=[];trs.forEach(function(tr){if(tr.style.display==='none'){return;} var cells=tr.querySelectorAll('th,td'); if(!cells.length){return;} var row=[]; cells.forEach(function(c){var t=(c.innerText||c.textContent||'').replace(/\\s+/g,' ').trim(); row.push(csvEscape(t));}); lines.push(row.join(';'));}); var blob=new Blob([lines.join('\\r\\n')],{type:'text/csv;charset=windows-1252;'}); var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=fileName||'tabela.csv'; document.body.appendChild(a); a.click(); setTimeout(function(){URL.revokeObjectURL(a.href); a.remove();},0);}"
    Write-VbsLine $Writer "function _slugifyAnchor(t){t=(t||'').toString().toLowerCase().replace(/[\\u00C0-\\u017F]/g,'').replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,''); if(!t){t='bloco';} return t;}"
    Write-VbsLine $Writer "function _summaryText(node){if(!node){return 'Secao';} var c=node.cloneNode(true); Array.prototype.slice.call(c.querySelectorAll('.collapsible-sub')).forEach(function(n){n.remove();}); return (c.textContent||'Secao').replace(/\\s+/g,' ').trim();}"
    Write-VbsLine $Writer "function _firstDirectByTag(el,tag){if(!el||!el.children){return null;} var t=(tag||'').toLowerCase(); for(var i=0;i<el.children.length;i++){var c=el.children[i]; if(c.tagName&&c.tagName.toLowerCase()===t){return c;}} return null;}"
    Write-VbsLine $Writer "function _wrapSectionSubBlocks(detailsEl, fallbackTitle){if(!detailsEl){return;} var kids=Array.prototype.slice.call(detailsEl.children); if(!kids.length){return;} var groups=[]; var current=null; kids.forEach(function(n){if(n.tagName && n.tagName.toLowerCase()==='summary'){return;} if(n.tagName && n.tagName.toLowerCase()==='h3'){current={title:(n.textContent||fallbackTitle||'Subbloco').replace(/\\s+/g,' ').trim(), nodes:[]}; groups.push(current); return;} if(!current){current={title:fallbackTitle||'Visao geral', nodes:[]}; groups.push(current);} current.nodes.push(n);}); if(!groups.length){return;} groups.forEach(function(g,idx){if(!g.nodes.length){return;} var sub=document.createElement('details'); sub.className='sub-collapsible'; sub.open=false; var subId=(detailsEl.id||'sec')+'-sub-'+(idx+1)+'-'+_slugifyAnchor(g.title); sub.id=subId; var sm=document.createElement('summary'); sm.textContent=g.title; sub.appendChild(sm); g.nodes[0].parentNode.insertBefore(sub,g.nodes[0]); g.nodes.forEach(function(n){sub.appendChild(n);});});}"
    Write-VbsLine $Writer "function _buildQuickMenuFromSections(){var host=document.getElementById('quickNavDynamic'); if(!host){return;} host.innerHTML=''; var sum=document.createElement('a'); sum.href='#sumario'; sum.className='fab-link-main'; sum.textContent='Sumario'; host.appendChild(sum); var sections=Array.prototype.slice.call(document.querySelectorAll('main.wrap > details.collapsible-card[id]')); if(!sections.length){return;} sections.forEach(function(sec){var mainSummary=_firstDirectByTag(sec,'summary')||sec.querySelector('summary'); var title=_summaryText(mainSummary); var group=document.createElement('details'); group.className='fab-group'; var sm=document.createElement('summary'); sm.textContent=title; group.appendChild(sm); var inner=document.createElement('div'); inner.className='fab-submenu'; var mainLink=document.createElement('a'); mainLink.href='#'+sec.id; mainLink.className='fab-link-main'; mainLink.textContent='Ir para bloco'; inner.appendChild(mainLink); Array.prototype.slice.call(sec.children||[]).forEach(function(sub){if(!(sub&&sub.tagName&&sub.tagName.toLowerCase()==='details'&&sub.classList&&sub.classList.contains('sub-collapsible')&&sub.id)){return;} var a=document.createElement('a'); a.href='#'+sub.id; var s=_firstDirectByTag(sub,'summary')||sub.querySelector('summary'); a.textContent=_summaryText(s); inner.appendChild(a);}); group.appendChild(inner); host.appendChild(group);});}"
    Write-VbsLine $Writer "document.addEventListener('DOMContentLoaded', function(){var ids={'hardware':1,'discos':1,'usb':1,'so':1,'identidade':1,'pastas':1,'shares':1,'artefatos':1,'controladores':1,'rede':1,'redeplus':1,'cis':1,'seguranca':1,'ameacas':1,'servicos':1,'execucao':1,'apps':1}; var subDefaults={'hardware':'Placa-mae, BIOS, CPU, Memoria','discos':'Discos Fisicos, Volumes, Particoes','usb':'Celulares, dispositivos externos e PnP relevantes','so':'Sistema Operacional e contexto','identidade':'Identidade do sistema, contas locais, grupos e compartilhamentos locais (contexto forense)','pastas':'Telemetria de pastas do usuario','shares':'Impressao (spooler, filas, portas e drivers)','artefatos':'Pagefile, Prefetch, artefatos e snapshots','controladores':'Controladores de disco, backup e historico de unidades','rede':'Rede e configuracao TCP/IP','redeplus':'IP/TCP/DNS/VPN e portas TCP abertas','cis':'Controles criticos (referencia CIS) para triagem de incidente','seguranca':'Processos e eventos criticos','ameacas':'Deteccao e correlacao','servicos':'Servicos detalhados','execucao':'Primeira/ultima execucao (aproximacao por artefatos)','apps':'Detalhes do sistema, softwares e persistencia'}; Array.prototype.slice.call(document.querySelectorAll('main.wrap > section.card[id]')).forEach(function(sec){if(!ids[sec.id]){return;} var h2=_firstDirectByTag(sec,'h2')||sec.querySelector('h2'); if(!h2){return;} var details=document.createElement('details'); details.className=sec.className+' collapsible-card'; details.id=sec.id; if(sec.getAttribute('style')){details.setAttribute('style',sec.getAttribute('style'));} details.open=false; var summary=document.createElement('summary'); summary.textContent=(h2.textContent||'Secao').replace(/\\s+/g,' ').trim(); var note=document.createElement('span'); note.className='collapsible-sub'; note.textContent='Clique para expandir/recolher'; summary.appendChild(note); details.appendChild(summary); sec.removeAttribute('id'); sec.removeAttribute('style'); if(h2.parentNode===sec){sec.removeChild(h2);} while(sec.firstChild){details.appendChild(sec.firstChild);} sec.parentNode.replaceChild(details, sec); _wrapSectionSubBlocks(details, subDefaults[details.id]||summary.textContent);}); _buildQuickMenuFromSections();});"
    Write-VbsLine $Writer "document.addEventListener('DOMContentLoaded', function(){var qWrap=document.getElementById('quickNav');var qBtn=document.getElementById('quickNavBtn');var qMenu=document.getElementById('quickNavMenu');if(!qWrap||!qBtn||!qMenu){return;} function closeMenu(){qMenu.classList.remove('show');qBtn.setAttribute('aria-expanded','false');} qBtn.addEventListener('click',function(e){e.stopPropagation();var open=qMenu.classList.toggle('show');qBtn.setAttribute('aria-expanded',open?'true':'false');}); qMenu.addEventListener('click',function(e){var t=e.target; if(t&&t.tagName&&t.tagName.toLowerCase()==='a'){closeMenu();}}); document.addEventListener('click',function(e){if(!qWrap.contains(e.target)){closeMenu();}});});"
    Write-VbsLine $Writer "document.addEventListener('DOMContentLoaded', function(){"
    Write-VbsLine $Writer "  var tables = document.querySelectorAll('table');"
    Write-VbsLine $Writer "  tables.forEach(function(table, idx) {"
    Write-VbsLine $Writer "    var tableId = 'table-' + idx;"
    Write-VbsLine $Writer "    table.id = tableId;"
    Write-VbsLine $Writer "    var rows = table.querySelectorAll('tbody tr');"
    Write-VbsLine $Writer "    if(rows.length === 0) rows = table.querySelectorAll('tr');"
    Write-VbsLine $Writer "    if(rows.length > 5) {"
    Write-VbsLine $Writer "      var filterDiv = document.createElement('div');"
    Write-VbsLine $Writer "      filterDiv.classList.add('filter-container');"
    Write-VbsLine $Writer "      var filterLabel = document.createElement('label');"
    Write-VbsLine $Writer "      filterLabel.style.marginRight = '2px';"
    Write-VbsLine $Writer "      filterLabel.textContent = 'Filtrar:';"
    Write-VbsLine $Writer "      filterLabel.style.color = '#94a3b8';"
    Write-VbsLine $Writer "      var filterInput = document.createElement('input');"
    Write-VbsLine $Writer "      filterInput.type = 'text';"
    Write-VbsLine $Writer "      filterInput.classList.add('filter-input');"
    Write-VbsLine $Writer "      filterInput.placeholder = 'Digite para filtrar linhas...';"
    Write-VbsLine $Writer "      var exportBtn = document.createElement('button');"
    Write-VbsLine $Writer "      exportBtn.type = 'button';"
    Write-VbsLine $Writer "      exportBtn.classList.add('table-export-btn');"
    Write-VbsLine $Writer "      exportBtn.textContent = 'Exportar CSV';"
    Write-VbsLine $Writer "      exportBtn.addEventListener('click', function(){ exportTableCsv(table, tableId + '.csv'); });"
    Write-VbsLine $Writer "      filterDiv.appendChild(filterLabel);"
    Write-VbsLine $Writer "      filterDiv.appendChild(filterInput);"
    Write-VbsLine $Writer "      filterDiv.appendChild(exportBtn);"
    Write-VbsLine $Writer "      table.parentNode.insertBefore(filterDiv, table);"
    Write-VbsLine $Writer "      filterInput.addEventListener('keyup', function() {"
    Write-VbsLine $Writer "        var filter = this.value.toUpperCase();"
    Write-VbsLine $Writer "        for(var i = 1; i < rows.length; i++) {"
    Write-VbsLine $Writer "          var text = rows[i].textContent || rows[i].innerText;"
    Write-VbsLine $Writer "          if(text.toUpperCase().indexOf(filter) > -1) {"
    Write-VbsLine $Writer "            rows[i].style.display = '';"
    Write-VbsLine $Writer "          } else {"
    Write-VbsLine $Writer "            rows[i].style.display = 'none';"
    Write-VbsLine $Writer "          }"
    Write-VbsLine $Writer "        }"
    Write-VbsLine $Writer "      });"
    Write-VbsLine $Writer "    }"
    Write-VbsLine $Writer "  });"
    Write-VbsLine $Writer "});"
    Write-VbsLine $Writer "</script>"
    Write-VbsLine $Writer "</body></html>"
}

function WriteHtmlChunked {
    param(
        [System.IO.StreamWriter]$OutFile,
        [string]$HtmlText
    )

    $s = [string](Nz $HtmlText '')
    if ($s -eq '') { return }
    $chunkSize = 6000
    $pos = 0
    while ($pos -lt $s.Length) {
        if ([bool](Nz $script:OutputWriteFailed $false)) { return }
        $len = [Math]::Min($chunkSize, $s.Length - $pos)
        try {
            $OutFile.Write($s.Substring($pos, $len))
        }
        catch {
            $script:OutputWriteFailed = $true
            $script:OutputWriteError = $_.Exception.Message
            Write-ProgressLog -Message ('ERROR: falha ao escrever HTML (chunk): ' + $_.Exception.Message) -Force
            throw
        }
        $pos += $chunkSize
    }
}

function LimitThreatSampleRowsHtml {
    param(
        [string]$RowsHtml,
        [int]$MaxLen
    )

    $n = [int](To-LongSafe $MaxLen)
    if ($n -le 0) { $n = 28000 }
    $s = [string](Nz $RowsHtml '')
    if ($s.Length -le $n) { return $s }
    return $s.Substring(0, $n) + "<tr><td colspan='3'><span class='warn'>Amostras truncadas para reduzir erro de escrita/renderizacao e acelerar o HTML.</span></td></tr>"
}

function WriteThreatBarRowHtml {
    param(
        [string]$LabelText,
        $ValueNum,
        $MaxNum,
        [string]$CssKind
    )

    $writer = $script:CurrentWriter
    if ($null -eq $writer) { return }
    $w = PercentWidthPct -ValueNum $ValueNum -MaxNum $MaxNum
    $colorStyle = 'background:linear-gradient(90deg,#86efac,#22c55e)'
    switch (([string](Nz $CssKind '')).ToLowerInvariant()) {
        'bad' { $colorStyle = 'background:linear-gradient(90deg,#fda4af,#ef4444)' }
        'warn' { $colorStyle = 'background:linear-gradient(90deg,#fde68a,#f59e0b)' }
        default { $colorStyle = 'background:linear-gradient(90deg,#67e8f9,#3b82f6)' }
    }
    Write-VbsLine $writer ("<tr><td>" + (HtmlEncode $LabelText) + "</td><td>" + [long](To-LongSafe $ValueNum) + "</td><td><div class='bar'><span style='width:" + $w + '%;' + $colorStyle + "'></span></div></td></tr>")
}

function TrackThreatPriorityBucketHits {
    param(
        [string]$PriorityBucket,
        $HitCount
    )

    switch (([string](Nz $PriorityBucket '')).Trim().ToLowerInvariant()) {
        'red' {
            $script:threatRedHits = [long](To-LongSafe $script:threatRedHits) + [long](To-LongSafe $HitCount)
        }
        'yellow' {
            $script:threatYellowHits = [long](To-LongSafe $script:threatYellowHits) + [long](To-LongSafe $HitCount)
        }
    }
}

function BuildThreatEventQueryCommand {
    param(
        [string]$ChannelName,
        [string]$IdsCsv,
        $MaxCount,
        [string]$FmtName
    )

    return BuildThreatEventQueryCommandEx -ChannelName $ChannelName -IdsCsv $IdsCsv -MaxCount $MaxCount -FmtName $FmtName -LookbackHours 0
}

function BuildThreatEventQueryCommandEx {
    param(
        [string]$ChannelName,
        [string]$IdsCsv,
        $MaxCount,
        [string]$FmtName,
        $LookbackHours
    )

    $timeClause = ''
    $lookbackNum = [long](To-LongSafe $LookbackHours)
    if ($lookbackNum -gt 0) {
        $msLookback = $lookbackNum * 3600000
        $timeClause = ' and TimeCreated[timediff(@SystemTime) <= ' + $msLookback + ']'
    }
    $q = '*[System[(' + (ThreatEventXPathIds -IdsCsv $IdsCsv) + ')' + $timeClause + ']]'
    return 'cmd /c wevtutil qe "' + $ChannelName + '" /rd:true /c:' + [long](To-LongSafe $MaxCount) + ' /f:' + $FmtName + ' /q:"' + $q + '" 2>&1'
}

function ThreatEventXPathIds {
    param(
        [string]$IdsCsv
    )

    $arr = ([string](Nz $IdsCsv '')).Split(',')
    $parts = @()
    foreach ($v in $arr) {
        $t = ([string](Nz $v '')).Trim()
        if ($t -ne '') {
            $parts += ('EventID=' + [long](To-LongSafe $t))
        }
    }
    if ($parts.Count -eq 0) { return 'EventID=0' }
    return ($parts -join ' or ')
}

function CountXmlEventNodes {
    param(
        [string]$XmlText
    )

    $s = [string](Nz $XmlText '')
    if ($s.Trim() -eq '') { return 0 }
    $matches = [regex]::Matches($s, '<Event(\s|>)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    return $matches.Count
}

function ThreatChannelBucket {
    param(
        [string]$ChannelName
    )

    $c = ([string](Nz $ChannelName '')).ToUpperInvariant()
    if ($c -eq 'SECURITY') { return 'security' }
    if ($c -eq 'SYSTEM') { return 'system' }
    if ($c.Contains('SYSMON')) { return 'sysmon' }
    if ($c.Contains('POWERSHELL')) { return 'powershell' }
    if ($c.Contains('BITS')) { return 'bits' }
    return $c.ToLowerInvariant()
}

function ThreatEventGroupNameSimple {
    param(
        [string]$ChannelName,
        $EventId
    )

    $bucket = ThreatChannelBucket -ChannelName $ChannelName
    if ($bucket -eq 'sysmon') { return 'Sysmon' }
    if ($bucket -eq 'powershell') { return 'PowerShell' }
    if ($bucket -eq 'bits') { return 'BITS' }

    switch ([long](To-LongSafe $EventId)) {
        { $_ -in 4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4771, 4776, 4740 } { return 'Autenticacao/Acesso' }
        { $_ -in 4778, 4779 } { return 'RDP' }
        { $_ -in 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4756, 4738, 4767 } { return 'Contas/Privilegio' }
        { $_ -in 4688, 4689, 4697, 7045, 7040, 4698, 4702, 4719, 1100, 1102, 104 } { return 'Execucao/Persistencia' }
        { $_ -in 4656, 4659, 4660, 4663, 4670, 4907 } { return 'FileSystem/Delecao' }
        { $_ -in 5156, 5157, 5158, 5140, 5145, 5142, 5144 } { return 'Rede/Exfil' }
        { $_ -in 25, 8193, 8222, 5038 } { return 'VSS/Impacto' }
        default { return 'Monitorado' }
    }
}

function ThreatEventSeverity {
    param(
        [string]$ChannelName,
        $EventId
    )

    $bucket = ThreatChannelBucket -ChannelName $ChannelName
    $idn = [long](To-LongSafe $EventId)
    if ($bucket -eq 'sysmon') {
        switch ($idn) {
            { $_ -in 8, 10, 11, 13 } { return 'ALERTA' }
            { $_ -in 1, 3, 4, 7 } { return 'WARN' }
        }
    }
    if ($bucket -eq 'powershell') {
        if ($idn -eq 4104) { return 'ALERTA' }
        return 'WARN'
    }
    switch ($idn) {
        { $_ -in 1102, 1100, 4719, 7045, 4697, 4698, 4724, 4728, 4732, 4756, 25 } { return 'ALERTA' }
        { $_ -in 4625, 4771, 4740, 4672, 4769, 7040, 4702, 104, 5038, 8193, 8222, 59, 60, 63, 5158, 5142, 5144, 4660, 4663, 4688, 4656, 4659 } { return 'WARN' }
        default { return 'INFO' }
    }
}

function ThreatSeverityCss {
    param(
        [string]$SevText
    )
    switch (([string](Nz $SevText '')).ToUpperInvariant()) {
        'ALERTA' { return 'bad' }
        'WARN' { return 'warn' }
        default { return 'ok' }
    }
}

function IsThreatHighPriority {
    param(
        [string]$ChannelName,
        $EventId
    )
    $idn = [long](To-LongSafe $EventId)
    if ((ThreatChannelBucket -ChannelName $ChannelName) -eq 'sysmon') {
        if ($idn -in 1, 3, 10, 11) { return $true }
    }
    return ($idn -in 4688, 4663, 4624, 4625, 4672, 4769, 7045, 4698, 5156, 1102, 4104)
}

function ThreatEventLabel {
    param(
        [string]$ChannelName,
        $EventId
    )

    $idn = [long](To-LongSafe $EventId)
    if ((ThreatChannelBucket -ChannelName $ChannelName) -eq 'sysmon') {
        switch ($idn) {
            1 { return 'Process Create' }
            3 { return 'Network Connection' }
            4 { return 'Sysmon Service State' }
            7 { return 'Image Load' }
            8 { return 'CreateRemoteThread' }
            10 { return 'ProcessAccess' }
            11 { return 'FileCreate' }
            13 { return 'Registry Modification' }
            default { return 'Sysmon Event' }
        }
    }
    switch ($idn) {
        4624 { return 'Logon sucesso' }
        4625 { return 'Logon falha' }
        4672 { return 'Privilegios especiais' }
        4688 { return 'Processo criado' }
        4698 { return 'Scheduled task criada' }
        4697 { return 'Servico instalado' }
        4719 { return 'Politica de auditoria alterada' }
        4740 { return 'Conta bloqueada' }
        4769 { return 'Kerberos service ticket' }
        4778 { return 'RDP reconectada' }
        4779 { return 'RDP desconectada' }
        7045 { return 'Servico criado' }
        4104 { return 'PowerShell script block' }
        1102 { return 'Security log apagado' }
        default { return 'Evento monitorado' }
    }
}

function CountThreatEventIdsFromXml {
    param(
        [string]$XmlText,
        [string]$ChannelName,
        [hashtable]$CountsDict,
        [ref]$HitCount
    )

    $HitCount.Value = 0
    if ($null -eq $CountsDict) { return }
    $matches = [regex]::Matches([string](Nz $XmlText ''), '<EventID(?:\s+[^>]*)?>(\d+)</EventID>', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $matches) {
        $eventId = [long](To-LongSafe $m.Groups[1].Value)
        $key = ([string](Nz $ChannelName '')).ToUpperInvariant() + '|' + $eventId
        if ($CountsDict.ContainsKey($key)) {
            $CountsDict[$key] = [long](To-LongSafe $CountsDict[$key]) + 1
        }
        else {
            $CountsDict[$key] = 1
        }
        $HitCount.Value = [long](To-LongSafe $HitCount.Value) + 1
        $script:threatEventTotalHits = [long](To-LongSafe $script:threatEventTotalHits) + 1
        switch (ThreatChannelBucket -ChannelName $ChannelName) {
            'security' { $script:threatSecurityHits = [long](To-LongSafe $script:threatSecurityHits) + 1 }
            'system' { $script:threatSystemHits = [long](To-LongSafe $script:threatSystemHits) + 1 }
            'powershell' { $script:threatPowerShellHits = [long](To-LongSafe $script:threatPowerShellHits) + 1 }
            'sysmon' { $script:threatSysmonHits = [long](To-LongSafe $script:threatSysmonHits) + 1 }
            'bits' { $script:threatBitsHits = [long](To-LongSafe $script:threatBitsHits) + 1 }
        }
        $sev = ThreatEventSeverity -ChannelName $ChannelName -EventId $eventId
        switch ($sev) {
            'ALERTA' { $script:threatEventAlertCount = [long](To-LongSafe $script:threatEventAlertCount) + 1 }
            'WARN' { $script:threatEventWarnCount = [long](To-LongSafe $script:threatEventWarnCount) + 1 }
            default { $script:threatEventInfoCount = [long](To-LongSafe $script:threatEventInfoCount) + 1 }
        }
        if (IsThreatHighPriority -ChannelName $ChannelName -EventId $eventId) {
            $script:threatHighPriorityHits = [long](To-LongSafe $script:threatHighPriorityHits) + 1
        }
    }
}

function BuildThreatEventSummaryRows {
    param(
        [hashtable]$CountsDict
    )

    if ($null -eq $CountsDict -or $CountsDict.Count -le 0) { return '' }
    $rows = ''
    $keys = SortDictKeysByValueDesc $CountsDict
    $maxCount = 1
    foreach ($k in $keys) {
        if ([long](To-LongSafe $CountsDict[$k]) -gt $maxCount) {
            $maxCount = [long](To-LongSafe $CountsDict[$k])
        }
    }
    foreach ($key in $keys) {
        $parts = ([string]$key).Split('|')
        if ($parts.Length -ge 2) {
            $channelName = $parts[0]
            $eventId = [long](To-LongSafe $parts[1])
            $countVal = [long](To-LongSafe $CountsDict[$key])
            $sev = ThreatEventSeverity -ChannelName $channelName -EventId $eventId
            $rows += "<tr><td>" + (HtmlEncode $channelName) + "</td><td>" + $eventId + "</td><td>" + (HtmlEncode ((ThreatEventGroupNameSimple -ChannelName $channelName -EventId $eventId) + ' / ' + (ThreatEventLabel -ChannelName $channelName -EventId $eventId))) + "</td><td><span class='tag " + (ThreatSeverityCss -SevText $sev) + "'>" + (HtmlEncode $sev) + "</span></td><td>" + $countVal + "</td><td><div class='bar'><span style='width:" + (PercentWidthPct -ValueNum $countVal -MaxNum $maxCount) + "%'></span></div></td></tr>"
        }
    }
    return $rows
}

function CollectThreatEventQueryFiltered {
    param(
        [string]$ChannelName,
        [string]$QueryLabel,
        [string]$IdsCsv,
        $MaxCount,
        $TimeoutSecs,
        $LookbackHours,
        $SampleLimit,
        $SampleMaxChars,
        [string]$PriorityBucket,
        [hashtable]$CountsDict,
        [ref]$ChannelRows,
        [ref]$SampleRows
    )

    $maxUse = [long](To-LongSafe $MaxCount)
    $toUse = [long](To-LongSafe $TimeoutSecs)
    if (([string](Nz $ChannelName '')).ToUpperInvariant() -eq 'SYSTEM') {
        if ($maxUse -gt 24) { $maxUse = 24 }
        if ($toUse -gt 8) { $toUse = 8 }
        $SampleLimit = 0
        $SampleMaxChars = 0
    }

    $labelText = $ChannelName
    if (([string](Nz $QueryLabel '')).Trim() -ne '') {
        $labelText = $labelText + "<br><span class='mini-note'>" + (HtmlEncode $QueryLabel) + "</span>"
    }
    $cmdXml = BuildThreatEventQueryCommandEx -ChannelName $ChannelName -IdsCsv $IdsCsv -MaxCount $maxUse -FmtName 'xml' -LookbackHours $LookbackHours
    $rawXml = GetCommandOutputWithTimeout -CommandText $cmdXml -TimeoutSecs ([int](To-LongSafe $toUse))
    $filterNote = 'IDs=' + $IdsCsv + ' | c=' + $maxUse
    if ([long](To-LongSafe $LookbackHours) -gt 0) {
        $filterNote += ' | janela=' + [long](To-LongSafe $LookbackHours) + 'h'
    }

    if (([string](Nz $rawXml '')).IndexOf('<Event', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $hitCount = 0
        CountThreatEventIdsFromXml -XmlText $rawXml -ChannelName $ChannelName -CountsDict $CountsDict -HitCount ([ref]$hitCount)
        TrackThreatPriorityBucketHits -PriorityBucket $PriorityBucket -HitCount $hitCount
        $ChannelRows.Value = [string](Nz $ChannelRows.Value '') + "<tr><td class='location-col'>" + $labelText + "</td><td><span class='tag ok'>OK</span></td><td>" + $hitCount + "</td><td class='location-col'>" + (HtmlEncode $filterNote) + "</td></tr>"

        $exportFileName = 'threat_events_' + $ChannelName + '_' + $QueryLabel + '_' + [string](Nz $script:strRunId '')
        $exportPath = ExportTextArtifact -SubDirName 'ameacas_eventos' -FileBaseName $exportFileName -FileExt 'xml' -ContentText $rawXml
        $exportStatus = "<span class='tag ok'>OK</span>"
        $exportNote = 'XML wevtutil | ' + $filterNote
        if (([string](Nz $exportPath '')).Trim() -ne '') {
            $script:threatEventExportCount = [long](To-LongSafe $script:threatEventExportCount) + 1
            $SampleRows.Value = [string](Nz $SampleRows.Value '') + "<tr><td class='location-col'>" + $labelText + "</td><td class='location-col'>" + (HtmlEncode $filterNote) + "</td><td>" + $hitCount + "</td><td>" + $exportStatus + "</td><td class='location-col'><a href='" + (HtmlEncode $exportPath) + "' style='color:#7dd3fc'>" + (HtmlEncode $exportPath) + "</a></td><td class='location-col'>" + (HtmlEncode $exportNote) + "</td></tr>"
            LogCustody -Etapa 'THREAT_EVENT_EXPORT' -Status 'OK' -Detalhes ($ChannelName + ' | ' + $hitCount + ' hits | ' + $exportPath)
        }
        else {
            $SampleRows.Value = [string](Nz $SampleRows.Value '') + "<tr><td class='location-col'>" + $labelText + "</td><td class='location-col'>" + (HtmlEncode $filterNote) + "</td><td>" + $hitCount + "</td><td><span class='tag warn'>WARN</span></td><td>-</td><td class='location-col'>Falha ao gravar exportacao XML do canal.</td></tr>"
            LogCustody -Etapa 'THREAT_EVENT_EXPORT' -Status 'WARN' -Detalhes ($ChannelName + ' | falha ao gravar XML')
        }
    }
    else {
        $noteTxt = AbbrevText -Text $rawXml -MaxLen 240
        if ($noteTxt -eq '-') { $noteTxt = 'Canal sem retorno, sem permissao ou indisponivel.' }
        $ChannelRows.Value = [string](Nz $ChannelRows.Value '') + "<tr><td class='location-col'>" + $labelText + "</td><td><span class='tag warn'>WARN</span></td><td>0</td><td class='location-col'>" + (HtmlEncode ($filterNote + ' | ' + $noteTxt)) + "</td></tr>"
        $exportFileName = 'threat_events_' + $ChannelName + '_' + $QueryLabel + '_' + [string](Nz $script:strRunId '') + '_sem_retorno'
        $exportPath = ExportTextArtifact -SubDirName 'ameacas_eventos' -FileBaseName $exportFileName -FileExt 'txt' -ContentText $rawXml
        if (([string](Nz $exportPath '')).Trim() -ne '') {
            $script:threatEventExportCount = [long](To-LongSafe $script:threatEventExportCount) + 1
            $SampleRows.Value = [string](Nz $SampleRows.Value '') + "<tr><td class='location-col'>" + $labelText + "</td><td class='location-col'>" + (HtmlEncode $filterNote) + "</td><td>0</td><td><span class='tag warn'>WARN</span></td><td class='location-col'><a href='" + (HtmlEncode $exportPath) + "' style='color:#7dd3fc'>" + (HtmlEncode $exportPath) + "</a></td><td class='location-col'>" + (HtmlEncode $noteTxt) + "</td></tr>"
        }
        else {
            $SampleRows.Value = [string](Nz $SampleRows.Value '') + "<tr><td class='location-col'>" + $labelText + "</td><td class='location-col'>" + (HtmlEncode $filterNote) + "</td><td>0</td><td><span class='tag warn'>WARN</span></td><td>-</td><td class='location-col'>" + (HtmlEncode $noteTxt) + "</td></tr>"
        }
    }
}

function CollectThreatEventsFromChannelSimple {
    param(
        [string]$ChannelName,
        [string]$IdsCsv,
        $MaxCount,
        $TimeoutSecs,
        [hashtable]$CountsDict,
        [ref]$ChannelRows,
        [ref]$SampleRows
    )
    CollectThreatEventQueryFiltered -ChannelName $ChannelName -QueryLabel 'Padrao' -IdsCsv $IdsCsv -MaxCount $MaxCount -TimeoutSecs $TimeoutSecs -LookbackHours 0 -SampleLimit 6 -SampleMaxChars 4000 -PriorityBucket '' -CountsDict $CountsDict -ChannelRows $ChannelRows -SampleRows $SampleRows
}

function CollectThreatEventsOptimized {
    param(
        [hashtable]$CountsDict,
        [ref]$ChannelRows,
        [ref]$SampleRows
    )

    $ChannelRows.Value = ''
    $SampleRows.Value = ''
    CollectThreatEventQueryFiltered -ChannelName 'Security' -QueryLabel 'RED | Credencial/Execucao/Auditoria' -IdsCsv '1102,4719,4697,4698,4688,4663,4625,4672,4769,4740' -MaxCount 180 -TimeoutSecs 14 -LookbackHours 48 -SampleLimit 3 -SampleMaxChars 1600 -PriorityBucket 'red' -CountsDict $CountsDict -ChannelRows $ChannelRows -SampleRows $SampleRows
    CollectThreatEventQueryFiltered -ChannelName 'System' -QueryLabel 'RED | Servicos/VSS/Impacto (janela reduzida)' -IdsCsv '25,104,7040,7045,8193,8222' -MaxCount 24 -TimeoutSecs 6 -LookbackHours 24 -SampleLimit 0 -SampleMaxChars 0 -PriorityBucket 'red' -CountsDict $CountsDict -ChannelRows $ChannelRows -SampleRows $SampleRows
    CollectThreatEventQueryFiltered -ChannelName 'Microsoft-Windows-PowerShell/Operational' -QueryLabel 'RED | PowerShell operacional' -IdsCsv '4103,4104,4105,4106' -MaxCount 60 -TimeoutSecs 8 -LookbackHours 24 -SampleLimit 3 -SampleMaxChars 1800 -PriorityBucket 'red' -CountsDict $CountsDict -ChannelRows $ChannelRows -SampleRows $SampleRows
    CollectThreatEventQueryFiltered -ChannelName 'Microsoft-Windows-Sysmon/Operational' -QueryLabel 'RED | Sysmon core' -IdsCsv '1,3,8,10,11,13' -MaxCount 120 -TimeoutSecs 10 -LookbackHours 96 -SampleLimit 3 -SampleMaxChars 1800 -PriorityBucket 'red' -CountsDict $CountsDict -ChannelRows $ChannelRows -SampleRows $SampleRows
    CollectThreatEventQueryFiltered -ChannelName 'Security' -QueryLabel 'YELLOW | Auth/RDP/Rede/SMB' -IdsCsv '4624,4634,4647,4648,4771,4776,4778,4779,5140,5142,5144,5145,5156,5157,5158' -MaxCount 120 -TimeoutSecs 10 -LookbackHours 24 -SampleLimit 0 -SampleMaxChars 0 -PriorityBucket 'yellow' -CountsDict $CountsDict -ChannelRows $ChannelRows -SampleRows $SampleRows
    CollectThreatEventQueryFiltered -ChannelName 'Security' -QueryLabel 'YELLOW | Contas/FS/Complementar' -IdsCsv '4689,4702,4720,4722,4723,4724,4725,4726,4728,4732,4738,4756,4767,4768,5038,1100,4656,4659,4660,4670,4907' -MaxCount 100 -TimeoutSecs 10 -LookbackHours 48 -SampleLimit 0 -SampleMaxChars 0 -PriorityBucket 'yellow' -CountsDict $CountsDict -ChannelRows $ChannelRows -SampleRows $SampleRows
    CollectThreatEventQueryFiltered -ChannelName 'Microsoft-Windows-Sysmon/Operational' -QueryLabel 'YELLOW | Sysmon suporte' -IdsCsv '4,7' -MaxCount 50 -TimeoutSecs 8 -LookbackHours 96 -SampleLimit 0 -SampleMaxChars 0 -PriorityBucket 'yellow' -CountsDict $CountsDict -ChannelRows $ChannelRows -SampleRows $SampleRows
    CollectThreatEventQueryFiltered -ChannelName 'Microsoft-Windows-Bits-Client/Operational' -QueryLabel 'YELLOW | BITS' -IdsCsv '59,60,63' -MaxCount 30 -TimeoutSecs 6 -LookbackHours 96 -SampleLimit 0 -SampleMaxChars 0 -PriorityBucket 'yellow' -CountsDict $CountsDict -ChannelRows $ChannelRows -SampleRows $SampleRows
}

function EventClass {
    param(
        [string]$Text
    )
    $m = ([string](Nz $Text '')).ToLowerInvariant()
    if ($m -eq 'error') { return 'bad' }
    if ($m -eq 'warning') { return 'warn' }
    return 'ok'
}

function RemainingGlobalCommandRuntimeSecs {
    if ([long](To-LongSafe $script:GlobalCommandRuntimeLimitSecs) -le 0) {
        return 0
    }
    $elapsedSecs = SecondsBetweenTicks -StartTick ([double](To-DoubleSafe $script:dblScriptStartTick) ) -EndTick ([double](Get-Date).TimeOfDay.TotalSeconds)
    $remainingSecs = [long](To-LongSafe $script:GlobalCommandRuntimeLimitSecs) - [long][Math]::Floor([double](To-DoubleSafe $elapsedSecs))
    if ($remainingSecs -lt 0) { $remainingSecs = 0 }
    return $remainingSecs
}

function ApplyCommandTimeoutPolicy {
    param(
        $RequestedTimeoutSecs
    )

    $t = [long](To-LongSafe $RequestedTimeoutSecs)
    if ($t -lt 0) { $t = 0 }
    if ([bool](Nz $script:ValidationQueryTimeoutMode $false)) {
        $validationSecs = [long](To-LongSafe $script:ValidationQueryTimeoutSecs)
        if ($validationSecs -gt 0 -and ($t -eq 0 -or $t -gt $validationSecs)) {
            $t = $validationSecs
        }
    }
    if ([long](To-LongSafe $script:GlobalCommandRuntimeLimitSecs) -gt 0) {
        $remSecs = RemainingGlobalCommandRuntimeSecs
        if ($remSecs -le 0) { return 0 }
        if ($t -eq 0 -or $t -gt $remSecs) { $t = $remSecs }
    }
    return $t
}

function CollapseSpaces {
    param(
        [string]$Text
    )
    $t = ([string](Nz $Text '')).Trim()
    while ($t.Contains('  ')) {
        $t = $t.Replace('  ', ' ')
    }
    return $t
}

function JoinTokensPlain {
    param(
        [string[]]$Arr,
        [int]$StartIdx
    )
    if ($null -eq $Arr -or $Arr.Count -eq 0) { return '' }
    if ($StartIdx -lt 0) { $StartIdx = 0 }
    if ($StartIdx -ge $Arr.Count) { return '' }
    $acc = ''
    for ($i = $StartIdx; $i -lt $Arr.Count; $i++) {
        if ($acc -ne '') { $acc += ' ' }
        $acc += [string](Nz $Arr[$i] '')
    }
    return $acc
}

function TryParseDirFileLine {
    param(
        [string]$Line,
        [ref]$StampText,
        [ref]$SizeText,
        [ref]$FileName
    )

    $StampText.Value = ''
    $SizeText.Value = ''
    $FileName.Value = ''
    $s = ([string](Nz $Line '')).Trim()
    if ($s -eq '') { return $false }
    if ($s -match 'Directory of|Diretorio de|Volume in drive|O volume na unidade|File\(s\)|Arquivo\(s\)|Dir\(s\)|Pasta\(s\)') { return $false }

    $s = CollapseSpaces $s
    $parts = $s.Split(' ')
    if ($parts.Length -lt 4) { return $false }

    $idxSize = 2
    if ($parts.Length -ge 5) {
        $t2 = $parts[2].ToUpperInvariant()
        if ($t2 -in 'AM', 'PM', 'A.M.', 'P.M.') { $idxSize = 3 }
    }
    if ($idxSize -gt ($parts.Length - 2)) { return $false }
    if ($parts[$idxSize].ToUpperInvariant() -eq '<DIR>') { return $false }
    $sizeNumProbe = 0.0
    if (-not [double]::TryParse($parts[$idxSize], [ref]$sizeNumProbe)) { return $false }

    $stamp = $parts[0] + ' ' + $parts[1]
    if ($idxSize -eq 3) { $stamp += ' ' + $parts[2] }
    $nameVal = JoinTokensPlain -Arr $parts -StartIdx ($idxSize + 1)
    if ($nameVal.Trim() -eq '') { return $false }

    $StampText.Value = $stamp
    $SizeText.Value = $parts[$idxSize]
    $FileName.Value = $nameVal
    return $true
}

function ParseDirPrefetchOutput {
    param(
        [string]$DirOutput,
        [hashtable]$StampMap,
        [hashtable]$SizeMap,
        [ref]$FileCount,
        [ref]$BytesTotal
    )

    $FileCount.Value = 0
    $BytesTotal.Value = 0.0
    if (([string](Nz $DirOutput '')).Trim() -eq '') { return }
    if ($null -eq $StampMap) { return }

    $lines = [string](Nz $DirOutput '').Split(@("`r`n", "`n"), [System.StringSplitOptions]::None)
    foreach ($line in $lines) {
        $stampText = ''
        $sizeText = ''
        $fileName = ''
        if (TryParseDirFileLine -Line $line -StampText ([ref]$stampText) -SizeText ([ref]$sizeText) -FileName ([ref]$fileName)) {
            if ($fileName.ToUpperInvariant().EndsWith('.PF')) {
                $StampMap[$fileName] = $stampText
                if ($null -ne $SizeMap) {
                    $sizeNum = [double](To-DoubleSafe $sizeText)
                    $SizeMap[$fileName] = $sizeNum
                    $FileCount.Value = [long](To-LongSafe $FileCount.Value) + 1
                    $BytesTotal.Value = [double](To-DoubleSafe $BytesTotal.Value) + $sizeNum
                }
            }
        }
    }
}

function GetPrefetchFilesTableRows {
    param(
        [string]$PrefetchPath
    )

    $rows = ''
    if (-not (Test-Path -LiteralPath $PrefetchPath -PathType Container)) { return '' }
    try {
        $folderFiles = Get-ChildItem -LiteralPath $PrefetchPath -File -ErrorAction Stop
    }
    catch {
        return ''
    }

    foreach ($f in $folderFiles) {
        if ($f.Name.ToLowerInvariant().EndsWith('.pf')) {
            $rows += "<tr><td>" + (HtmlEncode $f.Name) + "</td><td>" + (HtmlEncode ([string]$f.CreationTime)) + "</td><td>" + (HtmlEncode ([string]$f.LastWriteTime)) + "</td><td>" + (HtmlEncode (FormatBytes $f.Length)) + "</td></tr>"
        }
    }
    return $rows
}

function GetRecentFilesTop {
    param(
        $LimitCount
    )

    $n = [int](To-LongSafe $LimitCount)
    if ($n -le 0) { $n = 20 }
    $psCmd = "powershell -NoProfile -Command ""`$p = Join-Path `$env:APPDATA 'Microsoft\Windows\Recent'; if (Test-Path -LiteralPath `$p) { `$sh = New-Object -ComObject WScript.Shell; Get-ChildItem -LiteralPath `$p -File -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First " + $n + " | ForEach-Object { `$t=''; `$a=''; try { if (`$_.Extension -ieq '.lnk') { `$sc = `$sh.CreateShortcut(`$_.FullName); `$t = `$sc.TargetPath; `$a = `$sc.Arguments } } catch {}; [pscustomobject]@{ Name=`$_.Name; Ext=`$_.Extension; Created=`$_.CreationTime; Modified=`$_.LastWriteTime; Size=`$_.Length; Target=`$t; Args=`$a; Folder=`$_.DirectoryName } } | Format-Table -Wrap -AutoSize | Out-String -Width 360 } else { 'Pasta Recent nao encontrada: ' + `$p }"""
    return GetCommandOutputWithTimeout -CommandText $psCmd -TimeoutSecs 12
}

function WalkFolder {
    param(
        [System.IO.DirectoryInfo]$FolderObj,
        [ref]$TotalFiles,
        [ref]$TotalDirs,
        [ref]$TotalBytes
    )

    if ($null -eq $FolderObj) { return }
    try {
        foreach ($f in $FolderObj.GetFiles()) {
            $TotalFiles.Value = [long](To-LongSafe $TotalFiles.Value) + 1
            $TotalBytes.Value = [double](To-DoubleSafe $TotalBytes.Value) + [double](To-DoubleSafe $f.Length)
        }
        foreach ($sf in $FolderObj.GetDirectories()) {
            $TotalDirs.Value = [long](To-LongSafe $TotalDirs.Value) + 1
            WalkFolder -FolderObj $sf -TotalFiles $TotalFiles -TotalDirs $TotalDirs -TotalBytes $TotalBytes
        }
    }
    catch {
    }
}

function WriteProgramDataFoldersSize {
    param(
        [string]$ProgramDataPath
    )

    $writer = $script:CurrentWriter
    if ($null -eq $writer) { return }
    $category = GetForensicCategory $ProgramDataPath
    $psCmd = "powershell -NoProfile -Command ""Get-ChildItem -Path 'C:\ProgramData\' -Directory -ErrorAction SilentlyContinue | ForEach-Object { `$size = (Get-ChildItem -Path `$_.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; Write-Host `$_.Name '|' [math]::Round(`$size/1MB,2) 'MB' } | Sort-Object -Descending"" 2>nul"
    $output = GetCommandOutput -CommandText $psCmd

    if ($output.IndexOf('[TIMEOUT', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
        Write-VbsLine $writer ("<tr><td>" + (HtmlEncode $ProgramDataPath) + "</td><td>" + (HtmlEncode $category) + "</td><td colspan='3'><span class='warn'>Timeout - pasta muito grande para analise completa</span></td></tr>")
    }
    elseif (([string](Nz $output '')).Trim() -eq '' -or ([string](Nz $output '')).Trim() -eq 'N/A') {
        Write-VbsLine $writer ("<tr><td>" + (HtmlEncode $ProgramDataPath) + "</td><td>" + (HtmlEncode $category) + "</td><td colspan='3'>Sem acesso ou pasta vazia</td></tr>")
    }
    else {
        $lines = [string](Nz $output '').Split(@("`r`n", "`n"), [System.StringSplitOptions]::None)
        if ($lines.Count -lt 6) {
            Write-VbsLine $writer ("<tr><td>" + (HtmlEncode $ProgramDataPath) + "</td><td>" + (HtmlEncode $category) + "</td><td colspan='3'><pre style='font-size:0.85em;white-space:pre-wrap'>" + (HtmlEncode $output) + "</pre></td></tr>")
        }
        else {
            $cut = [string](Nz $output '')
            if ($cut.Length -gt 2000) { $cut = $cut.Substring(0, 2000) }
            Write-VbsLine $writer ("<tr><td>" + (HtmlEncode $ProgramDataPath) + "</td><td>" + (HtmlEncode $category) + "</td><td colspan='3'><pre style='font-size:0.85em;white-space:pre-wrap;max-height:300px;overflow-y:auto'>" + (HtmlEncode $cut) + "...</pre></td></tr>")
        }
    }
}

function WriteRecentDirTable {
    $writer = $script:CurrentWriter
    if ($null -eq $writer) { return }

    $recentPath = [System.Environment]::ExpandEnvironmentVariables('%APPDATA%') + '\Microsoft\Windows\Recent'
    $rowCount = 0
    $truncated = $false
    $maxItems = 50

    Write-VbsLine $writer "<div class='scroll-table'>"
    Write-VbsLine $writer "<table><tr><th>Nome</th><th>Extensao</th><th>Tamanho</th><th>Data de criacao</th><th>Ultima gravacao</th><th class='location-col'>Caminho</th></tr>"
    if (-not (Test-Path -LiteralPath $recentPath -PathType Container)) {
        Write-VbsLine $writer "<tr><td colspan='6'>Pasta Recent nao encontrada.</td></tr>"
        Write-VbsLine $writer "</table></div>"
        return
    }

    try {
        $files = Get-ChildItem -LiteralPath $recentPath -File -ErrorAction Stop
    }
    catch {
        Write-VbsLine $writer ("<tr><td colspan='6'>Falha ao abrir a pasta Recent: " + (HtmlEncode $_.Exception.Message) + "</td></tr>")
        Write-VbsLine $writer "</table></div>"
        return
    }

    foreach ($f in $files) {
        if ($rowCount -ge $maxItems) {
            $truncated = $true
            break
        }
        Write-VbsLine $writer ("<tr><td>" + (HtmlEncode $f.Name) + "</td><td>" + (HtmlEncode $f.Extension.TrimStart('.')) + "</td><td>" + (HtmlEncode (FormatBytes $f.Length)) + "</td><td>" + (HtmlEncode ([string]$f.CreationTime)) + "</td><td>" + (HtmlEncode ([string]$f.LastWriteTime)) + "</td><td class='location-col'>" + (HtmlEncode $f.FullName) + "</td></tr>")
        $rowCount++
    }

    if ($rowCount -eq 0) {
        Write-VbsLine $writer "<tr><td colspan='6'>Nenhum item listado foi lido com sucesso.</td></tr>"
    }
    elseif ($truncated) {
        Write-VbsLine $writer ("<tr><td colspan='6'><span class='warn'>Exibicao limitada a " + $maxItems + " itens para reduzir tempo de coleta/renderizacao da pasta Recent.</span></td></tr>")
    }

    Write-VbsLine $writer "</table>"
    Write-VbsLine $writer "</div>"
}

$strComputer = if ($PSBoundParameters.ContainsKey('ComputerNameOverride')) { $ComputerNameOverride } else { $env:COMPUTERNAME }
$userDomain = if ($PSBoundParameters.ContainsKey('UserDomainOverride')) { $UserDomainOverride } else { $env:USERDOMAIN }
$userName = if ($PSBoundParameters.ContainsKey('UserNameOverride')) { $UserNameOverride } else { $env:USERNAME }
$dtScriptStart = Get-Date
$script:NowReference = if ($PSBoundParameters.ContainsKey('NowOverride')) { $NowOverride } else { $dtScriptStart }
$script:VerboseProgressEnabled = [bool]$VerboseProgress
$script:DefaultCommandTimeoutSecs = [int]$DefaultCommandTimeoutSecs
$script:ContinueOnSectionErrorFlag = [bool]$ContinueOnSectionError

$script:hostManufacturerName = ''
$script:hostModelName = ''
$script:hostAssetType = 'Indeterminado'
$script:hostBatteryCount = 0
$script:hostCpuLogicalCount = 0
$script:hostRamTotalBytes = 0
$script:hostServiceTag = ''
$script:hostLoggedUserSid = ''
$script:serviceTotalCount = 0
$script:serviceRunningCount = 0
$script:serviceStoppedCount = 0

$script:UserDomainText = [string](Nz $userDomain '')
$script:UserNameText = [string](Nz $userName '')
$script:SummaryProcCountOverride = $SummaryProcCountOverride
$script:BatteryEstimatedChargeOverride = $BatteryEstimatedChargeOverride
$script:TrimInfoOverride = $TrimInfoOverride
$script:VolumeInfoOverride = $VolumeInfoOverride
$script:DefragInfoOverride = $DefragInfoOverride
$script:StorageOptInfoOverride = $StorageOptInfoOverride
$script:diskChartLabels = ''
$script:diskChartUsed = ''
$script:diskChartFree = ''
$script:removableCount = 0
$script:fixedCount = 0
$script:externalDriveRegisteredCount = 0
$script:strDfirTimelineRecords = ''
$script:dfirTimelineRecordCount = 0
$script:networkAdapterCount = 0
$script:folderChartLabels = ''
$script:folderChartFiles = ''
$script:strUserArtifactTimelineRecords = ''
$script:userArtifactTimelineRecordCount = 0
$script:userArtifactTimelineCreateCount = 0
$script:userArtifactTimelineAccessCount = 0
$script:userArtifactTimelineModifyCount = 0
$script:WmiQueryIndex = @{}
$script:RegistryValueIndex = @{}
$script:CommandOutputIndex = @{}
$script:ProcessNameByPidIndex = @{}
$script:CommandOutputOverrides = @{}
$script:objActivityStartStamp = New-Object 'System.Collections.Generic.Dictionary[string,string]'
$script:objActivityStartTick = New-Object 'System.Collections.Generic.Dictionary[string,string]'

$script:strLogTimelineRows = ''
$script:strLogActivityRows = ''
$script:strLogQueryRows = ''
$script:strWarnErrorDetailRows = ''
$script:warnErrorDetailCount = 0
$script:logEventCount = 0
$script:logWarnCount = 0
$script:logErrorCount = 0
$script:logActivityCount = 0
$script:logStartCount = 0
$script:logOkCount = 0
$script:logNeutralCount = 0
$script:logEndCount = 0
$script:logPureOkCount = 0
$script:logEndWithoutStartCount = 0
$script:logEndWithStartCount = 0
$script:checklistTotalCount = 0
$script:checklistOkCount = 0
$script:cmdExecCount = 0
$script:cmdTimeoutCount = 0
$script:cmdFailCount = 0
$script:cmdTotalSecs = 0.0
$script:logQueryCount = 0

$script:threatEventTotalHits = 0
$script:threatEventAlertCount = 0
$script:threatEventWarnCount = 0
$script:threatEventInfoCount = 0
$script:threatHighPriorityHits = 0
$script:threatSecurityHits = 0
$script:threatPowerShellHits = 0
$script:threatSysmonHits = 0
$script:threatBitsHits = 0
$script:threatSystemHits = 0
$script:threatRegistryChecks = 0
$script:threatRegistryAlertCount = 0
$script:threatRegistryWarnCount = 0
$script:threatRegistryInfoCount = 0
$script:threatRedHits = 0
$script:threatYellowHits = 0
$script:threatRegistryPersistHits = 0
$script:threatRegistryAccessHits = 0
$script:threatRegistryTelemetryHits = 0
$script:threatRegistryCredHits = 0
$script:threatRegistryNetworkHits = 0
$script:threatEventExportCount = 0
$script:threatRegistrySnapshotExportCount = 0
$script:securityEventExportCount = 0
$script:evtxExportCount = 0
$script:evtExportCount = 0
$script:registryRootExportCount = 0
$script:smallArtifactExportCount = 0
$script:strEventLogArtifactExportRows = ''
$script:strRegistryRootArtifactExportRows = ''
$script:strSmallArtifactExportRows = ''
$script:bundleZipPath = ''
$script:bundleZipBytes = 0
$script:prefetchTimelineCaptured = $false
$script:OutputWriteFailed = $false
$script:OutputWriteError = ''

$strStartTime = if ($PSBoundParameters.ContainsKey('StartTimeOverride')) { $StartTimeOverride } else { TimestampLocalMillis $dtScriptStart }
$strRunId = BuildRunId
$strOutputFile = if ($PSBoundParameters.ContainsKey('OutputFile') -and $OutputFile) {
    if ([System.IO.Path]::IsPathRooted($OutputFile)) { $OutputFile } else { Join-Path $PSScriptRoot $OutputFile }
}
else {
    Join-Path $PSScriptRoot ($strComputer + '.html')
}
$strLogHtmlFile = 'StatusLog.html'
$strLogHtmlFilePath = Join-Path $PSScriptRoot $strLogHtmlFile
$strCustodyFileName = $strComputer + '_' + $strRunId + '_custody.csv'
$strCustodyFilePath = Join-Path $PSScriptRoot $strCustodyFileName
$script:strComputer = $strComputer
$script:strRunId = $strRunId
$script:strExportBaseDir = ''
$script:strStartTime = $strStartTime
$script:dblScriptStartTick = [double](Get-Date).TimeOfDay.TotalSeconds
$script:strLogHtmlFile = $strLogHtmlFile
$script:strLogHtmlFilePath = $strLogHtmlFilePath
$script:strCustodyFileName = $strCustodyFileName
$script:strCustodyFilePath = $strCustodyFilePath
$projectRootPath = Split-Path -Parent $PSScriptRoot
$script:TelemetrySkipPaths = @(
    $PSScriptRoot,
    $projectRootPath,
    (Join-Path $PSScriptRoot 'export')
) | Where-Object { ([string](Nz $_ '')).Trim() -ne '' } | Select-Object -Unique
$script:MinFreeSpaceBytes = [long](To-LongSafe ([Math]::Max([double]1.0, [double](To-DoubleSafe $MinFreeSpaceMB)))) * 1MB
$script:CurrentFreeSpaceBytes = [int64](Get-FreeSpaceBytesForPath -Path $strOutputFile)
$script:LowDiskSpaceMode = $false
$script:SkipHeavyExports = $false
if ($script:CurrentFreeSpaceBytes -ge 0 -and $script:CurrentFreeSpaceBytes -lt $script:MinFreeSpaceBytes) {
    $script:LowDiskSpaceMode = $true
    $script:SkipHeavyExports = [bool]$SkipHeavyExportsWhenLowDisk
    Write-ProgressLog -Message ('WARN: espaco livre baixo no disco de saida: ' + (FormatBytes $script:CurrentFreeSpaceBytes) + ' (minimo recomendado: ' + (FormatBytes $script:MinFreeSpaceBytes) + ').') -Force
}

if (Test-Path -LiteralPath $strOutputFile) {
    try {
        Remove-Item -LiteralPath $strOutputFile -Force -ErrorAction Stop
    }
    catch {
        Write-Host 'Aviso: arquivo HTML em uso; usando nome alternativo.'
        $outDir = Split-Path -Parent $strOutputFile
        if ([string](Nz $outDir '').Trim() -eq '') { $outDir = $PSScriptRoot }
        $strOutputFile = Join-Path $outDir ($strComputer + '_' + $strRunId + '.html')
    }
}

$script:objCustodyFile = $null
try {
    $script:objCustodyFile = Open-VbsTextWriter -Path $strCustodyFilePath
    $script:objCustodyFile.WriteLine("""timestamp"",""run_id"",""etapa"",""status"",""detalhes"",""usuario"",""host""")
}
catch {
    $script:objCustodyFile = $null
}

# ---- Open structured JSON audit log ----
Open-AuditLog -BasePath $PSScriptRoot -RunId $strRunId -Level $AuditLevel

$objFile = $null
try {
    $objFile = Open-VbsTextWriter -Path $strOutputFile
}
catch {
    Write-Host ('Falha ao criar HTML de saida: ' + $_.Exception.Message)
    exit 1
}

try {
    $script:CurrentWriter = $objFile
    LogCustody -Etapa 'SCRIPT' -Status 'START' -Detalhes 'Inicializacao da execucao'
    LogCustody -Etapa 'INIT' -Status 'OK' -Detalhes 'Inicializacao concluida'
    if ([bool](Nz $script:LowDiskSpaceMode $false)) {
        LogCustody -Etapa 'INIT' -Status 'WARN' -Detalhes ('Espaco livre baixo detectado: ' + (FormatBytes $script:CurrentFreeSpaceBytes) + ' | modo reducao: ' + (IIfBool $script:SkipHeavyExports 'ON' 'OFF'))
    }
    Write-ProgressLog -Message ('Stage selecionado: ' + $Stage) -Force
    switch ($Stage) {
        'FullExact' {
            Write-HeaderHeroBlock -Writer $objFile -ComputerNameText $strComputer -DomainText $userDomain -UserText $userName -StartTimeText $strStartTime
            Invoke-SectionStep -SectionName 'WriteSummaryDashboardSection' -Action { WriteSummaryDashboardSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteHardwareSection' -Action { WriteHardwareSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteDiskSection' -Action { WriteDiskSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteUSBSection' -Action { WriteUSBSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteSystemSection' -Action { WriteSystemSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteIdentityUsersSection' -Action { WriteIdentityUsersSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteFolderTelemetrySection' -Action { WriteFolderTelemetrySection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteSharesPortsPrintersSection' -Action { WriteSharesPortsPrintersSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WritePagingArtifactsSection' -Action { WritePagingArtifactsSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteControllersBackupSection' -Action { WriteControllersBackupSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteNetworkSection' -Action { WriteNetworkSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteNetworkDeepSection' -Action { WriteNetworkDeepSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteCISSection' -Action { WriteCISSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteSecuritySection' -Action { WriteSecuritySection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteThreatHuntSection' -Action { WriteThreatHuntSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'ExportOriginalArtifactsSection' -Action {
                if ([bool](Nz $script:SkipHeavyExports $false)) {
                    Write-ProgressLog -Message 'WARN: ExportOriginalArtifactsSection ignorada por espaco baixo no disco.' -Force
                    LogCustody -Etapa 'ExportOriginalArtifactsSection' -Status 'WARN' -Detalhes 'Etapa ignorada por espaco baixo no disco'
                    return
                }
                ExportOriginalArtifactsSection
            }
            Invoke-SectionStep -SectionName 'WriteServicesSection' -Action { WriteServicesSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteExecutionArtifactsSection' -Action { WriteExecutionArtifactsSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteSoftwareSection' -Action { WriteSoftwareSection -Writer $objFile }
            Invoke-SectionStep -SectionName 'WriteFinalFooterAndClose' -Action { Write-FinalFooterAndClose -Writer $objFile -LogHtmlFile $strLogHtmlFile }
        }
        'HeaderHeroOnly' {
            Write-HeaderHeroBlock -Writer $objFile -ComputerNameText $strComputer -DomainText $userDomain -UserText $userName -StartTimeText $strStartTime
        }
        'HeaderHeroSummaryOnly' {
            Write-HeaderHeroBlock -Writer $objFile -ComputerNameText $strComputer -DomainText $userDomain -UserText $userName -StartTimeText $strStartTime
            WriteSummaryDashboardSection -Writer $objFile
        }
        'HeaderHeroSummaryHardwareOnly' {
            Write-HeaderHeroBlock -Writer $objFile -ComputerNameText $strComputer -DomainText $userDomain -UserText $userName -StartTimeText $strStartTime
            WriteSummaryDashboardSection -Writer $objFile
            WriteHardwareSection -Writer $objFile
        }
        'HeaderHeroSummaryHardwareDiskOnly' {
            Write-HeaderHeroBlock -Writer $objFile -ComputerNameText $strComputer -DomainText $userDomain -UserText $userName -StartTimeText $strStartTime
            WriteSummaryDashboardSection -Writer $objFile
            WriteHardwareSection -Writer $objFile
            WriteDiskSection -Writer $objFile
        }
        'HeaderHeroSummaryHardwareDiskUsbOnly' {
            Write-HeaderHeroBlock -Writer $objFile -ComputerNameText $strComputer -DomainText $userDomain -UserText $userName -StartTimeText $strStartTime
            WriteSummaryDashboardSection -Writer $objFile
            WriteHardwareSection -Writer $objFile
            WriteDiskSection -Writer $objFile
            WriteUSBSection -Writer $objFile
        }
        'HeaderHeroSummaryHardwareDiskUsbSystemOnly' {
            Write-HeaderHeroBlock -Writer $objFile -ComputerNameText $strComputer -DomainText $userDomain -UserText $userName -StartTimeText $strStartTime
            WriteSummaryDashboardSection -Writer $objFile
            WriteHardwareSection -Writer $objFile
            WriteDiskSection -Writer $objFile
            WriteUSBSection -Writer $objFile
            WriteSystemSection -Writer $objFile
        }
        'HeaderHeroSummaryHardwareDiskUsbSystemIdentityOnly' {
            Write-HeaderHeroBlock -Writer $objFile -ComputerNameText $strComputer -DomainText $userDomain -UserText $userName -StartTimeText $strStartTime
            WriteSummaryDashboardSection -Writer $objFile
            WriteHardwareSection -Writer $objFile
            WriteDiskSection -Writer $objFile
            WriteUSBSection -Writer $objFile
            WriteSystemSection -Writer $objFile
            WriteIdentityUsersSection -Writer $objFile
        }
        'HeaderHeroSummaryHardwareDiskUsbSystemIdentityFoldersOnly' {
            Write-HeaderHeroBlock -Writer $objFile -ComputerNameText $strComputer -DomainText $userDomain -UserText $userName -StartTimeText $strStartTime
            WriteSummaryDashboardSection -Writer $objFile
            WriteHardwareSection -Writer $objFile
            WriteDiskSection -Writer $objFile
            WriteUSBSection -Writer $objFile
            WriteSystemSection -Writer $objFile
            WriteIdentityUsersSection -Writer $objFile
            WriteFolderTelemetrySection -Writer $objFile
        }
        'HeaderHeroSummaryHardwareDiskUsbSystemIdentityInfraOnly' {
            Write-HeaderHeroBlock -Writer $objFile -ComputerNameText $strComputer -DomainText $userDomain -UserText $userName -StartTimeText $strStartTime
            WriteSummaryDashboardSection -Writer $objFile
            WriteHardwareSection -Writer $objFile
            WriteDiskSection -Writer $objFile
            WriteUSBSection -Writer $objFile
            WriteSystemSection -Writer $objFile
            WriteIdentityUsersSection -Writer $objFile
            WriteFolderTelemetrySection -Writer $objFile
            WriteSharesPortsPrintersSection -Writer $objFile
            WritePagingArtifactsSection -Writer $objFile
            WriteControllersBackupSection -Writer $objFile
            WriteNetworkSection -Writer $objFile
            WriteNetworkDeepSection -Writer $objFile
        }
        'HeaderHeroSummaryHardwareDiskUsbSystemIdentityInfraServicesOnly' {
            Write-HeaderHeroBlock -Writer $objFile -ComputerNameText $strComputer -DomainText $userDomain -UserText $userName -StartTimeText $strStartTime
            WriteSummaryDashboardSection -Writer $objFile
            WriteHardwareSection -Writer $objFile
            WriteDiskSection -Writer $objFile
            WriteUSBSection -Writer $objFile
            WriteSystemSection -Writer $objFile
            WriteIdentityUsersSection -Writer $objFile
            WriteFolderTelemetrySection -Writer $objFile
            WriteSharesPortsPrintersSection -Writer $objFile
            WritePagingArtifactsSection -Writer $objFile
            WriteControllersBackupSection -Writer $objFile
            WriteNetworkSection -Writer $objFile
            WriteNetworkDeepSection -Writer $objFile
            WriteServicesSection -Writer $objFile
        }
        'HeaderHeroSummaryHardwareDiskUsbSystemIdentityInfraServicesCisOnly' {
            Write-HeaderHeroBlock -Writer $objFile -ComputerNameText $strComputer -DomainText $userDomain -UserText $userName -StartTimeText $strStartTime
            WriteSummaryDashboardSection -Writer $objFile
            WriteHardwareSection -Writer $objFile
            WriteDiskSection -Writer $objFile
            WriteUSBSection -Writer $objFile
            WriteSystemSection -Writer $objFile
            WriteIdentityUsersSection -Writer $objFile
            WriteFolderTelemetrySection -Writer $objFile
            WriteSharesPortsPrintersSection -Writer $objFile
            WritePagingArtifactsSection -Writer $objFile
            WriteControllersBackupSection -Writer $objFile
            WriteNetworkSection -Writer $objFile
            WriteNetworkDeepSection -Writer $objFile
            WriteServicesSection -Writer $objFile
            WriteCISSection -Writer $objFile
        }
    }
}
finally {
    $script:CurrentWriter = $null
    if ($null -ne $objFile) {
        try {
            $objFile.Close()
        }
        catch {
            Write-ProgressLog -Message ('WARN: falha ao fechar HTML principal: ' + $_.Exception.Message) -Force
        }
    }
}

if ($Stage -eq 'FullExact') {
    $strEndTime = TimestampLocalMillis (Get-Date)
    LogCustody -Etapa 'SCRIPT' -Status 'END' -Detalhes ('Execucao concluida; HTML gerado: ' + $strOutputFile)
    try {
        WriteExecutionLogHtml -MainHtmlFile $strOutputFile -EndStamp $strEndTime
    }
    catch {
        Write-ProgressLog -Message ('WARN: falha ao gerar StatusLog.html: ' + $_.Exception.Message) -Force
        LogCustody -Etapa 'STATUSLOG' -Status 'WARN' -Detalhes ('Falha ao gerar status log: ' + $_.Exception.Message)
    }
}

if ($null -ne $script:objCustodyFile) {
    try {
        $script:objCustodyFile.Close()
    }
    catch {
        Write-ProgressLog -Message ('WARN: falha ao fechar custody CSV: ' + $_.Exception.Message) -Force
    }
}

# ---- Close structured JSON audit log ----
Close-AuditLog


# ---- Cleanup: Remove original files preserved in ZIP if ZIP exists ----
if ($Stage -eq 'FullExact' -and (Test-Path -LiteralPath ([string]$script:bundleZipPath) -PathType Leaf)) {
    try {
        $zipInfo = Get-Item -LiteralPath ([string]$script:bundleZipPath)
        if ($zipInfo.Length -gt 1024) { # Minimal check to ensure zip is not empty/corrupt
            $filesToClean = @($strOutputFile, $strLogHtmlFilePath, $strCustodyFilePath)
            if ($script:AuditJsonPath -and (Test-Path -LiteralPath $script:AuditJsonPath)) { $filesToClean += $script:AuditJsonPath }
            
            Write-ProgressLog -Message "Limpando arquivos originais preservados no ZIP de evidencias..."
            foreach ($f in $filesToClean) {
                if (Test-Path -LiteralPath $f -PathType Leaf) {
                    [void](Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue)
                }
            }
            $expDir = GetRunExportBaseDir
            if (Test-Path -LiteralPath $expDir -PathType Container) {
                [void](Remove-Item -LiteralPath $expDir -Recurse -Force -ErrorAction SilentlyContinue)
            }
        }
    }
    catch {
        Write-ProgressLog -Message ('WARN: erro na limpeza pos-coleta (preservacao ZIP): ' + $_.Exception.Message)
    }
}

if (-not $SuppressFinalEcho) {
    Write-Host ('Inventario forense concluido. Arquivos movidos para o ZIP: ' + $script:bundleZipPath)
}
