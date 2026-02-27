' Descricao: Inventario automatizado com foco em telemetria forense
' Autor original: Nicolas Flores Ferreira
' Reestruturado para HTML5/CSS3 e coleta detalhada: 2026

Option Explicit
On Error Resume Next

Const HKCU = &H80000001
Const HKLM = &H80000002
Const ForReading = 1
Const ForWriting = 2
Const TristateFalse = 0
Const VALIDATION_QUERY_TIMEOUT_MODE = False
Const VALIDATION_QUERY_TIMEOUT_SECS = 2
Const GLOBAL_COMMAND_RUNTIME_LIMIT_SECS = 900

Dim objFSO, objShell, objNetwork, objFile, objWMI, objRegistry, objCustodyFile
Dim strComputer, strOutputFile, strNow, strStartTime, strCustodyFile, strRunId, strLogHtmlFile
Dim diskChartLabels, diskChartUsed, diskChartFree
Dim removableCount, fixedCount, networkAdapterCount, processCount, errorEventCount, serviceTotalCount, serviceRunningCount, serviceStoppedCount, externalDriveRegisteredCount
Dim folderChartLabels, folderChartFiles
Dim objActivityStartStamp, objActivityStartTick, strLogTimelineRows, strLogActivityRows, strLogQueryRows
Dim strWarnErrorDetailRows, warnErrorDetailCount
Dim logEventCount, logWarnCount, logErrorCount, logActivityCount, logStartCount, logOkCount, logNeutralCount, checklistTotalCount, checklistOkCount, cmdExecCount, cmdTimeoutCount, cmdFailCount, cmdTotalSecs, logQueryCount
Dim logEndCount, logPureOkCount, logEndWithoutStartCount, logEndWithStartCount
Dim dtScriptStart, dblScriptStartTick, hostManufacturerName, hostModelName, hostAssetType, hostBatteryCount, hostCpuLogicalCount, hostRamTotalBytes, hostServiceTag, hostLoggedUserSid
Dim threatEventTotalHits, threatEventAlertCount, threatEventWarnCount, threatEventInfoCount, threatHighPriorityHits
Dim threatSecurityHits, threatPowerShellHits, threatSysmonHits, threatBitsHits, threatSystemHits
Dim threatRegistryChecks, threatRegistryAlertCount, threatRegistryWarnCount, threatRegistryInfoCount
Dim threatRedHits, threatYellowHits
Dim threatRegistryPersistHits, threatRegistryAccessHits, threatRegistryTelemetryHits, threatRegistryCredHits, threatRegistryNetworkHits
Dim strDfirTimelineRecords, dfirTimelineRecordCount, prefetchTimelineCaptured
Dim strExportBaseDir, strThreatEventExportStatusRows, strThreatRegistrySnapshotStatusRows, strSecurityEventExportStatusRows
Dim threatEventExportCount, threatRegistrySnapshotExportCount, securityEventExportCount
Dim evtxExportCount, evtExportCount, registryRootExportCount, smallArtifactExportCount
Dim strEventLogArtifactExportRows, strRegistryRootArtifactExportRows, strSmallArtifactExportRows
Dim bundleZipPath, bundleZipBytes
Dim strUserArtifactTimelineRecords, userArtifactTimelineRecordCount, userArtifactTimelineCreateCount, userArtifactTimelineAccessCount, userArtifactTimelineModifyCount

Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objShell = CreateObject("WScript.Shell")
Set objNetwork = CreateObject("WScript.Network")
Set objActivityStartStamp = CreateObject("Scripting.Dictionary")
Set objActivityStartTick = CreateObject("Scripting.Dictionary")
strComputer = objNetwork.ComputerName
dtScriptStart = Now
dblScriptStartTick = Timer
strNow = FormatDateTime(Now, 2) & " " & FormatDateTime(Now, 3)
strStartTime = TimestampLocalMillis(dtScriptStart)
strRunId = BuildRunId()
strOutputFile = strComputer & ".html"
strCustodyFile = strComputer & "_" & strRunId & "_custody.csv"
strLogHtmlFile = "StatusLog.html"
strLogTimelineRows = ""
strLogActivityRows = ""
strLogQueryRows = ""
strWarnErrorDetailRows = ""
warnErrorDetailCount = 0
strExportBaseDir = ""
strThreatEventExportStatusRows = ""
strThreatRegistrySnapshotStatusRows = ""
strSecurityEventExportStatusRows = ""
threatEventExportCount = 0
threatRegistrySnapshotExportCount = 0
securityEventExportCount = 0
evtxExportCount = 0
evtExportCount = 0
registryRootExportCount = 0
smallArtifactExportCount = 0
strEventLogArtifactExportRows = ""
strRegistryRootArtifactExportRows = ""
strSmallArtifactExportRows = ""
bundleZipPath = ""
bundleZipBytes = 0
strUserArtifactTimelineRecords = ""
userArtifactTimelineRecordCount = 0
userArtifactTimelineCreateCount = 0
userArtifactTimelineAccessCount = 0
userArtifactTimelineModifyCount = 0
logEventCount = 0
logWarnCount = 0
logErrorCount = 0
logActivityCount = 0
logStartCount = 0
logOkCount = 0
logNeutralCount = 0
logEndCount = 0
logPureOkCount = 0
logEndWithoutStartCount = 0
logEndWithStartCount = 0
checklistTotalCount = 0
checklistOkCount = 0
cmdExecCount = 0
cmdTimeoutCount = 0
cmdFailCount = 0
cmdTotalSecs = 0
logQueryCount = 0
threatEventTotalHits = 0
threatEventAlertCount = 0
threatEventWarnCount = 0
threatEventInfoCount = 0
threatHighPriorityHits = 0
threatSecurityHits = 0
threatPowerShellHits = 0
threatSysmonHits = 0
threatBitsHits = 0
threatSystemHits = 0
threatRegistryChecks = 0
threatRegistryAlertCount = 0
threatRegistryWarnCount = 0
threatRegistryInfoCount = 0
threatRedHits = 0
threatYellowHits = 0
threatRegistryPersistHits = 0
threatRegistryAccessHits = 0
threatRegistryTelemetryHits = 0
threatRegistryCredHits = 0
threatRegistryNetworkHits = 0
hostManufacturerName = ""
hostModelName = ""
hostAssetType = "Indeterminado"
hostBatteryCount = 0
hostCpuLogicalCount = 0
hostRamTotalBytes = 0
hostServiceTag = ""
hostLoggedUserSid = ""
serviceTotalCount = 0
serviceRunningCount = 0
serviceStoppedCount = 0
externalDriveRegisteredCount = 0
strDfirTimelineRecords = ""
dfirTimelineRecordCount = 0
prefetchTimelineCaptured = False
Set objCustodyFile = Nothing

On Error Resume Next
Err.Clear
Set objCustodyFile = objFSO.OpenTextFile(strCustodyFile, ForWriting, True, TristateFalse)
If Err.Number = 0 Then
    objCustodyFile.WriteLine """timestamp"",""run_id"",""etapa"",""status"",""detalhes"",""usuario"",""host"""
Else
    Set objCustodyFile = Nothing
    Err.Clear
End If
On Error Goto 0

LogCustody "SCRIPT", "START", "Inicializacao da execucao"

On Error Resume Next
Err.Clear
If objFSO.FileExists(strOutputFile) Then
    objFSO.DeleteFile strOutputFile, True
    If Err.Number <> 0 Then
        WScript.Echo "Aviso: arquivo HTML em uso; usando nome alternativo."
        Err.Clear
        strOutputFile = strComputer & "_" & strRunId & ".html"
    End If
End If

Set objFile = objFSO.OpenTextFile(strOutputFile, ForWriting, True, TristateFalse)
If Err.Number <> 0 Then
    WScript.Echo "Falha ao criar HTML de saida: " & Err.Description
    WScript.Quit 1
End If
On Error Goto 0

Dim wmiRetries
wmiRetries = 0
Dim wmiConnected
wmiConnected = False

Do While wmiRetries < 3 And Not wmiConnected
    On Error Resume Next
    Err.Clear
    Set objWMI = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
    Set objRegistry = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\default:StdRegProv")
    
    If Err.Number = 0 Then
        wmiConnected = True
    Else
        wmiRetries = wmiRetries + 1
        If wmiRetries < 3 Then
            WScript.Sleep 2000
        End If
    End If
    On Error Goto 0
Loop

If Err.Number <> 0 Or Not wmiConnected Then
    Dim errMsg
    errMsg = "Aviso: Falha ao conectar com servicos WMI"
    If Err.Number <> 0 Then
        errMsg = errMsg & " (Codigo: " & Err.Number & ")"
    End If
    errMsg = errMsg & " - O script continuar com dados limitados. Use privilegios elevados para coleta completa."
    
    LogCustody "INIT", "WARN", errMsg
    WScript.Echo "?? " & errMsg
End If

Err.Clear
LogCustody "INIT", "OK", "Inicializacao concluida"

objFile.WriteLine "<!DOCTYPE html>"
objFile.WriteLine "<html lang='pt-BR'>"
objFile.WriteLine "<head>"
objFile.WriteLine "  <meta charset='windows-1252'>"
objFile.WriteLine "  <meta name='viewport' content='width=device-width, initial-scale=1'>"
objFile.WriteLine "  <title>Relatorio Forense - " & HtmlEncode(strComputer) & "</title>"
objFile.WriteLine "  <style>"
objFile.WriteLine "    :root{--bg:#0f172a;--card:#111827;--muted:#94a3b8;--text:#e2e8f0;--accent:#38bdf8;--ok:#22c55e;--warn:#f59e0b;--bad:#ef4444;}"
objFile.WriteLine "    *{box-sizing:border-box} body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:linear-gradient(180deg,#020617,#0f172a);color:var(--text);}"
objFile.WriteLine "    .wrap{max-width:1320px;margin:0 auto;padding:24px} .hero{background:rgba(17,24,39,.85);border:1px solid #1f2937;padding:20px;border-radius:14px;backdrop-filter:blur(4px)}"
objFile.WriteLine "    h1,h2,h3{margin:.2rem 0 1rem 0} h1{font-size:clamp(1.4rem,5vw,2.2rem)} h2{font-size:1.2rem;border-left:4px solid var(--accent);padding-left:10px}"
objFile.WriteLine "    .muted{color:var(--muted);font-size:clamp(0.8rem,2vw,0.95rem)} .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;margin-top:16px}"
objFile.WriteLine "    .card{background:rgba(17,24,39,.9);border:1px solid #1f2937;border-radius:12px;padding:14px;box-shadow:0 8px 20px rgba(0,0,0,.2)}"
objFile.WriteLine "    .kpi{font-size:clamp(1.3rem,4vw,1.7rem);font-weight:700} .kpi-text{font-size:clamp(.95rem,2.6vw,1.15rem);line-height:1.25;white-space:normal;overflow-wrap:anywhere;word-break:break-word} .kpi-label{font-size:clamp(0.75rem,2vw,0.85rem);color:var(--muted)}"
objFile.WriteLine "    table{width:100%;border-collapse:collapse;margin:10px 0;background:#0b1220;border-radius:10px;overflow:hidden;table-layout:auto} th,td{padding:clamp(6px,2vw,8px);border-bottom:1px solid #1f2937;vertical-align:top;word-wrap:break-word;word-break:break-word} th{background:#111827;color:#93c5fd;text-align:left;font-size:clamp(0.8rem,2vw,0.95rem)}"
objFile.WriteLine "    tr:hover td{background:#0f1a2e} .tag{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.75rem} .ok{background:rgba(34,197,94,.2);color:#86efac}.warn{background:rgba(245,158,11,.2);color:#fcd34d}.bad{background:rgba(239,68,68,.2);color:#fca5a5}"
objFile.WriteLine "    .bar{height:8px;background:#1f2937;border-radius:999px;overflow:hidden}.bar > span{display:block;height:100%;background:linear-gradient(90deg,#06b6d4,#3b82f6)}"
objFile.WriteLine "    .toc{display:flex;flex-wrap:wrap;gap:clamp(8px,2vw,10px);margin-top:16px} .toc a{color:#7dd3fc;text-decoration:none;font-size:clamp(0.7rem,1.8vw,0.9rem);line-height:1.4;padding:clamp(4px,1vw,6px) clamp(8px,2vw,10px);background:rgba(56,189,248,.1);border-radius:6px;display:inline-block;white-space:nowrap;transition:all .2s ease}.toc a:hover{text-decoration:underline;background:rgba(56,189,248,.2);transform:translateY(-2px)}"
objFile.WriteLine "    .location-col{white-space:normal;word-break:break-word}"
objFile.WriteLine "    .filter-container{margin:10px 0;padding:12px;background:rgba(30,41,59,.5);border-radius:8px;border:1px solid #1f2937;display:flex;align-items:center;gap:8px;flex-wrap:wrap}.filter-input{padding:8px 12px;background:#0b1220;border:1px solid #1f2937;border-radius:6px;color:#e2e8f0;font-size:0.9rem;width:100%;max-width:400px;transition:all .2s;flex:1 1 280px}.filter-input:focus{outline:none;border-color:#38bdf8;box-shadow:0 0 8px rgba(56,189,248,.3)}.table-export-btn{padding:8px 12px;border:1px solid #2563eb;border-radius:6px;background:#1d4ed8;color:#eff6ff;cursor:pointer;font-size:.85rem}.table-export-btn:hover{background:#2563eb}"
objFile.WriteLine "    .scroll-to-top{position:fixed;bottom:30px;right:30px;width:50px;height:50px;background:#38bdf8;color:#0f172a;border:none;border-radius:50%;font-size:24px;cursor:pointer;display:none;align-items:center;justify-content:center;box-shadow:0 4px 12px rgba(56,189,248,.4);z-index:999;transition:all .3s;font-weight:bold}.scroll-to-top:hover{background:#0ea5e9;transform:translateY(-3px);box-shadow:0 6px 16px rgba(56,189,248,.6)}.scroll-to-top.show{display:flex}"
objFile.WriteLine "    .fab-nav{position:fixed;left:22px;bottom:22px;z-index:1000}"
objFile.WriteLine "    .fab-main{width:54px;height:54px;border:none;border-radius:50%;background:linear-gradient(135deg,#22d3ee,#3b82f6);color:#03111f;font-weight:700;font-size:22px;cursor:pointer;box-shadow:0 10px 22px rgba(0,0,0,.35)}"
objFile.WriteLine "    .fab-main:hover{transform:translateY(-2px)}"
objFile.WriteLine "    .fab-menu{display:none;position:absolute;left:0;bottom:66px;min-width:280px;max-width:min(92vw,420px);max-height:70vh;overflow:auto;padding:10px;border-radius:12px;background:rgba(2,6,23,.96);border:1px solid #1f2937;box-shadow:0 12px 28px rgba(0,0,0,.45)}"
objFile.WriteLine "    .fab-menu.show{display:block}"
objFile.WriteLine "    .fab-menu .fab-title{font-size:.78rem;color:#93c5fd;margin:0 0 8px 0;padding-bottom:6px;border-bottom:1px solid #1f2937}"
objFile.WriteLine "    .fab-menu a{display:block;color:#e2e8f0;text-decoration:none;padding:7px 9px;border-radius:8px;font-size:.85rem}"
objFile.WriteLine "    .fab-menu a:hover{background:rgba(56,189,248,.12);color:#7dd3fc}"
objFile.WriteLine "    .fab-group{border:1px solid rgba(31,41,55,.7);border-radius:10px;background:rgba(15,23,42,.35);margin:7px 0;overflow:hidden}"
objFile.WriteLine "    .fab-group summary{cursor:pointer;list-style:none;padding:8px 10px;color:#bae6fd;font-size:.82rem;font-weight:700;display:flex;align-items:center;gap:8px}"
objFile.WriteLine "    .fab-group summary::-webkit-details-marker{display:none}"
objFile.WriteLine "    .fab-group summary::before{content:'+';width:16px;height:16px;display:inline-flex;align-items:center;justify-content:center;border-radius:999px;background:rgba(56,189,248,.1);color:#7dd3fc;font-weight:700;font-size:.8rem}"
objFile.WriteLine "    .fab-group[open] summary::before{content:'-'}"
objFile.WriteLine "    .fab-group .fab-submenu{padding:0 6px 6px 6px;border-top:1px solid rgba(31,41,55,.6)}"
objFile.WriteLine "    .fab-group .fab-submenu a{font-size:.8rem;padding:6px 8px;margin-top:4px;color:#cbd5e1}"
objFile.WriteLine "    .fab-link-main{font-weight:600}"
objFile.WriteLine "    .split-2{display:grid;grid-template-columns:minmax(0,3fr) minmax(0,1fr);gap:14px;align-items:start}"
objFile.WriteLine "    .split-panel{background:rgba(15,23,42,.45);border:1px solid #1f2937;border-radius:12px;padding:12px;min-height:100%;overflow:hidden}.split-panel h3{margin-top:.2rem}.split-panel table{table-layout:auto}.split-panel .scroll-table{margin-top:6px}"
objFile.WriteLine "    .mini-note{color:#94a3b8;font-size:.8rem;margin:.2rem 0 .8rem 0}"
objFile.WriteLine "    details.collapsible-card{padding:0;overflow:hidden} details.collapsible-card[open]{padding:14px} details.collapsible-card summary{list-style:none;cursor:pointer;padding:14px 16px;font-weight:700;color:#e2e8f0;display:flex;align-items:center;gap:10px;background:linear-gradient(180deg,rgba(30,41,59,.45),rgba(15,23,42,.3));border-bottom:1px solid rgba(31,41,55,.8)} details.collapsible-card[open] summary{margin:-14px -14px 12px -14px} details.collapsible-card summary::-webkit-details-marker{display:none} details.collapsible-card summary::before{content:'+';display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:rgba(56,189,248,.12);color:#7dd3fc;font-weight:700;flex:0 0 22px} details.collapsible-card[open] summary::before{content:'-'} details.collapsible-card .collapsible-sub{color:#94a3b8;font-size:.78rem;font-weight:400;margin-left:auto;padding-left:8px}"
objFile.WriteLine "    details.sub-collapsible{margin:10px 0 0 0;border:1px solid rgba(31,41,55,.75);border-radius:10px;background:rgba(2,6,23,.22);overflow:hidden} details.sub-collapsible[open]{padding:10px} details.sub-collapsible > summary{list-style:none;cursor:pointer;padding:10px 12px;color:#cbd5e1;font-weight:600;font-size:.92rem;background:rgba(15,23,42,.45);border-bottom:1px solid rgba(31,41,55,.7)} details.sub-collapsible > summary::-webkit-details-marker{display:none} details.sub-collapsible > summary::before{content:'+';display:inline-block;width:16px;text-align:center;margin-right:8px;color:#7dd3fc} details.sub-collapsible[open] > summary::before{content:'-'} details.sub-collapsible[open] > summary{margin:-10px -10px 10px -10px}"
objFile.WriteLine "    @media(max-width:1120px){.split-2{grid-template-columns:1fr}.split-panel{padding:10px}}"
objFile.WriteLine "    footer{margin:25px 0;color:var(--muted);font-size:clamp(0.8rem,2vw,0.85rem)} pre{white-space:pre-wrap;word-break:break-word;font-size:clamp(0.7rem,1.5vw,0.85rem)} .snap-pre{white-space:pre;word-break:normal;overflow:auto;display:block} .scroll-table{overflow-x:auto;border-radius:10px;-webkit-overflow-scrolling:touch} .scroll-table table{margin:10px 0;min-width:100%;width:auto} .scroll-table th,.scroll-table td{white-space:nowrap} .snap-no-wrap table{min-width:1100px} .snap-no-wrap pre{white-space:pre;word-break:normal;overflow:auto;max-width:none} @media(max-width:768px){.wrap{padding:16px} h1{font-size:clamp(1.3rem,5vw,1.8rem)} h2{font-size:clamp(1rem,3vw,1.2rem)} .hero{padding:16px} table{font-size:clamp(0.75rem,2vw,0.9rem)} th,td{padding:clamp(4px,1.5vw,6px)} .grid{grid-template-columns:1fr}} @media(max-width:480px){.wrap{padding:12px} .hero{padding:12px} .toc{gap:6px} .toc a{font-size:0.7rem;padding:4px 8px} h2{border-left-width:3px}.scroll-to-top{bottom:20px;right:20px;width:45px;height:45px;font-size:20px}}"
objFile.WriteLine "  </style>"
objFile.WriteLine "  <script src='https://cdn.jsdelivr.net/npm/chart.js'></script>"
objFile.WriteLine "</head><body><main class='wrap'>"
objFile.WriteLine "  <div class='fab-nav' id='quickNav'>"
objFile.WriteLine "    <button class='fab-main' id='quickNavBtn' title='Menu rapido de links' aria-label='Menu rapido de links' aria-expanded='false'>+</button>"
objFile.WriteLine "    <div class='fab-menu' id='quickNavMenu'>"
objFile.WriteLine "      <div class='fab-title'>Navegacao rapida</div>"
objFile.WriteLine "      <div id='quickNavDynamic'><a href='#sumario' class='fab-link-main'>Sumario</a></div>"
objFile.WriteLine "    </div>"
objFile.WriteLine "  </div>"
objFile.WriteLine "  <button class='scroll-to-top' id='scrollTopBtn' title='Ir para o topo'>&#8593;</button>"
objFile.WriteLine "  <section class='hero'>"
objFile.WriteLine "    <h1>Relatorio de Telemetria Forense</h1>"
objFile.WriteLine "    <p class='muted'>Host: <strong>" & HtmlEncode(strComputer) & "</strong> | Usurio da coleta: <strong>" & HtmlEncode(objNetwork.UserDomain & "\" & objNetwork.UserName) & "</strong> | Inicio da geracao: <strong>" & HtmlEncode(strStartTime) & "</strong></p>"
objFile.WriteLine "    <nav class='toc'>"
objFile.WriteLine "      <a href='#sumario'>Sumario</a><a href='#hardware'>Hardware</a><a href='#discos'>Volumes/Discos</a><a href='#usb'>Dispositivos Externos</a><a href='#so'>Sistema</a><a href='#identidade'>Usuarios/Contas</a><a href='#pastas'>Pastas Usuario</a><a href='#shares'>Shares/Portas/Impressao</a><a href='#artefatos'>Artefatos</a><a href='#controladores'>Controladores/Backup</a><a href='#rede'>Rede</a><a href='#redeplus'>TCP/DNS/VPN</a><a href='#cis'>CIS/Hardening</a><a href='#seguranca'>Eventos</a><a href='#ameacas'>Deteccao</a><a href='#servicos'>Servicos</a><a href='#execucao'>Execucao de Software</a><a href='#apps'>Softwares/Persistencia</a>"
objFile.WriteLine "    </nav>"
objFile.WriteLine "  </section>"

LogCustody "WriteSummaryDashboardSection", "START", "Inicio da etapa"
Call WriteSummaryDashboardSection()
LogCustody "WriteSummaryDashboardSection", "END", "Etapa concluida"

LogCustody "WriteHardwareSection", "START", "Inicio da etapa"
Call WriteHardwareSection()
LogCustody "WriteHardwareSection", "END", "Etapa concluida"

LogCustody "WriteDiskSection", "START", "Inicio da etapa"
Call WriteDiskSection()
LogCustody "WriteDiskSection", "END", "Etapa concluida"

LogCustody "WriteUSBSection", "START", "Inicio da etapa"
Call WriteUSBSection()
LogCustody "WriteUSBSection", "END", "Etapa concluida"

LogCustody "WriteSystemSection", "START", "Inicio da etapa"
Call WriteSystemSection()
LogCustody "WriteSystemSection", "END", "Etapa concluida"

LogCustody "WriteIdentityUsersSection", "START", "Inicio da etapa"
Call WriteIdentityUsersSection()
LogCustody "WriteIdentityUsersSection", "END", "Etapa concluida"

LogCustody "WriteFolderTelemetrySection", "START", "Inicio da etapa"
Call WriteFolderTelemetrySection()
LogCustody "WriteFolderTelemetrySection", "END", "Etapa concluida"

LogCustody "WriteSharesPortsPrintersSection", "START", "Inicio da etapa"
Call WriteSharesPortsPrintersSection()
LogCustody "WriteSharesPortsPrintersSection", "END", "Etapa concluida"

LogCustody "WritePagingArtifactsSection", "START", "Inicio da etapa"
Call WritePagingArtifactsSection()
LogCustody "WritePagingArtifactsSection", "END", "Etapa concluida"

LogCustody "WriteControllersBackupSection", "START", "Inicio da etapa"
Call WriteControllersBackupSection()
LogCustody "WriteControllersBackupSection", "END", "Etapa concluida"

LogCustody "WriteNetworkSection", "START", "Inicio da etapa"
Call WriteNetworkSection()
LogCustody "WriteNetworkSection", "END", "Etapa concluida"

LogCustody "WriteNetworkDeepSection", "START", "Inicio da etapa"
Call WriteNetworkDeepSection()
LogCustody "WriteNetworkDeepSection", "END", "Etapa concluida"

LogCustody "WriteCISSection", "START", "Inicio da etapa"
Call WriteCISSection()
LogCustody "WriteCISSection", "END", "Etapa concluida"

LogCustody "WriteSecuritySection", "START", "Inicio da etapa"
Call WriteSecuritySection()
LogCustody "WriteSecuritySection", "END", "Etapa concluida"

LogCustody "WriteThreatHuntSection", "START", "Inicio da etapa"
Call WriteThreatHuntSection()
LogCustody "WriteThreatHuntSection", "END", "Etapa concluida"

LogCustody "ExportOriginalArtifactsSection", "START", "Inicio da etapa"
Call ExportOriginalArtifactsSection()
LogCustody "ExportOriginalArtifactsSection", "END", "Etapa concluida"

LogCustody "WriteServicesSection", "START", "Inicio da etapa"
Call WriteServicesSection()
LogCustody "WriteServicesSection", "END", "Etapa concluida"

LogCustody "WriteExecutionArtifactsSection", "START", "Inicio da etapa"
Call WriteExecutionArtifactsSection()
LogCustody "WriteExecutionArtifactsSection", "END", "Etapa concluida"

LogCustody "WriteSoftwareSection", "START", "Inicio da etapa"
Call WriteSoftwareSection()
LogCustody "WriteSoftwareSection", "END", "Etapa concluida"

Dim strEndTime
strEndTime = TimestampLocalMillis(Now)
objFile.WriteLine "<footer>Relatorio gerado automaticamente via WMI/Registry/CMD. Finalizacao: <strong>" & HtmlEncode(strEndTime) & "</strong>. Log de execucao: <a href='" & HtmlEncode(strLogHtmlFile) & "' style='color:#7dd3fc'>" & HtmlEncode(strLogHtmlFile) & "</a>. Recomenda-se executar como administrador para maxima cobertura forense.</footer>"
objFile.WriteLine "</main>"
objFile.WriteLine "<script>"
objFile.WriteLine "window.addEventListener('scroll', function(){var btn = document.getElementById('scrollTopBtn'); if(window.pageYOffset > 300) btn.classList.add('show'); else btn.classList.remove('show');});"
objFile.WriteLine "document.getElementById('scrollTopBtn').addEventListener('click', function(){window.scrollTo({top:0, behavior:'smooth'});});"
objFile.WriteLine "function csvEscape(v){v=(v==null?'' : String(v));var q=String.fromCharCode(34); if(/[;,\\n]/.test(v)||v.indexOf(q)>-1){return q+v.split(q).join(q+q)+q;} return v;}"
objFile.WriteLine "function exportTableCsv(table,fileName){var trs=Array.prototype.slice.call(table.querySelectorAll('tr'));var lines=[];trs.forEach(function(tr){if(tr.style.display==='none'){return;} var cells=tr.querySelectorAll('th,td'); if(!cells.length){return;} var row=[]; cells.forEach(function(c){var t=(c.innerText||c.textContent||'').replace(/\s+/g,' ').trim(); row.push(csvEscape(t));}); lines.push(row.join(';'));}); var blob=new Blob([lines.join('\\r\\n')],{type:'text/csv;charset=windows-1252;'}); var a=document.createElement('a'); a.href=URL.createObjectURL(blob); a.download=fileName||'tabela.csv'; document.body.appendChild(a); a.click(); setTimeout(function(){URL.revokeObjectURL(a.href); a.remove();},0);}"
objFile.WriteLine "function _slugifyAnchor(t){t=(t||'').toString().toLowerCase().replace(/[\\u00C0-\\u017F]/g,'').replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,''); if(!t){t='bloco';} return t;}"
objFile.WriteLine "function _summaryText(node){if(!node){return 'Secao';} var c=node.cloneNode(true); Array.prototype.slice.call(c.querySelectorAll('.collapsible-sub')).forEach(function(n){n.remove();}); return (c.textContent||'Secao').replace(/\\s+/g,' ').trim();}"
objFile.WriteLine "function _wrapSectionSubBlocks(detailsEl, fallbackTitle){if(!detailsEl){return;} var kids=Array.prototype.slice.call(detailsEl.children); if(!kids.length){return;} var groups=[]; var current=null; kids.forEach(function(n){if(n.tagName && n.tagName.toLowerCase()==='summary'){return;} if(n.tagName && n.tagName.toLowerCase()==='h3'){current={title:(n.textContent||fallbackTitle||'Subbloco').replace(/\\s+/g,' ').trim(), nodes:[]}; groups.push(current); return;} if(!current){current={title:fallbackTitle||'Visao geral', nodes:[]}; groups.push(current);} current.nodes.push(n);}); if(!groups.length){return;} groups.forEach(function(g,idx){if(!g.nodes.length){return;} var sub=document.createElement('details'); sub.className='sub-collapsible'; sub.open=false; var subId=(detailsEl.id||'sec')+'-sub-'+(idx+1)+'-'+_slugifyAnchor(g.title); sub.id=subId; var sm=document.createElement('summary'); sm.textContent=g.title; sub.appendChild(sm); g.nodes[0].parentNode.insertBefore(sub,g.nodes[0]); g.nodes.forEach(function(n){sub.appendChild(n);});});}"
objFile.WriteLine "function _buildQuickMenuFromSections(){var host=document.getElementById('quickNavDynamic'); if(!host){return;} host.innerHTML=''; var sum=document.createElement('a'); sum.href='#sumario'; sum.className='fab-link-main'; sum.textContent='Sumario'; host.appendChild(sum); var sections=Array.prototype.slice.call(document.querySelectorAll('main.wrap > details.collapsible-card[id]')); if(!sections.length){return;} sections.forEach(function(sec){var mainSummary=sec.querySelector(':scope > summary')||sec.querySelector('summary'); var title=_summaryText(mainSummary); var group=document.createElement('details'); group.className='fab-group'; var sm=document.createElement('summary'); sm.textContent=title; group.appendChild(sm); var inner=document.createElement('div'); inner.className='fab-submenu'; var mainLink=document.createElement('a'); mainLink.href='#'+sec.id; mainLink.className='fab-link-main'; mainLink.textContent='Ir para bloco'; inner.appendChild(mainLink); Array.prototype.slice.call(sec.querySelectorAll(':scope > details.sub-collapsible[id]')).forEach(function(sub){var a=document.createElement('a'); a.href='#'+sub.id; var s=sub.querySelector(':scope > summary')||sub.querySelector('summary'); a.textContent=_summaryText(s); inner.appendChild(a);}); group.appendChild(inner); host.appendChild(group);});}"
objFile.WriteLine "document.addEventListener('DOMContentLoaded', function(){var ids={'hardware':1,'discos':1,'usb':1,'so':1,'identidade':1,'pastas':1,'shares':1,'artefatos':1,'controladores':1,'rede':1,'redeplus':1,'cis':1,'seguranca':1,'ameacas':1,'servicos':1,'execucao':1,'apps':1}; var subDefaults={'hardware':'Hardware (placa-mae, BIOS, CPU, memoria)','discos':'Volumes, particoes e discos fisicos','usb':'Dispositivos externos e PnP relevantes','so':'Sistema Operacional e contexto','identidade':'Identidade do sistema, contas locais e grupos (contexto forense)','pastas':'Telemetria de pastas do usuario','shares':'Compartilhamentos, portas abertas e impressao','artefatos':'Pagefile, Prefetch, artefatos e snapshots','controladores':'Controladores de disco, backup e historico de unidades','rede':'Rede e configuracao TCP/IP','redeplus':'IP/TCP/DNS/VPN (coleta complementar)','cis':'Controles criticos (referencia CIS) para triagem de incidente','seguranca':'Processos e eventos criticos','ameacas':'Deteccao e correlacao','servicos':'Servicos detalhados','execucao':'Primeira/ultima execucao (aproximacao por artefatos)','apps':'Softwares instalados e persistencia (forense)'}; Array.prototype.slice.call(document.querySelectorAll('main.wrap > section.card[id]')).forEach(function(sec){if(!ids[sec.id]){return;} var h2=sec.querySelector(':scope > h2')||sec.querySelector('h2'); if(!h2){return;} var details=document.createElement('details'); details.className=sec.className+' collapsible-card'; details.id=sec.id; if(sec.getAttribute('style')){details.setAttribute('style',sec.getAttribute('style'));} details.open = false; var summary=document.createElement('summary'); summary.textContent=(h2.textContent||'Secao').replace(/\\s+/g,' ').trim(); var note=document.createElement('span'); note.className='collapsible-sub'; note.textContent='Clique para expandir/recolher'; summary.appendChild(note); details.appendChild(summary); sec.removeAttribute('id'); sec.removeAttribute('style'); if(h2.parentNode===sec){sec.removeChild(h2);} while(sec.firstChild){details.appendChild(sec.firstChild);} sec.parentNode.replaceChild(details, sec); _wrapSectionSubBlocks(details, subDefaults[details.id] || summary.textContent);}); _buildQuickMenuFromSections();});"
objFile.WriteLine "document.addEventListener('DOMContentLoaded', function(){var qWrap=document.getElementById('quickNav');var qBtn=document.getElementById('quickNavBtn');var qMenu=document.getElementById('quickNavMenu');if(!qWrap||!qBtn||!qMenu){return;} function closeMenu(){qMenu.classList.remove('show');qBtn.setAttribute('aria-expanded','false');} qBtn.addEventListener('click',function(e){e.stopPropagation();var open=qMenu.classList.toggle('show');qBtn.setAttribute('aria-expanded',open?'true':'false');}); qMenu.addEventListener('click',function(e){var t=e.target; if(t&&t.tagName&&t.tagName.toLowerCase()==='a'){closeMenu();}}); document.addEventListener('click',function(e){if(!qWrap.contains(e.target)){closeMenu();}});});"
objFile.WriteLine "document.addEventListener('DOMContentLoaded', function(){"
objFile.WriteLine "  var tables = document.querySelectorAll('table');"
objFile.WriteLine "  tables.forEach(function(table, idx) {"
objFile.WriteLine "    var tableId = 'table-' + idx;"
objFile.WriteLine "    table.id = tableId;"
objFile.WriteLine "    var rows = table.querySelectorAll('tbody tr');"
objFile.WriteLine "    if(rows.length === 0) rows = table.querySelectorAll('tr');"
objFile.WriteLine "    if(rows.length > 5) {"
objFile.WriteLine "      var filterDiv = document.createElement('div');"
objFile.WriteLine "      filterDiv.classList.add('filter-container');"
objFile.WriteLine "      var filterLabel = document.createElement('label');"
objFile.WriteLine "      filterLabel.style.marginRight = '2px';"
objFile.WriteLine "      filterLabel.textContent = 'Filtrar:';"
objFile.WriteLine "      filterLabel.style.color = '#94a3b8';"
objFile.WriteLine "      var filterInput = document.createElement('input');"
objFile.WriteLine "      filterInput.type = 'text';"
objFile.WriteLine "      filterInput.classList.add('filter-input');"
objFile.WriteLine "      filterInput.placeholder = 'Digite para filtrar linhas...';"
objFile.WriteLine "      var exportBtn = document.createElement('button');"
objFile.WriteLine "      exportBtn.type = 'button';"
objFile.WriteLine "      exportBtn.classList.add('table-export-btn');"
objFile.WriteLine "      exportBtn.textContent = 'Exportar CSV';"
objFile.WriteLine "      exportBtn.addEventListener('click', function(){ exportTableCsv(table, tableId + '.csv'); });"
objFile.WriteLine "      filterDiv.appendChild(filterLabel);"
objFile.WriteLine "      filterDiv.appendChild(filterInput);"
objFile.WriteLine "      filterDiv.appendChild(exportBtn);"
objFile.WriteLine "      table.parentNode.insertBefore(filterDiv, table);"
objFile.WriteLine "      filterInput.addEventListener('keyup', function() {"
objFile.WriteLine "        var filter = this.value.toUpperCase();"
objFile.WriteLine "        for(var i = 1; i < rows.length; i++) {"
objFile.WriteLine "          var text = rows[i].textContent || rows[i].innerText;"
objFile.WriteLine "          if(text.toUpperCase().indexOf(filter) > -1) {"
objFile.WriteLine "            rows[i].style.display = '';"
objFile.WriteLine "          } else {"
objFile.WriteLine "            rows[i].style.display = 'none';"
objFile.WriteLine "          }"
objFile.WriteLine "        }"
objFile.WriteLine "      });"
objFile.WriteLine "    }"
objFile.WriteLine "  });"
objFile.WriteLine "});"
objFile.WriteLine "</script>"
objFile.WriteLine "</body></html>"
objFile.Close
LogCustody "SCRIPT", "END", "Execucao concluida; HTML gerado: " & strOutputFile
WriteExecutionLogHtml strOutputFile, strEndTime
If Not (objCustodyFile Is Nothing) Then
    On Error Resume Next
    objCustodyFile.Close
    Err.Clear
    On Error Goto 0
End If

WScript.Echo "Inventario forense concluido: " & strOutputFile & " | Log: " & strLogHtmlFile

Sub WriteSummaryDashboardSection()
    Dim colOS, os, colCS, cs, colCPU, cpu, totalCPUs, colProc, proc, procCount
    Dim colSvc, svc, svcCount, evtCount, errorCount, ramGbText, osInstallText, osUpdateText, tmpDt
    Dim colExtDrive, extDrive, extDriveRegisteredSummaryCount

    procCount = 0
    svcCount = 0
    evtCount = 0
    errorCount = 0
    totalCPUs = 0
    ramGbText = "-"
    osInstallText = "-"
    osUpdateText = "-"
    extDriveRegisteredSummaryCount = 0

    EnsureHostIdentityContext

    objFile.WriteLine "<section id='sumario' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Sumario Executivo - Dashboard de Telemetria</h2>"

    Set colOS = objWMI.ExecQuery("SELECT * FROM Win32_OperatingSystem")
    Set colCS = objWMI.ExecQuery("SELECT * FROM Win32_ComputerSystem")
    Set colCPU = objWMI.ExecQuery("SELECT * FROM Win32_Processor")
    Set colProc = objWMI.ExecQuery("SELECT * FROM Win32_Process")
    Set colSvc = objWMI.ExecQuery("SELECT * FROM Win32_Service")
    Set colExtDrive = objWMI.ExecQuery("SELECT * FROM Win32_PnPEntity WHERE PNPClass='DiskDrive' OR PNPClass='USB' OR (PNPDeviceID LIKE 'USBSTOR%' OR PNPDeviceID LIKE 'USB\\\\%')")
    evtCount = 0
    errorCount = 0

    For Each cpu In colCPU
        totalCPUs = totalCPUs + 1
    Next
    For Each proc In colProc
        procCount = procCount + 1
    Next
    For Each svc In colSvc
        serviceTotalCount = serviceTotalCount + 1
        svcCount = svcCount + 1
    Next
    For Each extDrive In colExtDrive
        If InStr(UCase(Nz(extDrive.PNPDeviceID, "")), "USB") > 0 Then
            extDriveRegisteredSummaryCount = extDriveRegisteredSummaryCount + 1
        End If
    Next
    objFile.WriteLine "<div class='grid'>"

    For Each os In colOS
        If CDbl(0 + os.TotalVisibleMemorySize) > 0 Then
            ramGbText = CStr(Int(((CDbl(0 + os.TotalVisibleMemorySize) * 1024) / 1073741824) * 10) / 10) & " GB"
        End If
        osInstallText = WmiDateToString(os.InstallDate)
        If TryParseWmiDateValue(os.InstallDate, tmpDt) Then
            osInstallText = FormatDateTimeHumanized(tmpDt)
        End If
        osUpdateText = GetLatestHotfixInstalledOnText()
        objFile.WriteLine "<div class='card'><div class='kpi'>" & HtmlEncode(Nz(os.Caption, "-")) & "</div><div class='kpi-label'>Sistema Operacional</div></div>"
        objFile.WriteLine "<div class='card'><div class='kpi kpi-text'>" & HtmlEncode(osInstallText) & "</div><div class='kpi-label'>Instalacao do SO</div></div>"
        objFile.WriteLine "<div class='card'><div class='kpi'>" & HtmlEncode(ramGbText) & "</div><div class='kpi-label'>RAM Total (GB)</div></div>"
    Next

    For Each cs In colCS
        hostManufacturerName = Nz(cs.Manufacturer, "-")
        hostModelName = Nz(cs.Model, "-")
        hostCpuLogicalCount = CLng(0 + cs.NumberOfLogicalProcessors)
        hostRamTotalBytes = CDbl(0 + cs.TotalPhysicalMemory)
        objFile.WriteLine "<div class='card'><div class='kpi'>" & HtmlEncode(Nz(cs.Manufacturer, "-")) & "</div><div class='kpi-label'>Fabricante</div></div>"
        objFile.WriteLine "<div class='card'><div class='kpi kpi-text'>" & HtmlEncode(Nz(cs.Model, "-")) & "</div><div class='kpi-label'>Modelo</div></div>"
    Next

    objFile.WriteLine "<div class='card'><div class='kpi kpi-text'>" & HtmlEncode(osUpdateText) & "</div><div class='kpi-label'>Atualizacao do SO</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & procCount & "</div><div class='kpi-label'>Processos ativos</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & svcCount & "</div><div class='kpi-label'>Servicos totais</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi kpi-text'>" & HtmlEncode(Nz(hostLoggedUserSid, "-")) & "</div><div class='kpi-label'>SID usuario logado</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi kpi-text'>" & HtmlEncode(Nz(hostServiceTag, "-")) & "</div><div class='kpi-label'>Service Tag</div></div>"

    objFile.WriteLine "</div>"

    objFile.WriteLine "</section>"
End Sub

Sub WriteSystemSection()
    Dim colOS, os, colMemPerf, memPerf
    Dim hiberEnabled, hiberFilePath

    objFile.WriteLine "<section id='so' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Sistema Operacional e Contexto</h2>"

    Set colOS = objWMI.ExecQuery("SELECT * FROM Win32_OperatingSystem")
    For Each os In colOS
        objFile.WriteLine "<table><tr><th>Campo</th><th>Valor</th></tr>"
        WriteKV "Nome do SO", os.Caption
        WriteKV "Versao", os.Version
        WriteKV "Build", os.BuildNumber
        WriteKV "Arquitetura", os.OSArchitecture
        WriteKV "Serial do SO", os.SerialNumber
        WriteKV "Idioma/Locale", os.Locale
        WriteKV "Diretorio Windows", os.WindowsDirectory
        WriteKV "Diretorio Sistema", os.SystemDirectory
        WriteKV "Ultimo boot", WmiDateToString(os.LastBootUpTime)
        WriteKV "Data instalacao SO", WmiDateToString(os.InstallDate)
        WriteKV "Memoria fisica total", FormatBytes(os.TotalVisibleMemorySize * 1024)
        WriteKV "Memoria fisica livre", FormatBytes(os.FreePhysicalMemory * 1024)
        WriteKV "Memoria virtual total", FormatBytes(os.TotalVirtualMemorySize * 1024)
        WriteKV "Memoria virtual livre", FormatBytes(os.FreeVirtualMemory * 1024)
        WriteKV "Arquivo paginacao livre", FormatBytes(os.FreeSpaceInPagingFiles * 1024)
        WriteKV "Arquivo paginacao total", FormatBytes(os.SizeStoredInPagingFiles * 1024)
        objFile.WriteLine "</table>"
    Next

    Set colMemPerf = objWMI.ExecQuery("SELECT * FROM Win32_PerfFormattedData_PerfOS_Memory")
    For Each memPerf In colMemPerf
        objFile.WriteLine "<table><tr><th colspan='2'>Telemetria de memoria e cache (PerfOS) - indicadores para analise forense</th></tr>"
        WriteKV "Cache em uso (bytes)", FormatBytes(memPerf.CacheBytes)
        WriteKV "Pico de cache (maximo observado)", FormatBytes(memPerf.CacheBytesPeak)
        WriteKV "Memoria comprometida (alocada)", FormatBytes(memPerf.CommittedBytes)
        WriteKV "Limite de memoria comprometida", FormatBytes(memPerf.CommitLimit)
        WriteKV "Pool paginado (kernel)", FormatBytes(memPerf.PoolPagedBytes)
        WriteKV "Pool nao paginado (kernel)", FormatBytes(memPerf.PoolNonpagedBytes)
        WriteKV "Falhas de pagina por segundo", memPerf.PageFaultsPersec
        objFile.WriteLine "</table>"
    Next

    hiberEnabled = ReadDWORDValue("SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled", -1)
    hiberFilePath = "C:\hiberfil.sys"
    objFile.WriteLine "<table><tr><th colspan='2'>Hibernacao (artefato forense)</th></tr>"
    WriteKV "Hibernacao habilitada (registro)", hiberEnabled
    WriteKV "Arquivo hiberfil.sys presente", objFSO.FileExists(hiberFilePath)
    If objFSO.FileExists(hiberFilePath) Then
        WriteKV "Tamanho hiberfil.sys", FormatBytes(objFSO.GetFile(hiberFilePath).Size)
    End If
    objFile.WriteLine "</table>"

    objFile.WriteLine "</section>"
End Sub

Sub WriteHardwareSection()
    Dim colCS, cs, colCPU, cpu, colBIOS, bios, colRAM, ram
    Dim totalRAM, slotCount, colCSP, csp, colBatt, batt, batteryRows

    totalRAM = 0
    slotCount = 0
    hostBatteryCount = 0

    objFile.WriteLine "<section id='hardware' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Hardware (placa-mae, BIOS, CPU, memoria)</h2>"

    Set colCS = objWMI.ExecQuery("SELECT * FROM Win32_ComputerSystem")
    For Each cs In colCS
        hostManufacturerName = Nz(cs.Manufacturer, "-")
        hostModelName = Nz(cs.Model, "-")
        hostCpuLogicalCount = CLng(0 + cs.NumberOfLogicalProcessors)
        hostRamTotalBytes = CDbl(0 + cs.TotalPhysicalMemory)
        objFile.WriteLine "<table><tr><th>Campo</th><th>Valor</th></tr>"
        WriteKV "Fabricante", cs.Manufacturer
        WriteKV "Modelo", cs.Model
        WriteKV "Familia", cs.SystemFamily
        WriteKV "SKU", cs.SystemSKUNumber
        WriteKV "Tipo do sistema", cs.SystemType
        WriteKV "Dominio", cs.Domain
        WriteKV "Funcao no dominio", cs.DomainRole
        WriteKV "Usuario logado", cs.UserName
        WriteKV "Numero processadores fisicos", cs.NumberOfProcessors
        WriteKV "Numero processadores logicos", cs.NumberOfLogicalProcessors
        WriteKV "RAM total reportada", FormatBytes(cs.TotalPhysicalMemory)
        objFile.WriteLine "</table>"
    Next

    Set colCSP = objWMI.ExecQuery("SELECT * FROM Win32_ComputerSystemProduct")
    For Each csp In colCSP
        objFile.WriteLine "<table><tr><th colspan='2'>Produto e Service Tag</th></tr>"
        WriteKV "Nome do Produto", csp.Name
        WriteKV "Versao", csp.Version
        WriteKV "Service Tag / Serial", csp.IdentifyingNumber
        WriteKV "SKU (Produto)", csp.SKUNumber
        objFile.WriteLine "</table>"
    Next

    Set colBIOS = objWMI.ExecQuery("SELECT * FROM Win32_BIOS")
    For Each bios In colBIOS
        objFile.WriteLine "<table><tr><th colspan='2'>BIOS</th></tr>"
        WriteKV "Fabricante", bios.Manufacturer
        WriteKV "Versao SMBIOS", bios.SMBIOSBIOSVersion
        WriteKV "Versao", bios.Version
        WriteKV "Numero de serie", bios.SerialNumber
        WriteKV "Data de release", WmiDateToString(bios.ReleaseDate)
        objFile.WriteLine "</table>"
    Next

    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>CPU</th><th>Detalhes</th></tr>"
    Set colCPU = objWMI.ExecQuery("SELECT * FROM Win32_Processor")
    For Each cpu In colCPU
        objFile.WriteLine "<tr><td>" & HtmlEncode(cpu.DeviceID) & "</td><td class='location-col'>" & HtmlEncode(cpu.Name) & "<br>Fabricante: " & HtmlEncode(cpu.Manufacturer) & "<br>Nucleos: " & Nz(cpu.NumberOfCores, "-") & " | Logicos: " & Nz(cpu.NumberOfLogicalProcessors, "-") & "<br>Clock: " & Nz(cpu.MaxClockSpeed, "-") & " MHz | Arquitetura: " & CpuArch(cpu.Architecture) & "<br>L2: " & FormatBytes(cpu.L2CacheSize * 1024) & " | L3: " & FormatBytes(cpu.L3CacheSize * 1024) & "</td></tr>"
    Next
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Slot</th><th>Capacidade</th><th>Velocidade</th><th>Tipo</th><th>Fabricante</th><th class='location-col'>Part Number</th><th class='location-col'>Serial</th></tr>"
    Set colRAM = objWMI.ExecQuery("SELECT * FROM Win32_PhysicalMemory")
    For Each ram In colRAM
        slotCount = slotCount + 1
        totalRAM = totalRAM + CDbl(0 + ram.Capacity)
        objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(ram.DeviceLocator, "N/A")) & "</td><td>" & FormatBytes(ram.Capacity) & "</td><td>" & Nz(ram.Speed, "-") & " MHz</td><td>" & MemoryTypeName(ram.MemoryType) & "</td><td>" & HtmlEncode(Nz(ram.Manufacturer, "-")) & "</td><td class='location-col'>" & HtmlEncode(Nz(ram.PartNumber, "-")) & "</td><td class='location-col'>" & HtmlEncode(Nz(ram.SerialNumber, "-")) & "</td></tr>"
    Next
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "<div class='grid'>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & slotCount & "</div><div class='kpi-label'>Modulos RAM detectados</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & FormatBytes(totalRAM) & "</div><div class='kpi-label'>Capacidade RAM instalada</div></div>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "<h3>Bateria / mobilidade (indicador de laptop)</h3>"
    objFile.WriteLine "<table><tr><th>Nome</th><th>Status</th><th>Carga estimada</th><th>Quimica</th></tr>"
    batteryRows = 0
    Set colBatt = objWMI.ExecQuery("SELECT * FROM Win32_Battery")
    For Each batt In colBatt
        hostBatteryCount = hostBatteryCount + 1
        batteryRows = batteryRows + 1
        objFile.WriteLine "<tr><td>" & HtmlEncode(SafeWmiProp(batt, "Name", "Bateria")) & "</td><td>" & HtmlEncode(BatteryStatusName(SafeWmiProp(batt, "BatteryStatus", "-"))) & "</td><td>" & HtmlEncode(Nz(SafeWmiProp(batt, "EstimatedChargeRemaining", "-"), "-")) & "%</td><td>" & HtmlEncode(BatteryChemistryName(SafeWmiProp(batt, "Chemistry", "-"))) & "</td></tr>"
    Next
    If batteryRows = 0 Then objFile.WriteLine "<tr><td colspan='4'>Nenhuma bateria detectada via WMI (pode indicar desktop/VM ou driver indisponivel).</td></tr>"
    objFile.WriteLine "</table>"

    If hostBatteryCount > 0 Then
        hostAssetType = "Laptop / portatil (bateria detectada)"
    ElseIf InStr(UCase(hostModelName), "VIRTUAL") > 0 Or InStr(UCase(hostModelName), "VMWARE") > 0 Or InStr(UCase(hostModelName), "VBOX") > 0 Then
        hostAssetType = "VM / virtual"
    Else
        hostAssetType = "Desktop/Workstation (sem bateria detectada)"
    End If

    objFile.WriteLine "</section>"
End Sub

Sub WriteNetworkSection()
    Dim colNIC, nic, colNICCfg, cfg
    networkAdapterCount = 0

    objFile.WriteLine "<section id='rede' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Rede e configuracao TCP/IP</h2>"

    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Adaptador</th><th>MAC</th><th>Status</th><th>Velocidade</th><th>Fabricante</th><th>Modelo/PNP</th></tr>"
    Set colNIC = objWMI.ExecQuery("SELECT * FROM Win32_NetworkAdapter WHERE PhysicalAdapter=True")
    For Each nic In colNIC
        networkAdapterCount = networkAdapterCount + 1
        objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(nic.NetConnectionID, nic.Name)) & "</td><td>" & HtmlEncode(Nz(nic.MACAddress, "-")) & "</td><td>" & HtmlEncode(NetConnectionStatusName(nic.NetConnectionStatus)) & "</td><td>" & HumanSpeed(nic.Speed) & "</td><td>" & HtmlEncode(Nz(nic.Manufacturer, "-")) & "</td><td class='location-col'>" & HtmlEncode(Nz(nic.Name, "-")) & "<br>" & HtmlEncode(Nz(nic.PNPDeviceID, "-")) & "</td></tr>"
    Next
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    Set colNICCfg = objWMI.ExecQuery("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True")
    For Each cfg In colNICCfg
        objFile.WriteLine "<div class='scroll-table'>"
        objFile.WriteLine "<table><tr><th colspan='2'>" & HtmlEncode(cfg.Description) & "</th></tr>"
        WriteKV "DHCP", cfg.DHCPEnabled
        WriteKV "DHCP Server", cfg.DHCPServer
        WriteKV "DNS Suffix", cfg.DNSDomain
        WriteKVHtml "IP", JoinArray(cfg.IPAddress, "<br>")
        WriteKVHtml "Mascara", JoinArray(cfg.IPSubnet, "<br>")
        WriteKVHtml "Gateway", JoinArray(cfg.DefaultIPGateway, "<br>")
        WriteKVHtml "DNS", JoinArray(cfg.DNSServerSearchOrder, "<br>")
        WriteKV "WINS Primario", cfg.WINSPrimaryServer
        WriteKV "WINS Secundario", cfg.WINSSecondaryServer
        objFile.WriteLine "</table>"
        objFile.WriteLine "</div>"
    Next

    objFile.WriteLine "<div class='grid'><div class='card'><div class='kpi'>" & networkAdapterCount & "</div><div class='kpi-label'>Adaptadores fisicos detectados</div></div></div>"
    objFile.WriteLine "</section>"
End Sub

Sub WriteDiskSection()
    Dim colLogical, ld, colPhysical, pd, totalDisks
    Dim trimInfo
    totalDisks = 0
    diskChartLabels = ""
    diskChartUsed = ""
    diskChartFree = ""
    removableCount = 0
    fixedCount = 0

    objFile.WriteLine "<section id='discos' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Volumes, particoes e discos fisicos</h2>"

    objFile.WriteLine "<table><tr><th>Volume</th><th>Tipo</th><th>Sistema de Arquivos</th><th>Tamanho</th><th>Livre</th><th>Uso</th><th>Serial</th></tr>"
    Set colLogical = objWMI.ExecQuery("SELECT * FROM Win32_LogicalDisk")
    For Each ld In colLogical
        Dim totalB, freeB, usedB, usagePct, driveKind, usageBar
        totalB = CDbl(0 + ld.Size)
        freeB = CDbl(0 + ld.FreeSpace)
        usedB = totalB - freeB
        If totalB > 0 Then
            usagePct = Int((usedB / totalB) * 100)
            usageBar = "<div class='bar'><span style='width:" & usagePct & "%'></span></div> " & usagePct & "%"
        Else
            usageBar = "-"
        End If

        driveKind = DriveTypeName(ld.DriveType)
        If ld.DriveType = 2 Then removableCount = removableCount + 1
        If ld.DriveType = 3 Then fixedCount = fixedCount + 1

        If ld.DriveType = 3 And totalB > 0 Then
            AppendChartData Nz(ld.DeviceID, "SemID"), usedB / 1024 / 1024 / 1024, freeB / 1024 / 1024 / 1024
        End If

        objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(ld.DeviceID, "-")) & "</td><td>" & HtmlEncode(driveKind) & "</td><td>" & HtmlEncode(Nz(ld.FileSystem, "-")) & "</td><td>" & FormatBytes(ld.Size) & "</td><td>" & FormatBytes(ld.FreeSpace) & "</td><td>" & usageBar & "</td><td>" & HtmlEncode(Nz(ld.VolumeSerialNumber, "-")) & "</td></tr>"
    Next
    objFile.WriteLine "</table>"

    objFile.WriteLine "<table><tr><th>Disco</th><th>Modelo</th><th>Interface</th><th>Media</th><th>Tipo (HDD/SSD?)</th><th>Tamanho</th><th>Particoes</th><th>Serial/PnP</th></tr>"
    Set colPhysical = objWMI.ExecQuery("SELECT * FROM Win32_DiskDrive")
    For Each pd In colPhysical
        totalDisks = totalDisks + 1
        objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(pd.DeviceID, "-")) & "</td><td>" & HtmlEncode(Nz(pd.Model, "-")) & "</td><td>" & HtmlEncode(Nz(pd.InterfaceType, "-")) & "</td><td>" & HtmlEncode(Nz(pd.MediaType, "-")) & "</td><td>" & HtmlEncode(InferDiskType(pd.Model, pd.MediaType)) & "</td><td>" & FormatBytes(pd.Size) & "</td><td>" & Nz(pd.Partitions, "-") & "</td><td>" & HtmlEncode(Nz(pd.SerialNumber, Nz(pd.PNPDeviceID, "-"))) & "</td></tr>"
    Next
    objFile.WriteLine "</table>"

    objFile.WriteLine "<table><tr><th colspan='2'>Otimizacao de Disco / TRIM</th></tr>"
    trimInfo = GetCommandOutput("cmd /c fsutil behavior query DisableDeleteNotify")
    WriteKVHtml "fsutil DisableDeleteNotify", HtmlPre(trimInfo)
    
    Dim trimStatus, defragInfo
    trimStatus = GetVolumeInfoSummary()
    WriteKVHtml "Informacoes de Volume (WMI/CIM)", HtmlPre(trimStatus)
    
    defragInfo = GetDefragStatusSummary()
    WriteKVHtml "Status Defragmentacao (resumo)", HtmlPre(defragInfo)
    
    Dim storageOptInfo
    storageOptInfo = GetStorageOptimizationSummary()
    WriteKVHtml "Otimizacoes de Armazenamento", HtmlPre(storageOptInfo)
    objFile.WriteLine "</table>"

    Call WritePhysicalDiskMediaTypeSection()

    objFile.WriteLine "<div class='grid'>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & totalDisks & "</div><div class='kpi-label'>Discos fisicos detectados</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & fixedCount & "</div><div class='kpi-label'>Volumes fixos</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & removableCount & "</div><div class='kpi-label'>Volumes removiveis</div></div>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "<canvas id='diskChart' height='110'></canvas>"
    objFile.WriteLine "<script>"
    objFile.WriteLine "const diskLabels=[" & diskChartLabels & "];"
    objFile.WriteLine "const diskUsed=[" & diskChartUsed & "];"
    objFile.WriteLine "const diskFree=[" & diskChartFree & "];"
    objFile.WriteLine "if(diskLabels.length){new Chart(document.getElementById('diskChart'),{type:'bar',data:{labels:diskLabels,datasets:[{label:'Usado (GB)',data:diskUsed,backgroundColor:'#ef4444'},{label:'Livre (GB)',data:diskFree,backgroundColor:'#22c55e'}]},options:{responsive:true,plugins:{legend:{labels:{color:'#e2e8f0'}}},scales:{x:{ticks:{color:'#cbd5e1'}},y:{ticks:{color:'#cbd5e1'}}}}});}"
    objFile.WriteLine "</script>"

    objFile.WriteLine "</section>"
End Sub

Sub WritePhysicalDiskMediaTypeSection()
    Dim objStorage, colPD, p
    On Error Resume Next
    Set objStorage = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & strComputer & "\root\Microsoft\Windows\Storage")
    If Err.Number = 0 Then
        Set colPD = objStorage.ExecQuery("SELECT * FROM MSFT_PhysicalDisk")
        If Err.Number = 0 Then
            objFile.WriteLine "<table><tr><th>FriendlyName</th><th>BusType</th><th>MediaType</th><th>HealthStatus</th><th>Size</th><th>Serial</th></tr>"
            For Each p In colPD
                objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(p.FriendlyName, "-")) & "</td><td>" & HtmlEncode(BusTypeName(p.BusType)) & "</td><td>" & HtmlEncode(MediaTypeName(p.MediaType)) & "</td><td>" & HtmlEncode(Nz(p.HealthStatus, "-")) & "</td><td>" & FormatBytes(p.Size) & "</td><td>" & HtmlEncode(Nz(p.SerialNumber, "-")) & "</td></tr>"
            Next
            objFile.WriteLine "</table>"
        End If
    End If
    Err.Clear
End Sub

Sub WriteUSBSection()
    Dim colPnP, dev, countUSB, vid, pid, pserial, usbRows
    countUSB = 0
    usbRows = ""
    objFile.WriteLine "<section id='usb' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Dispositivos externos e PnP relevantes</h2>"

    Set colPnP = objWMI.ExecQuery("SELECT * FROM Win32_PnPEntity WHERE PNPDeviceID LIKE 'USB%' OR Name LIKE '%USB%' OR Name LIKE '%Mass Storage%' OR Name LIKE '%Storage%'")
    For Each dev In colPnP
        countUSB = countUSB + 1
        vid = ParseBetween(UCase(Nz(dev.PNPDeviceID, "")), "VID_", "&")
        pid = ParseBetween(UCase(Nz(dev.PNPDeviceID, "")), "PID_", "&")
        pserial = ParsePnPSerial(Nz(dev.PNPDeviceID, ""))
        usbRows = usbRows & "<tr><td>" & HtmlEncode(Nz(dev.Name, "-")) & "</td><td>" & HtmlEncode(Nz(dev.PNPClass, "-")) & "</td><td>" & HtmlEncode(Nz(dev.Manufacturer, "-")) & "</td><td>" & HtmlEncode(Nz(dev.Status, "-")) & "</td><td>" & HtmlEncode(Nz(dev.Description, "-")) & "</td><td>" & HtmlEncode("VID=" & Nz(vid, "-") & " PID=" & Nz(pid, "-")) & "</td><td>" & HtmlEncode(pserial) & "</td><td class='location-col'>" & HtmlEncode(Nz(dev.PNPDeviceID, "-")) & "</td></tr>"
    Next

    objFile.WriteLine "<div class='grid'><div class='card'><div class='kpi'>" & countUSB & "</div><div class='kpi-label'>Dispositivos USB/PnP listados</div></div></div>"
    objFile.WriteLine "<h3>Listagem geral de dispositivos USB/PnP</h3>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Nome</th><th>Classe</th><th>Fabricante</th><th>Status</th><th>Modelo</th><th>VID/PID</th><th>Serial parseado</th><th class='location-col'>PNPDeviceID</th></tr>"
    If Trim(usbRows) = "" Then
        objFile.WriteLine "<tr><td colspan='8'>Nenhum dispositivo USB/PnP relevante listado.</td></tr>"
    Else
        objFile.WriteLine usbRows
    End If
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"
    
    objFile.WriteLine "<h3>Drives Externos Especificos (USB Stick, External HDD/SDD, Storage)</h3>"
    Call WriteExternalDrivesDetailed()
    
    objFile.WriteLine "</section>"
End Sub

Sub WriteExternalDrivesDetailed()
    Dim colDrives, drive, iRemovable, driveType, lastConnection
    Dim vid, pid, serialNum, manufacturer, model
    externalDriveRegisteredCount = 0
    
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Unidade</th><th>Tipo</th><th>Fabricante</th><th>Modelo</th><th>Marca (VID)</th><th>PID</th><th>Serial/Service Tag</th><th>Ultima conexao</th><th class='location-col'>PNPDeviceID</th></tr>"
    
    Set colDrives = objWMI.ExecQuery("SELECT * FROM Win32_PnPEntity WHERE PNPClass='DiskDrive' OR PNPClass='USB' OR (PNPDeviceID LIKE 'USBSTOR%' OR PNPDeviceID LIKE 'USB\\\\%')")
    
    For Each drive In colDrives
        vid = ParseBetween(UCase(Nz(drive.PNPDeviceID, "")), "VID_", "&")
        pid = ParseBetween(UCase(Nz(drive.PNPDeviceID, "")), "PID_", "&")
        serialNum = ParsePnPSerial(Nz(drive.PNPDeviceID, ""))
        manufacturer = Nz(drive.Manufacturer, "-")
        model = Nz(drive.Description, "") & " " & Nz(drive.Name, "")
        driveType = InferExternalDriveType(Nz(drive.Name, "") & " " & Nz(drive.Description, ""))
        lastConnection = "-"
        
        If InStr(Nz(drive.PNPDeviceID, ""), "USB") > 0 Then
            externalDriveRegisteredCount = externalDriveRegisteredCount + 1
            objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(drive.Name, "-")) & "</td><td>" & HtmlEncode(driveType) & "</td><td>" & HtmlEncode(manufacturer) & "</td><td>" & HtmlEncode(model) & "</td><td>" & HtmlEncode(Nz(vid, "-")) & "</td><td>" & HtmlEncode(Nz(pid, "-")) & "</td><td>" & HtmlEncode(serialNum) & "</td><td>" & lastConnection & "</td><td class='location-col'>" & HtmlEncode(Nz(drive.PNPDeviceID, "-")) & "</td></tr>"
        End If
    Next
    
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"
    
    Dim usbStorageInfo
    usbStorageInfo = GetCommandOutput("cmd /c Get-WmiObject -Class Win32_LogicalDisk -Filter ""DriveType=2"" 2>nul | Select-Object DeviceID, VolumeName, Size, FreeSpace 2>nul | Out-String 2>nul || echo N/A")
    objFile.WriteLine "<table><tr><th colspan='2'>Informacoes de Drives Removiveis (tipo=2)</th></tr>"
    WriteKV "Detalhes", usbStorageInfo
    objFile.WriteLine "</table>"
End Sub

Function InferExternalDriveType(description)
    Dim desc
    desc = UCase(Nz(description, ""))
    If InStr(desc, "STICK") > 0 Or InStr(desc, "USB STICK") > 0 Then
        InferExternalDriveType = "USB Stick"
    ElseIf InStr(desc, "EXTERNAL") > 0 Or InStr(desc, "EXT") > 0 Then
        If InStr(desc, "SSD") > 0 Then
            InferExternalDriveType = "External SSD"
        Else
            InferExternalDriveType = "External HDD"
        End If
    ElseIf InStr(desc, "STORAGE") > 0 Or InStr(desc, "DISK") > 0 Or InStr(desc, "DRIVE") > 0 Then
        InferExternalDriveType = "Storage/Disk"
    Else
        InferExternalDriveType = "USB Device/Unknown"
    End If
End Function

Sub WriteFolderTelemetrySection()
    Dim userProfile, desktopPath, downloadsPath, documentsPath
    Dim dFiles, dDirs, dBytes, dwFiles, dwDirs, dwBytes, docFiles, docDirs, docBytes

    folderChartLabels = ""
    folderChartFiles = ""

    userProfile = objShell.ExpandEnvironmentStrings("%USERPROFILE%")
    desktopPath = userProfile & "\Desktop"
    downloadsPath = userProfile & "\Downloads"
    documentsPath = userProfile & "\Documents"

    CountFolderStats desktopPath, dFiles, dDirs, dBytes
    CountFolderStats downloadsPath, dwFiles, dwDirs, dwBytes
    CountFolderStats documentsPath, docFiles, docDirs, docBytes

    objFile.WriteLine "<section id='pastas' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Telemetria de Pastas do Usuario</h2>"
    
    objFile.WriteLine "<h3>Pastas de Usuario (Desktop/Downloads/Documents)</h3>"
    objFile.WriteLine "<table><tr><th>Pasta</th><th>Caminho</th><th>Total de Arquivos</th><th>Total de Subpastas</th><th>Tamanho estimado</th></tr>"
    objFile.WriteLine "<tr><td>Desktop</td><td>" & HtmlEncode(desktopPath) & "</td><td>" & dFiles & "</td><td>" & dDirs & "</td><td>" & FormatBytes(dBytes) & "</td></tr>"
    objFile.WriteLine "<tr><td>Downloads</td><td>" & HtmlEncode(downloadsPath) & "</td><td>" & dwFiles & "</td><td>" & dwDirs & "</td><td>" & FormatBytes(dwBytes) & "</td></tr>"
    objFile.WriteLine "<tr><td>Documents</td><td>" & HtmlEncode(documentsPath) & "</td><td>" & docFiles & "</td><td>" & docDirs & "</td><td>" & FormatBytes(docBytes) & "</td></tr>"
    objFile.WriteLine "</table>"

    AppendFolderChartData "Desktop", dFiles
    AppendFolderChartData "Downloads", dwFiles
    AppendFolderChartData "Documents", docFiles

    objFile.WriteLine "<canvas id='folderChart' height='90'></canvas>"
    objFile.WriteLine "<script>"
    objFile.WriteLine "const folderLabels=[" & folderChartLabels & "];"
    objFile.WriteLine "const folderFiles=[" & folderChartFiles & "];"
    objFile.WriteLine "if(folderLabels.length){new Chart(document.getElementById('folderChart'),{type:'doughnut',data:{labels:folderLabels,datasets:[{label:'Arquivos',data:folderFiles,backgroundColor:['#38bdf8','#22c55e','#f59e0b']}]},options:{plugins:{legend:{labels:{color:'#e2e8f0'}}}}});}"
    objFile.WriteLine "</script>"
    
    objFile.WriteLine "<h3>Artefatos Forenses (volumetria de pastas criticas)</h3>"
    Call WritePastasTelemetriaForense()

    objFile.WriteLine "<h3>Atalhos recentes do usuario atual (pasta Recent, sem limite de itens)</h3>"
    Call WriteCurrentUserRecentShortcuts(0)

    objFile.WriteLine "</section>"
End Sub

Sub WritePastasTelemetriaForense()
    Dim folderPaths, folder, fileCount, dirCount, bytesTotal, folderPath
    Dim systemRoot, userProfile
    Dim i, path, files, dirs, bytes
    
    systemRoot = objShell.ExpandEnvironmentStrings("%SystemRoot%")
    userProfile = objShell.ExpandEnvironmentStrings("%USERPROFILE%")
    
    ReDim folderPaths(19)
    i = 0
    
    folderPaths(i) = "C:\$Recycle.Bin\": i = i + 1
    folderPaths(i) = systemRoot & "\Prefetch\": i = i + 1
    folderPaths(i) = systemRoot & "\System32\winevt\Logs\": i = i + 1
    folderPaths(i) = userProfile & "\AppData\Roaming\Microsoft\Windows\Recent\": i = i + 1
    folderPaths(i) = userProfile & "\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\": i = i + 1
    folderPaths(i) = userProfile & "\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\": i = i + 1
    folderPaths(i) = userProfile & "\AppData\Local\Google\Chrome\User Data\Default\": i = i + 1
    folderPaths(i) = userProfile & "\AppData\Local\Microsoft\Edge\User Data\Default\": i = i + 1
    folderPaths(i) = userProfile & "\AppData\Roaming\Mozilla\Firefox\Profiles\": i = i + 1
    folderPaths(i) = systemRoot & "\Temp\": i = i + 1
    folderPaths(i) = userProfile & "\AppData\Local\Temp\": i = i + 1
    folderPaths(i) = systemRoot & "\AppCompat\Programs\": i = i + 1
    folderPaths(i) = systemRoot & "\System32\Config\": i = i + 1
    folderPaths(i) = systemRoot & "\System32\sru\": i = i + 1
    folderPaths(i) = systemRoot & "\System32\Tasks\": i = i + 1
    folderPaths(i) = userProfile & "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\": i = i + 1
    folderPaths(i) = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\": i = i + 1
    folderPaths(i) = "C:\ProgramData\Microsoft\Windows Defender\Support\": i = i + 1
    folderPaths(i) = systemRoot & "\Logs\": i = i + 1
    
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Caminho da Pasta</th><th>Categoria Forense</th><th>Arquivos</th><th>Subpastas</th><th>Tamanho Total</th></tr>"
    
    Dim j
    For j = 0 To UBound(folderPaths)
        If folderPaths(j) <> "" Then
            path = folderPaths(j)
            
            CountFolderStats path, fileCount, dirCount, bytesTotal
            Dim category
            category = GetForensicCategory(path)
            objFile.WriteLine "<tr><td>" & HtmlEncode(path) & "</td><td>" & HtmlEncode(category) & "</td><td>" & fileCount & "</td><td>" & dirCount & "</td><td>" & FormatBytes(bytesTotal) & "</td></tr>"
        End If
    Next
    
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"
End Sub

Sub WriteProgramDataFoldersSize(programDataPath)
    Dim category, psCmd, output, lines, line
    Dim folderName, folderSize
    
    category = GetForensicCategory(programDataPath)
    
    psCmd = "powershell -NoProfile -Command ""Get-ChildItem -Path 'C:\ProgramData\' -Directory -ErrorAction SilentlyContinue | ForEach-Object { $size = (Get-ChildItem -Path $_.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum; Write-Host $_.Name '|' [math]::Round($size/1MB,2) 'MB' } | Sort-Object -Descending"" 2>nul"
    
    output = GetCommandOutput(psCmd)
    
    If InStr(output, "[TIMEOUT") > 0 Then
        objFile.WriteLine "<tr><td>" & HtmlEncode(programDataPath) & "</td><td>" & HtmlEncode(category) & "</td><td colspan='3'><span class='warn'>Timeout - pasta muito grande para analise completa</span></td></tr>"
    Else
        If Trim(output) = "" Or Trim(output) = "N/A" Then
            objFile.WriteLine "<tr><td>" & HtmlEncode(programDataPath) & "</td><td>" & HtmlEncode(category) & "</td><td colspan='3'>Sem acesso ou pasta vazia</td></tr>"
        Else
            lines = Split(output, vbCrLf)
            If UBound(lines) < 5 Then
                objFile.WriteLine "<tr><td>" & HtmlEncode(programDataPath) & "</td><td>" & HtmlEncode(category) & "</td><td colspan='3'><pre style='font-size:0.85em;white-space:pre-wrap'>" & HtmlEncode(output) & "</pre></td></tr>"
            Else
                objFile.WriteLine "<tr><td>" & HtmlEncode(programDataPath) & "</td><td>" & HtmlEncode(category) & "</td><td colspan='3'><pre style='font-size:0.85em;white-space:pre-wrap;max-height:300px;overflow-y:auto'>" & HtmlEncode(Left(output, 2000)) & "...</pre></td></tr>"
            End If
        End If
    End If
End Sub

Function GetForensicCategory(folderPath)
    Dim path
    path = UCase(folderPath)
    
    If InStr(path, "$RECYCLE.BIN") > 0 Then
        GetForensicCategory = "Lixeira"
    ElseIf InStr(path, "PREFETCH") > 0 Then
        GetForensicCategory = "Execucao de Programas"
    ElseIf InStr(path, "WINEVT\LOGS") > 0 Then
        GetForensicCategory = "Logs de Eventos"
    ElseIf InStr(path, "RECENT") > 0 Or InStr(path, "AUTOMATICDE") > 0 Or InStr(path, "CUSTOMDE") > 0 Then
        GetForensicCategory = "Acesso a Arquivos Recentes"
    ElseIf InStr(path, "CHROME") > 0 Then
        GetForensicCategory = "Navegacao Web (Chrome)"
    ElseIf InStr(path, "EDGE") > 0 Then
        GetForensicCategory = "Navegacao Web (Edge)"
    ElseIf InStr(path, "FIREFOX") > 0 Then
        GetForensicCategory = "Navegacao Web (Firefox)"
    ElseIf InStr(path, "TEMP") > 0 Then
        GetForensicCategory = "Arquivos Temporarios"
    ElseIf InStr(path, "APPCOMPAT") > 0 Then
        GetForensicCategory = "Compatibilidade de Aplicativos"
    ElseIf InStr(path, "CONFIG") > 0 Then
        GetForensicCategory = "Configuracoes do Sistema (Registry hives)"
    ElseIf InStr(path, "\SRU\") > 0 Then
        GetForensicCategory = "System Resource Usage (performance)"
    ElseIf InStr(path, "TASKS") > 0 Then
        GetForensicCategory = "Tarefas Agendadas"
    ElseIf InStr(path, "STARTUP") > 0 Then
        GetForensicCategory = "Inicializacao Automatica"
    ElseIf InStr(path, "WINDOWS DEFENDER") > 0 Then
        GetForensicCategory = "Antivirus/Defender"
    ElseIf InStr(path, "\LOGS\") > 0 Then
        GetForensicCategory = "Logs do Sistema"
    ElseIf InStr(path, "PROGRAMDATA") > 0 Then
        GetForensicCategory = "Dados de Aplicativos"
    Else
        GetForensicCategory = "Diversos"
    End If
End Function

Sub WriteCISSection()
    Dim rdpDeny, enableLua, consentPrompt, smb1, firewallDomain, firewallPrivate, firewallPublic
    Dim bitlocker, defenderSvc

    objFile.WriteLine "<section id='cis' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Controles Criticos (referencia CIS) para triagem de incidente</h2>"
    objFile.WriteLine "<table><tr><th>Controle</th><th>Valor coletado</th><th>Observacao Forense</th></tr>"

    rdpDeny = ReadDWORDValue("SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", -1)
    enableLua = ReadDWORDValue("SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", -1)
    consentPrompt = ReadDWORDValue("SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", -1)
    smb1 = ReadDWORDValue("SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", -1)
    firewallDomain = ReadDWORDValue("SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", -1)
    firewallPrivate = ReadDWORDValue("SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall", -1)
    firewallPublic = ReadDWORDValue("SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", -1)
    bitlocker = GetCommandOutput("cmd /c manage-bde -status")
    defenderSvc = GetServiceState("WinDefend")

    objFile.WriteLine "<tr><td>Acesso remoto (RDP) habilitado/bloqueado</td><td>" & rdpDeny & "</td><td>Valor de <code>fDenyTSConnections</code>: 0=RDP permitido; 1=RDP bloqueado.</td></tr>"
    objFile.WriteLine "<tr><td>Controle de Conta de Usuario (UAC) ativo</td><td>" & enableLua & "</td><td><code>EnableLUA</code>: 1 indica UAC habilitado (recomendado).</td></tr>"
    objFile.WriteLine "<tr><td>UAC: nivel de prompt para administrador</td><td>" & consentPrompt & "</td><td><code>ConsentPromptBehaviorAdmin</code>: define o comportamento da elevacao administrativa.</td></tr>"
    objFile.WriteLine "<tr><td>SMBv1 (servidor) habilitado/desabilitado</td><td>" & smb1 & "</td><td><code>SMB1</code>: 0/desabilitado e a configuracao recomendada.</td></tr>"
    objFile.WriteLine "<tr><td>Firewall do Windows (perfil Dominio)</td><td>" & firewallDomain & "</td><td><code>EnableFirewall</code>: 1=habilitado.</td></tr>"
    objFile.WriteLine "<tr><td>Firewall do Windows (perfil Privado)</td><td>" & firewallPrivate & "</td><td><code>EnableFirewall</code> em <code>StandardProfile</code>: 1=habilitado.</td></tr>"
    objFile.WriteLine "<tr><td>Firewall do Windows (perfil Publico)</td><td>" & firewallPublic & "</td><td><code>EnableFirewall</code> em <code>PublicProfile</code>: 1=habilitado.</td></tr>"
    objFile.WriteLine "<tr><td>Antivirus Microsoft Defender (servico WinDefend)</td><td>" & HtmlEncode(defenderSvc) & "</td><td>Confirme se o servico esta em execucao e o modo de inicializacao.</td></tr>"
    objFile.WriteLine "<tr><td>Criptografia de disco (BitLocker - manage-bde)</td><td colspan='2'><pre style='white-space:pre-wrap;color:#cbd5e1'>" & HtmlEncode(bitlocker) & "</pre></td></tr>"

    objFile.WriteLine "</table>"

    objFile.WriteLine "<h3>Politicas locais e GPO (highlight em edicoes locais)</h3>"
    objFile.WriteLine "<table><tr><th>Coleta</th><th>Saida</th></tr>"
    objFile.WriteLine "<tr><td>Resumo de GPO aplicada (gpresult /r)</td><td><pre>" & HtmlEncode(GetCommandOutputWithTimeout("cmd /c gpresult /r", 45)) & "</pre></td></tr>"
    objFile.WriteLine "<tr><td>Politica de seguranca local (secedit /export, resumo rapido)</td><td><pre><span class='warn'>Exporta apenas politicas e direitos de usuario, com timeout e filtro de linhas para reduzir demora.</span><br>" & HtmlEncode(GetSeceditSummary()) & "</pre></td></tr>"
    objFile.WriteLine "</table>"

    objFile.WriteLine "<h3>Membros locais do grupo Administrators</h3>"
    objFile.WriteLine "<table><tr><th>Conta</th><th>Fonte</th></tr>"
    ListLocalAdministrators
    objFile.WriteLine "</table>"

    objFile.WriteLine "</section>"
End Sub

Sub WriteSecuritySection()
    Dim colProc, proc, topCount
    Dim evtCount, eventExportRows

    processCount = 0
    errorEventCount = 0
    evtCount = 0
    eventExportRows = ""
    strSecurityEventExportStatusRows = ""
    securityEventExportCount = 0

    objFile.WriteLine "<section id='seguranca' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Processos e eventos criticos</h2>"

    objFile.WriteLine "<h3>Top processos por memoria (Working Set)</h3>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Processo</th><th>PID</th><th class='location-col'>Caminho</th><th>Memoria</th><th>Data criacao</th><th class='location-col'>Linha de comando</th></tr>"
    Set colProc = objWMI.ExecQuery("SELECT * FROM Win32_Process")
    topCount = 0
    For Each proc In colProc
        processCount = processCount + 1
        If topCount < 120 Then
            objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(proc.Name, "-")) & "</td><td>" & Nz(proc.ProcessId, "-") & "</td><td class='location-col'>" & HtmlEncode(Nz(proc.ExecutablePath, "-")) & "</td><td>" & FormatBytes(proc.WorkingSetSize) & "</td><td>" & HtmlEncode(WmiDateToString(proc.CreationDate)) & "</td><td class='location-col'>" & HtmlEncode(Nz(proc.CommandLine, "-")) & "</td></tr>"
            topCount = topCount + 1
        End If
    Next
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    AppendSecurityRecentEventExportRow eventExportRows, "Application", "Application", "*[System[(Level=2 or Level=3)]]", 80, 12, evtCount, errorEventCount
    AppendSecurityRecentEventExportRow eventExportRows, "System", "System", "*[System[(Level=2 or Level=3)]]", 80, 12, evtCount, errorEventCount
    AppendSecurityRecentEventExportRow eventExportRows, "Setup (Software/Instalacao)", "Setup", "*[System[(Level=2 or Level=3)]]", 60, 10, evtCount, errorEventCount
    AppendSecurityRecentEventExportRow eventExportRows, "Security (ultimos eventos)", "Security", "", 80, 12, evtCount, errorEventCount
    If Trim(eventExportRows) = "" Then eventExportRows = "<tr><td colspan='6'>Nenhuma exportacao de eventos realizada.</td></tr>"
    strSecurityEventExportStatusRows = eventExportRows

    objFile.WriteLine "<h3>Eventos recentes (exportados via wevtutil; removidos do HTML para reduzir carga)</h3>"
    objFile.WriteLine "<div class='mini-note'>Os eventos foram exportados para arquivos na pasta de resultados da execucao. O HTML exibe apenas status, volume e local do artefato.</div>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Canal</th><th>Status</th><th>Amostra</th><th>Formato</th><th>Arquivo</th><th>Observacao</th></tr>" & eventExportRows & "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "<div class='grid'>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & processCount & "</div><div class='kpi-label'>Processos em execucao</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & evtCount & "</div><div class='kpi-label'>Canais de eventos exportados</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & errorEventCount & "</div><div class='kpi-label'>Falhas/avisos em exportacao de canais</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & securityEventExportCount & "</div><div class='kpi-label'>Arquivos de eventos gerados</div></div>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "</section>"
End Sub

Sub AppendSecurityRecentEventExportRow(eventRows, displayLabel, channelName, xPathQuery, maxCount, timeoutSecs, totalEvents, failCount)
    Dim cmdExport, cmdMeta, cmdOut, filePath, fileHref, statusTag, noteText, fmtLabel
    Dim qPart, exportName, outBytes, sampleInfo

    qPart = ""
    If Trim(CStr(xPathQuery & "")) <> "" Then qPart = " /q:""" & xPathQuery & """"
    fmtLabel = "TEXT"
    noteText = "Canal=" & channelName & " | c=" & CLng(0 + maxCount)
    If Trim(CStr(xPathQuery & "")) <> "" Then noteText = noteText & " | filtro nivel erro/aviso"

    exportName = "recent_" & displayLabel & "_" & strRunId
    filePath = GetRunExportSubDir("eventos_recentes") & "\" & SanitizeFileNameComponent(exportName) & ".txt"
    cmdExport = "cmd /c wevtutil qe """ & channelName & """ /rd:true /c:" & CLng(0 + maxCount) & " /f:text" & qPart & " > """ & filePath & """ 2>&1"
    cmdOut = GetCommandOutputWithTimeout(cmdExport, timeoutSecs)
    fileHref = HtmlEncode(filePath)
    outBytes = GetFileSizeBytesSafe(filePath)
    sampleInfo = IIfBool(outBytes > 0, "arquivo gerado", "sem retorno")

    If Trim(filePath) <> "" And outBytes > 0 And InStr(1, cmdOut, "TIMEOUT", vbTextCompare) = 0 Then
        totalEvents = CLng(0 + totalEvents) + 1
        statusTag = "<span class='tag ok'>OK</span>"
        securityEventExportCount = CLng(0 + securityEventExportCount) + 1
        eventRows = eventRows & "<tr><td>" & HtmlEncode(displayLabel) & "</td><td>" & statusTag & "</td><td>" & HtmlEncode(sampleInfo) & "</td><td>" & fmtLabel & "</td><td class='location-col'><a href='" & fileHref & "' style='color:#7dd3fc'>" & HtmlEncode(filePath) & "</a><br><span class='muted'>" & HtmlEncode(FormatBytes(outBytes)) & "</span></td><td class='location-col'>" & HtmlEncode(noteText) & "</td></tr>"
        LogCustody "EVENT_EXPORT", "OK", displayLabel & " | arquivo=" & filePath
    Else
        failCount = CLng(0 + failCount) + 1
        If Trim(filePath) <> "" And outBytes > 0 Then
            securityEventExportCount = CLng(0 + securityEventExportCount) + 1
        End If
        eventRows = eventRows & "<tr><td>" & HtmlEncode(displayLabel) & "</td><td><span class='tag warn'>WARN</span></td><td>" & HtmlEncode(sampleInfo) & "</td><td>" & fmtLabel & "</td><td class='location-col'>" & IIfBool(Trim(filePath)<>"", "<a href='" & HtmlEncode(filePath) & "' style='color:#7dd3fc'>" & HtmlEncode(filePath) & "</a>", "-") & "</td><td class='location-col'>" & HtmlEncode(noteText & " | timeout, sem permissao, canal indisponivel ou retorno vazio") & "</td></tr>"
        LogCustody "EVENT_EXPORT", "WARN", displayLabel & " | timeout/sem retorno"
    End If
End Sub


Sub WriteThreatHuntSection()
    Dim registryRows, registrySnapshotRows
    Dim huntCmdRows, huntCmdOkCount, huntCmdFailCount, huntCmdSkipCount

    threatEventTotalHits = 0
    threatEventAlertCount = 0
    threatEventWarnCount = 0
    threatEventInfoCount = 0
    threatHighPriorityHits = 0
    threatSecurityHits = 0
    threatPowerShellHits = 0
    threatSysmonHits = 0
    threatBitsHits = 0
    threatSystemHits = 0
    threatRedHits = 0
    threatYellowHits = 0
    threatEventExportCount = 0
    strThreatEventExportStatusRows = ""
    strThreatRegistrySnapshotStatusRows = ""

    threatRegistryChecks = 0
    threatRegistryAlertCount = 0
    threatRegistryWarnCount = 0
    threatRegistryInfoCount = 0
    threatRegistryPersistHits = 0
    threatRegistryAccessHits = 0
    threatRegistryTelemetryHits = 0
    threatRegistryCredHits = 0
    threatRegistryNetworkHits = 0
    threatRegistrySnapshotExportCount = 0
    huntCmdRows = ""
    huntCmdOkCount = 0
    huntCmdFailCount = 0
    huntCmdSkipCount = 0

    CollectThreatRegistryChecks registryRows, registrySnapshotRows
    CollectThreatHuntCommandSnapshots huntCmdRows, huntCmdOkCount, huntCmdFailCount, huntCmdSkipCount
    If Trim(registryRows) = "" Then registryRows = "<tr><td colspan='7'>Nenhuma checagem de registro retornou dados.</td></tr>"
    If Trim(registrySnapshotRows) = "" Then registrySnapshotRows = "<tr><td colspan='6'>Nenhum snapshot de registro exportado.</td></tr>"
    If Trim(huntCmdRows) = "" Then huntCmdRows = "<tr><td colspan='8'>Nenhum comando de triagem executado.</td></tr>"
    strThreatRegistrySnapshotStatusRows = registrySnapshotRows

    objFile.WriteLine "<section id='ameacas' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Checagens reais de registro (persistencia, auditoria, acesso e telemetria)</h2>"
    objFile.WriteLine "<div class='mini-note'>Bloco simplificado para triagem: mantidas apenas checagens reais de registro e snapshots exportados (sem eventos priorizados/correlacao).</div>"

    objFile.WriteLine "<div class='grid'>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & threatRegistryChecks & "</div><div class='kpi-label'>Checagens de registro executadas</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'><span class='tag bad'>" & threatRegistryAlertCount & "</span> / <span class='tag warn'>" & threatRegistryWarnCount & "</span></div><div class='kpi-label'>Achados (alerta/warn)</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & threatRegistrySnapshotExportCount & "</div><div class='kpi-label'>Snapshots de registro exportados</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & huntCmdOkCount & " / " & (CLng(0 + huntCmdOkCount) + CLng(0 + huntCmdFailCount) + CLng(0 + huntCmdSkipCount)) & "</div><div class='kpi-label'>Comandos TH (sucesso/total)</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi kpi-text'>" & HtmlEncode(hostAssetType) & "</div><div class='kpi-label'>Tipo do host</div></div>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "<h3>Comandos de triagem / discovery (saidas em <code>Resultados\\*.result</code>)</h3>"
    objFile.WriteLine "<div class='mini-note'>Comandos de consulta com perfil de discovery (podem gerar telemetria/alerta em EDR). O custody log registra somente os comandos desta lista que finalizam com sucesso.</div>"
    objFile.WriteLine "<div class='scroll-table'><table><tr><th>Ferramenta</th><th>Categoria</th><th>Status</th><th>ExitCode</th><th>Timeout(s)</th><th>Arquivo .result</th><th class='location-col'>Comando</th><th class='location-col'>Observacao</th></tr>" & huntCmdRows & "</table></div>"

    objFile.WriteLine "<h3>Snapshots de chaves criticas (reg query) exportados</h3>"
    objFile.WriteLine "<div class='scroll-table snap-no-wrap'><table><tr><th>Grupo</th><th>Consulta</th><th>Status</th><th>Arquivo</th><th>Tamanho</th><th>Observacao</th></tr>" & registrySnapshotRows & "</table></div>"

    objFile.WriteLine "<h3>Checagens reais de registro (persistencia, auditoria, acesso e telemetria)</h3>"
    objFile.WriteLine "<div class='scroll-table'><table><tr><th>Grupo</th><th>Root</th><th>Chave</th><th>Valor</th><th>Conteudo</th><th>Severidade</th><th class='location-col'>Observacao</th></tr>" & registryRows & "</table></div>"

    If threatRegistryAlertCount > 0 Then
        LogCustody "THREAT_HUNT", "WARN", "Registro alert=" & threatRegistryAlertCount & " warn=" & threatRegistryWarnCount & " | checks=" & threatRegistryChecks
    Else
        LogCustody "THREAT_HUNT", "OK", "Registro checks=" & threatRegistryChecks & " | snapshots=" & threatRegistrySnapshotExportCount
    End If

    objFile.WriteLine "</section>"
End Sub
Sub WriteHtmlChunked(outFile, htmlText)
    Dim s, pos, chunkSize
    s = CStr(Nz(htmlText, ""))
    If s = "" Then Exit Sub
    chunkSize = 6000
    pos = 1
    Do While pos <= Len(s)
        outFile.Write Mid(s, pos, chunkSize)
        pos = pos + chunkSize
    Loop
End Sub

Function LimitThreatSampleRowsHtml(rowsHtml, maxLen)
    Dim n, s
    n = CLng(0 + maxLen)
    If n <= 0 Then n = 28000
    s = CStr(Nz(rowsHtml, ""))
    If Len(s) <= n Then
        LimitThreatSampleRowsHtml = s
    Else
        LimitThreatSampleRowsHtml = Left(s, n) & "<tr><td colspan='3'><span class='warn'>Amostras truncadas para reduzir erro de escrita/renderizacao e acelerar o HTML.</span></td></tr>"
    End If
End Function

Sub WriteThreatBarRowHtml(labelText, valueNum, maxNum, cssKind)
    Dim w, colorStyle
    w = PercentWidthPct(valueNum, maxNum)
    colorStyle = "background:linear-gradient(90deg,#86efac,#22c55e)"
    Select Case LCase(Nz(cssKind, ""))
        Case "bad": colorStyle = "background:linear-gradient(90deg,#fda4af,#ef4444)"
        Case "warn": colorStyle = "background:linear-gradient(90deg,#fde68a,#f59e0b)"
        Case Else: colorStyle = "background:linear-gradient(90deg,#67e8f9,#3b82f6)"
    End Select
    objFile.WriteLine "<tr><td>" & HtmlEncode(labelText) & "</td><td>" & CLng(0 + valueNum) & "</td><td><div class='bar'><span style='width:" & w & "%;" & colorStyle & "'></span></div></td></tr>"
End Sub
Sub CollectThreatEventsOptimized(countsDict, channelRows, sampleRows)
    channelRows = ""
    sampleRows = ""

    ' RED flags primeiro (janela maior para evidencias criticas, baixo volume)
    CollectThreatEventQueryFiltered "Security", "RED | Credencial/Execucao/Auditoria", "1102,4719,4697,4698,4688,4663,4625,4672,4769,4740", 180, 14, 48, 3, 1600, "red", countsDict, channelRows, sampleRows
    CollectThreatEventQueryFiltered "System", "RED | Servicos/VSS/Impacto (janela reduzida)", "25,104,7040,7045,8193,8222", 24, 6, 24, 0, 0, "red", countsDict, channelRows, sampleRows
    CollectThreatEventQueryFiltered "Microsoft-Windows-PowerShell/Operational", "RED | PowerShell operacional", "4103,4104,4105,4106", 60, 8, 24, 3, 1800, "red", countsDict, channelRows, sampleRows
    CollectThreatEventQueryFiltered "Microsoft-Windows-Sysmon/Operational", "RED | Sysmon core", "1,3,8,10,11,13", 120, 10, 96, 3, 1800, "red", countsDict, channelRows, sampleRows

    ' YELLOW flags (ruido controlado, janela menor e amostra textual opcional)
    CollectThreatEventQueryFiltered "Security", "YELLOW | Auth/RDP/Rede/SMB", "4624,4634,4647,4648,4771,4776,4778,4779,5140,5142,5144,5145,5156,5157,5158", 120, 10, 24, 0, 0, "yellow", countsDict, channelRows, sampleRows
    CollectThreatEventQueryFiltered "Security", "YELLOW | Contas/FS/Complementar", "4689,4702,4720,4722,4723,4724,4725,4726,4728,4732,4738,4756,4767,4768,5038,1100,4656,4659,4660,4670,4907", 100, 10, 48, 0, 0, "yellow", countsDict, channelRows, sampleRows
    CollectThreatEventQueryFiltered "Microsoft-Windows-Sysmon/Operational", "YELLOW | Sysmon suporte", "4,7", 50, 8, 96, 0, 0, "yellow", countsDict, channelRows, sampleRows
    CollectThreatEventQueryFiltered "Microsoft-Windows-Bits-Client/Operational", "YELLOW | BITS", "59,60,63", 30, 6, 96, 0, 0, "yellow", countsDict, channelRows, sampleRows
End Sub

Sub CollectThreatEventsFromChannelSimple(channelName, idsCsv, maxCount, timeoutSecs, countsDict, channelRows, sampleRows)
    CollectThreatEventQueryFiltered channelName, "Padrao", idsCsv, maxCount, timeoutSecs, 0, 6, 4000, "", countsDict, channelRows, sampleRows
End Sub

Sub CollectThreatEventQueryFiltered(channelName, queryLabel, idsCsv, maxCount, timeoutSecs, lookbackHours, sampleLimit, sampleMaxChars, priorityBucket, countsDict, channelRows, sampleRows)
    Dim cmdXml, rawXml, hitCount, noteTxt, labelText, filterNote
    Dim exportPath, exportFileName, exportNote, exportStatus

    If UCase(Nz(channelName, "")) = "SYSTEM" Then
        If CLng(0 + maxCount) > 24 Then maxCount = 24
        If CLng(0 + timeoutSecs) > 8 Then timeoutSecs = 8
        sampleLimit = 0
        sampleMaxChars = 0
    End If

    labelText = channelName
    If Trim(CStr(queryLabel & "")) <> "" Then labelText = labelText & "<br><span class='mini-note'>" & HtmlEncode(queryLabel) & "</span>"

    cmdXml = BuildThreatEventQueryCommandEx(channelName, idsCsv, maxCount, "xml", lookbackHours)
    rawXml = GetCommandOutputWithTimeout(cmdXml, timeoutSecs)
    filterNote = "IDs=" & idsCsv & " | c=" & CLng(0 + maxCount)
    If CLng(0 + lookbackHours) > 0 Then filterNote = filterNote & " | janela=" & CLng(0 + lookbackHours) & "h"

    If InStr(1, rawXml, "<Event", vbTextCompare) > 0 Then
        hitCount = 0
        CountThreatEventIdsFromXml rawXml, channelName, countsDict, hitCount
        TrackThreatPriorityBucketHits priorityBucket, hitCount
        channelRows = channelRows & "<tr><td class='location-col'>" & labelText & "</td><td><span class='tag ok'>OK</span></td><td>" & hitCount & "</td><td class='location-col'>" & HtmlEncode(filterNote) & "</td></tr>"
        exportFileName = "threat_events_" & channelName & "_" & queryLabel & "_" & strRunId
        exportPath = ExportTextArtifact("ameacas_eventos", exportFileName, "xml", rawXml)
        exportStatus = "<span class='tag ok'>OK</span>"
        exportNote = "XML wevtutil | " & filterNote
        If Trim(exportPath) <> "" Then
            threatEventExportCount = CLng(0 + threatEventExportCount) + 1
            sampleRows = sampleRows & "<tr><td class='location-col'>" & labelText & "</td><td class='location-col'>" & HtmlEncode(filterNote) & "</td><td>" & hitCount & "</td><td>" & exportStatus & "</td><td class='location-col'><a href='" & HtmlEncode(exportPath) & "' style='color:#7dd3fc'>" & HtmlEncode(exportPath) & "</a></td><td class='location-col'>" & HtmlEncode(exportNote) & "</td></tr>"
            LogCustody "THREAT_EVENT_EXPORT", "OK", channelName & " | " & hitCount & " hits | " & exportPath
        Else
            sampleRows = sampleRows & "<tr><td class='location-col'>" & labelText & "</td><td class='location-col'>" & HtmlEncode(filterNote) & "</td><td>" & hitCount & "</td><td><span class='tag warn'>WARN</span></td><td>-</td><td class='location-col'>Falha ao gravar exportacao XML do canal.</td></tr>"
            LogCustody "THREAT_EVENT_EXPORT", "WARN", channelName & " | falha ao gravar XML"
        End If
    Else
        noteTxt = AbbrevText(rawXml, 240)
        If noteTxt = "-" Then noteTxt = "Canal sem retorno, sem permissao ou indisponivel."
        channelRows = channelRows & "<tr><td class='location-col'>" & labelText & "</td><td><span class='tag warn'>WARN</span></td><td>0</td><td class='location-col'>" & HtmlEncode(filterNote & " | " & noteTxt) & "</td></tr>"
        exportFileName = "threat_events_" & channelName & "_" & queryLabel & "_" & strRunId & "_sem_retorno"
        exportPath = ExportTextArtifact("ameacas_eventos", exportFileName, "txt", rawXml)
        If Trim(exportPath) <> "" Then
            threatEventExportCount = CLng(0 + threatEventExportCount) + 1
            sampleRows = sampleRows & "<tr><td class='location-col'>" & labelText & "</td><td class='location-col'>" & HtmlEncode(filterNote) & "</td><td>0</td><td><span class='tag warn'>WARN</span></td><td class='location-col'><a href='" & HtmlEncode(exportPath) & "' style='color:#7dd3fc'>" & HtmlEncode(exportPath) & "</a></td><td class='location-col'>" & HtmlEncode(noteTxt) & "</td></tr>"
        Else
            sampleRows = sampleRows & "<tr><td class='location-col'>" & labelText & "</td><td class='location-col'>" & HtmlEncode(filterNote) & "</td><td>0</td><td><span class='tag warn'>WARN</span></td><td>-</td><td class='location-col'>" & HtmlEncode(noteTxt) & "</td></tr>"
        End If
    End If
End Sub

Sub TrackThreatPriorityBucketHits(priorityBucket, hitCount)
    Select Case LCase(Trim(CStr(priorityBucket & "")))
        Case "red": threatRedHits = CLng(0 + threatRedHits) + CLng(0 + hitCount)
        Case "yellow": threatYellowHits = CLng(0 + threatYellowHits) + CLng(0 + hitCount)
    End Select
End Sub

Function BuildThreatEventQueryCommand(channelName, idsCsv, maxCount, fmtName)
    BuildThreatEventQueryCommand = BuildThreatEventQueryCommandEx(channelName, idsCsv, maxCount, fmtName, 0)
End Function

Function BuildThreatEventQueryCommandEx(channelName, idsCsv, maxCount, fmtName, lookbackHours)
    Dim q, timeClause, msLookback
    timeClause = ""
    If IsNumeric(lookbackHours) Then
        If CLng(0 + lookbackHours) > 0 Then
            msLookback = CLng(0 + lookbackHours) * 3600000
            timeClause = " and TimeCreated[timediff(@SystemTime) <= " & msLookback & "]"
        End If
    End If
    q = "*[System[(" & ThreatEventXPathIds(idsCsv) & ")" & timeClause & "]]"
    BuildThreatEventQueryCommandEx = "cmd /c wevtutil qe """ & channelName & """ /rd:true /c:" & CLng(0 + maxCount) & " /f:" & fmtName & " /q:""" & q & """ 2>&1"
End Function

Function ThreatEventXPathIds(idsCsv)
    Dim arr, i, out, v
    out = ""
    arr = Split(idsCsv, ",")
    For i = 0 To UBound(arr)
        v = Trim(arr(i))
        If v <> "" Then
            If out <> "" Then out = out & " or "
            out = out & "EventID=" & CLng(0 + v)
        End If
    Next
    If out = "" Then out = "EventID=0"
    ThreatEventXPathIds = out
End Function

Function CountXmlEventNodes(xmlText)
    Dim re, matches
    CountXmlEventNodes = 0
    If Trim(CStr(xmlText & "")) = "" Then Exit Function
    Set re = CreateObject("VBScript.RegExp")
    re.Global = True
    re.IgnoreCase = True
    re.Pattern = "<Event(\s|>)"
    If re.Test(CStr(xmlText)) Then
        Set matches = re.Execute(CStr(xmlText))
        CountXmlEventNodes = matches.Count
    End If
End Function

Sub CountThreatEventIdsFromXml(xmlText, channelName, countsDict, hitCount)
    Dim re, matches, m, eventId, key, sev, bucket
    hitCount = 0

    Set re = CreateObject("VBScript.RegExp")
    re.Global = True
    re.IgnoreCase = True
    re.Pattern = "<EventID(?:\s+[^>]*)?>(\d+)</EventID>"

    If re.Test(xmlText) Then
        Set matches = re.Execute(xmlText)
        For Each m In matches
            eventId = CLng(0 + m.SubMatches(0))
            key = UCase(channelName) & "|" & CStr(eventId)
            If countsDict.Exists(key) Then
                countsDict(key) = CLng(0 + countsDict(key)) + 1
            Else
                countsDict.Add key, 1
            End If

            hitCount = hitCount + 1
            threatEventTotalHits = CLng(0 + threatEventTotalHits) + 1
            bucket = ThreatChannelBucket(channelName)
            Select Case bucket
                Case "security": threatSecurityHits = CLng(0 + threatSecurityHits) + 1
                Case "system": threatSystemHits = CLng(0 + threatSystemHits) + 1
                Case "powershell": threatPowerShellHits = CLng(0 + threatPowerShellHits) + 1
                Case "sysmon": threatSysmonHits = CLng(0 + threatSysmonHits) + 1
                Case "bits": threatBitsHits = CLng(0 + threatBitsHits) + 1
            End Select

            sev = ThreatEventSeverity(channelName, eventId)
            Select Case sev
                Case "ALERTA": threatEventAlertCount = CLng(0 + threatEventAlertCount) + 1
                Case "WARN": threatEventWarnCount = CLng(0 + threatEventWarnCount) + 1
                Case Else: threatEventInfoCount = CLng(0 + threatEventInfoCount) + 1
            End Select
            If IsThreatHighPriority(channelName, eventId) Then threatHighPriorityHits = CLng(0 + threatHighPriorityHits) + 1
        Next
    End If
End Sub

Function BuildThreatEventSummaryRows(countsDict)
    Dim rows, keys, i, key, parts, channelName, eventId, countVal, maxCount, sev
    rows = ""
    If countsDict.Count <= 0 Then
        BuildThreatEventSummaryRows = ""
        Exit Function
    End If

    keys = SortDictKeysByValueDesc(countsDict)
    maxCount = 1
    For i = 0 To UBound(keys)
        If CLng(0 + countsDict(keys(i))) > maxCount Then maxCount = CLng(0 + countsDict(keys(i)))
    Next

    For i = 0 To UBound(keys)
        key = CStr(keys(i))
        parts = Split(key, "|")
        If UBound(parts) >= 1 Then
            channelName = parts(0)
            eventId = CLng(0 + parts(1))
            countVal = CLng(0 + countsDict(key))
            sev = ThreatEventSeverity(channelName, eventId)
            rows = rows & "<tr><td>" & HtmlEncode(channelName) & "</td><td>" & eventId & "</td><td>" & HtmlEncode(ThreatEventGroupNameSimple(channelName, eventId) & " / " & ThreatEventLabel(channelName, eventId)) & "</td><td><span class='tag " & ThreatSeverityCss(sev) & "'>" & HtmlEncode(sev) & "</span></td><td>" & countVal & "</td><td><div class='bar'><span style='width:" & PercentWidthPct(countVal, maxCount) & "%'></span></div></td></tr>"
        End If
    Next
    BuildThreatEventSummaryRows = rows
End Function
Function ThreatChannelBucket(channelName)
    Dim c
    c = UCase(Nz(channelName, ""))
    If c = "SECURITY" Then
        ThreatChannelBucket = "security"
    ElseIf c = "SYSTEM" Then
        ThreatChannelBucket = "system"
    ElseIf InStr(c, "SYSMON") > 0 Then
        ThreatChannelBucket = "sysmon"
    ElseIf InStr(c, "POWERSHELL") > 0 Then
        ThreatChannelBucket = "powershell"
    ElseIf InStr(c, "BITS") > 0 Then
        ThreatChannelBucket = "bits"
    Else
        ThreatChannelBucket = LCase(c)
    End If
End Function

Function ThreatEventGroupNameSimple(channelName, eventId)
    If ThreatChannelBucket(channelName) = "sysmon" Then
        ThreatEventGroupNameSimple = "Sysmon"
        Exit Function
    End If
    If ThreatChannelBucket(channelName) = "powershell" Then
        ThreatEventGroupNameSimple = "PowerShell"
        Exit Function
    End If
    If ThreatChannelBucket(channelName) = "bits" Then
        ThreatEventGroupNameSimple = "BITS"
        Exit Function
    End If

    Select Case CLng(0 + eventId)
        Case 4624,4625,4634,4647,4648,4672,4768,4769,4771,4776,4740: ThreatEventGroupNameSimple = "Autenticacao/Acesso"
        Case 4778,4779: ThreatEventGroupNameSimple = "RDP"
        Case 4720,4722,4723,4724,4725,4726,4728,4732,4756,4738,4767: ThreatEventGroupNameSimple = "Contas/Privilegio"
        Case 4688,4689,4697,7045,7040,4698,4702,4719,1100,1102,104: ThreatEventGroupNameSimple = "Execucao/Persistencia"
        Case 4656,4659,4660,4663,4670,4907: ThreatEventGroupNameSimple = "FileSystem/Delecao"
        Case 5156,5157,5158,5140,5145,5142,5144: ThreatEventGroupNameSimple = "Rede/Exfil"
        Case 25,8193,8222,5038: ThreatEventGroupNameSimple = "VSS/Impacto"
        Case Else: ThreatEventGroupNameSimple = "Monitorado"
    End Select
End Function

Function ThreatEventSeverity(channelName, eventId)
    Dim bucket, idn
    bucket = ThreatChannelBucket(channelName)
    idn = CLng(0 + eventId)

    If bucket = "sysmon" Then
        Select Case idn
            Case 8,10,11,13: ThreatEventSeverity = "ALERTA": Exit Function
            Case 1,3,4,7: ThreatEventSeverity = "WARN": Exit Function
        End Select
    End If
    If bucket = "powershell" Then
        If idn = 4104 Then ThreatEventSeverity = "ALERTA" Else ThreatEventSeverity = "WARN"
        Exit Function
    End If

    Select Case idn
        Case 1102,1100,4719,7045,4697,4698,4724,4728,4732,4756,25
            ThreatEventSeverity = "ALERTA"
        Case 4625,4771,4740,4672,4769,7040,4702,104,5038,8193,8222,59,60,63,5158,5142,5144,4660,4663,4688,4656,4659
            ThreatEventSeverity = "WARN"
        Case Else
            ThreatEventSeverity = "INFO"
    End Select
End Function

Function ThreatSeverityCss(sevText)
    Select Case UCase(Nz(sevText, ""))
        Case "ALERTA": ThreatSeverityCss = "bad"
        Case "WARN": ThreatSeverityCss = "warn"
        Case Else: ThreatSeverityCss = "ok"
    End Select
End Function

Function IsThreatHighPriority(channelName, eventId)
    Dim idn
    idn = CLng(0 + eventId)
    If ThreatChannelBucket(channelName) = "sysmon" Then
        Select Case idn
            Case 1,3,10,11: IsThreatHighPriority = True: Exit Function
        End Select
    End If
    Select Case idn
        Case 4688,4663,4624,4625,4672,4769,7045,4698,5156,1102,4104
            IsThreatHighPriority = True
        Case Else
            IsThreatHighPriority = False
    End Select
End Function

Function ThreatEventLabel(channelName, eventId)
    Dim idn
    idn = CLng(0 + eventId)
    If ThreatChannelBucket(channelName) = "sysmon" Then
        Select Case idn
            Case 1: ThreatEventLabel = "Process Create"
            Case 3: ThreatEventLabel = "Network Connection"
            Case 4: ThreatEventLabel = "Sysmon Service State"
            Case 7: ThreatEventLabel = "Image Load"
            Case 8: ThreatEventLabel = "CreateRemoteThread"
            Case 10: ThreatEventLabel = "ProcessAccess"
            Case 11: ThreatEventLabel = "FileCreate"
            Case 13: ThreatEventLabel = "Registry Modification"
            Case Else: ThreatEventLabel = "Sysmon Event"
        End Select
        Exit Function
    End If
    Select Case idn
        Case 4624: ThreatEventLabel = "Logon sucesso"
        Case 4625: ThreatEventLabel = "Logon falha"
        Case 4672: ThreatEventLabel = "Privilegios especiais"
        Case 4688: ThreatEventLabel = "Processo criado"
        Case 4698: ThreatEventLabel = "Scheduled task criada"
        Case 4697: ThreatEventLabel = "Servico instalado"
        Case 4719: ThreatEventLabel = "Politica de auditoria alterada"
        Case 4740: ThreatEventLabel = "Conta bloqueada"
        Case 4769: ThreatEventLabel = "Kerberos service ticket"
        Case 4778: ThreatEventLabel = "RDP reconectada"
        Case 4779: ThreatEventLabel = "RDP desconectada"
        Case 7045: ThreatEventLabel = "Servico criado"
        Case 4104: ThreatEventLabel = "PowerShell script block"
        Case 1102: ThreatEventLabel = "Security log apagado"
        Case Else: ThreatEventLabel = "Evento monitorado"
    End Select
End Function

Function SortDictKeysByValueDesc(dictObj)
    Dim keys, i, j, tmp
    If dictObj.Count <= 0 Then
        SortDictKeysByValueDesc = Array()
        Exit Function
    End If
    keys = dictObj.Keys
    For i = 0 To UBound(keys) - 1
        For j = i + 1 To UBound(keys)
            If CLng(0 + dictObj(keys(j))) > CLng(0 + dictObj(keys(i))) Then
                tmp = keys(i)
                keys(i) = keys(j)
                keys(j) = tmp
            End If
        Next
    Next
    SortDictKeysByValueDesc = keys
End Function

Function AbbrevText(s, maxLen)
    Dim t, n
    n = CLng(0 + maxLen)
    If n <= 0 Then n = 240
    t = CStr(Nz(s, ""))
    t = Replace(t, vbCrLf, " | ")
    t = Replace(t, vbCr, " | ")
    t = Replace(t, vbLf, " | ")
    Do While InStr(t, "  ") > 0
        t = Replace(t, "  ", " ")
    Loop
    t = Trim(t)
    If Len(t) > n Then t = Left(t, n) & "..."
    If t = "" Then t = "-"
    AbbrevText = t
End Function

Function AbbrevTextKeepLines(s, maxLen)
    Dim t, n, trimmedCheck
    n = CLng(0 + maxLen)
    If n <= 0 Then n = 240
    t = CStr(Nz(s, ""))
    t = Replace(t, vbCrLf, vbLf)
    t = Replace(t, vbCr, vbLf)
    If Len(t) > n Then t = Left(t, n) & vbLf & "..."
    trimmedCheck = Replace(t, vbLf, "")
    trimmedCheck = Replace(trimmedCheck, vbCr, "")
    If Trim(trimmedCheck) = "" Then t = "-"
    AbbrevTextKeepLines = t
End Function
Sub CollectThreatRegistryChecks(registryRows, registrySnapshotRows)
    Dim vDword, vText, cnt
    registryRows = ""
    registrySnapshotRows = ""

    vDword = ReadDWORDValueRoot(HKLM, "SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", -1)
    AddThreatRegistryCheckRow registryRows, "RDP", "HKLM", "SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections", CStr(vDword), IIfBool(CLng(0 + vDword)=0, "WARN", "INFO"), "0 permite RDP; correlacione com 4624 Tipo 10/4778/4779."

    vDword = ReadDWORDValueRoot(HKLM, "SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "PortNumber", -1)
    AddThreatRegistryCheckRow registryRows, "RDP", "HKLM", "SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "PortNumber", CStr(vDword), IIfBool(CLng(0 + vDword)>0 And CLng(0 + vDword)<>3389, "WARN", "INFO"), "Porta do listener RDP."

    vDword = ReadDWORDValueRoot(HKLM, "SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", -1)
    AddThreatRegistryCheckRow registryRows, "RDP", "HKLM", "SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication", CStr(vDword), IIfBool(CLng(0 + vDword)=0, "WARN", "INFO"), "0 pode indicar NLA desabilitado."

    vDword = ReadDWORDValueRoot(HKLM, "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", -1)
    AddThreatRegistryCheckRow registryRows, "PowerShell", "HKLM", "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", CStr(vDword), IIfBool(CLng(0 + vDword)=1, "INFO", "WARN"), "Visibilidade do evento 4104."

    vDword = ReadDWORDValueRoot(HKLM, "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging", -1)
    AddThreatRegistryCheckRow registryRows, "PowerShell", "HKLM", "SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging", CStr(vDword), IIfBool(CLng(0 + vDword)=1, "INFO", "WARN"), "Visibilidade do evento 4103."

    vDword = ReadDWORDValueRoot(HKLM, "SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting", -1)
    AddThreatRegistryCheckRow registryRows, "PowerShell", "HKLM", "SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription", "EnableTranscripting", CStr(vDword), IIfBool(CLng(0 + vDword)=1, "INFO", "WARN"), "Transcricao PowerShell."

    vDword = ReadDWORDValueRoot(HKLM, "SYSTEM\CurrentControlSet\Services\EventLog", "Start", -1)
    AddThreatRegistryCheckRow registryRows, "EventLog", "HKLM", "SYSTEM\CurrentControlSet\Services\EventLog", "Start", RegistryServiceStartName(vDword), IIfBool(CLng(0 + vDword)=4, "ALERTA", IIfBool(CLng(0 + vDword)=2, "INFO", "WARN")), "Servico de logs do Windows."

    cnt = RegistryValueCount(HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    AddThreatRegistryCheckRow registryRows, "Persistencia", "HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "(count)", CStr(cnt), IIfBool(cnt>3, "WARN", "INFO"), "Autostart da maquina."
    cnt = RegistryValueCount(HKCU, "SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    AddThreatRegistryCheckRow registryRows, "Persistencia", "HKCU", "SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "(count)", CStr(cnt), IIfBool(cnt>4, "WARN", "INFO"), "Autostart do usuario atual."
    cnt = RegistryValueCount(HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
    AddThreatRegistryCheckRow registryRows, "Persistencia", "HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "(count)", CStr(cnt), IIfBool(cnt>0, "WARN", "INFO"), "Execucao unica pendente."
    cnt = RegistryValueCount(HKCU, "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
    AddThreatRegistryCheckRow registryRows, "Persistencia", "HKCU", "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "(count)", CStr(cnt), IIfBool(cnt>0, "WARN", "INFO"), "Execucao unica (usuario)."

    vText = ReadRegistryTextValueRoot(HKLM, "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", "-")
    AddThreatRegistryCheckRow registryRows, "Persistencia", "HKLM", "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", AbbrevText(vText, 180), IIfBool(UCase(Trim(vText))<>"EXPLORER.EXE", "ALERTA", "INFO"), "Shell padrao esperado: explorer.exe"
    vText = ReadRegistryTextValueRoot(HKLM, "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", "-")
    AddThreatRegistryCheckRow registryRows, "Persistencia", "HKLM", "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", AbbrevText(vText, 180), IIfBool(InStr(UCase(vText), "USERINIT.EXE")=0, "ALERTA", "INFO"), "Verificar alteracoes em userinit.exe"

    cnt = RegistrySubKeyCount(HKLM, "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
    AddThreatRegistryCheckRow registryRows, "Persistencia/Evasao", "HKLM", "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "(subkeys)", CStr(cnt), IIfBool(cnt>0, "WARN", "INFO"), "IFEO pode ser usado para hijack/debugger."

    vDword = ReadDWORDValueRoot(HKLM, "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "LoadAppInit_DLLs", -1)
    AddThreatRegistryCheckRow registryRows, "Persistencia/Evasao", "HKLM", "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "LoadAppInit_DLLs", CStr(vDword), IIfBool(CLng(0 + vDword)=1, "WARN", "INFO"), "Ativa carga de AppInit DLLs."
    vText = ReadRegistryTextValueRoot(HKLM, "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", "-")
    AddThreatRegistryCheckRow registryRows, "Persistencia/Evasao", "HKLM", "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", AbbrevText(vText, 180), IIfBool(Trim(vText)<>"" And Trim(vText)<>"-", "ALERTA", "INFO"), "DLLs para injecao via AppInit."

    vDword = ReadDWORDValueRoot(HKLM, "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", -1)
    AddThreatRegistryCheckRow registryRows, "Credenciais/LSA", "HKLM", "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", CStr(vDword), IIfBool(CLng(0 + vDword)=1, "ALERTA", "INFO"), "1 aumenta risco de credenciais em memoria."
    vDword = ReadDWORDValueRoot(HKLM, "SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", -1)
    AddThreatRegistryCheckRow registryRows, "Credenciais/LSA", "HKLM", "SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", CStr(vDword), IIfBool(CLng(0 + vDword)=1, "INFO", "WARN"), "Protecao LSA/PPL."
    vDword = ReadDWORDValueRoot(HKLM, "SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", -1)
    AddThreatRegistryCheckRow registryRows, "Credenciais/LSA", "HKLM", "SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", CStr(vDword), IIfBool(CLng(0 + vDword)>-1 And CLng(0 + vDword)<3, "WARN", "INFO"), "Niveis baixos favorecem NTLM legado."

    vDword = ReadDWORDValueRoot(HKLM, "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", -1)
    AddThreatRegistryCheckRow registryRows, "Firewall", "HKLM", "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", CStr(vDword), IIfBool(CLng(0 + vDword)=0, "WARN", "INFO"), "Firewall dominio."
    vDword = ReadDWORDValueRoot(HKLM, "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", -1)
    AddThreatRegistryCheckRow registryRows, "Firewall", "HKLM", "SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", CStr(vDword), IIfBool(CLng(0 + vDword)=0, "WARN", "INFO"), "Firewall publico."
    vDword = ReadDWORDValueRoot(HKLM, "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", -1)
    AddThreatRegistryCheckRow registryRows, "SMB/BITS", "HKLM", "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", CStr(vDword), IIfBool(CLng(0 + vDword)=1, "WARN", "INFO"), "SMBv1 legado."
    vDword = ReadDWORDValueRoot(HKLM, "SYSTEM\CurrentControlSet\Services\BITS", "Start", -1)
    AddThreatRegistryCheckRow registryRows, "SMB/BITS", "HKLM", "SYSTEM\CurrentControlSet\Services\BITS", "Start", RegistryServiceStartName(vDword), "INFO", "Servico BITS (correlacionar com 59/60/63)."

    If RegistryKeyExistsRoot(HKLM, "SYSTEM\CurrentControlSet\Services\Sysmon64") Or RegistryKeyExistsRoot(HKLM, "SYSTEM\CurrentControlSet\Services\Sysmon") Then
        AddThreatRegistryCheckRow registryRows, "Sysmon", "HKLM", "SYSTEM\CurrentControlSet\Services\Sysmon64|Sysmon", "(exist)", "sim", "INFO", "Servico Sysmon detectado."
    Else
        AddThreatRegistryCheckRow registryRows, "Sysmon", "HKLM", "SYSTEM\CurrentControlSet\Services\Sysmon64|Sysmon", "(exist)", "nao", "WARN", "Sysmon nao detectado (opcional, mas recomendado)."
    End If
    AddThreatRegistryCheckRow registryRows, "Sysmon", "HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational", "(exist)", IIfBool(RegistryKeyExistsRoot(HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational"), "sim", "nao"), IIfBool(RegistryKeyExistsRoot(HKLM, "SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational"), "INFO", "WARN"), "Canal operacional do Sysmon."

    vDword = ReadDWORDValueRoot(HKLM, "SYSTEM\CurrentControlSet\Services\VSS", "Start", -1)
    AddThreatRegistryCheckRow registryRows, "VSS", "HKLM", "SYSTEM\CurrentControlSet\Services\VSS", "Start", RegistryServiceStartName(vDword), "INFO", "Servico VSS."
    vDword = ReadDWORDValueRoot(HKLM, "SYSTEM\CurrentControlSet\Services\VolSnap", "Start", -1)
    AddThreatRegistryCheckRow registryRows, "VSS", "HKLM", "SYSTEM\CurrentControlSet\Services\VolSnap", "Start", RegistryServiceStartName(vDword), "INFO", "Driver VolSnap (shadow copy)."

    AppendThreatRegistrySnapshot registrySnapshotRows, "RDP", "cmd /c reg query ""HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"""
    AppendThreatRegistrySnapshot registrySnapshotRows, "PowerShell", "cmd /c reg query ""HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"""
    AppendThreatRegistrySnapshot registrySnapshotRows, "PowerShell", "cmd /c reg query ""HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"""
    AppendThreatRegistrySnapshot registrySnapshotRows, "Run (HKLM)", "cmd /c reg query ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"""
    AppendThreatRegistrySnapshot registrySnapshotRows, "Run (HKCU)", "cmd /c reg query ""HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"""
    AppendThreatRegistrySnapshot registrySnapshotRows, "Winlogon", "cmd /c reg query ""HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"" /v Shell"
    AppendThreatRegistrySnapshot registrySnapshotRows, "WDigest", "cmd /c reg query ""HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"""
End Sub

Sub AddThreatRegistryCheckRow(registryRows, groupName, rootName, keyPath, valueName, valueDisplay, severityText, noteText)
    Dim sev, css
    sev = UCase(Nz(severityText, "INFO"))
    Select Case sev
        Case "ALERTA": css = "bad": threatRegistryAlertCount = CLng(0 + threatRegistryAlertCount) + 1
        Case "WARN": css = "warn": threatRegistryWarnCount = CLng(0 + threatRegistryWarnCount) + 1
        Case Else: css = "ok": threatRegistryInfoCount = CLng(0 + threatRegistryInfoCount) + 1
    End Select
    threatRegistryChecks = CLng(0 + threatRegistryChecks) + 1
    UpdateThreatRegistryBucketCounters groupName
    registryRows = registryRows & "<tr><td>" & HtmlEncode(groupName) & "</td><td>" & HtmlEncode(rootName) & "</td><td class='location-col'>" & HtmlEncode(keyPath) & "</td><td>" & HtmlEncode(valueName) & "</td><td class='location-col'>" & HtmlEncode(Nz(valueDisplay, "-")) & "</td><td><span class='tag " & css & "'>" & HtmlEncode(sev) & "</span></td><td class='location-col'>" & HtmlEncode(noteText) & "</td></tr>"
End Sub

Sub UpdateThreatRegistryBucketCounters(groupName)
    Dim g
    g = UCase(Trim(CStr(groupName & "")))
    Select Case g
        Case "PERSISTENCIA", "PERSISTENCIA/EVASAO"
            threatRegistryPersistHits = CLng(0 + threatRegistryPersistHits) + 1
        Case "RDP"
            threatRegistryAccessHits = CLng(0 + threatRegistryAccessHits) + 1
        Case "EVENTLOG", "POWERSHELL", "SYSMON", "VSS"
            threatRegistryTelemetryHits = CLng(0 + threatRegistryTelemetryHits) + 1
        Case "CREDENCIAIS/LSA"
            threatRegistryCredHits = CLng(0 + threatRegistryCredHits) + 1
        Case "FIREWALL", "SMB/BITS"
            threatRegistryNetworkHits = CLng(0 + threatRegistryNetworkHits) + 1
        Case Else
            threatRegistryAccessHits = CLng(0 + threatRegistryAccessHits) + 1
    End Select
End Sub

Sub AppendThreatRegistrySnapshot(registrySnapshotRows, groupName, cmd)
    Dim outText, exportPath, outBytes, statusTag, noteTxt
    outText = GetCommandOutputWithTimeout(cmd, 8)
    exportPath = ExportTextArtifact("ameacas_registro", "snapshot_" & groupName & "_" & ShortCommandForLog(cmd) & "_" & strRunId, "txt", outText)
    noteTxt = AbbrevText(Replace(outText, vbCrLf, " | "), 220)
    If Trim(exportPath) <> "" Then
        threatRegistrySnapshotExportCount = CLng(0 + threatRegistrySnapshotExportCount) + 1
        outBytes = GetFileSizeBytesSafe(exportPath)
        statusTag = "<span class='tag ok'>OK</span>"
        registrySnapshotRows = registrySnapshotRows & "<tr><td>" & HtmlEncode(groupName) & "</td><td><code>" & HtmlEncode(ShortCommandForLog(cmd)) & "</code></td><td>" & statusTag & "</td><td class='location-col'><a href='" & HtmlEncode(exportPath) & "' style='color:#7dd3fc'>" & HtmlEncode(exportPath) & "</a></td><td>" & HtmlEncode(FormatBytes(outBytes)) & "</td><td class='location-col'>" & HtmlEncode(noteTxt) & "</td></tr>"
        LogCustody "REG_SNAPSHOT_EXPORT", "OK", groupName & " | " & exportPath
    Else
        registrySnapshotRows = registrySnapshotRows & "<tr><td>" & HtmlEncode(groupName) & "</td><td><code>" & HtmlEncode(ShortCommandForLog(cmd)) & "</code></td><td><span class='tag warn'>WARN</span></td><td>-</td><td>-</td><td class='location-col'>Falha ao exportar snapshot. " & HtmlEncode(noteTxt) & "</td></tr>"
        LogCustody "REG_SNAPSHOT_EXPORT", "WARN", groupName & " | Falha na exportacao"
    End If
End Sub

Sub CollectThreatHuntCommandSnapshots(rowsHtml, okCount, failCount, skipCount)
    Dim dnsDomain, adDomain, probeHost, gpReportPath, gpReportNote

    rowsHtml = ""
    okCount = 0
    failCount = 0
    skipCount = 0

    probeHost = Trim(CStr(strComputer & ""))
    If probeHost = "" Then probeHost = "localhost"
    dnsDomain = GetThreatHuntDnsQueryDomain()
    adDomain = GetThreatHuntAdDomainName()

    RunThreatHuntCommandSnapshot "PowerShell Test-NetConnection (conectividade)", "powershell", "conectividade", "powershell -NoProfile -Command ""Test-NetConnection -ComputerName '" & EscapePsSingleQuoted(probeHost) & "' -Port 445 -InformationLevel Detailed | Format-List * | Out-String -Width 260""", 20, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "getmac /v /fo csv", "getmac", "interfaces_mac", "cmd /c getmac /v /fo csv 2>&1", 20, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "nslookup -type=ANY dominio", "nslookup", "dns_any", "cmd /c nslookup -type=ANY """ & dnsDomain & """ 2>&1", 20, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "systeminfo", "systeminfo", "inventario_so", "cmd /c systeminfo 2>&1", 90, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "wmic os get ...", "wmic", "inventario_os_wmic", "cmd /c wmic os get Caption,Version,BuildNumber,OSArchitecture,CSName,LastBootUpTime,InstallDate /format:list 2>&1", 35, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "tasklist /v /fo csv", "tasklist", "processos_csv", "cmd /c tasklist /v /fo csv 2>&1", 45, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "tasklist /fi imagename=svchost.exe", "tasklist", "svchost_filtro", "cmd /c tasklist /fi ""imagename eq svchost.exe"" 2>&1", 20, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "sc query type= service state= all", "sc", "servicos_enum", "cmd /c sc query type^= service state^= all 2>&1", 35, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "driverquery /fo table /si", "driverquery", "drivers_assinatura", "cmd /c driverquery /fo table /si 2>&1", 45, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "net user", "net", "contas_locais", "cmd /c net user 2>&1", 20, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "whoami /priv", "whoami", "privilegios", "cmd /c whoami /priv 2>&1", 20, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "schtasks /query /fo LIST /v", "schtasks", "tarefas_schtasks", "cmd /c schtasks /query /fo LIST /v 2>&1", 60, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "PowerShell Get-ScheduledTask", "powershell", "tarefas_getscheduledtask", "powershell -NoProfile -Command ""Get-ScheduledTask | Sort-Object TaskPath,TaskName | Format-Table TaskPath,TaskName,State,Author -AutoSize | Out-String -Width 260""", 45, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "qwinsta / query session", "qwinsta", "sessoes", "cmd /c qwinsta 2>&1", 20, rowsHtml, okCount, failCount, ""

    If Trim(CStr(adDomain & "")) <> "" Then
        RunThreatHuntCommandSnapshot "nltest /sc_query:DOMINIO", "nltest", "ad_secure_channel", "cmd /c nltest /sc_query:""" & adDomain & """ 2>&1", 25, rowsHtml, okCount, failCount, ""
        RunThreatHuntCommandSnapshot "net user /domain", "net", "ad_usuarios", "cmd /c net user /domain 2>&1", 35, rowsHtml, okCount, failCount, ""
    Else
        AppendThreatHuntCommandSkipRow rowsHtml, "nltest", "ad_secure_channel", "Host nao aparenta estar em dominio AD; comando ignorado."
        skipCount = CLng(0 + skipCount) + 1
        AppendThreatHuntCommandSkipRow rowsHtml, "net", "ad_usuarios", "Host nao aparenta estar em dominio AD; comando ignorado."
        skipCount = CLng(0 + skipCount) + 1
    End If

    RunThreatHuntCommandSnapshot "wmic process ... commandline", "wmic", "processo_cmdline", "cmd /c wmic process where ""name='svchost.exe'"" get CommandLine,CreationDate,Priority /format:list 2>&1", 45, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "auditpol /get /category:*", "auditpol", "auditoria_config", "cmd /c auditpol /get /category:* 2>&1", 35, rowsHtml, okCount, failCount, ""

    gpReportPath = BuildThreatHuntResultadosFilePath("gpresult", "gpo_html", "html")
    gpReportNote = "Relatorio HTML: " & gpReportPath
    RunThreatHuntCommandSnapshot "gpresult /h report.html", "gpresult", "gpo", "cmd /c gpresult /h """ & gpReportPath & """ /f 2>&1", 120, rowsHtml, okCount, failCount, gpReportNote

    RunThreatHuntCommandSnapshot "certutil -dump", "certutil", "pki_dump", "cmd /c certutil -dump 2>&1", 35, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "fsutil fsinfo ntfsinfo C:", "fsutil", "ntfsinfo_c", "cmd /c fsutil fsinfo ntfsinfo C: 2>&1", 25, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "fsutil behavior query DisableDeleteNotify", "fsutil", "trim_behavior", "cmd /c fsutil behavior query DisableDeleteNotify 2>&1", 20, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "fsutil usn queryjournal C:", "fsutil", "usn_queryjournal_c", "cmd /c fsutil usn queryjournal C: 2>&1", 25, rowsHtml, okCount, failCount, ""
    RunThreatHuntCommandSnapshot "vssadmin list shadows", "vssadmin", "vss_shadows", "cmd /c vssadmin list shadows 2>&1", 25, rowsHtml, okCount, failCount, ""
End Sub

Sub RunThreatHuntCommandSnapshot(displayLabel, toolName, categoryName, cmdText, timeoutSecs, rowsHtml, okCount, failCount, extraNote)
    Dim cmdOut, exitCode, timedOut, resultFile, stampLocal, headerText
    Dim statusTxt, statusHtml, noteTxt, noteExtra

    ExecuteCommandWithLocalTimeoutEx cmdText, timeoutSecs, cmdOut, exitCode, timedOut
    stampLocal = TimestampLocalMillis(Now)
    noteExtra = ""
    noteExtra = Trim(CStr(extraNote & ""))

    statusTxt = "OK"
    noteTxt = ""
    If CBool(timedOut) Then
        statusTxt = "WARN"
        noteTxt = "Timeout local apos " & CLng(0 + timeoutSecs) & "s."
    ElseIf CLng(0 + exitCode) <> 0 Then
        statusTxt = "WARN"
        noteTxt = "ExitCode=" & CLng(0 + exitCode)
    ElseIf Not HasUsefulOutput(cmdOut) Then
        statusTxt = "WARN"
        noteTxt = "Comando concluiu sem retorno util."
    End If
    If noteExtra <> "" Then
        If noteTxt <> "" Then
            noteTxt = noteTxt & " | " & noteExtra
        Else
            noteTxt = noteExtra
        End If
    End If

    headerText = "timestamp_local=" & stampLocal & vbCrLf & _
                 "rotulo=" & displayLabel & vbCrLf & _
                 "tool=" & toolName & vbCrLf & _
                 "categoria=" & categoryName & vbCrLf & _
                 "timeout_s=" & CLng(0 + timeoutSecs) & vbCrLf & _
                 "exit_code=" & CLng(0 + exitCode) & vbCrLf & _
                 "timed_out=" & LCase(CStr(CBool(timedOut))) & vbCrLf & _
                 "comando=" & cmdText & vbCrLf & String(72, "-") & vbCrLf
    resultFile = ExportThreatHuntResultFile(toolName, categoryName, headerText & CStr(Nz(cmdOut, "")))

    If statusTxt = "OK" And Trim(CStr(resultFile & "")) <> "" Then
        okCount = CLng(0 + okCount) + 1
        LogCustody "THREAT_HUNT_CMD", "OK", toolName & "/" & categoryName & " | arquivo=" & resultFile
        statusHtml = "<span class='tag ok'>OK</span>"
        If noteTxt = "" Then noteTxt = "Concluido com sucesso."
    Else
        failCount = CLng(0 + failCount) + 1
        statusHtml = "<span class='tag warn'>WARN</span>"
        If Trim(CStr(resultFile & "")) = "" Then
            If noteTxt <> "" Then
                noteTxt = noteTxt & " | "
            End If
            noteTxt = noteTxt & "Falha ao gravar arquivo .result."
        End If
    End If

    rowsHtml = rowsHtml & "<tr><td>" & HtmlEncode(toolName) & "</td><td>" & HtmlEncode(categoryName) & "</td><td>" & statusHtml & "</td><td>" & HtmlEncode(CStr(CLng(0 + exitCode))) & "</td><td>" & HtmlEncode(CStr(CLng(0 + timeoutSecs))) & "</td><td class='location-col'>" & IIfBool(Trim(CStr(resultFile & "")) <> "", "<a href='" & HtmlEncode(resultFile) & "' style='color:#7dd3fc'>" & HtmlEncode(resultFile) & "</a>", "-") & "</td><td class='location-col'><code>" & HtmlEncode(ShortCommandForLog(cmdText)) & "</code></td><td class='location-col'>" & HtmlEncode(noteTxt) & "</td></tr>"
End Sub

Sub AppendThreatHuntCommandSkipRow(rowsHtml, toolName, categoryName, noteText)
    Dim resultFile, contentText
    contentText = "timestamp_local=" & TimestampLocalMillis(Now) & vbCrLf & _
                  "tool=" & toolName & vbCrLf & _
                  "categoria=" & categoryName & vbCrLf & _
                  "status=SKIPPED" & vbCrLf & _
                  "motivo=" & Nz(noteText, "-")
    resultFile = ExportThreatHuntResultFile(toolName, categoryName, contentText)
    rowsHtml = rowsHtml & "<tr><td>" & HtmlEncode(toolName) & "</td><td>" & HtmlEncode(categoryName) & "</td><td><span class='tag warn'>SKIP</span></td><td>-</td><td>-</td><td class='location-col'>" & IIfBool(Trim(CStr(resultFile & "")) <> "", "<a href='" & HtmlEncode(resultFile) & "' style='color:#7dd3fc'>" & HtmlEncode(resultFile) & "</a>", "-") & "</td><td class='location-col'>-</td><td class='location-col'>" & HtmlEncode(noteText) & "</td></tr>"
End Sub

Sub ExecuteCommandWithLocalTimeoutEx(cmd, timeoutSecs, outText, exitCodeOut, timedOut)
    Dim ex, out, errOut, startTime, finalOut
    outText = ""
    exitCodeOut = -1
    timedOut = False

    On Error Resume Next
    Set ex = objShell.Exec(cmd)
    If Err.Number <> 0 Then
        outText = "Falha ao executar comando: " & Err.Description
        exitCodeOut = -2
        Err.Clear
        On Error Goto 0
        Exit Sub
    End If

    out = ""
    errOut = ""
    finalOut = ""
    startTime = Now

    Do
        Err.Clear
        If Not ex.StdOut.AtEndOfStream Then out = out & ex.StdOut.Read(1024)
        Err.Clear
        If Not ex.StdErr.AtEndOfStream Then errOut = errOut & ex.StdErr.Read(1024)
        If ex.Status <> 0 Then Exit Do

        If CLng(0 + timeoutSecs) > 0 Then
            If DateDiff("s", startTime, Now) >= CLng(0 + timeoutSecs) Then
                ex.Terminate
                Err.Clear
                timedOut = True
                exitCodeOut = 124
                outText = "[TIMEOUT APOS " & CLng(0 + timeoutSecs) & "s] Comando interrompido por demora."
                On Error Goto 0
                Exit Sub
            End If
        End If
        WScript.Sleep 100
    Loop

    Err.Clear
    If Not ex.StdOut.AtEndOfStream Then out = out & ex.StdOut.ReadAll
    Err.Clear
    If Not ex.StdErr.AtEndOfStream Then errOut = errOut & ex.StdErr.ReadAll

    If Trim(out) <> "" Then
        finalOut = Trim(out)
        If Trim(errOut) <> "" Then finalOut = finalOut & vbCrLf & "[stderr]" & vbCrLf & Trim(errOut)
    Else
        finalOut = Trim(errOut)
    End If
    If Trim(CStr(finalOut & "")) = "" Then finalOut = "(sem saida)"

    Err.Clear
    exitCodeOut = CLng(0 + ex.ExitCode)
    If Err.Number <> 0 Then
        Err.Clear
        exitCodeOut = -3
    End If
    outText = finalOut
    On Error Goto 0
End Sub

Function GetThreatHuntResultsDir()
    Dim dirPath
    dirPath = "Resultados"
    On Error Resume Next
    If Not objFSO.FolderExists(dirPath) Then objFSO.CreateFolder dirPath
    If Err.Number <> 0 Then Err.Clear
    On Error Goto 0
    GetThreatHuntResultsDir = dirPath
End Function

Function ThreatHuntFileStamp()
    Dim dt, msPart
    dt = Now
    msPart = CLng((Timer - Int(Timer)) * 1000)
    If msPart < 0 Then msPart = 0
    ThreatHuntFileStamp = Year(dt) & Right("0" & Month(dt), 2) & Right("0" & Day(dt), 2) & "_" & _
        Right("0" & Hour(dt), 2) & Right("0" & Minute(dt), 2) & Right("0" & Second(dt), 2) & "_" & Right("000" & msPart, 3)
End Function

Function BuildThreatHuntResultadosFilePath(toolName, categoryName, fileExt)
    Dim extNorm
    extNorm = Trim(CStr(fileExt & ""))
    If extNorm = "" Then extNorm = "result"
    If Left(extNorm, 1) = "." Then extNorm = Mid(extNorm, 2)
    BuildThreatHuntResultadosFilePath = GetThreatHuntResultsDir() & "\" & ThreatHuntFileStamp() & "_" & SanitizeFileNameComponent(toolName) & "_" & SanitizeFileNameComponent(categoryName) & "." & LCase(extNorm)
End Function

Function ExportThreatHuntResultFile(toolName, categoryName, contentText)
    Dim fullPath, f, rawText
    ExportThreatHuntResultFile = ""
    fullPath = BuildThreatHuntResultadosFilePath(toolName, categoryName, "result")
    rawText = CStr(Nz(contentText, ""))

    On Error Resume Next
    Err.Clear
    Set f = objFSO.OpenTextFile(fullPath, ForWriting, True, TristateFalse)
    If Err.Number <> 0 Then
        Err.Clear
        Set f = Nothing
        On Error Goto 0
        Exit Function
    End If

    f.Write rawText
    If Err.Number <> 0 Then
        Err.Clear
        f.Write HtmlAsciiSafe(rawText)
    End If
    f.Close
    Set f = Nothing

    If Err.Number = 0 Then
        ExportThreatHuntResultFile = fullPath
    Else
        Err.Clear
    End If
    On Error Goto 0
End Function

Function GetThreatHuntAdDomainName()
    Dim dom, colCs, cs
    dom = Trim(CStr(objShell.ExpandEnvironmentStrings("%USERDNSDOMAIN%") & ""))
    If dom <> "" Then
        GetThreatHuntAdDomainName = dom
        Exit Function
    End If

    dom = ""
    On Error Resume Next
    Set colCs = objWMI.ExecQuery("SELECT Domain,PartOfDomain FROM Win32_ComputerSystem")
    If Err.Number = 0 Then
        For Each cs In colCs
            If CBool(Nz(cs.PartOfDomain, False)) Then
                dom = Trim(CStr(Nz(cs.Domain, "")))
                Exit For
            End If
        Next
    End If
    Err.Clear
    On Error Goto 0
    GetThreatHuntAdDomainName = dom
End Function

Function GetThreatHuntDnsQueryDomain()
    Dim d
    d = Trim(CStr(GetThreatHuntAdDomainName() & ""))
    If d = "" Then d = "example.com"
    GetThreatHuntDnsQueryDomain = d
End Function

Function ReadDWORDValueRoot(rootKey, keyPath, valueName, defaultValue)
    Dim val, rc
    val = defaultValue
    On Error Resume Next
    rc = objRegistry.GetDWORDValue(rootKey, keyPath, valueName, val)
    If Err.Number <> 0 Or rc <> 0 Then
        ReadDWORDValueRoot = defaultValue
        Err.Clear
    Else
        ReadDWORDValueRoot = CLng(0 + val)
    End If
    On Error Goto 0
End Function

Function ReadRegistryTextValueRoot(rootKey, keyPath, valueName, defaultValue)
    Dim val, rc, arr
    val = ""
    On Error Resume Next
    rc = objRegistry.GetStringValue(rootKey, keyPath, valueName, val)
    If Err.Number = 0 And rc = 0 Then ReadRegistryTextValueRoot = Nz(val, defaultValue): On Error Goto 0: Exit Function
    Err.Clear
    rc = objRegistry.GetExpandedStringValue(rootKey, keyPath, valueName, val)
    If Err.Number = 0 And rc = 0 Then ReadRegistryTextValueRoot = Nz(val, defaultValue): On Error Goto 0: Exit Function
    Err.Clear
    rc = objRegistry.GetMultiStringValue(rootKey, keyPath, valueName, arr)
    If Err.Number = 0 And rc = 0 And IsArray(arr) Then ReadRegistryTextValueRoot = Join(arr, "; "): On Error Goto 0: Exit Function
    Err.Clear
    ReadRegistryTextValueRoot = defaultValue
    On Error Goto 0
End Function

Function RegistryKeyExistsRoot(rootKey, keyPath)
    Dim rc, names, types, subKeys
    On Error Resume Next
    rc = objRegistry.EnumValues(rootKey, keyPath, names, types)
    If Err.Number = 0 And rc = 0 Then RegistryKeyExistsRoot = True: On Error Goto 0: Exit Function
    Err.Clear
    rc = objRegistry.EnumKey(rootKey, keyPath, subKeys)
    RegistryKeyExistsRoot = (Err.Number = 0 And rc = 0)
    Err.Clear
    On Error Goto 0
End Function

Function RegistryValueCount(rootKey, keyPath)
    Dim rc, names, types
    RegistryValueCount = 0
    On Error Resume Next
    rc = objRegistry.EnumValues(rootKey, keyPath, names, types)
    If Err.Number = 0 And rc = 0 And IsArray(names) Then RegistryValueCount = UBound(names) - LBound(names) + 1
    Err.Clear
    On Error Goto 0
End Function

Function RegistrySubKeyCount(rootKey, keyPath)
    Dim rc, subKeys
    RegistrySubKeyCount = 0
    On Error Resume Next
    rc = objRegistry.EnumKey(rootKey, keyPath, subKeys)
    If Err.Number = 0 And rc = 0 And IsArray(subKeys) Then RegistrySubKeyCount = UBound(subKeys) - LBound(subKeys) + 1
    Err.Clear
    On Error Goto 0
End Function

Function RegistryServiceStartName(v)
    Select Case CLng(0 + v)
        Case 0: RegistryServiceStartName = "Boot"
        Case 1: RegistryServiceStartName = "System"
        Case 2: RegistryServiceStartName = "Auto"
        Case 3: RegistryServiceStartName = "Manual"
        Case 4: RegistryServiceStartName = "Disabled"
        Case Else: RegistryServiceStartName = CStr(v)
    End Select
End Function

Function BatteryStatusName(v)
    Select Case CLng(0 + v)
        Case 1: BatteryStatusName = "Discharging"
        Case 2: BatteryStatusName = "AC / Not charging"
        Case 3: BatteryStatusName = "Fully charged"
        Case 4: BatteryStatusName = "Low"
        Case 5: BatteryStatusName = "Critical"
        Case 6: BatteryStatusName = "Charging"
        Case 7: BatteryStatusName = "Charging High"
        Case 8: BatteryStatusName = "Charging Low"
        Case 9: BatteryStatusName = "Charging Critical"
        Case 11: BatteryStatusName = "Partially charged"
        Case Else: BatteryStatusName = Nz(v, "-")
    End Select
End Function

Function BatteryChemistryName(v)
    Select Case CLng(0 + v)
        Case 1: BatteryChemistryName = "Other"
        Case 2: BatteryChemistryName = "Unknown"
        Case 3: BatteryChemistryName = "Lead Acid"
        Case 4: BatteryChemistryName = "NiCd"
        Case 5: BatteryChemistryName = "NiMH"
        Case 6: BatteryChemistryName = "Li-ion"
        Case 7: BatteryChemistryName = "Zinc Air"
        Case 8: BatteryChemistryName = "Li-Poly"
        Case Else: BatteryChemistryName = Nz(v, "-")
    End Select
End Function
Sub WriteIdentityUsersSection()
    Dim colOS, os, regOwner, regOrg
    Dim usersPath, usersFolder, sf, colUsers, u, colGroups, g, colProfiles, up, profilePath, profileName, lastUseTxt

    objFile.WriteLine "<section id='identidade' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Identidade do sistema, contas locais e grupos (contexto forense)</h2>"

    Set colOS = objWMI.ExecQuery("SELECT * FROM Win32_OperatingSystem")
    For Each os In colOS
        objFile.WriteLine "<table><tr><th>Campo</th><th>Valor</th></tr>"
        WriteKV "Dispositivo de boot (origem de inicializacao)", os.BootDevice
        WriteKV "Diretorio de instalacao", os.WindowsDirectory
        WriteKV "Fuso horario (offset atual)", ParseTimeZoneOffset(os.CurrentTimeZone)
        WriteKV "Idioma do sistema (LCID)", ParseWindowsLanguageCode(os.OSLanguage)
        WriteKV "Usuario registrado no SO (WMI)", os.RegisteredUser
        WriteKV "Organizacao registrada no SO (WMI)", os.Organization
        objFile.WriteLine "</table>"
    Next

    regOwner = ReadStringValue("SOFTWARE\Microsoft\Windows NT\CurrentVersion", "RegisteredOwner", "-")
    regOrg = ReadStringValue("SOFTWARE\Microsoft\Windows NT\CurrentVersion", "RegisteredOrganization", "-")
    objFile.WriteLine "<table><tr><th>Registro (metadado do SO)</th><th>Valor</th></tr>"
    WriteKV "Proprietario registrado (Registry)", regOwner
    WriteKV "Organizacao registrada (Registry)", regOrg
    objFile.WriteLine "</table>"

    usersPath = objShell.ExpandEnvironmentStrings("%SystemDrive%") & "\Users"
    objFile.WriteLine "<h3>Perfis encontrados em C:\Users</h3>"
    objFile.WriteLine "<table><tr><th>Pasta de Perfil</th><th>Data criacao</th><th>Data Ultima modificacao</th></tr>"
    If objFSO.FolderExists(usersPath) Then
        Set usersFolder = objFSO.GetFolder(usersPath)
        For Each sf In usersFolder.SubFolders
            objFile.WriteLine "<tr><td>" & HtmlEncode(sf.Name) & "</td><td>" & HtmlEncode(sf.DateCreated) & "</td><td>" & HtmlEncode(sf.DateLastModified) & "</td></tr>"
            If IsRelevantUserProfileName(sf.Name) Then AppendDfirTimelineRecordFromDate sf.DateCreated, "Usuario criado", sf.Name, "Criacao de perfil local", "Pasta de perfil em C:\\Users", "FSO:C:\\Users", "INFO"
        Next
    Else
        objFile.WriteLine "<tr><td colspan='3'>Pasta Users nao encontrada.</td></tr>"
    End If
    objFile.WriteLine "</table>"

    objFile.WriteLine "<h3>Usuarios locais registrados</h3>"
    objFile.WriteLine "<table><tr><th>Nome</th><th>SID</th><th>Status</th><th>Conta local</th><th>Ultimo logon</th></tr>"
    Set colUsers = objWMI.ExecQuery("SELECT * FROM Win32_UserAccount WHERE LocalAccount=True")
    For Each u In colUsers
        objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(u.Name, "-")) & "</td><td>" & HtmlEncode(Nz(u.SID, "-")) & "</td><td>" & HtmlEncode(IIfBool(u.Disabled, "Desabilitado", "Habilitado")) & "</td><td>" & HtmlEncode(u.LocalAccount) & "</td><td>-</td></tr>"
    Next
    objFile.WriteLine "</table>"

    objFile.WriteLine "<h3>Perfis de usuario (ultimo acesso via Win32_UserProfile)</h3>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Perfil</th><th>SID</th><th>Ultimo uso</th><th>Loaded</th><th class='location-col'>LocalPath</th></tr>"
    Set colProfiles = objWMI.ExecQuery("SELECT SID,LocalPath,LastUseTime,Loaded,Special FROM Win32_UserProfile")
    For Each up In colProfiles
        If UCase(CStr(SafeWmiProp(up, "Special", "False"))) <> "TRUE" Then
            profilePath = CStr(SafeWmiProp(up, "LocalPath", "-"))
            profileName = GetLeafNameFromPath(profilePath)
            lastUseTxt = WmiDateToString(SafeWmiProp(up, "LastUseTime", ""))
            objFile.WriteLine "<tr><td>" & HtmlEncode(profileName) & "</td><td>" & HtmlEncode(SafeWmiProp(up, "SID", "-")) & "</td><td>" & HtmlEncode(lastUseTxt) & "</td><td>" & HtmlEncode(SafeWmiProp(up, "Loaded", "-")) & "</td><td class='location-col'>" & HtmlEncode(profilePath) & "</td></tr>"
            If lastUseTxt <> "-" And IsRelevantUserProfileName(profileName) Then
                AppendDfirTimelineRecordFromWmi SafeWmiProp(up, "LastUseTime", ""), "Ultimo usuario acessado", profileName, "Ultimo uso de perfil", "SID=" & CStr(SafeWmiProp(up, "SID", "-")) & " | Loaded=" & CStr(SafeWmiProp(up, "Loaded", "-")), "WMI:Win32_UserProfile", "WARN"
            End If
        End If
    Next
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "<h3>Grupos locais</h3>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Grupo</th><th class='location-col'>SID</th><th class='location-col'>Descricao</th></tr>"
    Set colGroups = objWMI.ExecQuery("SELECT * FROM Win32_Group WHERE LocalAccount=True")
    For Each g In colGroups
        objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(g.Name, "-")) & "</td><td class='location-col'>" & HtmlEncode(Nz(g.SID, "-")) & "</td><td class='location-col'>" & HtmlEncode(Nz(g.Description, "-")) & "</td></tr>"
    Next
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "</section>"
End Sub

Sub WriteNetworkDeepSection()
    Dim ipcfg, routeOut, vpnOut
    objFile.WriteLine "<section id='redeplus' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>IP/TCP/DNS/VPN (coleta complementar)</h2>"
    ipcfg = GetCommandOutputWithTimeout("cmd /c ipconfig /all", 60)
    routeOut = GetCommandOutputWithTimeout("cmd /c route print", 30)
    vpnOut = GetCommandOutputWithTimeout("cmd /c rasdial", 30)

    objFile.WriteLine "<table><tr><th>Coleta</th><th>Saida</th></tr>"
    objFile.WriteLine "<tr><td>Configuracao detalhada de rede (ipconfig /all)</td><td><pre>" & HtmlEncode(ipcfg) & "</pre></td></tr>"
    objFile.WriteLine "<tr><td>Tabela de rotas ativa (route print)</td><td><pre>" & HtmlEncode(routeOut) & "</pre></td></tr>"
    objFile.WriteLine "<tr><td>Conexoes VPN discadas ativas (rasdial)</td><td><pre>" & HtmlEncode(vpnOut) & "</pre></td></tr>"
    objFile.WriteLine "</table>"
    objFile.WriteLine "</section>"
End Sub

Sub WritePagingArtifactsSection()
    Dim colPF, pf
    Dim prefetchPath, pfCount, pfBytes, pfDirs
    Dim shadowOut

    objFile.WriteLine "<section id='artefatos' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Pagefile, Prefetch, artefatos e snapshots</h2>"

    objFile.WriteLine "<h3>Detalhes de paginacao</h3>"
    objFile.WriteLine "<table><tr><th>Nome</th><th>Alocado MB</th><th>Uso atual MB</th><th>Pico MB</th><th>Temp MB</th></tr>"
    Set colPF = objWMI.ExecQuery("SELECT * FROM Win32_PageFileUsage")
    For Each pf In colPF
        objFile.WriteLine "<tr><td>" & HtmlEncode(SafeWmiProp(pf, "Name", SafeWmiProp(pf, "Description", "-"))) & "</td><td>" & SafeWmiProp(pf, "AllocatedBaseSize", "-") & "</td><td>" & SafeWmiProp(pf, "CurrentUsage", "-") & "</td><td>" & SafeWmiProp(pf, "PeakUsage", "-") & "</td><td>" & SafeWmiProp(pf, "TemporaryPageFile", "-") & "</td></tr>"
    Next
    objFile.WriteLine "</table>"

    prefetchPath = objShell.ExpandEnvironmentStrings("%SystemRoot%") & "\Prefetch"
    CountFolderStats prefetchPath, pfCount, pfDirs, pfBytes
    objFile.WriteLine "<table><tr><th colspan='2'>Prefetch</th></tr>"
    WriteKV "Caminho", prefetchPath
    WriteKV "Total de arquivos", pfCount
    WriteKV "Total de subpastas", pfDirs
    WriteKV "Tamanho total", FormatBytes(pfBytes)
    objFile.WriteLine "</table>"

    shadowOut = GetCommandOutput("cmd /c vssadmin list shadows")
    objFile.WriteLine "<div class='scroll-table snap-no-wrap'><table><tr><th>Snapshots (VSS)</th></tr><tr><td><pre class='snap-pre'>" & HtmlEncode(shadowOut) & "</pre></td></tr></table></div>"
    objFile.WriteLine "</section>"
End Sub

Sub WriteControllersBackupSection()
    Dim colIDE, ide, colSCSI, scsi, colTape, tape, colDiskCtl, dc

    objFile.WriteLine "<section id='controladores' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Controladores de disco, backup e historico de unidades</h2>"

    objFile.WriteLine "<h3>Controladores IDE/SCSI</h3>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Tipo</th><th>Nome</th><th>Fabricante</th><th class='location-col'>PNPDeviceID</th></tr>"
    Set colIDE = objWMI.ExecQuery("SELECT * FROM Win32_IDEController")
    For Each ide In colIDE
        objFile.WriteLine "<tr><td>IDE</td><td>" & HtmlEncode(Nz(ide.Name, "-")) & "</td><td>" & HtmlEncode(Nz(ide.Manufacturer, "-")) & "</td><td class='location-col'>" & HtmlEncode(Nz(ide.PNPDeviceID, "-")) & "</td></tr>"
    Next
    Set colSCSI = objWMI.ExecQuery("SELECT * FROM Win32_SCSIController")
    For Each scsi In colSCSI
        objFile.WriteLine "<tr><td>SCSI</td><td>" & HtmlEncode(Nz(scsi.Name, "-")) & "</td><td>" & HtmlEncode(Nz(scsi.Manufacturer, "-")) & "</td><td class='location-col'>" & HtmlEncode(Nz(scsi.PNPDeviceID, "-")) & "</td></tr>"
    Next
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "<h3>Unidades de backup/tape</h3>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Nome</th><th>Status</th><th class='location-col'>PNPDeviceID</th></tr>"
    Set colTape = objWMI.ExecQuery("SELECT * FROM Win32_TapeDrive")
    For Each tape In colTape
        objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(tape.Name, "-")) & "</td><td>" & HtmlEncode(Nz(tape.Status, "-")) & "</td><td class='location-col'>" & HtmlEncode(Nz(tape.PNPDeviceID, "-")) & "</td></tr>"
    Next
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "<h3>Dispositivos de armazenamento conectados (PnP class DiskDrive)</h3>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Nome</th><th>Fabricante</th><th>Service</th><th class='location-col'>PNPDeviceID</th></tr>"
    Set colDiskCtl = objWMI.ExecQuery("SELECT * FROM Win32_PnPEntity WHERE PNPClass='DiskDrive' OR PNPDeviceID LIKE 'USBSTOR%'")
    For Each dc In colDiskCtl
        objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(dc.Name, "-")) & "</td><td>" & HtmlEncode(Nz(dc.Manufacturer, "-")) & "</td><td>" & HtmlEncode(Nz(dc.Service, "-")) & "</td><td class='location-col'>" & HtmlEncode(Nz(dc.PNPDeviceID, "-")) & "</td></tr>"
    Next
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "</section>"
End Sub

Sub WriteRecentDirTable()
    Dim recentPath, folderObj, f, rowCount, maxItems, truncated

    recentPath = objShell.ExpandEnvironmentStrings("%APPDATA%") & "\Microsoft\Windows\Recent"
    rowCount = 0
    truncated = False
    maxItems = 50

    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Nome</th><th>Extensao</th><th>Tamanho</th><th>Data de criacao</th><th>Ultima gravacao</th><th class='location-col'>Caminho</th></tr>"

    If objFSO.FolderExists(recentPath) = False Then
        objFile.WriteLine "<tr><td colspan='6'>Pasta Recent nao encontrada.</td></tr>"
        objFile.WriteLine "</table></div>"
        Exit Sub
    End If

    On Error Resume Next
    Err.Clear
    Set folderObj = objFSO.GetFolder(recentPath)
    If Err.Number <> 0 Then
        objFile.WriteLine "<tr><td colspan='6'>Falha ao abrir a pasta Recent: " & HtmlEncode(Err.Description) & "</td></tr>"
        objFile.WriteLine "</table></div>"
        Err.Clear
        On Error Goto 0
        Exit Sub
    End If

    For Each f In folderObj.Files
        If rowCount >= maxItems Then
            truncated = True
            Exit For
        End If
        Err.Clear
        objFile.WriteLine "<tr><td>" & HtmlEncode(f.Name) & "</td><td>" & HtmlEncode(objFSO.GetExtensionName(f.Name)) & "</td><td>" & HtmlEncode(FormatBytes(f.Size)) & "</td><td>" & HtmlEncode(CStr(f.DateCreated)) & "</td><td>" & HtmlEncode(CStr(f.DateLastModified)) & "</td><td class='location-col'>" & HtmlEncode(f.Path) & "</td></tr>"
        If Err.Number = 0 Then
            rowCount = rowCount + 1
        Else
            Err.Clear
        End If
    Next
    On Error Goto 0

    If rowCount = 0 Then
        objFile.WriteLine "<tr><td colspan='6'>Nenhum item listado foi lido com sucesso.</td></tr>"
    ElseIf truncated Then
        objFile.WriteLine "<tr><td colspan='6'><span class='warn'>Exibicao limitada a " & maxItems & " itens para reduzir tempo de coleta/renderizacao da pasta Recent.</span></td></tr>"
    End If

    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"
End Sub
Sub WriteServicesSection()
    Dim colSvc, svc, autoCnt, manualCnt, disabledCnt, runningCnt, stoppedCnt
    autoCnt = 0: manualCnt = 0: disabledCnt = 0: runningCnt = 0: stoppedCnt = 0
    serviceTotalCount = 0: serviceRunningCount = 0: serviceStoppedCount = 0

    objFile.WriteLine "<section id='servicos' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Servicos detalhados</h2>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Service</th><th>DisplayName</th><th>Startup</th><th>Status</th><th>Usuario</th><th class='location-col'>Path</th><th>PID</th></tr>"
    Set colSvc = objWMI.ExecQuery("SELECT * FROM Win32_Service")
    For Each svc In colSvc
        serviceTotalCount = serviceTotalCount + 1
        If LCase(Nz(svc.StartMode, "")) = "auto" Then autoCnt = autoCnt + 1
        If LCase(Nz(svc.StartMode, "")) = "manual" Then manualCnt = manualCnt + 1
        If LCase(Nz(svc.StartMode, "")) = "disabled" Then disabledCnt = disabledCnt + 1
        If LCase(Nz(svc.State, "")) = "running" Then runningCnt = runningCnt + 1: serviceRunningCount = serviceRunningCount + 1
        If LCase(Nz(svc.State, "")) = "stopped" Then stoppedCnt = stoppedCnt + 1: serviceStoppedCount = serviceStoppedCount + 1
        objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(svc.Name, "-")) & "</td><td>" & HtmlEncode(Nz(svc.DisplayName, "-")) & "</td><td>" & HtmlEncode(Nz(svc.StartMode, "-")) & "</td><td>" & HtmlEncode(Nz(svc.State, "-")) & "</td><td>" & HtmlEncode(Nz(svc.StartName, "-")) & "</td><td class='location-col'>" & HtmlEncode(Nz(svc.PathName, "-")) & "</td><td>" & Nz(svc.ProcessId, "-") & "</td></tr>"
    Next
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "<canvas id='serviceChart' height='90'></canvas>"
    objFile.WriteLine "<script>new Chart(document.getElementById('serviceChart'),{type:'bar',data:{labels:['Auto','Manual','Disabled','Running','Stopped'],datasets:[{label:'Servicos',data:[" & autoCnt & "," & manualCnt & "," & disabledCnt & "," & runningCnt & "," & stoppedCnt & "],backgroundColor:['#38bdf8','#f59e0b','#ef4444','#22c55e','#94a3b8']}]},options:{plugins:{legend:{labels:{color:'#e2e8f0'}}},scales:{x:{ticks:{color:'#cbd5e1'}},y:{ticks:{color:'#cbd5e1'}}}}});</script>"
    objFile.WriteLine "</section>"
End Sub

Sub WriteSharesPortsPrintersSection()
    Dim colShare, sh, colDrv, drv
    Dim portsOut

    objFile.WriteLine "<section id='shares' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Compartilhamentos, portas abertas e impressao</h2>"

    objFile.WriteLine "<h3>Compartilhamentos locais</h3>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Nome</th><th class='location-col'>Path</th><th class='location-col'>Descricao</th><th>Tipo</th></tr>"
    Set colShare = objWMI.ExecQuery("SELECT * FROM Win32_Share")
    For Each sh In colShare
        objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(sh.Name, "-")) & "</td><td class='location-col'>" & HtmlEncode(Nz(sh.Path, "-")) & "</td><td class='location-col'>" & HtmlEncode(Nz(sh.Description, "-")) & "</td><td>" & HtmlEncode(FormatShareType(sh.Type)) & "</td></tr>"
    Next
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    portsOut = GetCommandOutput("cmd /c netstat -ano -p tcp")
    objFile.WriteLine "<h3>Portas TCP abertas (atencao para servicos expostos)</h3>"
    objFile.WriteLine "<table><tr><th>Saida netstat</th></tr><tr><td><pre>" & HtmlEncode(portsOut) & "</pre></td></tr></table>"
    objFile.WriteLine "<table><tr><th>Portas potencialmente sensiveis expostas</th></tr><tr><td><pre>" & HtmlEncode(ExtractSensitivePorts(portsOut)) & "</pre></td></tr></table>"

    objFile.WriteLine "<h3>Drivers de impressora</h3>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Nome</th><th>Versao</th><th>Fabricante</th><th class='location-col'>Path</th></tr>"
    Set colDrv = objWMI.ExecQuery("SELECT * FROM Win32_PrinterDriver")
    For Each drv In colDrv
        objFile.WriteLine "<tr><td>" & HtmlEncode(SafeWmiProp(drv, "Name", "-")) & "</td><td>" & HtmlEncode(GetPrinterDriverVersion(drv)) & "</td><td>" & HtmlEncode(SafeWmiProp(drv, "Manufacturer", "-")) & "</td><td class='location-col'>" & HtmlEncode(SafeWmiProp(drv, "DriverPath", SafeWmiProp(drv, "InfName", "-"))) & "</td></tr>"
    Next
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "</section>"
End Sub

Sub WriteExecutionArtifactsSection()
    Dim prefetchPath, fileCount, bytesTotal, rowsHtml, errMsg

    objFile.WriteLine "<section id='execucao' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Primeira/Ultima execucao (aproximacao por artefatos)</h2>"

    prefetchPath = objShell.ExpandEnvironmentStrings("%SystemRoot%") & "\Prefetch"
    rowsHtml = GetPrefetchTableRowsFromDir(prefetchPath, fileCount, bytesTotal, errMsg)

    objFile.WriteLine "<h3>Volumetria da pasta Prefetch</h3>"
    objFile.WriteLine "<table><tr><th>Artefato</th><th>Valor</th></tr>"
    WriteKV "Caminho da pasta Prefetch", prefetchPath
    WriteKV "Quantidade de arquivos .pf", fileCount
    WriteKV "Tamanho total dos arquivos .pf", FormatBytes(bytesTotal)
    If Trim(errMsg) <> "" Then
        WriteKV "Observacao da coleta", errMsg
    Else
        WriteKV "Origem da coleta", "cmd /c dir (sem PowerShell)"
    End If
    objFile.WriteLine "</table>"

    objFile.WriteLine "<h3>Indicadores relevantes de execucao (triagem rapida)</h3>"
    WriteExecutionArtifactHighlights prefetchPath

    objFile.WriteLine "<h3>Arquivos Prefetch (.pf)</h3>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Nome</th><th>Data de criacao</th><th>Ultima gravao (Last Write)</th><th>Tamanho</th></tr>"
    If Trim(rowsHtml) = "" Then
        objFile.WriteLine "<tr><td colspan='4'>Nenhum arquivo .pf encontrado ou sem permissao de leitura.</td></tr>"
    Else
        objFile.WriteLine rowsHtml
    End If
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "</section>"
End Sub

Sub WriteExecutionArtifactHighlights(prefetchPath)
    Dim folderObj, f, firstWrite, lastWrite, hasAny
    Dim progDict, progName, recentPath, autoDestPath, customDestPath
    Dim recentFiles, recentDirs, recentBytes, autoFiles, autoDirs, autoBytes, customFiles, customDirs, customBytes
    Dim topRows, keys, i, k

    hasAny = False
    Set progDict = CreateObject("Scripting.Dictionary")

    On Error Resume Next
    Err.Clear
    If objFSO.FolderExists(prefetchPath) Then
        Set folderObj = objFSO.GetFolder(prefetchPath)
        If Err.Number = 0 Then
            For Each f In folderObj.Files
                If LCase(objFSO.GetExtensionName(CStr(f.Name))) = "pf" Then
                    hasAny = True
                    If Not IsDate(firstWrite) Then firstWrite = f.DateLastModified
                    If Not IsDate(lastWrite) Then lastWrite = f.DateLastModified
                    If f.DateLastModified < firstWrite Then firstWrite = f.DateLastModified
                    If f.DateLastModified > lastWrite Then lastWrite = f.DateLastModified

                    progName = UCase(Trim(CStr(PrefetchProgramNameFromPf(f.Name))))
                    If progName = "" Then progName = "(PF)"
                    If progDict.Exists(progName) Then
                        progDict(progName) = CLng(0 + progDict(progName)) + 1
                    Else
                        progDict.Add progName, 1
                    End If
                End If
                If Err.Number <> 0 Then Err.Clear
            Next
        Else
            Err.Clear
        End If
    End If
    On Error Goto 0

    recentPath = objShell.ExpandEnvironmentStrings("%APPDATA%") & "\Microsoft\Windows\Recent"
    autoDestPath = recentPath & "\AutomaticDestinations"
    customDestPath = recentPath & "\CustomDestinations"
    CountFolderStats recentPath, recentFiles, recentDirs, recentBytes
    CountFolderStats autoDestPath, autoFiles, autoDirs, autoBytes
    CountFolderStats customDestPath, customFiles, customDirs, customBytes

    objFile.WriteLine "<div class='grid'>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & IIfBool(hasAny, HtmlEncode(FormatDateTimeLocal(firstWrite)), "-") & "</div><div class='kpi-label'>Prefetch mais antigo (LastWrite)</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & IIfBool(hasAny, HtmlEncode(FormatDateTimeLocal(lastWrite)), "-") & "</div><div class='kpi-label'>Prefetch mais recente (LastWrite)</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & progDict.Count & "</div><div class='kpi-label'>Programas distintos no Prefetch</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & recentFiles & "</div><div class='kpi-label'>Arquivos em Recent (recursivo)</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & autoFiles & "</div><div class='kpi-label'>Jump Lists AutoDestinations</div></div>"
    objFile.WriteLine "<div class='card'><div class='kpi'>" & customFiles & "</div><div class='kpi-label'>Jump Lists CustomDestinations</div></div>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "<table><tr><th>Artefato de usuario</th><th>Caminho</th><th>Arquivos</th><th>Subpastas</th><th>Tamanho</th></tr>"
    objFile.WriteLine "<tr><td>Recent</td><td class='location-col'>" & HtmlEncode(recentPath) & "</td><td>" & recentFiles & "</td><td>" & recentDirs & "</td><td>" & HtmlEncode(FormatBytes(recentBytes)) & "</td></tr>"
    objFile.WriteLine "<tr><td>AutomaticDestinations</td><td class='location-col'>" & HtmlEncode(autoDestPath) & "</td><td>" & autoFiles & "</td><td>" & autoDirs & "</td><td>" & HtmlEncode(FormatBytes(autoBytes)) & "</td></tr>"
    objFile.WriteLine "<tr><td>CustomDestinations</td><td class='location-col'>" & HtmlEncode(customDestPath) & "</td><td>" & customFiles & "</td><td>" & customDirs & "</td><td>" & HtmlEncode(FormatBytes(customBytes)) & "</td></tr>"
    objFile.WriteLine "</table>"

    topRows = ""
    If progDict.Count > 0 Then
        keys = SortDictKeysByValueDesc(progDict)
        For i = 0 To UBound(keys)
            If i >= 20 Then Exit For
            k = CStr(keys(i))
            topRows = topRows & "<tr><td>" & (i + 1) & "</td><td>" & HtmlEncode(k) & "</td><td>" & CLng(0 + progDict(k)) & "</td></tr>"
        Next
    End If
    If Trim(topRows) = "" Then topRows = "<tr><td colspan='3'>Sem arquivos .pf suficientes para agregacao.</td></tr>"
    objFile.WriteLine "<div class='scroll-table'><table><tr><th>#</th><th>Programa (nome inferido do .pf)</th><th>Ocorrencias</th></tr>" & topRows & "</table></div>"
    objFile.WriteLine "<div class='mini-note'>Interpretacao aproximada: recorrencia em Prefetch sugere execucao historica; datas refletem timestamps do arquivo (<em>nao</em> substituem logs completos de processo).</div>"
End Sub

Function GetPrefetchTableRowsFromDir(prefetchPath, fileCount, bytesTotal, errMsg)
    Dim outList, lines, line, filePath, f, rowsHtml, i

    fileCount = 0
    bytesTotal = 0
    errMsg = ""
    rowsHtml = ""

    If objFSO.FolderExists(prefetchPath) = False Then
        errMsg = "Pasta Prefetch nao encontrada."
        GetPrefetchTableRowsFromDir = ""
        Exit Function
    End If

    outList = GetCommandOutputWithTimeout("cmd /c dir /a:-d /b /o:n """ & prefetchPath & "\*.pf""", 20)
    If Trim(outList) = "" Or UCase(Trim(outList)) = "N/A" Then
        errMsg = "Saida vazia ao listar arquivos .pf via dir."
        GetPrefetchTableRowsFromDir = ""
        Exit Function
    End If

    If InStr(1, outList, "File Not Found", vbTextCompare) > 0 Or InStr(1, outList, "Arquivo Nao Encontrado", vbTextCompare) > 0 Or InStr(1, outList, "Arquivo nao encontrado", vbTextCompare) > 0 Then
        GetPrefetchTableRowsFromDir = ""
        Exit Function
    End If

    lines = Split(outList, vbCrLf)
    On Error Resume Next
    For i = 0 To UBound(lines)
        line = Trim(CStr(lines(i) & ""))
        If line <> "" Then
            If Right(UCase(line), 3) = ".PF" Then
                filePath = prefetchPath & "\" & line
                If objFSO.FileExists(filePath) Then
                    Err.Clear
                    Set f = objFSO.GetFile(filePath)
                    If Err.Number = 0 Then
                        fileCount = fileCount + 1
                        bytesTotal = bytesTotal + CDbl(0 + f.Size)
                        rowsHtml = rowsHtml & "<tr><td>" & HtmlEncode(f.Name) & "</td><td>" & HtmlEncode(CStr(f.DateCreated)) & "</td><td>" & HtmlEncode(CStr(f.DateLastModified)) & "</td><td>" & HtmlEncode(FormatBytes(f.Size)) & "</td></tr>"
                        If Not prefetchTimelineCaptured Then AppendDfirTimelineRecordFromDate f.DateLastModified, "Programas ultima execucao", PrefetchProgramNameFromPf(f.Name), "Ultima execucao (aprox. Prefetch)", "PF=" & f.Name & " | Tamanho=" & FormatBytes(f.Size), "FSO:Prefetch", "INFO"
                    Else
                        Err.Clear
                    End If
                End If
            End If
        End If
    Next
    On Error Goto 0

    If fileCount = 0 And Trim(rowsHtml) = "" Then
        errMsg = "Nenhum arquivo .pf foi interpretado a partir do dir."
    End If

    If Not prefetchTimelineCaptured Then prefetchTimelineCaptured = True
    GetPrefetchTableRowsFromDir = rowsHtml
End Function

Sub ParseDirPrefetchOutput(dirOutput, stampMap, sizeMap, fileCount, bytesTotal)
    Dim lines, line, stampText, sizeText, fileName, i, sizeNum
    fileCount = 0
    bytesTotal = 0
    If Trim(CStr(dirOutput & "")) = "" Then Exit Sub

    lines = Split(dirOutput, vbCrLf)
    For i = 0 To UBound(lines)
        line = lines(i)
        stampText = "": sizeText = "": fileName = ""
        If TryParseDirFileLine(line, stampText, sizeText, fileName) Then
            If Right(UCase(fileName), 3) = ".PF" Then
                If Not stampMap.Exists(fileName) Then stampMap.Add fileName, stampText Else stampMap(fileName) = stampText
                If Not (sizeMap Is Nothing) Then
                    sizeNum = CDbl(0)
                    If IsNumeric(sizeText) Then sizeNum = CDbl(sizeText)
                    If Not sizeMap.Exists(fileName) Then
                        sizeMap.Add fileName, sizeNum
                    Else
                        sizeMap(fileName) = sizeNum
                    End If
                    fileCount = fileCount + 1
                    bytesTotal = bytesTotal + sizeNum
                End If
            End If
        End If
    Next
End Sub

Function TryParseDirFileLine(line, stampText, sizeText, fileName)
    Dim s, parts, idxSize, t2
    TryParseDirFileLine = False
    stampText = "": sizeText = "": fileName = ""

    s = Trim(CStr(line & ""))
    If s = "" Then Exit Function
    If InStr(1, s, "Directory of", vbTextCompare) > 0 Then Exit Function
    If InStr(1, s, "Diretorio de", vbTextCompare) > 0 Then Exit Function
    If InStr(1, s, "Volume in drive", vbTextCompare) > 0 Then Exit Function
    If InStr(1, s, "O volume na unidade", vbTextCompare) > 0 Then Exit Function
    If InStr(1, s, "File(s)", vbTextCompare) > 0 Then Exit Function
    If InStr(1, s, "Arquivo(s)", vbTextCompare) > 0 Then Exit Function
    If InStr(1, s, "Dir(s)", vbTextCompare) > 0 Then Exit Function
    If InStr(1, s, "Pasta(s)", vbTextCompare) > 0 Then Exit Function

    s = CollapseSpaces(s)
    parts = Split(s, " ")
    If UBound(parts) < 3 Then Exit Function

    idxSize = 2
    t2 = ""
    If UBound(parts) >= 4 Then
        t2 = UCase(parts(2))
        If t2 = "AM" Or t2 = "PM" Or t2 = "A.M." Or t2 = "P.M." Then idxSize = 3
    End If

    If idxSize > UBound(parts) - 1 Then Exit Function
    If UCase(parts(idxSize)) = "<DIR>" Then Exit Function
    If Not IsNumeric(parts(idxSize)) Then Exit Function

    stampText = parts(0) & " " & parts(1)
    If idxSize = 3 Then stampText = stampText & " " & parts(2)
    sizeText = parts(idxSize)
    fileName = JoinTokensPlain(parts, idxSize + 1)
    If Trim(fileName) = "" Then Exit Function

    TryParseDirFileLine = True
End Function

Function CollapseSpaces(s)
    Dim t
    t = Trim(CStr(s & ""))
    Do While InStr(t, "  ") > 0
        t = Replace(t, "  ", " ")
    Loop
    CollapseSpaces = t
End Function

Function JoinTokensPlain(arr, startIdx)
    Dim i, acc
    acc = ""
    For i = startIdx To UBound(arr)
        If acc <> "" Then acc = acc & " "
        acc = acc & arr(i)
    Next
    JoinTokensPlain = acc
End Function

Sub WriteSoftwareSection()
    objFile.WriteLine "<section id='apps' class='card' style='margin-top:16px'>"
    objFile.WriteLine "<h2>Softwares instalados e persistencia (forense)</h2>"

    objFile.WriteLine "<h3>Softwares instalados (Registry)</h3>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th class='location-col'>Nome</th><th>Versao</th><th>Publicador</th><th>Instalacao</th></tr>"
    ListInstalledSoftware "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
    ListInstalledSoftware "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "<h3>Softwares de criptografia (deteccao por nome)</h3>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th class='location-col'>Nome</th><th>Versao</th><th>Publisher</th></tr>"
    ListCryptoSoftware "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\"
    ListCryptoSoftware "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\"
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "<h3>Entradas de inicializacao automatica</h3>"
    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Nome</th><th>Comando</th><th class='location-col'>Localizacao</th><th>Usuario</th></tr>"
    ListStartupCommands
    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"

    objFile.WriteLine "</section>"
End Sub

Sub ListInstalledSoftware(baseKey)
    Dim subKeys, subKey, displayName, displayVersion, publisher, installDate, rc
    rc = objRegistry.EnumKey(HKLM, baseKey, subKeys)
    If rc <> 0 Then Exit Sub
    If IsArray(subKeys) = False Then Exit Sub

    For Each subKey In subKeys
        displayName = "": displayVersion = "": publisher = "": installDate = ""
        objRegistry.GetStringValue HKLM, baseKey & subKey, "DisplayName", displayName
        objRegistry.GetStringValue HKLM, baseKey & subKey, "DisplayVersion", displayVersion
        objRegistry.GetStringValue HKLM, baseKey & subKey, "Publisher", publisher
        objRegistry.GetStringValue HKLM, baseKey & subKey, "InstallDate", installDate

        If Trim(displayName) <> "" Then
            objFile.WriteLine "<tr><td class='location-col'>" & HtmlEncode(displayName) & "</td><td>" & HtmlEncode(Nz(displayVersion, "-")) & "</td><td>" & HtmlEncode(Nz(publisher, "-")) & "</td><td>" & HtmlEncode(NormalizeInstallDate(installDate)) & "</td></tr>"
        End If
    Next
End Sub

Sub ListStartupCommands()
    Dim colStart, st, loc
    Set colStart = objWMI.ExecQuery("SELECT * FROM Win32_StartupCommand")
    For Each st In colStart
        loc = HtmlEncode(Nz(st.Location, "-"))
        loc = Replace(loc, ";", ";<br>")
        loc = Replace(loc, ",", ",<br>")
        objFile.WriteLine "<tr><td>" & HtmlEncode(Nz(st.Name, "-")) & "</td><td class='location-col'>" & HtmlEncode(Nz(st.Command, "-")) & "</td><td class='location-col'>" & loc & "</td><td>" & HtmlEncode(Nz(st.User, "-")) & "</td></tr>"
    Next
End Sub

Sub ListLocalAdministrators()
    Dim grp, member
    On Error Resume Next
    Set grp = GetObject("WinNT://" & strComputer & "/Administrators,group")
    If Err.Number <> 0 Then
        objFile.WriteLine "<tr><td colspan='2'>Nao foi possivel enumerar grupo Administrators: " & HtmlEncode(Err.Description) & "</td></tr>"
        Err.Clear
        Exit Sub
    End If

    For Each member In grp.Members
        objFile.WriteLine "<tr><td>" & HtmlEncode(member.Name) & "</td><td>" & HtmlEncode(member.ADsPath) & "</td></tr>"
    Next
End Sub

Sub CountFolderStats(path, totalFiles, totalDirs, totalBytes)
    Dim folder
    totalFiles = 0: totalDirs = 0: totalBytes = 0
    If objFSO.FolderExists(path) = False Then Exit Sub
    Set folder = objFSO.GetFolder(path)
    WalkFolder folder, totalFiles, totalDirs, totalBytes
End Sub

Sub WalkFolder(folderObj, totalFiles, totalDirs, totalBytes)
    Dim f, sf
    On Error Resume Next
    For Each f In folderObj.Files
        totalFiles = totalFiles + 1
        totalBytes = totalBytes + CDbl(0 + f.Size)
    Next
    For Each sf In folderObj.SubFolders
        totalDirs = totalDirs + 1
        WalkFolder sf, totalFiles, totalDirs, totalBytes
    Next
End Sub


Sub ListCryptoSoftware(baseKey)
    Dim subKeys, subKey, displayName, displayVersion, publisher, rc, n
    rc = objRegistry.EnumKey(HKLM, baseKey, subKeys)
    If rc <> 0 Then Exit Sub
    If IsArray(subKeys) = False Then Exit Sub
    For Each subKey In subKeys
        displayName = "": displayVersion = "": publisher = ""
        objRegistry.GetStringValue HKLM, baseKey & subKey, "DisplayName", displayName
        objRegistry.GetStringValue HKLM, baseKey & subKey, "DisplayVersion", displayVersion
        objRegistry.GetStringValue HKLM, baseKey & subKey, "Publisher", publisher
        n = UCase(displayName)
        If InStr(n, "BITLOCKER") > 0 Or InStr(n, "VERACRYPT") > 0 Or InStr(n, "TRUECRYPT") > 0 Or InStr(n, "SYMANTEC ENCRYPTION") > 0 Or InStr(n, "MCAFEE DRIVE ENCRYPTION") > 0 Or InStr(n, "SOPHOS SAFEGUARD") > 0 Then
            objFile.WriteLine "<tr><td class='location-col'>" & HtmlEncode(displayName) & "</td><td>" & HtmlEncode(Nz(displayVersion, "-")) & "</td><td>" & HtmlEncode(Nz(publisher, "-")) & "</td></tr>"
        End If
    Next
End Sub

Function ReadStringValue(keyPath, valueName, defaultValue)
    Dim val, rc
    val = ""
    rc = objRegistry.GetStringValue(HKLM, keyPath, valueName, val)
    If rc <> 0 Then
        ReadStringValue = defaultValue
    Else
        ReadStringValue = Nz(val, defaultValue)
    End If
End Function

Function IIfBool(b, t, f)
    If CBool(b) Then
        IIfBool = t
    Else
        IIfBool = f
    End If
End Function

Sub WriteKV(k, v)
    objFile.WriteLine "<tr><td>" & HtmlEncode(CStr(k)) & "</td><td>" & HtmlEncode(Nz(v, "-")) & "</td></tr>"
End Sub

Sub WriteKVHtml(k, htmlV)
    objFile.WriteLine "<tr><td>" & HtmlEncode(CStr(k)) & "</td><td>" & Nz(htmlV, "-") & "</td></tr>"
End Sub

Function HtmlPre(s)
    HtmlPre = "<pre>" & HtmlEncode(Nz(s, "-")) & "</pre>"
End Function

Function Nz(v, fallback)
    If IsNull(v) Or IsEmpty(v) Then
        Nz = fallback
    ElseIf Trim(CStr(v)) = "" Then
        Nz = fallback
    Else
        Nz = CStr(v)
    End If
End Function

Function StripControlChars(s)
    Dim t, i, ch, code, out
    t = CStr(s)
    out = ""
    For i = 1 To Len(t)
        ch = Mid(t, i, 1)
        code = AscW(ch)
        If code < 0 Then code = code + 65536
        If code = 9 Or code = 10 Or code = 13 Or code >= 32 Then
            out = out & ch
        End If
    Next
    StripControlChars = out
End Function

Function HtmlEncode(s)
    Dim t
    t = StripControlChars(CStr(s))
    t = Replace(t, "&", "&amp;")
    t = Replace(t, "<", "&lt;")
    t = Replace(t, ">", "&gt;")
    t = Replace(t, Chr(34), "&quot;")
    t = Replace(t, "'", "&#39;")
    HtmlEncode = HtmlAsciiSafe(t)
End Function

Function HtmlAsciiSafe(s)
    Dim t, i, ch, code, out
    t = CStr(Nz(s, ""))
    out = ""
    For i = 1 To Len(t)
        ch = Mid(t, i, 1)
        code = AscW(ch)
        If code < 0 Then code = code + 65536

        ' Evita erro de escrita ANSI (FSO TextStream) com surrogates/caracteres fora de codepage
        If (code >= &HD800 And code <= &HDFFF) Then
            out = out & "&#65533;"
        ElseIf code > 126 Then
            out = out & "&#" & CStr(code) & ";"
        Else
            out = out & ch
        End If
    Next
    HtmlAsciiSafe = out
End Function

Function FormatBytes(v)
    Dim n
    If Not IsNumeric(v) Then
        FormatBytes = "-"
        Exit Function
    End If
    n = CDbl(v)
    If n <= 0 Then
        FormatBytes = "0 B"
    ElseIf n < 1024 Then
        FormatBytes = CLng(n) & " B"
    ElseIf n < 1024^2 Then
        FormatBytes = FormatNumber(n / 1024, 2) & " KB"
    ElseIf n < 1024^3 Then
        FormatBytes = FormatNumber(n / (1024^2), 2) & " MB"
    ElseIf n < 1024^4 Then
        FormatBytes = FormatNumber(n / (1024^3), 2) & " GB"
    Else
        FormatBytes = FormatNumber(n / (1024^4), 2) & " TB"
    End If
End Function

Function WmiDateToString(d)
    If Len(d & "") >= 14 Then
        WmiDateToString = Mid(d, 7, 2) & "/" & Mid(d, 5, 2) & "/" & Left(d, 4) & " " & Mid(d, 9, 2) & ":" & Mid(d, 11, 2) & ":" & Mid(d, 13, 2)
    Else
        WmiDateToString = Nz(d, "-")
    End If
End Function

Function TryParseWmiDateValue(wmiDate, ByRef outDt)
    Dim s
    TryParseWmiDateValue = False
    s = CStr(Nz(wmiDate, ""))
    If Len(s) < 14 Then Exit Function

    On Error Resume Next
    Err.Clear
    outDt = DateSerial(CLng(Left(s, 4)), CLng(Mid(s, 5, 2)), CLng(Mid(s, 7, 2))) + _
        TimeSerial(CLng(Mid(s, 9, 2)), CLng(Mid(s, 11, 2)), CLng(Mid(s, 13, 2)))
    If Err.Number = 0 Then
        TryParseWmiDateValue = True
    Else
        Err.Clear
    End If
    On Error Goto 0
End Function

Function HumanizeDateDistancePt(dt)
    Dim deltaDays
    If Not IsDate(dt) Then
        HumanizeDateDistancePt = "-"
        Exit Function
    End If

    deltaDays = DateDiff("d", DateValue(CDate(dt)), Date)
    Select Case CLng(0 + deltaDays)
        Case 0
            HumanizeDateDistancePt = "hoje"
        Case 1
            HumanizeDateDistancePt = "ontem"
        Case -1
            HumanizeDateDistancePt = "amanha"
        Case Else
            If CLng(0 + deltaDays) > 1 Then
                HumanizeDateDistancePt = "ha " & deltaDays & " dias"
            Else
                HumanizeDateDistancePt = "em " & Abs(CLng(deltaDays)) & " dias"
            End If
    End Select
End Function

Function FormatDateTimeHumanized(dt)
    If Not IsDate(dt) Then
        FormatDateTimeHumanized = "-"
        Exit Function
    End If
    FormatDateTimeHumanized = FormatDateTimeLocal(dt) & " (" & HumanizeDateDistancePt(dt) & ")"
End Function

Function FormatDateHumanized(dt)
    If Not IsDate(dt) Then
        FormatDateHumanized = "-"
        Exit Function
    End If
    FormatDateHumanized = Right("0" & Day(dt), 2) & "/" & Right("0" & Month(dt), 2) & "/" & Year(dt) & " (" & HumanizeDateDistancePt(dt) & ")"
End Function

Function JoinArray(arr, sep)
    Dim out, item
    out = ""
    If IsArray(arr) Then
        For Each item In arr
            If out <> "" Then out = out & sep
            out = out & HtmlEncode(Nz(item, "-"))
        Next
        JoinArray = out
    Else
        JoinArray = HtmlEncode(Nz(arr, "-"))
    End If
End Function

Function DriveTypeName(t)
    Select Case CLng(0 + t)
        Case 1: DriveTypeName = "Sem raiz"
        Case 2: DriveTypeName = "Removivel"
        Case 3: DriveTypeName = "Local"
        Case 4: DriveTypeName = "Rede"
        Case 5: DriveTypeName = "CD/DVD"
        Case 6: DriveTypeName = "RAM Disk"
        Case Else: DriveTypeName = "Desconhecido"
    End Select
End Function

Function EventClass(t)
    Dim m
    m = LCase(Nz(t, ""))
    If m = "error" Then
        EventClass = "bad"
    ElseIf m = "warning" Then
        EventClass = "warn"
    Else
        EventClass = "ok"
    End If
End Function

Function CpuArch(a)
    Select Case CLng(0 + a)
        Case 0: CpuArch = "x86"
        Case 5: CpuArch = "ARM"
        Case 6: CpuArch = "Itanium"
        Case 9: CpuArch = "x64"
        Case Else: CpuArch = "Desconhecida"
    End Select
End Function

Function HumanSpeed(s)
    If Not IsNumeric(s) Then
        HumanSpeed = "-"
    ElseIf CDbl(s) = 0 Then
        HumanSpeed = "-"
    Else
        HumanSpeed = FormatNumber(CDbl(s) / 1000000000, 2) & " Gbps"
    End If
End Function

Function NormalizeInstallDate(v)
    If Len(v & "") = 8 And IsNumeric(v) Then
        NormalizeInstallDate = Mid(v, 7, 2) & "/" & Mid(v, 5, 2) & "/" & Left(v, 4)
    Else
        NormalizeInstallDate = Nz(v, "-")
    End If
End Function

Sub AppendChartData(label, usedGB, freeGB)
    Dim safe
    safe = Replace(label, "'", "\'")
    If diskChartLabels <> "" Then
        diskChartLabels = diskChartLabels & ","
        diskChartUsed = diskChartUsed & ","
        diskChartFree = diskChartFree & ","
    End If
    diskChartLabels = diskChartLabels & "'" & safe & "'"
    diskChartUsed = diskChartUsed & CStr(Int(CDbl(usedGB) * 100) / 100)
    diskChartFree = diskChartFree & CStr(Int(CDbl(freeGB) * 100) / 100)
End Sub

Sub AppendFolderChartData(label, totalFiles)
    Dim safe
    safe = Replace(label, "'", "\'")
    If folderChartLabels <> "" Then
        folderChartLabels = folderChartLabels & ","
        folderChartFiles = folderChartFiles & ","
    End If
    folderChartLabels = folderChartLabels & "'" & safe & "'"
    folderChartFiles = folderChartFiles & CStr(CLng(0 + totalFiles))
End Sub

Function MemoryTypeName(mt)
    Select Case CLng(0 + mt)
        Case 20: MemoryTypeName = "DDR"
        Case 21: MemoryTypeName = "DDR2"
        Case 24: MemoryTypeName = "DDR3"
        Case 26: MemoryTypeName = "DDR4"
        Case 34: MemoryTypeName = "DDR5"
        Case Else: MemoryTypeName = "Tipo " & CLng(0 + mt)
    End Select
End Function

Function NetConnectionStatusName(s)
    Select Case CLng(0 + s)
        Case 0: NetConnectionStatusName = "Desconectado"
        Case 1: NetConnectionStatusName = "Conectando"
        Case 2: NetConnectionStatusName = "Conectado"
        Case 7: NetConnectionStatusName = "Midia desconectada"
        Case Else: NetConnectionStatusName = "Status " & CLng(0 + s)
    End Select
End Function

Function ParseBetween(src, marker, terminator)
    Dim p1, p2, tmp
    ParseBetween = "-"
    p1 = InStr(1, src, marker, vbTextCompare)
    If p1 <= 0 Then Exit Function
    tmp = Mid(src, p1 + Len(marker))
    p2 = InStr(1, tmp, terminator, vbTextCompare)
    If p2 > 1 Then
        ParseBetween = Left(tmp, p2 - 1)
    Else
        ParseBetween = tmp
    End If
End Function

Function ParsePnPSerial(pnpid)
    Dim parts
    ParsePnPSerial = "-"
    parts = Split(pnpid, "\")
    If UBound(parts) >= 2 Then
        ParsePnPSerial = parts(UBound(parts))
    End If
End Function

Function InferDiskType(model, media)
    Dim s
    s = UCase(Nz(model, "") & " " & Nz(media, ""))
    If InStr(s, "SSD") > 0 Or InStr(s, "NVME") > 0 Then
        InferDiskType = "Provavel SSD"
    ElseIf InStr(s, "HDD") > 0 Or InStr(s, "SATA") > 0 Then
        InferDiskType = "Provavel HDD"
    Else
        InferDiskType = "Nao determinado"
    End If
End Function

Function MediaTypeName(m)
    Select Case CLng(0 + m)
        Case 3: MediaTypeName = "HDD"
        Case 4: MediaTypeName = "SSD"
        Case 5: MediaTypeName = "SCM"
        Case Else: MediaTypeName = "Desconhecido(" & CLng(0 + m) & ")"
    End Select
End Function

Function BusTypeName(b)
    Select Case CLng(0 + b)
        Case 1: BusTypeName = "SCSI"
        Case 2: BusTypeName = "ATAPI"
        Case 3: BusTypeName = "ATA"
        Case 7: BusTypeName = "USB"
        Case 10: BusTypeName = "SAS"
        Case 11: BusTypeName = "SATA"
        Case 17: BusTypeName = "NVMe"
        Case Else: BusTypeName = "Bus " & CLng(0 + b)
    End Select
End Function

Function ReadDWORDValue(keyPath, valueName, defaultValue)
    Dim val, rc
    val = defaultValue
    rc = objRegistry.GetDWORDValue(HKLM, keyPath, valueName, val)
    If rc <> 0 Then
        ReadDWORDValue = defaultValue
    Else
        ReadDWORDValue = val
    End If
End Function

Function GetCommandOutput(cmd)
    GetCommandOutput = GetCommandOutputWithTimeout(cmd, 0)
End Function

Function SecondsBetweenTicks(startTick, endTick)
    Dim secs
    secs = CDbl(0 + endTick) - CDbl(0 + startTick)
    If secs < 0 Then secs = secs + 86400
    SecondsBetweenTicks = secs
End Function

Function RemainingGlobalCommandRuntimeSecs()
    Dim elapsedSecs, remainingSecs
    If CLng(0 + GLOBAL_COMMAND_RUNTIME_LIMIT_SECS) <= 0 Then
        RemainingGlobalCommandRuntimeSecs = 0
        Exit Function
    End If
    elapsedSecs = SecondsBetweenTicks(dblScriptStartTick, Timer)
    remainingSecs = CLng(0 + GLOBAL_COMMAND_RUNTIME_LIMIT_SECS) - CLng(Int(elapsedSecs))
    If remainingSecs < 0 Then remainingSecs = 0
    RemainingGlobalCommandRuntimeSecs = remainingSecs
End Function

Function ApplyCommandTimeoutPolicy(requestedTimeoutSecs)
    Dim t, remSecs
    t = CLng(0 + requestedTimeoutSecs)
    If t < 0 Then t = 0

    If VALIDATION_QUERY_TIMEOUT_MODE Then
        If t = 0 Or t > CLng(0 + VALIDATION_QUERY_TIMEOUT_SECS) Then
            t = CLng(0 + VALIDATION_QUERY_TIMEOUT_SECS)
        End If
    End If

    remSecs = RemainingGlobalCommandRuntimeSecs()
    If CLng(0 + GLOBAL_COMMAND_RUNTIME_LIMIT_SECS) > 0 Then
        If remSecs <= 0 Then
            ApplyCommandTimeoutPolicy = 0
            Exit Function
        End If
        If t = 0 Or t > remSecs Then t = remSecs
    End If

    ApplyCommandTimeoutPolicy = t
End Function

Function ShortCommandForLog(cmdText)
    Dim s
    s = CStr(cmdText & "")
    s = Replace(s, vbCr, " ")
    s = Replace(s, vbLf, " ")
    s = Replace(s, vbTab, " ")
    Do While InStr(s, "  ") > 0
        s = Replace(s, "  ", " ")
    Loop
    s = Trim(s)
    If Len(s) > 220 Then s = Left(s, 220) & "..."
    ShortCommandForLog = s
End Function

Function GetCommandOutputWithTimeout(cmd, timeoutSecs)
    Dim ex, out, errOut, startTime, finalOut
    Dim cmdTickStart, cmdLabel, elapsedSecs, resultTag
    On Error Resume Next

    out = ""
    errOut = ""
    finalOut = ""
    resultTag = "OK"
    timeoutSecs = ApplyCommandTimeoutPolicy(timeoutSecs)
    startTime = Now
    cmdTickStart = Timer
    cmdLabel = ShortCommandForLog(cmd)

    If CLng(0 + GLOBAL_COMMAND_RUNTIME_LIMIT_SECS) > 0 And RemainingGlobalCommandRuntimeSecs() <= 0 Then
        cmdTimeoutCount = CLng(0 + cmdTimeoutCount) + 1
        cmdExecCount = CLng(0 + cmdExecCount) + 1
        LogCustody "PESQUISA", "START", "Comando: " & cmdLabel & " | Execucao bloqueada por limite global"
        LogCustody "PESQUISA", "WARN", "Limite global de comandos atingido (" & GLOBAL_COMMAND_RUNTIME_LIMIT_SECS & "s): " & cmdLabel
        LogCustody "PESQUISA", "END", "Comando: " & cmdLabel & " | Resultado: GLOBAL_TIMEOUT_PREVENTIVO"
        GetCommandOutputWithTimeout = "[GLOBAL TIMEOUT APOS " & GLOBAL_COMMAND_RUNTIME_LIMIT_SECS & "s] Execucao de comandos bloqueada para evitar travamento."
        Exit Function
    End If

    cmdExecCount = CLng(0 + cmdExecCount) + 1
    LogCustody "PESQUISA", "START", "Comando: " & cmdLabel

    Set ex = objShell.Exec(cmd)
    If Err.Number <> 0 Then
        cmdFailCount = CLng(0 + cmdFailCount) + 1
        LogCustody "PESQUISA", "BAD", "Falha ao iniciar comando: " & cmdLabel & " | erro: " & Err.Description
        LogCustody "PESQUISA", "END", "Comando: " & cmdLabel & " | Resultado: ERRO_INICIO"
        GetCommandOutputWithTimeout = "Falha ao executar comando: " & Err.Description
        Err.Clear
        Exit Function
    End If

    Do
        Err.Clear
        If Not ex.StdOut.AtEndOfStream Then out = out & ex.StdOut.Read(1024)
        Err.Clear
        If Not ex.StdErr.AtEndOfStream Then errOut = errOut & ex.StdErr.Read(1024)

        If ex.Status <> 0 Then Exit Do

        If timeoutSecs > 0 Then
            If DateDiff("s", startTime, Now) >= timeoutSecs Then
                On Error Resume Next
                ex.Terminate
                Err.Clear
                cmdTimeoutCount = CLng(0 + cmdTimeoutCount) + 1
                elapsedSecs = SecondsBetweenTicks(cmdTickStart, Timer)
                cmdTotalSecs = CDbl(0 + cmdTotalSecs) + elapsedSecs
                LogCustody "PESQUISA", "WARN", "Timeout: " & cmdLabel & " | limite_s: " & timeoutSecs
                LogCustody "PESQUISA", "END", "Comando: " & cmdLabel & " | Resultado: TIMEOUT"
                GetCommandOutputWithTimeout = "[TIMEOUT APOS " & timeoutSecs & "s] Comando interrompido por demora."
                Exit Function
            End If
        End If

        If CLng(0 + GLOBAL_COMMAND_RUNTIME_LIMIT_SECS) > 0 Then
            If RemainingGlobalCommandRuntimeSecs() <= 0 Then
                On Error Resume Next
                ex.Terminate
                Err.Clear
                cmdTimeoutCount = CLng(0 + cmdTimeoutCount) + 1
                elapsedSecs = SecondsBetweenTicks(cmdTickStart, Timer)
                cmdTotalSecs = CDbl(0 + cmdTotalSecs) + elapsedSecs
                LogCustody "PESQUISA", "WARN", "Limite global de comandos atingido (" & GLOBAL_COMMAND_RUNTIME_LIMIT_SECS & "s): " & cmdLabel
                LogCustody "PESQUISA", "END", "Comando: " & cmdLabel & " | Resultado: GLOBAL_TIMEOUT"
                GetCommandOutputWithTimeout = "[GLOBAL TIMEOUT APOS " & GLOBAL_COMMAND_RUNTIME_LIMIT_SECS & "s] Comando interrompido."
                Exit Function
            End If
        End If

        WScript.Sleep 100
    Loop

    Err.Clear
    If Not ex.StdOut.AtEndOfStream Then out = out & ex.StdOut.ReadAll
    Err.Clear
    If Not ex.StdErr.AtEndOfStream Then errOut = errOut & ex.StdErr.ReadAll

    out = Trim(out)
    errOut = Trim(errOut)
    If out <> "" Then
        finalOut = out
        If errOut <> "" Then finalOut = finalOut & vbCrLf & "[stderr]" & vbCrLf & errOut
    Else
        finalOut = errOut
    End If

    If finalOut = "" Then resultTag = "VAZIO"
    elapsedSecs = SecondsBetweenTicks(cmdTickStart, Timer)
    cmdTotalSecs = CDbl(0 + cmdTotalSecs) + elapsedSecs
    LogCustody "PESQUISA", "END", "Comando: " & cmdLabel & " | Resultado: " & resultTag

    GetCommandOutputWithTimeout = Trim(finalOut)
    On Error Goto 0
End Function

Function GetRecentFilesTop(limitCount)
    Dim psCmd, n
    n = CLng(0 + limitCount)
    If n <= 0 Then n = 20
    psCmd = "powershell -NoProfile -Command ""$p = Join-Path $env:APPDATA 'Microsoft\Windows\Recent'; if (Test-Path -LiteralPath $p) { $sh = New-Object -ComObject WScript.Shell; Get-ChildItem -LiteralPath $p -File -Force -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First " & n & " | ForEach-Object { $t=''; $a=''; try { if ($_.Extension -ieq '.lnk') { $sc = $sh.CreateShortcut($_.FullName); $t = $sc.TargetPath; $a = $sc.Arguments } } catch {}; [pscustomobject]@{ Name=$_.Name; Ext=$_.Extension; Created=$_.CreationTime; Modified=$_.LastWriteTime; Size=$_.Length; Target=$t; Args=$a; Folder=$_.DirectoryName } } | Format-Table -Wrap -AutoSize | Out-String -Width 360 } else { 'Pasta Recent nao encontrada: ' + $p }"""
    GetRecentFilesTop = GetCommandOutputWithTimeout(psCmd, 12)
End Function

Function GetSeceditSummary()
    Dim tempCfg, cmd, cmdOut, ts, line, preview, hits, previewCount, hitCount
    Randomize
    tempCfg = objShell.ExpandEnvironmentStrings("%TEMP%") & "\secpol_" & Replace(CStr(Timer), ".", "") & "_" & Right("000000" & CStr(CLng(Rnd() * 1000000)), 6) & ".cfg"
    cmd = "cmd /c secedit /export /areas SECURITYPOLICY USER_RIGHTS /cfg """ & tempCfg & """ >nul 2>&1"
    cmdOut = GetCommandOutputWithTimeout(cmd, 45)

    preview = ""
    hits = ""
    previewCount = 0
    hitCount = 0

    If objFSO.FileExists(tempCfg) Then
        On Error Resume Next
        Err.Clear
        Set ts = objFSO.OpenTextFile(tempCfg, ForReading, False, -1)
        If Err.Number <> 0 Then
            Err.Clear
            Set ts = objFSO.OpenTextFile(tempCfg, ForReading, False, TristateFalse)
        End If
        If Err.Number = 0 Then
            Do Until ts.AtEndOfStream
                line = ts.ReadLine
                If InStr(line, Chr(0)) > 0 Then line = Replace(line, Chr(0), "")
                If previewCount < 140 Then
                    preview = preview & line & vbCrLf
                    previewCount = previewCount + 1
                End If
                If IsSeceditInterestingLine(line) Then
                    hits = hits & line & vbCrLf
                    hitCount = hitCount + 1
                    If hitCount >= 180 Then Exit Do
                End If
            Loop
            ts.Close
        End If
        Err.Clear
        objFSO.DeleteFile tempCfg, True
        Err.Clear
        On Error Goto 0
    End If

    If Trim(hits) <> "" Then
        GetSeceditSummary = "Resumo filtrado (areas SECURITYPOLICY/USER_RIGHTS):" & vbCrLf & Trim(hits)
    ElseIf Trim(preview) <> "" Then
        GetSeceditSummary = "Preview da exportacao (inicio do arquivo):" & vbCrLf & Trim(preview)
    ElseIf HasUsefulOutput(cmdOut) Then
        GetSeceditSummary = cmdOut
    Else
        GetSeceditSummary = "Falha ao exportar politica local via secedit ou coleta expirada por timeout."
    End If
End Function

Function IsSeceditInterestingLine(lineText)
    Dim s
    s = UCase(Trim(CStr(lineText & "")))
    If s = "" Then
        IsSeceditInterestingLine = False
        Exit Function
    End If
    If Left(s, 1) = ";" Then
        IsSeceditInterestingLine = False
        Exit Function
    End If

    If s = "[SYSTEM ACCESS]" Or s = "[EVENT AUDIT]" Or s = "[PRIVILEGE RIGHTS]" Then
        IsSeceditInterestingLine = True
        Exit Function
    End If

    If InStr(s, "MINIMUMPASSWORDAGE=") = 1 Or InStr(s, "MAXIMUMPASSWORDAGE=") = 1 Or _
       InStr(s, "MINIMUMPASSWORDLENGTH=") = 1 Or InStr(s, "PASSWORDCOMPLEXITY=") = 1 Or _
       InStr(s, "PASSWORDHISTORYSIZE=") = 1 Or InStr(s, "LOCKOUTBADCOUNT=") = 1 Or _
       InStr(s, "RESETLOCKOUTCOUNT=") = 1 Or InStr(s, "LOCKOUTDURATION=") = 1 Or _
       InStr(s, "AUDITSYSTEMEVENTS=") = 1 Or InStr(s, "AUDITLOGONEVENTS=") = 1 Or _
       InStr(s, "AUDITOBJECTACCESS=") = 1 Or InStr(s, "AUDITPOLICYCHANGE=") = 1 Then
        IsSeceditInterestingLine = True
        Exit Function
    End If

    If InStr(s, "SEREMOTEINTERACTIVELOGONRIGHT=") = 1 Or InStr(s, "SEDENYREMOTEINTERACTIVELOGONRIGHT=") = 1 Or _
       InStr(s, "SEBACKUPPRIVILEGE=") = 1 Or InStr(s, "SERESTOREPRIVILEGE=") = 1 Or _
       InStr(s, "SEDEBUGPRIVILEGE=") = 1 Or InStr(s, "SETAKEOWNERSHIPPRIVILEGE=") = 1 Or _
       InStr(s, "SESHUTDOWNPRIVILEGE=") = 1 Then
        IsSeceditInterestingLine = True
        Exit Function
    End If

    IsSeceditInterestingLine = False
End Function
Function GetServiceState(serviceName)
    Dim colSvc, svc
    GetServiceState = "nao encontrado"
    Set colSvc = objWMI.ExecQuery("SELECT * FROM Win32_Service WHERE Name='" & serviceName & "'")
    For Each svc In colSvc
        serviceTotalCount = serviceTotalCount + 1
        GetServiceState = Nz(svc.State, "-") & " / StartMode=" & Nz(svc.StartMode, "-")
    Next
End Function



Function BuildRunId()
    Dim dt, rndPart
    dt = Now
    Randomize
    rndPart = Right("000000" & CStr(CLng(Rnd() * 999999)), 6)
    BuildRunId = Year(dt) & Right("0" & Month(dt), 2) & Right("0" & Day(dt), 2) & "_" & _
        Right("0" & Hour(dt), 2) & Right("0" & Minute(dt), 2) & Right("0" & Second(dt), 2) & "_" & rndPart
End Function

Function LogStatusClass(statusText)
    Dim s
    s = UCase(Trim(CStr(statusText & "")))
    Select Case s
        Case "WARN", "WARNING"
            LogStatusClass = "warn"
        Case "ERROR", "FAIL", "BAD"
            LogStatusClass = "bad"
        Case "START"
            LogStatusClass = "start"
        Case "END", "OK"
            LogStatusClass = "ok"
        Case Else
            LogStatusClass = "neutral"
    End Select
End Function

Function FormatDurationFromTicks(startTick, endTick)
    Dim secs, mins, remSecs, hrs, remMins
    secs = CDbl(0 + endTick) - CDbl(0 + startTick)
    If secs < 0 Then secs = secs + 86400

    If secs < 1 Then
        FormatDurationFromTicks = CStr(Int(secs * 1000)) & " ms"
        Exit Function
    End If

    If secs < 60 Then
        FormatDurationFromTicks = FormatNumber(secs, 2) & " s"
        Exit Function
    End If

    mins = Int(secs / 60)
    remSecs = secs - (mins * 60)
    If mins < 60 Then
        FormatDurationFromTicks = mins & " min " & Right("0" & Int(remSecs), 2) & " s"
        Exit Function
    End If

    hrs = Int(mins / 60)
    remMins = mins Mod 60
    FormatDurationFromTicks = hrs & " h " & Right("0" & remMins, 2) & " min " & Right("0" & Int(remSecs), 2) & " s"
End Function

Function GetFileSizeBytesSafe(filePath)
    On Error Resume Next
    If objFSO.FileExists(filePath) Then
        GetFileSizeBytesSafe = CDbl(objFSO.GetFile(filePath).Size)
        If Err.Number <> 0 Then
            Err.Clear
            GetFileSizeBytesSafe = 0
        End If
    Else
        GetFileSizeBytesSafe = 0
    End If
    On Error Goto 0
End Function

Function GetFileDateModifiedSafe(filePath)
    On Error Resume Next
    If objFSO.FileExists(filePath) Then
        GetFileDateModifiedSafe = CStr(objFSO.GetFile(filePath).DateLastModified)
        If Err.Number <> 0 Then
            Err.Clear
            GetFileDateModifiedSafe = "-"
        End If
    Else
        GetFileDateModifiedSafe = "-"
    End If
    On Error Goto 0
End Function

Function EscapePsSingleQuoted(s)
    EscapePsSingleQuoted = Replace(CStr(s), "'", "''")
End Function

Function NormalizeHexToken(s)
    Dim t, i, ch, out
    t = UCase(Trim(CStr(s & "")))
    out = ""
    For i = 1 To Len(t)
        ch = Mid(t, i, 1)
        If (ch >= "0" And ch <= "9") Or (ch >= "A" And ch <= "F") Then
            out = out & ch
        End If
    Next
    NormalizeHexToken = out
End Function

Function LooksLikeMd5Hex(s)
    Dim i, ch
    s = UCase(Trim(CStr(s & "")))
    If Len(s) <> 32 Then
        LooksLikeMd5Hex = False
        Exit Function
    End If
    For i = 1 To 32
        ch = Mid(s, i, 1)
        If Not ((ch >= "0" And ch <= "9") Or (ch >= "A" And ch <= "F")) Then
            LooksLikeMd5Hex = False
            Exit Function
        End If
    Next
    LooksLikeMd5Hex = True
End Function

Function GetCommandOutputWithLocalTimeoutSilent(cmd, timeoutSecs)
    Dim ex, out, errOut, startTime, finalOut
    GetCommandOutputWithLocalTimeoutSilent = ""

    On Error Resume Next
    Set ex = objShell.Exec(cmd)
    If Err.Number <> 0 Then
        GetCommandOutputWithLocalTimeoutSilent = "Falha ao executar comando: " & Err.Description
        Err.Clear
        On Error Goto 0
        Exit Function
    End If

    out = ""
    errOut = ""
    finalOut = ""
    startTime = Now

    Do
        Err.Clear
        If Not ex.StdOut.AtEndOfStream Then out = out & ex.StdOut.Read(1024)
        Err.Clear
        If Not ex.StdErr.AtEndOfStream Then errOut = errOut & ex.StdErr.Read(1024)

        If ex.Status <> 0 Then Exit Do

        If CLng(0 + timeoutSecs) > 0 Then
            If DateDiff("s", startTime, Now) >= CLng(0 + timeoutSecs) Then
                ex.Terminate
                Err.Clear
                GetCommandOutputWithLocalTimeoutSilent = "[TIMEOUT APOS " & CLng(0 + timeoutSecs) & "s] Comando interrompido por demora."
                On Error Goto 0
                Exit Function
            End If
        End If

        WScript.Sleep 100
    Loop

    Err.Clear
    If Not ex.StdOut.AtEndOfStream Then out = out & ex.StdOut.ReadAll
    Err.Clear
    If Not ex.StdErr.AtEndOfStream Then errOut = errOut & ex.StdErr.ReadAll

    out = Trim(out)
    errOut = Trim(errOut)
    If out <> "" Then
        finalOut = out
        If errOut <> "" Then finalOut = finalOut & vbCrLf & "[stderr]" & vbCrLf & errOut
    Else
        finalOut = errOut
    End If

    GetCommandOutputWithLocalTimeoutSilent = Trim(finalOut)
    On Error Goto 0
End Function

Function GetFileMD5(filePath)
    Dim psCmd, cmdOut, lines, line, token, certCmd
    GetFileMD5 = "N/A"
    If objFSO.FileExists(filePath) = False Then
        Exit Function
    End If

    psCmd = "powershell -NoProfile -Command ""try { (Get-FileHash -LiteralPath '" & EscapePsSingleQuoted(filePath) & "' -Algorithm MD5 -ErrorAction Stop).Hash } catch { Write-Output ('ERROR: ' + $_.Exception.Message) }"""
    cmdOut = GetCommandOutputWithLocalTimeoutSilent(psCmd, 15)
    lines = Split(CStr(cmdOut & ""), vbCrLf)
    For Each line In lines
        token = NormalizeHexToken(line)
        If LooksLikeMd5Hex(token) Then
            GetFileMD5 = token
            Exit Function
        End If
    Next

    certCmd = "cmd /c certutil -hashfile """ & filePath & """ MD5"
    cmdOut = GetCommandOutputWithLocalTimeoutSilent(certCmd, 20)
    lines = Split(CStr(cmdOut & ""), vbCrLf)
    For Each line In lines
        token = NormalizeHexToken(line)
        If LooksLikeMd5Hex(token) Then
            GetFileMD5 = token
            Exit Function
        End If
    Next
End Function

Function GetLogDetailField(detailText)
    Dim s, p
    s = Trim(CStr(detailText & ""))
    If s = "" Then
        GetLogDetailField = "detalhes"
        Exit Function
    End If
    p = InStr(1, s, ":")
    If p > 1 And p <= 60 Then
        GetLogDetailField = Trim(Left(s, p - 1))
        If GetLogDetailField = "" Then GetLogDetailField = "detalhes"
    Else
        GetLogDetailField = "detalhes"
    End If
End Function

Function GetLogDetailValue(detailText)
    Dim s, p
    s = Trim(CStr(detailText & ""))
    If s = "" Then
        GetLogDetailValue = "-"
        Exit Function
    End If
    p = InStr(1, s, ":")
    If p > 1 And p < Len(s) Then
        GetLogDetailValue = Trim(Mid(s, p + 1))
        If GetLogDetailValue = "" Then GetLogDetailValue = "-"
    Else
        GetLogDetailValue = s
    End If
End Function

Function PercentWidthPct(valueNum, maxNum)
    Dim p
    If CDbl(0 + maxNum) <= 0 Then
        PercentWidthPct = 0
        Exit Function
    End If
    p = Int((CDbl(0 + valueNum) / CDbl(0 + maxNum)) * 100)
    If CDbl(0 + valueNum) > 0 And p < 2 Then p = 2
    If p > 100 Then p = 100
    If p < 0 Then p = 0
    PercentWidthPct = p
End Function

Function IsChecklistStageName(stageName)
    Dim s
    s = CStr(stageName & "")
    If Left(s, 5) = "Write" And InStr(1, s, "Section", vbTextCompare) > 0 Then
        IsChecklistStageName = True
    Else
        IsChecklistStageName = False
    End If
End Function

Function GetPesquisaCommand(detailText)
    Dim s, p1, p2
    s = CStr(detailText & "")
    p1 = InStr(1, s, "Comando:", vbTextCompare)
    If p1 <= 0 Then
        GetPesquisaCommand = s
        Exit Function
    End If
    s = Trim(Mid(s, p1 + Len("Comando:")))
    p2 = InStr(1, s, "| Resultado:", vbTextCompare)
    If p2 > 0 Then
        GetPesquisaCommand = Trim(Left(s, p2 - 1))
    Else
        GetPesquisaCommand = Trim(s)
    End If
    If GetPesquisaCommand = "" Then GetPesquisaCommand = "-"
End Function

Function GetPesquisaResultado(detailText)
    Dim s, p1
    s = CStr(detailText & "")
    p1 = InStr(1, s, "Resultado:", vbTextCompare)
    If p1 <= 0 Then
        GetPesquisaResultado = "-"
        Exit Function
    End If
    GetPesquisaResultado = Trim(Mid(s, p1 + Len("Resultado:")))
    If GetPesquisaResultado = "" Then GetPesquisaResultado = "-"
End Function

Sub WriteExecutionLogHtml(mainHtmlFile, endStamp)
    Dim logFile, totalDuration, activityHtml, timelineHtml, queryHtml, warnBadge, errBadge, dfirPriorityTimelineHtml, userTimelineHtml
    Dim reportBytes, csvBytes, reportMd5, csvMd5, logMd5, reportModified, csvModified
    Dim maxStatusCount, maxFileBytes, statusChartHtml, fileChartHtml, detailTableHtml, timelineColSpan, detectionChartHtml, hostProfileChartHtml, hostInfoHtml, maxDetectionCount, maxHostMetric
    Dim checklistRate, checklistText, avgCmdDurationText, cmdStatsText
    Dim cmdQualityChartHtml, maxCmdMetric, exportDetailRows, userTimelineChartHtml, maxUserTimelineMetric
    Dim statusReconHtml, statusDelta, statusBalanceTarget, warnErrorHtml
    Dim statusStartPendingCount, statusEndsPairedText
    Dim eventExportRowsHtml, registryRootRowsHtml, smallArtifactRowsHtml
    Dim zipDisplayName

    EnsureHostIdentityContext
    totalDuration = FormatDurationFromTicks(dblScriptStartTick, Timer)
    warnBadge = IIfBool(logWarnCount > 0, "<span class='pill warn'>" & logWarnCount & " avisos</span>", "<span class='pill ok'>0 avisos</span>")
    errBadge = IIfBool(logErrorCount > 0, "<span class='pill bad'>" & logErrorCount & " erros</span>", "<span class='pill ok'>0 erros</span>")
    zipDisplayName = SanitizeFileNameComponent(IIfBool(Trim(CStr(hostServiceTag & "")) <> "" And hostServiceTag <> "-", hostServiceTag, strComputer)) & ".zip"

    reportBytes = GetFileSizeBytesSafe(mainHtmlFile)
    csvBytes = GetFileSizeBytesSafe(strCustodyFile)
    reportModified = GetFileDateModifiedSafe(mainHtmlFile)
    csvModified = GetFileDateModifiedSafe(strCustodyFile)
    reportMd5 = GetFileMD5(mainHtmlFile)
    csvMd5 = GetFileMD5(strCustodyFile)
    logMd5 = "-"

    activityHtml = strLogActivityRows
    If Trim(activityHtml) = "" Then activityHtml = "<tr><td colspan='7'>Nenhuma atividade consolidada (START/END) registrada.</td></tr>"

    timelineHtml = strLogTimelineRows
    timelineColSpan = 7
    If Trim(timelineHtml) = "" Then timelineHtml = "<tr><td colspan='" & timelineColSpan & "'>Nenhum evento de log registrado.</td></tr>"
    dfirPriorityTimelineHtml = BuildDfirPriorityTimelineHtml()
    userTimelineHtml = BuildUserArtifactTimelineRowsHtml()
    If Trim(userTimelineHtml) = "" Then userTimelineHtml = "<tr><td colspan='4'>Sem timeline de artefatos do usuario (Recent/atalhos) nesta execucao.</td></tr>"

    queryHtml = strLogQueryRows
    If Trim(queryHtml) = "" Then queryHtml = "<tr><td colspan='6'>Nenhuma pesquisa/comando registrada.</td></tr>"
    warnErrorHtml = strWarnErrorDetailRows
    If Trim(warnErrorHtml) = "" Then warnErrorHtml = "<tr><td colspan='6'>Sem eventos WARN/BAD registrados nesta execucao.</td></tr>"
    eventExportRowsHtml = strEventLogArtifactExportRows
    If Trim(eventExportRowsHtml) = "" Then eventExportRowsHtml = "<tr><td colspan='6'>Nenhum export de EVT/EVTX registrado.</td></tr>"
    registryRootRowsHtml = strRegistryRootArtifactExportRows
    If Trim(registryRootRowsHtml) = "" Then registryRootRowsHtml = "<tr><td colspan='6'>Nenhum export de raiz de registro (.reg) registrado.</td></tr>"
    smallArtifactRowsHtml = strSmallArtifactExportRows
    If Trim(smallArtifactRowsHtml) = "" Then smallArtifactRowsHtml = "<tr><td colspan='6'>Nenhum export de pequenos artefatos registrado.</td></tr>"

    If CLng(0 + checklistTotalCount) > 0 Then
        checklistRate = Int((CDbl(0 + checklistOkCount) / CDbl(0 + checklistTotalCount)) * 100)
        checklistText = checklistOkCount & " / " & checklistTotalCount & " itens OK (" & checklistRate & "%)"
    Else
        checklistText = "Sem itens de checklist consolidados"
    End If

    If CLng(0 + cmdExecCount) > 0 Then
        avgCmdDurationText = FormatDurationFromTicks(0, CDbl(0 + cmdTotalSecs) / CDbl(0 + cmdExecCount))
    Else
        avgCmdDurationText = "-"
    End If
    cmdStatsText = cmdExecCount & " execucoes | " & cmdTimeoutCount & " timeout | " & cmdFailCount & " falhas"

    maxStatusCount = CLng(0 + logStartCount)
    If CLng(0 + logOkCount) > maxStatusCount Then maxStatusCount = CLng(0 + logOkCount)
    If CLng(0 + logWarnCount) > maxStatusCount Then maxStatusCount = CLng(0 + logWarnCount)
    If CLng(0 + logErrorCount) > maxStatusCount Then maxStatusCount = CLng(0 + logErrorCount)
    If CLng(0 + logNeutralCount) > maxStatusCount Then maxStatusCount = CLng(0 + logNeutralCount)
    If maxStatusCount <= 0 Then maxStatusCount = 1

    maxFileBytes = reportBytes
    If csvBytes > maxFileBytes Then maxFileBytes = csvBytes
    If CDbl(0 + bundleZipBytes) > maxFileBytes Then maxFileBytes = CDbl(0 + bundleZipBytes)
    If maxFileBytes <= 0 Then maxFileBytes = 1

    statusChartHtml = ""
    statusChartHtml = statusChartHtml & "<div class='bar-row'><div class='bar-head'><span>START</span><strong>" & logStartCount & "</strong></div><div class='meter'><span class='fill start' style='width:" & PercentWidthPct(logStartCount, maxStatusCount) & "%'></span></div></div>"
    statusChartHtml = statusChartHtml & "<div class='bar-row'><div class='bar-head'><span>OK/END</span><strong>" & logOkCount & "</strong></div><div class='meter'><span class='fill ok' style='width:" & PercentWidthPct(logOkCount, maxStatusCount) & "%'></span></div></div>"
    statusChartHtml = statusChartHtml & "<div class='bar-row'><div class='bar-head'><span>WARN</span><strong>" & logWarnCount & "</strong></div><div class='meter'><span class='fill warn' style='width:" & PercentWidthPct(logWarnCount, maxStatusCount) & "%'></span></div></div>"
    statusChartHtml = statusChartHtml & "<div class='bar-row'><div class='bar-head'><span>ERROR/BAD</span><strong>" & logErrorCount & "</strong></div><div class='meter'><span class='fill bad' style='width:" & PercentWidthPct(logErrorCount, maxStatusCount) & "%'></span></div></div>"
    statusChartHtml = statusChartHtml & "<div class='bar-row'><div class='bar-head'><span>NEUTRAL</span><strong>" & logNeutralCount & "</strong></div><div class='meter'><span class='fill neutral' style='width:" & PercentWidthPct(logNeutralCount, maxStatusCount) & "%'></span></div></div>"

    fileChartHtml = ""
    fileChartHtml = fileChartHtml & "<div class='bar-row'><div class='bar-head'><span>Relatorio principal (.html)</span><strong>" & HtmlEncode(FormatBytes(reportBytes)) & "</strong></div><div class='meter'><span class='fill report' style='width:" & PercentWidthPct(reportBytes, maxFileBytes) & "%'></span></div></div>"
    fileChartHtml = fileChartHtml & "<div class='bar-row'><div class='bar-head'><span>Custody CSV</span><strong>" & HtmlEncode(FormatBytes(csvBytes)) & "</strong></div><div class='meter'><span class='fill csv' style='width:" & PercentWidthPct(csvBytes, maxFileBytes) & "%'></span></div></div>"
    fileChartHtml = fileChartHtml & "<div class='bar-row'><div class='bar-head'><span>Pacote compactado (" & HtmlEncode(zipDisplayName) & ")</span><strong>__ZIP_SIZE_TEXT__</strong></div><div class='meter'><span class='fill neutral' style='width:__ZIP_BAR_PCT__%'></span></div></div>"

    maxCmdMetric = 1
    If CLng(0 + cmdExecCount) > maxCmdMetric Then maxCmdMetric = CLng(0 + cmdExecCount)
    If CLng(0 + cmdTimeoutCount) > maxCmdMetric Then maxCmdMetric = CLng(0 + cmdTimeoutCount)
    If CLng(0 + cmdFailCount) > maxCmdMetric Then maxCmdMetric = CLng(0 + cmdFailCount)
    cmdQualityChartHtml = ""
    cmdQualityChartHtml = cmdQualityChartHtml & "<div class='bar-row'><div class='bar-head'><span>Comandos executados</span><strong>" & cmdExecCount & "</strong></div><div class='meter'><span class='fill start' style='width:" & PercentWidthPct(cmdExecCount, maxCmdMetric) & "%'></span></div></div>"
    cmdQualityChartHtml = cmdQualityChartHtml & "<div class='bar-row'><div class='bar-head'><span>Timeouts</span><strong>" & cmdTimeoutCount & "</strong></div><div class='meter'><span class='fill warn' style='width:" & PercentWidthPct(cmdTimeoutCount, maxCmdMetric) & "%'></span></div></div>"
    cmdQualityChartHtml = cmdQualityChartHtml & "<div class='bar-row'><div class='bar-head'><span>Falhas</span><strong>" & cmdFailCount & "</strong></div><div class='meter'><span class='fill bad' style='width:" & PercentWidthPct(cmdFailCount, maxCmdMetric) & "%'></span></div></div>"

    maxDetectionCount = 1
    If CLng(0 + threatEventAlertCount) > maxDetectionCount Then maxDetectionCount = CLng(0 + threatEventAlertCount)
    If CLng(0 + threatEventWarnCount) > maxDetectionCount Then maxDetectionCount = CLng(0 + threatEventWarnCount)
    If CLng(0 + threatRegistryAlertCount) > maxDetectionCount Then maxDetectionCount = CLng(0 + threatRegistryAlertCount)
    If CLng(0 + threatRegistryWarnCount) > maxDetectionCount Then maxDetectionCount = CLng(0 + threatRegistryWarnCount)
    If CLng(0 + threatHighPriorityHits) > maxDetectionCount Then maxDetectionCount = CLng(0 + threatHighPriorityHits)
    If CLng(0 + threatEventTotalHits) > maxDetectionCount Then maxDetectionCount = CLng(0 + threatEventTotalHits)

    detectionChartHtml = ""
    detectionChartHtml = detectionChartHtml & "<div class='bar-row'><div class='bar-head'><span>Eventos (amostra)</span><strong>" & threatEventTotalHits & "</strong></div><div class='meter'><span class='fill neutral' style='width:" & PercentWidthPct(threatEventTotalHits, maxDetectionCount) & "%'></span></div></div>"
    detectionChartHtml = detectionChartHtml & "<div class='bar-row'><div class='bar-head'><span>Eventos ALERTA</span><strong>" & threatEventAlertCount & "</strong></div><div class='meter'><span class='fill bad' style='width:" & PercentWidthPct(threatEventAlertCount, maxDetectionCount) & "%'></span></div></div>"
    detectionChartHtml = detectionChartHtml & "<div class='bar-row'><div class='bar-head'><span>Eventos WARN</span><strong>" & threatEventWarnCount & "</strong></div><div class='meter'><span class='fill warn' style='width:" & PercentWidthPct(threatEventWarnCount, maxDetectionCount) & "%'></span></div></div>"
    detectionChartHtml = detectionChartHtml & "<div class='bar-row'><div class='bar-head'><span>Hits Prioridade Alta</span><strong>" & threatHighPriorityHits & "</strong></div><div class='meter'><span class='fill start' style='width:" & PercentWidthPct(threatHighPriorityHits, maxDetectionCount) & "%'></span></div></div>"
    detectionChartHtml = detectionChartHtml & "<div class='bar-row'><div class='bar-head'><span>Registro ALERTA</span><strong>" & threatRegistryAlertCount & "</strong></div><div class='meter'><span class='fill bad' style='width:" & PercentWidthPct(threatRegistryAlertCount, maxDetectionCount) & "%'></span></div></div>"
    detectionChartHtml = detectionChartHtml & "<div class='bar-row'><div class='bar-head'><span>Registro WARN</span><strong>" & threatRegistryWarnCount & "</strong></div><div class='meter'><span class='fill warn' style='width:" & PercentWidthPct(threatRegistryWarnCount, maxDetectionCount) & "%'></span></div></div>"
    detectionChartHtml = detectionChartHtml & "<div class='bar-row'><div class='bar-head'><span>Exports eventos (ameacas)</span><strong>" & threatEventExportCount & "</strong></div><div class='meter'><span class='fill report' style='width:" & PercentWidthPct(threatEventExportCount, maxDetectionCount) & "%'></span></div></div>"
    detectionChartHtml = detectionChartHtml & "<div class='bar-row'><div class='bar-head'><span>Snapshots registro exportados</span><strong>" & threatRegistrySnapshotExportCount & "</strong></div><div class='meter'><span class='fill csv' style='width:" & PercentWidthPct(threatRegistrySnapshotExportCount, maxDetectionCount) & "%'></span></div></div>"

    maxHostMetric = 1
    If CLng(0 + processCount) > maxHostMetric Then maxHostMetric = CLng(0 + processCount)
    If CLng(0 + serviceTotalCount) > maxHostMetric Then maxHostMetric = CLng(0 + serviceTotalCount)
    If CLng(0 + serviceRunningCount) > maxHostMetric Then maxHostMetric = CLng(0 + serviceRunningCount)
    If CLng(0 + networkAdapterCount) > maxHostMetric Then maxHostMetric = CLng(0 + networkAdapterCount)
    If CLng(0 + fixedCount) > maxHostMetric Then maxHostMetric = CLng(0 + fixedCount)
    If CLng(0 + removableCount) > maxHostMetric Then maxHostMetric = CLng(0 + removableCount)

    hostProfileChartHtml = ""
    hostProfileChartHtml = hostProfileChartHtml & "<div class='bar-row'><div class='bar-head'><span>Processos</span><strong>" & processCount & "</strong></div><div class='meter'><span class='fill neutral' style='width:" & PercentWidthPct(processCount, maxHostMetric) & "%'></span></div></div>"
    hostProfileChartHtml = hostProfileChartHtml & "<div class='bar-row'><div class='bar-head'><span>Servicos (total)</span><strong>" & serviceTotalCount & "</strong></div><div class='meter'><span class='fill report' style='width:" & PercentWidthPct(serviceTotalCount, maxHostMetric) & "%'></span></div></div>"
    hostProfileChartHtml = hostProfileChartHtml & "<div class='bar-row'><div class='bar-head'><span>Servicos em execucao</span><strong>" & serviceRunningCount & "</strong></div><div class='meter'><span class='fill ok' style='width:" & PercentWidthPct(serviceRunningCount, maxHostMetric) & "%'></span></div></div>"
    hostProfileChartHtml = hostProfileChartHtml & "<div class='bar-row'><div class='bar-head'><span>Adaptadores fisicos</span><strong>" & networkAdapterCount & "</strong></div><div class='meter'><span class='fill start' style='width:" & PercentWidthPct(networkAdapterCount, maxHostMetric) & "%'></span></div></div>"
    hostProfileChartHtml = hostProfileChartHtml & "<div class='bar-row'><div class='bar-head'><span>Volumes locais</span><strong>" & fixedCount & "</strong></div><div class='meter'><span class='fill csv' style='width:" & PercentWidthPct(fixedCount, maxHostMetric) & "%'></span></div></div>"
    hostProfileChartHtml = hostProfileChartHtml & "<div class='bar-row'><div class='bar-head'><span>Volumes removiveis</span><strong>" & removableCount & "</strong></div><div class='meter'><span class='fill warn' style='width:" & PercentWidthPct(removableCount, maxHostMetric) & "%'></span></div></div>"

    hostInfoHtml = "<div class='grid'>" & _
        "<div class='card'><div class='label'>Hardware</div><div class='value'>" & HtmlEncode(Nz(hostManufacturerName, "-")) & " / " & HtmlEncode(Nz(hostModelName, "-")) & "</div></div>" & _
        "<div class='card'><div class='label'>Tipo do host</div><div class='value'>" & HtmlEncode(Nz(hostAssetType, "Indeterminado")) & "</div></div>" & _
        "<div class='card'><div class='label'>CPU Logicos</div><div class='value'>" & hostCpuLogicalCount & "</div></div>" & _
        "<div class='card'><div class='label'>RAM total</div><div class='value'>" & HtmlEncode(FormatBytes(hostRamTotalBytes)) & "</div></div>" & _
        "<div class='card'><div class='label'>Baterias WMI</div><div class='value'>" & hostBatteryCount & "</div></div>" & _
        "<div class='card'><div class='label'>Falhas em export de eventos (seguranca)</div><div class='value'>" & errorEventCount & "</div></div>" & _
        "</div>"
    maxUserTimelineMetric = 1
    If CLng(0 + userArtifactTimelineCreateCount) > maxUserTimelineMetric Then maxUserTimelineMetric = CLng(0 + userArtifactTimelineCreateCount)
    If CLng(0 + userArtifactTimelineAccessCount) > maxUserTimelineMetric Then maxUserTimelineMetric = CLng(0 + userArtifactTimelineAccessCount)
    If CLng(0 + userArtifactTimelineModifyCount) > maxUserTimelineMetric Then maxUserTimelineMetric = CLng(0 + userArtifactTimelineModifyCount)
    userTimelineChartHtml = ""
    userTimelineChartHtml = userTimelineChartHtml & "<div class='bar-row'><div class='bar-head'><span>Usuario - Criacao</span><strong>" & userArtifactTimelineCreateCount & "</strong></div><div class='meter'><span class='fill start' style='width:" & PercentWidthPct(userArtifactTimelineCreateCount, maxUserTimelineMetric) & "%'></span></div></div>"
    userTimelineChartHtml = userTimelineChartHtml & "<div class='bar-row'><div class='bar-head'><span>Usuario - Acesso</span><strong>" & userArtifactTimelineAccessCount & "</strong></div><div class='meter'><span class='fill warn' style='width:" & PercentWidthPct(userArtifactTimelineAccessCount, maxUserTimelineMetric) & "%'></span></div></div>"
    userTimelineChartHtml = userTimelineChartHtml & "<div class='bar-row'><div class='bar-head'><span>Usuario - Modificacao</span><strong>" & userArtifactTimelineModifyCount & "</strong></div><div class='meter'><span class='fill ok' style='width:" & PercentWidthPct(userArtifactTimelineModifyCount, maxUserTimelineMetric) & "%'></span></div></div>"
    exportDetailRows = ""
    exportDetailRows = exportDetailRows & "<tr><td>Eventos recentes (Seguranca)</td><td>" & securityEventExportCount & "</td><td class='path'>" & HtmlEncode(GetRunExportSubDir("eventos_recentes")) & "</td><td>" & HtmlEncode(GetPathDateCreatedSafe(GetRunExportSubDir("eventos_recentes"))) & "</td></tr>"
    exportDetailRows = exportDetailRows & "<tr><td>Eventos priorizados (Ameacas)</td><td>" & threatEventExportCount & "</td><td class='path'>" & HtmlEncode(GetRunExportSubDir("ameacas_eventos")) & "</td><td>" & HtmlEncode(GetPathDateCreatedSafe(GetRunExportSubDir("ameacas_eventos"))) & "</td></tr>"
    exportDetailRows = exportDetailRows & "<tr><td>Snapshots de registro (Ameacas)</td><td>" & threatRegistrySnapshotExportCount & "</td><td class='path'>" & HtmlEncode(GetRunExportSubDir("ameacas_registro")) & "</td><td>" & HtmlEncode(GetPathDateCreatedSafe(GetRunExportSubDir("ameacas_registro"))) & "</td></tr>"
    exportDetailRows = exportDetailRows & "<tr><td>EVTX exportados</td><td>" & evtxExportCount & "</td><td class='path'>" & HtmlEncode(GetRunExportNestedSubDir("artefatos\eventos\evtx")) & "</td><td>" & HtmlEncode(GetPathDateCreatedSafe(GetRunExportNestedSubDir("artefatos\eventos\evtx"))) & "</td></tr>"
    exportDetailRows = exportDetailRows & "<tr><td>EVT legados exportados</td><td>" & evtExportCount & "</td><td class='path'>" & HtmlEncode(GetRunExportNestedSubDir("artefatos\eventos\evt")) & "</td><td>" & HtmlEncode(GetPathDateCreatedSafe(GetRunExportNestedSubDir("artefatos\eventos\evt"))) & "</td></tr>"
    exportDetailRows = exportDetailRows & "<tr><td>Raizes de registro (.reg)</td><td>" & registryRootExportCount & "</td><td class='path'>" & HtmlEncode(GetRunExportNestedSubDir("artefatos\originais\registro")) & "</td><td>" & HtmlEncode(GetPathDateCreatedSafe(GetRunExportNestedSubDir("artefatos\originais\registro"))) & "</td></tr>"
    exportDetailRows = exportDetailRows & "<tr><td>Pequenos artefatos</td><td>" & smallArtifactExportCount & "</td><td class='path'>" & HtmlEncode(GetRunExportNestedSubDir("artefatos")) & "</td><td>" & HtmlEncode(GetPathDateCreatedSafe(GetRunExportNestedSubDir("artefatos"))) & "</td></tr>"
    detailTableHtml = ""
    detailTableHtml = detailTableHtml & "<tr><th>Arquivo</th><th>Caminho</th><th>Tamanho</th><th>Ultima gravacao</th><th>Hash MD5</th></tr>"
    detailTableHtml = detailTableHtml & "<tr><td>Relatorio principal</td><td class='path'>" & HtmlEncode(mainHtmlFile) & "</td><td>" & HtmlEncode(FormatBytes(reportBytes)) & "</td><td>" & HtmlEncode(reportModified) & "</td><td><code>" & HtmlEncode(reportMd5) & "</code></td></tr>"
    detailTableHtml = detailTableHtml & "<tr><td>Status log</td><td class='path'>" & HtmlEncode(strLogHtmlFile) & "</td><td>- (gerado nesta etapa)</td><td>" & HtmlEncode(endStamp) & "</td><td><code>(calculado apos compactacao e registrado no custody csv; nao exibido inline para evitar auto-invalidacao do hash)</code></td></tr>"
    detailTableHtml = detailTableHtml & "<tr><td>Custody CSV</td><td class='path'>" & HtmlEncode(strCustodyFile) & "</td><td>" & HtmlEncode(FormatBytes(csvBytes)) & "</td><td>" & HtmlEncode(csvModified) & "</td><td><code>" & HtmlEncode(csvMd5) & "</code> <span class='muted'>(pre-close)</span></td></tr>"
    detailTableHtml = detailTableHtml & "<tr><td>Pasta de exportacoes</td><td class='path'>" & HtmlEncode(GetRunExportBaseDir()) & "</td><td>-</td><td>-</td><td>-</td></tr>"
    detailTableHtml = detailTableHtml & "<tr><td>Pacote compactado</td><td class='path'>__ZIP_PATH__</td><td>__ZIP_SIZE_TEXT__</td><td>__ZIP_MTIME__</td><td><code>__ZIP_MD5__</code></td></tr>"

    statusBalanceTarget = CLng(0 + logOkCount) + CLng(0 + logWarnCount) + CLng(0 + logErrorCount) + CLng(0 + logNeutralCount)
    statusDelta = CLng(0 + logStartCount) - CLng(0 + logEndCount)
    statusStartPendingCount = 0
    If Not (objActivityStartStamp Is Nothing) Then statusStartPendingCount = CLng(0 + objActivityStartStamp.Count)
    If CLng(0 + logEndWithoutStartCount) <= 0 Then
        statusEndsPairedText = "SIM"
    Else
        statusEndsPairedText = "NAO (" & logEndWithoutStartCount & " END sem START)"
    End If
    statusReconHtml = ""
    statusReconHtml = statusReconHtml & "<div class='grid'>"
    statusReconHtml = statusReconHtml & "<div class='card'><div class='label'>START</div><div class='value'>" & logStartCount & "</div></div>"
    statusReconHtml = statusReconHtml & "<div class='card'><div class='label'>END (literal)</div><div class='value'>" & logEndCount & "</div></div>"
    statusReconHtml = statusReconHtml & "<div class='card'><div class='label'>OK (literal)</div><div class='value'>" & logPureOkCount & "</div></div>"
    statusReconHtml = statusReconHtml & "<div class='card'><div class='label'>WARN</div><div class='value'>" & logWarnCount & "</div></div>"
    statusReconHtml = statusReconHtml & "<div class='card'><div class='label'>ERROR/BAD</div><div class='value'>" & logErrorCount & "</div></div>"
    statusReconHtml = statusReconHtml & "<div class='card'><div class='label'>ENDs com START</div><div class='value'>" & logEndWithStartCount & "</div></div>"
    statusReconHtml = statusReconHtml & "<div class='card'><div class='label'>ENDs sem START</div><div class='value'>" & logEndWithoutStartCount & "</div></div>"
    statusReconHtml = statusReconHtml & "<div class='card'><div class='label'>START pendentes</div><div class='value'>" & statusStartPendingCount & "</div></div>"
    statusReconHtml = statusReconHtml & "<div class='card'><div class='label'>Delta START-END</div><div class='value'>" & statusDelta & "</div></div>"
    statusReconHtml = statusReconHtml & "</div>"
    statusReconHtml = statusReconHtml & "<div class='section-note'>Validacao de pareamento de atividades: o grafico principal usa classes de status (OK inclui END), enquanto esta tabela usa status literais para conferir se cada END teve START correspondente.</div>"
    statusReconHtml = statusReconHtml & "<div class='scroll'><table><tr><th>Comparacao</th><th>Valor</th><th>Interpretacao</th></tr>"
    statusReconHtml = statusReconHtml & "<tr><td>START</td><td>" & logStartCount & "</td><td>Eventos de inicio de etapa/comando.</td></tr>"
    statusReconHtml = statusReconHtml & "<tr><td>END (literal)</td><td>" & logEndCount & "</td><td>Fechamentos de etapa/comando (sem incluir OK intermediario).</td></tr>"
    statusReconHtml = statusReconHtml & "<tr><td>OK (literal)</td><td>" & logPureOkCount & "</td><td>Eventos OK nao-END (ex.: integridade/exports/registro de sucesso).</td></tr>"
    statusReconHtml = statusReconHtml & "<tr><td>ENDs com START</td><td>" & logEndWithStartCount & "</td><td>Fechamentos pareados corretamente.</td></tr>"
    statusReconHtml = statusReconHtml & "<tr><td>ENDs sem START</td><td>" & logEndWithoutStartCount & "</td><td>Deve ser 0; indica fechamento orfao.</td></tr>"
    statusReconHtml = statusReconHtml & "<tr><td>START pendentes (sem END ate o fechamento)</td><td>" & statusStartPendingCount & "</td><td>Starts ainda abertos no momento de gerar o StatusLog.</td></tr>"
    statusReconHtml = statusReconHtml & "<tr><td>Todos os ENDs possuem START?</td><td>" & statusEndsPairedText & "</td><td>Validacao direta de pareamento START/END.</td></tr>"
    statusReconHtml = statusReconHtml & "<tr><td>OK/END (classe do grafico)</td><td>" & logOkCount & "</td><td>Classe agregada usada no grafico de volumes por status.</td></tr>"
    statusReconHtml = statusReconHtml & "<tr><td>WARN + BAD + NEUTRAL</td><td>" & (CLng(0 + logWarnCount) + CLng(0 + logErrorCount) + CLng(0 + logNeutralCount)) & "</td><td>Eventos adicionais/intermediarios que nao representam novos STARTs.</td></tr>"
    statusReconHtml = statusReconHtml & "<tr><td>Total eventos nao-START (classe)</td><td>" & statusBalanceTarget & "</td><td>Soma de OK/END, WARN, BAD e NEUTRAL no grafico.</td></tr>"
    statusReconHtml = statusReconHtml & "</table></div>"

    If LooksLikeMd5Hex(reportMd5) Then
        LogCustody "INTEGRITY", "OK", "MD5 relatorio principal=" & reportMd5
    Else
        LogCustody "INTEGRITY", "WARN", "Nao foi possivel calcular MD5 do relatorio principal"
    End If
    If LooksLikeMd5Hex(csvMd5) Then
        LogCustody "INTEGRITY", "OK", "MD5 custody (pre-close)=" & csvMd5
    Else
        LogCustody "INTEGRITY", "WARN", "Nao foi possivel calcular MD5 do custody CSV (pre-close)"
    End If

    On Error Resume Next
    Err.Clear
    Set logFile = objFSO.OpenTextFile(strLogHtmlFile, ForWriting, True, TristateFalse)
    If Err.Number <> 0 Then
        Err.Clear
        Exit Sub
    End If
    On Error Goto 0

    logFile.WriteLine "<!DOCTYPE html>"
    logFile.WriteLine "<html lang='pt-BR'><head><meta charset='windows-1252'><meta name='viewport' content='width=device-width, initial-scale=1'>"
    logFile.WriteLine "<title>Status Log - " & HtmlEncode(strComputer) & "</title>"
    logFile.WriteLine "<style>"
    logFile.WriteLine ":root{--bg:#eef4fb;--ink:#0f172a;--muted:#64748b;--line:#dbe5f0;--card:#ffffff;--ok:#16a34a;--warn:#d97706;--bad:#dc2626;--start:#2563eb;--neutral:#64748b;--report:#0ea5e9;--csv:#7c3aed}*{box-sizing:border-box}body{margin:0;color:var(--ink);font-family:'Segoe UI',Tahoma,Arial,sans-serif;background:radial-gradient(circle at 10% 0%,#dbeafe 0,#eef4fb 35%,#f8fafc 100%)}.wrap{max-width:1320px;margin:0 auto;padding:18px}.hero{background:rgba(255,255,255,.88);border:1px solid rgba(148,163,184,.35);border-radius:18px;padding:16px;box-shadow:0 14px 34px rgba(15,23,42,.08)}h1{margin:.1rem 0 .35rem 0;font-size:clamp(1.15rem,3vw,1.9rem)}h2{margin:0 0 .8rem 0;font-size:1rem}.muted{color:var(--muted);font-size:.9rem}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-top:12px}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:12px;box-shadow:0 6px 16px rgba(15,23,42,.04)}.label{font-size:.74rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}.value{margin-top:6px;font-weight:700;font-size:.96rem;word-break:break-word}.pill{display:inline-block;padding:3px 8px;border-radius:999px;font-size:.78rem;font-weight:600}.pill.ok{background:#dcfce7;color:#166534}.pill.warn{background:#fef3c7;color:#92400e}.pill.bad{background:#fee2e2;color:#991b1b}.layout{display:grid;grid-template-columns:1fr;gap:14px;margin-top:14px}.section{background:rgba(255,255,255,.9);border:1px solid rgba(148,163,184,.35);border-radius:16px;padding:14px;box-shadow:0 10px 24px rgba(15,23,42,.04)}.section.full{grid-column:1/-1}.section-note{color:var(--muted);font-size:.82rem;margin:-2px 0 10px 0}.bar-row{margin:10px 0}.bar-head{display:flex;justify-content:space-between;gap:8px;font-size:.86rem;margin-bottom:5px}.bar-head span{color:#334155}.bar-head strong{font-size:.84rem}.meter{height:12px;border-radius:999px;background:#e8eef6;overflow:hidden;border:1px solid #d8e2ee}.fill{display:block;height:100%;border-radius:999px}.fill.start{background:linear-gradient(90deg,#60a5fa,#2563eb)}.fill.ok{background:linear-gradient(90deg,#86efac,#16a34a)}.fill.warn{background:linear-gradient(90deg,#fde68a,#d97706)}.fill.bad{background:linear-gradient(90deg,#fca5a5,#dc2626)}.fill.neutral{background:linear-gradient(90deg,#cbd5e1,#64748b)}.fill.report{background:linear-gradient(90deg,#67e8f9,#0284c7)}.fill.csv{background:linear-gradient(90deg,#c4b5fd,#7c3aed)}table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:12px;overflow:hidden}th,td{padding:8px 9px;border-bottom:1px solid #e8eef6;text-align:left;vertical-align:top;font-size:.84rem}th{background:#f8fbff;color:#334155;position:sticky;top:0;z-index:1}tr:last-child td{border-bottom:none}.scroll{overflow:auto;max-height:440px;border-radius:12px}.scroll table{min-width:760px}.path{word-break:break-all}code{font-family:Consolas,monospace;font-size:.8rem;word-break:break-all}.row-start td{background:#eff6ff}.row-ok td{background:#f0fdf4}.row-warn td{background:#fffbeb}.row-bad td{background:#fef2f2}.row-neutral td{background:#f8fafc}.chip{display:inline-block;padding:2px 7px;border-radius:999px;font-size:.74rem;font-weight:700}.chip.start{background:#dbeafe;color:#1d4ed8}.chip.ok{background:#dcfce7;color:#166534}.chip.warn{background:#fef3c7;color:#92400e}.chip.bad{background:#fee2e2;color:#991b1b}.chip.neutral{background:#e2e8f0;color:#334155}@media(max-width:1020px){.layout{grid-template-columns:1fr}.wrap{padding:12px}th,td{font-size:.79rem;padding:7px 8px}}@media(max-width:760px){.grid{grid-template-columns:1fr 1fr}.hero{padding:12px}.section{padding:10px}.bar-head{font-size:.8rem}}@media(max-width:560px){.grid{grid-template-columns:1fr}.wrap{padding:10px}.scroll table{min-width:680px}h1{font-size:1.05rem}}</style>"
    logFile.WriteLine "<style>.dfir-timeline{list-style:none;margin:0;padding:2px 0 2px 22px;position:relative}.dfir-timeline:before{content:'';position:absolute;left:7px;top:4px;bottom:4px;width:2px;background:linear-gradient(#bfdbfe,#cbd5e1)}.dfir-item{position:relative;margin:0 0 12px 0}.dfir-dot{position:absolute;left:-19px;top:10px;width:12px;height:12px;border-radius:50%;background:#94a3b8;border:2px solid #fff;box-shadow:0 0 0 2px #e2e8f0}.dfir-item.bad .dfir-dot{background:#dc2626}.dfir-item.warn .dfir-dot{background:#d97706}.dfir-item.ok .dfir-dot{background:#16a34a}.dfir-card{background:#fff;border:1px solid #dbe5f0;border-radius:14px;padding:10px 11px;box-shadow:0 8px 20px rgba(15,23,42,.05)}.dfir-head{display:flex;justify-content:space-between;gap:8px;align-items:center;flex-wrap:wrap}.dfir-head time{font-weight:700;font-size:.82rem;color:#0f172a}.dfir-title{margin-top:4px;font-weight:700;font-size:.92rem}.dfir-meta{margin-top:3px;color:#64748b;font-size:.78rem}.dfir-text{margin-top:6px;font-size:.82rem;color:#334155;word-break:break-word}@media(max-width:760px){.dfir-timeline{padding-left:18px}.dfir-dot{left:-15px;width:10px;height:10px}.dfir-card{padding:9px}}</style>"
    logFile.WriteLine "<style>.section,.hero,.card{max-width:100%;overflow:hidden}.scroll{max-width:100%}.scroll table{width:max-content;min-width:100%}details.status-collapsible{padding:0;overflow:hidden}details.status-collapsible[open]{padding:14px}details.status-collapsible>summary{list-style:none;cursor:pointer;padding:14px 16px;font-weight:700;color:#0f172a;display:flex;align-items:center;gap:10px;background:linear-gradient(180deg,#f8fbff,#eef5ff);border-bottom:1px solid #dbe5f0}details.status-collapsible>summary::-webkit-details-marker{display:none}details.status-collapsible>summary::before{content:'+';width:20px;height:20px;border-radius:999px;display:inline-flex;align-items:center;justify-content:center;background:#dbeafe;color:#1d4ed8;font-weight:700}details.status-collapsible[open]>summary::before{content:'-'}details.status-collapsible[open]>summary{margin:-14px -14px 10px -14px}.canvas,canvas{max-width:100%}</style>"
    logFile.WriteLine "</head><body><main class='wrap'>"
    logFile.WriteLine "<section class='hero'>"
    logFile.WriteLine "<h1>Status Log da Coleta</h1>"
    logFile.WriteLine "<div class='muted'>Host: <strong>" & HtmlEncode(strComputer) & "</strong> | Usuario: <strong>" & HtmlEncode(objNetwork.UserDomain & "\" & objNetwork.UserName) & "</strong> | Run ID: <strong>" & HtmlEncode(strRunId) & "</strong></div>"
    logFile.WriteLine "<div class='grid'>"
    logFile.WriteLine "<div class='card'><div class='label'>Inicio</div><div class='value'>" & HtmlEncode(strStartTime) & "</div></div>"
    logFile.WriteLine "<div class='card'><div class='label'>Fim</div><div class='value'>" & HtmlEncode(endStamp) & "</div></div>"
    logFile.WriteLine "<div class='card'><div class='label'>Duracao Total</div><div class='value'>" & HtmlEncode(totalDuration) & "</div></div>"
    logFile.WriteLine "<div class='card'><div class='label'>Eventos / Atividades</div><div class='value'>" & logEventCount & " eventos | " & logActivityCount & " atividades</div></div>"
    logFile.WriteLine "<div class='card'><div class='label'>Checklist OK (itens rodados)</div><div class='value'>" & HtmlEncode(checklistText) & "</div></div>"
    logFile.WriteLine "<div class='card'><div class='label'>Pesquisas / Comandos</div><div class='value'>" & HtmlEncode(cmdStatsText) & "<br><span class='muted'>Tempo medio: " & HtmlEncode(avgCmdDurationText) & "</span></div></div>"
    logFile.WriteLine "<div class='card'><div class='label'>Status</div><div class='value'>" & warnBadge & " " & errBadge & "</div></div>"
    logFile.WriteLine "<div class='card'><div class='label'>MD5 do " & HtmlEncode(strComputer) & ".html</div><div class='value'><code>" & HtmlEncode(reportMd5) & "</code></div></div>"
    logFile.WriteLine "<div class='card'><div class='label'>Service Tag</div><div class='value'>" & HtmlEncode(Nz(hostServiceTag, "-")) & "</div></div>"
    logFile.WriteLine "<div class='card'><div class='label'>Host / Hardware</div><div class='value'>" & HtmlEncode(Nz(hostManufacturerName, "-")) & " / " & HtmlEncode(Nz(hostModelName, "-")) & "</div></div>"
    logFile.WriteLine "<div class='card'><div class='label'>Tipo / Mobilidade</div><div class='value'>" & HtmlEncode(Nz(hostAssetType, "Indeterminado")) & " | Baterias: " & hostBatteryCount & "</div></div>"
    logFile.WriteLine "</div></section>"

    Call WriteStatusIncidentFocusSection(logFile)

    logFile.WriteLine "<div class='layout'>"
    logFile.WriteLine "<section class='section'>"
    logFile.WriteLine "<h2>Grafico de Volumes por Status</h2>"
    logFile.WriteLine "<div class='section-note'>Volume de eventos registrados por classe de status.</div>"
    logFile.WriteLine statusChartHtml
    logFile.WriteLine "</section>"

    logFile.WriteLine "<section class='section'>"
    logFile.WriteLine "<h2>Validacao START/END (pareamento)</h2>"
    logFile.WriteLine statusReconHtml
    logFile.WriteLine "</section>"

    logFile.WriteLine "<section class='section'>"
    logFile.WriteLine "<h2>Grafico de Volumes de Arquivos Gerados</h2>"
    logFile.WriteLine "<div class='section-note'>Comparativo de tamanho dos artefatos gerados nesta execucao.</div>"
    logFile.WriteLine fileChartHtml
    logFile.WriteLine "</section>"

    logFile.WriteLine "<section class='section'>"
    logFile.WriteLine "<h2>Saude das Pesquisas e Exportacoes</h2>"
    logFile.WriteLine "<div class='section-note'>Execucoes, timeouts/falhas e volume de arquivos exportados por bloco (seguranca/ameacas).</div>"
    logFile.WriteLine cmdQualityChartHtml
    logFile.WriteLine "<div class='scroll'><table><tr><th>Bloco</th><th>Arquivos exportados</th><th>Pasta</th><th>Data backup (criacao da pasta)</th></tr>" & exportDetailRows & "</table></div>"
    logFile.WriteLine "</section>"

    logFile.WriteLine "<section class='section'>"
    logFile.WriteLine "<h2>Detalhes de EVT/EVTX exportados e chaves de registro (.reg)</h2>"
    logFile.WriteLine "<div class='section-note'>Substitui indicadores de deteccao por evidencias exportadas: logs EVT/EVTX, raizes de registro completas (.reg) e pequenos artefatos em <code>export\\artefatos\\&lt;categoria&gt;</code> / <code>artefatos\\originais</code>.</div>"
    logFile.WriteLine "<div class='scroll'><table><tr><th>Categoria</th><th>Artefato</th><th>Status</th><th>Caminho</th><th>Tamanho</th><th>Observacao</th></tr>" & eventExportRowsHtml & "</table></div>"
    logFile.WriteLine "<div class='scroll' style='margin-top:10px'><table><tr><th>Categoria</th><th>Artefato</th><th>Status</th><th>Caminho</th><th>Tamanho</th><th>Observacao</th></tr>" & registryRootRowsHtml & "</table></div>"
    logFile.WriteLine "<div class='scroll' style='margin-top:10px'><table><tr><th>Categoria</th><th>Artefato</th><th>Status</th><th>Caminho</th><th>Tamanho</th><th>Observacao</th></tr>" & smallArtifactRowsHtml & "</table></div>"
    logFile.WriteLine "</section>"

    logFile.WriteLine "<section class='section'>"
    logFile.WriteLine "<h2>Perfil do Host / Hardware (resumo da coleta)</h2>"
    logFile.WriteLine "<div class='section-note'>Metricas consolidadas a partir de hardware, discos, rede, seguranca e servicos; inclui indicador de laptop/portatil.</div>"
    logFile.WriteLine hostInfoHtml
    logFile.WriteLine hostProfileChartHtml
    logFile.WriteLine "</section>"

    logFile.WriteLine "<section class='section full'>"
    logFile.WriteLine "<h2>Detalhes e Integridade</h2>"
    logFile.WriteLine "<div class='section-note'>Inclui hashes MD5 de artefatos principais (relatorio/custody/zip) e registra integridade adicional no custody CSV, incluindo o hash do StatusLog apos a compactacao.</div>"
    logFile.WriteLine "<div class='scroll'><table>" & detailTableHtml & "</table></div>"
    logFile.WriteLine "</section>"

    logFile.WriteLine "<section class='section full'>"
    logFile.WriteLine "<h2>Pesquisas / Comandos (tempo por pesquisa)</h2>"
    logFile.WriteLine "<div class='section-note'>Cada chamada a comando externo e registrada com inicio/fim/duracao.</div>"
    logFile.WriteLine "<div class='scroll'><table><tr><th>#</th><th>Pesquisa</th><th>Inicio</th><th>Fim</th><th>Duracao</th><th>Resultado</th></tr>" & queryHtml & "</table></div>"
    logFile.WriteLine "</section>"

    logFile.WriteLine "<section class='section'>"
    logFile.WriteLine "<h2>Atividades (inicio/fim/duracao)</h2>"
    logFile.WriteLine "<div class='section-note'>Atividades consolidadas a partir de pares START/END.</div>"
    logFile.WriteLine "<div class='scroll'><table><tr><th>#</th><th>Atividade</th><th>Inicio</th><th>Fim</th><th>Duracao</th><th>Status final</th><th>Detalhes</th></tr>" & activityHtml & "</table></div>"
    logFile.WriteLine "</section>"

    logFile.WriteLine "<section class='section full'>"
    logFile.WriteLine "<h2>Timeline DFIR priorizada</h2>"
    logFile.WriteLine "<div class='section-note'>Ordenacao crescente por timestamp de: Usuario criado, Ultimo usuario acessado e Programas ultima execucao (proxy Prefetch/LastWrite). Foco em red/yellow flags e triagem rapida.</div>"
    If Trim(dfirPriorityTimelineHtml) = "" Then
        logFile.WriteLine "<div class='muted'>Sem dados suficientes para montar a timeline DFIR priorizada (perfis/prefetch indisponiveis).</div>"
    Else
        logFile.WriteLine dfirPriorityTimelineHtml
    End If
    logFile.WriteLine "</section>"

    logFile.WriteLine "<section class='section full'>"
    logFile.WriteLine "<h2>Timeline de Artefatos do Usuario (criacao / acesso / modificacao)</h2>"
    logFile.WriteLine "<div class='section-note'>Gerada a partir da coleta direta de atalhos da pasta Recent do usuario atual. Mostra timestamps do sistema de arquivos e contagem por tipo de evento.</div>"
    logFile.WriteLine userTimelineChartHtml
    logFile.WriteLine "<div class='scroll'><table><tr><th>Datetime</th><th>Tipo</th><th>Item</th><th>Caminho</th></tr>" & userTimelineHtml & "</table></div>"
    logFile.WriteLine "</section>"

    logFile.WriteLine "<section class='section'>"
    logFile.WriteLine "<h2>Timeline de Eventos</h2>"
    logFile.WriteLine "<div class='section-note'>Colunas: item / evento / campo / datetime / valor.</div>"
    logFile.WriteLine "<div class='scroll'><table><tr><th>#</th><th>Datetime</th><th>Item</th><th>Evento</th><th>Campo</th><th>Valor</th><th>Classe</th></tr>" & timelineHtml & "</table></div>"
    logFile.WriteLine "</section>"

    logFile.WriteLine "</div>"
    logFile.WriteLine "<script>document.addEventListener('DOMContentLoaded',function(){Array.prototype.slice.call(document.querySelectorAll('section.section')).forEach(function(sec){var h2=sec.querySelector(':scope > h2')||sec.querySelector('h2');if(!h2){return;}var d=document.createElement('details');d.className='section status-collapsible'; if(sec.classList.contains('full')){d.className=d.className+' full';} d.open=false; var s=document.createElement('summary'); s.textContent=(h2.textContent||'Bloco').replace(/\\s+/g,' ').trim(); d.appendChild(s); if(h2.parentNode===sec){sec.removeChild(h2);} while(sec.firstChild){d.appendChild(sec.firstChild);} sec.parentNode.replaceChild(d,sec);});});</script>"
    logFile.WriteLine "</main></body></html>"
    logFile.Close

    CreateStatusBundleZip mainHtmlFile
    ReplaceStatusLogZipPlaceholders maxFileBytes, endStamp

    logMd5 = GetFileMD5(strLogHtmlFile)
    If Trim(CStr(logMd5 & "")) <> "" And UCase(Trim(CStr(logMd5 & ""))) <> "N/A" Then
        LogCustody "INTEGRITY", "OK", "MD5 status log=" & logMd5
    Else
        LogCustody "INTEGRITY", "WARN", "Nao foi possivel calcular MD5 do status log"
    End If
End Sub

Sub WriteStatusIncidentFocusSection(logFile)
    logFile.WriteLine "<section class='section' style='margin-top:14px'>"
    logFile.WriteLine "<h2>Foco de triagem (eventos e chaves de registro agrupados)</h2>"
    logFile.WriteLine "<div class='section-note'>Guia rapido para leitura do status/timeline e correlacao no host. Eventos abaixo refletem os grupos priorizados para incidente.</div>"

    logFile.WriteLine "<h3>Eventos Windows / PowerShell / Sysmon (grupos priorizados)</h3>"
    logFile.WriteLine "<div class='scroll'><table><tr><th>Grupo</th><th>Eventos / IDs</th><th>Foco analitico</th></tr>"
    logFile.WriteLine "<tr><td>Autenticacao / Acesso</td><td>4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4771, 4776, 4740</td><td>Logon sucesso/falha, credenciais explicitas, privilegios especiais, Kerberos/NTLM e bloqueio de conta (spray/bruteforce/movimentacao lateral).</td></tr>"
    logFile.WriteLine "<tr><td>RDP</td><td>4624 (Logon Type 10), 4778, 4779</td><td>Logon remoto interativo, reconexao e desconexao de sessao. Correlacionar IP/origem/horario.</td></tr>"
    logFile.WriteLine "<tr><td>Contas / Privilegio / Persistencia</td><td>4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4756, 4738, 4767</td><td>Criacao, habilitacao, reset/troca de senha, alteracao de grupos privilegiados e modificacoes de conta.</td></tr>"
    logFile.WriteLine "<tr><td>Execucao de processo / Persistencia</td><td>4688, 4689, 4697, 7045, 7040, 4698, 4702, 4719, 1100, 1102, 104</td><td>Processos, servicos, tarefas agendadas, alteracoes de auditoria e limpeza/parada de logs (defense evasion).</td></tr>"
    logFile.WriteLine "<tr><td>PowerShell</td><td>4103, 4104, 4105, 4106</td><td>Module logging, script block e pipeline (execucao fileless/ofuscada e trilha de comando).</td></tr>"
    logFile.WriteLine "<tr><td>Sysmon (se habilitado)</td><td>1, 3, 4, 7, 8, 10, 11, 13</td><td>Processo, rede, estado do servico, DLL load, injecao, acesso a processo, criacao de arquivo e modificacao de registro.</td></tr>"
    logFile.WriteLine "<tr><td>File system / Delecao em massa</td><td>4656, 4659, 4663, 4660, 4670, 4907</td><td>Handles, delete intent, operacoes em objetos, delecao, ACL e SACL (picos e comportamento destrutivo).</td></tr>"
    logFile.WriteLine "<tr><td>Rede / Exfiltracao</td><td>5156, 5157, 5158, 5140, 5145, 5142, 5144</td><td>Conexoes permitidas/bloqueadas, bind local, shares SMB e operacoes detalhadas em share.</td></tr>"
    logFile.WriteLine "<tr><td>BITS (exfiltracao stealth)</td><td>59, 60, 63</td><td>Criacao, transferencia e conclusao de jobs BITS para upload/download discreto.</td></tr>"
    logFile.WriteLine "<tr><td>Credential access / Dump</td><td>4688 (ferramentas dump), 4656/4663 (LSASS), Sysmon 10 (LSASS), Sysmon 11 (.dmp)</td><td>Execucao de utilitarios de dump e acesso/leitura de memoria sensivel (LSASS).</td></tr>"
    logFile.WriteLine "<tr><td>Compressao / Preparacao para exfil</td><td>4688 (7z/rar/tar/PowerShell), 4663 (leitura massiva), Sysmon 11 (.zip/.7z/.rar)</td><td>Preparacao de lotes para exfiltracao e criacao de artefatos compactados.</td></tr>"
    logFile.WriteLine "<tr><td>Shadow copy / Impacto / Ransomware</td><td>System 25, 8193, 8222, 5038</td><td>VSS/shadow copy, erros de VSS e integridade de codigo (sinais de impacto/evasao).</td></tr>"
    logFile.WriteLine "<tr><td>Prioridade alta em incidente</td><td>4688, 4663, 4624/4625, 4672, 4769, 7045, 4698, 5156, 1102, 4104, Sysmon 1/3/10/11</td><td>Conjunto minimo de priorizacao para triagem inicial, escopo e contencao.</td></tr>"
    logFile.WriteLine "</table></div>"

    logFile.WriteLine "<h3>Chaves de registro para correlacao (persistencia, auditoria e acesso)</h3>"
    logFile.WriteLine "<div class='section-note'>Lista de referencia para checagem manual/automatizada. Alguns itens podem nao existir conforme versao/politica do Windows.</div>"
    logFile.WriteLine "<div class='scroll'><table><tr><th>Grupo</th><th>Chaves (HKLM/HKCU)</th><th>Uso forense</th></tr>"
    logFile.WriteLine "<tr><td>RDP / Terminal Services</td><td><code>HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server</code><br><code>HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp</code><br><code>HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services</code></td><td>Habilitacao de RDP, configuracoes de sessao e politicas de acesso remoto.</td></tr>"
    logFile.WriteLine "<tr><td>PowerShell Logging</td><td><code>HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging</code><br><code>HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging</code><br><code>HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription</code></td><td>Verifica se 4103/4104 e transcricao estao habilitados e como foram configurados.</td></tr>"
    logFile.WriteLine "<tr><td>Auditoria / Event Log</td><td><code>HKLM\SYSTEM\CurrentControlSet\Services\EventLog</code><br><code>HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog</code><br><code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels</code></td><td>Retencao, canais e parametros de logs (inclui indicios de reducao/alteracao de trilha).</td></tr>"
    logFile.WriteLine "<tr><td>Persistencia - Run / Winlogon</td><td><code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code><br><code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce</code><br><code>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</code><br><code>HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce</code><br><code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon</code></td><td>Autostart tradicional, shell/userinit e persistencia no logon.</td></tr>"
    logFile.WriteLine "<tr><td>Persistencia - Services / Tasks</td><td><code>HKLM\SYSTEM\CurrentControlSet\Services</code><br><code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks</code><br><code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree</code></td><td>Correlaciona 4697/7045/7040 e 4698/4702 com registros persistidos.</td></tr>"
    logFile.WriteLine "<tr><td>Persistencia / Evasao avancada</td><td><code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options</code><br><code>HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs</code><br><code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad</code></td><td>IFEO hijack, AppInit e extensoes de shell usadas em persistencia/evasao.</td></tr>"
    logFile.WriteLine "<tr><td>Credenciais / LSA</td><td><code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa</code><br><code>HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest</code><br><code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters</code></td><td>Hardening/legacy que impacta NTLM/Kerberos e risco de credential access.</td></tr>"
    logFile.WriteLine "<tr><td>Firewall / Rede / SMB / BITS</td><td><code>HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy</code><br><code>HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters</code><br><code>HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters</code><br><code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\BITS</code></td><td>Correlaciona 5156/5157/5158, shares SMB, SMBv1 e comportamento de jobs BITS.</td></tr>"
    logFile.WriteLine "<tr><td>Sysmon / Telemetria</td><td><code>HKLM\SYSTEM\CurrentControlSet\Services\Sysmon64</code> (ou <code>Sysmon</code>)<br><code>HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv</code><br><code>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational</code></td><td>Estado/configuracao do Sysmon e disponibilidade do canal operacional.</td></tr>"
    logFile.WriteLine "<tr><td>VSS / Shadow Copy</td><td><code>HKLM\SYSTEM\CurrentControlSet\Services\VSS</code><br><code>HKLM\SYSTEM\CurrentControlSet\Services\VolSnap</code></td><td>Referencia para correlacao com eventos VSS (8193/8222) e impacto em recuperacao.</td></tr>"
    logFile.WriteLine "</table></div>"
    logFile.WriteLine "</section>"
End Sub
Sub LogCustody(etapa, status, detalhes)
    Dim ts, tsLocal, userRef, hostRef, d, sUpper, cssClass
    Dim eventIndex, endTick, startTick, startStamp, durationText
    Dim detailField, detailValue, eventCellHtml, isChecklist

    On Error Resume Next
    ts = TimestampISO(Now)
    tsLocal = TimestampLocalMillis(Now)
    userRef = objNetwork.UserDomain & "\" & objNetwork.UserName
    hostRef = strComputer
    d = Replace(Nz(detalhes, ""), Chr(34), "''")
    sUpper = UCase(Trim(CStr(status & "")))
    cssClass = LogStatusClass(sUpper)
    detailField = GetLogDetailField(d)
    detailValue = GetLogDetailValue(d)
    eventCellHtml = "<span class='chip " & cssClass & "'>" & HtmlEncode(CStr(status)) & "</span>"
    isChecklist = IsChecklistStageName(etapa)

    logEventCount = CLng(0 + logEventCount) + 1
    eventIndex = logEventCount
    Select Case cssClass
        Case "start": logStartCount = CLng(0 + logStartCount) + 1
        Case "ok": logOkCount = CLng(0 + logOkCount) + 1
        Case "warn": logWarnCount = CLng(0 + logWarnCount) + 1
        Case "bad": logErrorCount = CLng(0 + logErrorCount) + 1
        Case Else: logNeutralCount = CLng(0 + logNeutralCount) + 1
    End Select
    If sUpper = "END" Then logEndCount = CLng(0 + logEndCount) + 1
    If sUpper = "OK" Then logPureOkCount = CLng(0 + logPureOkCount) + 1

    If isChecklist And sUpper = "START" Then checklistTotalCount = CLng(0 + checklistTotalCount) + 1
    If isChecklist And sUpper = "END" Then checklistOkCount = CLng(0 + checklistOkCount) + 1

strLogTimelineRows = strLogTimelineRows & "<tr class='row-" & cssClass & "'><td>" & eventIndex & "</td><td>" & HtmlEncode(tsLocal) & "</td><td>" & HtmlEncode(CStr(etapa)) & "</td><td>" & eventCellHtml & "</td><td>" & HtmlEncode(detailField) & "</td><td>" & HtmlEncode(detailValue) & "</td><td>" & HtmlEncode(cssClass) & "</td></tr>"
    If cssClass = "warn" Or cssClass = "bad" Then
        warnErrorDetailCount = CLng(0 + warnErrorDetailCount) + 1
        strWarnErrorDetailRows = strWarnErrorDetailRows & "<tr class='row-" & cssClass & "'><td>" & warnErrorDetailCount & "</td><td>" & HtmlEncode(tsLocal) & "</td><td>" & HtmlEncode(CStr(etapa)) & "</td><td>" & eventCellHtml & "</td><td>" & HtmlEncode(detailField) & "</td><td class='path'>" & HtmlEncode(detailValue) & "</td></tr>"
    End If

    If sUpper = "START" Then
        objActivityStartStamp(CStr(etapa)) = tsLocal
        objActivityStartTick(CStr(etapa)) = CStr(Timer)
    ElseIf sUpper = "END" Then
        If objActivityStartStamp.Exists(CStr(etapa)) Then
            startStamp = CStr(objActivityStartStamp(CStr(etapa)))
            startTick = CDbl(0 + objActivityStartTick(CStr(etapa)))
            endTick = Timer
            durationText = FormatDurationFromTicks(startTick, endTick)
            logActivityCount = CLng(0 + logActivityCount) + 1
            strLogActivityRows = strLogActivityRows & "<tr class='row-" & cssClass & "'><td>" & logActivityCount & "</td><td>" & HtmlEncode(CStr(etapa)) & "</td><td>" & HtmlEncode(startStamp) & "</td><td>" & HtmlEncode(tsLocal) & "</td><td>" & HtmlEncode(durationText) & "</td><td>" & HtmlEncode(CStr(status)) & "</td><td>" & HtmlEncode(d) & "</td></tr>"
            If UCase(CStr(etapa)) = "PESQUISA" Then
                logQueryCount = CLng(0 + logQueryCount) + 1
                strLogQueryRows = strLogQueryRows & "<tr class='row-" & cssClass & "'><td>" & logQueryCount & "</td><td class='path'>" & HtmlEncode(GetPesquisaCommand(d)) & "</td><td>" & HtmlEncode(startStamp) & "</td><td>" & HtmlEncode(tsLocal) & "</td><td>" & HtmlEncode(durationText) & "</td><td>" & HtmlEncode(GetPesquisaResultado(d)) & "</td></tr>"
            End If
            logEndWithStartCount = CLng(0 + logEndWithStartCount) + 1
            objActivityStartStamp.Remove CStr(etapa)
            objActivityStartTick.Remove CStr(etapa)
        Else
            logEndWithoutStartCount = CLng(0 + logEndWithoutStartCount) + 1
        End If
    End If

    If Not (objCustodyFile Is Nothing) Then
        objCustodyFile.WriteLine Chr(34) & ts & Chr(34) & "," & Chr(34) & strRunId & Chr(34) & "," & Chr(34) & etapa & Chr(34) & "," & Chr(34) & status & Chr(34) & "," & Chr(34) & d & Chr(34) & "," & Chr(34) & userRef & Chr(34) & "," & Chr(34) & hostRef & Chr(34)
        If Err.Number <> 0 Then
            Err.Clear
            threatEventTotalHits = 0
threatEventAlertCount = 0
threatEventWarnCount = 0
threatEventInfoCount = 0
threatHighPriorityHits = 0
threatSecurityHits = 0
threatPowerShellHits = 0
threatSysmonHits = 0
threatBitsHits = 0
threatSystemHits = 0
threatRegistryChecks = 0
threatRegistryAlertCount = 0
threatRegistryWarnCount = 0
threatRegistryInfoCount = 0
threatRedHits = 0
threatYellowHits = 0
threatRegistryPersistHits = 0
threatRegistryAccessHits = 0
threatRegistryTelemetryHits = 0
threatRegistryCredHits = 0
threatRegistryNetworkHits = 0
hostManufacturerName = ""
hostModelName = ""
hostAssetType = "Indeterminado"
hostBatteryCount = 0
hostCpuLogicalCount = 0
hostRamTotalBytes = 0
serviceTotalCount = 0
serviceRunningCount = 0
serviceStoppedCount = 0
strDfirTimelineRecords = ""
dfirTimelineRecordCount = 0
prefetchTimelineCaptured = False
Set objCustodyFile = Nothing
        End If
    End If
    On Error Goto 0
End Sub

Function TimestampISO(dt)
    Dim ms
    Randomize
    ms = Right("00" & CLng(Rnd() * 999), 3)
    TimestampISO = Year(dt) & "-" & Right("0" & Month(dt),2) & "-" & Right("0" & Day(dt),2) & "T" & Right("0" & Hour(dt),2) & ":" & Right("0" & Minute(dt),2) & ":" & Right("0" & Second(dt),2) & "." & ms
End Function

Function ParseTimeZoneOffset(v)
    Dim m, sign, absM, hh, mm
    If Not IsNumeric(v) Then
        ParseTimeZoneOffset = Nz(v, "-")
        Exit Function
    End If
    m = CLng(v)
    sign = "+"
    If m < 0 Then sign = "-"
    absM = Abs(m)
    hh = Int(absM / 60)
    mm = absM Mod 60
    ParseTimeZoneOffset = "UTC" & sign & Right("0" & hh, 2) & ":" & Right("0" & mm, 2) & " (offset atual: " & m & " min)"
End Function

Function ParseWindowsLanguageCode(v)
    Dim n, label
    If Not IsNumeric(v) Then
        ParseWindowsLanguageCode = Nz(v, "-")
        Exit Function
    End If
    n = CLng(v)
    Select Case n
        Case 1046: label = "Portugues (Brasil)"
        Case 2070: label = "Portugues (Portugal)"
        Case 1033: label = "Ingles (Estados Unidos)"
        Case 2057: label = "Ingles (Reino Unido)"
        Case 3082: label = "Espanhol (Espanha)"
        Case 1034: label = "Espanhol"
        Case 1031: label = "Alemao"
        Case 1036: label = "Frances"
        Case 1040: label = "Italiano"
        Case 1041: label = "Japones"
        Case 1042: label = "Coreano"
        Case 2052: label = "Chines (Simplificado)"
        Case 1028: label = "Chines (Tradicional)"
        Case Else: label = "LCID nao mapeado"
    End Select
    ParseWindowsLanguageCode = label & " [" & n & "]"
End Function
Function TimestampLocalMillis(dt)
    Dim ms, frac
    frac = Timer - Int(Timer)
    If frac < 0 Then frac = 0
    ms = Right("000" & CStr(Int(frac * 1000)), 3)
    TimestampLocalMillis = Right("0" & Day(dt), 2) & "/" & Right("0" & Month(dt), 2) & "/" & Year(dt) & _
        " " & Right("0" & Hour(dt), 2) & ":" & Right("0" & Minute(dt), 2) & ":" & Right("0" & Second(dt), 2) & "." & ms
End Function

Function GetLeafNameFromPath(fullPath)
    Dim s, p
    s = CStr(Nz(fullPath, ""))
    If s = "" Then
        GetLeafNameFromPath = "-"
        Exit Function
    End If
    p = InStrRev(s, "\")
    If p > 0 Then
        GetLeafNameFromPath = Mid(s, p + 1)
    Else
        GetLeafNameFromPath = s
    End If
End Function

Function IsRelevantUserProfileName(profileName)
    Dim n
    n = UCase(Trim(CStr(profileName & "")))
    If n = "" Then IsRelevantUserProfileName = False: Exit Function
    Select Case n
        Case "PUBLIC", "DEFAULT", "DEFAULT USER", "ALL USERS", "DEFAULTAPPPOOL", "DEFAULTUSER0", "WDAGUTILITYACCOUNT"
            IsRelevantUserProfileName = False
        Case Else
            IsRelevantUserProfileName = True
    End Select
End Function

Function PrefetchProgramNameFromPf(fileName)
    Dim n, p
    n = CStr(Nz(fileName, ""))
    If UCase(Right(n, 3)) = ".PF" Then n = Left(n, Len(n) - 3)
    p = InStrRev(n, "-")
    If p > 1 Then
        PrefetchProgramNameFromPf = Left(n, p - 1)
    Else
        PrefetchProgramNameFromPf = n
    End If
    If Trim(PrefetchProgramNameFromPf) = "" Then PrefetchProgramNameFromPf = Nz(fileName, "(pf)")
End Function

Function FormatDateTimeLocal(dt)
    If Not IsDate(dt) Then
        FormatDateTimeLocal = "-"
        Exit Function
    End If
    FormatDateTimeLocal = Right("0" & Day(dt), 2) & "/" & Right("0" & Month(dt), 2) & "/" & Year(dt) & _
        " " & Right("0" & Hour(dt), 2) & ":" & Right("0" & Minute(dt), 2) & ":" & Right("0" & Second(dt), 2)
End Function

Function SortKeyFromDateValue(dt)
    If Not IsDate(dt) Then
        SortKeyFromDateValue = ""
        Exit Function
    End If
    SortKeyFromDateValue = Year(dt) & "-" & Right("0" & Month(dt), 2) & "-" & Right("0" & Day(dt), 2) & " " & _
        Right("0" & Hour(dt), 2) & ":" & Right("0" & Minute(dt), 2) & ":" & Right("0" & Second(dt), 2)
End Function

Function SortKeyFromWmiDate(wmiDate)
    Dim d
    d = CStr(Nz(wmiDate, ""))
    If Len(d) < 14 Then
        SortKeyFromWmiDate = ""
        Exit Function
    End If
    SortKeyFromWmiDate = Left(d, 4) & "-" & Mid(d, 5, 2) & "-" & Mid(d, 7, 2) & " " & Mid(d, 9, 2) & ":" & Mid(d, 11, 2) & ":" & Mid(d, 13, 2)
End Function

Function DfirTimelineFieldSafe(v)
    Dim s
    s = CStr(Nz(v, "-"))
    s = Replace(s, Chr(30), "/")
    s = Replace(s, vbCrLf, " | ")
    s = Replace(s, vbCr, " | ")
    s = Replace(s, vbLf, " | ")
    DfirTimelineFieldSafe = s
End Function

Sub AppendDfirTimelineRecordFromDate(dt, categoryText, itemText, eventText, valueText, sourceText, severityText)
    Dim sortKey, displayText
    sortKey = SortKeyFromDateValue(dt)
    If sortKey = "" Then Exit Sub
    displayText = FormatDateTimeLocal(dt)
    AppendDfirTimelineRecord sortKey, displayText, categoryText, itemText, eventText, valueText, sourceText, severityText
End Sub

Sub AppendDfirTimelineRecordFromWmi(wmiDate, categoryText, itemText, eventText, valueText, sourceText, severityText)
    Dim sortKey, displayText
    sortKey = SortKeyFromWmiDate(wmiDate)
    If sortKey = "" Then Exit Sub
    displayText = WmiDateToString(wmiDate)
    AppendDfirTimelineRecord sortKey, displayText, categoryText, itemText, eventText, valueText, sourceText, severityText
End Sub

Sub AppendDfirTimelineRecord(sortKey, displayTime, categoryText, itemText, eventText, valueText, sourceText, severityText)
    Dim sep, line
    sep = Chr(30)
    line = DfirTimelineFieldSafe(sortKey) & sep & DfirTimelineFieldSafe(displayTime) & sep & DfirTimelineFieldSafe(categoryText) & sep & _
           DfirTimelineFieldSafe(itemText) & sep & DfirTimelineFieldSafe(eventText) & sep & DfirTimelineFieldSafe(valueText) & sep & _
           DfirTimelineFieldSafe(sourceText) & sep & DfirTimelineFieldSafe(UCase(Nz(severityText, "INFO")))
    If strDfirTimelineRecords <> "" Then strDfirTimelineRecords = strDfirTimelineRecords & vbLf
    strDfirTimelineRecords = strDfirTimelineRecords & line
    dfirTimelineRecordCount = CLng(0 + dfirTimelineRecordCount) + 1
End Sub

Function SortStringArrayAsc(arr)
    Dim i, j, tmp
    If Not IsArray(arr) Then
        SortStringArrayAsc = arr
        Exit Function
    End If
    If UBound(arr) <= 0 Then
        SortStringArrayAsc = arr
        Exit Function
    End If
    For i = 0 To UBound(arr) - 1
        For j = i + 1 To UBound(arr)
            If CStr(arr(j)) < CStr(arr(i)) Then
                tmp = arr(i)
                arr(i) = arr(j)
                arr(j) = tmp
            End If
        Next
    Next
    SortStringArrayAsc = arr
End Function

Function DfirTimelineSeverityCss(sevText)
    Select Case UCase(Nz(sevText, "INFO"))
        Case "ALERTA", "BAD": DfirTimelineSeverityCss = "bad"
        Case "WARN", "WARNING": DfirTimelineSeverityCss = "warn"
        Case Else: DfirTimelineSeverityCss = "ok"
    End Select
End Function

Function BuildDfirPriorityTimelineHtml()
    Dim sep, rawLines, lines, i, line, parts, htmlOut
    Dim cat, itemText, eventText, valueText, sourceText, sevText, displayText, skipItem
    Dim cntUserCreate, cntLastUser, cntProgram, maxUserCreate, maxLastUser, maxProgram

    If Trim(CStr(strDfirTimelineRecords & "")) = "" Then
        BuildDfirPriorityTimelineHtml = ""
        Exit Function
    End If

    sep = Chr(30)
    rawLines = Split(strDfirTimelineRecords, vbLf)
    lines = SortStringArrayAsc(rawLines)
    htmlOut = "<ol class='dfir-timeline'>"
    maxUserCreate = 24
    maxLastUser = 24
    maxProgram = 36

    For i = 0 To UBound(lines)
        line = Trim(CStr(lines(i) & ""))
        If line <> "" Then
            parts = Split(line, sep)
            If UBound(parts) >= 7 Then
                displayText = parts(1)
                cat = parts(2)
                itemText = parts(3)
                eventText = parts(4)
                valueText = parts(5)
                sourceText = parts(6)
                sevText = parts(7)
                skipItem = False

                If UCase(cat) = "USUARIO CRIADO" Then
                    If cntUserCreate >= maxUserCreate Then
                        skipItem = True
                    Else
                        cntUserCreate = cntUserCreate + 1
                    End If
                ElseIf UCase(cat) = "ULTIMO USUARIO ACESSADO" Then
                    If cntLastUser >= maxLastUser Then
                        skipItem = True
                    Else
                        cntLastUser = cntLastUser + 1
                    End If
                ElseIf UCase(cat) = "PROGRAMAS ULTIMA EXECUCAO" Then
                    If cntProgram >= maxProgram Then
                        skipItem = True
                    Else
                        cntProgram = cntProgram + 1
                    End If
                Else
                    skipItem = True
                End If

                If Not skipItem Then
                    htmlOut = htmlOut & "<li class='dfir-item " & DfirTimelineSeverityCss(sevText) & "'>"
                    htmlOut = htmlOut & "<div class='dfir-dot'></div><div class='dfir-card'>"
                    htmlOut = htmlOut & "<div class='dfir-head'><time>" & HtmlEncode(displayText) & "</time><span class='chip " & DfirTimelineSeverityCss(sevText) & "'>" & HtmlEncode(cat) & "</span></div>"
                    htmlOut = htmlOut & "<div class='dfir-title'>" & HtmlEncode(itemText) & "</div>"
                    htmlOut = htmlOut & "<div class='dfir-meta'>" & HtmlEncode(eventText) & " | " & HtmlEncode(sourceText) & "</div>"
                    htmlOut = htmlOut & "<div class='dfir-text'>" & HtmlEncode(valueText) & "</div>"
                    htmlOut = htmlOut & "</div></li>"
                End If
            End If
        End If
    Next

    htmlOut = htmlOut & "</ol>"
    If cntUserCreate = 0 And cntLastUser = 0 And cntProgram = 0 Then htmlOut = ""
    BuildDfirPriorityTimelineHtml = htmlOut
End Function

Function ExtractSensitivePorts(netstatOut)
    Dim lines, line, acc
    acc = ""
    lines = Split(netstatOut, vbCrLf)
    For Each line In lines
        If InStr(line, "LISTENING") > 0 Then
            If InStr(line, ":21") > 0 Or InStr(line, ":23") > 0 Or InStr(line, ":25") > 0 Or InStr(line, ":53") > 0 Or InStr(line, ":69") > 0 Or InStr(line, ":80") > 0 Or InStr(line, ":110") > 0 Or InStr(line, ":135") > 0 Or InStr(line, ":139") > 0 Or InStr(line, ":143") > 0 Or InStr(line, ":445") > 0 Or InStr(line, ":1433") > 0 Or InStr(line, ":1521") > 0 Or InStr(line, ":3389") > 0 Or InStr(line, ":5900") > 0 Then
                acc = acc & line & vbCrLf
            End If
        End If
    Next
    If Trim(acc) = "" Then acc = "Nenhuma porta sensivel comum detectada em estado LISTENING."
    ExtractSensitivePorts = acc
End Function

Function HasUsefulOutput(s)
    Dim t
    t = Trim(CStr(s & ""))
    If t = "" Then
        HasUsefulOutput = False
    ElseIf UCase(t) = "N/A" Then
        HasUsefulOutput = False
    ElseIf InStr(1, t, "Falha ao executar comando:", vbTextCompare) > 0 Then
        HasUsefulOutput = False
    ElseIf InStr(1, t, "is not recognized", vbTextCompare) > 0 Then
        HasUsefulOutput = False
    ElseIf InStr(1, t, "nao e reconhecido", vbTextCompare) > 0 Then
        HasUsefulOutput = False
    Else
        HasUsefulOutput = True
    End If
End Function

Function SafeWmiProp(wmiObj, propName, fallback)
    Dim v
    On Error Resume Next
    Err.Clear
    v = ""
    v = wmiObj.Properties_.Item(propName).Value
    If Err.Number <> 0 Then
        Err.Clear
        SafeWmiProp = fallback
    Else
        SafeWmiProp = Nz(v, fallback)
    End If
    On Error Goto 0
End Function

Function GetPrinterDriverVersion(drv)
    Dim v, dt
    v = SafeWmiProp(drv, "DriverVersion", "")
    If Trim(CStr(v & "")) = "" Then v = SafeWmiProp(drv, "Version", "")
    If Trim(CStr(v & "")) = "" Then
        dt = SafeWmiProp(drv, "DriverDate", "")
        If Len(CStr(dt & "")) >= 14 Then
            v = WmiDateToString(dt)
        ElseIf Trim(CStr(dt & "")) <> "" Then
            v = dt
        End If
    End If
    If Trim(CStr(v & "")) = "" Then v = "-"
    GetPrinterDriverVersion = CStr(v)
End Function

Function GetPrefetchFilesTableRows(prefetchPath)
    Dim folder, f, rows
    rows = ""

    On Error Resume Next
    Err.Clear
    Set folder = objFSO.GetFolder(prefetchPath)
    If Err.Number <> 0 Then
        Err.Clear
        GetPrefetchFilesTableRows = ""
        On Error Goto 0
        Exit Function
    End If

    For Each f In folder.Files
        Err.Clear
        If LCase(Right(CStr(f.Name), 3)) = ".pf" Then
            rows = rows & "<tr><td>" & HtmlEncode(f.Name) & "</td><td>" & HtmlEncode(CStr(f.DateCreated)) & "</td><td>" & HtmlEncode(CStr(f.DateLastModified)) & "</td><td>" & HtmlEncode(FormatBytes(f.Size)) & "</td></tr>"
        End If
        If Err.Number <> 0 Then Err.Clear
    Next

    On Error Goto 0
    GetPrefetchFilesTableRows = rows
End Function

Function GetVolumeInfoSummary()
    Dim colVol, ld, out, hasRows, wmicOut
    hasRows = False
    out = ""

    On Error Resume Next
    Err.Clear
    Set colVol = objWMI.ExecQuery("SELECT * FROM Win32_LogicalDisk")
    If Err.Number = 0 Then
        out = "Origem: WMI (Win32_LogicalDisk)" & vbCrLf
        For Each ld In colVol
            hasRows = True
            out = out & Nz(ld.DeviceID, "-") & " | " & DriveTypeName(ld.DriveType) & _
                " | FS=" & Nz(ld.FileSystem, "-") & _
                " | Livre=" & FormatBytes(ld.FreeSpace) & _
                " | Total=" & FormatBytes(ld.Size) & _
                " | Label=" & Nz(ld.VolumeName, "-") & vbCrLf
        Next
    End If
    Err.Clear
    On Error Goto 0

    If hasRows Then
        GetVolumeInfoSummary = Trim(out)
        Exit Function
    End If

    wmicOut = GetCommandOutput("cmd /c wmic logicaldisk get DeviceID,DriveType,FileSystem,FreeSpace,Size,VolumeName /format:table")
    If HasUsefulOutput(wmicOut) Then
        GetVolumeInfoSummary = "Origem: WMIC fallback" & vbCrLf & wmicOut
        Exit Function
    End If

    GetVolumeInfoSummary = "N/A (falha em WMI/WMIC para Win32_LogicalDisk)"
End Function

Function GetDefragStatusSummary()
    Dim s
    s = GetCommandOutput("cmd /c defrag /C /A /V 2>nul | findstr /I /R ""Volume Unidade Fragment Fragmenta Average Total Optimization Otimiza Consolidation Consolida""")
    If HasUsefulOutput(s) Then
        GetDefragStatusSummary = "Origem: defrag /A /V" & vbCrLf & s
        Exit Function
    End If

    s = GetCommandOutput("cmd /c wevtutil qe Microsoft-Windows-Defrag/Operational /rd:true /c:5 /f:text")
    If HasUsefulOutput(s) Then
        GetDefragStatusSummary = "Origem: wevtutil (Microsoft-Windows-Defrag/Operational)" & vbCrLf & s
        Exit Function
    End If

    GetDefragStatusSummary = "N/A (defrag/wevtutil indisponivel)"
End Function

Function GetStorageOptimizationSummary()
    Dim parts, s
    parts = ""

    s = GetCommandOutput("cmd /c schtasks /Query /TN ""\Microsoft\Windows\Defrag\ScheduledDefrag"" /V /FO LIST")
    If HasUsefulOutput(s) Then
        parts = parts & "[ScheduledDefrag]" & vbCrLf & s & vbCrLf & vbCrLf
    End If

    s = GetCommandOutput("cmd /c reg query ""HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy""")
    If HasUsefulOutput(s) Then
        parts = parts & "[StorageSense]" & vbCrLf & s & vbCrLf & vbCrLf
    End If

    s = GetCommandOutput("cmd /c reg query ""HKLM\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction"" /v Enable")
    If HasUsefulOutput(s) Then
        parts = parts & "[BootOptimizeFunction]" & vbCrLf & s & vbCrLf
    End If

    If Trim(parts) = "" Then
        GetStorageOptimizationSummary = "N/A (schtasks/reg query sem retorno util)"
    Else
        GetStorageOptimizationSummary = Trim(parts)
    End If
End Function

Function FormatShareType(v)
    Dim rawNum, signedNum
    If Not IsNumeric(v) Then
        FormatShareType = Nz(v, "-")
        Exit Function
    End If

    rawNum = CDbl(v)
    signedNum = ShareTypeToSigned32(rawNum)
    FormatShareType = ShareTypeName(signedNum) & " (" & CStr(Fix(rawNum)) & ")"
End Function

Function ShareTypeName(v)
    Dim n
    n = CLng(0 + v)
    Select Case n
        Case 0: ShareTypeName = "Disk Drive"
        Case 1: ShareTypeName = "Print Queue"
        Case 2: ShareTypeName = "Device"
        Case 3: ShareTypeName = "IPC"
        Case 2147483644: ShareTypeName = "IPC (Admin?)"
        Case 1073741824: ShareTypeName = "Disk (Temporary)"
        Case 1073741825: ShareTypeName = "Print (Temporary)"
        Case 1073741826: ShareTypeName = "Device (Temporary)"
        Case 1073741827: ShareTypeName = "IPC (Temporary)"
        Case -2147483648: ShareTypeName = "Disk (Admin/Hidden)"
        Case -2147483647: ShareTypeName = "Print (Admin/Hidden)"
        Case -2147483646: ShareTypeName = "Device (Admin/Hidden)"
        Case -2147483645: ShareTypeName = "IPC (Admin/Hidden)"
        Case Else: ShareTypeName = "Tipo " & CStr(n)
    End Select
End Function

Function ShareTypeToSigned32(n)
    Dim d
    d = CDbl(n)
    If d > CDbl("2147483647") Then
        d = d - CDbl("4294967296")
    End If
    ShareTypeToSigned32 = CLng(d)
End Function

Function SanitizeFileNameComponent(s)
    Dim t, badChars, i, ch
    t = Trim(CStr(Nz(s, "")))
    If t = "" Then t = "arquivo"
    badChars = Array("\", "/", ":", "*", "?", """", "<", ">", "|")
    For i = 0 To UBound(badChars)
        t = Replace(t, badChars(i), "_")
    Next
    t = Replace(t, " ", "_")
    Do While InStr(t, "__") > 0
        t = Replace(t, "__", "_")
    Loop
    If Len(t) > 90 Then t = Left(t, 90)
    If Right(t, 1) = "." Then t = Left(t, Len(t) - 1)
    If t = "" Then t = "arquivo"
    SanitizeFileNameComponent = t
End Function

Function PsQuoteLiteral(s)
    PsQuoteLiteral = "'" & Replace(CStr(Nz(s, "")), "'", "''") & "'"
End Function

Sub EnsureHostIdentityContext()
    Dim colCsp, csp
    If Trim(CStr(hostServiceTag & "")) = "" Then
        On Error Resume Next
        Err.Clear
        Set colCsp = objWMI.ExecQuery("SELECT IdentifyingNumber FROM Win32_ComputerSystemProduct")
        If Err.Number = 0 Then
            For Each csp In colCsp
                hostServiceTag = Trim(CStr(Nz(csp.IdentifyingNumber, "")))
                If hostServiceTag <> "" Then Exit For
            Next
        End If
        If Trim(CStr(hostServiceTag & "")) = "" Then hostServiceTag = "-"
        Err.Clear
        On Error Goto 0
    End If

    If Trim(CStr(hostLoggedUserSid & "")) = "" Then
        hostLoggedUserSid = ResolveCurrentUserSid()
        If Trim(CStr(hostLoggedUserSid & "")) = "" Then hostLoggedUserSid = "-"
    End If
End Sub

Function ResolveCurrentUserSid()
    Dim qName, qDomain, colUsers, u, sidOut, psOut
    ResolveCurrentUserSid = ""
    qName = Replace(CStr(objNetwork.UserName & ""), "'", "''")
    qDomain = Replace(CStr(objNetwork.UserDomain & ""), "'", "''")

    On Error Resume Next
    Err.Clear
    Set colUsers = objWMI.ExecQuery("SELECT Name,Domain,SID FROM Win32_UserAccount WHERE Name='" & qName & "'")
    If Err.Number = 0 Then
        For Each u In colUsers
            If UCase(Trim(CStr(Nz(u.Name, "")))) = UCase(Trim(CStr(objNetwork.UserName & ""))) Then
                If UCase(Trim(CStr(Nz(u.Domain, "")))) = UCase(Trim(CStr(objNetwork.UserDomain & ""))) Then
                    sidOut = Trim(CStr(Nz(u.SID, "")))
                    If sidOut <> "" Then
                        ResolveCurrentUserSid = sidOut
                        Exit Function
                    End If
                End If
            End If
        Next
    End If
    Err.Clear
    On Error Goto 0

    psOut = GetCommandOutputWithTimeout("powershell -NoProfile -Command ""try { ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value } catch { '' }""", 8)
    psOut = Trim(CStr(psOut & ""))
    If InStr(psOut, vbCr) > 0 Then psOut = Trim(Split(psOut, vbCr)(0))
    If InStr(psOut, vbLf) > 0 Then psOut = Trim(Split(psOut, vbLf)(0))
    If Left(UCase(psOut), 2) = "S-" Then ResolveCurrentUserSid = psOut
End Function

Function TryBuildDateYMD(yNum, mNum, dNum, ByRef outDt)
    TryBuildDateYMD = False
    If Not IsNumeric(yNum) Then Exit Function
    If Not IsNumeric(mNum) Then Exit Function
    If Not IsNumeric(dNum) Then Exit Function

    If CLng(0 + yNum) < 1900 Or CLng(0 + yNum) > 2100 Then Exit Function
    If CLng(0 + mNum) < 1 Or CLng(0 + mNum) > 12 Then Exit Function
    If CLng(0 + dNum) < 1 Or CLng(0 + dNum) > 31 Then Exit Function

    On Error Resume Next
    Err.Clear
    outDt = DateSerial(CLng(0 + yNum), CLng(0 + mNum), CLng(0 + dNum))
    If Err.Number = 0 Then
        TryBuildDateYMD = True
    Else
        Err.Clear
    End If
    On Error Goto 0
End Function

Function ChooseBestAmbiguousDate(usDt, hasUs, brDt, hasBr, rawTxt, ByRef outDt)
    Dim futureLimit, localeDt
    ChooseBestAmbiguousDate = False
    futureLimit = DateAdd("d", 2, Date)

    If hasUs And Not hasBr Then
        outDt = usDt
        ChooseBestAmbiguousDate = True
        Exit Function
    End If
    If hasBr And Not hasUs Then
        outDt = brDt
        ChooseBestAmbiguousDate = True
        Exit Function
    End If
    If Not hasUs And Not hasBr Then Exit Function

    If CDate(usDt) <= futureLimit And CDate(brDt) > futureLimit Then
        outDt = usDt
        ChooseBestAmbiguousDate = True
        Exit Function
    End If
    If CDate(brDt) <= futureLimit And CDate(usDt) > futureLimit Then
        outDt = brDt
        ChooseBestAmbiguousDate = True
        Exit Function
    End If

    On Error Resume Next
    Err.Clear
    If IsDate(rawTxt) Then
        localeDt = CDate(rawTxt)
        If Err.Number = 0 Then
            outDt = localeDt
            ChooseBestAmbiguousDate = True
            On Error Goto 0
            Exit Function
        End If
    End If
    Err.Clear
    On Error Goto 0

    outDt = usDt
    ChooseBestAmbiguousDate = True
End Function

Function TryParseQfeInstalledOnDate(rawTxt, ByRef outDt)
    Dim s, parts, a, b, c, tmpDt
    Dim usDt, brDt, hasUs, hasBr
    TryParseQfeInstalledOnDate = False

    s = Trim(CStr(Nz(rawTxt, "")))
    If s = "" Then Exit Function
    If InStr(s, " ") > 0 Then s = Trim(Split(s, " ")(0))
    s = Replace(s, ".", "/")
    s = Replace(s, "-", "/")

    If Len(s) = 8 And IsNumeric(s) Then
        If TryBuildDateYMD(Left(s, 4), Mid(s, 5, 2), Right(s, 2), tmpDt) Then
            outDt = tmpDt
            TryParseQfeInstalledOnDate = True
            Exit Function
        End If
    End If

    parts = Split(s, "/")
    If UBound(parts) = 2 Then
        a = Trim(CStr(parts(0)))
        b = Trim(CStr(parts(1)))
        c = Trim(CStr(parts(2)))

        If IsNumeric(a) And IsNumeric(b) And IsNumeric(c) Then
            If Len(a) = 4 Then
                If TryBuildDateYMD(a, b, c, tmpDt) Then
                    outDt = tmpDt
                    TryParseQfeInstalledOnDate = True
                    Exit Function
                End If
            ElseIf Len(c) = 4 Then
                hasUs = TryBuildDateYMD(c, a, b, usDt)
                hasBr = TryBuildDateYMD(c, b, a, brDt)
                If ChooseBestAmbiguousDate(usDt, hasUs, brDt, hasBr, s, outDt) Then
                    TryParseQfeInstalledOnDate = True
                    Exit Function
                End If
            End If
        End If
    End If

    On Error Resume Next
    Err.Clear
    If IsDate(s) Then
        outDt = CDate(s)
        If Err.Number = 0 Then
            TryParseQfeInstalledOnDate = True
            On Error Goto 0
            Exit Function
        End If
    End If
    Err.Clear
    On Error Goto 0
End Function

Function GetLatestHotfixInstalledOnText()
    Dim colQfe, qfe, rawTxt, bestDt, hasDate, parsedDt
    GetLatestHotfixInstalledOnText = "-"
    hasDate = False

    On Error Resume Next
    Err.Clear
    Set colQfe = objWMI.ExecQuery("SELECT InstalledOn, HotFixID FROM Win32_QuickFixEngineering")
    If Err.Number <> 0 Then
        Err.Clear
        On Error Goto 0
        Exit Function
    End If

    For Each qfe In colQfe
        rawTxt = Trim(CStr(Nz(qfe.InstalledOn, "")))
        If rawTxt <> "" Then
            Err.Clear
            If TryParseQfeInstalledOnDate(rawTxt, parsedDt) Then
                If Not hasDate Then
                    bestDt = CDate(parsedDt)
                    hasDate = True
                ElseIf CDate(parsedDt) > bestDt Then
                    bestDt = CDate(parsedDt)
                End If
            End If
            If Err.Number <> 0 Then Err.Clear
        End If
    Next
    On Error Goto 0

    If hasDate Then
        GetLatestHotfixInstalledOnText = FormatDateHumanized(bestDt)
    End If
End Function

Function GetRunExportNestedSubDir(relPath)
    Dim baseDir, curPath, normRel, parts, i, p
    baseDir = GetRunExportBaseDir()
    curPath = baseDir
    normRel = Replace(CStr(Nz(relPath, "")), "/", "\")
    parts = Split(normRel, "\")
    On Error Resume Next
    For i = 0 To UBound(parts)
        p = Trim(CStr(parts(i) & ""))
        If p <> "" Then
            curPath = curPath & "\" & SanitizeFileNameComponent(p)
            If Not objFSO.FolderExists(curPath) Then objFSO.CreateFolder curPath
            If Err.Number <> 0 Then Err.Clear
        End If
    Next
    On Error Goto 0
    GetRunExportNestedSubDir = curPath
End Function

Function CountFilesRecursiveSafe(folderPath)
    Dim f
    CountFilesRecursiveSafe = 0
    On Error Resume Next
    If Trim(CStr(folderPath & "")) = "" Then Exit Function
    If Not objFSO.FolderExists(folderPath) Then Exit Function
    Set f = objFSO.GetFolder(folderPath)
    If Err.Number <> 0 Then
        Err.Clear
        Exit Function
    End If
    CountFilesRecursiveSafe = CountFilesRecursiveFolderObj(f)
    On Error Goto 0
End Function

Function CountFilesRecursiveFolderObj(folderObj)
    Dim cnt, fl, sf
    cnt = 0
    On Error Resume Next
    For Each fl In folderObj.Files
        cnt = cnt + 1
    Next
    For Each sf In folderObj.SubFolders
        cnt = cnt + CountFilesRecursiveFolderObj(sf)
    Next
    If Err.Number <> 0 Then Err.Clear
    On Error Goto 0
    CountFilesRecursiveFolderObj = cnt
End Function

Function GetPathSizeBytesSafe(pathValue)
    GetPathSizeBytesSafe = -1
    On Error Resume Next
    If Trim(CStr(pathValue & "")) = "" Then Exit Function
    If objFSO.FileExists(pathValue) Then
        GetPathSizeBytesSafe = CLng(0 + objFSO.GetFile(pathValue).Size)
        Exit Function
    End If
    If objFSO.FolderExists(pathValue) Then
        GetPathSizeBytesSafe = CDbl(0 + objFSO.GetFolder(pathValue).Size)
        Exit Function
    End If
    Err.Clear
    On Error Goto 0
End Function

Function GetPathDateCreatedSafe(pathValue)
    GetPathDateCreatedSafe = "-"
    On Error Resume Next
    If Trim(CStr(pathValue & "")) = "" Then Exit Function
    If objFSO.FileExists(pathValue) Then
        GetPathDateCreatedSafe = CStr(objFSO.GetFile(pathValue).DateCreated)
        Exit Function
    End If
    If objFSO.FolderExists(pathValue) Then
        GetPathDateCreatedSafe = CStr(objFSO.GetFolder(pathValue).DateCreated)
        Exit Function
    End If
    Err.Clear
    On Error Goto 0
End Function

Sub AppendArtifactExportStatusRow(ByRef rowsHtml, categoria, artefato, statusText, pathValue, observacao)
    Dim cssClass, sizeBytes, sizeText
    cssClass = LogStatusClass(UCase(Trim(CStr(statusText & ""))))
    If cssClass = "" Then cssClass = "neutral"
    sizeBytes = GetPathSizeBytesSafe(pathValue)
    If CDbl(0 + sizeBytes) >= 0 Then
        sizeText = FormatBytes(sizeBytes)
    Else
        sizeText = "-"
    End If
    rowsHtml = rowsHtml & "<tr class='row-" & cssClass & "'><td>" & HtmlEncode(Nz(categoria, "-")) & "</td><td>" & HtmlEncode(Nz(artefato, "-")) & "</td><td><span class='chip " & cssClass & "'>" & HtmlEncode(Nz(statusText, "-")) & "</span></td><td class='path'>" & HtmlEncode(Nz(pathValue, "-")) & "</td><td>" & HtmlEncode(sizeText) & "</td><td class='path'>" & HtmlEncode(Nz(observacao, "-")) & "</td></tr>"
End Sub

Function BuildPsCopyPatternPreserveCmd(srcDir, filePattern, recurseFlag, destDir)
    Dim recOpt
    recOpt = ""
    If CBool(recurseFlag) Then recOpt = " -Recurse"
    BuildPsCopyPatternPreserveCmd = "powershell -NoProfile -Command ""$ErrorActionPreference='SilentlyContinue'; $src=" & PsQuoteLiteral(srcDir) & "; $dst=" & PsQuoteLiteral(destDir) & "; if(-not (Test-Path -LiteralPath $src)){ 'NO_SOURCE'; exit 0 }; New-Item -ItemType Directory -Force -Path $dst | Out-Null; $n=0; Get-ChildItem -LiteralPath $src -Filter " & PsQuoteLiteral(filePattern) & " -File" & recOpt & " -ErrorAction SilentlyContinue | ForEach-Object { $rel=$_.FullName.Substring($src.Length).TrimStart('\'); $target=Join-Path $dst $rel; $parent=Split-Path -Parent $target; if($parent){ New-Item -ItemType Directory -Force -Path $parent | Out-Null }; Copy-Item -LiteralPath $_.FullName -Destination $target -Force -ErrorAction SilentlyContinue; if(Test-Path -LiteralPath $target){ try { $di=Get-Item -LiteralPath $target -Force; $di.CreationTime=$_.CreationTime; $di.LastWriteTime=$_.LastWriteTime; $di.LastAccessTime=$_.LastAccessTime; $di.Attributes=$_.Attributes } catch {}; $n++ } }; 'COPIED=' + $n"""
End Function

Function BuildPsCopySingleFilePreserveCmd(srcFile, destDir, destName)
    Dim targetPath
    targetPath = destDir & "\" & SanitizeFileNameComponent(destName)
    BuildPsCopySingleFilePreserveCmd = "powershell -NoProfile -Command ""$ErrorActionPreference='SilentlyContinue'; $src=" & PsQuoteLiteral(srcFile) & "; $dstDir=" & PsQuoteLiteral(destDir) & "; $dst=" & PsQuoteLiteral(targetPath) & "; if(-not (Test-Path -LiteralPath $src)){ 'NO_SOURCE'; exit 0 }; New-Item -ItemType Directory -Force -Path $dstDir | Out-Null; try { Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop; $si=Get-Item -LiteralPath $src -Force; $di=Get-Item -LiteralPath $dst -Force; $di.CreationTime=$si.CreationTime; $di.LastWriteTime=$si.LastWriteTime; $di.LastAccessTime=$si.LastAccessTime; $di.Attributes=$si.Attributes; 'COPIED=1' } catch { 'ERROR=' + $_.Exception.Message }"""
End Function

Sub ExportPatternArtifactCategory(categoryName, displayName, srcDir, filePattern, recurseFlag, timeoutSecs)
    Dim targetDir, beforeCount, afterCount, deltaCount, cmdOut, statusTxt, noteTxt
    targetDir = GetRunExportNestedSubDir("artefatos\" & categoryName)
    beforeCount = CountFilesRecursiveSafe(targetDir)
    cmdOut = GetCommandOutputWithTimeout(BuildPsCopyPatternPreserveCmd(srcDir, filePattern, recurseFlag, targetDir), CLng(0 + timeoutSecs))
    afterCount = CountFilesRecursiveSafe(targetDir)
    deltaCount = CLng(0 + afterCount) - CLng(0 + beforeCount)
    If deltaCount > 0 Then
        smallArtifactExportCount = CLng(0 + smallArtifactExportCount) + deltaCount
        statusTxt = "OK"
        noteTxt = "Arquivos copiados: " & deltaCount & " | Origem: " & srcDir & " | Filtro: " & filePattern
    ElseIf InStr(UCase(CStr(cmdOut & "")), "NO_SOURCE") > 0 Then
        statusTxt = "WARN"
        noteTxt = "Origem nao encontrada: " & srcDir
    Else
        statusTxt = "WARN"
        noteTxt = "Nenhum arquivo copiado. Origem: " & srcDir & " | Filtro: " & filePattern
    End If
    If Trim(CStr(cmdOut & "")) <> "" Then noteTxt = noteTxt & " | Resultado: " & ShortCommandForLog(cmdOut)
    AppendArtifactExportStatusRow strSmallArtifactExportRows, "Pequenos artefatos", displayName, statusTxt, targetDir, noteTxt
End Sub

Sub ExportSingleFileArtifactCategory(categoryName, displayName, srcFile, timeoutSecs)
    Dim targetDir, beforeCount, afterCount, deltaCount, cmdOut, statusTxt, noteTxt, outName
    targetDir = GetRunExportNestedSubDir("artefatos\" & categoryName)
    beforeCount = CountFilesRecursiveSafe(targetDir)
    outName = objFSO.GetFileName(srcFile)
    If Trim(CStr(outName & "")) = "" Then outName = SanitizeFileNameComponent(displayName)
    cmdOut = GetCommandOutputWithTimeout(BuildPsCopySingleFilePreserveCmd(srcFile, targetDir, outName), CLng(0 + timeoutSecs))
    afterCount = CountFilesRecursiveSafe(targetDir)
    deltaCount = CLng(0 + afterCount) - CLng(0 + beforeCount)
    If deltaCount > 0 Then
        smallArtifactExportCount = CLng(0 + smallArtifactExportCount) + deltaCount
        statusTxt = "OK"
        noteTxt = "Arquivo copiado com preservacao de timestamps/atributos (quando permitido). Origem: " & srcFile
    ElseIf InStr(UCase(CStr(cmdOut & "")), "NO_SOURCE") > 0 Then
        statusTxt = "WARN"
        noteTxt = "Arquivo nao encontrado: " & srcFile
    Else
        statusTxt = "WARN"
        noteTxt = "Falha/arquivo bloqueado: " & srcFile
    End If
    If Trim(CStr(cmdOut & "")) <> "" Then noteTxt = noteTxt & " | Resultado: " & ShortCommandForLog(cmdOut)
    AppendArtifactExportStatusRow strSmallArtifactExportRows, "Pequenos artefatos", displayName, statusTxt, targetDir, noteTxt
End Sub

Sub ExportOriginalArtifactsSection()
    EnsureHostIdentityContext
    ExportEventLogArtifacts
    ExportRegistryRootArtifacts
    ExportSmallForensicArtifacts
End Sub

Sub ExportEventLogArtifacts()
    Dim evtxDir, legacyEvtDir, channels, ch, filePath, cmdOut, statusTxt, noteTxt
    Dim i, legacyDirs, legacySrc, legacyFile, legacyCountBefore, legacyCountAfter, copiedLegacy

    evtxDir = GetRunExportNestedSubDir("artefatos\eventos\evtx")
    channels = Array("Application", "System", "Security", "Setup", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Sysmon/Operational")

    For i = 0 To UBound(channels)
        ch = CStr(channels(i))
        filePath = evtxDir & "\" & SanitizeFileNameComponent(ch) & ".evtx"
        cmdOut = GetCommandOutputWithTimeout("cmd /c wevtutil epl """ & ch & """ """ & filePath & """ /ow:true 2>&1", 75)
        If objFSO.FileExists(filePath) Then
            evtxExportCount = CLng(0 + evtxExportCount) + 1
            statusTxt = "OK"
            noteTxt = "Exportado via wevtutil epl"
        ElseIf InStr(UCase(CStr(cmdOut & "")), "FAILED") > 0 Or InStr(UCase(CStr(cmdOut & "")), "ERRO") > 0 Then
            statusTxt = "WARN"
            noteTxt = "Falha ao exportar canal via wevtutil"
        Else
            statusTxt = "WARN"
            noteTxt = "Canal indisponivel ou sem permissao"
        End If
        If Trim(CStr(cmdOut & "")) <> "" Then noteTxt = noteTxt & " | Resultado: " & ShortCommandForLog(cmdOut)
        AppendArtifactExportStatusRow strEventLogArtifactExportRows, "Eventos", ch & " (.evtx)", statusTxt, filePath, noteTxt
    Next

    legacyEvtDir = GetRunExportNestedSubDir("artefatos\eventos\evt")
    legacyCountBefore = CountFilesRecursiveSafe(legacyEvtDir)
    legacyDirs = Array(objShell.ExpandEnvironmentStrings("%WINDIR%") & "\System32\Config", objShell.ExpandEnvironmentStrings("%WINDIR%") & "\System32\winevt\Logs")

    On Error Resume Next
    For i = 0 To UBound(legacyDirs)
        legacySrc = CStr(legacyDirs(i))
        If objFSO.FolderExists(legacySrc) Then
            For Each legacyFile In objFSO.GetFolder(legacySrc).Files
                If LCase(objFSO.GetExtensionName(legacyFile.Name)) = "evt" Then
                    objFSO.CopyFile legacyFile.Path, legacyEvtDir & "\" & legacyFile.Name, True
                    If Err.Number <> 0 Then Err.Clear
                End If
            Next
        End If
    Next
    On Error Goto 0

    legacyCountAfter = CountFilesRecursiveSafe(legacyEvtDir)
    copiedLegacy = CLng(0 + legacyCountAfter) - CLng(0 + legacyCountBefore)
    If copiedLegacy > 0 Then
        evtExportCount = CLng(0 + evtExportCount) + copiedLegacy
        AppendArtifactExportStatusRow strEventLogArtifactExportRows, "Eventos", "Arquivos legados .evt", "OK", legacyEvtDir, "Arquivos .evt copiados: " & copiedLegacy
    Else
        AppendArtifactExportStatusRow strEventLogArtifactExportRows, "Eventos", "Arquivos legados .evt", "WARN", legacyEvtDir, "Nenhum arquivo .evt localizado (comum em Windows modernos)."
    End If
End Sub

Sub ExportRegistryRootArtifacts()
    Dim regDir, roots, labels, files, i, rootKey, filePath, cmdOut, statusTxt, noteTxt, timeoutSecs
    regDir = GetRunExportNestedSubDir("artefatos\originais\registro")

    roots = Array("HKCR", "HKCU", "HKLM", "HKU", "HKCC")
    labels = Array("HKEY_CLASSES_ROOT", "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE", "HKEY_USERS", "HKEY_CURRENT_CONFIG")
    files = Array("HKEY_CLASSES_ROOT.reg", "HKEY_CURRENT_USER.reg", "HKEY_LOCAL_MACHINE.reg", "HKEY_USERS.reg", "HKEY_CURRENT_CONFIG.reg")

    For i = 0 To UBound(roots)
        rootKey = CStr(roots(i))
        filePath = regDir & "\" & CStr(files(i))
        timeoutSecs = 240
        If UCase(rootKey) = "HKU" Or UCase(rootKey) = "HKCC" Then timeoutSecs = 420
        cmdOut = GetCommandOutputWithTimeout("cmd /c reg export " & rootKey & " """ & filePath & """ /y 2>&1", timeoutSecs)
        If objFSO.FileExists(filePath) Then
            registryRootExportCount = CLng(0 + registryRootExportCount) + 1
            statusTxt = "OK"
            noteTxt = "Exportado como .reg"
        Else
            statusTxt = "WARN"
            noteTxt = "Falha/timeout/permissao insuficiente ao exportar raiz"
        End If
        If timeoutSecs <> 240 Then noteTxt = noteTxt & " | timeout_s=" & timeoutSecs
        If Trim(CStr(cmdOut & "")) <> "" Then noteTxt = noteTxt & " | Resultado: " & ShortCommandForLog(cmdOut)
        AppendArtifactExportStatusRow strRegistryRootArtifactExportRows, "Registro", CStr(labels(i)), statusTxt, filePath, noteTxt
    Next
End Sub

Sub ExportSmallForensicArtifacts()
    Dim userProfile, appDataRoam, localAppData, recyclePath
    EnsureHostIdentityContext

    userProfile = objShell.ExpandEnvironmentStrings("%USERPROFILE%")
    appDataRoam = objShell.ExpandEnvironmentStrings("%APPDATA%")
    localAppData = objShell.ExpandEnvironmentStrings("%LOCALAPPDATA%")

    ExportSingleFileArtifactCategory "mft", "$MFT (C:)", "C:\$MFT", 120

    ExportPatternArtifactCategory "atalhos\desktop", "Atalhos (.lnk) - Desktop", userProfile & "\Desktop", "*.lnk", True, 120
    ExportPatternArtifactCategory "atalhos\downloads", "Atalhos (.lnk) - Downloads", userProfile & "\Downloads", "*.lnk", True, 120
    ExportPatternArtifactCategory "atalhos\recent", "Atalhos (.lnk) - Recent", appDataRoam & "\Microsoft\Windows\Recent", "*.lnk", True, 120

    ExportPatternArtifactCategory "thumbs\desktop", "Thumbs.db - Desktop", userProfile & "\Desktop", "Thumbs.db", True, 90
    ExportPatternArtifactCategory "thumbs\downloads", "Thumbs.db - Downloads", userProfile & "\Downloads", "Thumbs.db", True, 90

    If Trim(CStr(hostLoggedUserSid & "")) <> "" And hostLoggedUserSid <> "-" Then
        recyclePath = "C:\$Recycle.Bin\" & hostLoggedUserSid
        ExportPatternArtifactCategory "lixeira", "Lixeira ($I*) - SID atual", recyclePath, "$I*", True, 150
    Else
        AppendArtifactExportStatusRow strSmallArtifactExportRows, "Pequenos artefatos", "Lixeira ($I*) - SID atual", "WARN", GetRunExportNestedSubDir("artefatos\lixeira"), "SID do usuario logado indisponivel para montar caminho da lixeira."
    End If

    ExportSingleFileArtifactCategory "hives", "NTUSER.DAT (usuario atual)", userProfile & "\NTUSER.DAT", 180
    ExportSingleFileArtifactCategory "hives", "USRCLASS.DAT (usuario atual)", localAppData & "\Microsoft\Windows\UsrClass.dat", 180
End Sub

Sub CreateStatusBundleZip(mainHtmlFile)
    Dim zipBaseName, cmdOut, cmdZip, cmdZipFallback, zipMd5
    EnsureHostIdentityContext
    zipBaseName = SanitizeFileNameComponent(IIfBool(Trim(CStr(hostServiceTag & "")) <> "" And hostServiceTag <> "-", hostServiceTag, strComputer)) & ".zip"
    bundleZipPath = zipBaseName
    bundleZipBytes = 0

    cmdZip = "powershell -NoProfile -Command ""$ErrorActionPreference='SilentlyContinue'; $dst=" & PsQuoteLiteral(bundleZipPath) & "; if(Test-Path -LiteralPath $dst){ Remove-Item -LiteralPath $dst -Force -ErrorAction SilentlyContinue }; $items=@(); foreach($p in @(" & PsQuoteLiteral(mainHtmlFile) & "," & PsQuoteLiteral(strLogHtmlFile) & "," & PsQuoteLiteral(strCustodyFile) & "," & PsQuoteLiteral(GetRunExportBaseDir()) & "," & PsQuoteLiteral("css") & "," & PsQuoteLiteral("img") & "," & PsQuoteLiteral("js") & ")){ if(Test-Path -LiteralPath $p){ $items += $p } }; if($items.Count -gt 0){ try { Compress-Archive -Path $items -DestinationPath $dst -Force -CompressionLevel Optimal; 'ZIP_OK=' + $items.Count } catch { 'ZIP_ERR=' + $_.Exception.Message } } else { 'ZIP_EMPTY' }"""
    cmdOut = GetCommandOutputWithTimeout(cmdZip, 240)
    If Not objFSO.FileExists(bundleZipPath) Then
        cmdZipFallback = "powershell -NoProfile -Command ""$ErrorActionPreference='SilentlyContinue'; $dst=" & PsQuoteLiteral(bundleZipPath) & "; if(Test-Path -LiteralPath $dst){ Remove-Item -LiteralPath $dst -Force -ErrorAction SilentlyContinue }; $items=@(); foreach($p in @(" & PsQuoteLiteral(mainHtmlFile) & "," & PsQuoteLiteral(strLogHtmlFile) & "," & PsQuoteLiteral(strCustodyFile) & "," & PsQuoteLiteral(GetRunExportBaseDir()) & "," & PsQuoteLiteral("css") & "," & PsQuoteLiteral("img") & "," & PsQuoteLiteral("js") & ")){ if(Test-Path -LiteralPath $p){ $items += $p } }; if($items.Count -gt 0){ try { Compress-Archive -Path $items -DestinationPath $dst -Force; 'ZIP_OK_FALLBACK=' + $items.Count } catch { 'ZIP_ERR_FALLBACK=' + $_.Exception.Message } } else { 'ZIP_EMPTY' }"""
        cmdOut = cmdOut & vbCrLf & "[fallback]" & vbCrLf & GetCommandOutputWithTimeout(cmdZipFallback, 240)
    End If

    If objFSO.FileExists(bundleZipPath) Then
        bundleZipBytes = GetFileSizeBytesSafe(bundleZipPath)
        LogCustody "BUNDLE", "OK", "Pacote compilado: " & bundleZipPath & " | tamanho=" & FormatBytes(bundleZipBytes)
        zipMd5 = GetFileMD5(bundleZipPath)
        If LooksLikeMd5Hex(zipMd5) Then
            LogCustody "INTEGRITY", "OK", "MD5 bundle zip=" & zipMd5
        Else
            LogCustody "INTEGRITY", "WARN", "Nao foi possivel calcular MD5 do bundle zip"
        End If
    Else
        LogCustody "BUNDLE", "WARN", "Falha ao compilar pacote " & zipBaseName & " | " & ShortCommandForLog(cmdOut)
    End If
End Sub

Sub ReplaceStatusLogZipPlaceholders(baseMaxBytes, fallbackStamp)
    Dim zipPathText, zipSizeText, zipMtimeText, zipMd5Text, zipBarPct, finalMaxBytes
    Dim fRead, fWrite, htmlText

    zipPathText = "-"
    zipSizeText = "-"
    zipMtimeText = HtmlEncode(Nz(fallbackStamp, "-"))
    zipMd5Text = "-"
    zipBarPct = 0
    finalMaxBytes = CDbl(0 + baseMaxBytes)

    If finalMaxBytes <= 0 Then finalMaxBytes = 1
    If Trim(CStr(bundleZipPath & "")) <> "" And objFSO.FileExists(bundleZipPath) Then
        zipPathText = HtmlEncode(bundleZipPath)
        zipSizeText = HtmlEncode(FormatBytes(bundleZipBytes))
        zipMtimeText = HtmlEncode(GetFileDateModifiedSafe(bundleZipPath))
        zipMd5Text = HtmlEncode(GetFileMD5(bundleZipPath))
        If CDbl(0 + bundleZipBytes) > finalMaxBytes Then finalMaxBytes = CDbl(0 + bundleZipBytes)
        zipBarPct = PercentWidthPct(bundleZipBytes, finalMaxBytes)
    End If

    On Error Resume Next
    Err.Clear
    If Not objFSO.FileExists(strLogHtmlFile) Then Exit Sub
    Set fRead = objFSO.OpenTextFile(strLogHtmlFile, ForReading, False, TristateFalse)
    If Err.Number <> 0 Then
        Err.Clear
        Exit Sub
    End If
    htmlText = fRead.ReadAll
    fRead.Close
    Set fRead = Nothing

    htmlText = Replace(htmlText, "__ZIP_PATH__", zipPathText)
    htmlText = Replace(htmlText, "__ZIP_SIZE_TEXT__", zipSizeText)
    htmlText = Replace(htmlText, "__ZIP_MTIME__", zipMtimeText)
    htmlText = Replace(htmlText, "__ZIP_MD5__", zipMd5Text)
    htmlText = Replace(htmlText, "__ZIP_BAR_PCT__", CStr(zipBarPct))

    Set fWrite = objFSO.OpenTextFile(strLogHtmlFile, ForWriting, True, TristateFalse)
    If Err.Number = 0 Then
        fWrite.Write htmlText
        fWrite.Close
        Set fWrite = Nothing
    Else
        Err.Clear
    End If
    On Error Goto 0
End Sub

Function GetRunExportBaseDir()
    Dim baseDir
    If Trim(CStr(strExportBaseDir & "")) <> "" Then
        GetRunExportBaseDir = strExportBaseDir
        Exit Function
    End If

    baseDir = "export"
    On Error Resume Next
    If Not objFSO.FolderExists(baseDir) Then objFSO.CreateFolder baseDir
    strExportBaseDir = baseDir & "\" & SanitizeFileNameComponent(strComputer & "_" & strRunId & "_exports")
    If Not objFSO.FolderExists(strExportBaseDir) Then objFSO.CreateFolder strExportBaseDir
    If Err.Number <> 0 Then
        Err.Clear
    End If
    On Error Goto 0
    GetRunExportBaseDir = strExportBaseDir
End Function

Function GetRunExportSubDir(subName)
    Dim baseDir, folderPath
    baseDir = GetRunExportBaseDir()
    folderPath = baseDir & "\" & SanitizeFileNameComponent(subName)
    On Error Resume Next
    If Not objFSO.FolderExists(folderPath) Then objFSO.CreateFolder folderPath
    If Err.Number <> 0 Then Err.Clear
    On Error Goto 0
    GetRunExportSubDir = folderPath
End Function

Function ExportTextArtifact(subDirName, fileBaseName, fileExt, contentText)
    Dim folderPath, fullPath, extNorm, f
    ExportTextArtifact = ""
    folderPath = GetRunExportSubDir(subDirName)
    If Trim(CStr(folderPath & "")) = "" Then Exit Function

    extNorm = LCase(Trim(CStr(fileExt & "")))
    If extNorm = "" Then extNorm = "txt"
    If Left(extNorm, 1) = "." Then extNorm = Mid(extNorm, 2)

    fullPath = folderPath & "\" & SanitizeFileNameComponent(fileBaseName) & "." & extNorm

    On Error Resume Next
    Err.Clear
    Set f = objFSO.OpenTextFile(fullPath, ForWriting, True, TristateFalse)
    If Err.Number <> 0 Then
        Err.Clear
        Set f = Nothing
        On Error Goto 0
        Exit Function
    End If
    f.Write HtmlAsciiSafe(CStr(Nz(contentText, "")))
    f.Close
    Set f = Nothing
    If Err.Number <> 0 Then
        Err.Clear
        fullPath = ""
    End If
    On Error Goto 0
    ExportTextArtifact = fullPath
End Function

Sub AppendUserArtifactTimelineRecordFromDate(dtValue, eventKind, itemName, sourcePath)
    Dim sortKey, displayText, sep, line, kindUpper
    If Not IsDate(dtValue) Then Exit Sub
    sortKey = SortKeyFromDateValue(dtValue)
    If sortKey = "" Then Exit Sub
    displayText = FormatDateTimeLocal(dtValue)
    sep = Chr(30)
    kindUpper = UCase(Trim(CStr(eventKind & "")))
    line = DfirTimelineFieldSafe(sortKey) & sep & DfirTimelineFieldSafe(displayText) & sep & _
           DfirTimelineFieldSafe(kindUpper) & sep & DfirTimelineFieldSafe(Nz(itemName, "-")) & sep & DfirTimelineFieldSafe(Nz(sourcePath, "-"))
    If strUserArtifactTimelineRecords <> "" Then strUserArtifactTimelineRecords = strUserArtifactTimelineRecords & vbLf
    strUserArtifactTimelineRecords = strUserArtifactTimelineRecords & line
    userArtifactTimelineRecordCount = CLng(0 + userArtifactTimelineRecordCount) + 1

    Select Case kindUpper
        Case "CRIACAO": userArtifactTimelineCreateCount = CLng(0 + userArtifactTimelineCreateCount) + 1
        Case "ACESSO": userArtifactTimelineAccessCount = CLng(0 + userArtifactTimelineAccessCount) + 1
        Case "MODIFICACAO": userArtifactTimelineModifyCount = CLng(0 + userArtifactTimelineModifyCount) + 1
    End Select
End Sub

Sub WriteCurrentUserRecentShortcuts(maxItems)
    Dim recentPath, folderObj, f, recs, recCount, line, rowsHtml
    Dim sep, sortKey, targetPath, sc, n, limitN, i, parts

    recentPath = objShell.ExpandEnvironmentStrings("%APPDATA%") & "\Microsoft\Windows\Recent"
    limitN = CLng(0 + maxItems)
    If limitN < 0 Then limitN = 0
    sep = Chr(30)
    rowsHtml = ""
    recCount = 0

    objFile.WriteLine "<div class='scroll-table'>"
    objFile.WriteLine "<table><tr><th>Atalho</th><th>Ultima modificacao</th><th>Criacao</th><th>Ultimo acesso</th><th>Destino (quando resolvido)</th><th class='location-col'>Caminho</th><th>Tamanho</th></tr>"

    On Error Resume Next
    Err.Clear
    If objFSO.FolderExists(recentPath) Then
        Set folderObj = objFSO.GetFolder(recentPath)
        If Err.Number = 0 Then
            ReDim recs(0)
            For Each f In folderObj.Files
                Err.Clear
                If LCase(objFSO.GetExtensionName(CStr(f.Name))) = "lnk" Then
                    sortKey = SortKeyFromDateValue(f.DateLastModified)
                    targetPath = "-"
                    Set sc = Nothing
                    Err.Clear
                    Set sc = objShell.CreateShortcut(f.Path)
                    If Err.Number = 0 Then
                        targetPath = Nz(sc.TargetPath, "-")
                        If Trim(CStr(targetPath & "")) = "" Then targetPath = "-"
                    Else
                        Err.Clear
                    End If
                    Set sc = Nothing

                    line = DfirTimelineFieldSafe(sortKey) & sep & DfirTimelineFieldSafe(f.Name) & sep & _
                           DfirTimelineFieldSafe(FormatDateTimeLocal(f.DateLastModified)) & sep & _
                           DfirTimelineFieldSafe(FormatDateTimeLocal(f.DateCreated)) & sep & _
                           DfirTimelineFieldSafe(FormatDateTimeLocal(f.DateLastAccessed)) & sep & _
                           DfirTimelineFieldSafe(targetPath) & sep & DfirTimelineFieldSafe(f.Path) & sep & _
                           DfirTimelineFieldSafe(FormatBytes(f.Size))

                    If recCount = 0 Then
                        recs(0) = line
                    Else
                        ReDim Preserve recs(recCount)
                        recs(recCount) = line
                    End If
                    recCount = recCount + 1

                    AppendUserArtifactTimelineRecordFromDate f.DateCreated, "Criacao", f.Name, f.Path
                    AppendUserArtifactTimelineRecordFromDate f.DateLastAccessed, "Acesso", f.Name, f.Path
                    AppendUserArtifactTimelineRecordFromDate f.DateLastModified, "Modificacao", f.Name, f.Path
                End If
                If Err.Number <> 0 Then Err.Clear
            Next
        End If
    End If
    On Error Goto 0

    If recCount > 0 Then
        recs = SortStringArrayAsc(recs)
        n = 0
        For i = UBound(recs) To 0 Step -1
            If limitN > 0 Then
                If n >= limitN Then Exit For
            End If
            parts = Split(CStr(recs(i)), sep)
            If UBound(parts) >= 7 Then
                rowsHtml = rowsHtml & "<tr><td>" & HtmlEncode(parts(1)) & "</td><td>" & HtmlEncode(parts(2)) & "</td><td>" & HtmlEncode(parts(3)) & "</td><td>" & HtmlEncode(parts(4)) & "</td><td class='location-col'>" & HtmlEncode(parts(5)) & "</td><td class='location-col'>" & HtmlEncode(parts(6)) & "</td><td>" & HtmlEncode(parts(7)) & "</td></tr>"
                n = n + 1
            End If
        Next
        If Trim(rowsHtml) <> "" Then
            objFile.WriteLine rowsHtml
        Else
            objFile.WriteLine "<tr><td colspan='7'>Nenhum atalho recente interpretado na pasta Recent.</td></tr>"
        End If
    Else
        objFile.WriteLine "<tr><td colspan='7'>Pasta Recent sem atalhos .lnk, sem acesso ou inexistente: " & HtmlEncode(recentPath) & "</td></tr>"
    End If

    objFile.WriteLine "</table>"
    objFile.WriteLine "</div>"
    objFile.WriteLine "<div class='mini-note'>Origem: coleta direta da pasta <code>" & HtmlEncode(recentPath) & "</code>; usados os timestamps do sistema de arquivos (Criacao/Acesso/Modificacao) e tentativa de resolucao do alvo do atalho.</div>"
End Sub

Function BuildUserArtifactTimelineRowsHtml()
    Dim rawLines, lines, i, line, parts, rows
    rows = ""
    If Trim(CStr(strUserArtifactTimelineRecords & "")) = "" Then
        BuildUserArtifactTimelineRowsHtml = ""
        Exit Function
    End If
    rawLines = Split(strUserArtifactTimelineRecords, vbLf)
    lines = SortStringArrayAsc(rawLines)
    For i = UBound(lines) To 0 Step -1
        line = Trim(CStr(lines(i) & ""))
        If line <> "" Then
            parts = Split(line, Chr(30))
            If UBound(parts) >= 4 Then
                rows = rows & "<tr><td>" & HtmlEncode(parts(1)) & "</td><td>" & HtmlEncode(parts(2)) & "</td><td>" & HtmlEncode(parts(3)) & "</td><td class='path'>" & HtmlEncode(parts(4)) & "</td></tr>"
            End If
        End If
    Next
    BuildUserArtifactTimelineRowsHtml = rows
End Function
