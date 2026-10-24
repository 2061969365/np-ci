# 用本地面板 WS（ws://127.0.0.1:33272/ws，帧分隔 <$!$>）驱动官方客户端：
#   1) login（明文账号密码）
#   2) 等状态帧 1<...> / 2<...>（y = 顶号确认，自动回 y）
#   3) pclist 确认 pcid 在线
#   4) conpc <pcid>（映射模式连接）
param(
    [Parameter(Mandatory = $true)][string]$Pcid,
    [Parameter(Mandatory = $true)][string]$User,
    [Parameter(Mandatory = $true)][string]$Pwd,
    [int]$MaxWaitMs = 25000
)

$ErrorActionPreference = 'Stop'
$sep = '<$!$>'

$ws = [System.Net.WebSockets.ClientWebSocket]::new()
$cts = [System.Threading.CancellationTokenSource]::new()
$ws.ConnectAsync([Uri]'ws://127.0.0.1:33272/ws', $cts.Token).Wait(15000) | Out-Null
Write-Host "WS connected: $($ws.State)"

function Send-Frame([string]$s) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($s)
    $seg = [ArraySegment[byte]]::new($bytes)
    $ws.SendAsync($seg, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cts.Token).Wait(8000) | Out-Null
    $shown = $s
    if ($s -like 'login*' -or $s -like 'y*') { $shown = ($s -split [regex]::Escape($sep))[0] + $sep + '<masked>' }
    Write-Host "WS -> $shown"
}

function Recv-Frame([int]$timeoutMs) {
    $buf = New-Object byte[] 262144
    $seg = [ArraySegment[byte]]::new($buf)
    $task = $ws.ReceiveAsync($seg, $cts.Token)
    if (-not $task.Wait($timeoutMs)) { return $null }
    if ($task.Result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) { return '<close>' }
    return [Text.Encoding]::UTF8.GetString($buf, 0, $task.Result.Count)
}

function Drain([int]$ms) {
    $deadline = (Get-Date).AddMilliseconds($ms)
    while ((Get-Date) -lt $deadline) {
        $f = Recv-Frame 1500
        if ($null -eq $f) { continue }
        Write-Host "WS <- $f"
        if ($f -eq '<close>') { return }
    }
}

# 0) 先读启动状态帧
Drain 3000 | Out-Null

# 1) 登录
Send-Frame ("login" + $sep + $User + $sep + $Pwd + $sep + "0" + $sep + "0")
$deadline = (Get-Date).AddSeconds(20)
$logged = $false
while ((Get-Date) -lt $deadline -and -not $logged) {
    $f = Recv-Frame 1500
    if ($null -eq $f) { continue }
    Write-Host "WS <- $f"
    if ($f -like 'y*') {
        Write-Host '收到 y（顶号确认），回 y'
        Send-Frame ("y" + $sep + $User + $sep + $Pwd + $sep + "0" + $sep + "0")
        continue
    }
    if ($f -match '^[12]<') { $logged = $true }
}
if (-not $logged) {
    Write-Host '::warning::未检测到登录成功状态帧，做诊断后重试一次 login'
    $pid0 = (Get-Process natpierce -ErrorAction SilentlyContinue).Id
    Write-Host "--- natpierce pid=$pid0 TCP:"
    Get-NetTCPConnection -OwningProcess $pid0 -ErrorAction SilentlyContinue |
        Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort |
        Format-Table -AutoSize | Out-String | Write-Host
    Send-Frame 'pcinfo'
    Drain 3000 | Out-Null
    Send-Frame ("login" + $sep + $User + $sep + $Pwd + $sep + "0" + $sep + "0")
    Drain 12000 | Out-Null
    $pid0 = (Get-Process natpierce -ErrorAction SilentlyContinue).Id
    Write-Host "--- natpierce pid=$pid0 TCP (retry 后):"
    Get-NetTCPConnection -OwningProcess $pid0 -ErrorAction SilentlyContinue |
        Select-Object State, RemoteAddress, RemotePort |
        Format-Table -AutoSize | Out-String | Write-Host
    Send-Frame 'pclist'
    Drain 4000 | Out-Null
}

# 2) 主机列表
Send-Frame 'pclist'
Drain 5000 | Out-Null

# 3) 映射模式连接
Send-Frame ("conpc" + $sep + $Pcid)
Drain $MaxWaitMs | Out-Null

Send-Frame 'pclist'
Drain 3000 | Out-Null

$ws.Dispose()
Write-Host 'panel-connect done'
