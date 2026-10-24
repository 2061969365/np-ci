# 用本地面板 WS（ws://127.0.0.1:33272/ws，帧分隔 <$!$>）驱动官方客户端：
#   官方客户端已在启动时按 config 的 Auto_login 自动登录，
#   这里只发 conpc <pcid>（映射模式连接）并打印所有回帧。
param(
    [Parameter(Mandatory = $true)][string]$Pcid,
    [int]$MaxWaitMs = 25000
)

$ErrorActionPreference = 'Stop'
$sep = '<$!$>'

function New-Ws {
    $ws = [System.Net.WebSockets.ClientWebSocket]::new()
    $cts = [System.Threading.CancellationTokenSource]::new()
    $ws.ConnectAsync([Uri]'ws://127.0.0.1:33272/ws', $cts.Token).Wait(15000) | Out-Null
    return @{ ws = $ws; cts = $cts }
}

function Send-Frame($c, [string]$s) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($s)
    $seg = [ArraySegment[byte]]::new($bytes)
    $c.ws.SendAsync($seg, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $c.cts.Token).Wait(8000) | Out-Null
    Write-Host "WS -> $s"
}

function Recv-Frame($c, [int]$timeoutMs) {
    $buf = New-Object byte[] 262144
    $seg = [ArraySegment[byte]]::new($buf)
    $task = $c.ws.ReceiveAsync($seg, $c.cts.Token)
    if (-not $task.Wait($timeoutMs)) { return $null }
    if ($task.Result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) { return '<close>' }
    return [Text.Encoding]::UTF8.GetString($buf, 0, $task.Result.Count)
}

function Drain($c, [int]$ms) {
    $deadline = (Get-Date).AddMilliseconds($ms)
    while ((Get-Date) -lt $deadline) {
        $f = Recv-Frame $c 1500
        if ($null -eq $f) { continue }
        Write-Host "WS <- $f"
        if ($f -eq '<close>') { return }
    }
}

$c = New-Ws
Write-Host "WS connected: $($c.ws.State)"

# 先拉一次主机列表确认登录态
Send-Frame $c 'pclist'
Drain $c 5000

# 映射模式连接
Send-Frame $c ("conpc" + $sep + $Pcid)
Drain $c $MaxWaitMs

Send-Frame $c 'pclist'
Drain $c 3000

$c.ws.Dispose()
Write-Host 'panel-connect done'
