# 定义需要监控的端口列表
# $portsToMonitor = @(445, 135, 139, 5985, 3389)
param ([array]$portsToMonitor=@(
        445,    # SMB - 常被用于传播蠕虫和勒索软件
        135,    # RPC - 远程过程调用，常用于Windows网络服务
        139,    # NetBIOS - 文件共享和打印服务
        5985,   # WinRM - Windows远程管理
        3389,   # RDP - 远程桌面协议
        22,     # SSH - 安全外壳协议，常用于Unix/Linux系统的远程管理
        1433,   # Microsoft SQL Server - 数据库服务，可能被利用进行数据窃取
        3306,   # MySQL - 另一种常见的数据库服务端口
        5900,   # VNC - 虚拟网络计算，远程桌面访问
        1723,   # PPTP VPN - 虚拟专用网络服务
        8000,   # HTTP 备用端口，常用于Web应用
        8080,   # HTTP 备用端口，常用于Web应用
        3268,   # Global Catalog (Active Directory) - 用于目录服务查询
        389,    # LDAP - 轻量级目录访问协议
        636,    # LDAPS - 加密的LDAP
        21      # FTP - 文件传输协议    
    )
)


# 定义告警函数
function Send-Alert {
    param (
        [int]$Port,
        [string]$RemoteIP,
        [string]$Timestamp=(Get-Date)
    )

    # 此处应根据具体需求实现具体的告警机制，例如发送邮件、记录日志或调用 API
    # 示例：将告警信息记录到日志文件
    $logMessage = "$(Get-Date) - Alert: Connection attempt detected on port $Port from IP $RemoteIP"
    Write-Output $logMessage
    # 可选：将日志写入文件
    Add-Content -Path ".\LogFile.txt" -Value $logMessage

    # 示例：通过 HTTP POST 发送告警到远程服务器
    $payload = @{port = $Port; remoteIP = $RemoteIP; timestamp = (Get-Date)} | ConvertTo-Json
    Invoke-RestMethod -Uri "https://yourserver.com/alert" -Method Post -Body $payload -ContentType "application/json"
}

# 检查指定端口是否被监听的函数
function Is-PortListening {
    param (
        [int]$Port
    )
    $tcpConnections = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return $tcpConnections.Count -gt 0
}

# 启动监听器的函数
function Start-PortListener {
    param (
        [int]$Port
    )

    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
        $listener.Start()
        Write-Output "Started listening on port $Port as honeypot."

        while ($true) {
            # 侦听客户端连接（阻塞调用）
            $client = $listener.AcceptTcpClient()
            $remoteEndPoint = $client.Client.RemoteEndPoint.ToString()
            Write-Output "Connection attempt detected on port $Port from $remoteEndPoint"

            # 调用告警函数
            Send-Alert -Port $Port -RemoteIP $remoteEndPoint 

            # 关闭客户端连接
            $client.Close()
        }
    }
    catch {
        Write-Error "Failed to start listener on port $Port. It might already be in use by a legitimate service."
    }
}


function Tcp-honeyport{
    param ([array]$portsList)
    foreach ($port in $portsList) {
        if (-not (Is-PortListening -Port $port)) {
            # 如果端口未被监听，启动一个后台作业来监听该端口
            Start-Job -ScriptBlock {
                param($p)
                Start-PortListener -Port $p
            } -ArgumentList $port | Out-Null
            Write-Output "Started honeypot on port $port."
        }
        else {
            Write-Output "Port $port is already in use by a legitimate service. Skipping honeypot setup for this port."
        }
    }

    # 保持脚本运行以维持监听器
    # 可以通过添加一个无限循环或等待用户输入来实现
    Write-Output "Honeypot is running. Press [Ctrl]+[C] to stop."
    while ($true) { Start-Sleep -Seconds 60 }
}

function Main {
    Tcp-honeyport -portsList $portsToMonitor
} 

if ($MyInvocation.MyCommand.Path -eq $PSCommandPath) {
    Main
}