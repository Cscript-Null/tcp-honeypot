# TCP-Honeypot

该项目是一个基于Go语言编写的蜜罐程序，用于检测和记录对指定端口的未经授权的访问尝试。该程序支持将警报记录到日志文件、发送HTTP POST请求到指定服务器，并可以选择性地封禁访问IP。

## 功能特性

- **端口监听**：监听多个指定的端口，记录所有连接尝试。
- **日志记录**：将连接尝试记录到日志文件中。
- **HTTP告警**：通过HTTP POST请求将告警发送到远程服务器。
- **IP封禁**：可选的IP封禁功能，支持临时或永久封禁。
- **配置文件支持**：通过JSON配置文件自定义监听端口、日志位置、告警服务器等。

## 环境要求

- Go 1.16 或更高版本
- Linux 系统（需要`iptables`来封禁IP）

## 安装步骤

### 1. 克隆项目

```bash
git clone https://github.com/yourusername/honeypot.git
cd honeypot
```

### 2. 编译程序

确保你的系统已经安装了Go语言环境，执行以下命令编译程序：

```bash
go build -o honeypot main.go
```

### 3. 配置文件

在程序运行之前，你需要创建一个`config.json`文件来指定程序的配置。以下是一个示例配置文件：

```json
{
  "LogToFile": true,
  "PostToServer": true,
  "ServerURL": "https://yourserver.com/alert",
  "BanIP": true,
  "BanDuration": 10,
  "PortsToMonitor": [445, 135, 139, 5985, 3389, 22, 1433, 3306, 5900, 1723],
  "LogFile": "./LogFile.txt"
}
```

#### 配置选项说明：

- `LogToFile`: 是否将告警记录到日志文件中（`true` 或 `false`）。
- `PostToServer`: 是否将告警通过HTTP POST请求发送到远程服务器（`true` 或 `false`）。
- `ServerURL`: 发送告警的远程服务器URL。
- `BanIP`: 是否启用IP封禁功能（`true` 或 `false`）。
- `BanDuration`: 封禁时间（分钟），如果为0，则永久封禁。
- `PortsToMonitor`: 需要监听的端口列表。
- `LogFile`: 日志文件的保存路径。

### 4. 运行程序

使用以下命令运行蜜罐程序：

```bash
sudo ./honeypot
```

**注意**：由于程序可能需要修改`iptables`规则来封禁IP，因此建议使用`sudo`权限运行。

## 日志文件

默认情况下，日志文件会记录在`./LogFile.txt`中。你可以在配置文件中自定义日志文件路径。

日志条目格式如下：

```
2024-11-05T22:45:00+08:00 - Alert: Connection attempt detected on port 22 from IP 192.168.1.100
```

## 封禁IP

如果启用了`BanIP`选项，程序会使用`iptables`封禁恶意IP。封禁时间可以通过`BanDuration`字段设置，单位为分钟。如果设置为`0`，则永久封禁。

## 远程告警

如果启用了`PostToServer`选项，程序会通过HTTP POST请求将告警发送到配置的`ServerURL`。告警数据将以JSON格式发送，格式如下：

```json
{
  "port": 22,
  "remote_ip": "192.168.1.100",
  "timestamp": "2024-11-05T22:45:00+08:00"
}
```

## 停止程序

你可以通过按下`Ctrl+C`来停止程序。程序会优雅地关闭所有端口监听器并退出。

## 注意事项

- 该程序需要在Linux系统上运行，并且需要`iptables`来封禁IP。
- 请确保你有足够的权限来修改`iptables`规则，否则封禁功能将无法正常工作。

## 常见问题

### 1. 如何更改监听的端口？
在`config.json`文件中的`PortsToMonitor`字段中添加或删除端口号即可。

### 2. 如何永久封禁IP？
将`BanDuration`设置为`0`，程序将永久封禁恶意IP。

### 3. 如何查看日志？
日志文件的路径在`config.json`文件中指定，默认路径为`./LogFile.txt`。你可以使用`cat`或`tail`命令查看日志内容：

```bash
tail -f ./LogFile.txt
```

## 贡献

欢迎提交Pull Request或Issue来帮助改进该项目。

## 许可证

该项目使用MIT许可证。详细信息请查看[LICENSE](./LICENSE)文件。

---

通过这个`README.md`文档，用户可以快速了解如何安装、配置和运行该蜜罐程序。
