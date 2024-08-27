# 证书部署 Webhook 服务
## 一、简介
本项目是一个使用 Go 语言和 Gin 框架实现的证书部署 Webhook 服务。当接收到特定的证书部署请求时，该服务能够解析请求中的数据，获取域名对应的 IP 地址，并通过 SSH 将证书和密钥发送到指定 IP 的服务器上，并重新加载 Nginx 服务。
## 二、功能特点
### 1. 证书部署处理
接收包含证书信息的 Webhook 请求，包括证书名称、关联域名、私钥、完整证书链和过期时间等。
验证请求签名，确保请求的合法性。
### 2. IP 地址解析
对于请求中的证书关联域名，尝试解析出对应的 IP 地址。支持处理通配符域名，若遇到通配符域名会根据特定规则进行处理。
### 3. SSH 操作
通过读取配置文件中的 SSH 连接信息（用户、私钥、端口、证书存储路径等），建立与目标服务器的 SSH 连接。
在目标服务器上创建证书存储目录，将证书和密钥写入指定路径，并重新加载 Nginx 服务以应用新的证书。
## 三、使用方法
### 1. 配置文件
在项目目录下创建一个名为config.json的配置文件，文件格式如下：
```{
    "ip_address_1": {
        "user": "ssh_username_1",
        "privateKey": "ssh_private_key_1",
        "port": "ssh_port_1",
        "certPath": "certificate_path_1",
        "token": "token_1"
    },
    "ip_address_2": {
        "user": "ssh_username_2",
        "privateKey": "ssh_private_key_2",
        "port": "ssh_port_2",
        "certPath": "certificate_path_2",
        "token": "token_2"
    },
    //... 可添加更多 IP 地址的配置
    "*": {
        "user": "default_username",
        "privateKey": "default_private_key",
        "port": "default_port",
        "certPath": "default_certificate_path",
        "token": "default_token"
    }
}
```
其中，ip_address_n为具体的 IP 地址或域名，每个配置项包含 SSH 连接所需的用户、私钥、端口、证书存储路径和用于签名验证的令牌。通配符配置项*用于在无法找到特定 IP 或域名的配置时提供默认值。
### 2. 启动服务
运行以下命令启动服务：
```
$ go run main.go
```
服务将在端口 3901 上监听请求。
###  3. 发送 Webhook 请求
向`http://your_server_ip:3901/v1/webhook`发送 POST 请求，请求体格式如下：
```
{
    "timestamp": <当前时间戳>,
    "payload": {
        "certificateName": "<证书名称>",
        "certificateDomains": ["<证书关联域名列表>"],
        "certificateCertKey": "<证书私钥（PEM 格式）>",
        "certificateFullchainCerts": "<证书（包含证书和中间证书，PEM 格式）>",
        "certificateExpireAt": <证书过期时间戳>
    },
    "sign": "<请求签名，格式为 MD5(时间戳:回调令牌)>"
}
```
## 四、注意事项
### 1. 安全性
配置文件中的私钥信息应妥善保管，避免泄露。
在生产环境中，不建议使用InsecureIgnoreHostKey作为主机密钥验证方式，应采用更安全的方法来验证服务器的主机密钥。（TODO）
### 2. 通配符域名处理
对于通配符域名，解析 IP 地址时会进行特殊处理。但请注意，随便取一个类似ip.example.com的名称去检测 IP 地址可能不准确。（TODO）
### 3. 签名验证
确保发送请求时的签名计算正确，使用正确的回调令牌进行签名验证，以保证请求的合法性。
## 五、贡献
欢迎提交问题和改进建议，共同完善这个项目。
希望这个 README 文件对你有所帮助！如果你有任何其他问题，请随时联系项目维护者。