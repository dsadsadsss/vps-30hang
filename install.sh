#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 全局变量
SERVICE_NAME="vps-proxy"
INSTALL_DIR="/opt/vps-proxy"
CONFIG_FILE="$INSTALL_DIR/.env"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
OPENRC_FILE="/etc/init.d/$SERVICE_NAME"
SCRIPT_FILE="$INSTALL_DIR/index.js"

# 检测初始化系统
detect_init_system() {
    if command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; then
        echo "systemd"
    elif command -v rc-service >/dev/null 2>&1; then
        echo "openrc"
    elif command -v service >/dev/null 2>&1; then
        echo "sysv"
    else
        echo "unknown"
    fi
}

# 服务管理函数
start_service() {
    local init_system=$(detect_init_system)
    case $init_system in
        "systemd")
            systemctl start "$SERVICE_NAME"
            ;;
        "openrc")
            rc-service "$SERVICE_NAME" start
            ;;
        *)
            echo -e "${RED}无法启动服务：未知的初始化系统${NC}"
            return 1
            ;;
    esac
}

stop_service() {
    local init_system=$(detect_init_system)
    case $init_system in
        "systemd")
            systemctl stop "$SERVICE_NAME" 2>/dev/null
            ;;
        "openrc")
            rc-service "$SERVICE_NAME" stop 2>/dev/null
            ;;
    esac
}

restart_service() {
    local init_system=$(detect_init_system)
    case $init_system in
        "systemd")
            systemctl restart "$SERVICE_NAME"
            ;;
        "openrc")
            rc-service "$SERVICE_NAME" restart
            ;;
        *)
            stop_service
            sleep 2
            start_service
            ;;
    esac
}

is_service_active() {
    local init_system=$(detect_init_system)
    case $init_system in
        "systemd")
            systemctl is-active --quiet "$SERVICE_NAME"
            ;;
        "openrc")
            rc-service "$SERVICE_NAME" status >/dev/null 2>&1
            ;;
        *)
            return 1
            ;;
    esac
}

disable_service() {
    local init_system=$(detect_init_system)
    case $init_system in
        "systemd")
            systemctl disable "$SERVICE_NAME" 2>/dev/null
            ;;
        "openrc")
            rc-update del "$SERVICE_NAME" default 2>/dev/null
            ;;
    esac
}

show_service_logs() {
    local init_system=$(detect_init_system)
    case $init_system in
        "systemd")
            echo -e "${BLUE}最近20条服务日志:${NC}"
            journalctl -u "$SERVICE_NAME" -n 20 --no-pager
            echo
            echo -e "${BLUE}实时查看日志请使用: ${NC}journalctl -u $SERVICE_NAME -f"
            ;;
        "openrc")
            echo -e "${BLUE}OpenRC日志查看:${NC}"
            if [ -f "/var/log/$SERVICE_NAME.log" ]; then
                tail -20 "/var/log/$SERVICE_NAME.log"
            else
                echo -e "${YELLOW}日志文件不存在，请检查 /var/log/ 目录${NC}"
            fi
            ;;
        *)
            echo -e "${YELLOW}无法显示日志：未知的初始化系统${NC}"
            ;;
    esac
}

show_service_status() {
    local init_system=$(detect_init_system)
    echo -e "${CYAN}=== 服务状态 ($init_system) ===${NC}"
    
    case $init_system in
        "systemd")
            systemctl status "$SERVICE_NAME" --no-pager
            ;;
        "openrc")
            rc-service "$SERVICE_NAME" status
            ;;
        *)
            echo -e "${YELLOW}无法显示状态：未知的初始化系统${NC}"
            ;;
    esac
}

# 检测系统类型
detect_system() {
    if [[ -f /etc/alpine-release ]]; then
        echo "alpine"
    elif [[ -f /etc/redhat-release ]]; then
        echo "centos"
    elif cat /etc/issue | grep -Eqi "alpine"; then
        echo "alpine"
    elif cat /etc/issue | grep -Eqi "debian"; then
        echo "debian"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        echo "ubuntu"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
        echo "centos"
    elif cat /proc/version | grep -Eqi "alpine"; then
        echo "alpine"
    elif cat /proc/version | grep -Eqi "debian"; then
        echo "debian"
    elif cat /proc/version | grep -Eqi "ubuntu"; then
        echo "ubuntu"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
        echo "centos"
    else
        echo "unknown"
    fi
}

# 安装依赖
install_dependencies() {
    local system=$(detect_system)
    
    echo -e "${BLUE}正在安装系统依赖...${NC}"
    
    case $system in
        "ubuntu"|"debian")
            apt-get update
            apt-get install -y curl wget unzip systemd
            ;;
        "centos")
            yum update -y
            yum install -y curl wget unzip systemd
            ;;
        "alpine")
            apk update
            apk add --no-cache curl wget unzip openrc nodejs npm
            # Alpine使用OpenRC而不是systemd
            rc-update add local default 2>/dev/null || true
            ;;
        *)
            echo -e "${RED}未知系统类型，请手动安装 curl、wget、unzip${NC}"
            ;;
    esac
}

# 安装Node.js
install_nodejs() {
    local system=$(detect_system)
    
    if command -v node >/dev/null 2>&1; then
        local node_version=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
        if [ "$node_version" -ge 14 ]; then
            echo -e "${GREEN}Node.js 已安装 (版本: $(node -v))${NC}"
            return 0
        fi
    fi
    
    echo -e "${BLUE}正在安装 Node.js...${NC}"
    
    case $system in
        "alpine")
            # Alpine已在依赖安装时安装了nodejs和npm
            echo -e "${GREEN}Node.js 安装完成 (Alpine)${NC}"
            ;;
        "ubuntu"|"debian")
            # 下载并安装Node.js
            curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
            apt-get install -y nodejs
            ;;
        "centos")
            curl -fsSL https://rpm.nodesource.com/setup_lts.x | bash -
            yum install -y nodejs npm
            ;;
        *)
            # 使用通用安装方法
            curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
            source ~/.bashrc
            nvm install --lts
            nvm use --lts
            ;;
    esac
    
    if command -v node >/dev/null 2>&1; then
        echo -e "${GREEN}Node.js 安装成功 (版本: $(node -v))${NC}"
    else
        echo -e "${RED}Node.js 安装失败${NC}"
        exit 1
    fi
}

# 创建服务目录
create_directories() {
    echo -e "${BLUE}创建服务目录...${NC}"
    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
}

# 创建Node.js脚本
create_script() {
    echo -e "${BLUE}创建应用脚本...${NC}"
    
    cat > "$SCRIPT_FILE" << 'EOF'
const os = require('os');
const http = require('http');
const { Buffer } = require('buffer');
const fs = require('fs');
const axios = require('axios');
const path = require('path');
const net = require('net');
const { exec, execSync } = require('child_process');
const { WebSocket, createWebSocketStream } = require('ws');
const 哈哈哈 = (...args) => console.log.bind(this, ...args);
const 嘻嘻嘻 = (...args) => console.error.bind(this, ...args);
const 美好的一天 = process.env.UUID || 'b28f60af-d0b9-4ddf-baaa-7e49c93c380b';
const 彩虹桥 = 美好的一天.replace(/-/g, "");
const 服务器很棒 = process.env.NSERVER || '';
const 端口很好 = process.env.NPORT || '443';        
const 密钥很牛 = process.env.NKEY || '';             
const 域名超赞 = process.env.DOMAIN || '';  //填反代域名
const 名字不错 = process.env.NAME || 'ws';
const 监听端口 = process.env.PORT || 3000;

// 分割关键词
const 协议前缀 = 'vl' + 'ess' + '://';
const 固定服务器 = 'ip.sb:443';
const 加密选项 = '?encryption=none&security=tls&sni=';
const 连接类型 = '&type=ws&host=';
const 路径配置 = '&path=%2F#';

// 创建HTTP路由
const 超级服务器 = http.createServer((req, res) => {
  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Hello, World\n');
  } else if (req.url === `/${美好的一天}`) {
    // 如果DOMAIN未设置，则使用当前请求的host作为域名
    const 实际域名 = 域名超赞 || req.headers.host;
    
    let 订阅链接;
    
    if (域名超赞) {
      // DOMAIN已设置，使用原有逻辑
      订阅链接 = 协议前缀 + 美好的一天 + '@' + 固定服务器 + 加密选项 + 实际域名 + 连接类型 + 实际域名 + 路径配置 + 名字不错;
    } else {
      // DOMAIN未设置，使用当前网址作为服务器，security=none
      let 当前服务器 = req.headers.host;
      
      // 如果当前域名没有带端口，则添加:80
      if (!当前服务器.includes(':')) {
        当前服务器 = 当前服务器 + ':80';
      }
      
      const 无加密选项 = '?encryption=none&security=none&host=';
      const 原始域名 = req.headers.host.split(':')[0]; // host参数使用原始域名（不带端口）
      订阅链接 = 协议前缀 + 美好的一天 + '@' + 当前服务器 + 无加密选项 + 原始域名 + '&type=ws&path=%2F#' + 名字不错;
    }
    
    const 编码结果 = Buffer.from(订阅链接).toString('base64');

    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(编码结果 + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

超级服务器.listen(监听端口, () => {
  console.log(`HTTP Server is running on port ${监听端口}`);
});

// 判断系统架构
function 检测系统架构() {
  const arch = os.arch();
  const platform = os.platform();
  
  console.log(`Detected architecture: ${arch}, platform: ${platform}`);
  
  if (arch === 'arm' || arch === 'arm64') {
    return 'arm';
  } else if (arch === 's390x') {
    return 's390x';
  } else {
    return 'amd';
  }
}

// 下载对应系统架构的文件
function 获取远程文件(文件名称, 下载地址, 完成回调) {
  const 本地路径 = path.join("./", 文件名称);
  const 文件写入器 = fs.createWriteStream(本地路径);
  axios({
    method: 'get',
    url: 下载地址,
    responseType: 'stream',
  })
    .then(返回结果 => {
      返回结果.data.pipe(文件写入器);
      文件写入器.on('finish', function() {
        文件写入器.close();
        完成回调(null, 文件名称);
      });
    })
    .catch(出现错误 => {
      完成回调(`Download ${文件名称} failed: ${出现错误.message}`);
    });
}

function 批量下载文件() {
  const 当前架构 = 检测系统架构();
  const 文件列表 = 根据架构获取文件(当前架构);

  if (文件列表.length === 0) {
    console.log(`Can't find a file for the current architecture`);
    return;
  }

  let 完成数量 = 0;

  文件列表.forEach(文件详情 => {
    获取远程文件(文件详情.文件名称, 文件详情.下载地址, (err, fileName) => {
      if (err) {
        console.log(`Download ${fileName} failed`);
      } else {
        console.log(`Download ${fileName} successfully`);

        完成数量++;

        if (完成数量 === 文件列表.length) {
          setTimeout(() => {
            文件权限设置();
          }, 3000);
        }
      }
    });
  });
}

function 根据架构获取文件(架构名称) {
  if (架构名称 === 'arm') {
    return [
      { 文件名称: "npm", 下载地址: "https://github.com/Fscarmon/flies/releases/latest/download/agent-linux_arm64" },
    ];
  } else if (架构名称 === 'amd') {
    return [
      { 文件名称: "npm", 下载地址: "https://github.com/Fscarmon/flies/releases/latest/download/agent-linux_amd64" },
    ];
  } else if (架构名称 === 's390x') {
    // IBM s390x架构，如果有专门的二进制文件则使用，否则尝试通用版本
    console.log('s390x architecture detected, using generic binary or skipping');
    return [
      // 注意：这里假设有s390x版本，如果没有则可能需要跳过或使用其他替代方案
      { 文件名称: "npm", 下载地址: "https://github.com/Fscarmon/flies/releases/latest/download/agent-linux_s390x" },
    ];
  }
  return [];
}

// 授权并运行程序
function 文件权限设置() {
  const 程序路径 = './npm';
  const 执行权限 = 0o775;
  fs.chmod(程序路径, 执行权限, (err) => {
    if (err) {
      console.error(`Empowerment failed:${err}`);
    } else {
      console.log(`Empowerment success:${执行权限.toString(8)} (${执行权限.toString(10)})`);

      // 运行程序
      let 安全连接 = '';
      if (服务器很棒 && 端口很好 && 密钥很牛) {
        if (端口很好 === '443') {
          安全连接 = '--tls';
        } else {
          安全连接 = '';
        }
        const 启动命令 = `./npm -s ${服务器很棒}:${端口很好} -p ${密钥很牛} ${安全连接} --skip-conn --disable-auto-update --skip-procs --report-delay 4 >/dev/null 2>&1 &`;
        try {
          exec(启动命令);
          console.log('webapp is running');
        } catch (error) {
          console.error(`webapp running error: ${error}`);
        }
      } else {
        console.log('NS variable is empty,skip running');
      }
    }
  });
}

// 只有当NSERVER存在时才下载和运行二进制文件
if (服务器很棒) {
  批量下载文件();
} else {
  console.log('NSERVER variable is empty, skip downloading and running binary files');
}

// WebSocket 服务器
const 套接字服务器 = new WebSocket.Server({ server: 超级服务器 });
套接字服务器.on('connection', ws => {
  ws.on('message', 接收消息 => {
    if (接收消息.length < 18) {
      return;
    }
    try {
      const [协议版本] = 接收消息;
      const 用户标识 = 接收消息.slice(1, 17);
      if (!用户标识.every((v, i) => v == parseInt(彩虹桥.substr(i * 2, 2), 16))) {
        return;
      }
      let 当前位置 = 接收消息.slice(17, 18).readUInt8() + 19;
      const 目标端口 = 接收消息.slice(当前位置, 当前位置 += 2).readUInt16BE(0);
      const 地址格式 = 接收消息.slice(当前位置, 当前位置 += 1).readUInt8();
      const 目标主机 = 地址格式 === 1 ? 接收消息.slice(当前位置, 当前位置 += 4).join('.') :
        (地址格式 === 2 ? new TextDecoder().decode(接收消息.slice(当前位置 + 1, 当前位置 += 1 + 接收消息.slice(当前位置, 当前位置 + 1).readUInt8())) :
          (地址格式 === 3 ? 接收消息.slice(当前位置, 当前位置 += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));
      ws.send(new Uint8Array([协议版本, 0]));
      const 数据流 = createWebSocketStream(ws);
      net.connect({ host: 目标主机, port: 目标端口 }, function () {
        this.write(接收消息.slice(当前位置));
        数据流.on('error', () => {}).pipe(this).on('error', () => {}).pipe(数据流);
      }).on('error', () => {});
    } catch (err) {
      // 静默处理错误
    }
  }).on('error', () => {});
});
EOF

    chmod +x "$SCRIPT_FILE"
}

# 安装npm依赖
install_npm_dependencies() {
    echo -e "${BLUE}安装npm依赖...${NC}"
    cd "$INSTALL_DIR"
    
    cat > package.json << 'EOF'
{
  "name": "vps-proxy",
  "version": "1.0.0",
  "description": "VPS Proxy Service",
  "main": "index.js",
  "dependencies": {
    "axios": "latest",
    "ws": "latest"
  },
  "scripts": {
    "start": "node index.js"
  }
}
EOF

    npm install
}

# 获取用户输入
get_user_input() {
    echo -e "${CYAN}=== 配置参数 ===${NC}"
    
    read -p "请输入端口 (PORT) [默认: 3000]: " input_port
    PORT=${input_port:-3000}
    
    read -p "请输入名称 (NAME) [默认: ws]: " input_name
    NAME=${input_name:-ws}
    
    read -p "请输入UUID [默认: b28f60af-d0b9-4ddf-baaa-7e49c93c380b]: " input_uuid
    UUID=${input_uuid:-b28f60af-d0b9-4ddf-baaa-7e49c93c380b}
    
    read -p "请输入NSERVER (可选): " NSERVER
    
    if [ ! -z "$NSERVER" ]; then
        read -p "请输入NPORT [默认: 443]: " input_nport
        NPORT=${input_nport:-443}
        
        read -p "请输入NKEY: " NKEY
    fi
    
    read -p "请输入DOMAIN (可选): " DOMAIN
}

# 创建配置文件
create_config() {
    echo -e "${BLUE}创建配置文件...${NC}"
    
    cat > "$CONFIG_FILE" << EOF
PORT=$PORT
NAME=$NAME
UUID=$UUID
NSERVER=$NSERVER
NPORT=$NPORT
NKEY=$NKEY
DOMAIN=$DOMAIN
EOF

    chmod 600 "$CONFIG_FILE"
}

# 创建systemd服务文件
create_systemd_service() {
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=VPS Proxy Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$CONFIG_FILE
ExecStart=$(which node) $SCRIPT_FILE
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
}

# 创建OpenRC服务文件（Alpine）
create_openrc_service() {
    cat > "$OPENRC_FILE" << EOF
#!/sbin/openrc-run

name="VPS Proxy Service"
description="VPS Proxy Service"

user="root"
group="root"

pidfile="/var/run/\${RC_SVCNAME}.pid"
command="$(which node)"
command_args="$SCRIPT_FILE"
command_background="yes"
command_user="\$user:\$group"

directory="$INSTALL_DIR"

start_pre() {
    # 加载环境变量
    if [ -f "$CONFIG_FILE" ]; then
        export \$(cat $CONFIG_FILE | grep -v '^#' | xargs)
    fi
}

depend() {
    need net
    after firewall
}
EOF

    chmod +x "$OPENRC_FILE"
    rc-update add "$SERVICE_NAME" default
}

# 创建服务
create_service() {
    local init_system=$(detect_init_system)
    echo -e "${BLUE}创建系统服务 ($init_system)...${NC}"
    
    case $init_system in
        "systemd")
            create_systemd_service
            ;;
        "openrc")
            create_openrc_service
            ;;
        *)
            echo -e "${YELLOW}未检测到支持的初始化系统，请手动配置服务${NC}"
            return 1
            ;;
    esac
}

# 安装函数
install() {
    echo -e "${GREEN}=== 开始安装 VPS Proxy 服务 ===${NC}"
    
    # 检查是否已安装
    if [ -d "$INSTALL_DIR" ]; then
        echo -e "${YELLOW}检测到已安装，请先卸载后再安装${NC}"
        return 1
    fi
    
    install_dependencies
    install_nodejs
    create_directories
    create_script
    install_npm_dependencies
    get_user_input
    create_config
    create_service
    
    # 启动服务
    start_service
    
    if is_service_active; then
        SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")
        echo -e "${GREEN}=== 安装完成 ===${NC}"
        echo -e "${GREEN}服务已启动并设置为开机自启${NC}"
        echo -e "${CYAN}访问地址: http://$SERVER_IP:$PORT${NC}"
        echo -e "${CYAN}节点链接: http://$SERVER_IP:$PORT/$UUID${NC}"
    else
        echo -e "${RED}服务启动失败，请检查日志${NC}"
        show_service_logs
    fi
}

# 卸载函数
uninstall() {
    echo -e "${YELLOW}=== 开始卸载 VPS Proxy 服务 ===${NC}"
    
    # 停止并禁用服务
    stop_service
    disable_service
    
    # 删除服务文件
    rm -f "$SERVICE_FILE"
    rm -f "$OPENRC_FILE"
    
    local init_system=$(detect_init_system)
    if [ "$init_system" = "systemd" ]; then
        systemctl daemon-reload
    fi
    
    # 删除安装目录
    rm -rf "$INSTALL_DIR"
    
    echo -e "${GREEN}卸载完成${NC}"
}

# 修改配置
modify_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}配置文件不存在，请先安装服务${NC}"
        return 1
    fi
    
    echo -e "${CYAN}=== 当前配置 ===${NC}"
    cat "$CONFIG_FILE"
    echo
    
    echo -e "${CYAN}=== 修改配置 ===${NC}"
    get_user_input
    create_config
    
    # 重启服务
    restart_service
    
    if is_service_active; then
        echo -e "${GREEN}配置修改完成，服务已重启${NC}"
    else
        echo -e "${RED}服务重启失败，请检查日志${NC}"
        show_service_logs
    fi
}

# 查看节点链接
show_node_link() {
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "${RED}配置文件不存在，请先安装服务${NC}"
        return 1
    fi
    
    source "$CONFIG_FILE"
    
    echo -e "${CYAN}=== 节点信息 ===${NC}"
    echo -e "${GREEN}服务状态: $(is_service_active && echo "运行中" || echo "已停止")${NC}"
    echo -e "${GREEN}监听端口: $PORT${NC}"
    echo -e "${GREEN}UUID: $UUID${NC}"
    echo -e "${GREEN}名称: $NAME${NC}"
    echo -e "${GREEN}系统类型: $(detect_system)${NC}"
    echo -e "${GREEN}初始化系统: $(detect_init_system)${NC}"
    echo
    echo -e "${CYAN}=== 访问链接 ===${NC}"
    
    # 获取服务器IP
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")
    
    echo -e "${YELLOW}基础访问: ${NC}http://$SERVER_IP:$PORT"
    echo -e "${YELLOW}节点链接: ${NC}http://$SERVER_IP:$PORT/$UUID"
    echo
    echo -e "${PURPLE}使用方法：${NC}"
    echo -e "1. 复制节点链接到浏览器访问"
    echo -e "2. 将返回的base64编码内容导入到客户端"
    echo -e "3. 或直接使用返回的vless链接"
}

# 查看日志
show_logs() {
    show_service_logs
}

# 检查服务状态
check_status() {
    show_service_status
}

# 主菜单
main_menu() {
    clear
    echo -e "${PURPLE}===============================================${NC}"
    echo -e "${PURPLE}            vps nodexy一键管理脚本${NC}"
    echo -e "${PURPLE}     支持: Ubuntu/Debian/CentOS/Alpine${NC}"
    echo -e "${PURPLE}     架构: AMD64/ARM64/IBM s390x${NC}"
    echo -e "${PURPLE}===============================================${NC}"
    echo
    echo -e "${CYAN}1.${NC} 安装服务"
    echo -e "${CYAN}2.${NC} 卸载服务"
    echo -e "${CYAN}3.${NC} 修改配置"
    echo -e "${CYAN}4.${NC} 查看订阅链接"
    echo -e "${CYAN}5.${NC} 查看服务状态"
    echo -e "${CYAN}6.${NC} 查看日志"
    echo -e "${CYAN}0.${NC} 退出"
    echo
    echo -e "${PURPLE}===============================================${NC}"
}

# 主程序
main() {
    # 检查root权限
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}此脚本需要root权限运行${NC}"
        exit 1
    fi
    
    while true; do
        main_menu
        read -p $'\033[1;32m请选择操作 [0-6]: \033[0m' choice
        
        case $choice in
            1)
                install
                read -p "按回车键继续..."
                ;;
            2)
                read -p $'\033[1;33m确认卸载服务？[y/N]: \033[0m' confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    uninstall
                fi
                read -p "按回车键继续..."
                ;;
            3)
                modify_config
                read -p "按回车键继续..."
                ;;
            4)
                show_node_link
                read -p "按回车键继续..."
                ;;
            5)
                check_status
                read -p "按回车键继续..."
                ;;
            6)
                show_logs
                read -p "按回车键继续..."
                ;;
            0)
                echo -e "${GREEN}再见！${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}无效选择，请重新输入${NC}"
                sleep 2
                ;;
        esac
    done
}

# 运行主程序
main "$@"