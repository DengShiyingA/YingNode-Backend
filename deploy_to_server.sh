#!/bin/bash
SERVER="root@38.76.199.94"
DEST="/opt/YingNode-Backend"
LOCAL_DIR="/Users/two/Documents/YingNode-Backend-main/"

echo "=================================================="
echo "🚀 开始一键部署 YingNode 后端到 38.76.199.94"
echo "=================================================="

echo "[1/3] 正在准备服务器环境 (安装 rsync)..."
# 先登录服务器把 rsync 装上，并创建目录
ssh $SERVER "apt-get update -qq && apt-get install -y rsync -qq && mkdir -p $DEST"

echo ""
echo "[2/3] 正在将最新代码上传到服务器..."
# 同步代码（排除掉不需要的本地环境文件和缓存）
rsync -avz --exclude '.git' --exclude '.venv' --exclude '__pycache__' --exclude '*.pyc' --exclude '.DS_Store' --exclude 'xray' $LOCAL_DIR $SERVER:$DEST

echo ""
echo "[3/3] 正在服务器上配置 Python 环境和运行服务..."
ssh $SERVER << 'EOF'
  cd /opt/YingNode-Backend
  
  # 如果是 Ubuntu/Debian 系统，确保基础工具链安装好
  if command -v apt-get >/dev/null; then
      apt-get update -qq
      apt-get install -y python3-pip python3-venv -qq
  fi

  echo "  -> 创建干净的虚拟环境..."
  python3 -m venv .venv
  
  echo "  -> 安装项目需要的依赖库..."
  .venv/bin/pip install -r requirements.txt gunicorn -q

  echo ""
  echo "[3/3] 配置并在后台启动长驻服务进程 (Systemd)..."
  cat > /etc/systemd/system/yingnode-api.service << 'SERVICE_EOF'
[Unit]
Description=YingNode Backend API Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/YingNode-Backend
ExecStart=/opt/YingNode-Backend/.venv/bin/gunicorn -w 4 -b 0.0.0.0:5001 app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE_EOF

  systemctl daemon-reload
  systemctl enable yingnode-api >/dev/null 2>&1
  systemctl restart yingnode-api
  
  echo ""
  echo "✅ 部署大功告成！API 服务已成功运行在服务器的 5001 端口！"
EOF
