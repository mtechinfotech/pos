#!/bin/sh
set -e

OUTPUT=$(cat /etc/*release)

# --- Detect OS ---
if echo $OUTPUT | grep -q "Ubuntu 18.04" ; then
    apt update -y && apt install -y -qq wget curl git python3 python3-pip python3-venv mariadb-server
    SERVER_OS="Ubuntu"
elif echo $OUTPUT | grep -q "Ubuntu 20.04" ; then
    apt update -y && apt install -y -qq wget curl git python3 python3-pip python3-venv mariadb-server
    SERVER_OS="Ubuntu"
elif echo $OUTPUT | grep -q "Ubuntu 22.04" ; then
    apt update -y && apt install -y -qq wget curl git python3 python3-pip python3-venv mariadb-server
    SERVER_OS="Ubuntu"
elif echo $OUTPUT | grep -q "CentOS Linux 7" ; then
    yum install -y curl wget git python3 python3-pip python3-venv mariadb-server
    SERVER_OS="CentOS7"
elif echo $OUTPUT | grep -q "CentOS Linux 8" ; then
    yum install -y curl wget git python3 python3-pip python3-venv mariadb-server
    SERVER_OS="CentOS8"
else
    echo -e "\n❌ Unsupported OS"
    echo -e "\nSupported: Ubuntu 18.04/20.04/22.04, CentOS 7/8\n"
    exit 1
fi

echo "✅ Detected $SERVER_OS"

# --- Install POS from GitHub ---
INSTALL_DIR="/usr/local/pos"

if [ ! -d "$INSTALL_DIR" ]; then
    echo "📂 Cloning repository..."
    git clone https://github.com/mtechinfotech/pos.git $INSTALL_DIR
else
    echo "🔄 Updating repository..."
    cd $INSTALL_DIR && git pull
fi

cd $INSTALL_DIR

# --- Python Virtual Environment ---
if [ ! -d "venv" ]; then
    echo "🐍 Creating Python virtual environment..."
    python3 -m venv venv
fi

. venv/bin/activate
pip install --upgrade pip

if [ -f "requirements.txt" ]; then
    echo "📦 Installing Python dependencies..."
    pip install -r requirements.txt
fi

# --- Database (Django assumed) ---
if [ -f "manage.py" ]; then
    echo "🗂 Running Django migrations..."
    python manage.py migrate
    python manage.py collectstatic --noinput || true
fi

# --- Setup systemd service for auto-start ---
SERVICE_FILE="/etc/systemd/system/pos.service"

echo "🛠 Creating systemd service for auto-start..."

cat > $SERVICE_FILE <<EOL
[Unit]
Description=MTech POS Service
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python manage.py runserver 0.0.0.0:8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd and enable service
systemctl daemon-reload
systemctl enable pos
systemctl start pos

echo "✅ POS installation & service setup completed!"
echo ""
echo "🌐 Your app is running and will auto-start on reboot."
echo "➡ To check status: systemctl status pos"
echo "➡ To see logs: journalctl -u pos -f"
echo "➡ Visit: http://your-server-ip:8000"
