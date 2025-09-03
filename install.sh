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

echo "✅ Installation finished!"
echo ""
echo "➡ To start the app, run:"
echo "cd $INSTALL_DIR && source venv/bin/activate && python manage.py runserver 0.0.0.0:8000"
echo ""
echo "🌐 Then visit: http://your-server-ip:8000"
