#!/bin/bash
# SOC SIEM — скрипт установки
# Использование: sudo bash install.sh

set -e

SOC_DIR="/opt/soc"
SOC_USER=$(whoami)

echo "=== SOC SIEM Installer ==="
echo "Установка в: $SOC_DIR"
echo "Пользователь: $SOC_USER"
echo ""

# Зависимости
echo "[1/6] Установка системных зависимостей..."
apt-get update -qq
apt-get install -y python3 python3-venv python3-pip ufw fail2ban

# Создаём директорию
echo "[2/6] Создание директории..."
mkdir -p "$SOC_DIR"
cp app.py "$SOC_DIR/"
cp .env.example "$SOC_DIR/.env"

# Python окружение
echo "[3/6] Создание виртуального окружения..."
python3 -m venv "$SOC_DIR/venv"
"$SOC_DIR/venv/bin/pip" install --quiet -r requirements.txt

# Права sudo для ufw и fail2ban
echo "[4/6] Настройка sudo..."
cat > /etc/sudoers.d/soc << EOF
$SOC_USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw
$SOC_USER ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client
EOF
chmod 440 /etc/sudoers.d/soc

# systemd сервис
echo "[5/6] Установка systemd сервиса..."
sed "s/YOUR_USER/$SOC_USER/g" soc.service > /etc/systemd/system/soc.service
systemctl daemon-reload
systemctl enable soc

echo ""
echo "=== Установка завершена ==="
echo ""
echo "ВАЖНО: Перед запуском настройте /opt/soc/.env:"
echo "  1. Задайте SOC_PASSWORD_HASH (хэш вашего пароля)"
echo "  2. Задайте SOC_SECRET_KEY (случайную строку)"
echo "  3. Добавьте свой IP в SOC_WHITELIST"
echo ""
echo "Сгенерировать хэш пароля:"
echo "  python3 -c \"import hashlib; print(hashlib.sha256(b'ВАШ_ПАРОЛЬ').hexdigest())\""
echo ""
echo "[6/6] Запуск:"
echo "  sudo systemctl start soc"
echo "  sudo systemctl status soc"
