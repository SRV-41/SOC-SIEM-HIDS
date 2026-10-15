# SOC SIEM / HIDS — Self-Hosted Security Monitor

Лёгкий веб-дашборд для мониторинга безопасности Ubuntu-сервера. Собирает события из системных логов, автоматически блокирует атакующих через UFW, показывает геолокацию, интегрируется с fail2ban.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0+-green)
![SQLite](https://img.shields.io/badge/SQLite-3-lightblue)
![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%2B-orange)

## Возможности

- **Мониторинг в реальном времени** — события обновляются каждые 5 секунд
- **Автоблокировка** — IP автоматически блокируется через UFW при превышении порога угрозы
- **GeoIP** — геолокация атакующих через ip-api.com (без регистрации)
- **Исторические графики** — история атак за 24 часа
- **Статистика** — круговая диаграмма по типам атак
- **Персистентность** — данные сохраняются в SQLite, не теряются при перезапуске
- **Ручное управление** — блокировка/разблокировка IP через интерфейс
- **Белый список** — IP которые никогда не блокируются
- **Экспорт логов** — CSV за 24 часа или 7 дней
- **fail2ban интеграция** — показывает статус jail'ов
- **Rate limiting** — защита страницы входа от брутфорса

## Источники данных

| Лог | Что обнаруживает |
|-----|-----------------|
| `/var/log/auth.log` | SSH bruteforce, invalid user, BREAK-IN, sudo fail |
| `/var/log/ufw.log` | Заблокированные пакеты UFW |
| `/var/log/nginx/access.log` | SQL injection, XSS, Path traversal, LFI/RFI |
| `ss -tun` | Connection flood (10+ соединений с одного IP) |

## Система оценки угроз

| Тип события | Очки |
|-------------|------|
| SSH_BREAKIN | 10 |
| SQL_INJECTION / LFI_ATTEMPT | 9 |
| RFI_ATTEMPT | 9 |
| PATH_TRAVERSAL | 8 |
| XSS_ATTEMPT | 7 |
| SUDO_FAIL | 5 |
| SSH_INVALID_USER | 4 |
| SSH_FAIL | 3 |
| AUTH_FAIL | 2 |
| UFW_BLOCK / HTTP_5XX | 2 |
| HTTP_ERROR | 1 |

При достижении порога (по умолчанию 15 очков) IP автоматически блокируется.

## Требования

- Ubuntu 20.04+ (или любой Debian-based дистрибутив)
- Python 3.10+
- UFW
- fail2ban (опционально)

## Установка

### Автоматическая

```bash
git clone https://github.com/SRV-41/SOC-SIEM-HIDS.git
cd SOC-SIEM-HIDS
sudo bash install.sh
```

### Ручная

```bash
# 1. Клонируем
git clone https://github.com/SRV-41/SOC-SIEM-HIDS.git
cd SOC-SIEM-HIDS

# 2. Виртуальное окружение
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Конфигурация
cp .env.example .env
nano .env  # заполните значения

# 4. Права sudo
echo "$USER ALL=(ALL) NOPASSWD: /usr/sbin/ufw" | sudo tee /etc/sudoers.d/soc
echo "$USER ALL=(ALL) NOPASSWD: /usr/bin/fail2ban-client" | sudo tee -a /etc/sudoers.d/soc
sudo chmod 440 /etc/sudoers.d/soc

# 5. systemd сервис
sudo cp soc.service /etc/systemd/system/
# Замените YOUR_USER на ваше имя пользователя в soc.service
sudo systemctl daemon-reload
sudo systemctl enable soc
sudo systemctl start soc
```

## Конфигурация

Все параметры задаются через переменные окружения в файле `.env`:

```env
SOC_PORT=5050
SOC_USERNAME=admin
SOC_PASSWORD_HASH=<sha256 хэш пароля>
SOC_SECRET_KEY=<случайная строка>
SOC_BLOCK_THRESHOLD=15
SOC_UFW_BLOCKING=true
SOC_WHITELIST=192.168.1.1,10.0.0.1
```

### Генерация хэша пароля

```bash
python3 -c "import hashlib; print(hashlib.sha256(b'ВАШ_ПАРОЛЬ').hexdigest())"
```

## Структура проекта

```
SOC-SIEM-HIDS/
├── app.py              # Основное приложение
├── requirements.txt    # Python зависимости
├── .env.example        # Шаблон конфигурации
├── .gitignore
├── soc.service         # systemd unit файл
├── install.sh          # Скрипт автоустановки
└── README.md
```

## Интерфейс

Открыть в браузере: `http://IP_СЕРВЕРА:5050`

| Вкладка | Описание |
|---------|----------|
| 📊 Обзор | График атак, диаграмма типов, события, fail2ban |
| 🎯 Угрозы | Таблица IP с геолокацией и счётом угрозы, чёрный список |
| 📜 Журнал | Сырые логи с экспортом в CSV |
| ⚙️ Управление | Ручная блокировка, белый список |

## Безопасность

- Смените пароль по умолчанию перед первым запуском
- Добавьте свой IP в `SOC_WHITELIST` чтобы не заблокировать себя
- Рекомендуется закрыть порт 5050 для внешнего доступа через UFW и открыть только с нужных IP
- Для fail2ban интеграции нужен доступ к Unix-сокету `/var/run/fail2ban/fail2ban.sock`

## Лицензия

MIT
