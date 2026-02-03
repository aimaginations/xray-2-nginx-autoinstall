#!/bin/bash
# Скрипт запускается ПОД root
# Перед запуском:
#   export domain=moi-domen.mom
# или скрипт сам спросит домен

set -e

# --- Ввод домена и пользователя ---

if [ -z "$domain" ]; then
  read -p "Введите домен (например, moi-domen.mom): " domain
fi

read -p "Введите имя пользователя для сайта: " user

if ! id "$user" &>/dev/null; then
  echo "Пользователь $user не найден, создаю..."
  useradd -m -s /bin/bash "$user"
fi

USER_HOME=$(eval echo "~$user")
WEB_ROOT="$USER_HOME/www/$domain"

echo "Домен: $domain"
echo "Пользователь: $user"
echo "Каталог сайта: $WEB_ROOT"
mkdir -p "$WEB_ROOT"
chown -R "$user:$user" "$USER_HOME/www"

# --- Базовые пакеты ---

apt update
apt install -y curl wget nginx qrencode jq

# --- acme.sh и сертификаты ---

su - "$user" -c "curl https://get.acme.sh | sh"
ACME_HOME="$USER_HOME/.acme.sh"

su - "$user" -c "$ACME_HOME/acme.sh --upgrade --auto-upgrade"

# Выпуск сертификата через webroot = каталог сайта
su - "$user" -c "$ACME_HOME/acme.sh --issue --server letsencrypt -d $domain -w $WEB_ROOT --keylength ec-256 --force"

# Папка для сертификатов Xray
mkdir -p /usr/local/etc/xray/xray_cert/
chown -R root:root /usr/local/etc/xray
chmod 755 /usr/local/etc/xray

# Установка сертификата в xray_cert
su - "$user" -c "$ACME_HOME/acme.sh --install-cert -d $domain --ecc \
  --fullchain-file /usr/local/etc/xray/xray_cert/xray.crt \
  --key-file /usr/local/etc/xray/xray_cert/xray.key"

chmod +r /usr/local/etc/xray/xray_cert/xray.key

# --- Скрипт автообновления сертификата для Xray ---

cat << EOF > /usr/local/etc/xray/xray_cert/xray-cert-renew
#!/bin/bash
su - $user -c "$ACME_HOME/acme.sh --install-cert -d $domain --ecc \
  --fullchain-file /usr/local/etc/xray/xray_cert/xray.crt \
  --key-file /usr/local/etc/xray/xray_cert/xray.key"
chmod +r /usr/local/etc/xray/xray_cert/xray.key
systemctl restart xray
EOF

chmod +x /usr/local/etc/xray/xray_cert/xray-cert-renew

crontab -l 2>/dev/null | grep -q "xray-cert-renew" || (
  crontab -l 2>/dev/null
  echo "0 1 1 * *   bash /usr/local/etc/xray/xray_cert/xray-cert-renew"
) | crontab -

# --- Включаем BBR ---

bbr=$(sysctl -a 2>/dev/null | grep "net.ipv4.tcp_congestion_control = bbr" || true)
if [ -z "$bbr" ]; then
  echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  sysctl -p
fi

# --- Установка Xray ---

bash -c "$(curl -4 -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

[ -f /usr/local/etc/xray/.keys ] && rm /usr/local/etc/xray/.keys
touch /usr/local/etc/xray/.keys

shortsid=$(openssl rand -hex 8)
uuid=$(xray uuid)

echo "shortsid: $shortsid" >> /usr/local/etc/xray/.keys
echo "uuid: $uuid" >> /usr/local/etc/xray/.keys
echo "domain: $domain" >> /usr/local/etc/xray/.keys

# --- Конфиг Xray с PROXY protocol (xver: 1) ---

cat << EOF > /usr/local/etc/xray/config.json
{
  "dns": {
    "servers": [
      "https+local://1.1.1.1/dns-query",
      "localhost"
    ]
  },
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "domain": [
          "geosite:category-ads-all"
        ],
        "outboundTag": "block"
      }
    ]
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "email": "main",
            "id": "$uuid",
            "flow": "xtls-rprx-vision",
            "level": 0
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": 8080,
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "fingerprint": "chrome",
          "alpn": "http/1.1",
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/xray_cert/xray.crt",
              "keyFile": "/usr/local/etc/xray/xray_cert/xray.key"
            }
          ]
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ]
}
EOF

# --- Утилиты управления пользователями Xray ---

cat << 'EOF' > /usr/local/bin/userlist
#!/bin/bash
emails=($(jq -r '.inbounds[0].settings.clients[].email' "/usr/local/etc/xray/config.json"))
if [[ ${#emails[@]} -eq 0 ]]; then
  echo "Список клиентов пуст"
  exit 1
fi
echo "Список клиентов:"
for i in "${!emails[@]}"; do
  echo "$((i+1)). ${emails[$i]}"
done
EOF
chmod +x /usr/local/bin/userlist

cat << 'EOF' > /usr/local/bin/mainuser
#!/bin/bash
protocol=$(jq -r '.inbounds[0].protocol' /usr/local/etc/xray/config.json)
port=$(jq -r '.inbounds[0].port' /usr/local/etc/xray/config.json)
uuid=$(awk -F': ' '/uuid/ {print $2}' /usr/local/etc/xray/.keys)
domain=$(awk -F': ' '/domain/ {print $2}' /usr/local/etc/xray/.keys)
fp=$(jq -r '.inbounds[0].streamSettings.tlsSettings.fingerprint' /usr/local/etc/xray/config.json)
link="$protocol://$uuid@$domain:$port?security=tls&alpn=http%2F1.1&fp=$fp&spx=/&type=tcp&flow=xtls-rprx-vision&headerType=none&encryption=none#mainuser"
echo ""
echo "Ссылка для подключения:"
echo "$link"
echo ""
echo "QR-код:"
echo "$link" | qrencode -t ansiutf8
EOF
chmod +x /usr/local/bin/mainuser

cat << 'EOF' > /usr/local/bin/newuser
#!/bin/bash
read -p "Введите имя пользователя (email): " email
if [[ -z "$email" || "$email" == *" "* ]]; then
  echo "Имя пользователя не может быть пустым или содержать пробелы."
  exit 1
fi
user_json=$(jq --arg email "$email" '.inbounds[0].settings.clients[] | select(.email == $email)' /usr/local/etc/xray/config.json)
if [[ -z "$user_json" ]]; then
  uuid=$(xray uuid)
  jq --arg email "$email" --arg uuid "$uuid" '.inbounds[0].settings.clients += [{"email": $email, "id": $uuid, "flow": "xtls-rprx-vision"}]' /usr/local/etc/xray/config.json > tmp.json && mv tmp.json /usr/local/etc/xray/config.json
  systemctl restart xray
  index=$(jq --arg email "$email" '.inbounds[0].settings.clients | to_entries[] | select(.value.email == $email) | .key' /usr/local/etc/xray/config.json)
  protocol=$(jq -r '.inbounds[0].protocol' /usr/local/etc/xray/config.json)
  port=$(jq -r '.inbounds[0].port' /usr/local/etc/xray/config.json)
  uuid=$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].id' /usr/local/etc/xray/config.json)
  username=$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].email' /usr/local/etc/xray/config.json)
  domain=$(awk -F': ' '/domain/ {print $2}' /usr/local/etc/xray/.keys)
  fp=$(jq -r '.inbounds[0].streamSettings.tlsSettings.fingerprint' /usr/local/etc/xray/config.json)
  link="$protocol://$uuid@$domain:$port?security=tls&alpn=http%2F1.1&fp=$fp&spx=/&type=tcp&flow=xtls-rprx-vision&headerType=none&encryption=none#$username"
  echo ""
  echo "Ссылка для подключения:"
  echo "$link"
  echo ""
  echo "QR-код:"
  echo "$link" | qrencode -t ansiutf8
else
  echo "Пользователь с таким именем уже существует."
fi
EOF
chmod +x /usr/local/bin/newuser

cat << 'EOF' > /usr/local/bin/rmuser
#!/bin/bash
emails=($(jq -r '.inbounds[0].settings.clients[].email' "/usr/local/etc/xray/config.json"))
if [[ ${#emails[@]} -eq 0 ]]; then
  echo "Нет клиентов для удаления."
  exit 1
fi
echo "Список клиентов:"
for i in "${!emails[@]}"; do
  echo "$((i+1)). ${emails[$i]}"
done
read -p "Введите номер клиента для удаления: " choice
if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#emails[@]} )); then
  echo "Ошибка: номер должен быть от 1 до ${#emails[@]}"
  exit 1
fi
selected_email="${emails[$((choice - 1))]}"
jq --arg email "$selected_email" '(.inbounds[0].settings.clients) |= map(select(.email != $email))' "/usr/local/etc/xray/config.json" > tmp && mv tmp "/usr/local/etc/xray/config.json"
systemctl restart xray
echo "Клиент $selected_email удалён."
EOF
chmod +x /usr/local/bin/rmuser

cat << 'EOF' > /usr/local/bin/sharelink
#!/bin/bash
emails=($(jq -r '.inbounds[0].settings.clients[].email' /usr/local/etc/xray/config.json))
if [[ ${#emails[@]} -eq 0 ]]; then
  echo "Список клиентов пуст"
  exit 1
fi
for i in "${!emails[@]}"; do
  echo "$((i + 1)). ${emails[$i]}"
done
read -p "Выберите клиента: " client
if ! [[ "$client" =~ ^[0-9]+$ ]] || (( client < 1 || client > ${#emails[@]} )); then
  echo "Ошибка: номер должен быть от 1 до ${#emails[@]}"
  exit 1
fi
selected_email="${emails[$((client - 1))]}"
index=$(jq --arg email "$selected_email" '.inbounds[0].settings.clients | to_entries[] | select(.value.email == $email) | .key' /usr/local/etc/xray/config.json)
protocol=$(jq -r '.inbounds[0].protocol' /usr/local/etc/xray/config.json)
port=$(jq -r '.inbounds[0].port' /usr/local/etc/xray/config.json)
uuid=$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].id' /usr/local/etc/xray/config.json)
username=$(jq --argjson index "$index" -r '.inbounds[0].settings.clients[$index].email' /usr/local/etc/xray/config.json)
domain=$(awk -F': ' '/domain/ {print $2}' /usr/local/etc/xray/.keys)
fp=$(jq -r '.inbounds[0].streamSettings.tlsSettings.fingerprint' /usr/local/etc/xray/config.json)
link="$protocol://$uuid@$domain:$port?security=tls&alpn=http%2F1.1&fp=$fp&spx=/&type=tcp&flow=xtls-rprx-vision&headerType=none&encryption=none#$username"
echo ""
echo "Ссылка для подключения:"
echo "$link"
echo ""
echo "QR-код:"
echo "$link" | qrencode -t ansiutf8
EOF
chmod +x /usr/local/bin/sharelink

# --- Nginx: Xray → 127.0.0.1:8080 с PROXY protocol ---

cat << EOF > /etc/nginx/sites-available/default
server {
    listen 80;
    server_name $domain;
    return 301 https://\$host\$request_uri;
}

server {
    listen 127.0.0.1:8080 proxy_protocol;
    server_name $domain;

    real_ip_header proxy_protocol;
    set_real_ip_from 127.0.0.1;

    root $WEB_ROOT;
    index index.html;

    location / {
        try_files \$uri /index.html;
    }

    location /ip {
        default_type application/json;
        return 200 '{"ip":"\$remote_addr"}';
    }
}
EOF

# Простейшая стартовая страница
if [ ! -f "$WEB_ROOT/index.html" ]; then
  cat << EOF > "$WEB_ROOT/index.html"
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <title>$domain</title>
</head>
<body>
  <h1>Сайт для $domain</h1>
  <p>Текущий IP: <span id="ip">загрузка...</span></p>
  <script>
    fetch('/ip').then(r => r.json()).then(d => {
      document.getElementById('ip').textContent = d.ip;
    }).catch(() => {
      document.getElementById('ip').textContent = 'ошибка';
    });
  </script>
</body>
</html>
EOF
  chown "$user:$user" "$WEB_ROOT/index.html"
fi

nginx -t
systemctl restart nginx
systemctl restart xray

# --- Подсказка в $HOME/root ---

cat << EOF > ~/help_xray_nginx
Команды для управления пользователями Xray:

    mainuser  - ссылка основного пользователя
    newuser   - создать нового пользователя
    rmuser    - удалить пользователя
    sharelink - список пользователей и ссылки
    userlist  - список клиентов

Файл конфигурации Xray:

    /usr/local/etc/xray/config.json

Перезапуск Xray:

    systemctl restart xray

Перезапуск Nginx:

    systemctl restart nginx

Каталог сайта:

    $WEB_ROOT

EOF

echo "======================================="
echo "Установка завершена."
echo "Домен: $domain"
echo "Пользователь сайта: $user"
echo "Каталог сайта: $WEB_ROOT"
echo "Попробуй открыть: https://$domain"
echo "И проверь /ip и работу VPN."
echo "======================================="
mainuser
