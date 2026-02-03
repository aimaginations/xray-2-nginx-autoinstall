#!/bin/bash
# Скрипт запускается ПОД root
# Автоматическая установка Xray + nginx + PROXY protocol
# Сайт создаётся в /home/$USER/www/$domain

set -e

# --- Ввод домена и пользователя ---

read -p "Введите домен (например, moi-domen.mom): " domain_raw
read -p "Введите имя пользователя для сайта: " user

# --- Фильтрация домена от мусора (русские буквы, пробелы, невидимые символы) ---
domain=$(echo "$domain_raw" | tr -cd 'a-zA-Z0-9.-')

if [[ -z "$domain" ]]; then
  echo "Ошибка: домен пуст или содержит недопустимые символы."
  exit 1
fi

echo "Используем домен: $domain"

# --- Создание пользователя, если нет ---
if ! id "$user" &>/dev/null; then
  echo "Пользователь $user не найден, создаю..."
  useradd -m -s /bin/bash "$user"
fi

USER_HOME=$(eval echo "~$user")
WEB_ROOT="$USER_HOME/www/$domain"

echo "Каталог сайта: $WEB_ROOT"
mkdir -p "$WEB_ROOT"
chown -R "$user:$user" "$USER_HOME/www"

# --- Базовые пакеты ---
apt update
apt install -y curl wget nginx qrencode jq

# --- ВРЕМЕННЫЙ nginx ДЛЯ ВЫПУСКА СЕРТИФИКАТА ---
cat << EOF > /etc/nginx/sites-available/default
server {
    listen 80;
    server_name $domain;

    root $WEB_ROOT;
}
EOF

nginx -t
systemctl restart nginx

# --- acme.sh и сертификаты ---
su - "$user" -c "curl https://get.acme.sh | sh"
ACME_HOME="$USER_HOME/.acme.sh"

su - "$user" -c "$ACME_HOME/acme.sh --upgrade --auto-upgrade"

# --- Создаём папку для сертификатов ДО установки ---
mkdir -p /usr/local/etc/xray/xray_cert/
chmod 755 /usr/local/etc/xray/xray_cert

# --- Выпуск сертификата ---
su - "$user" -c "$ACME_HOME/acme.sh --issue --server letsencrypt -d $domain -w $WEB_ROOT --keylength ec-256 --force"

# --- Установка сертификата ---
su - "$user" -c "$ACME_HOME/acme.sh --install-cert -d $domain --ecc \
  --fullchain-file /usr/local/etc/xray/xray_cert/xray.crt \
  --key-file /usr/local/etc/xray/xray_cert/xray.key"

chmod +r /usr/local/etc/xray/xray_cert/xray.key

# --- Скрипт автообновления сертификата ---
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

# --- Конфиг Xray ---
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

# --- Основной nginx с PROXY protocol ---
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

nginx -t
systemctl restart nginx
systemctl restart xray

echo "======================================="
echo "Установка завершена."
echo "Домен: $domain"
echo "Пользователь сайта: $user"
echo "Каталог сайта: $WEB_ROOT"
echo "Открой: https://$domain"
echo "======================================="
