#!/bin/bash

mkdir -p /opt/portplow
mkdir -p /var/opt/portplow

# Set timezone to UTC
rm /etc/localtime
ln -s /usr/share/zoneinfo/UTC /etc/localtime

DEBIAN_FRONTEND=noninteractive

# Make alias to metadata storage endpoint
# http://169.254.169.254/metadata/v1/
echo "169.254.169.254 infoinfo" >> /etc/hosts

# Allow IPTables-Persistent to install automatically
echo "iptables-persistent	iptables-persistent/autosave_v4	boolean	true" | /usr/bin/debconf-set-selections
echo "iptables-persistent	iptables-persistent/autosave_v6	boolean	true" | /usr/bin/debconf-set-selections

apt-get update
apt-get dist-upgrade -y

apt-get install -y git gcc make libpcap-dev nmap python3-pip tmux python3-dev supervisor python3 nginx iptables-persistent

# Install masscan
git clone https://github.com/robertdavidgraham/masscan.git /opt/portplow/masscan
cd /opt/portplow/masscan/
make -j

# Setup environment for client
pip3 install requests coloredlogs

echo -n {{CLIENT_SCRIPT}} | base64 -d > /opt/portplow/client.py

cat >/etc/supervisor/conf.d/portplow-client.conf <<"EOF"
[program:portplow]
command=/usr/bin/python /opt/portplow/client.py
startretries=10
autorestart=true
environment=PORTPLOW_URL="{{SERVICE_URL}}",PORTPLOW_TOKEN="{{API_TOKEN}}",PORTPLOW_DELAY="{{DELAY}}",PORTPLOW_DIR="{{DIR}}"
EOF

cat >/opt/portplow/envsettings <<"EOF"
export PORTPLOW_URL="{{SERVICE_URL}}"
export PORTPLOW_TOKEN="{{API_TOKEN}}"
export PORTPLOW_DELAY="{{DELAY}}"
export PORTPLOW_DIR="{{DIR}}"
EOF

cat >/etc/nginx/sites-enabled/default <<"EOF"
server {
    listen 80 default_server;
    listen [::]:80 default_server ipv6only=on;

    root /var/www/html;
    index index.html index.htm;

    server_name localhost;

    location / {
        try_files $uri $uri/ =404;
        # auth_basic "Restricted Content";
        # auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
EOF

mkdir -p /var/www/html
cat >/var/www/html/index.html <<"EOF"
{{SEC_MESSAGE}}
EOF

chown -R www:www -R /var/www/

# IP Tables setup
NETWORKS="{{NETWORKS}} 127.0.0.0/8 196.227.250.250/32"
/sbin/iptables -F

for net in $NETWORKS
do
    /sbin/iptables -A INPUT -p tcp --dport 80 -s $net -j ACCEPT
done
/sbin/iptables -A INPUT -p tcp --dport 80 -j DROP

/etc/init.d/iptables-persistent save

# Create cron job to update security message
cat >/usr/bin/update_sec_message <<"EOF"
curl -L {{DECONFLICTION_URL}} > /var/www/html/index.html
chmod +r /var/www/html/index.html
EOF

chmod +x /usr/bin/update_sec_message

/usr/bin/update_sec_message

# Add job update to crontab
line="0,30 * * * * /usr/bin/update_sec_message"
(crontab -u root -l; echo "$line" ) | crontab -u root -

reboot