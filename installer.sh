#!/usr/bin/env bash

# Check if root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Random password generator
random_password()
{
    cat /dev/urandom | tr -dc "a-zA-Z0-9\!@#\$^&*_+><~" | fold -w 32 | head -n 1
}

DEBIAN_FRONTEND=noninteractive

read -p "What domain are you using? " DOMAIN
read -p "What email address to use for SSL? " EMAIL
read -p "Digital Ocean API token? " API_TOKEN
read -p "Email username? " EMAIL_USER
read -p "Email password? " EMAIL_PASS

apt-get update
apt-get dist-upgrade -y
apt-get install -y ca-certificates wget git bc

# Add nginx and postgres repositories
echo "deb http://apt.postgresql.org/pub/repos/apt/ $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list
# echo "deb http://nginx.org/packages/mainline/ubuntu/ $(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
add-apt-repository -y ppa:nginx/development

wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -
#wget --quiet -O - http://nginx.org/keys/nginx_signing.key | apt-key add -

# Preseed packages
#echo "postgresql-common postgresql-common/obsolete-major error" | /usr/bin/debconf-set-selections
#echo "postgresql-common postgresql-common/catversion-bump note" | /usr/bin/debconf-set-selections
echo "postgresql-common postgresql-common/ssl boolean true" | /usr/bin/debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | /usr/bin/debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | /usr/bin/debconf-set-selections

# Install packages
apt-get update
apt-get install -y postgresql-9.5 nginx python3 python3-dev python3-pip redis-server libpq-dev

pip3 install -r /opt/portplow/requirements.txt

useradd -r portplow -d /opt/portplow

mkdir -p /etc/circus
ln -s /opt/portplow/configs/etc/circus/circus.ini /etc/circus/

cp /opt/portplow/configs/etc/init/portplow.conf /etc/init/

# Nginx configuration
rm /etc/nginx/sites-enabled/default
ln -s /opt/portplow/configs/etc/nginx/sites-available/default /etc/nginx/sites-enabled/portplow

# Copy the config template over
cp /opt/portplow/configs/portplow.conf.default ~portplow/.portplow.conf

# Make sure the portplow user has access.
chown -R portplow:www-data /opt/portplow/

# Setup SSL encryption
openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
git clone https://github.com/letsencrypt/letsencrypt /opt/letsencrypt
cd /opt/letsencrypt
./letsencrypt-auto certonly -a webroot --webroot-path=/var/www/html -d $DOMAIN  --email $EMAIL --agree-tos

SECRET_KEY=$(random_password)
DB_PASS=$(random_password)
PUB_IP=$(dig +short myip.opendns.com @resolver1.opendns.com)

# Replace variables in the configuration file.
PORTPLOW_CONFIG=/opt/portplow/.portplow.conf
sed -i "s/--api-token--/$API_TOKEN/" /opt/portplow/.portplow.conf
sed -i "s/--public-ip--/$PUB_IP/g" /opt/portplow/.portplow.conf
sed -i "s/--domain--/$DOMAIN/g" /opt/portplow/.portplow.conf
sed -i "s/--api-token--/$TOKEN/g" /opt/portplow/.portplow.conf
sed -i "s/--email-user--/$EMAIL_USER/g" /opt/portplow/.portplow.conf
sed -i "s/--email-pass--/$EMAIL_PASS/g" /opt/portplow/.portplow.conf
sed -i "s/--db-pass--/$DB_PASS/g" /opt/portplow/.portplow.conf
sed -i "s/--secret-key--/$SECRET_KEY/g" /opt/portplow/.portplow.conf
sed -i "s/--domain--/$DOMAIN/g" /opt/portplow/configs/etc/nginx/sites-available/default

# Add database and user
sudo -u postgres bash -c "psql -c \"CREATE USER portplow WITH PASSWORD '$DB_PASS';\""
sudo -u postgres createdb -O portplow portplow

service nginx restart
service postgresql restart
service portplow restart

cd /opt/portplow
sudo -H -u portplow ./manage.py collectstatic --no-input
sudo -H -u portplow ./manage.py migrate

echo "Make sure you update the settings in ~portplow/.portplow.conf"
echo "After making changes, restart the portplow service with 'service portplow restart'"
