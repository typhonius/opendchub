#!/bin/bash

echo "This script will run a complete install of OpenDCHub, stunnel and associated software. Best run on a stock Ubuntu server but may work on pre-existing intallations. Hit Ctrl-C in the next 5 seconds to cancel install."

for i in {5..1} ; do
  echo $i;
  sleep 1;
done

echo "Starting installation"

command -v lsb_release > /dev/null 2>&1 || { 
  echo >&2 "Script configured for Ubuntu.  Aborting."
  exit 1
}

VERSION=`lsb_release -cs`
RELEASE=`lsb_release -rs | cut -d '.' -f1`

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root" 1>&2
  exit 1
fi

# Create the Hub user
getent passwd hub
if [ $? -eq 0 ]; then
  echo "Hub user already exists"
  exit 1
fi


echo "Creating hub user"
useradd hub -m -d /home/hub -s /bin/bash

# Prior to precise ubuntu used admin for the admin group.
adduser hub sudo
adduser hub admin

# Add hub to sudoers
echo "hub ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

echo "Updating OS"
apt-get update -y > /dev/null
apt-get install -y make gcc++ autoconf stunnel libperl-dev git curl openssl sudo expat libexpat1-dev sqlite3 libsqlite3-dev > /dev/null

#Install CPAN stuff
echo "Downloading CPAN, cpanimus and all bot prerequisites. This may take several minutes to complete."
curl -L http://cpanmin.us | perl - --self-upgrade > /dev/null
cpanm Clone Config::IniFiles Cwd DBI DBD::SQLite Data::Dumper DateTime DateTime::Duration DateTime::Format::Duration Exporter File::Basename FindBin HTTP::Request IPC::System::Simple JSON LWP::Simple LWP::UserAgent List::Util Log::Log4perl Mail::Sendmail Math::Round Module::Load Number::Bytes::Human Number::Format POSIX SQL::Abstract::Limit SQL::Abstract Scalar::Util Storable Switch Sys::Hostname Text::Tabs Time::HiRes WWW::TheMovieDB XML::Simple YAML YAML::AppConfig > /dev/null


# Configure stunnel by writing the CSR
"Generating PEM files for stunnel and creating the conf file"
cat > /etc/stunnel/stunnel.csr << "EOF"
FQDN = test.example.org
ORGNAME = DC Hub
ALTNAME = DNS:$FQDN
[ req ]
default_bits = 2048
prompt = no
encrypt_key = no
default_md = sha1
distinguished_name = dn
req_extensions = req_ext

[ dn ]
C = AU
O = $ORGNAME
CN = $FQDN

[ req_ext ]
subjectAltName = $ALTNAME
EOF

#Create the PEM file by openssl-ing the CSR. Permissions must be 600 on the pem
openssl req -new -x509 -days 365 -nodes -config /etc/stunnel/stunnel.csr -out /etc/stunnel/stunnel.pem -keyout /etc/stunnel/stunnel.pem
chmod 600 /etc/stunnel/stunnel.pem

#Create the conf file for stunnel
cat > /etc/stunnel/stunnel.conf << "EOF"
cert = /etc/stunnel/stunnel.pem
key = /etc/stunnel/stunnel.pem
debug = 4
output = stunnel.log
;ciphers = AES128-SHA:AES256-SHA:DHE-DSS-AES128-SHA:DHE-DSS-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA
;sslVersion = all
;options = NO_SSLv2
;options = NO_SSLv3
;options = NO_TLSv1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
;fips = no

[DC]
accept = 7659
connect = 8145

[DC2]
accept = 7660
connect = 8145

TIMEOUTclose = 0
EOF

echo "Starting stunnel"
stunnel4

# Assume su of the user, download then install ODCH.
echo "Downloading and installing ODCH"
cd /home/hub
su hub -c 'git clone https://github.com/odchbot/opendchub' && cd /home/hub/opendchub
su hub -c 'tar zxf opendchub.tar.gz' && cd opendchub
su hub -c './configure > /dev/null'
su hub -c 'make > /dev/null'
su hub -c 'sudo make install'

#We'll need to IP of the server for the ODCH config file
HOST_IP=`ifconfig | egrep "inet addr:(.*)  Bcast" | awk {'print $2'} | cut -d ':' -f 2-`

echo "Writing out ODCH config prior to starting"
cat > /home/hub/.opendchub/config << "EOF"
hub_name = "Open DC Hub"

max_users = 1000

hub_full_mess = "Sorry, this hub is full at the moment"

hub_description = "A Unix/Linux Direct Connect Hub"

min_share = 0

admin_pass = "woqdiewfue"

default_pass = ""

link_pass = "idmwqofuhewqf"

users_per_fork = 1000

listening_port = 8145

admin_port = 53696

admin_localhost = 0

hublist_upload = 1

public_hub_host = "example.org"

hub_hostname = "$HOST_IP"

min_version = ""

redirect_host = ""

registered_only = 0

check_key = 0

reverse_dns = 0

ban_overrides_allow = 0

verbosity = 4

redir_on_min_share = 1

syslog_enable = 0

searchcheck_exclude_internal = 1

searchcheck_exclude_all = 0

kick_bantime = 5

searchspam_time = 5

max_email_len = 50

max_desc_len = 100

crypt_enable = 1

EOF

#Take the terminal to the correct ODCH directory, remove the default scripts directory and clone the CB repo before starting ODCH
echo "Removing default scripts dir and downloading the bot repo"
rm -rf /home/hub/.opendchub/scripts
git clone -b v3 https://github.com/odchbot/odchbot.git /home/hub/.opendchub/scripts
cp /home/hub/.opendchub/scripts/odchbot.yml.example /home/hub/.opendchub/scripts/odchbot.yml
chown -R hub. /home/hub/.opendchub
su hub -c 'opendchub'

#Adding default nick:pass to the reglist
echo "Adding default nickname and password to the reglist - use 'nick' as the nickname and 'pass' as the password"
echo 'nick $1$vpW4FsNG$ObxMyxwPZ7617qvy8WxCS. 2' | tee /home/hub/.opendchub/reglist

echo "Your users will be able to connect directly to OpenDCHub using $HOST_IP:8145 or via stunnel by adding the following line to their own stunnel.conf and then connecting to localhost:8008"
echo "[ODCH]"
echo "accept = 8008"
echo "connect = $HOST_IP:7659"


