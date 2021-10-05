#!/usr/bin/env bash

#**************************************************************************#
#  Filename: prepare.sh                   (Created: 2020-08-23)            #
#                                         (Updated: YYYY-MM-DD)            #
#  Info:                                                                   #
#    Prepares machine for CTFd. Running with gunicorn under the            #
#       ctfd user and using nginx as a proxy for HTTPs                     #
#  Author:                                                                 #
#    Ryan Hays                                                             #
#                                                                          #
#  Tested on:                                                              #
#    Ubuntu 20.10                                                          #
#    Ubuntu 21.04                                                          #
#**************************************************************************#


# Setup a log file to catch all output
exec > >(tee -ia /root/ctfd_build_log.log)
exec 2> >(tee -ia /root/ctfd_build_err_log.log)


##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal


##### Setup some global vars
STAGE=0
TOTAL=$(grep '(${STAGE}/${TOTAL})' $0 | wc -l);(( TOTAL-- ))
STARTTIME=$(date +%s)
HOSTNAME=$(cat /etc/hostname)


##### PRE CHECKS #####
##### Check if we are running as root - else this script will fail (hard!)
if [[ "${EUID}" -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" This script must be ${RED}run as root${RESET}" 1>&2
  echo -e ' '${RED}'[!]'${RESET}" Quitting..." 1>&2
  sleep 10
  exit 1
else
  echo -e " ${BLUE}[*]${RESET} ${BOLD}CTFd Build Script${RESET}"
  sleep 3
fi

##### Fix display output for GUI programs (when connecting via SSH)
export DISPLAY=:0.0
export TERM=xterm

##### Change nameserver
echo 'nameserver 1.1.1.1' > /etc/resolv.conf

##### Check Internet access
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Checking ${GREEN}Internet access${RESET}"
#--- Can we ping google?
for i in {1..10}; do ping -c 1 -W ${i} www.google.com &>/dev/null && break; done
#--- Run this, if we can't
if [[ "$?" -ne 0 ]]; then
  echo -e ' '${RED}'[!]'${RESET}" ${RED}Possible DNS issues${RESET}(?)" 1>&2
  echo -e ' '${RED}'[!]'${RESET}" Will try and use ${YELLOW}DHCP${RESET} to 'fix' the issue" 1>&2
  chattr -i /etc/resolv.conf 2>/dev/null
  dhclient -r
  #--- Second interface causing issues?
  ip addr show eth1 &>/dev/null
  [[ "$?" == 0 ]] \
    && route delete default gw 192.168.155.1 2>/dev/null
  #--- Request a new IP
  dhclient
  dhclient eth0 2>/dev/null
  dhclient wlan0 2>/dev/null
  dhclient eth1 2>/dev/null
  #--- Wait and see what happens
  sleep 15s
  _TMP="true"
  _CMD="$(ping -c 1 8.8.8.8 &>/dev/null)"
  if [[ "$?" -ne 0 && "$_TMP" == "true" ]]; then
    _TMP="false"
    echo -e ' '${RED}'[!]'${RESET}" ${RED}No Internet access${RESET}" 1>&2
    echo -e ' '${RED}'[!]'${RESET}" You will need to manually fix the issue, before re-running this script" 1>&2
    sleep 10
    exit 1
  fi
  _CMD="$(ping -c 1 www.google.com &>/dev/null)"
  if [[ "$?" -ne 0 && "$_TMP" == "true" ]]; then
    _TMP="false"
    echo -e ' '${RED}'[!]'${RESET}" ${RED}Possible DNS issues${RESET}(?)" 1>&2
    echo -e ' '${RED}'[!]'${RESET}" You will need to manually fix the issue, before re-running this script" 1>&2
    sleep 10
    exit 1
  fi
  if [[ "$_TMP" == "false" ]]; then
    (dmidecode | grep -iq virtual) && echo -e " ${YELLOW}[i]${RESET} VM Detected"
    (dmidecode | grep -iq virtual) && echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Try switching network adapter mode${RESET} (e.g. NAT/Bridged)"
    echo -e ' '${RED}'[!]'${RESET}" Quitting..." 1>&2
    sleep 10
    exit 1
  fi
else
  echo -e " ${YELLOW}[i]${RESET} ${YELLOW}Detected Internet access${RESET}" 1>&2
fi


##### Main Setup #####
##### Update System
# This is not being quite
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Updating ${GREEN}System${RESET}"
apt-get -y -qq update \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
apt-get -y -qq upgrade \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
apt-get -y -qq dist-upgrade \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2
apt-get -y -qq autoremove \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} 1>&2

##### Installing Packages
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}Packages${RESET}"
apt-get -y -qq -o Dpkg::Use-Pty=0 install build-essential libffi-dev python3-pip gunicorn nginx git vim certbot python3-certbot-nginx unzip \
|| echo -e ' '${RED}'[!] Issue with apt install'${RESET} &>/dev/null

##### Adding CTFd user
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Adding ${GREEN}CTFd user${RESET}"
useradd ctfd
mkdir /var/log/CTFd
mkdir -p /home/ctfd
mkdir -p /home/ctfd/CTFd/ctfd_uploads

##### Installing CTFd
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Installing ${GREEN}CTFd${RESET}"
git clone -q -b master https://github.com/MrJester/CTFd.git /home/ctfd/CTFd \
|| echo -e ' '${RED}'[!] Issue when git cloning'${RESET} &>/dev/null
chown -R ctfd. /var/log/CTFd /home/ctfd/CTFd
pushd /home/ctfd/CTFd &>/dev/null
git pull -q
pip3 -q install -r requirements.txt &> /dev/null

cat >> /etc/systemd/system/ctfd.service << EOF
[Unit]
Description = CTFd
After = network.target
[Service]
PermissionsStartOnly = true
PIDFile = /run/CTFd.pid
User = ctfd
Group = ctfd
WorkingDirectory = /home/ctfd/CTFd
ExecStartPre = /bin/mkdir -p /run/CTFd
ExecStartPre = /bin/chown -R ctfd. /run/CTFd
ExecStart = /usr/bin/gunicorn 'CTFd:create_app()' --bind '0.0.0.0:8000' --workers 2 --worker-class 'gevent' --pid /run/CTFd/CTFd.pid --access-logfile "/var/log/CTFd/access.log" --error-logfile "/var/log/CTFd/error.log"
ExecReload = /bin/kill -s HUP $MAINPID
ExecStop = /bin/kill -s TERM $MAINPID
PrivateTmp = true
[Install]
WantedBy = multi-user.target
EOF

systemctl daemon-reload &> /dev/null
systemctl enable ctfd &> /dev/null
systemctl start ctfd &> /dev/null

##### Configuring nginx
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) Configuring ${GREEN}nginx${RESET}"
systemctl stop nginx &> /dev/null
cat >> /etc/nginx/sites-available/$HOSTNAME << EOF
server {
        listen 443 ssl;
        ssl_certificate     /etc/letsencrypt/live/$HOSTNAME/cert.pem;
        ssl_certificate_key /etc/letsencrypt/live/$HOSTNAME/privkey.pem;
        ssl_protocols       TLSv1.1 TLSv1.2;
        ssl_ciphers         ECDHE-ECDSA-CHACHA20-POLY1305:ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:!AES256-GCM-SHA256:!AES256-GCM-SHA128:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        server_name $HOSTNAME;
        location / {
                proxy_pass http://$HOSTNAME:8000;
        }
}
EOF

certbot certonly --standalone -n -d $HOSTNAME -m webmaster@$HOSTNAME --agree-tos &> /dev/null
ln -s /etc/nginx/sites-available/$HOSTNAME /etc/nginx/sites-enabled/ &> /dev/null
systemctl enable nginx &> /dev/null
systemctl start nginx &> /dev/null


##### CLEANUP #####
##### Clean the system
(( STAGE++ )); echo -e "\n\n ${GREEN}[+]${RESET} (${STAGE}/${TOTAL}) ${GREEN}Cleaning${RESET} the system"
#--- Clean package manager
for FILE in clean autoremove; do apt-get -y -qq "${FILE}"; done
apt-get -y -qq purge $(dpkg -l | tail -n +6 | egrep -v '^(h|i)i' | awk '{print $2}')   # Purged packages
#--- Reset folder location
cd ~/ &>/dev/null
#--- Remove any history files (as they could contain sensitive info)
history -c 2>/dev/null
for i in $(cut -d: -f6 /etc/passwd | sort -u); do
[ -e "${i}" ] && find "${i}" -type f -name '.*_history' -delete
done

##### Time taken
FINISHTIME=$(date +%s)
echo -e "\n\n ${YELLOW}[i]${RESET} Time (roughly) taken: ${YELLOW}$(( $(( FINISHTIME - STARTTIME )) / 60 )) minutes${RESET}"

echo -e "\n\n ${YELLOW}[i]${RESET} Please reboot the system now to ensure all changes are taken. ${YELLOW}${RESET}"
