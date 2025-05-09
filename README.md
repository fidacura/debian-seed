# debian-seed

A guide to setting up and maintaining a Debian VPS—secure, robust, and production-ready.

1. **Basic Server Configuration**

2. **Security Hardening**

3. **Web Server Setup**

4. **Monitoring**

5. **Server Maintenance**

6. **Data Backups**

7. **Upgrade Process**

8. **Bootstraps**

<br/>
<br/>

# 1. Basic server configuration

Basic Linux configurations to use in all VPS instances.

### System update && upgrade

```console
apt update && apt upgrade
```

### Hostname change

```console
hostnamectl set-hostname "hostname"
```

### Update /etc/hosts

```console
echo "hostname" > /etc/hostname
hostname -F /etc/hostname
```

### Timezone setup

```console
dpkg-reconfigure tzdata
date
```

### New user

```
adduser "username"
```

### Sudo

```console
apt install sudo
usermod -a -G sudo "username"
```

### Fish

A modern, easy-going, and powerful shell.

```console
sudo apt install fish
sudo chsh -s /usr/bin/fish
```

### Reboot

```console
sudo shutdown -r now
```

<br/>
<br/>

# 2. Hardening

Basic hardening configurations to use in all VPS instances.

## SSH hardening and daemon configuration

On the server:

```console
mkdir -p ~/.ssh/ && sudo chmod -R 700 ~/.ssh/
sudo chmod 700 -R ~/.ssh && chmod 600 ~/.ssh/authorized_keys
```

On local machine:

```console
scp ~/.ssh/id_rsa.pub username@vpsipaddress:~/.ssh/authorized_keys
```

File: /etc/ssh/sshd_config

```console
# Authentication reforce
PermitRootLogin no
PasswordAuthentication no

# Listen on only on IPv4
AddressFamily inet
```

Restart SSH

```console
sudo systemctl restart sshd
```

## Fail2ban

Simple intrusion prevention software.

```console
apt install fail2ban
```

Configure:

```console
cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

Lets configure jail.local with optimized settings:

sudo nano /etc/fail2ban/jail.local

```console
[DEFAULT]
# Base settings with progressive banning
bantime  = 24h        # Initial ban duration
findtime = 15m        # Detection window
maxretry = 2         # Failures allowed before ban

# Progressive ban system for repeat offenders
bantime.increment = true
bantime.multipliers = 1 3 6 12 24 48
bantime.maxtime = 4w
bantime.factor = 1

# Basic security settings
ignoreip = 127.0.0.1/8 ::1
backend = auto
usedns = warn
banaction = iptables-multiport
protocol = tcp
chain = INPUT

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 2
findtime = 10m
bantime = 48h

[nginx-badhosts]
enabled = true
port = http,https
filter = nginx-badhosts
logpath = /var/log/nginx/error.log
maxretry = 3
findtime = 15m
bantime = 24h
```

Then create a custom filter for nginx SSL issues:

```console
sudo nano /etc/fail2ban/filter.d/nginx-badhosts.conf
```

```console
[Definition]
failregex = SSL_do_handshake\(\) failed .* client: <HOST>
ignoreregex =
```

Adding a verification section:

```console
sudo systemctl restart fail2ban
sudo systemctl status fail2ban
sudo fail2ban-client status
sudo fail2ban-client status sshd
sudo fail2ban-client status nginx-badhosts
```

Test the nginx filter against logs:

```console
sudo fail2ban-regex /var/log/nginx/error.log /etc/fail2ban/filter.d/nginx-badhosts.conf
```

Monitor fail2ban activity:

```
sudo tail -f /var/log/fail2ban.log
```

Check currently banned IPs:

```
sudo fail2ban-client get sshd banned
sudo fail2ban-client get nginx-badhosts banned
```

## Crowdsec

Modern, collaborative security engine that works alongside fail2ban.

#### Installation

```console
# Add Crowdsec repository
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash

# Install Crowdsec with nginx collection
sudo apt install crowdsec
sudo apt install crowdsec-nginx-bouncer

# Initial setup
sudo cscli hub update
sudo cscli collections install crowdsecurity/nginx
sudo cscli collections install crowdsecurity/linux
sudo cscli collections install crowdsecurity/http-cve
```

Create parsers configuration:

```console
sudo nano /etc/crowdsec/acquis.yaml
```

```console
filenames:
  - /var/log/nginx/access.log
  - /var/log/nginx/error.log
labels:
  type: nginx
```

Configure Nginx Bouncer:

```console
sudo nano /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf
```

```console
api_key: # Will be automatically populated
ban_time: 1h
ban_mode: http-403
include_scenarios:
  - crowdsecurity/http-probing
  - crowdsecurity/http-bad-user-agent
  - crowdsecurity/nginx-http-bad-user-agent
  - crowdsecurity/http-crawl-non_statics
  - crowdsecurity/http-path-traversal-probing
```

Configure Nginx for Crowdsec:

```console
sudo nano /etc/nginx/conf.d/crowdsec_nginx.conf
```

```console
load_module /usr/lib/nginx/modules/ngx_http_crowdsec_module.so;

http {
    crowdsec_instance {
        path /var/run/crowdsec/crowdsec-nginx-bouncer.sock;
    }
    # ... rest of your http configuration
}
```

Start Services

```console
# Restart services to apply changes
sudo systemctl restart crowdsec
sudo systemctl restart nginx
sudo systemctl enable crowdsec

# Verify services
sudo systemctl status crowdsec
sudo cscli hub list
```

Basic Commands

```console
# Check Crowdsec status
sudo cscli metrics

# List current bans
sudo cscli decisions list

# List active scenarios
sudo cscli scenarios list

# List bouncers
sudo cscli bouncers list

# Check real-time logs
sudo journalctl -f -u crowdsec

# Add IP to whitelist
sudo cscli decisions add --ip X.X.X.X --duration 168h --type whitelist

# Remove IP from bans
sudo cscli decisions delete --ip X.X.X.X
```

Maintenance: daily tasks

```console
# Update hub collections
sudo cscli hub update

# Check for outdated scenarios
sudo cscli scenarios list -o

# Review metrics
sudo cscli metrics

# Review current decisions
sudo cscli decisions list

# Check bouncer status
sudo cscli bouncers list
```

Maintenance: weekly checks

```console
# Full database cleanup
sudo cscli database cleanup

# Update all collections
sudo cscli collections upgrade

# Check configuration validity
sudo crowdsec -c /etc/crowdsec/config.yaml -t

```

#### Integration with fail2ban

Crowdsec can work alongside fail2ban. Configure fail2ban to respect Crowdsec's decisions:

`````console
sudo nano /etc/fail2ban/jail.local
```
Add to [DEFAULT] section:
````console
ignoreip = 127.0.0.1/8 ::1 # Add your IPs and Crowdsec's IP range if used
```

### Rootkit protection

Rkhunter and chkrootkit:

```console
sudo apt install rkhunter
sudo rkhunter --propupd
sudo rkhunter --check
sudo apt install chkrootkit
`````

## Firewall

Always iptables: Minimal configuration; Easygoing; Effective.

```console
sudo iptables -L
sudo apt install iptables-persistent
sudo nano /etc/iptables/rules.v4
```

iptables file [ [download here](https://github.com/fidacura/Debian9000//) ]:

```console
*filter
# Allow all outgoing, but drop incoming and forwarding packets by default
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Custom per-protocol chains
:UDP - [0:0]
:TCP - [0:0]
:ICMP - [0:0]

# Acceptable UDP traffic

# Acceptable TCP traffic
-A TCP -p tcp --dport 80 -j ACCEPT
-A TCP -p tcp --dport 443 -j ACCEPT
-A TCP -p tcp --dport 22 -j ACCEPT

# Acceptable ICMP traffic

# Boilerplate acceptance policy
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i lo -j ACCEPT

# Drop invalid packets
-A INPUT -m conntrack --ctstate INVALID -j DROP

# Pass traffic to protocol-specific chains
## Only allow new connections (established and related should already be handled)
## For TCP, additionally only allow new SYN packets since that is the only valid
## method for establishing a new TCP connection
-A INPUT -p udp -m conntrack --ctstate NEW -j UDP
-A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP
-A INPUT -p icmp -m conntrack --ctstate NEW -j ICMP

# Reject anything that's fallen through to this point
## Try to be protocol-specific w/ rejection message
-A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable
-A INPUT -p tcp -j REJECT --reject-with tcp-reset
-A INPUT -j REJECT --reject-with icmp-proto-unreachable

# Commit the changes
COMMIT

*raw
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT

*security
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT

*mangle
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
COMMIT
```

```console
sudo iptables-restore -t /etc/iptables/rules.v4
sudo nano /etc/iptables/rules.v6
```

```console
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
COMMIT

*raw
:PREROUTING DROP [0:0]
:OUTPUT DROP [0:0]
COMMIT

*nat
:PREROUTING DROP [0:0]
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
:POSTROUTING DROP [0:0]
COMMIT

*security
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
COMMIT

*mangle
:PREROUTING DROP [0:0]
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
:POSTROUTING DROP [0:0]
COMMIT
```

```console
sudo ip6tables-restore -t /etc/iptables/rules.v6
sudo service netfilter-persistent reload
sudo iptables -S
sudo ip6tables -S
```

## Lynis

Lynis to perform full system audits.

```console
sudo apt install lynis
```

## whowatch

To monitor active SSH connections.

```console
sudo apt install whowatch
```

## Remove Unused Network-Facing Services

```console
sudo ss -atpu
sudo apt purge "package_name"
```

<br/>
<br/>

# 3. Web Server

Multiple configurations for regular web server needs.

1: Secure web traffic with Let's Encrypt's Certbot

2: Nginx with Server Blocks to host multiple websites

3: Apache with Virtual Host to host multiple websites

4: NodeJS and PM2 to host multiple Nuxt instances

## Let's Encrypt

```console
sudo apt install certbot
```

Request a certificate for Apache:

```console
sudo certbot --apache -d domain.com -d www.domain.com
```

Request a certificate for Nginx:

```console
sudo certbot --nginx -d domain.com -d www.domain.com
```

Certificate automated renewals:

```console
sudo certbot renew --dry-run
```

## Nginx

```console
sudo apt install nginx
sudo chmod -R 755 /var/www
```

### Nginx: New Website

Nginx folder structure.

```console
sudo mkdir -p /var/www/your_domain/html
```

```console
sudo chown -R $USER:$USER /var/www/your_domain/html
sudo chmod -R 755 /var/www/your_domain
sudo chmod -R 755 /var/www/your_domain
```

sample index.html

```console
$ nano /var/www/your_domain/html/index.html
```

your_domain config default config file

```console
sudo nano /etc/nginx/sites-available/your_domain
```

```nginx
limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;

server {
    root /var/www/website.net/html;
    index index.html index.htm index.nginx-debian.html;
    server_name website.net www.website.net;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    #add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), fullscreen=(self), payment=()";
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'self'; upgrade-insecure-requests;" always;

    # Hide Nginx version number
    server_tokens off;

    # 404 page
    error_page 404 /404.html;

    # SSL Session Caching
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # Gzip Compression
    gzip on;
    gzip_vary on;
    gzip_min_length 10240;
    gzip_proxied expired no-cache no-store private auth;
    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml;
    gzip_disable "MSIE [1-6]\.";

    location / {
        try_files $uri $uri/ =404;
        # Rate limiting
        limit_req zone=one burst=5;
    }

    listen [::]:443 ssl; # managed by Certbot
    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/website.net/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/website.net/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}

server {
    if ($host = www.website.net) {
        return 301 https://$host$request_uri;
    } # managed by Certbot

    if ($host = website.net) {
        return 301 https://$host$request_uri;
    } # managed by Certbot

    listen 80;
    listen [::]:80;
    server_name website.net www.website.net;
    return 404; # managed by Certbot
}
```

enable server block

```console
sudo ln -s /etc/nginx/sites-available/your_domain /etc/nginx/sites-enabled/
```

safeguard for hash bucket memory

```console
sudo nano /etc/nginx/nginx.conf
```

```nginx
...
http {
    ...
    server_names_hash_bucket_size 64;
    ...
}
...
```

nginx verification

```console
sudo nginx -t
```

```console
sudo systemctl restart nginx
```

## Apache

```console
sudo apt install apache2
sudo chmod -R 755 /var/www
```

Enable the ssl module

```console
sudo a2enmod ssl
```

Enable the proxy module

```console
sudo a2enmod proxy
```

Enable the http2 module

```console
sudo a2enmod http2
```

Restart Apache.

```console
sudo systemctl restart apache2
```

### Apache: New Website

Apache folder structure.

```console
$ mkdir -p /var/www/domain.com/public_html/
$ touch /var/www/domain.com/public_html/index.html
```

Apache config for http:

```console
$ touch /etc/apache2/sites-available/domain.com.conf
```

```apache
<VirtualHost *:80>
  ServerAdmin webmaster@domain.com
  ServerName domain.com
  ServerAlias www.domain.com
  DocumentRoot /var/www/domain.com/public_html/
  ErrorLog /var/www/domain.com/logs/error.log
  CustomLog /var/www/domain.com/logs/access.log combined
  Redirect permanent / https://domain.com/
</VirtualHost>
```

Apache config for https:

```console
$ touch /etc/apache2/sites-available/domain.com-ssl.conf
```

```apache
<IfModule mod_ssl.c>
  <VirtualHost *:443>
    ServerAdmin webmaster@domain.com
    ServerName domain.com
    ServerAlias www.domain.com
    DocumentRoot /var/www/domain.com/public_html/
    ErrorLog /var/www/domain.com/logs/error.log
    CustomLog /var/www/domain.com/logs/access.log combined
    SSLCertificateFile /etc/letsencrypt/live/domain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/domain.com/privkey.pem
    SSLCACertificateFile /etc/letsencrypt/live/domain.com/cert.pem
    Include /etc/letsencrypt/options-ssl-apache.conf
  </VirtualHost>
</IfModule>
```

Map the domain.

```console
sudo a2ensite domain.com.conf
```

Restart the Apache service to register the changes.

```console
sudo systemctl restart apache2
```

## Node and PM2

```console
sudo apt install nodejs
sudo apt install npm
sudo npm install pm2 -g
sudo pm2 list
sudo pm2 monit
```

Configuring Apache to Reserve Proxy to PM2:

```apache
<VirtualHost *:80>
  ServerAdmin webmaster@domain.com
  ServerName domain.com
  ServerAlias www.domain.com
  DocumentRoot /var/www/domain.com/public_html
  ErrorLog /var/www/domain.com/logs/error.log
  CustomLog /var/www/domain.com/logs/access.log combined

  ProxyPreserveHost On
  ProxyPass / http://localhost:3000/
  ProxyPassReverse / http://localhost:3000/

  Redirect permanent / https://domain.com/
</VirtualHost>
```

```apache
<IfModule mod_ssl.c>
  <VirtualHost *:443>
    ServerAdmin webmaster@domain.com
    ServerName domain.com
    ServerAlias www.domain.com
    DocumentRoot /var/www/domain.com/public_html
    ErrorLog /var/www/domain.com/logs/error.log
    CustomLog /var/www/domain.com/logs/access.log combined

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/

    SSLCertificateFile /etc/letsencrypt/live/domain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/domain.com/privkey.pem
    SSLCACertificateFile /etc/letsencrypt/live/domain.com/cert.pem
    Include /etc/letsencrypt/options-ssl-apache.conf
  </VirtualHost>
</IfModule>
```

<br/>
<br/>

# 4. Monitoring

Essential monitoring setup for all VPS instances.

### Netdata

Real-time performance and health monitoring system. Provides immediate insight into web server performance, system resources, and potential security issues.

Install required dependencies:

```console
sudo apt install wget curl
```

Install Netdata using the automatic installer

```console
$ wget -O /tmp/netdata-kickstart.sh https://my-netdata.io/kickstart.sh
sudo sh /tmp/netdata-kickstart.sh --no-updates --stable-channel --disable-telemetry
```

Verify the installation

```console
sudo systemctl status netdata
```

Restrict Netdata to localhost only:

```console
sudo nano /etc/netdata/netdata.conf
```

```console
[global]
    # Reduce retention to save resources (default is 3600)
    history = 1800

[web]
    # Only allow connections from localhost
    bind to = localhost
    allow connections from = localhost
    mode = static-threaded
```

Create a custom system configuration:

```console
sudo nano /etc/netdata/go.d.local/web_log.conf
```

```console
jobs:
  - name: nginx
    path: /var/log/nginx/access.log

  - name: apache
    path: /var/log/apache2/access.log
```

Create custom alerts for web hosting:

```console
sudo nano /etc/netdata/health.d/web_alerts.conf
```

```console
# High CPU Usage Alert
alarm: cpu_usage
    on: system.cpu
    lookup: average -3m unaligned of user,system,softirq,irq,guest
    units: %
    every: 1m
    warn: $this > 60
    crit: $this > 80
    info: CPU utilization exceeded threshold

# RAM Usage Alert
alarm: ram_usage
    on: system.ram
    lookup: average -1m percentage of used
    units: %
    every: 1m
    warn: $this > 70
    crit: $this > 85
    info: RAM utilization exceeded threshold

# Disk Space Alert
alarm: disk_space_usage
    on: disk.space
    lookup: average -1m percentage of used
    units: %
    every: 1m
    warn: $this > 80
    crit: $this > 90
    info: Disk space utilization exceeded threshold

# Web Server Response Time
alarm: web_response_time
    on: web_log.response_time
    lookup: average -3m
    units: ms
    every: 1m
    warn: $this > 500
    crit: $this > 1000
    info: Web server response time is too high
```

Restart Netdata

```console
sudo systemctl restart netdata
```

### Access Dashboard

From local machine:

```console
# Create SSH tunnel to access Netdata dashboard
$ ssh -L 19999:localhost:19999 username@server_ip

# Access dashboard by opening it in the browser:
# http://localhost:19999
```

<br/>
<br/>

# 5. Server Maintenance

Semi-regular healthy maintenance tasks.

### Lynis: System Auditing

```console
sudo lynis show options
sudo lynis audit system
```

### Rkhunter

```console
sudo rkhunter -C
sudo rkhunter > ~/audits/rkhunter-audit-results.txt
```

### chkrootkit

```console
sudo chkrootkit > ~/audits/chkrootkit-audit-results.txt
```

### whowatch

```console
sudo whowatch
```

<br/>
<br/>

# 6. Data backup

Create backup dirs in home folder:

```console
mkdir -p ~/backup/{sys-configs,web-configs,security,databases,custom}

```

Backup system configurations (these still need sudo to read):

```console
sudo tar -czvf ~/backup/sys-configs/etc-backup.tar.gz /etc/
sudo tar -czvf ~/backup/sys-configs/ssh-config.tar.gz /etc/ssh/
sudo tar -czvf ~/backup/sys-configs/user-data.tar.gz /home/

```

Backup web server configurations:

```console
sudo tar -czvf ~/backup/web-configs/nginx-sites.tar.gz /etc/nginx/sites-available/ /etc/nginx/sites-enabled/
sudo tar -czvf ~/backup/web-configs/apache-sites.tar.gz /etc/apache2/sites-available/ /etc/apache2/sites-enabled/ 2>/dev/null
sudo tar -czvf ~/backup/web-configs/www-data.tar.gz /var/www/
sudo tar -czvf ~/backup/web-configs/letsencrypt.tar.gz /etc/letsencrypt/

```

Backup security configurations:

```console
sudo tar -czvf ~/backup/security/iptables-rules.tar.gz /etc/iptables/
sudo tar -czvf ~/backup/security/fail2ban.tar.gz /etc/fail2ban/
sudo tar -czvf ~/backup/security/crowdsec.tar.gz /etc/crowdsec/ 2>/dev/null

```

Backup node and pm2:

```console
if command -v pm2 &> /dev/null; then
pm2 save
tar -czvf ~/backup/custom/pm2-config.tar.gz ~/.pm2/ 2>/dev/null
fi

```

Create a list of installed packages

```console
dpkg --get-selections > ~/backup/sys-configs/installed-packages.txt

```

Create a snapshot of current system state

```console
sudo apt install -y debsums
sudo debsums -s -c > ~/backup/sys-configs/modified-config-files.txt 2>&1

```

Create snapshot of file permissions in /etc

```console
sudo find /etc -type f -exec stat -c "%a %n" {} \; > ~/backup/sys-configs/etc-permissions.txt

```

Fix ownership of all backup files

```console
sudo chown -R $(whoami):$(whoami) ~/master-backup

```

Encrypt all backups

```console
cd ~
tar -czvf vps-backup.tar.gz backup/
gpg --symmetric --cipher-algo AES256 vps-backup.tar.gz

```

rsync the encrypted backups from VPS to local machine:

```console
rsync -ahvz username@vps-ip:~/vps-backup.tar.gz ~/local-backups/

```

Extract backups and Decrypt on local machine:

```console
gpg -d /path/to/local/encrypted_backups/vps-backup-home.tar.gz.gpg | tar xzvf -

```

<br/>
<br/>

# 7. Upgrade Process (Debian 12 Bookworm)

Preliminary Steps:

```console
# current system full update
sudo apt update
sudo apt upgrade
sudo apt full-upgrade

# remove unnecessary packages
sudo apt --purge autoremove

# check if any packages are on hold
apt-mark showhold
```

Update Sources List:

```console
# backup sources list
sudo cp /etc/apt/sources.list /etc/apt/sources.list.bullseye.bak

# create new sources list for Bookworm
sudo nano /etc/apt/sources.list
```

/etc/apt/sources.list:

```console
deb http://deb.debian.org/debian bookworm main contrib non-free-firmware non-free
# deb-src http://deb.debian.org/debian bookworm main contrib non-free-firmware non-free

deb http://security.debian.org/debian-security bookworm-security main contrib non-free-firmware non-free
# deb-src http://security.debian.org/debian-security bookworm-security main contrib non-free-firmware non-free

deb http://deb.debian.org/debian bookworm-updates main contrib non-free-firmware non-free
# deb-src http://deb.debian.org/debian bookworm-updates main contrib non-free-firmware non-free

# FastTrack repository (requires separate installation in Bookworm)
# Will be configured after upgrade
```

Perform the upgrade:

```console
# update package index with new sources
sudo apt update

# upgrade minimal essential packages
sudo apt upgrade --without-new-pkgs

# execute full dist-upgrade
sudo apt full-upgrade

# clean-up obsolete packages
sudo apt --purge autoremove

# re-install fasttrack for Bookworm (setup is different in Bookworm)
sudo apt install fasttrack-archive-keyring
sudo sh -c 'cat > /etc/apt/sources.list.d/fasttrack.list << EOF
deb https://fasttrack.debian.net/debian-fasttrack/ bookworm-fasttrack main contrib non-free
# deb-src https://fasttrack.debian.net/debian-fasttrack/ bookworm-fasttrack main contrib non-free
EOF'

# last update
sudo apt update
```

Post-Upgrade Tasks:

```console
# check for held or broken packages
sudo apt-mark showhold
sudo dpkg --audit
sudo apt --fix-broken install

# restart system to use the new kernel
sudo shutdown -r now

# post-reboot: verify version
lsb_release -a
uname -a

# re-install/re-config critical security components
sudo apt reinstall fail2ban
sudo systemctl restart fail2ban
sudo systemctl status fail2ban

# re-configure Crowdsec
if systemctl is-active --quiet crowdsec; then
    sudo apt reinstall crowdsec crowdsec-nginx-bouncer
    sudo systemctl restart crowdsec
    sudo systemctl status crowdsec
fi

# verify firewall rules are intact
sudo iptables -L
sudo service netfilter-persistent reload

# update and verify web server configs
if systemctl is-active --quiet nginx; then
    sudo nginx -t
    sudo systemctl restart nginx
fi

if systemctl is-active --quiet apache2; then
    sudo apache2ctl configtest
    sudo systemctl restart apache2
fi

# check for any overwritten modified files
sudo debsums -s -c
```

Post-upgrade Security Verification:

```console
# run security audit with Lynis
sudo lynis audit system

# comprehensive security checks
sudo fail2ban-client status
sudo systemctl status crowdsec
sudo netstat -tulpn | grep "LISTEN"
sudo lynis audit system
sudo rkhunter --check
sudo chkrootkit

# update SSL security settings for web servers
# Verify TLS 1.3 is enabled and older protocols disabled
sudo nano /etc/letsencrypt/options-ssl-nginx.conf
```

# 8. Bootstraps

A bunch of opinionated and hardened files for multiple software configs:

### apache2

[domain.com.conf](https://github.com/fidacura/Debian9000//)

[domain.com-ssl.conf](https://github.com/fidacura/Debian9000//)

### fail2ban

[jail.local](https://github.com/fidacura/Debian9000/fail2ban/jail.local/)
[nginx-badhosts.conf](https://github.com/fidacura/Debian9000/fail2ban/filter.d/nginx-badhosts.conf)

### fish

[fish.config](https://github.com/fidacura/Debian9000//)

### iptables

[iptables.sh](https://github.com/fidacura/Debian9000//)

### gnupg

[gpg.conf](https://github.com/fidacura/Debian9000//)

### nginx

[domain.com.conf](https://github.com/fidacura/Debian9000//)

[domain.com-ssl.conf](https://github.com/fidacura/Debian9000//)

### postfix

[main.cf](https://github.com/fidacura/Debian9000//)

### sshd

[sshd.conf](https://github.com/fidacura/Debian9000//)

[sshd-pfs_config](https://github.com/fidacura/Debian9000//)
