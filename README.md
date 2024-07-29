# Debian9000

An opinionated setup process for "all-things" Debian VPS configuration from scratch.

1: Basic server configuration for all instances.

2: Server hardening for all instances.

3: Web server configurations [ Apache / Nginx / Node + PM2 ]

4: Server maintenance

5: Data backups

6: Bootstraps

<br/>
<br/>

# 1. Basic server configuration

Basic Linux configurations to use in all VPS instances.

### System update && upgrade

```console
$ apt update && apt upgrade
```

### Hostname change

```console
$ hostnamectl set-hostname "hostname"
```

### Update /etc/hosts

```console
$ echo "hostname" > /etc/hostname
$ hostname -F /etc/hostname
```

### Timezone setup

```console
$ dpkg-reconfigure tzdata
$ date
```

### New user

```
$ adduser "username"
```

### Sudo

```console
$ apt install sudo
$ usermod -a -G sudo "username"
```

### Fish

A modern, easy-going, and powerful shell.

```console
$ sudo apt install fish
$ sudo chsh -s /usr/bin/fish
```

### Reboot

```console
$ sudo shutdown -r now
```

<br/>
<br/>

# 2. Hardening

Basic hardening configurations to use in all VPS instances.

### SSH hardening and daemon configuration

On the server:

```console
$ mkdir -p ~/.ssh/ && sudo chmod -R 700 ~/.ssh/
$ sudo chmod 700 -R ~/.ssh && chmod 600 ~/.ssh/authorized_keys
```

On local machine:

```console
$ scp ~/.ssh/id_rsa.pub username@vpsipaddress:~/.ssh/authorized_keys
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
$ sudo systemctl restart sshd
```

### Fail2ban

Simple intrusion prevention software.

```console
$ apt install fail2ban
```

Configure:

```console
$ cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
$ cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

File /etc/fail2ban/jail.local:

```console
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime = 3600
findtime = 600
maxretry = 3
backend = auto
usedns = warn
banaction = iptables-multiport
protocol = tcp
chain = INPUT
action_ = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
action_mw = %(action_)s
action_mwl = %(action_)s

[ssh]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime = 86400

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-botsearch]
enabled = true
filter = nginx-botsearch
port = http,https
logpath = /var/log/nginx/access.log

[nginx-badbots]
enabled = true
filter = nginx-badbots
port = http,https
logpath = /var/log/nginx/access.log

[nginx-noproxy]
enabled = true
filter = nginx-noproxy
port = http,https
logpath = /var/log/nginx/access.log
```

### Remove Unused Network-Facing Services

```console
$ sudo ss -atpu
$ sudo apt purge "package_name"
```

### Rootkit protection

Rkhunter and chkrootkit:

```console
$ sudo apt install rkhunter
$ sudo rkhunter --propupd
$ sudo rkhunter --check
$ sudo apt install chkrootkit
```

### Firewall

Always iptables: Minimal configuration; Easygoing; Effective.

```console
$ sudo iptables -L
$ sudo apt install iptables-persistent
$ sudo nano /etc/iptables/rules.v4
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
$ sudo iptables-restore -t /etc/iptables/rules.v4
$ sudo nano /etc/iptables/rules.v6
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
$ sudo ip6tables-restore -t /etc/iptables/rules.v6
$ sudo service netfilter-persistent reload
$ sudo iptables -S
$ sudo ip6tables -S
```

### Lynis

Lynis to perform full system audits.

```console
$ sudo apt install lynis
```

### whowatch

To monitor active SSH connections.

```console
$ sudo apt install whowatch
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
$ sudo apt install certbot
```

Request a certificate for Apache:

```console
$  sudo certbot --apache -d domain.com -d www.domain.com
```

Request a certificate for Nginx:

```console
$  sudo certbot --nginx -d domain.com -d www.domain.com
```

Certificate automated renewals:

```console
$  sudo certbot renew --dry-run
```

## Nginx

```console
$ sudo apt install nginx
$ sudo chmod -R 755 /var/www
```

### Nginx: New Website

Nginx folder structure.

```console
$ sudo mkdir -p /var/www/your_domain/html
```

```console
$ sudo chown -R $USER:$USER /var/www/your_domain/html
$ sudo chmod -R 755 /var/www/your_domain
$ sudo chmod -R 755 /var/www/your_domain
```

sample index.html

```console
$ nano /var/www/your_domain/html/index.html
```

your_domain config default config file

```console
$ sudo nano /etc/nginx/sites-available/your_domain
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
$ sudo ln -s /etc/nginx/sites-available/your_domain /etc/nginx/sites-enabled/
```

safeguard for hash bucket memory

```console
$ sudo nano /etc/nginx/nginx.conf
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
$ sudo nginx -t
```

```console
$ sudo systemctl restart nginx
```

## Apache

```console
$ sudo apt install apache2
$ sudo chmod -R 755 /var/www
```

Enable the ssl module

```console
$ sudo a2enmod ssl
```

Enable the proxy module

```console
$ sudo a2enmod proxy
```

Enable the http2 module

```console
$ sudo a2enmod http2
```

Restart Apache.

```console
$  sudo systemctl restart apache2
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
$ sudo a2ensite domain.com.conf
```

Restart the Apache service to register the changes.

```console
$ sudo systemctl restart apache2
```

## Node and PM2

```console
$ sudo apt install nodejs
$ sudo apt install npm
$ sudo npm install pm2 -g
$ sudo pm2 list
$ sudo pm2 monit
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

# 4. Maintenance

Semi-regular healthy maintenance tasks.

### Lynis: System Auditing

```console
$ sudo lynis show options
$ sudo lynis audit system
```

### Rkhunter

```console
$ sudo rkhunter -C
$ sudo rkhunter > ~/audits/rkhunter-audit-results.txt
```

### chkrootkit

```console
$ sudo chkrootkit > ~/audits/chkrootkit-audit-results.txt
```

### whowatch

```console
$ sudo whowatch
```

<br/>
<br/>

# 5. Data backup

Simple processes to backup (encrypted versions) all-things VPS data:

Regular compressed backups:

```console
# Create a directory for encrypted backups if it doesn't exist
$ mkdir -p ~/encrypted_backups

# Backup and encrypt home directory
$ tar czvf - ~/var/home | gpg --symmetric --cipher-algo AES256 -o ~/encrypted_backups/vps-backup-home.tar.gz.gpg

# Backup and encrypt web directory
$ tar czvf - ~/var/www | gpg --symmetric --cipher-algo AES256 -o ~/encrypted_backups/vps-backup-web.tar.gz.gpg

# Backup and encrypt logs
$ tar czvf - ~/var/log | gpg --symmetric --cipher-algo AES256 -o ~/encrypted_backups/vps-backup-logs.tar.gz.gpg

# Backup and encrypt Apache configuration
$ tar czvf - ~/etc/apache2 | gpg --symmetric --cipher-algo AES256 -o ~/encrypted_backups/vps-backup-apache.tar.gz.gpg

# Backup and encrypt Nginx configuration
$ tar czvf - ~/etc/nginx | gpg --symmetric --cipher-algo AES256 -o ~/encrypted_backups/vps-backup-nginx.tar.gz.gpg

# Backup and encrypt Let's Encrypt certificates
$ tar czvf - ~/etc/letsencrypt | gpg --symmetric --cipher-algo AES256 -o ~/encrypted_backups/vps-backup-letsencrypt-certificates.tar.gz.gpg

# Backup and encrypt security audits
$ tar czvf - ~/var/home/audits | gpg --symmetric --cipher-algo AES256 -o ~/encrypted_backups/vps-backup-security-audits.tar.gz.gpg
```

Then, use rsync to copy the encrypted backups from your VPS to your local machine:

```console
$ rsync -ahvz username@vpsipaddress:/path/to/encrypted_backups/ /path/to/local/encrypted_backups/
```

Then, on your local machine, decrypt and extract a specific backup:

```console
$ gpg -d /path/to/local/encrypted_backups/vps-backup-home.tar.gz.gpg | tar xzvf -
```

<br/>
<br/>

# 6. Bootstraps

A bunch of opinionated and hardened files for multiple software configs:

### apache2

[domain.com.conf](https://github.com/fidacura/Debian9000//)

[domain.com-ssl.conf](https://github.com/fidacura/Debian9000//)

### fail2ban

[jail.conf](https://github.com/fidacura/Debian9000//)

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
