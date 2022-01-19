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
bantime = 600
findtime = 600
maxretry = 3
backend = auto
usedns = warn
destemail = root@localhost
sendername = Fail2Ban
banaction = iptables-multiport
mta = sendmail
protocol = tcp
chain = INPUT
action_ = %(banaction)...
action_mw = %(banaction)...
protocol="%(protocol)s"...
action_mwl = %(banaction)s...

[ssh]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 4
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
$ touch ~/config/iptables.sh
```
iptables file [ [download here](https://github.com/fidacura/Debian9000//) ]:

```console  
#!/bin/bash

# Forget old rules
iptables -F
iptables -X
iptables -Z

# Default policy: drop
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Allow loopback and reject traffic to localhost that does not originate from lo0
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT ! -i lo -s 127.0.0.0/8 -j REJECT
iptables -A OUTPUT -o lo -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP
iptables -A OUTPUT -m state --state INVALID -j DROP
iptables -A FORWARD -m state --state INVALID -j DROP

# Allow ping and icmp packets
iptables -A INPUT -p icmp -m state --state NEW --icmp-type 8 -j ACCEPT

# Allow established and related packets already seen
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Input chain
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT
iptables -A INPUT -p tcp --dport 66333 -m state --state NEW -j ACCEPT

# apt-get permissions
iptables -A OUTPUT -p tcp -m tcp --dport 53 -m comment --comment "DNS-TCP" -j ACCEPT
iptables -A OUTPUT -p udp -m udp --dport 53 -m comment --comment "DNS-UDP" -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 80 -m comment --comment "HTTP" -j ACCEPT
iptables -A OUTPUT -p tcp -m tcp --dport 443 -m comment --comment "HTTPS" -j ACCEPT
```
iptables save and execute:
```console
$ bash ~/config/iptables.sh
$ sudo iptables -L -v
```
iptables persistency:
```console
$ sudo iptables-save > /etc/iptables.rules
$ sudo touch /etc/network/if-pre-up.d/iptablesload
```
File: /etc/network/if-pre-up.d/iptablesload
```bash
#!/bin/sh
iptables-restore < /etc/iptables.rules
exit 0
```
Make iptables file executable:
```console
$ sudo chmod +x /etc/network/if-pre-up.d/iptablesload
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

1: Apache with Virtual Host to host multiple websites

2: Nginx with Server Blocks to host multiple websites

3: NodeJS and PM2 to host multiple Nuxt instances

4: Secure web traffic with Let's Encrypt's Certbot

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

## Nginx
```console
$ sudo apt install nginx
$ sudo chmod -R 755 /var/www
```

### Nginx: New Website

Nginx folder structure.
```console
$ mkdir -p /var/www/domain.com/public_html/
$ touch /var/www/domain.com/public_html/index.html
```

NGINX config for http:
```console
$ touch /etc/nginx/conf.d/domain.com.conf
```
```nginx
server {
    listen         80 default_server;
    listen         [::]:80 default_server;
    server_name    domain.com www.domain.com;
    root           /var/www/domain.com;
    index          index.html;

    gzip             on;
    gzip_comp_level  3;
    gzip_types       text/plain text/css application/javascript image/*;
}
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
Simple processes to backup all-things VPS data:

Regular compressed backups:
```console
$ tar pczvf ~/backup/vps-backup-home.tar.gz ~/var/home
$ tar pczvf ~/backup/vps-backup-web.tar.gz ~/var/www
$ tar pczvf ~/backup/vps-backup-logs.tar.gz ~/var/log
$ tar pczvf ~/backup/vps-backup-apache.tar.gz ~/etc/apache2
$ tar pczvf ~/backup/vps-backup-nginx.tar.gz ~/etc/nginx
$ tar pczvf ~/backup/vps-backup-letsencrypt-certificates.tar.gz ~/etc/letsencrypt
$ tar pczvf ~/backup/vps-backup-security-audits.tar.gz ~/var/home/audits
```


Rsync from local machine:
```console
$ rsync -ahvz username@vpsipaddress:/path/to/source/backup /path/to/local/backup/
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