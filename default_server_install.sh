#!/bin/bash

# IMPORTANT before running script verify the following steps have been completed.
# 1.  Set servers hostname (hostnamectl set-hostname <hostname>).
# 2.  Logged in as user with sudo permissions.
# 3.  SSL/TLS Certificate obtained and installed in default location (/etc/letsencrypt/live/mail.$domain).
# 4.  DNS MX, A and/or AAAA records completed and allowed to propagate.
# 5.  Firewall ensure ports 25/tcp (SMTP), 587/tcp (Mail submission), 143/tcp
# (IMAP), 993/tcp (IMAPS), 465/tcp.

# To							 Action      From
# --							 ------      ----
# 22/tcp						 ALLOW IN    Anywhere
# 25/tcp (SMTP)					 ALLOW IN    Anywhere
# 587/tcp (Mail submission)		 ALLOW IN    Anywhere
# 143/tcp (IMAP)				 ALLOW IN    Anywhere
# 993/tcp (IMAPS)				 ALLOW IN    Anywhere
# 80,443/tcp (WWW Full)			 ALLOW IN    Anywhere
# 465/tcp						 ALLOW IN    Anywhere
# 22/tcp (v6)					 ALLOW IN    Anywhere (v6)
# 25/tcp (SMTP (v6))			 ALLOW IN    Anywhere (v6)
# 587/tcp (Mail submission (v6)) ALLOW IN    Anywhere (v6)
# 143/tcp (IMAP (v6))			 ALLOW IN    Anywhere (v6)
# 993/tcp (IMAPS (v6))			 ALLOW IN    Anywhere (v6)
# 80,443/tcp (WWW Full (v6))	 ALLOW IN    Anywhere (v6)
# 465/tcp (v6)					 ALLOW IN    Anywhere (v6)

# NOTE: When prompted at the beginning of the installation of Postfix select
# 'Internet Site' and enter your FQDN fully qualified domain name ie.
# domain.com not mail.domain.com.  Your email address will be user@domain.com
# your MX record will point mail servers to mail.domain.com.

# HOSTNAME: domain.com
# CERTIFICATE: mail.domain.com

# Run *Certbot* to obtain your standalone SSL certificate, run the following command after your
# DNS records have been updated / propagated and after you have completed the initial setup of
# the server ie. Created user accounts, set hostname, updated and general setup. I would
# wait until after the installation of the certificates and email server before setting up
# your firewall.

# sudo mv acme-dns-auth.py /etc/letsencrypt/
# sudo certbot certonly --manual --manual-auth-hook /etc/letsencrypt/acme-dns-auth.py --preferred-challenges dns --debug-challenges -d mail.domain.com
# Copy the dns CNAME record to your registrar wait the TTL time period and then
# press enter.  If everything worked properly and validation was successful you
# will get a prompt from certbot says *Congradulations! your certificate chain
# has been saved at: /full/path/to/cert.

# TEST CEERTIFICATE GENERATION
# sudo certbot certonly --standalone -d mail.<domain>.com --register-unsafely-without-email --agree-tos --test-cert

# PRODUCTION CERTIFICATE GENERATION
# sudo certbot certonly --standalone -d mail.<domain>.com

umask 022

export TERM=rxvt

[ $EUID -ne 0 ] && echo "ERROR: Check how script was executed should only be run by user/users with
SUDO privileges but NOT by the root user." && exit

source=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
sudoer=$SUDO_USER
domain="$(cat /etc/hostname)"
subdomain="mail"
maildomain="$subdomain.$domain"
certdir="/etc/letsencrypt/live/$maildomain"

[ ! -d /etc/letsencrypt/live/$maildomain ] && echo "SSL/TLS Certificate either not obtained or installed in none default location.
Either obtain your certificates via certbot or confirm there install location (Default '/etc/letsencrypt/live/$maildomain') and
run script again." && exit

# Please note this script also does some baseline configuring for packages that
# are NOT installed by defualt such as Perl greylist.pl server and
# postfix-policyd-spf-perl.  Defaults can easily be changed but make sure you
# also update the postfix/master.cf file services.
apt install postfix postfix-pcre dovecot-imapd dovecot-sieve opendkim opendkim-tools spamassassin \
	spamc fail2ban postfix-policyd-spf-python logrotate syslog-ng syslog-ng-scl \
	opendmarc libmilter-dev logwatch

echo "Configuring Postfix main.cf..."

# Uncomment the following lines to enable logging of TLS connection information.
# This will log TLS information in the mail log and add comments to headers.
# postconf -e "smtp_tls_loglevel = 1"
# postconf -e "smtpd_tls_loglevel = 1"
# postconf -e "smtpd_tls_received_header = yes"

postconf -e "biff = no"
postconf -e "myorigin = \$mydomain"
postconf -e "mail_name = $domain"
postconf -e "myhostname = $maildomain"
postconf -e "mydestination = \$myhostname, localhost.\$mydomain, localhost, \$mydomain, mail, localhost.localdomain"
postconf -e "mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128"
postconf -e "smtpd_delay_reject = yes"

postconf -e "relay_domains = \$mydestination"
postconf -e "mailbox_size_limit = 0"
postconf -e "message_size_limit = 0"
postconf -e "disable_vrfy_command = yes"

# Change the cert/key files to the default locations of the Let's Encrypt cert/key
postconf -e "smtpd_use_tls = yes"
postconf -e "smtpd_tls_auth_only = yes"
postconf -e "smtpd_tls_security_level = may"
postconf -e "smtpd_tls_key_file = $certdir/privkey.pem"
postconf -e "smtpd_tls_cert_file = $certdir/fullchain.pem"
postconf -e "smtpd_tls_CApath = /etc/ssl/certs/"

# Exclude insecure and obsolete encryption protocols.
postconf -e 'smtpd_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
postconf -e 'smtp_tls_mandatory_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
postconf -e 'smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'
postconf -e 'smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1'

# Here we tell Postfix to look to Dovecot for authenticating users/passwords.
# Dovecot will be putting an authentication socket in /var/spool/postfix/private/auth
postconf -e "smtpd_sasl_auth_enable = yes"
postconf -e "smtpd_sasl_type = dovecot"
postconf -e "smtpd_sasl_path = private/auth"
postconf -e "smtpd_sasl_security_options = noanonymous, noplaintext"
postconf -e "smtpd_sasl_tls_security_options = noanonymous"

postconf -e "smtp_tls_loglevel = 1"
postconf -e "smtp_tls_security_level = may"
postconf -e "smtp_tls_cert_file = $certdir/fullchain.pem"
postconf -e "smtp_tls_key_file = $certdir/privkey.pem"
postconf -e "smtp_tls_CApath = /etc/ssl/certs/"

# Postfix postscreen configuration.
postconf -e "postscreen_access_list = permit_mynetworks cidr:/etc/postfix/postscreen_access.cidr"
postconf -e "postscreen_blacklist_action = drop"
postconf -e "postscreen_greet_banner ="
postconf -e "postscreen_dnsbl_whitelist_threshold = -2"
postconf -e "postscreen_dnsbl_threshold = 4"

# postconf -e "postscreen_dnsbl_sites = zen.spamhaus.org*3, b.barracudacentral.org=127.0.0.[2..11]*2, bl.spameatingmonkey.net*2, bl.spamcop.net*1, dnsbl.sorbs.net*1"

cat >> '/etc/postfix/postscreen_access.cidr' << EOF
# Rule order matters. Put more specific allowlist entries
# before more general denylist entries.
# 192.168.1.1             permit
# 2001:db8::1             permit
# 192.168.0.0/16          reject
# 2001:db8::/32           reject
EOF

# TODO: Research possible new whitelist/blacklists.
# Postscreen dnswl check implementation.
postconf -e "postscreen_dnsbl_sites = zen.spamhaus.org*3, b.barracudacentral.org=127.0.0.[2..11]*2,	bl.spameatingmonkey.net*2, bl.spamcop.net, dnsbl.sorbs.net, swl.spamhaus.org*-4,list.dnswl.org=127.[0..255].[0..255].0*-2, list.dnswl.org=127.[0..255].[0..255].1*-4, list.dnswl.org=127.[0..255].[0..255].[2..3]*-6"

postconf -e "postscreen_dnsbl_action = enforce"
postconf -e "postscreen_greet_action = enforce"

# Policyd configuration (python).
# IMPORTANT: The check_policy_service unix:private/policyd-spf must be after reject_unauth_destination
# or server will become an open relay.
# helo, sender, relay and recipient restrictions
postconf -e 'policyd-spf_time_limit = 3600s'
postconf -e 'smtpd_helo_required = yes'
postconf -e 'smtpd_relay_restrictions = permit_sasl_authenticated reject_unauth_destination'
postconf -e 'smtpd_recipient_restrictions = permit_sasl_authenticated, permit_mynetworks, reject_unauth_destination, check_policy_service unix:private/policyd-spf'

# TODO: refactor smtpd restrictions.
# postconf -e 'smtpd_helo_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_invalid_helo_hostname, reject_non_fqdn_helo_hostname, reject_unknown_helo_hostname'

postconf -e 'smtpd_sender_restrictions = permit_sasl_authenticated, permit_mynetworks'

postconf -e "smtp_header_checks = regexp:/etc/postfix/header_check"
cat >> /etc/postfix/header_check << EOF
/^Authentication-Results:.*/	IGNORE
/^Received:.*/					IGNORE
/^X-Originating-IP:.*/			IGNORE
/^X-PWhois-.*/					IGNORE
/^X-Spam-.*/					IGNORE
EOF

# NOTE: The trailing slash here, or for any directory name in the home_mailbox
# command, is necessary as it distinguishes a Maildir.
postconf -e "home_mailbox = Maildir/"

echo "Configuring Postfix's master.cf..."
# Postfix master.cf integration of postscreen and spamassassin confirmation.
# Postfix postsreen README http://www.postfix.org/POSTSCREEN_README.html
# sed -i "/^\s*-o/d;/^\s*submission/d;/^\s*smtp/d;/^\s*cleanup/d" /etc/postfix/master.cf
sed -i.bak '/^\s*-o/d;/^\s*submission/d;/^\s*smtp/d' /etc/postfix/master.cf

cat >> '/etc/postfix/master.cf' << EOF
# Postfix master.cf configuration.
smtp unix		-       -       n       -       -       smtp
smtp inet		n       -       y       -       1       postscreen
smtpd pass		-       -       n       -       -       smtpd
  -o content_filter=spamassassin

dnsblog unix	-       -       n       -       0       dnsblog
tlsproxy unix	-       -       n       -       0       tlsproxy

submission inet n       -       y       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_tls_auth_only=yes
  -o smtpd_enforce_tls=yes

smtps     inet	n       -       y       -       -       smtpd
  -o syslog_name=postfix/smtps
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes

spamassassin unix -     n       n       -       -       pipe
  user=debian-spamd argv=/usr/bin/spamc -f -e /usr/sbin/sendmail -oi -f \${sender} \${recipient}

# Python implementation of postfix-spf.
policyd-spf unix -      n       n       -       0       spawn
  user=policyd-spf argv=/usr/bin/policyd-spf

# To enable greylisting uncomment here and add check_policy_service
# unix:private/greylist smtpd_recipient_restrictions.
# Perl greylist implementation.
# greylist  unix  -       n       n       -       0       spawn
#   user=nobody argv=/usr/bin/greylist.pl
EOF

# Create greylist.db location and set permissions.
#mkdir /var/mta
#chown nobody /var/mta

# If using postfix-policyd-spf-perl depending on the your distrobution you may
# need to install the perl libraries.
# perl -MCPAN -e shell
# install Mail::SPF

# The default dovecot configs are located in /etc/dovecot/conf.d/ the files are
# well documented and I encourage you to read them.

echo "Creating Dovecot config..."
cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.bak
cat > '/etc/dovecot/dovecot.conf' << EOF
# Dovecot config
# %u for username
# %n for the name in name@domain.com
# %d for the domain
# %h the user's home directory

ssl = required
#ssl_min_protocol = TLSv1.2
ssl_prefer_server_ciphers = yes
ssl_dh = </usr/share/dovecot/dh.pem

ssl_cert = <$certdir/fullchain.pem
ssl_key = <$certdir/privkey.pem
# Plaintext login. This is safe do to SSL further encryption is not warranted.
auth_mechanisms = plain login
auth_username_format = %n

protocols = \$protocols imap

imap_capability = +SPECIAL-USE

userdb {
	driver = passwd
}
#Fallback: Use plain old PAM to find user passwords
passdb {
	driver = pam
}

# Our mail for each user will be in ~/Mail, and the inbox will be ~/Mail/Inbox
# The LAYOUT option is also important because otherwise, the boxes will be \`.Sent\` instead of \`Sent\`.
mail_location = maildir:~/Mail:INBOX=~/Mail/Inbox:LAYOUT=fs
namespace inbox {
	inbox = yes
	mailbox Drafts {
	special_use = \\Drafts
	auto = subscribe
}
	mailbox Junk {
	special_use = \\Junk
	auto = subscribe
	autoexpunge = 30d
}
	mailbox DMARC {
	auto = subscribe
}
	mailbox Sent {
	special_use = \\Sent
	auto = subscribe
}
	mailbox Trash {
	special_use = \\Trash
	auto = subscribe
}
	mailbox Archive {
	special_use = \\Archive
	auto = subscribe
}
}

# Allow Postfix to use Dovecot's authentication system.
service auth {
  unix_listener /var/spool/postfix/private/auth {
	mode = 0660
	user = postfix
	group = postfix
}
}

protocol lda {
  mail_plugins = \$mail_plugins sieve
}

protocol lmtp {
  mail_plugins = \$mail_plugins sieve
}

plugin {
    # The location of the user's main script storage. The active script
    # in this storage is used as the main user script executed during
    # delivery. The include extension fetches the :personal scripts
    # from this location. When ManageSieve is used, this is also where
    # scripts are uploaded. This example uses the file system as
    # storage, with all the user's scripts located in the directory
    # ~/sieve and the active script (symbolic link) located at
    # ~/.dovecot.sieve.
    sieve = file:~/sieve;active=~/.dovecot.sieve

    # If the user has no personal active script (i.e. if the location
    # indicated in sieve= does not exist or has no active script), use
    # this one:
    sieve_default = /var/lib/dovecot/sieve/default.sieve

    # The include extension fetches the :global scripts from this
    # location.
    sieve_global = /var/lib/dovecot/sieve/global/
}
EOF

# Setting aliases, these aliases assume you will have one main account to receive
# system mail as well as your personal mail.  You can also add additional accounts
# if you want more but one will be your main account this is safer then using
# the root account and retrieving mail with a root login. (SEE COMMENT AT END OF
# ALIAS SECTION)
echo "Configuring postfix aliases..."
cat > '/etc/aliases' << EOF
# See man 5 aliases for format
postmaster:	root
mailer-daemon: root
hostmaster:	root
webmaster: root
usenet:	root
nobody:	root
abuse: root
mail: root
news: root
www: root
ftp: root
dmarc: root
root: $sudoer
EOF
# sed -e '0,/postmaster/ s/^#*/#/' -i /etc/aliases

# IMPORTANT: newaliases command must be run whenever the aliases file is changed.
newaliases

echo "Configuring dovecot sieve..."
mkdir -p /var/lib/dovecot/sieve/

echo "require [\"fileinto\", \"mailbox\"];
if header :contains \"X-Spam-Flag\" \"YES\"
	{
		fileinto \"Junk\";
	}

if header :contains \"Authentication-Results\" \"dmarc=fail\"
	{
		fileinto \"DMARC\";
	}" > /var/lib/dovecot/sieve/default.sieve

# Generate binary for sieve make sure you run sievec if you change this file
# and restart dovecot.service.
cut -d: -f1 /etc/passwd | grep -q "^vmail" || useradd vmail
chown -R vmail:vmail /var/lib/dovecot
sievec /var/lib/dovecot/sieve/default.sieve

echo "Preparing user authentication..."
grep -q nullok /etc/pam.d/dovecot ||
echo "auth    required        pam_unix.so nullok
account required        pam_unix.so" >> /etc/pam.d/dovecot

# Fail2ban settings and configuration.
echo "Setting up fail2ban jails..."
cp $source/fail2ban/fail2ban.local /etc/fail2ban/
cp $source/fail2ban/jail.local /etc/fail2ban/

echo "Writing postscreen filter..."
cp $source/fail2ban/filter/postfix-postscreen.conf /etc/fail2ban/filter.d/

cp $source/fail2ban/fail2ban-recidive-subnet/fail2ban/action.d/iptables-subnet.local /etc/fail2ban/action.d/
cp $source/fail2ban/fail2ban-recidive-subnet/fail2ban/filter.d/recidive-subnet.local /etc/fail2ban/filter.d/

cp $source/fail2ban/fail2ban-recidive-subnet/scripts/fail2ban-subnet-starter.sh /usr/local/sbin/
cp $source/fail2ban/fail2ban-recidive-subnet/scripts/fail2ban-subnet.awk /usr/local/sbin/

chmod +x /usr/local/sbin/fail2ban-subnet-starter.sh

# TODO: move inital log generation script call to end of scirpt.
/usr/local/sbin/fail2ban-subnet-starter.sh
(crontab -l 2>/dev/null; echo "5 * * * * /usr/local/sbin/fail2ban-subnet-starter.sh") | crontab -u root -

# SPF-Policyd settings and configuration.
echo "Writing policyd config..."
cat > /etc/postfix-policyd-spf-python/policyd-spf.conf << EOF
# For a fully commented sample config file see policyd-spf.conf.commented

debugLevel = 2
# The policy server can operate in a test only mode.  This allows you to see the potential
# impact of SPF checking in your mail logs without rejecting mail.  Headers are prepended in
# messages, but message delivery is not affected.  This mode is not enabled by default.  To
# enable it, set TestOnly = 0.  I have enabled TestOnly mode via this script after reviewing
# your logs changing 0 to 1 will enable blocking.
TestOnly = 0

Header_Type = SPF

HELO_reject = Fail
Mail_From_reject = Fail

PermError_reject = False
TempError_Defer = False

Hide_Receiver = Yes

skip_addresses = 127.0.0.0/8,::ffff:127.0.0.0/104,::1

Reason_Message = Message {rejectdefer} due to: {spf}. Please see {url}.
EOF

# OpenDKIM

# A lot of the big name email services, like Google, will automatically
# reject mark as spam unfamiliar and unauthenticated email addresses. As in, the
# server will flatly reject the email, not even delivering it to someone's
# Spam folder.

# OpenDKIM is a way to authenticate your email so you can send to such services
# without a problem.

# Create an OpenDKIM key in the proper place with proper permissions.
echo "Generating openDKIM keys..."
mkdir -p /etc/postfix/dkim
opendkim-genkey -D /etc/postfix/dkim/ -d "$domain" -s default -v
chgrp -R opendkim /etc/postfix/dkim/*
chmod -R g+r /etc/postfix/dkim/*
chmod o+r /etc/postfix/dkim/default.txt

# Generate the OpenDKIM info...
echo "Configuring openDKIM..."
grep -q "$domain" /etc/postfix/dkim/keytable 2>/dev/null ||
echo "default._domainkey.$domain $domain:default:/etc/postfix/dkim/default.private" >> /etc/postfix/dkim/keytable

grep -q "$domain" /etc/postfix/dkim/signingtable 2>/dev/null ||
echo "*@$domain default._domainkey.$domain" >> /etc/postfix/dkim/signingtable

grep -q "127.0.0.1" /etc/postfix/dkim/trustedhosts 2>/dev/null || echo "localhost
127.0.0.1
mail.$domain
$domain
*.$domain" >> /etc/postfix/dkim/trustedhosts

# TODO: refactor openDKIM configuration initialization.
# ...and source it from opendkim.conf
grep -q "^KeyTable" /etc/opendkim.conf 2>/dev/null || echo "KeyTable file:/etc/postfix/dkim/keytable
SigningTable refile:/etc/postfix/dkim/signingtable
InternalHosts refile:/etc/postfix/dkim/trustedhosts" >> /etc/opendkim.conf

sed -i '/Socket/s/^#*/#/' /etc/opendkim.conf
sed -i '0,/^#Socket\t\t\tlocal.*/s//Socket\t\t\tinet:12301@localhost/' /etc/opendkim.conf

# OpenDKIM daemon settings, removing previously activated socket.
sed -i '/SOCKET/s/^#*/#/' /etc/default/opendkim
echo "SOCKET=inet:12301@localhost" >> /etc/default/opendkim

# Generate the OpenDMARC info...
echo "Configuring openDMARC..."

sed -e '/^.[[:alpha:]]*/ s/^#*/#/' -i.bak /etc/opendmarc.conf
cat >> /etc/opendmarc.conf << EOF
# Local config /etc/opendmarc.conf
Socket						inet:8893@localhost
AuthservID					OpenDMARC
TrustedAuthservIDs			$maildomain
UserID						opendmarc
PidFile						/run/opendmarc/opendmarc.pid
RejectFailures				false
Syslog						true
IgnoreAuthenticatedClients	true
RequiredHeaders				true
SPFSelfValidate				true
EOF

mkdir -p /var/spool/postfix/opendmarc
chown opendmarc:opendmarc /var/spool/postfix/opendmarc -R
chmod 750 /var/spool/postfix/opendmarc -R
usermod -a -G opendmarc postfix

# Generate pwhois service...
echo "Configuring pwhois_milter..."
cat >> /etc/systemd/system/pwhois.service << EOF
[Unit]
Description=Prefix Whois Postfix Milter
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/local/sbin/pwhois_milter.sh

[Install]
WantedBy=multi-user.target
EOF

pwhois_dir="$source/pwhois_milter_v1.5.1/"
make -C $pwhois_dir && make -C $pwhois_dir install || echo "ERROR: building pwhois_milter"
cp $pwhois_dir/init-scripts/systemd/pwhois_milter.sh /usr/local/sbin/
chmod +x /usr/local/sbin/pwhois_milter.sh

# Here we add to postconf the needed settings for working with OpenDKIM
echo "Configuring Postfix with OpenDKIM settings..."
postconf -e "milter_default_action = accept"
postconf -e "milter_protocol = 6"
postconf -e "smtpd_milters = inet:localhost:12301, inet:localhost:3356, inet:localhost:8893"
postconf -e "non_smtpd_milters = inet:localhost:12301"
postconf -e "mailbox_command = /usr/lib/dovecot/deliver"

# Spamassassin setting and configuration.
# Enable SpamAssassin update cronjob.
# sed -i "s|^CRON=0|CRON=1|" /etc/default/spamassassin

mkdir "/var/log/spamassassin"
SAHOME="/var/lib/spamassassin"
echo "OPTIONS=\"--create-prefs --max-children 5 --username debian-spamd --helper-home-dir ${SAHOME} -s /var/log/spamassassin/spamd.log\"
CRON=1" >> /etc/default/spamassassin

cp /etc/spamassassin/local.cf /etc/spamassassin/local.cf.bak
echo "rewrite_header Subject [***** SPAM _SCORE_ *****]
report_safe             2
required_score          5.0
use_bayes               1
bayes_auto_learn        1
skip_rbl_checks			1

header		DMARC_FAIL	Authentication-Results =~ /dmarc=fail/
describe	DMARC_FAIL	The email failed DMARC checks.
score		DMARC_FAIL	3.0
" > /etc/spamassassin/local.cf

sed -e '/SPF/s/^#*/#/;/URIDNSBL/s/^#*/#/' -i.bak /etc/spamassassin/init.pre

# Add certbot deploy hook to restart postfix and dovecot.
# echo "#deploy-hook = service postfix restart && service dovecot restart" >> /etc/letsencrypt/cli.ini
sed -i "/^ExecStart/s/$/ --deploy-hook = 'systemctl reboot'/" /lib/systemd/system/certbot.service

# A fix for "Opendkim won't start: can't open PID file?", as specified here: https://serverfault.com/a/847442
/lib/opendkim/opendkim.service.generate
systemctl daemon-reload

# Restarting services to reload configs and generate log files.
for n in dovecot.service postfix.service opendkim.service spamd.service certbot.timer fail2ban.service pwhois.service; do
	printf "Enabling & Restarting %s..." "$n"
	systemctl enable "$n" && systemctl restart "$n" && printf " ...done\\n"
done

# Generating DNS txt entries.  See README.md for additional DNS service records and further information.
pval="$(tr -d "\n" </etc/postfix/dkim/default.txt | sed "s/k=rsa.* \"p=/k=rsa; p=/;s/\"\s*\"//;s/\"\s*).*//" | grep -o "p=.*")"
dkimentry="default._domainkey	TXT		v=DKIM1; k=rsa; $pval"
dmarcentry="_dmarc	TXT		v=DMARC1; p=quarantine; rua=mailto:dmarc@$domain; fo=1"
spfentry="@		TXT		v=spf1 mx a:$domain -all"
mxentry="$domain	MX	10	$maildomain	300"

echo "Checking user groups..."
getent group mail | grep "$sudoer" && echo "$sudoer in mail group." || usermod -a -G mail "$sudoer" \
	&& echo "Adding $sudoer to mail group."
useradd -m -G mail dmarc
echo "Adding dmarc user to mail group."

echo -e "$dkimentry \n
$dmarcentry \n
$mxentry \n
$spfentry" >> "/etc/postfix/dns_txt_records"

cat << EOF
*******************************************************************************
*******************************************************************************

    ATTENTION: Add these records to your DNS records on your registrar's site.

*******************************************************************************
*******************************************************************************

$dkimentry

$dmarcentry

$mxentry

$spfentry

Records also saved to /etc/postfix/dns_txt_records or later reference.

Once you do that, you're done! Check the README for how to add users/accounts
and how to log in.

Note also recommended to reboot server and check that all services."
EOF

# Included in this git repo I have also included copies of the EICAR and GTUBE
# text files that can be used to check antivirus and spam filters.

# vim: ft=sh:
