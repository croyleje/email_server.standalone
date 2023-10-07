#!/bin/bash
# This script removes all generated configs including but not limited to /etc/fail2ban/jail.local
# and /etc/postfix/postscreen_access.cidr.  This script should only be used when doing testing your final
# install should be done starting from a freshly updated clean install of Debian
# 12 Bookworm.

[ $EUID -ne 0 ] && echo "ERROR: removal script must be run with SUDO or as root user." && exit

apt purge postfix postfix-pcre dovecot-imapd dovecot-sieve opendkim opendkim-tools spamassassin spamc fail2ban postfix-policyd-spf-python opendmarc

rm -rf /etc/postfix /var/lib/postfix /etc/dovecot /var/lib/dovecot /etc/spamassassin /var/lib/spamassassin /etc/postfix-policyd-spf-python /etc/fail2ban /root/.spamassassin /var/log/spamassassin /etc/opendkim.conf /etc/opendmarc.conf
