# email_server.standalone

This script will setup an email server on a Debian 12 Bookworm.  Support for Ubuntu
and Debian < 12 has been dropped.  Please reader this *README.md* and the script's
comments before running it.  There are steps that **must** be taken before running
the script.

**Read this readme and the script's comments before running it.**

When prompted by the dialog menu at the beginning of the postfix install, select
*"Internet Site"*, then give your single fully qualified domain name ie.
`domain.com` **not** `mail.domain.com`.  You will be prompted again later in the
installation process and asked about setting up a database for *openDMARC*
select **NO**.  The database is used for generating reports for other mailbox
providers and is not needed for the verification of your domain.

# Server requirements.

A server with 1GB RAM and 1vCPU is sufficient for the default configuration.  If
SPAMASSASSIN is not used a server with 0.5GB RAM is sufficient, bandwidth and
storage limits are dependent on mail volume(including attachments).

If you plan on adding antivirus scanning to your server you will need to increase
your ram to at least >= 2GB.

## Certbot

Make sure your DNS records are updated before running _certbot_ you can use the
`whois` command to verify that any changes you've made have been propagated
otherwise you will receive and error from _certbot_.  Also before you run the script
your SSL Certificate must be obtained.  This can be done but running this
command.

#### Testing Certificates
`sudo certbot certonly --standalone -d mail.domain.com
--register-unsafely-without-email --agree-tos --test-cert`

#### Production Certificates
`sudo certbot certonly --standalone -d mail.domain.com`


It is also recommended that you add a `--deploy-hook` to your *Certbot* renewal service.
On Debian it is located at `/lib/systemd/system/certbot.service`.  You just need
to modify the line to `ExecStart=/usr/bin/certbot -q renew --deploy-hook 'systemctl reboot'`.

***IMPORTANT*** Certbot uses short term certificates that expire every 90 days.
The Certbot package installs a systemd timer and service that can used to
automate the renewal or a simple cron job can be used.  Certbot needs to answer
a cryptographic challenge issued by the Let\’s Encrypt API in order to prove
control of the domain. It uses ports 80 (HTTP) or 443 (HTTPS) to accomplish this,
ensure one or both of these ports is open in your firewall.

## Firewall (ufw)

Common configuration for UFW firewall allow on both ip4 & ipv6. *(Note port 80
open to allow automated cert renewal via certbot.)*

- 22/tcp
- 80,443/tcp (WWW Full)
- 587/tcp (Mail submission)
- 993/tcp (IMAPS)
- 143/tcp (IMAP)
- 25/tcp (SMTP)
- 465/tcp

## This script installs.

- **Postfix** to send and receive mail.
- **Dovecot** to get mail to your email client (mutt, Thunderbird, etc).
- **Spamassassin** to prevent spam and allow you to make custom filters.
- **pwhois_milter_v1.5.1** to help know where your emails are coming from.
- **OpenDKIM** to validate you so you can send to Gmail and other big sites.
- **OpenDMARC** to validate your domain and prevent spoofing.
- **Policyd-spf-python** to help prevent spoofing and phishing attacks.
- **Fail2ban** to help secure the server and block brute force attacks.
- **DNSBLs** blacklists enforced by postfix-postscreen and Spamassassin.
- **Logrotate** configs where needed for the installed packages.

## Server security

  This script sets some **baselevel** security in the way of _Fail2ban_, _TLS_,
  _SPF_, _Spamassassin_, and _DNSBLs_ but you most have secure passwords and
  proper configs for this to make any difference.  The default configs for
  _Fail2ban_ and _Spamassassin_ in this script setup a reasonable baseline but
  if your going to run your own email server or web server you have to maintain
  your own security.  The idea that some no name website or single email server
  won't be worth attacking like I have see and heard others say is just
  **wrong** most of these attacks are preformed by bots with little to no human
  interaction.  Logins must **not** contain any combination of dictionary words
  and or names.  And **must** be at least 9 characters long and contain special
  characters.  Equal to or greater than 11 characters recommended.

  The _Spamassassin_ default config for versions >= 3.0 has **URIDNSBL** enabled by
  default but we will be using _postfix-postscreen_ to check against DNSBLs before
  the email is even accepted by postfix.  This will help reduce the load on
  server resources and also help prevent backscatter.

  The _Fail2ban_ configs setup several jails _sshd_, _dovecot_, _postfix_,
  _postfix-postscreen_ (Not covered by postfix aggressive mode) and _recidive_
  and _recidive-subnet_ these along with _SPF_ checking instituted via postfix
  provides a wide array of not only spam blocking but also general server security
  and also a good baselevel of email server security.

##  Requirements

 1. A **Debian 12 Bookworm**. I've tested this on a
    [Vultr](https://www.vultr.com/?ref=8637959) Debian 12 servers and servers running
    Ubuntu 20.04LTS but Debian < 12 and Ubuntu are no longer supported officially
    supported.
 2. **A Let's Encrypt SSL certificate for your domain.** This is where the
	script departs from others.  You will **NOT** need to create an Nginx or
    Apache server and setup a placeholder website.  We will be using a standalone SSL
    certificate from Let's Encrypt [Certbot](https://certbot.eff.org/).
 3. You need to set up some minimal DNS records for **A RECORD**, **MX**, and
    **AAAA** if your planning on using IPV6.
 4. **A Reverse DNS entry for your server.** Go to your VPS settings and add an
    entry for your IPV4 Reverse DNS that goes from your IP address to
    `mail.<yourdomain.com>`. If your using IPV6, you can do the same for
    that. This has been tested on Vultr, and all decent VPS hosts will have
    a section on their instance settings page to add a reverse rDNS entry.
    You can use the 'Test Email Server' or 'smtp' tool on
    [mxtoolbox](https://mxtoolbox.com/SuperTool.aspx) to test if you set up
    a reverse DNS correctly. Most large email services like gmail and Outlook
    will stop emails coming from mail servers without a invalid rDNS lookup.
    This means your email will fail to even make it to the recipients spam folder.
 5. `apt purge` all your previous (failed) attempts to install and configure a
    mailserver. Get rid of _all_ your system settings for Postfix, Dovecot,
    OpenDKIM and everything else. This script builds off of a fresh install.
 6. Most VPS providers block port 25 by default to prevent spammers from using
    there services to send out bulk emails. If this is the case with your VPS
    provider simple open a support ticket requesting to have port 25 opened.
    You may have to answer a few questions about the volume of mail you predict
    to send/receive but as long as your not planning on spamming or having an
    open relay there should be no issue.
 7. **Set System Timezone** most if not all VPS providers by default have the
    timezone set for Universal Time UTC but for logging reasons and to have easily
    readable timestamps I recommend changing your timezone to suite your
    locale.  This can be done easily with the `timedatectl` command and will
    make your life much easier when it comes to reading logs and should the need
    arise debugging any issues.

## Post-install requirement!

- After the script runs, you'll have to add additional DNS TXT records which
  are displayed at the end when the script is complete. They will help ensure
  your mail is validated and secure.

- Certbot renewal is automatically enabled on systems using the systemd init
  system.  Otherwise a simple crontab will work but you also need to make sure
  you restart your server after renewal, the new certificate is not applied until
  either reboot or system services restart.  As mentioned above I recommend
  using a `--deply-hook` to automatically restart your sever when new certificates
  have been deployed.

- It is also highly recommended to generate a postscreen_access.cidr file and
  add your servers public ip address/adresses.  This file should be located at
  `/etc/postfix/postscreen_access.cidr`.

## DNS/rDNS records.

- A/AAAA RECORD mail.doamin.com IP ADDRESS
- MX RECORD @ mail.domain.com

- Auto discovery DNS service records.

| Service     | Protocol | Priority | Weight | Port | Target          | Description    |
-----|-----|------|-----|-------|-------|-------|
| _imaps      | _tcp     | 0        | 1      | 993  | mail.domain.com | Encrypted IMAP |
| _smtps      | _tcp     | 0        | 1      | 465  | mail.domain.com | Encrypted SMTP |
| _submission | _tcp     | 0        | 1      | 587  | mail.domain.com | Submissions    |

*Reverse DNS* records need to be set with your VPS provider most have a placeholder
in your account dashboard.  If you are using a home based server *not* recommended
then your ISP will need to set your rDNS.

## Making new users/mail accounts.

`useradd -m -s /bin/bash -G sudo,mail <USERNAME>`
`passwd <USERNAME>`

Try to avoid '{(' in password if you use neomutt.

This will create a new user *<USERNAME>* with the email address *<USERNAME>@domain.com*.

## Setting aliases.

- SMTP/RFC mandate that any publicly accessible mail server that accepts any mail
  at all must also except mail at the *"postmaster"* account and some might also
  expect *"hostmaster", "abuse", "webmaster"* and others.  You can either
  redirect those address to root or a specific user.  I have supplied a list of
  common aliases that are usually expected on most mail servers in the basic
  config.  I suggest redirecting them all to *"root"* and then redirecting
  *"root"* to your main account **(this is how I have set up the aliases file)**.

- Additional aliases maybe added to the `/etc/aliases` file to redirect mail to
  any account.  If you decide to add additional aliases make sure to run the
  `newaliases` command with sudo privileges afterwords.

## Logging in from an MUA (ie. mutt, neomutt, ect.) remotely.

Let's say you want to access your mail with Thunderbird or mutt or another
email program. For my domain, the server information will be as follows:

- SMTP server: `mail.domain.com`
- SMTP port: 587
- SMTP STARTTLS
- IMAP server: `mail.domain.com`
- IMAP port: 993
- IMAP TLS/SSL
- Username `user` (ie. *not* `user@domain.com`)

## Troubleshooting -- Can't send mail?

- Check logs ie. `mail.log` and `mail.err` to see the specific problem.
- Go to [this site](https://appmaildev.com/en/dkim) to test your TXT records.
  If your DKIM, SPF or DMARC tests fail you probably copied in the TXT records
  incorrectly.
- If everything looks good and you *can* send mail, but it still goes to Gmail
  or another big provider's spam directory, your domain (especially if it's a
  new one) might be on a public spam list.  Check
  [this site](https://mxtoolbox.com/blacklists.aspx) to see if it is. Don't
  worry if you are: sometimes especially new domains are automatically assumed
  to be spam temporally. If you are blacklisted by one of these, look into it
  and it will explain why and how to remove yourself.
- Two useful tools will be `postconf -d` and `postconf -n` they will list the
  default and currently set *Postfix* settings.  *Remember any changes to either
  Postfix Dovecot or Fail2ban will not take effect until that service is
  restarted*.
- [This site](https://www.mail-tester.com) is also excellent to test your new
  server.
- If your server works fine and then just stops one day confirm your SSL Certificates
  have not expired.  This seems to be the most common issue letsencrypt will
  automatically update the certificates but the system must be rebooted or
  services restarted to have those certificates applied.

## Mailbox location and format.

 Mail will be stored in Maildir form in the home directory in \$home/Mail.  This
 makes it easier for use with offline sync ie. offlineimap or isync(mbsync).

 The mailbox names are: Inbox, Sent, Drafts, Archive, Junk(Spam), Trash these are
 fairly standard names but can be changed to your liking, but if your planning
 on having more then one account or sync with other imap servers I recommend
 staying with this naming convention.

 Use the typical unix login system for mail users. Users will log into their
 email with their system username and password on the server. No usage of a
 redundant mySQL database to do this.

## Server updating/maintenance.

Enabling automatic updates is recommended.  This can be done by installing the
the `unattended-upgrades` package and editing the `/etc/apt/apt.conf.d/50unattended-upgrades`
and `/etc/apt/apt.conf.d/20auto-upgrades` files.  The default settings should
be sufficient but you may want to change the `Unattended-Upgrade::Automatic-Reboot`
and `Unattended-Upgrade::Automatic-Reboot-Time` settings to allow automatic
reboots at off peak hours. It is also recommended to install the `needrestart`
package to help identify services that need to be restarted after updates.

# News/Updates (Debian 12 Bookworm)

Moving forward this script will be moved to Debian 12 Bookworm exclusively.  This
means as of October 1, 2023 Ubuntu 18.04LTS and Debian < 12 will no longer be
supported.  The biggest breaking changes come from Fail2ban and Postfix.  Fail2ban
has been updated to version 1.0.2 and Postfix has been updated to version 3.7.

### News

Added ***pwhois_milter_v1.5.1*** so you can see where your emails are coming from.
This can easily be disabled by removing the `pwhois_milter` entry from the
smtps_milters entry in `/etc/postfix/main.cf`.  But I have found it to be a very
useful addition and the extra overhead is minimal.  Also the configuration is
setup to strip the *whois headers* from any reply's or forwards.  So there is no
concern about leaking any information about your server or ip address.

Added ***recidive-subnet*** jail to Fail2ban.  Subnet banning is officially supported
and enabled by default.
