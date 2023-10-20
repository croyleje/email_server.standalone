#!/bin/bash
# Imapsync is a tool for syncing/migrating IMAP mailboxes. For further
# information.  See the link below.

# https://github.com/imapsync/imapsync

# This simple script will sync two IMAP servers and report the results to
# destination "Inbox". It is not intended to be used as a cron job, but rather
# run as a one off after migrating mailboxes/servers.

# User is the email username not the full email address ie. default not
# default@domain.com.

# Server can be either the FQDN or the IP address of the server.

# TLS/SSL on by default when available.
# If you prefer to force a connection without TLS/SSL use the --notls1 and/or
# --notls2 flags.

# The --passfile1 and --passfile2 flags can be used to specify a file that
# contains the password for the user.  This can be useful if you are running
# via cron job and don't want to expose the password in the command line.  Make
# sure the password contains the password on the first line of the file and the
# file has permissions set to (600 or rw-------).

imapsync \
	--syncinternaldates --nosyncacls --emailreport2 --dry \
	--host1 <server> --user1 <user> --password1 <password> \
	--host2 <server> --user2 <user> --password2 <password>

# vim: set ft=sh:
