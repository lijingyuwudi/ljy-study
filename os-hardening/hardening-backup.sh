#!/bin/bash
if [ ! -d "/opt/hardening_backup/" ]; then
mkdir -p /opt/hardening_backup/
fi

cp /etc/fstab /opt/hardening_backup/
cp /etc/modprobe.d/CIS.conf /opt/hardening_backup/
cp /etc/crontab /opt/hardening_backup/
cp /boot/grub2/grub.cfg /opt/hardening_backup/
cp -r /boot/grub2/ /opt/hardening_backup/
cp /etc/security/limits.conf /opt/hardening_backup/
cp /etc/sysctl.conf /opt/hardening_backup/
cp /etc/ntp.conf /opt/hardening_backup/
cp /etc/sysconfig/ntpd /opt/hardening_backup/
cp /etc/postfix/main.cf /opt/hardening_backup/
cp /etc/sysctl.d/infra-tuning.conf /opt/hardening_backup/
cp /etc/hosts.allow /opt/hardening_backup/
cp /etc/hosts.deny /opt/hardening_backup/
cp /etc/default/grub /opt/hardening_backup/
cp /etc/audit/audit.rules /opt/hardening_backup/
cp /etc/rsyslog.conf /opt/hardening_backup/
cp -r /etc/rsyslog.d/*.conf /opt/hardening_backup/
cp /etc/ssh/sshd_config /opt/hardening_backup/
cp /etc/security/pwquality.conf /opt/hardening_backup/
cp /etc/pam.d/password-auth /opt/hardening_backup/
cp /etc/pam.d/system-auth /opt/hardening_backup/
cp /etc/login.defs /opt/hardening_backup/
cp /etc/passwd /opt/hardening_backup/
cp /etc/bashrc /opt/hardening_backup/
cp /etc/profile /opt/hardening_backup/
cp /etc/securetty /opt/hardening_backup/
cp /etc/pam.d/su /opt/hardening_backup/
cp /etc/group /opt/hardening_backup/
cp /usr/lib/systemd/system/tmp.mount /opt/hardening_backup/
#cp /etc/systemd/system/local-fs.target.wants/tmp.mount /opt/hardening_backup/
cp /etc/motd /opt/hardening_backup/
cp /etc/issue /opt/hardening_backup/
cp /etc/issue.net /opt/hardening_backup/
cp /etc/audit/auditd.conf /opt/hardening_backup/
#cp /etc/cron.deny /opt/hardening_backup/
#cp /etc/at.deny /opt/hardening_backup/
