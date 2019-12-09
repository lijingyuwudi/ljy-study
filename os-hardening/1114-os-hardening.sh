#!/bin/bash

set -x

echo 'install cramfs /bin/true' >> /etc/modprobe.d/CIS.conf
rmmod cramfs
echo -e "[\033[32m OK \033[0m] 1.1.1.1 	Ensure mounting of cramfs filesystems is disabled (Scored) "

echo 'install freevxfs /bin/true' >> /etc/modprobe.d/CIS.conf
rmmod freevxfs
echo -e "[\033[32m OK \033[0m] 1.1.1.2 	Ensure mounting of freevxfs filesystems is disabled (Scored) "
 	

echo 'install jffs2 /bin/true' >> /etc/modprobe.d/CIS.conf
rmmod jffs2
echo -e "[\033[32m OK \033[0m] 1.1.1.3 	Ensure mounting of jffs2 filesystems is disabled (Scored) "

echo 'install hfs /bin/true' >> /etc/modprobe.d/CIS.conf
rmmod hfs
echo -e "[\033[32m OK \033[0m] 1.1.1.4 	Ensure mounting of hfs filesystems is disabled (Scored) "

echo 'install hfsplus /bin/true' >> /etc/modprobe.d/CIS.conf
rmmod hfsplus
echo -e "[\033[32m OK \033[0m] 1.1.1.5 	Ensure mounting of hfsplus filesystems is disabled (Scored) "

echo 'install squashfs /bin/true' >> /etc/modprobe.d/CIS.conf
rmmod squashfs
echo -e "[\033[32m OK \033[0m] 1.1.1.6 	Ensure mounting of squashfs filesystems is disabled (Scored) "

echo 'install udf /bin/true' >> /etc/modprobe.d/CIS.conf
rmmod udf
echo -e "[\033[32m OK \033[0m] 1.1.1.7 	Ensure mounting of udf filesystems is disabled (Scored) "

#echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
#rmmod vfat
#echo -e "[\033[32m OK \033[0m] 1.1.1.8 	Ensure mounting of fat filesystems is disabled (Scored) "

mount -o remount,noexec /dev/shm
echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
echo -e "[\033[32m OK \033[0m] 1.1.17 	Ensure noexec option set on /dev/shm partition (Scored) "

yum install -y aide
echo -e "[\033[32m OK \033[0m] 1.3.1 	Ensure AIDE is installed (Scored) "

echo '0 5 * * * /usr/sbin/aide --check' >> /etc/crontab
echo -e "[\033[32m OK \033[0m] 1.3.2 	Ensure filesystem integrity is regularly checked (Scored) "

chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg
touch /boot/grub2/user.cfg
chown root:root /boot/grub2/user.cfg
chmod og-rwx /boot/grub2/user.cfg
echo -e "[\033[32m OK \033[0m] 1.4.1 	Ensure permissions on bootloader config are configured (Scored) "

echo '* hard core 0' >> /etc/security/limits.conf
#echo '/etc/sysctl.conf' >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0
echo -e "[\033[32m OK \033[0m] 1.5.1 	Ensure core dumps are restricted (Scored) "

echo -e "[\033[32m OK \033[0m] 1.5.2 	Ensure XD/NX support is enabled (Not Scored) " 

echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.conf
sysctl -w kernel.randomize_va_space=2
echo -e "[\033[32m OK \033[0m] 1.5.3 	Ensure address space layout randomization (ASLR) is enabled (Scored) "

chown root:root /etc/motd
chmod 644 /etc/motd
echo -e "[\033[32m OK \033[0m] 1.7.1.4 	Ensure permissions on /etc/motd are configured (Not Scored) "

chown root:root /etc/issue.net
chmod 644 /etc/issue.net
echo -e "[\033[32m OK \033[0m] 1.7.1.6 	Ensure permissions on /etc/issue.net are configured (Not Scored) "

sed -i 's/^restrict default.*/restrict -4 default kod nomodify notrap nopeer noquery\nrestrict -6 default kod nomodify notrap nopeer noquery/' /etc/ntp.conf
sed -i 's/\(^OPTIONS="\).*"/\1-u ntp:ntp"/' /etc/sysconfig/ntpd
echo -e "[\033[32m OK \033[0m] 2.2.1.2 	Ensure ntp is configured (Scored) "

sed -i 's/\(^inet_interfaces = \).*/\1loopback-only/' /etc/postfix/main.cf
systemctl restart postfix
echo -e "[\033[32m OK \033[0m] 2.2.15 	Ensure mail transfer agent is configured for local-only mode (Scored) "

yum remove -y telnet
echo -e "[\033[32m OK \033[0m] 2.3.4 	Ensure telnet client is not installed (Scored) "

echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.default.accept_redirects = 0' >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
echo -e "[\033[32m OK \033[0m] 3.2.2 	Ensure ICMP redirects are not accepted (Scored) "

echo 'net.ipv4.conf.all.secure_redirects = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.default.secure_redirects = 0' >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
echo -e "[\033[32m OK \033[0m] 3.2.3 	Ensure secure ICMP redirects are not accepted (Scored) "

echo 'net.ipv4.conf.all.log_martians = 1' >> /etc/sysctl.conf
echo 'net.ipv4.conf.default.log_martians = 1' >> /etc/sysctl.conf
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1
echo -e "[\033[32m OK \033[0m] 3.2.4 	Ensure suspicious packets are logged (Scored)"

echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1' >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
echo -e "[\033[32m OK \033[0m] 3.2.5 	Ensure broadcast ICMP requests are ignored (Scored) "

echo 'net.ipv4.icmp_ignore_bogus_error_responses = 1' >> /etc/sysctl.conf
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.route.flush=1
echo -e "[\033[32m OK \033[0m] 3.2.6 	Ensure bogus ICMP responses are ignored (Scored) "

echo 'net.ipv4.conf.all.rp_filter = 1' >> /etc/sysctl.conf
echo 'net.ipv4.conf.default.rp_filter = 1' >> /etc/sysctl.conf
sed -i 's/\(^net\.ipv4\.conf\.default\.rp_filter=\).*/\11/' /etc/sysctl.d/infra-tuning.conf
sed -i 's/\(^net\.ipv4\.conf\.all\.rp_filter=\).*/\11/' /etc/sysctl.d/infra-tuning.conf
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
echo -e "[\033[32m OK \033[0m] 3.2.7 	Ensure Reverse Path Filtering is enabled (Scored) "

echo 'net.ipv6.conf.all.accept_ra = 0' >> /etc/sysctl.conf
echo 'net.ipv6.conf.default.accept_ra = 0' >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1
echo -e "[\033[32m OK \033[0m] 3.3.1 	Ensure IPv6 router advertisements are not accepted (Not Scored) "

echo 'net.ipv6.conf.all.accept_redirects = 0' >> /etc/sysctl.conf
echo 'net.ipv6.conf.default.accept_redirects = 0' >> /etc/sysctl.conf
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1
echo -e "[\033[32m OK \033[0m] 3.3.2 	Ensure IPv6 redirects are not accepted (Not Scored) "

# 该操作会导致k8s基础组件故障
# sed -i 's/\(^GRUB_CMDLINE_LINUX="\)\(.*\)"$/\1\2 ipv6.disable=1"/' /etc/default/grub
# grub2-mkconfig > /boot/grub2/grub.cfg
# echo -e "[\033[32m OK \033[0m] 3.3.3 	Ensure IPv6 is disabled (Not Scored) "

# 待客户确定
echo "ALL: ALL" >> /etc/hosts.allow
#viper ip
#echo "ALL:10.28.168.0/24" >> /etc/hosts.allow
#echo "ALL:10.28.129.0/24" >> /etc/hosts.allow
#echo "ALL:10.30.49.0/24" >> /etc/hosts.allow

#customer ip
#echo "ALL:192.168.168.0/23" >> /etc/hosts.allow
#echo "ALL:192.168.170.0/24" >> /etc/hosts.allow
#echo "ALL:192.168.171.0/24" >> /etc/hosts.allow
#echo "ALL:192.168.172.0/24" >> /etc/hosts.allow
#echo "ALL:10.31.90.0/24" >> /etc/hosts.allow
#echo "ALL:10.31.91.0/24" >> /etc/hosts.allow
#echo "ALL:10.31.98.0/24" >> /etc/hosts.allow
#echo "ALL:10.31.99.0/24" >> /etc/hosts.allow
echo -e "[\033[32m OK \033[0m] 3.4.2 	Ensure /etc/hosts.allow is configured (Scored)" 

# 待客户确定
echo "ALL: ALL" >> /etc/hosts.deny
echo -e "[\033[32m OK \033[0m] 3.4.3 	Ensure /etc/hosts.deny is configured (Scored) "

echo 'install dccp /bin/true' >> /etc/modprobe.d/CIS.conf
echo -e "[\033[32m OK \033[0m] 3.5.1 	Ensure DCCP is disabled (Not Scored) "

echo 'install sctp /bin/true' >> /etc/modprobe.d/CIS.conf
echo -e "[\033[32m OK \033[0m] 3.5.2 	Ensure SCTP is disabled (Not Scored) "

echo 'install rds /bin/true' >> /etc/modprobe.d/CIS.conf
echo -e "[\033[32m OK \033[0m] 3.5.3 	Ensure RDS is disabled (Not Scored) "

echo 'install tipc /bin/true' >> /etc/modprobe.d/CIS.conf
echo -e "[\033[32m OK \033[0m] 3.5.4 	Ensure TIPC is disabled (Not Scored) "

sed -i 's/\(^GRUB_CMDLINE_LINUX="\)\(.*\)"$/\1\2 audit=1"/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg
echo -e "[\033[32m OK \033[0m] 4.1.3 	Ensure auditing for processes that start prior to auditd is enabled (Scored) "

echo '-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change' >> /etc/audit/rules.d/audit.rules 
echo '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change' >> /etc/audit/rules.d/audit.rules 
echo '-a always,exit -F arch=b64 -S clock_settime -k time-change' >> /etc/audit/rules.d/audit.rules 
echo '-a always,exit -F arch=b32 -S clock_settime -k time-change' >> /etc/audit/rules.d/audit.rules 
echo '-w /etc/localtime -p wa -k time-change' >> /etc/audit/rules.d/audit.rules
echo -e "[\033[32m OK \033[0m] 4.1.4 	Ensure events that modify date and time information are collected (Scored) "

echo '-w /etc/group -p wa -k identity' >> /etc/audit/rules.d/audit.rules  
echo '-w /etc/passwd -p wa -k identity' >> /etc/audit/rules.d/audit.rules  
echo '-w /etc/gshadow -p wa -k identity' >> /etc/audit/rules.d/audit.rules 
echo '-w /etc/shadow -p wa -k identity ' >> /etc/audit/rules.d/audit.rules 
echo '-w /etc/security/opasswd -p wa -k identity' >> /etc/audit/rules.d/audit.rules 
echo -e "[\033[32m OK \033[0m] 4.1.5 	Ensure events that modify user/group information are collected (Scored) "

echo '-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale' >> /etc/audit/rules.d/audit.rules 
echo '-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale' >> /etc/audit/rules.d/audit.rules  
echo '-w /etc/issue -p wa -k system-locale' >> /etc/audit/rules.d/audit.rules  
echo '-w /etc/issue.net -p wa -k system-locale' >> /etc/audit/rules.d/audit.rules  
echo '-w /etc/hosts -p wa -k system-locale' >> /etc/audit/rules.d/audit.rules  
echo '-w /etc/sysconfig/network -p wa -k system-locale' >> /etc/audit/rules.d/audit.rules  
echo '-w /etc/sysconfig/network-scripts/ -p wa -k system-locale' >> /etc/audit/rules.d/audit.rules 
echo -e "[\033[32m OK \033[0m] 4.1.6 	Ensure events that modify the system's network environment are collected (Scored)"

echo '-w /etc/selinux/ -p wa -k MAC-policy' >> /etc/audit/rules.d/audit.rules  
echo '-w /usr/share/selinux/ -p wa -k MAC-policy' >> /etc/audit/rules.d/audit.rules   
echo -e "[\033[32m OK \033[0m] 4.1.7 	Ensure events that modify the system's Mandatory Access Controls are collected (Scored) "

echo '-w /var/log/lastlog -p wa -k logins' >> /etc/audit/rules.d/audit.rules   
echo '-w /var/run/faillock/ -p wa -k logins' >> /etc/audit/rules.d/audit.rules  
echo -e "[\033[32m OK \033[0m] 4.1.8 	Ensure login and logout events are collected (Scored) "

echo '-w /var/run/utmp -p wa -k session' >> /etc/audit/rules.d/audit.rules   
echo '-w /var/log/wtmp -p wa -k logins' >> /etc/audit/rules.d/audit.rules   
echo '-w /var/log/btmp -p wa -k logins' >> /etc/audit/rules.d/audit.rules  
echo -e "[\033[32m OK \033[0m] 4.1.9 	Ensure session initiation information is collected (Scored) "

echo '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/rules.d/audit.rules
echo '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' >> /etc/audit/rules.d/audit.rules
echo -e "[\033[32m OK \033[0m] 4.1.10 	Ensure discretionary access control permission modification events are collected (Scored) "

echo '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access' >> /etc/audit/rules.d/audit.rules 
echo '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access' >> /etc/audit/rules.d/audit.rules 
echo '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access' >> /etc/audit/rules.d/audit.rules 
echo '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access' >> /etc/audit/rules.d/audit.rules
echo -e "[\033[32m OK \033[0m] 4.1.11 	Ensure unsuccessful unauthorized file access attempts are collected (Scored) "

find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' >> /etc/audit/rules.d/audit.rules
echo -e "[\033[32m OK \033[0m] 4.1.12 	Ensure use of privileged commands is collected (Scored) "

echo '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts' >> /etc/audit/rules.d/audit.rules 
echo '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts' >> /etc/audit/rules.d/audit.rules
echo -e "[\033[32m OK \033[0m] 4.1.13 	Ensure successful file system mounts are collected (Scored) "

echo '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete' >> /etc/audit/rules.d/audit.rules  
echo '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete' >> /etc/audit/rules.d/audit.rules 
echo -e "[\033[32m OK \033[0m] 4.1.14 	Ensure file deletion events by users are collected (Scored) "

echo '-w /etc/sudoers -p wa -k scope' >> /etc/audit/rules.d/audit.rules  
echo '-w /etc/sudoers.d/ -p wa -k scope' >> /etc/audit/rules.d/audit.rules 
echo -e "[\033[32m OK \033[0m] 4.1.15 	Ensure changes to system administration scope (sudoers) is collected (Scored) "

echo '-w /var/log/sudo.log -p wa -k actions' >> /etc/audit/rules.d/audit.rules 
echo -e "[\033[32m OK \033[0m] 4.1.16 	Ensure system administrator actions (sudolog) are collected (Scored) "

echo '-w /sbin/insmod -p x -k modules' >> /etc/audit/rules.d/audit.rules   
echo '-w /sbin/rmmod -p x -k modules' >> /etc/audit/rules.d/audit.rules   
echo '-w /sbin/modprobe -p x -k modules' >> /etc/audit/rules.d/audit.rules   
echo '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules' >> /etc/audit/rules.d/audit.rules  
echo -e "[\033[32m OK \033[0m] 4.1.17 	Ensure kernel module loading and unloading is collected (Scored) "

echo '$FileCreateMode 0640' >> /etc/rsyslog.conf
echo '$FileCreateMode 0640' >> /etc/rsyslog.d/*.conf
echo -e "[\033[32m OK \033[0m] 4.2.1.3 	Ensure rsyslog default file permissions configured (Scored) "

find /var/log -type f -exec chmod g-wx,o-rwx {} +
echo -e "[\033[32m OK \033[0m] 4.2.4 	Ensure permissions on all logfiles are configured (Scored) "

chown root:root /etc/crontab
chmod og-rwx /etc/crontab
echo -e "[\033[32m OK \033[0m] 5.1.2 	Ensure permissions on /etc/crontab are configured (Scored) "

chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
echo -e "[\033[32m OK \033[0m] 5.1.3 	Ensure permissions on /etc/cron.hourly are configured (Scored) "

chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
echo -e "[\033[32m OK \033[0m] 5.1.4 	Ensure permissions on /etc/cron.daily are configured (Scored) "

chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
echo -e "[\033[32m OK \033[0m] 5.1.5 	Ensure permissions on /etc/cron.weekly are configured (Scored) "

chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
echo -e "[\033[32m OK \033[0m] 5.1.6 	Ensure permissions on /etc/cron.monthly are configured (Scored) "

chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
echo -e "[\033[32m OK \033[0m] 5.1.7 	Ensure permissions on /etc/cron.d are configured (Scored) "

echo 'Protocol 2' >> /etc/ssh/sshd_config
echo -e "[\033[32m OK \033[0m] 5.2.2 	Ensure SSH Protocol is set to 2 (Scored) "

echo 'LogLevel INFO' >> /etc/ssh/sshd_config
echo -e "[\033[32m OK \033[0m] 5.2.3 	Ensure SSH LogLevel is set to INFO (Scored) "

echo 'MaxAuthTries 4' >> /etc/ssh/sshd_config
echo -e "[\033[32m OK \033[0m] 5.2.5 	Ensure SSH MaxAuthTries is set to 4 or less (Scored) "

echo 'IgnoreRhosts yes' >> /etc/ssh/sshd_config
echo -e "[\033[32m OK \033[0m] 5.2.6 	Ensure SSH IgnoreRhosts is enabled (Scored) "

echo 'HostbasedAuthentication no' >> /etc/ssh/sshd_config
echo -e "[\033[32m OK \033[0m] 5.2.7 	Ensure SSH HostbasedAuthentication is disabled (Scored) "

echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config
echo -e "[\033[32m OK \033[0m] 5.2.9 	Ensure SSH PermitEmptyPasswords is disabled (Scored) "

echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com' >> /etc/ssh/sshd_config
echo -e "[\033[32m OK \033[0m] 5.2.11 	Ensure only approved MAC algorithms are used (Scored) "

echo -e 'ClientAliveInterval 300\nClientAliveCountMax 0' >> /etc/ssh/sshd_config
echo -e "[\033[32m OK \033[0m] 5.2.12 	Ensure SSH Idle Timeout Interval is configured (Scored) "

echo 'LoginGraceTime 60' >> /etc/ssh/sshd_config
echo -e "[\033[32m OK \033[0m] 5.2.13 	Ensure SSH LoginGraceTime is set to one minute or less (Scored) "

# 待客户确定
echo -e 'AllowUsers root\nAllowGroups root\nDenyUsers ALL\nDenyGroups ALL' >> /etc/ssh/sshd_config
#echo -e 'AllowGroups root wheel' >> /etc/ssh/sshd_config
echo -e "[\033[32m OK \033[0m] 5.2.14 	Ensure SSH access is limited (Scored) "

#echo -e 'minlen = 14 \ndcredit = -1 \nucredit = -1 \nocredit = -1 \nlcredit = -1' >> /etc/security/pwquality.conf
echo -e 'minlen = 8 \ndcredit = -1 \nucredit = -1 \nocredit = -1 \nlcredit = -1' >> /etc/security/pwquality.conf
echo -e "[\033[32m OK \033[0m] 5.3.1 	Ensure password creation requirements are configured (Scored) "

echo 'auth required pam_faillock.so preauth audit silent deny=5 unlock_time=1800 ' >> /etc/pam.d/password-auth
echo 'auth [success=1 default=bad] pam_unix.so ' >> /etc/pam.d/password-auth
echo 'auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=1800 ' >> /etc/pam.d/password-auth
echo 'auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=1800 ' >> /etc/pam.d/password-auth
echo 'auth required pam_faillock.so preauth audit silent deny=5 unlock_time=1800 ' >> /etc/pam.d/system-auth
echo 'auth [success=1 default=bad] pam_unix.so ' >> /etc/pam.d/system-auth
echo 'auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=1800 ' >> /etc/pam.d/system-auth
echo 'auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=1800 ' >> /etc/pam.d/system-auth
echo -e "[\033[32m OK \033[0m] 5.3.2 	Ensure lockout for failed password attempts is configured (Scored) "

sed -i 's/\(^password.*sufficient.*pam_unix.so\)\(.*\)/\1\2 remember=5/' /etc/pam.d/password-auth
sed -i 's/\(^password.*sufficient.*pam_unix.so\)\(.*\)/\1\2 remember=5/' /etc/pam.d/system-auth
echo -e "[\033[32m OK \033[0m] 5.3.3 	Ensure password reuse is limited (Scored) "

sed -i s'/\(^PASS_MAX_DAYS\).*/\1 90/' /etc/login.defs
chage --maxdays 90 root
echo -e "[\033[32m OK \033[0m] 5.4.1.1 	Ensure password expiration is 365 days or less (Scored) "

sed -i s'/\(^PASS_MIN_DAYS\).*/\1 1/' /etc/login.defs
chage --mindays 1 root
echo -e "[\033[32m OK \033[0m] 5.4.1.2 	Ensure minimum days between password changes is 7 or more (Scored) "

sed -i 's/^\(PASS_WARN_AGE\).*/\1 14/' /etc/login.defs
chage --warndays 14 root
echo -e "[\033[32m OK \033[0m] 5.4.1.3 	Ensure password expiration warning days is 14 or more (Scored) "

for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd` ; do 
	if [ $user != "root" ]; then 
		usermod -L $user 
		if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ]; then 
			usermod -s /sbin/nologin $user
		fi 
	fi 
done
echo -e "[\033[32m OK \033[0m] 5.4.2 	Ensure system accounts are non-login (Scored) "

sed -i 's/\(.*umask\).*/\1 027/' /etc/bashrc
sed -i 's/\(.*umask\).*/\1 027/' /etc/profile
echo -e "[\033[32m OK \033[0m] 5.4.4 	Ensure default user umask is 027 or more restrictive (Scored) "

echo "TMOUT=600" >> /etc/bashrc
echo "TMOUT=600" >> /etc/profile
echo -e "[\033[32m OK \033[0m] 5.4.5 	Ensure default user shell timeout is 900 seconds or less (Scored) "

sed -i '/^[a-su-z0-9].*/d' /etc/securetty
echo -e "[\033[32m OK \033[0m] 5.5 	Ensure root login is restricted to system console (Not Scored) "

echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su
sed -i 's/\(^wheel\:x\:10\:\)/\1root/' /etc/group
echo -e "[\033[32m OK \033[0m] 5.6 	Ensure access to the su command is restricted (Scored) "

chmod -R 750 /home
chmod 755 /home
echo -e "[\033[32m OK \033[0m] 6.2.8 	Ensure users' home directories permissions are 750 or more restrictive (Scored) "

################################################################################################################################
# --------------------------------------------------------  第二次新增  --------------------------------------------------------  
################################################################################################################################

systemctl unmask tmp.mount 
systemctl enable tmp.mount 
#sed -i 's/^Options.*/&,noexec,nodev,nosuid/' /etc/systemd/system/local-fs.target.wants/tmp.mount
sed -i 's/^Options.*/&,noexec,nodev,nosuid/' /usr/lib/systemd/system/tmp.mount
echo -e "[\033[32m OK \033[0m] 1.1.2 	Ensure separate partition exists for /tmp (Scored) "

sed -i 's#gpgcheck = 0#gpgcheck = 1#g' `grep "gpgcheck = 0" -rl /etc/yum.repos.d/`
echo -e "[\033[32m OK \033[0m] 1.1.3 	 Ensure gpgcheck is globally activated (Scored) "

echo -e "1 */1 * * * root df --local -P | awk {'if (NR!=1) print \$6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t" >> /etc/crontab

df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
echo -e "[\033[32m OK \033[0m] 1.1.21 	Ensure sticky bit is set on all world-writable directories (Scored) "

echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd
echo -e "[\033[32m OK \033[0m] 1.7.1.1 	Ensure message of the day is configured properly (Scored) "

echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue 
echo -e "[\033[32m OK \033[0m] 1.7.1.2 	Ensure local login warning banner is configured properly (Not Scored) "

echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
echo -e "[\033[32m OK \033[0m] 1.7.1.3 	Ensure remote login warning banner is configured properly (Not Scored) "

yum install -y dconf
mkdir -p /etc/dconf/profile/
echo -e "user-db:user\nsystem-db:gdm\nfile-db:/usr/share/gdm/greeter-dconf-defaults" > /etc/dconf/profile/gdm
mkdir -p /etc/dconf/db/gdm.d/
echo -e "[org/gnome/login-screen] \nbanner-message-enable=true \nbanner-message-text='Authorized uses only. All activity may be monitored and reported.'" > /etc/dconf/db/gdm.d/01-banner-message
dconf update 
echo -e "[\033[32m OK \033[0m] 1.7.2 	Ensure GDM login banner is configured (Scored) "

# 执行后服务启动异常
# yum remove -y xorg-x11*
# echo -e "[\033[32m OK \033[0m] 2.2.2 	Ensure X Window System is not installed (Scored) "
sed -i 's/^\(max_log_file = \).*/\112/' /etc/audit/auditd.conf
echo -e "[\033[32m OK \033[0m] 4.1.1.1 	Ensure audit log storage size is configured (Not Scored) "

sed -i 's/^\(space_left_action = \).*/\1email/' /etc/audit/auditd.conf
sed -i 's/^\(action_mail_acct = \).*/\1root/' /etc/audit/auditd.conf
sed -i 's/^\(admin_space_left_action = \).*/\1halt/' /etc/audit/auditd.conf
echo -e "[\033[32m OK \033[0m] 4.1.1.2 	Ensure system is disabled when audit logs are full (Scored) "

sed -i 's/^\(max_log_file_action = \).*/\1keep_logs/'  /etc/audit/auditd.conf
echo -e "[\033[32m OK \033[0m] 4.1.1.3 	Ensure audit logs are not automatically deleted (Scored)"

echo "-e 2 " >> /etc/audit/rules.d/audit.rules 
echo -e "[\033[32m OK \033[0m] 4.1.18 	Ensure the audit configuration is immutable (Scored) "

# syslog-ng相关的操作，不操作
# yum install -y syslog-ng
# sed -i '1i*.emerg                                 :omusrmsg:* \nmail.*                                  -/var/log/mail \nmail.info                               -/var/log/mail.info \nmail.warning                            -/var/log/mail.warn \nmail.err                                 /var/log/mail.err \nnews.crit                               -/var/log/news/news.crit \nnews.err                                -/var/log/news/news.err \nnews.notice                             -/var/log/news/news.notice \n*.=warning;*.=err                       -/var/log/warn \n*.crit                                   /var/log/warn \n*.*;mail.none;news.none                 -/var/log/messages \nlocal0,local1.*                         -/var/log/localmessages \nlocal2,local3.*                         -/var/log/localmessages \nlocal4,local5.*                         -/var/log/localmessages \nlocal6,local7.*                         -/var/log/localmessages '  /etc/rsyslog.conf 
# sed -i '1i*.emerg                                 :omusrmsg:* \nmail.*                                  -/var/log/mail \nmail.info                               -/var/log/mail.info \nmail.warning                            -/var/log/mail.warn \nmail.err                                 /var/log/mail.err \nnews.crit                               -/var/log/news/news.crit \nnews.err                                -/var/log/news/news.err \nnews.notice                             -/var/log/news/news.notice \n*.=warning;*.=err                       -/var/log/warn \n*.crit                                   /var/log/warn \n*.*;mail.none;news.none                 -/var/log/messages \nlocal0,local1.*                         -/var/log/localmessages \nlocal2,local3.*                         -/var/log/localmessages \nlocal4,local5.*                         -/var/log/localmessages \nlocal6,local7.*                         -/var/log/localmessages '  /etc/rsyslog.d/*.conf
# pkill -HUP rsyslogd 
# echo -e "[\033[32m OK \033[0m] 4.2.1.2 	Ensure logging is configured (Not Scored) "
#
# # 客户自己设置远端log地址
# echo "*.* @@loghost.example.com" >> /etc/rsyslog.conf
# echo "*.* @@loghost.example.com" >> /etc/rsyslog.d/*.conf 
# pkill -HUP rsyslogd
# echo -e "[\033[32m OK \033[0m] 4.2.1.4 	Ensure rsyslog is configured to send logs to a remote log host (Scored) "
#
# systemctl enable syslog-ng 
# echo -e "[\033[32m OK \033[0m] 4.2.2.1 	Ensure syslog-ng service is enabled (Scored) "
#
# echo -e "log { source(src); source(chroots); filter(f_console); destination(console); }; \nlog { source(src); source(chroots); filter(f_console); destination(xconsole); }; \nlog { source(src); source(chroots); filter(f_newscrit); destination(newscrit); }; \nlog { source(src); source(chroots); filter(f_newserr); destination(newserr); }; \nlog { source(src); source(chroots); filter(f_newsnotice); destination(newsnotice); }; \nlog { source(src); source(chroots); filter(f_mailinfo); destination(mailinfo); }; \nlog { source(src); source(chroots); filter(f_mailwarn); destination(mailwarn); }; \nlog { source(src); source(chroots); filter(f_mailerr);  destination(mailerr); }; \nlog { source(src); source(chroots); filter(f_mail); destination(mail); }; \nlog { source(src); source(chroots); filter(f_acpid); destination(acpid); flags(final); }; \nlog { source(src); source(chroots); filter(f_acpid_full); destination(devnull); flags(final); }; \nlog { source(src); source(chroots); filter(f_acpid_old); destination(acpid); flags(final); }; \nlog { source(src); source(chroots); filter(f_netmgm); destination(netmgm); flags(final); }; \nlog { source(src); source(chroots); filter(f_local); destination(localmessages); }; \nlog { source(src); source(chroots); filter(f_messages); destination(messages); }; \nlog { source(src); source(chroots); filter(f_iptables); destination(firewall); }; \nlog { source(src); source(chroots); filter(f_warn); destination(warn); };" >> /etc/syslog-ng/syslog-ng.conf 
# pkill -HUP syslog-ng
# echo -e "[\033[32m OK \033[0m] 4.2.2.2 	Ensure logging is configured (Not Scored) "
#
# sed -i '0,/^options/{//d;b};0,/};$/d' /etc/syslog-ng/syslog-ng.conf
# echo "options { chain_hostnames(off); flush_lines(0); perm(0640); stats_freq(3600); threaded(yes); };" >> /etc/syslog-ng/syslog-ng.conf
# echo -e "[\033[32m OK \033[0m] 4.2.2.3 	Ensure syslog-ng default file permissions configured (Scored) "
#
# echo -e "destination logserver { tcp(\"logfile.example.com\" port(514)); }; \nlog { source(src); destination(logserver); }" >> /etc/syslog-ng/syslog-ng.conf 
# pkill -HUP syslog-ng
# echo -e "[\033[32m OK \033[0m] 4.2.2.4 	Ensure syslog-ng is configured to send logs to a remote log host (Not Scored) "
#
# echo -e "source net{ tcp(); }; \ndestination remote { file(\"/var/log/remote/${FULLHOST}-log\"); }; \nlog { source(net); destination(remote); };" >> /etc/syslog-ng/syslog-ng.conf 
# pkill -HUP syslog-ng
# echo -e "[\033[32m OK \033[0m] 4.2.2.5 	Ensure remote syslog-ng messages are only accepted on designated log hosts (Not Scored) "
#
# echo -e "[\033[32m OK \033[0m] 4.3	Ensure logrotate is configured (Not Scored) "

rm /etc/cron.deny 
rm /etc/at.deny 
touch /etc/cron.allow 
touch /etc/at.allow 
chmod og-rwx /etc/cron.allow 
chmod og-rwx /etc/at.allow 
chown root:root /etc/cron.allow 
chown root:root /etc/at.allow 
echo -e "[\033[32m OK \033[0m] 5.1.8 	Ensure at/cron is restricted to authorized users "

sed -i 's/^\(X11Forwarding \).*/\1no/' /etc/ssh/sshd_config 
echo -e "[\033[32m OK \033[0m] 5.2.4 	Ensure SSH X11 forwarding is disabled (Scored) "

#sed -i 's/^\(PermitRootLogin \).*/\1no/' /etc/ssh/sshd_config
echo -e "[\033[32m OK \033[0m] 5.2.8 	Ensure SSH root login is disabled (Scored) "

echo 'PermitUserEnvironment no' >> /etc/ssh/sshd_config
echo -e "[\033[32m OK \033[0m] 5.2.10 	Ensure SSH PermitUserEnvironment is disabled "

echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
echo -e "[\033[32m OK \033[0m] 5.2.15 	Ensure SSH warning banner is configured (Scored) "

useradd -D -f 30 
chage --inactive 30 root
echo -e "[\033[32m OK \033[0m] 5.4.1.4 	Ensure inactive password lock is 30 days or less (Scored) "

################
# 6.1.1 	Audit system file permissions (Not Scored) 
# 6.1.13 	Audit SUID executables (Not Scored) 
# 6.1.14 	Audit SGID executables (Not Scored) 
systemctl disable rpcbind
echo -e "[\033[32m OK \033[0m] 2.2.7 Ensure NFS and RPC are not enabled (Scored)  "

#################################################################################################
##------------------------------------1111新增--------------------------------------------------#
#################################################################################################
#################################################################################################

mkdir -p /root/bin
echo -e "[\033[32m OK \033[0m] 6.2.6 Ensure root PATH Integrity (Scored)   "

#################ntp################
\cp -rf /opt/os-hardening/ntp.conf /etc/
systemctl enable ntpd
systemctl start ntpd

##############2.2.15####################
yum install -y net-tools

##################4.2.4##################
echo -e "1 */1 * * * root find /var/log -type f -exec chmod g-wx,o-rwx {} +" >> /etc/crontab

####1.5.1#################
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

echo -e "[\033[32m OK \033[0m]--------------- Finish-----------------  "
