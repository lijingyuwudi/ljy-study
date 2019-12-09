#!/bin/bash

set green "\033\[1;32m"
set red "\033\[1;31m"
set normal "\033\[0m"
set blue "\033\[1;34m"
set -x 
#set -e
echo -e "\e[1;32m****************1.1.1.1**************\e[0m\n">/opt/hardening_ouput.log
modprobe -n -v cramfs>>/opt/hardening_ouput.log
lsmod | grep cramfs >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "${blue}-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "install /bin/true">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.1.2**************\e[0m\n">>/opt/hardening_ouput.log
modprobe -n -v freevxfs>>/opt/hardening_ouput.log
lsmod | grep freevxfs >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "install /bin/true">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.1.3**************\e[0m\n">>/opt/hardening_ouput.log
modprobe -n -v jffs2>>/opt/hardening_ouput.log
lsmod | grep jffs2 >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "install /bin/true">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.1.4**************\e[0m\n">>/opt/hardening_ouput.log
 modprobe -n -v hfs >>/opt/hardening_ouput.log
 lsmod | grep hfs >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "install /bin/true">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.1.5**************\e[0m\n">>/opt/hardening_ouput.log
 modprobe -n -v hfsplus >>/opt/hardening_ouput.log
 lsmod | grep hfsplus >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "install /bin/true">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.1.6**************\n\e[0m">>/opt/hardening_ouput.log
modprobe -n -v squashfs >>/opt/hardening_ouput.log
lsmod | grep squashfs >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "install /bin/true">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.1.7**************\n\e[0m">>/opt/hardening_ouput.log
 modprobe -n -v udf >>/opt/hardening_ouput.log
lsmod | grep udf >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "install /bin/true" >>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.1.8**************\n\e[0m">>/opt/hardening_ouput.log
modprobe -n -v vfat >> /opt/hardening_ouput.log
lsmod | grep vfat >> /opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "install /bin/true" >>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.2**************\n\e[0m">>/opt/hardening_ouput.log
 mount | grep /tmp >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.3**************\n\e[0m">>/opt/hardening_ouput.log
mount | grep /tmp >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.4**************\n\e[0m">>/opt/hardening_ouput.log
mount | grep /tmp >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.5**************\n\e[0m">>/opt/hardening_ouput.log
mount | grep /tmp >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.7**************\n\e[0m">>/opt/hardening_ouput.log
mount | grep /var/tmp >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "/dev/mapper/centos-var_tmp on /var/tmp type xfs (rw,nosuid,nodev,noexec,relatime)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.8**************\n\e[0m">>/opt/hardening_ouput.log
mount | grep /var/tmp >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "/dev/mapper/centos-var_tmp on /var/tmp type xfs (rw,nosuid,nodev,noexec,relatime)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.9**************\n\e[0m">>/opt/hardening_ouput.log
mount | grep /var/tmp >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "/dev/mapper/centos-var_tmp on /var/tmp type xfs (rw,nosuid,nodev,noexec,relatime)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.10**************\n\e[0m">>/opt/hardening_ouput.log
mount | grep /var/tmp >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "/dev/mapper/centos-var_tmp on /var/tmp type xfs (rw,nosuid,nodev,noexec,relatime)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.11**************\n\e[0m">>/opt/hardening_ouput.log
mount | grep /var/log >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "/dev/mapper/centos-var_log on /var/log type xfs (rw,relatime,attr2,inode64,noquota)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.12**************\n\e[0m">>/opt/hardening_ouput.log
mount | grep /var/log/audit >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "/dev/mapper/centos-var_log_audit on /var/log/audit type xfs (rw,relatime,attr2,inode64,noquota)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.13**************\n\e[0m">>/opt/hardening_ouput.log
mount | grep /home >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "/dev/mapper/centos-home on /home type xfs (rw,nodev,relatime,attr2,inode64,noquota)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.15**************\n\e[0m">>/opt/hardening_ouput.log
 mount | grep /dev/shm >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.16**************\n\e[0m">>/opt/hardening_ouput.log
 mount | grep /dev/shm >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.17**************\n\e[0m">>/opt/hardening_ouput.log
mount | grep /dev/shm >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.18：we don't have removable media\n\e[0m">>/opt/hardening_ouput.log

#echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************1.1.19：we don't have removable media\n\e[0m">>/opt/hardening_ouput.log

#echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************1.1.20：we don't have removable media\n\e[0m">>/opt/hardening_ouput.log

#echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************1.1.21**************\n\e[0m">>/opt/hardening_ouput.log
 df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be：no output returned---------\e[0m\n">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.1.22**************\n\e[0m">>/opt/hardening_ouput.log
 systemctl is-enabled autofs >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be:not installed .PASS-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log

#echo -e "\n\e[1;32m****************1.2.1**************\n\e[0m">>/opt/hardening_ouput.log
# yum repolist >>/opt/hardening_ouput.log

#echo -e "\e[1;34m-----------output should be:not sure how to pass-------------\e[0m\n">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.2.3**************\n\e[0m">>/opt/hardening_ouput.log
 grep ^gpgcheck /etc/yum.conf >>/opt/hardening_ouput.log
grep ^gpgcheck /etc/yum.repos.d/* >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: all instances of gpgcheck returned are set to ' 1 '-------------\e[0m\n">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.3.1**************\n\e[0m">>/opt/hardening_ouput.log
rpm -q aide >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "aide-<version> ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.3.2**************\n\e[0m">>/opt/hardening_ouput.log
crontab -u root -l | grep aide>>/opt/hardening_ouput.log
 grep -r aide /etc/cron.* /etc/crontab >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "0 5 * * * /usr/sbin/aide --check ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.4.1**************\n\e[0m">>/opt/hardening_ouput.log
stat /boot/grub2/grub.cfg >>/opt/hardening_ouput.log
echo -e "          ">>/opt/hardening_ouput.log
 stat /boot/grub2/user.cfg>>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log
echo -e "          ">>/opt/hardening_ouput.log
echo -e "Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.4.3**************\n\e[0m">>/opt/hardening_ouput.log
 grep /sbin/sulogin /usr/lib/systemd/system/rescue.service >>/opt/hardening_ouput.log
grep /sbin/sulogin /usr/lib/systemd/system/emergency.service >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be:manually verify-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"">>/opt/hardening_ouput.log
#echo -e "ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.5.1**************\n\e[0m">>/opt/hardening_ouput.log
grep "hard core" /etc/security/limits.conf /etc/security/limits.d/* >>/opt/hardening_ouput.log
 sysctl fs.suid_dumpable >>/opt/hardening_ouput.log
 grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "* hard core 0">>/opt/hardening_ouput.log
echo -e "fs.suid_dumpable = 0 ">>/opt/hardening_ouput.log
echo -e "fs.suid_dumpable = 0 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.5.2**************\n\e[0m">>/opt/hardening_ouput.log
 dmesg | grep NX >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "NX (Execute Disable) protection: active ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.5.3**************\n\e[0m">>/opt/hardening_ouput.log
sysctl kernel.randomize_va_space >>/opt/hardening_ouput.log
 grep "kernel\.randomize_va_space" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "kernel.randomize_va_space = 2 ">>/opt/hardening_ouput.log
echo -e "kernel.randomize_va_space = 2 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.5.4**************\n\e[0m">>/opt/hardening_ouput.log
 rpm -q prelink >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "package prelink is not installed ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.6.1.1**************\n\e[0m">>/opt/hardening_ouput.log
grep "^\s*linux" /boot/grub2/grub.cfg >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e " no linux line has the selinux=0 or enforcing=0 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.6.1.4**************\n\e[0m">>/opt/hardening_ouput.log
 rpm -q setroubleshoot >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "package setroubleshoot is not installed ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.6.1.5**************\n\e[0m">>/opt/hardening_ouput.log
 rpm -q mcstrans >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "package mcstrans is not installed ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.6.2**************\n\e[0m">>/opt/hardening_ouput.log
 rpm -q libselinux >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "libselinux-<version> ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.7.1.1**************\n\e[0m">>/opt/hardening_ouput.log
cat /etc/motd >>/opt/hardening_ouput.log
egrep '(\\v|\\r|\\m|\\s)' /etc/motd >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Authorized uses only. All activity may be monitored and reported.">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.7.1.2**************\n\e[0m">>/opt/hardening_ouput.log
cat /etc/issue >>/opt/hardening_ouput.log
egrep '(\\v|\\r|\\m|\\s)' /etc/issue >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Authorized uses only. All activity may be monitored and reported.">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.7.1.3**************\n\e[0m">>/opt/hardening_ouput.log
 cat /etc/issue.net >>/opt/hardening_ouput.log
egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Authorized uses only. All activity may be monitored and reported.">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.7.1.4**************\n\e[0m">>/opt/hardening_ouput.log
 stat /etc/motd >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.7.1.5**************\n\e[0m">>/opt/hardening_ouput.log
stat /etc/issue >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.7.1.6**************\n\e[0m">>/opt/hardening_ouput.log
stat /etc/issue.net >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************1.7.2**************\n\e[0m">>/opt/hardening_ouput.log
cat /etc/dconf/profile/gdm>>/opt/hardening_ouput.log
echo -e "        ">>/opt/hardening_ouput.log
cat /etc/dconf/db/gdm.d/01-banner-message>>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "user-db:user ">>/opt/hardening_ouput.log
echo -e "system-db:gdm ">>/opt/hardening_ouput.log
echo -e "file-db:/usr/share/gdm/greeter-dconf-defaults ">>/opt/hardening_ouput.log
echo -e "        ">>/opt/hardening_ouput.log
echo -e "[org/gnome/login-screen] ">>/opt/hardening_ouput.log
echo -e "banner-message-enable=true ">>/opt/hardening_ouput.log
echo -e "banner-message-text='<banner message>' ">>/opt/hardening_ouput.log

#echo -e "\n\e[1;32m****************1.8**************\n\e[0m">>/opt/hardening_ouput.log
#eck-update --security >>/opt/hardening_ouput.log

#echo -e "\e[1;34m-----------output should be:unsolved-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e " verify there are no updates or patches to install"

echo -e "\n\e[1;32m****************2.1.1**************\n\e[0m">>/opt/hardening_ouput.log
 chkconfig --list|grep chargen >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.1.2**************\n\e[0m">>/opt/hardening_ouput.log

 chkconfig --list|grep daytime >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.1.3**************\n\e[0m">>/opt/hardening_ouput.log
 chkconfig --list |grep discard >>/opt/hardening_ouput.log

#echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.1.4**************\n\e[0m">>/opt/hardening_ouput.log
 chkconfig --list|grep echo >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.1.5**************\n\e[0m">>/opt/hardening_ouput.log
 chkconfig --list |grep time >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.1.6**************\n\e[0m">>/opt/hardening_ouput.log
 chkconfig --list|grep tftp >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.1.7**************\n\e[0m">>/opt/hardening_ouput.log
systemctl is-enabled xinetd  >>/opt/hardening_ouput.log

#echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.2.1.1**************\n\e[0m">>/opt/hardening_ouput.log
rpm -q ntp>>/opt/hardening_ouput.log
rpm -q chrony >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e " verify either ntp or chrony is installed">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.2.1.2**************\n\e[0m">>/opt/hardening_ouput.log
grep "^restrict" /etc/ntp.conf >>/opt/hardening_ouput.log
echo -e "     ">>/opt/hardening_ouput.log
grep "^OPTIONS" /etc/sysconfig/ntpd >>/opt/hardening_ouput.log
echo -e "     ">>/opt/hardening_ouput.log
 grep "^ExecStart" /usr/lib/systemd/system/ntpd.service >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "restrict -4 default kod nomodify notrap nopeer noquery ">>/opt/hardening_ouput.log
echo -e "restrict -6 default kod nomodify notrap nopeer noquery ">>/opt/hardening_ouput.log
echo -e "        ">>/opt/hardening_ouput.log
echo -e "OPTIONS="-u ntp:ntp" ">>/opt/hardening_ouput.log
echo -e "       ">>/opt/hardening_ouput.log
echo -e "ExecStart=/usr/sbin/ntpd -u ntp:ntp $OPTIONS ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.2.2**************\n\e[0m">>/opt/hardening_ouput.log
rpm -qa xorg-x11* >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------This item can not do-------------\e[0m\n">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.2.3**************\n\e[0m">>/opt/hardening_ouput.log
systemctl is-enabled avahi-daemon >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be----------------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.2.4**************\n\e[0m">>/opt/hardening_ouput.log
systemctl is-enabled cups >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.2.5**************\n\e[0m">>/opt/hardening_ouput.log

systemctl is-enabled dhcpd >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************2.2.6**************\n\e[0m">>/opt/hardening_ouput.log

systemctl is-enabled slapd >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************2.2.7**************\n\e[0m">>/opt/hardening_ouput.log

systemctl is-enabled nfs >>/opt/hardening_ouput.log
systemctl is-enabled nfs-server >>/opt/hardening_ouput.log
systemctl is-enabled rpcbind >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled">>/opt/hardening_ouput.log
echo -e "disabled">>/opt/hardening_ouput.log
echo -e "disabled">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.2.8**************\n\e[0m">>/opt/hardening_ouput.log

systemctl is-enabled named >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************2.2.9**************\n\e[0m">>/opt/hardening_ouput.log

systemctl is-enabled vsftpd >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************2.2.10**************\n\e[0m">>/opt/hardening_ouput.log

systemctl is-enabled httpd >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************2.2.11**************\n\e[0m">>/opt/hardening_ouput.log

systemctl is-enabled dovecot >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************2.2.12**************\n\e[0m">>/opt/hardening_ouput.log

systemctl is-enabled smb >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************2.2.13**************\n\e[0m">>/opt/hardening_ouput.log

systemctl is-enabled squid >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log
#echo -e "\n\e[1;32m****************2.2.14**************\n\e[0m">>/opt/hardening_ouput.log

#echo -e "\e[1;34m-----------output should be:not installed. PASS-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************2.2.15**************\n\e[0m">>/opt/hardening_ouput.log
 netstat -an|grep LIST|grep ":25[[:space:]]" >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN" >>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.2.16**************\n\e[0m">>/opt/hardening_ouput.log

systemctl is-enabled ypserv >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************2.2.17**************\n\e[0m">>/opt/hardening_ouput.log

systemctl is-enabled rsh.socket >>/opt/hardening_ouput.log
systemctl is-enabled rlogin.socket >>/opt/hardening_ouput.log
systemctl is-enabled rexec.socket >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************2.2.18**************\n\e[0m">>/opt/hardening_ouput.log

systemctl is-enabled telnet.socket >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.2.19**************\n\e[0m">>/opt/hardening_ouput.log

systemctl is-enabled tfpt.socket >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.2.20**************\n\e[0m">>/opt/hardening_ouput.log
 systemctl is-enabled rsyncd >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not output">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.2.21**************\n\e[0m">>/opt/hardening_ouput.log
systemctl is-enabled ntalk >>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "disabled or not returned">>/opt/hardening_ouput.log
echo -e "\n\e[1;32m****************2.3.1**************\n\e[0m">>/opt/hardening_ouput.log
 rpm -q ypbind >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "package ypbind is not installed ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.3.2**************\n\e[0m">>/opt/hardening_ouput.log
 rpm -q rsh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "package rsh is not installed ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.3.3**************\n\e[0m">>/opt/hardening_ouput.log
 rpm -q talk >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "package talk is not installed ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.3.4**************\n\e[0m">>/opt/hardening_ouput.log
 rpm -q telnet >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "package telnet is not installed" >>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************2.3.5**************\n\e[0m">>/opt/hardening_ouput.log
 rpm -q openldap-clients >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "package openldap-clients is not installed ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.2.2**************\n\e[0m">>/opt/hardening_ouput.log
 sysctl net.ipv4.conf.all.accept_redirects >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 sysctl net.ipv4.conf.default.accept_redirects >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 grep "net\.ipv4\.conf\.all\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 grep "net\.ipv4\.conf\.default\.accept_redirects" /etc/sysctl.conf /etc/sysctl.d/*>>/opt/hardening_ouput.log
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.all.accept_redirects = 0 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.default.accept_redirects = 0 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.all.accept_redirects= 0">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.default.accept_redirects= 0 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.2.3**************\n\e[0m">>/opt/hardening_ouput.log
sysctl net.ipv4.conf.all.secure_redirects >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 sysctl net.ipv4.conf.default.secure_redirects >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
grep "net\.ipv4\.conf\.all\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
grep "net\.ipv4\.conf\.default\.secure_redirects" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.all.secure_redirects = 0 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.default.secure_redirects = 0 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.all.secure_redirects= 0 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.default.secure_redirects= 0 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.2.4**************\n\e[0m">>/opt/hardening_ouput.log
 sysctl net.ipv4.conf.all.log_martians >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 sysctl net.ipv4.conf.default.log_martians >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 grep "net\.ipv4\.conf\.all\.log_martians" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
grep "net\.ipv4\.conf\.default\.log_martians" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.all.log_martians = 1 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.default.log_martians = 1 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.all.log_martians = 1 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.default.log_martians = 1 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.2.5**************\n\e[0m">>/opt/hardening_ouput.log
 sysctl net.ipv4.icmp_echo_ignore_broadcasts >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 grep "net\.ipv4\.icmp_echo_ignore_broadcasts" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "net.ipv4.icmp_echo_ignore_broadcasts = 1 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.icmp_echo_ignore_broadcasts = 1 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.2.6**************\n\e[0m">>/opt/hardening_ouput.log
sysctl net.ipv4.icmp_ignore_bogus_error_responses >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 grep "net\.ipv4\.icmp_ignore_bogus_error_responses" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log
 
 echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
 echo -e "net.ipv4.icmp_ignore_bogus_error_responses = 1 ">>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
 echo -e "net.ipv4.icmp_ignore_bogus_error_responses = 1 ">>/opt/hardening_ouput.log
 
echo -e "\n\e[1;32m****************3.2.7**************\n\e[0m">>/opt/hardening_ouput.log
sysctl net.ipv4.conf.all.rp_filter >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 sysctl net.ipv4.conf.default.rp_filter >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
  grep "net\.ipv4\.conf\.all\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log
  echo -e "   ">>/opt/hardening_ouput.log
  grep "net\.ipv4\.conf\.default\.rp_filter" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.all.rp_filter = 1">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.default.rp_filter = 1 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.all.rp_filter = 1 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.conf.default.rp_filter = 1 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.2.8**************\n\e[0m">>/opt/hardening_ouput.log
 sysctl net.ipv4.tcp_syncookies >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
 grep "net\.ipv4\.tcp_syncookies" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "net.ipv4.tcp_syncookies = 1 " >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv4.tcp_syncookies = 1 " >>/opt/hardening_ouput.log


echo -e "\n\e[1;32m****************3.3.1**************\n\e[0m">>/opt/hardening_ouput.log
 sysctl net.ipv6.conf.all.accept_ra >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
 sysctl net.ipv6.conf.default.accept_ra >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
 grep "net\.ipv6\.conf\.all\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
  grep "net\.ipv6\.conf\.default\.accept_ra" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log
  
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "net.ipv6.conf.all.accept_ra = 0 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv6.conf.default.accept_ra = 0 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv6.conf.all.accept_ra = 0 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv6.conf.default.accept_ra = 0">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.3.2**************\n\e[0m">>/opt/hardening_ouput.log
sysctl net.ipv6.conf.all.accept_redirects >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
sysctl net.ipv6.conf.default.accept_redirects >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
grep "net\.ipv6\.conf\.all\.accept_redirect" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log 
grep "net\.ipv6\.conf\.default\.accept_redirect" /etc/sysctl.conf /etc/sysctl.d/* >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "net.ipv6.conf.all.accept_redirect = 0 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv6.conf.default.accept_redirect = 0">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv6.conf.all.accept_redirect = 0 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "net.ipv6.conf.default.accept_redirect = 0 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.4.1**************\n\e[0m">>/opt/hardening_ouput.log
 rpm -q tcp_wrappers >>/opt/hardening_ouput.log
  rpm -q tcp_wrappers-libs >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "tcp_wrappers-<version> ">>/opt/hardening_ouput.log
echo -e "tcp_wrappers-libs-<version> ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.4.2**************\n\e[0m">>/opt/hardening_ouput.log
cat /etc/hosts.allow >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "ALL:10.28.168.0/24" >>/opt/hardening_ouput.log
echo -e "ALL:10.28.129.0/24" >>/opt/hardening_ouput.log
echo -e "ALL:10.30.49.0/24" >>/opt/hardening_ouput.log
echo -e "ALL:192.168.168.0/23" >>/opt/hardening_ouput.log
echo -e "ALL:192.168.170.0/24" >>/opt/hardening_ouput.log
echo -e "ALL:192.168.171.0/24" >>/opt/hardening_ouput.log
echo -e "ALL:192.168.172.0/24" >>/opt/hardening_ouput.log
echo -e "ALL:10.31.90.0/24" >>/opt/hardening_ouput.log
echo -e "ALL:10.31.91.0/24" >>/opt/hardening_ouput.log
echo -e "ALL:10.31.98.0/24" >>/opt/hardening_ouput.log
echo -e "ALL:10.31.99.0/24" >>/opt/hardening_ouput.log


#echo -e "\e[1;34m-----------output should be:configured by the users-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.4.3**************\n\e[0m">>/opt/hardening_ouput.log
cat /etc/hosts.deny >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "ALL:ALL" >>/opt/hardening_ouput.log

#echo -e "\e[1;34m-----------output should be:configured by the users-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.4.4**************\n\e[0m">>/opt/hardening_ouput.log
 stat /etc/hosts.allow >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.4.5**************\n\e[0m">>/opt/hardening_ouput.log
 stat /etc/hosts.deny >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.5.1**************\n\e[0m">>/opt/hardening_ouput.log
modprobe -n -v dccp >>/opt/hardening_ouput.log
lsmod | grep dccp >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "install /bin/true ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.5.2**************\n\e[0m">>/opt/hardening_ouput.log
modprobe -n -v sctp >>/opt/hardening_ouput.log
lsmod | grep sctp >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "install /bin/true ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.5.3**************\n\e[0m">>/opt/hardening_ouput.log
 modprobe -n -v rds >>/opt/hardening_ouput.log
  lsmod | grep rds >>/opt/hardening_ouput.log
  
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "install /bin/true ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.5.4**************\n\e[0m">>/opt/hardening_ouput.log
modprobe -n -v tipc >>/opt/hardening_ouput.log
 lsmod | grep tipc >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "install /bin/true ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.6.1**************\n\e[0m">>/opt/hardening_ouput.log
rpm -q iptables >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "iptables-<version> ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************3.7**************\n\e[0m">>/opt/hardening_ouput.log
iwconfig >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 ip link show up >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "verify wireless interfaces are disabled">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.1.1**************\n\e[0m">>/opt/hardening_ouput.log
grep max_log_file /etc/audit/auditd.conf >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "max_log_file = 12 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.1.2**************\n\e[0m">>/opt/hardening_ouput.log
grep space_left_action /etc/audit/auditd.conf >>/opt/hardening_ouput.log
grep action_mail_acct /etc/audit/auditd.conf >>/opt/hardening_ouput.log
grep admin_space_left_action /etc/audit/auditd.conf >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "space_left_action = email" >>/opt/hardening_ouput.log
echo -e "action_mail_acct = root" >>/opt/hardening_ouput.log
echo -e "admin_space_left_action = halt" >>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.1.3**************\n\e[0m">>/opt/hardening_ouput.log
grep max_log_file_action /etc/audit/auditd.conf >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "max_log_file_action = keep_logs" >>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.2**************\n\e[0m">>/opt/hardening_ouput.log
systemctl is-enabled auditd >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "enabled">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.3**************\n\e[0m">>/opt/hardening_ouput.log
grep "^\s*linux" /boot/grub2/grub.cfg >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "verify that each linux line has the audit=1 parameter set">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.4**************\n\e[0m">>/opt/hardening_ouput.log
grep time-change /etc/audit/audit.rules >>/opt/hardening_ouput.log
auditctl -l | grep time-change >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change ">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b64 -S clock_settime -k time-change ">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b32 -S clock_settime -k time-change ">>/opt/hardening_ouput.log
echo -e "-w /etc/localtime -p wa -k time-change ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.5**************\n\e[0m">>/opt/hardening_ouput.log
grep identity /etc/audit/audit.rules >>/opt/hardening_ouput.log
 auditctl -l | grep identity >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-w /etc/group -p wa -k identity ">>/opt/hardening_ouput.log
echo -e "-w /etc/passwd -p wa -k identity ">>/opt/hardening_ouput.log
echo -e "-w /etc/gshadow -p wa -k identity ">>/opt/hardening_ouput.log
echo -e "-w /etc/shadow -p wa -k identity ">>/opt/hardening_ouput.log
echo -e "-w /etc/security/opasswd -p wa -k identity ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.6**************\n\e[0m">>/opt/hardening_ouput.log
grep system-locale /etc/audit/audit.rules >>/opt/hardening_ouput.log
 auditctl -l | grep system-locale >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale ">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale ">>/opt/hardening_ouput.log
echo -e "-w /etc/issue -p wa -k system-locale ">>/opt/hardening_ouput.log
echo -e "-w /etc/issue.net -p wa -k system-locale ">>/opt/hardening_ouput.log
echo -e "-w /etc/hosts -p wa -k system-locale">>/opt/hardening_ouput.log
echo -e "-w /etc/sysconfig/network -p wa -k system-locale ">>/opt/hardening_ouput.log
echo -e "-w /etc/sysconfig/network-scripts/ -p wa -k system-locale ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.7**************\n\e[0m">>/opt/hardening_ouput.log
grep MAC-policy /etc/audit/audit.rules >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-w /etc/selinux/ -p wa -k MAC-policy ">>/opt/hardening_ouput.log
echo -e "-w /usr/share/selinux/ -p wa -k MAC-policy ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.8**************\n\e[0m">>/opt/hardening_ouput.log
grep logins /etc/audit/audit.rules >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-w /var/log/lastlog -p wa -k logins ">>/opt/hardening_ouput.log
echo -e "-w /var/run/faillock/ -p wa -k logins ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.9**************\n\e[0m">>/opt/hardening_ouput.log
 grep session /etc/audit/audit.rules >>/opt/hardening_ouput.log
 auditctl -l | grep session >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
 grep logins /etc/audit/audit.rules >>/opt/hardening_ouput.log
  auditctl -l | grep logins >>/opt/hardening_ouput.log
  
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-w /var/run/utmp -p wa -k session ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "-w /var/log/wtmp -p wa -k logins " >>/opt/hardening_ouput.log
echo -e "-w /var/log/btmp -p wa -k logins " >>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.10**************\n\e[0m">>/opt/hardening_ouput.log
grep perm_mod /etc/audit/audit.rules >>/opt/hardening_ouput.log
auditctl -l | grep perm_mod >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod ">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod ">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod ">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod ">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.11**************\n\e[0m">>/opt/hardening_ouput.log
grep access /etc/audit/audit.rules >>/opt/hardening_ouput.log
 auditctl -l | grep access >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access ">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access ">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access ">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.12:too much ..inogre**************\n\e[0m">>/opt/hardening_ouput.log
#find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Verify all resulting lines are in the /etc/audit/audit.rules file ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.13**************\n\e[0m">>/opt/hardening_ouput.log
grep mounts /etc/audit/audit.rules >>/opt/hardening_ouput.log
auditctl -l | grep mounts >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts ">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.14**************\n\e[0m">>/opt/hardening_ouput.log
 grep delete /etc/audit/audit.rules >>/opt/hardening_ouput.log
 auditctl -l | grep delete >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete ">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.15**************\n\e[0m">>/opt/hardening_ouput.log
grep scope /etc/audit/audit.rules >>/opt/hardening_ouput.log
 auditctl -l | grep scope >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-w /etc/sudoers -p wa -k scope ">>/opt/hardening_ouput.log
echo -e "-w /etc/sudoers.d/ -p wa -k scope ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.16**************\n\e[0m">>/opt/hardening_ouput.log
grep actions /etc/audit/audit.rules >>/opt/hardening_ouput.log
 auditctl -l | grep actions >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-w /var/log/sudo.log -p wa -k actions ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.17**************\n\e[0m">>/opt/hardening_ouput.log
grep modules /etc/audit/audit.rules >>/opt/hardening_ouput.log
auditctl -l | grep modules /opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-w /sbin/insmod -p x -k modules ">>/opt/hardening_ouput.log
echo -e "-w /sbin/rmmod -p x -k modules">>/opt/hardening_ouput.log
echo -e "-w /sbin/modprobe -p x -k modules ">>/opt/hardening_ouput.log
echo -e "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.1.18**************\n\e[0m">>/opt/hardening_ouput.log
grep "^\s*[^#]" /etc/audit/audit.rules | tail -1 >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "-e 2 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.2.1.1**************\n\e[0m">>/opt/hardening_ouput.log
systemctl is-enabled rsyslog >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "enabled">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.2.1.2**************\n\e[0m">>/opt/hardening_ouput.log
ls -l /var/log/ >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be:not sure how to pass-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.2.1.3**************\n\e[0m">>/opt/hardening_ouput.log
grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "$FileCreateMode 0640 ">>/opt/hardening_ouput.log


echo -e "\n\e[1;32m****************4.2.1.5**************\n\e[0m">>/opt/hardening_ouput.log
grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "$ModLoad imtcp ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "$InputTCPServerRun 514 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.2.3**************\n\e[0m">>/opt/hardening_ouput.log
 rpm -q rsyslog >>/opt/hardening_ouput.log
 rpm -q syslog-ng >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "verify at least one indicates the package is installed">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.2.4**************\n\e[0m">>/opt/hardening_ouput.log
find /var/log -type f -ls >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "find /var/log -type f -exec chmod g-wx,o-rwx {} + ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************4.3**************\n\e[0m">>/opt/hardening_ouput.log
echo -e "Rsyslog will be sent to siem server,not need to configure" >>/opt/hardening_ouput.log
#echo -e "no sure how to verify" >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Rsyslog will be sent to siem server,not need to configure">>/opt/hardening_ouput.log 
#echo -e "no sure how to verify">>/opt/hardening_ouput.log 

echo -e "\n\e[1;32m****************5.1.1**************\n\e[0m">>/opt/hardening_ouput.log
systemctl is-enabled crond >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "enabled">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.1.2**************\n\e[0m">>/opt/hardening_ouput.log
 stat /etc/crontab >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.1.3**************\n\e[0m">>/opt/hardening_ouput.log
 stat /etc/cron.hourly >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0700/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.1.4**************\n\e[0m">>/opt/hardening_ouput.log
 stat /etc/cron.daily >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0700/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.1.5**************\n\e[0m">>/opt/hardening_ouput.log
 stat /etc/cron.weekly >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0700/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.1.6**************\n\e[0m">>/opt/hardening_ouput.log
stat /etc/cron.monthly >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0700/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.1.7**************\n\e[0m">>/opt/hardening_ouput.log
stat /etc/cron.d >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0700/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.1.8**************\n\e[0m">>/opt/hardening_ouput.log
# stat /etc/cron.deny >>/opt/hardening_ouput.log
#echo -e "   ">>/opt/hardening_ouput.log 
# stat /etc/at.deny >>/opt/hardening_ouput.log
# echo -e "   ">>/opt/hardening_ouput.log
 stat /etc/cron.allow >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
 stat /etc/at.allow >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "stat: cannot stat '/etc/cron.deny': No such file or directory ">>/opt/hardening_ouput.log
#echo -e "   ">>/opt/hardening_ouput.log
#echo -e "stat: cannot stat '/etc/at.deny': No such file or directory ">>/opt/hardening_ouput.log
#echo -e "   ">>/opt/hardening_ouput.log
echo -e "Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root)">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.1**************\n\e[0m">>/opt/hardening_ouput.log
stat /etc/ssh/sshd_config >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0600/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.2**************\n\e[0m">>/opt/hardening_ouput.log
grep "^Protocol" /etc/ssh/sshd_config >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Protocol 2 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.3**************\n\e[0m">>/opt/hardening_ouput.log
grep "^LogLevel" /etc/ssh/sshd_config >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "LogLevel INFO">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.4**************\n\e[0m">>/opt/hardening_ouput.log
grep "^X11Forwarding" /etc/ssh/sshd_config >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "X11Forwarding no ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.5**************\n\e[0m">>/opt/hardening_ouput.log
grep "^MaxAuthTries" /etc/ssh/sshd_config >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "MaxAuthTries 4 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.6**************\n\e[0m">>/opt/hardening_ouput.log
grep "^IgnoreRhosts" /etc/ssh/sshd_config >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "IgnoreRhosts yes ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.7**************\n\e[0m">>/opt/hardening_ouput.log
grep "^HostbasedAuthentication" /etc/ssh/sshd_config >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "HostbasedAuthentication no ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.8**************\n\e[0m">>/opt/hardening_ouput.log
grep "^PermitRootLogin" /etc/ssh/sshd_config >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "PermitRootLogin no" >>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.9**************\n\e[0m">>/opt/hardening_ouput.log
 grep "^PermitEmptyPasswords" /etc/ssh/sshd_config >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "PermitEmptyPasswords no ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.10**************\n\e[0m">>/opt/hardening_ouput.log
grep PermitUserEnvironment /etc/ssh/sshd_config >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "PermitUserEnvironment no ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.11**************\n\e[0m">>/opt/hardening_ouput.log
 grep "MACs" /etc/ssh/sshd_config >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.12**************\n\e[0m">>/opt/hardening_ouput.log
 grep "^ClientAliveInterval" /etc/ssh/sshd_config >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
  grep "^ClientAliveCountMax" /etc/ssh/sshd_config >>/opt/hardening_ouput.log
  
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "ClientAliveInterval 300 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "ClientAliveCountMax 0 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.13**************\n\e[0m">>/opt/hardening_ouput.log
grep "^LoginGraceTime" /etc/ssh/sshd_config >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "LoginGraceTime 60 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.14**************\n\e[0m">>/opt/hardening_ouput.log
grep "^AllowUsers" /etc/ssh/sshd_config >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
grep "^AllowGroups" /etc/ssh/sshd_config >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 grep "^DenyUsers" /etc/ssh/sshd_config >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
 grep "^DenyGroups" /etc/ssh/sshd_config >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be:configured by users-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "AllowUsers <userlist> ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "AllowGroups <grouplist> ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "DenyUsers <userlist> ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "DenyGroups <grouplist> ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.2.15**************\n\e[0m">>/opt/hardening_ouput.log
 grep "^Banner" /etc/ssh/sshd_config >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Banner /etc/issue.net ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.3.1**************\n\e[0m">>/opt/hardening_ouput.log
grep pam_pwquality.so /etc/pam.d/password-auth >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 grep pam_pwquality.so /etc/pam.d/system-auth >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
 grep ^minlen /etc/security/pwquality.conf >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
 grep ^dcredit /etc/security/pwquality.conf >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
  grep ^lcredit /etc/security/pwquality.conf >>/opt/hardening_ouput.log
  echo -e "   ">>/opt/hardening_ouput.log
  grep ^ocredit /etc/security/pwquality.conf >>/opt/hardening_ouput.log
  echo -e "   ">>/opt/hardening_ouput.log
  grep ^ucredit /etc/security/pwquality.conf >>/opt/hardening_ouput.log
  
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "password requisite pam_pwquality.so try_first_pass retry=3 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "password requisite pam_pwquality.so try_first_pass retry=3 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
#echo -e "minlen = 14 ">>/opt/hardening_ouput.log
echo -e "minlen = 8 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "dcredit = -1">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "lcredit = -1 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "ocredit = -1 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "ucredit = -1 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.3.2**************\n\e[0m">>/opt/hardening_ouput.log
cat /etc/pam.d/password-auth >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
cat /etc/pam.d/password-auth >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "auth required pam_faillock.so preauth audit silent deny=5 unlock_time=1800 ">>/opt/hardening_ouput.log
echo -e "auth [success=1 default=bad] pam_unix.so ">>/opt/hardening_ouput.log
echo -e "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=1800 ">>/opt/hardening_ouput.log
echo -e "auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=1800 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.3.3**************\n\e[0m">>/opt/hardening_ouput.log
 egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
  egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth >>/opt/hardening_ouput.log
  
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "password sufficient pam_unix.so remember=5 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "password sufficient pam_unix.so remember=5 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.3.4**************\n\e[0m">>/opt/hardening_ouput.log
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/password-auth >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/system-auth >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "password sufficient pam_unix.so sha512 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "password sufficient pam_unix.so sha512 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.4.1.1**************\n\e[0m">>/opt/hardening_ouput.log
grep PASS_MAX_DAYS /etc/login.defs >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log 
 egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
  chage --list root >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "PASS_MAX_DAYS 90 ##verify PASS_MAX_DAYS conforms to site policy (no more than 365 days)">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "<list of users> ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "Maximum number of days between password change          : 90 ##Verify all users with a password maximum days between password change conforms to site policy (no more than 365 days)">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.4.1.2**************\n\e[0m">>/opt/hardening_ouput.log
grep PASS_MIN_DAYS /etc/login.defs >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
  chage --list root >>/opt/hardening_ouput.log
  
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "PASS_MIN_DAYS 1 ## verify PASS_MIN_DAYS is 7 or more">>/opt/hardening_ouput.log
#echo -e "PASS_MIN_DAYS 7 ## verify PASS_MIN_DAYS is 7 or more">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "<list of users> ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "Minimum number of days between password change          : 1 ##Verify all users with a password have their minimum days between password change set to 1 or more">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.4.1.3**************\n\e[0m">>/opt/hardening_ouput.log
grep PASS_WARN_AGE /etc/login.defs >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
 chage --list root >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "PASS_WARN_AGE 7 ##verify PASS_WARN_AGE is 7 or more">>/opt/hardening_ouput.log
echo -e "PASS_WARN_AGE 14 ##verify PASS_WARN_AGE is 14 or more">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "<list of users> ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "Number of days of warning before password expires       : 7 ##Verify all users with a password have their number of days of warning before password expires set to 7 or more">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.4.1.4**************\n\e[0m">>/opt/hardening_ouput.log
 useradd -D | grep INACTIVE >>/opt/hardening_ouput.log
 echo -e "   ">>/opt/hardening_ouput.log
  egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 >>/opt/hardening_ouput.log
  echo -e "   ">>/opt/hardening_ouput.log
  chage --list root >>/opt/hardening_ouput.log
  
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "INACTIVE=30  ## verify INACTIVE is 30 or less ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "<list of users> ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "Password inactive                                       : <date>  ## Password inactive no more than 30 days after password expires ">>/opt/hardening_ouput.log


echo -e "\n\e[1;32m****************5.4.1.5**************\n\e[0m">>/opt/hardening_ouput.log
cat /etc/shadow | cut -d: -f1 >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
chage --list root >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "<list of users> ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "Last Change                                             : <date>  ##Verify no users with a have Password change date in the future">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.4.2**************\n\e[0m">>/opt/hardening_ouput.log
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print}' >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: no results are returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.4.3**************\n\e[0m">>/opt/hardening_ouput.log
grep "^root:" /etc/passwd | cut -f4 -d: >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "0">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.4.4**************\n\e[0m">>/opt/hardening_ouput.log
grep "umask" /etc/bashrc >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 grep "umask" /etc/profile /etc/profile.d/*.sh >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "umask 027 ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "umask 027 ">>/opt/hardening_ouput.log


echo -e "\n\e[1;32m****************5.4.5**************\n\e[0m">>/opt/hardening_ouput.log
grep "^TMOUT" /etc/bashrc >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 grep "^TMOUT" /etc/profile >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "TMOUT=600">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "TMOUT=600 ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************5.6**************\n\e[0m">>/opt/hardening_ouput.log
grep pam_wheel.so /etc/pam.d/su >>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
 grep wheel /etc/group >>/opt/hardening_ouput.log
 
echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "auth required pam_wheel.so use_uid ">>/opt/hardening_ouput.log
echo -e "   ">>/opt/hardening_ouput.log
echo -e "wheel:x:10:root,<user list> ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.1.2**************\n\e[0m">>/opt/hardening_ouput.log
stat /etc/passwd >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be:verify Uid and Gid are both 0/root and Access is 644 -------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.1.3**************\n\e[0m">>/opt/hardening_ouput.log
stat /etc/shadow >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be:verify Uid and Gid are 0/root , and Access is 000 -------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0000/----------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.1.4**************\n\e[0m">>/opt/hardening_ouput.log
 stat /etc/group >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify Uid and Gid are both 0/root and Access is 644 -------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.1.5**************\n\e[0m">>/opt/hardening_ouput.log
stat /etc/gshadow >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be:verify Uid and Gid are 0/root , and Access is 000 -------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0000/----------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.1.6**************\n\e[0m">>/opt/hardening_ouput.log
stat /etc/passwd- >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify Uid and Gid are both 0/root and Access is 644 or more restrictive-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0644/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.1.7**************\n\e[0m">>/opt/hardening_ouput.log
stat /etc/shadow- >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify verify Uid and Gid is 0/root, and Access is 000-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0000/----------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.1.8**************\n\e[0m">>/opt/hardening_ouput.log
 stat /etc/group- >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify Uid and Gid are both 0/root and Access is 644 or more restrictive-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0644/-rw-------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.1.9**************\n\e[0m">>/opt/hardening_ouput.log
 stat /etc/gshadow- >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be:verify Uid and Gid are 0/root, and Access is 000-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "Access: (0000/----------)  Uid: (    0/    root)   Gid: (    0/    root) ">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.1.10**************\n\e[0m">>/opt/hardening_ouput.log
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 |grep -v kube |grep -v docker >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.1.11**************\n\e[0m">>/opt/hardening_ouput.log
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser |grep -v docker |grep -v kafka|grep -v kubelet |grep -v mnt >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.1.12**************\n\e[0m">>/opt/hardening_ouput.log
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup |grep -v docker|grep -v kubelet |grep -v mnt >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.1**************\n\e[0m">>/opt/hardening_ouput.log
 cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}' >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.2**************\n\e[0m">>/opt/hardening_ouput.log
grep '^\+:' /etc/passwd >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.3**************\n\e[0m">>/opt/hardening_ouput.log
grep '^\+:' /etc/shadow >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.4**************\n\e[0m">>/opt/hardening_ouput.log
 grep '^\+:' /etc/group >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.5**************\n\e[0m">>/opt/hardening_ouput.log
 cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be-------------\e[0m\n">>/opt/hardening_ouput.log
echo -e "root">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.6**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.6.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.7**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.7.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.8**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.8.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.9**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.9.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.10**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.10.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.11**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.11.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.12**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.12.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.13**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.13.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.14**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.14.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.15**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.15.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.16**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.16.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.17**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.17.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.18**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.18.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log

echo -e "\n\e[1;32m****************6.2.19**************\n\e[0m">>/opt/hardening_ouput.log
sh /opt/os-hardening/6.2.19.sh >>/opt/hardening_ouput.log

echo -e "\e[1;34m-----------output should be: verify that no output is returned-------------\e[0m\n">>/opt/hardening_ouput.log
#echo -e "">>/opt/hardening_ouput.log
