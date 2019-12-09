#!/bin/bash
arr_name=('frsadmin')
#arr_name=('kanghan.adm' 'tzehong.adm' 'weilik.adm' 'qingguang.adm' 'guangwei.adm' 'tanya.adm' 'hungpoh.adm')
for i in ${arr_name[@]}; do
  result=`cat /etc/passwd |cut -d":" -f1|grep -q $i;echo $?`
  if [ $result -ne 1 ]; then
     echo $i user exists;
  else
     echo create user $i
     adduser $i --gid wheel
     echo "ABCabc!@#123" | passwd "$i" --stdin
#    usermod -aG wheel $i
     sudo -H -u $i bash -c 'echo "ABCabc!@#123"|sudo -S ls -al /root'
     passwd --expire $i
#    cat /etc/passwd |grep $i
  fi
done
#sed -i.bak '/AllowUsers/d' /etc/ssh/sshd_config
#sed -i '/DenyUsers/d' /etc/ssh/sshd_config
#sed -i '/DenyGroups/d' /etc/ssh/sshd_config
#chmod 755 /home
chmod -R 750 /home
#sed -i.bak 's/^\(PermitRootLogin\).*/\1\ no/' /etc/ssh/sshd_config
chmod 755 /home
#sed -i.bak 's/^\(minlen\ =\).*/\1\ 8/' /etc/security/pwquality.conf
#systemctl restart sshd
#systemctl enable ntpd
