1.服务器需要先联网。能够yum install
2.把os hardening 上传到/opt目录
3.执行sh hardening-backup.sh进行备份
4.执行sh 1206-os-hardening.sh 进行hardening实施（不用把终端断开，不然执行完之后会ssh连不上）
5.修改密码，新建窗口验证能ssh登陆
6.重启机器
7.执行sh 1118-check.sh 
8.查看/opt/hardening_out.log的结果验证