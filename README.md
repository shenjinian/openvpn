CentOS 6.x安装配置openvpn使用ldap进行身份认证，附带记录用户访问日志并发送邮件
一、环境
系统     CentOS 6.x  x64最小化安装
IP       202.119.191.11
二、安装openvpn
#基础配置
[root@vpn-ldap ~]# rpm -ivh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
[root@vpn-ldap ~]# sed -i 's@#b@b@g' /etc/yum.repos.d/epel.repo
[root@vpn-ldap ~]# sed  -i 's@mirrorlist@#mirrorlist@g' /etc/yum.repos.d/epel.repo
[root@vpn-ldap ~]# echo "*/10 * * * * /usr/sbin/ntpdate asia.pool.ntp.org  &>/dev/null" >/var/spool/cron/root
[root@vpn-ldap ~]# crontab -l
*/10 * * * * /usr/sbin/ntpdate asia.pool.ntp.org  &>/dev/null

#安装openvpn
[root@vpn-ldap ~]# yum install openssl openssl-devel lzo  openvpn easy-rsa  -y

#修改vars文件信息
[root@vpn-ldap ~]# cd /usr/share/easy-rsa/2.0/
[root@vpn-ldap 2.0]# vim vars 
#修改下面几项
export KEY_COUNTRY="CN"
export KEY_PROVINCE="JiangSu"
export KEY_CITY="NanJing"
export KEY_ORG="CPU"
export KEY_EMAIL="sjn@cpu.edu.cn"
export KEY_OU="NOC"

#重新加载环境变量
[root@vpn-ldap 2.0]# source vars

#清除所有证书和相关文件
[root@vpn-ldap 2.0]# ./clean-all 

#生成新的根证书和根秘钥
[root@vpn-ldap 2.0]# ./build-ca 

#给服务器端生成证书和秘钥
[root@vpn-ldap 2.0]# ./build-key-server server

#给vpn客户端创建证书和秘钥，这里我们给shen创建
[root@vpn-ldap 2.0]# ./build-key shen

#生成Diffie Hellman文件
#生成过程可能有点慢，等待一会就好
[root@vpn-ldap 2.0]# ./build-dh 

#生成ta.key文件（防DDos攻击、UDP淹没等恶意攻击）
[root@vpn-ldap 2.0]# openvpn --genkey --secret keys/ta.key

# 在openvpn的配置目录下新建一个keys目录
[root@vpn-ldap ~]# mkdir -p /etc/openvpn/keys
 
#将openvpn服务端需要用到的证书和秘钥复制到/etc/openvpn/keys目录下
[root@vpn-ldap ~]# cp /usr/share/easy-rsa/2.0/keys/{ca.crt,server.{crt,key},dh2048.pem,ta.key} /etc/openvpn/keys/

#复制服务端配置文件到/etc/openvpn
[root@vpn-ldap ~]# cp /usr/share/doc/openvpn-2.4.4/sample/sample-config-files/server.conf /etc/openvpn/

#编辑server.conf文件参数
[root@vpn-ldap ~]# vim  /etc/openvpn/server.conf

#修改openvpn的默认监听端口
;port 1194
port 51194

#使用UDP协议。速度快，防止握手攻击
;proto tcp
proto udp

#采用桥接，nat模式，在这种模式下openvpn server就相当于一台nat防火墙设备
;dev tap
dev tun

#验证客户端证书是否合法
ca keys/ca.crt
#server端使用的证书
cert keys/server.crt
key keys/server.key  # This file should be kept secret

#dh文件
dh keys/dh2048.pem

#防DDOS攻击，服务器端0,客户端1
tls-auth keys/ta.key 0

#LDAP认证，通过调用openvpn-auth-ldap.so进行LDAP认证
plugin /usr/lib64/openvpn/plugin/lib/openvpn-auth-ldap.so "/etc/openvpn/auth/ldap.conf cn=%u"

#使用ldap认证，不需要客户端证书
client-cert-not-required 
username-as-common-name 

#设定server端虚拟出来的网段，设置给客户端虚拟局域网的网段
server 10.8.0.0 255.255.255.0

#防止Openvpn 重启后忘记client端曾经使用过的IP地址
ifconfig-pool-persist ipp.txt

#通过VPN Server往Client push路由，client通过pull指令获得Server push的所有选项并应用
push "route 172.31.0.0 255.255.0.0"
push "route 202.119.185.0 255.255.255.0"
push "route 202.119.186.0 255.255.255.0"
push "route 202.119.188.0 255.255.255.0"
push "route 202.119.189.0 255.255.255.0"

#使Client的默认网关指向VPN，让Client的所有Traffic都通过VPN走
;push "redirect-gateway def1 bypass-dhcp"

#给客户端push DNS
push "dhcp-option DNS 202.119.189.100"

 
#Nat后面使用VPN，如果长时间不通信，NAT session 可能会失效，导致vpn连接丢失。#所有keepalive提供一个类似ping的机制，每10秒通过vpn的control通道ping对方，
#如果120秒无法ping通，则认为丢失，并重启vpn,重新连接。
keepalive 10 120
 
#可以让vpn的client之间互相访问，直接通过openvpn程序转发
client-to-client
 
#允许多个客户端使用同一个证书连接服务端
duplicate-cn
 
#对数据进行压缩，注意server和client 一致
comp-lzo

#控制最大客户端数量
max-clients 20                               

#以nobody用户运行，较安全
user nobody                                     
group nobody

#通过keepalive检测超时后，重新启动vpn，不重新读取keys,保留第一次使用的keys
persist-key
 
#通过keepalive检测超时后,重新启动vpn,一直保持tun或tap设备是linkup的，否则网络连接会先linkdown然后linkup
persist-tun
 
#定义了10小时之后需要重新验证key
reneg-sec 36000

#openvpn2.1以上版本一定要加此行 
script-security 3  

#把openvpn的状态写入日志中，短日志，每分钟刷新一次
status /var/log/openvpn/openvpn-status.log
 
#log日志，只保存一次启动的日志，每次启动之前都会清除这个文本
log   /var/log/openvpn/openvpn.log
 
#全部日志，每次启动的日志在这个文本中会追加，openvpn重启后会删除log内容，log-append则是追加log内容，并不删除。
log-append  /var/log/openvpn/openvpn.log
 
#日志记录级别
verb 3

#记录了当天登陆openvpn的用户名和时间
client-connect /etc/openvpn/connect
client-disconnect /etc/openvpn/disconnect

启动openvpn服务

#将openvpn添加到开机自启动
[root@vpn-ldap ~]# chkconfig openvpn on
[root@vpn-ldap ~]# service openvpn start
Starting openvpn:                                          [  OK  ]
[root@vpn-ldap ~]#netstat -lptun |grep vpn
udp        0      0 0.0.0.0:51194               0.0.0.0:*                               6050/openvpn  

开启路由转发功能 
[root@vpn-ldap ~]#vim /etc/sysctl.conf
net.ipv4.ip_forward =1  //将net.ipv4.ip_forward = 0修改为net.ipv4.ip_forward = 1
#使sysctl.conf文件生效
[root@vpn-ldap ~]#sysctl -p

添加iptables转发规则,在防火墙配置文件添加如下nat
[root@vpn-ldap ~]#iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE      //10.8.0.0是vpn服务器提供的局域网
//如果服务器是双网卡，那么eth0这块就要视情况变动了，例如有两个网卡，一个是外网的，一个是内网的，如果想连上vpn之后访问内网，这块就要填写内网的网卡

iptable开放51194端口
[root@vpn-ldap ~]#iptables -A INPUT -p udp --dport 51194 -j ACCEPT  //添加51194的UDP端口

保存iptables配置
[root@vpn-ldap ~]#service iptables save

创建客户端配置文件openvpn.ovpn
client

client
dev tun
proto udp
remote 221.178.153.153 51194
resolv-retry infinite
nobind
persist-key
persist-tun
ns-cert-type server

#ldap使用用户名密码认证
auth-user-pass 

#定义了100小时之后需要重新验证key
reneg-sec 36000

comp-lzo
verb 3

<ca> 

</ca>

key-direction 1
<tls-auth> 
***********
</tls-auth>

给OpenVPN添加用户访问日志并发送邮件

建立/etc/openvpn/connect文件，文件内容如下：
#!/bin/bash
day=`date +%F`
if [ -f /var/log/openvpn/log$day ];then
        echo "`date '+%F %H:%M:%S'` User $common_name IP $trusted_ip is logged in" >>/var/log/openvpn/log$day
else
        touch /var/log/openvpn/log$day
        echo "`date '+%F %H:%M:%S'` User $common_name IP $trusted_ip is logged in" >>/var/log/openvpn/log$day
fi

建立/etc/openvpn/disconnect文件，文件内容如下：
#!/bin/bash
day=`date +%F`
if [ -f /var/log/openvpn/log$day ];then
        echo "`date '+%F %H:%M:%S'` User $common_name IP $trusted_ip is logged off" >>/var/log/openvpn/log$day
else
        touch /var/log/openvpn/log$day
        echo "`date '+%F %H:%M:%S'` User $common_name IP $trusted_ip is logged off" >>/var/log/openvpn/log$day
fi

要将这两个脚本赋予执行权限
chmod +x /etc/openvpn/connect
chmod +x /etc/openvpn/disconnect
需要注意的一点是因为openvpn是以nodody帐号在运行，因此必须赋予nodody帐号对/var/log/openvpn这个目录的写权限，否则openvpn的运行将受到影响，用户登录过程不能完成。

2、修改openvpn服务器配置文件，启用脚本
修改/etc/openvpn/server.conf，添加如下两行
client-connect /etc/openvpn/connect
client-disconnect /etc/openvpn/disconnect
这样每天就会在/var/log/openvpn下面建立文件名为2007-06-04这样的文件，该文件记录了当天登陆openvpn的用户名和时间，输出例如：
2011-09-21 14:26:23 User client1 IP 120.31.66.103 is logged off
2011-09-21 14:26:27 User client1 IP 120.31.66.103 is logged in （这里需要注意，因为openvpn本身判断机制的原因，登出时间比实际登出时间慢3分钟）

3、安装sendmail与mail
安装sendmail
yum -y install sendmail
启动并设置开机启动
service sendmail start
chkconfig --level 3 sendmail on
安装mail
yum install -y mailx

4.设置发件人信息
上述发送邮件默认会使用linux当前登录用户信，通常会被当成垃圾邮件，指定发件人邮箱信息命令：vi /etc/mail.rc，编辑内容如：

set from=security@cpu.edu.cn
set smtp=smtphm.qiye.163.com
set smtp-auth-user=security@cpu.edu.cn
set smtp-auth-password=Cpu83271450
set smtp-auth=login

注意：如何发件服务器开通了客户端授权码，则配置中的smtp-auth-password不是邮箱登录密码，是邮箱服务器开启smtp的授权码，每个邮箱开启授权码操作不同（网易126邮箱开启菜单：设置-> 客户端授权密码）。

5、建立/etc/openvpn/mail2admin,并赋予执行权限 chmod +x mail2admin
#!/bin/bash
today=`date +%F`
if [ -f /var/log/openvpn/log$today ];then
mail -s “$today openvpn user access log” sjn@cpu.edu.cn < /var/log/openvpn/log$today
fi

6、建立cron工作表，每天定时23：55分发送当天的日志给管理员
#crontab -e
55 23 * * * /etc/openvpn/mail2admin





