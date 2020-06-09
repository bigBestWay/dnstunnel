#dnstunnel
使用者需要在域名服务做如下配置(以gandi.net为例):  
添加一条A记录: ns1 10800 IN A 55.55.55.55  
再添加一条NS记录: 1 1800 IN NS ns1.test.website.  

按照以上添加后  
在55.55.55.55上启动NDNS_server  
在目标机带参数启动NDNS_client .1.test.website


