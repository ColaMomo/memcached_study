# memcached 学习笔记

## memcached 整体架构
* 线程模型
* 请求处理
* 内存模型

## memcached 代码结构
* memcached.h -- memcached重要数据结构的定义如conn，conn_state，item
* memcached.c -- 启动入口
* thread.c -- worker线程初始化，以及封装了一些item的操作（item的具体操作在item.c中）
* item.c -- item的相关操作
* slab.c -- slab管理
* assoc.c -- hash表的相关操作

## 相关资源

##### 使用指南
* [Memcached常用命令及使用说明](http://www.cnblogs.com/jeffwongishandsome/archive/2011/11/06/2238265.html)

##### 架构原理
* [memcached全面剖析](http://www.cnblogs.com/shanyou/archive/2008/12/05/1348293.html)

##### 源码分析
* [memcached源码分析](http://blog.csdn.net/initphp/article/details/43915683)
* [memcached源码分析](http://calixwu.com/2014/11/memcached-yuanmafenxi.html)
* [memcached源码分析](http://blog.csdn.net/u013702678/article/category/1912405)
* [memcached学习笔记](http://www.hcoding.com/?p=121)
