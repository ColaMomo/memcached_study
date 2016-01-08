# memcached 线程模型

* memcahced使用libevent来处理网络请求。（后端：epoll）
* memcached采用多线程的设计，主要有两种线程，主线程和worker线程，主线程负责监听网络连接，worker线程负责处理请求的读写事件以及完成具体的请求操作。

## 主线程

主线程结构体定义  

``` c
typedef struct {
    pthread_t thread_id;        //线程id
    struct event_base *base;    //event_base
} LIBEVENT_DISPATCHER_THREAD;
```

主线程的整理流程(memcached.c)：
``` c
int main (int argc, char** argv) {
    ...
    //初始化主线程的libevent实例
    main_base = event_init();

    //初始化线程，参数是worker线程个数和主线程的event_base，实现见Thread.c
    //worker线程个数默认为4
    thread_init(settings.num_threads, main_base);

    //建立服务端的server_socket（tcp协议）
    if (settings.port && server_sockets(settings.port, tcp_transport, portnumber_file)) {
        vperror("failed to listen on TCP port %d", settings.port);
        exit(EX_OSERR);
    }

    //进入libevent的事件循环
    if (event_base_loop(main_base, 0) != 0) {
        retval = EXIT_FAILURE;
    }
    ...
}
```

初始化主线程（thread.c）  
``` c
void thread_init(int nthreads, struct event_base *main_base) {
    //创建nthreads个worker线程对象
    threads = calloc(nthreads, sizeof(LIBEVENT_THREAD));

    //设置主线程对象的event_base
    dispatcher_thread.base = main_base;
    //设置主线程对象的pid
    dispatcher_thread.thread_id = pthread_self();

    //为每个work线程创建与主线程通信的管道
    for (i = 0; i < nthreads; i++) {
        int fds[2];
        //建立管道
        if (pipe(fds)) {
            perror("Can't create notify pipe");
            exit(1);
        }
        threads[i].notify_receive_fd = fds[0]; //worker线程管道接收fd
        threads[i].notify_send_fd = fds[1];  //worker线程管道发送fd
        //初始化worker线程的libevent配置
        setup_thread(&threads[i]);
    }

    for (i = 0; i < nthreads; i++) {
        //创建worker线程，配置worker线程运行的函数：worker_libevent
        create_worker(worker_libevent, &threads[i]);
    }
}
```

创建服务端server_socket
``` c
static int server_sockets(int port, enum network_transport transport,
                          FILE *portnumber_file) {
    if (settings.inter == NULL) { //如果没有指定ip
        return server_socket(settings.inter, port, transport, portnumber_file);
    } else {
		    //如果有指定ip端口的话，则解析出指定的ip和端口，并创建socket
        ...
        ret |= server_socket(p, the_port, transport, portnumber_file);
        return ret;
    }
}
```

创建服务端socket
主要流程：
1. 获取网络地址
2. 创建socket
3. 设置socket相关属性，绑定地址
4. 监听连接
5. 创建事件，加入主线程的 event_base

``` c
static int server_socket(const char *interface, int port, enum network_transport transport, FILE *portnumber_file) {
    struct addrinfo *ai;
    struct addrinfo *next;
    struct addrinfo hints = { .ai_flags = AI_PASSIVE, .ai_family = AF_UNSPEC };
    snprintf(port_buf, sizeof(port_buf), "%d", port);
	  //获取网络地址（将主机名映射到网络地址）
    error= getaddrinfo(interface, port_buf, &hints, &ai);

    for (next= ai; next; next= next->ai_next) {
        conn *listen_conn_add;
        if ((sfd = new_socket(next)) == -1) {  //创建socket
            ...
        }
        //设置socket的属性
        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
        if (IS_UDP(transport)) {
            maximize_sndbuf(sfd);
        } else {
            error = setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));
            error = setsockopt(sfd, SOL_SOCKET, SO_LINGER, (void *)&ling, sizeof(ling));
            error = setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));
        }
        //将地址ai_addr与socket（sfd）绑定
        if (bind(sfd, next->ai_addr, next->ai_addrlen) == -1) {
            close(sfd);
            continue;
        } else {
            success++;
            //listen(): 监听连接
            if (!IS_UDP(transport) && listen(sfd, settings.backlog) == -1) {
                ...
            }
        }
        if (IS_UDP(transport)) {
            ...
        } else {
            //conn_new() 创建事件，加入主线程libevent进行监听
            if (!(listen_conn_add = conn_new(sfd, conn_listening, EV_READ | EV_PERSIST, 1, transport, main_base))) {
                ...
            }
            listen_conn_add->next = listen_conn;
            listen_conn = listen_conn_add;
        }
    }
	  //释放getaddrinfo()获取的网络地址的空间
    freeaddrinfo(ai);
    return success == 0;
}
```

创建连接对象，并加入监听事件
``` c
//参数：sfd: 要监听的socket fd； init_state: 连接的初始化状态conn_states； event_flags: 监听的事件； read_buff_size: 度缓存大小； transport: 监听的socket类型； base: libevent对象event_base
//返回值：每监听一个fd，都会创建一个conn来保存连接信息
conn *conn_new(const int sfd, enum conn_states init_state,
                const int event_flags,
                const int read_buffer_size, enum network_transport transport,
                struct event_base *base) {
    conn *c;
    c = conns[sfd];
    if (NULL == c) {
        if (!(c = (conn *)calloc(1, sizeof(conn)))) {
        }
        MEMCACHED_CONN_CREATE(c);


        //初始化conn对象的一些参数
        c->rbuf = (char *)malloc((size_t)c->rsize);
        c->wbuf = (char *)malloc((size_t)c->wsize);
        ...

        c->sfd = sfd;
        conns
       [sfd] = c;
    }

    if (transport == tcp_transport && init_state == conn_new_cmd) {
        if (getpeername(sfd, (struct sockaddr *) &c->request_addr,
                        &c->request_addr_size)) { //获取请求方的ip地址
            ...
        }
    }
  	//初始化conn对象的一些参数
    c->state = init_state;
    ...

  	//创建libevent监听事件，并指定回调函数event_handler
    event_set(&c->event, sfd, event_flags, event_handler, (void *)c);
  	//将事件加入到libevent中
    event_base_set(base, &c->event);
    c->ev_flags = event_flags;

  	//把事件加入监听
    if (event_add(&c->event, 0) == -1) {
    }

    stats.curr_conns++;
    stats.total_conns++;
    MEMCACHED_CONN_ALLOCATE(c->sfd);
    return c;
}
```

## worker线程

worker线程的结构体定义
worker线程和主线程相比，主要多了两个管道fd，和连接对象CQ_ITEM队列
``` c
typedef struct {
    pthread_t thread_id;         //线程id
    struct event_base *base;     //每个线程自己独立的event_base，监听的就是下面的notify_event事件对象
    struct event notify_event;  //事件对象，fd即为下面的notify_receive_fd
    int notify_receive_fd;      //管道接收fd
    int notify_send_fd;         //管道写入fd
    struct thread_stats stats;  //线程的一些统计
    struct conn_queue *new_conn_queue; //连接参数对象CQ_ITEM队列
    cache_t *suffix_cache;      
    uint8_t item_lock_type;     //控制线程锁的粒度
} LIBEVENT_THREAD;
```

在init_thread()初始化主线程时，会创建worker线程。
创建worker线程分为两步，首先调用setup_thread()初始化worker线程， 再调用create_worker() 创建worker线程，指定线程运行的起始函数：worker_libevent()。

初始化worker线程
这里主要作两个工作，一是初始化work线程的libevent和监听事件；二是初始化worker线程的CQ_ITEM队列。
``` c
static void setup_thread(LIBEVENT_THREAD *me) {
    //初始化worker线程的libevent
    me->base = event_init();
    //设置事件，监听与主线程的通信，事件处理函数为thread_libevent_process
    event_set(&me->notify_event, me->notify_receive_fd,
              EV_READ | EV_PERSIST, thread_libevent_process, me);
    event_base_set(me->base, &me->notify_event);
  	//将事件添加到libevent的事件循环中
    if (event_add(&me->notify_event, 0) == -1) {
    }

    //创建一个空队列，用于接收主线程发送过来的CQ_ITEM
    me->new_conn_queue = malloc(sizeof(struct conn_queue));
    //初始化CQ_ITEM队列
    cq_init(me->new_conn_queue);

    if (pthread_mutex_init(&me->stats.mutex, NULL) != 0) {
    }
    me->suffix_cache = cache_create("suffix", SUFFIX_SIZE, sizeof(char*),
}
```

创建worker线程
``` c
static void create_worker(void *(*func)(void *), void *arg) {
    pthread_t       thread;
    pthread_attr_t  attr;
    int             ret;
    pthread_attr_init(&attr);
    //创建线程
    //参数： thread: 指向线程标识符的指针; attr: 用来设置线程属性; func: 是线程运行函数的起始地址; arg: 运行函数的参数。
    if ((ret = pthread_create(&thread, &attr, func, arg)) != 0) {
    }
}
```

worker线程的起始函数：
```
 //启动worker线程的libevent主循环
static void *worker_libevent(void *arg) {
    LIBEVENT_THREAD *me = arg;
  	//每一个worker线程进入libevent循环，执行init_count++，主线程通过init_count确认所有线程都启动完毕
    register_thread_initialized();

    //进入libevent事件循环
    event_base_loop(me->base, 0);
    return NULL;
}
```

## 主线程与worker线程的通信

* 主线程负责接连接，worker线程负责具体的读写操作。
* 主线程接收连接后，将client_fd包装程CQ_ITEM对象，放入选择一个worker线程，将其放入worker线程的CQ_ITEM列表中。同时往worker线程的管道中写入一个字符“c”
* worker线程会监听管道事件，当关当读取fd上事件发生时，从队列中取出一个CQ_ITEM, 进行后续处理。

当有调用方请求连接时，主线程监听scoket读事件发生，执行回调函数event_handler()

```
void event_handler(const int fd, const short which, void *arg) {
    conn *c;
    c = (conn *)arg;
    assert(c != NULL);
    c->which = which;

    if (fd != c->sfd) {
        ...
        return;
    }

	//状态处理机，执行事件发生后的业务逻辑
    drive_machine(c);
    return;
}
```

drive_machine() 状态处理机是负责整个请求交互的核心函数，这里先只看主线程监听到连接请求的操作
```
static void drive_machine(conn *c) {
    bool stop = false;
    while (!stop) {
        switch(c->state) {
		//当主线程listen_fd有事件到达后触发，主线程的线程状态都是conn_listening状态
        case conn_listening:
            addrlen = sizeof(addr);
            sfd = accept(c->sfd, (struct sockaddr *)&addr, &addrlen);
            if (settings.maxconns_fast &&
                stats.curr_conns + stats.reserved_fds >= settings.maxconns - 1) {
                stats.rejected_conns++;
            } else {
				//主线程服务端接收到请求后，把client_fd分发给worker线程处理
                dispatch_conn_new(sfd, conn_new_cmd, EV_READ | EV_PERSIST,
                                     DATA_BUFFER_SIZE, tcp_transport);
            }

            stop = true;
            break;
        }
    }  
}
```

将主线程的连接分发给worker线程  
这里主要完成两个工作，一是将接收到的client_fd封装成CQ_ITEM对象，写入到worker线程的CQ_ITEM队列中；二是向CQ_ITEM的管道写入一个字符c，通知从先程进行处理。  

```
void dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags,
                       int read_buffer_size, enum network_transport transport) {
	//创建CQ_ITEM对象，封装了client_fd以及一些client连接信息
	CQ_ITEM *item = cqi_new();
    char buf[1];

	//通过轮询的方式选择worker线程
    int tid = (last_thread + 1) % settings.num_threads;
    LIBEVENT_THREAD *thread = threads + tid;
    last_thread = tid;

	//初始化CQ_ITEM对象
    item->sfd = sfd;
    item->init_state = init_state;
    item->event_flags = event_flags;
    item->read_buffer_size = read_buffer_size;
    item->transport = transport;

	//将CQ_ITEM放入所选择的worker线程的CQ_ITEM队列中
    cq_push(thread->new_conn_queue, item);

    MEMCACHED_CONN_DISPATCH(sfd, thread->thread_id);
    buf[0] = 'c';
	//主线程向所选择的worker线程的管道中写入一个'c'字符，
	//由于worker线程会监听管道的receive_fd, 于是会收到事件通知
	//触发worker线程的事件处理函数thread_libevent_process
    if (write(thread->notify_send_fd, buf, 1) != 1) {
    }
}
```

在worker线程的初始化方法setup_thread()中，worker线程将读取管道加入监听事件，当主线程向管道写入字符时，worker线程监听到事件发生，触发回调函数thread_libevent_process()

```
static void thread_libevent_process(int fd, short which, void *arg) {
    LIBEVENT_THREAD *me = arg;
    CQ_ITEM *item;
    char buf[1];

    if (read(fd, buf, 1) != 1) ｛｝

    switch (buf[0]) {
    case 'c':
	//从队列中取出主线程放入的CQ_ITEM
    item = cq_pop(me->new_conn_queue);

    if (NULL != item) {
		//创建监听事件，把worker线程传过来的client_fd加入监听事件，使用的是worker线程的libevent
        conn *c = conn_new(item->sfd, item->init_state, item->event_flags,
                           item->read_buffer_size, item->transport, me->base);
        if (c == NULL) {
        	...
        } else {
			//设置监听连接的线程为当前worker线程
            c->thread = me;
        }
        cqi_free(item);
    }
        break;
    case 'l':
    me->item_lock_type = ITEM_LOCK_GRANULAR;
    register_thread_initialized();
        break;
    case 'g':
    me->item_lock_type = ITEM_LOCK_GLOBAL;
    register_thread_initialized();
        break;
    }
}
```

在worker线程监听管道事件发生的回调函数中，worker线程也会调用conn_new(), 回看一下这个方法：  
主线程调用conn_new时，监听的是serversocket_fd，conn_state为conn_listening  
worker线程调用conn_new时，监听的是clientsocket_fd, conn_state为conn_new_cmd  
主线程和worker线程拥有各自独立的event_base

```
conn *conn_new(const int sfd, enum conn_states init_state,
                const int event_flags,
                const int read_buffer_size, enum network_transport transport,
                struct event_base *base) {
    ...
    event_set(&c->event, sfd, event_flags, event_handler, (void *)c);
  	//将事件加入到libevent中
    event_base_set(base, &c->event);
    if (event_add(&c->event, 0) == -1) {
    }
    ...
}
```

由此可以看出，worker线程监听两类事件，  
一类是读取管道fd上的事件，负责与主线程进行交互，处理函数为thread_libevent_process()  
一类是clientsocket_fd上的事件，负责与客户端进行交互，处理函数为event_handler()  
