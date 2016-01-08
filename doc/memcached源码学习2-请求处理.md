# memcached 请求处理

## 连接对象

memcached使用conn结构体来表示一个连接对象。

```
//连接对象
typedef struct conn conn;
struct conn {
    int    sfd; //连接的socket_fd
    sasl_conn_t *sasl_conn;
    bool authenticated;
    enum conn_states  state; //当前的连接状态
    enum bin_substates substate;
    rel_time_t last_cmd_time;
    struct event event; //监听的事件
    short  ev_flags; //监听的事件类型
    short  which;    //刚触发的事件

    char   *rbuf;   //从socket读入数据的缓存
    char   *rcurr;  //从rbuf中读出数据时，用于表示尚未读取数据的起始位置
    int    rsize;   //读buffer大小
    int    rbytes;  //rbuf中剩余数据的大小 

    char   *wbuf;  //向socket中写入数据的缓存
    char   *wcurr;  //从wbuf向socket中写入数据时，尚未写入数据的起始位置
    int    wsize;
    int    wbytes;
    enum conn_states  write_and_go;  //完成写操作后，将连接状态置为此状态
    void   *write_and_free;

    char   *ritem;    //指向item结构体的data中value地址
    int    rlbytes;   //尚未读完item的data的value的字节数
    void   *item;     //执行set/add/replace命令时，用于指向分配的item空间

    int    sbytes;   

	//下面是向socket写入数据时用的字段
    struct iovec *iov;  //iovec结构体数组
    int    iovsize;     //*iov数组大小
    int    iovused;     //*iov数组已被使用的元素个数

    struct msghdr *msglist;  //msghdr结构体数组，表示sendmsg要发送的消息列表
    int    msgsize;    //*msglist数组大小
    int    msgused;    //*msglist数组已使用的元素个数
    int    msgcurr;    //当前要发送的msghdr
    int    msgbytes;   //当前msghdr的字节数

    item   **ilist;  //get key1 key2命令时，要发送给客户端的item列表
    int    isize;    //列表大小
    item   **icurr;  //当前要发送的item
    int    ileft;	 //剩余item数目

    char   **suffixlist;
    int    suffixsize;
    char   **suffixcurr;
    int    suffixleft;

    enum protocol protocol;   
	enum network_transport transport; 
	
	//UDP相关的字段
    int    request_id; 
    struct sockaddr_in6 request_addr; 
    socklen_t request_addr_size;
    unsigned char *hdrbuf; 
    int    hdrsize;  

    bool   noreply;   
    struct {
        char *buffer;
        size_t size;
        size_t offset;
    } stats;

	//二进制相关的字段
    protocol_binary_request_header binary_header;
    uint64_t cas; 
    short cmd; 
    int opaque;
    int keylen;
    conn   *next;    
    LIBEVENT_THREAD *thread;
};
```

连接状态结构体

//枚举，连接状态
//主线程和worker线程都调用conn_new监听fd并创建conn对象
//当监听事件发生，event_handler被触发，调用drive_machine,
//根据conn_states来执行相应的操作  

```
enum conn_states {
    conn_listening,  /**< the socket which listens for connections */
    conn_new_cmd,    /**< Prepare connection for next command */
    conn_waiting,    /**< waiting for a readable socket */
    conn_read,       /**< reading in a command line */
    conn_parse_cmd,  /**< try to parse a command from the input buffer */
    conn_write,      /**< writing out a simple response */
    conn_nread,      /**< reading in a fixed number of bytes */
    conn_swallow,    /**< swallowing unnecessary bytes w/o storing */
    conn_closing,    /**< closing this connection */
    conn_mwrite,     /**< writing out many items sequentially */
    conn_closed,     /**< connection is closed */
    conn_max_state   /**< Max state value (used for assertion) */
};
```

## 状态处理机 


状态处理机的主体是一个while循环，里包含一个switch case，根据conn当前的连接状态conn_state，进入不同的case  
case可能会改变conn的连接状态，连接状态不断发生转移，在下一次循环进入另一个case  
直到最终进入某个case，将stop设置为true，结束循环  

```
static void drive_machine(conn *c) {
    bool stop = false;
    int nreqs = settings.reqs_per_event; //每个连接可以处理的最大请求数
    int res;
    const char *str;
    assert(c != NULL);

    while (!stop) {

        switch(c->state) {
        case conn_listening:	//主线程等待连接
          
        case conn_waiting:		//等待数据
         
        case conn_read:			//读取数据
			
        case conn_parse_cmd :	//解析数据
			
        case conn_new_cmd:		//worker线程初始化状态
           
        case conn_nread:		//进一步读区数据
			
        case conn_swallow:
         
        case conn_write:		//写入数据准备
           
        case conn_mwrite:		//写入数据执行
    
        case conn_closing:
        
        case conn_closed:
          
        case conn_max_state:
           
        }
    }

    return;
}

```

conn_lisntening为主线程建立连接的状态，具体执行的操作参见线程模型中的介绍。  
其他状态都是worker线程的状态。 下面分别看每个状态对应的处理操作。

### conn_new_cmd

work线程创建调用conn_new()方法创建连接对象，将连接状态初始化为conn_new_cmd, 监听clientsocket_fd.

```
case conn_new_cmd:
	//一次event的发生，有可能包含多个命令，从client_fd里读取到的一次数据，可能是多个命令数据堆在一起的一次时间通知
	//nreqs用来控制一次event最多能处理多少个命令
    --nreqs;
    if (nreqs >= 0) {
		//准备执行命令，reset_cmd_handler做了一些解析命令之前的初始化动作
        reset_cmd_handler(c);
    } else {
		...
        stop = true;
    }
    break;
```

重置命令处理  
当client_fd第一次发送命令时，worker线程处于conn_new_cmd状态，此时conn对象的读buf中还没有可读数据，因此worker线程进入conn_waiting状态。

```
static void reset_cmd_handler(conn *c) {
    c->cmd = -1;
    c->substate = bin_no_state;
    if(c->item != NULL) {
        item_remove(c->item); //清理item对象
        c->item = NULL;
    }
    conn_shrink(c);  //对buffer进行缩容
	//根据连接对象conn的读buf中是否有可读数据来决定进入哪个状态
    if (c->rbytes > 0) {
        conn_set_state(c, conn_parse_cmd);  //有可读数据，进入conn_parse_cmd状态
    } else {
        conn_set_state(c, conn_waiting);	//没有可读数据，进入conn_waiting状态
    }
}
```

### conn_waiting
conn_waiting状态会重新添加client_fd的读事件，并将连接状态更改为conn_read。  
但是，在update_event()中可以看到，如果更新事件的flag与之前相同，则不会重新添加事件，这是利用了epoll的水平触发机制，只要fd中还有可读数据，那么每epoll_wait 都会触发事件。

```
//等待数据
case conn_waiting:
if (!update_event(c, EV_READ | EV_PERSIST)) {
}

//将状态改为conn_read, 退出状态机循环
conn_set_state(c, conn_read);
stop = true;
break;
```

```
static bool update_event(conn *c, const int new_flags) {
    assert(c != NULL);

    struct event_base *base = c->event.ev_base;
    if (c->ev_flags == new_flags)
        return true;
    if (event_del(&c->event) == -1) return false;
    event_set(&c->event, c->sfd, new_flags, event_handler, (void *)c);
    event_base_set(base, &c->event);
    c->ev_flags = new_flags;
    if (event_add(&c->event, 0) == -1) return false;
    return true;
}
```

### conn_read

```
//执行读取数据
case conn_read:
//读出请求
res = IS_UDP(c->transport) ? try_read_udp(c) : try_read_network(c);

switch (res) {
case READ_NO_DATA_RECEIVED:
     conn_set_state(c, conn_waiting);  //如果没有数据，则继续等待
     break;
case READ_DATA_RECEIVED:  //成功接收数据，进入conn_parse_cmd状态，解析命令
     conn_set_state(c, conn_parse_cmd);
     break;
case READ_ERROR:
     conn_set_state(c, conn_closing);
     break;
case READ_MEMORY_ERROR:  //分配内存失败
     break;
}
break;
```

try_read_network() 将client_fd中的数据读取到连接对象的rbuf中
```
static enum try_read_result try_read_network(conn *c) {
    enum try_read_result gotdata = READ_NO_DATA_RECEIVED;
    int res;
    int num_allocs = 0;
    assert(c != NULL);

    if (c->rcurr != c->rbuf) {  //将尚未读取的数据重新放入rbuf中
        if (c->rbytes != 0) 
            memmove(c->rbuf, c->rcurr, c->rbytes);
        c->rcurr = c->rbuf;
    }

    while (1) {
        if (c->rbytes >= c->rsize) { //如果rbuf中剩余数据大于rbuf的大小，则对rbuf进行扩容
     		...
            char *new_rbuf = realloc(c->rbuf, c->rsize * 2);
            if (!new_rbuf) {
            	...
                return READ_MEMORY_ERROR;
            }
            c->rcurr = c->rbuf = new_rbuf;
            c->rsize *= 2;
        }

        int avail = c->rsize - c->rbytes; //读buffer空间还有多少可用
                res = read(c->sfd, c->rbuf + c->rbytes, avail); //往剩下的空间写入数据
        if (res > 0) {
            gotdata = READ_DATA_RECEIVED;
            c->rbytes += res;   //rytes是当前指针rcurr至读buffer末尾的数据大小
            if (res == avail) { //socket还有可读数据
                continue;
            } else { //socket的可读数据都读取完毕
                break;
            }
        }
        if (res == 0) {
            return READ_ERROR;
        }
        if (res == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            return READ_ERROR;
        }
    }
    return gotdata;
}
```

### conn_parse_cmd

在conn_read状态机处理方法中，如果把数据成功读区到rbuf中，则将状态设置为conn_parse_cmd，对命令进行解析。

```
//解析读出的数据
case conn_parse_cmd :
	//解析数据，如果解析的数据不够成一个完整的命令，则进入等待状态，等待更多的数据到达
    if (try_read_command(c) == 0) {
        conn_set_state(c, conn_waiting);
    }
    break;
```

```
//解析读取到的数据
static int try_read_command(conn *c) {
	//根据读区数据中的第一个字节确定数据协议
	//如果第一个字节时二进制协议的魔数，则为二进制协议，否则为ascii协议
    if (c->protocol == negotiating_prot || c->transport == udp_transport)  {
        if ((unsigned char)c->rbuf[0] == (unsigned char)PROTOCOL_BINARY_REQ) { //PROTOCOL_BINARY_REQ 定义参见ProtoCol_binary.h
            c->protocol = binary_prot;
        } else {
            c->protocol = ascii_prot;
        }
    }

    if (c->protocol == binary_prot) { 	//解析二进制协议
		...
	} else {	//解析ascii协议
		...
    }

    return 1;
}
```

* 二进制协议

数据格式定义：

	Byte/     0       |       1       |       2       |       3       |
       /              |               |               |               |
      |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
      +---------------+---------------+---------------+---------------+
     0/ HEADER                                                        /
      /                                                               /
      /                                                               /
      /                                                               /
      +---------------+---------------+---------------+---------------+
    24/ COMMAND-SPECIFIC EXTRAS (as needed)                           /
     +/  (note length in the extras length header field)              /
      +---------------+---------------+---------------+---------------+
     m/ Key (as needed)                                               /
     +/  (note length in key length header field)                     /
      +---------------+---------------+---------------+---------------+
     n/ Value (as needed)                                             /
     +/  (note length is total body length header field, minus        /
     +/   sum of the extras and key length body fields)               /  
     +----------------+---------------+---------------+---------------+
        Total 24 bytes
 
协议头定义：

	Byte/     0       |       1       |       2       |       3       |  
	   /              |               |               |               |  
	  |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|  
	  +---------------+---------------+---------------+---------------+  
	 0| Magic         | Opcode        | Key length                    |  
	  +---------------+---------------+---------------+---------------+  
	 4| Extras length | Data type     | vbucket id                    |  
	  +---------------+---------------+---------------+---------------+  
	 8| Total body length                                             |  
	  +---------------+---------------+---------------+---------------+  
	12| Opaque                                                        |  
	  +---------------+---------------+---------------+---------------+  
	16| CAS                                                           |  
	  |                                                               |  
	  +---------------+---------------+---------------+---------------+  
		Total 24 bytes  

由于二进制协议和文本协议的不同，在读取和解析数据时的操作也不同。  
对于二进制协议，连接进入conn_read状态时，会先读取header里的内容，然后将状态设置为conn_nread, 把body里面的内容读进c->ritem中。  
对于文本协议，连接进入conn_read状态时，会先读取一行的内容（以行结束符“\r\n”为标志），然后根据具体命令的不同，进入不同的状态。比如get命令，则直接进入conn_write状态；而set命令，需要进入conn_nread状态，将value的内容读取到c->ritem中。  

#### 解析二进制协议的命令

读取二进制数据，设置键长度，body长度，cas，命令类型等。  
再调用dispatch_bin_command() 根据命令类型进一步解析命令。

```
if (c->protocol == binary_prot) {
        if (c->rbytes < sizeof(c->binary_header)) {  //判断协议头是否完整
            return 0;
        } else {
#ifdef NEED_ALIGN
            if (((long)(c->rcurr)) % 8 != 0) {  //数据对齐
            	...    
			}
#endif
            protocol_binary_request_header* req;
            req = (protocol_binary_request_header*)c->rcurr;

            c->binary_header = *req;
            c->binary_header.request.keylen = ntohs(req->request.keylen);
            c->binary_header.request.bodylen = ntohl(req->request.bodylen);
            c->binary_header.request.cas = ntohll(req->request.cas);
      
            c->msgcurr = 0;
            c->msgused = 0;
            c->iovused = 0;
            if (add_msghdr(c) != 0) {
                out_of_memory(c,
                        "SERVER_ERROR Out of memory allocating headers");
                return 0;
            }

            c->cmd = c->binary_header.request.opcode;  //设置命令类型
            c->keylen = c->binary_header.request.keylen;
            c->opaque = c->binary_header.request.opaque;
            c->cas = 0;

            dispatch_bin_command(c);

            c->rbytes -= sizeof(c->binary_header);
            c->rcurr += sizeof(c->binary_header);
        }

```

解析二进制协议的命令，根据命令类型，执行下一步操作。  
对于有些命令，如get，set等直接返回；对于有些命令需要进一步读取数据.

```
static void dispatch_bin_command(conn *c) {
	...
    switch (c->cmd) {
    	...
    	case PROTOCOL_BINARY_CMD_SET: /* FALLTHROUGH */
		case PROTOCOL_BINARY_CMD_ADD: /* FALLTHROUGH */
		case PROTOCOL_BINARY_CMD_REPLACE:
            if (extlen == 8 && keylen != 0 && bodylen >= (keylen + 8)) {
                bin_read_key(c, bin_reading_set_header, 8);
            } else {
                protocol_error = 1;
            }
            break;
		case PROTOCOL_BINARY_CMD_GETQ:  /* FALLTHROUGH */
		case PROTOCOL_BINARY_CMD_GET:   /* FALLTHROUGH */
		case PROTOCOL_BINARY_CMD_GETKQ: /* FALLTHROUGH */
		case PROTOCOL_BINARY_CMD_GETK:
            if (extlen == 0 && bodylen == keylen && keylen > 0) {
                bin_read_key(c, bin_reading_get_key, 0);
            } else {
                protocol_error = 1;
            }
            break;
       	...
	}
    if (protocol_error)
        handle_binary_protocol_error(c);
}
```

```
static void bin_read_key(conn *c, enum bin_substates next_substate, int extra) {
    ...
    c->ritem = c->rcurr + sizeof(protocol_binary_request_header);
    conn_set_state(c, conn_nread);  //将连接状态设置为进一步读取数据状态
}
```

#### 解析ascii协议命令

```
else {
	char *el, *cont;

	if (c->rbytes == 0)  //读buffer中没有待解析的数据
		return 0;

	el = memchr(c->rcurr, '\n', c->rbytes); //通过换行符先找到第一个命令
	if (!el) {
		if (c->rbytes > 1024) { //处理数据过长的情况
			...
		}

            //如果没有找到换行符，说明数据还不构成一个完整的命令，返回0
			return 0;
        }
		//记录下一个命令的起始位置
        cont = el + 1;
		//将读取到的命令截取为字符串，eg: GET abc\r\n 变为 GET abc\0
        if ((el - c->rcurr) > 1 && *(el - 1) == '\r') {
            el--;
        }
        *el = '\0';

        assert(cont <= (c->rcurr + c->rbytes));

        c->last_cmd_time = current_time;
		//解析命令
        process_command(c, c->rcurr);
		//当前命令执行完后，rcurr指向下一个命令的开头
		//并计算rbytes的大小
        c->rbytes -= (cont - c->rcurr);
        c->rcurr = cont;

        assert(c->rcurr <= (c->rbuf + c->rsize));
    }
```

```
//解析与执行memcached命令
//这里只是执行了命令的一半，然后根据命令类型再次改变conn_state使程序再次进入状态机，
//完成命令的另一半工作
static void process_command(conn *c, char *command) {

    token_t tokens[MAX_TOKENS];
    size_t ntokens;
    int comm; //命令类型

    assert(c != NULL);

    MEMCACHED_PROCESS_COMMAND_START(c->sfd, c->rcurr, c->rbytes);

    if (settings.verbose > 1)
        fprintf(stderr, "<%d %s\n", c->sfd, command);

    c->msgcurr = 0;
    c->msgused = 0;
    c->iovused = 0;
    if (add_msghdr(c) != 0) {
        out_of_memory(c, "SERVER_ERROR out of memory preparing response");
        return;
    }

	//词法分析器，将命令分解成一个个token
    ntokens = tokenize_command(command, tokens, MAX_TOKENS);
    //对分解出来的token进行语法分析，解析命令
	if (ntokens >= 3 &&
        ((strcmp(tokens[COMMAND_TOKEN].value, "get") == 0) ||
         (strcmp(tokens[COMMAND_TOKEN].value, "bget") == 0))) {

        process_get_command(c, tokens, ntokens, false);

    } else if ((ntokens == 6 || ntokens == 7) &&
               ((strcmp(tokens[COMMAND_TOKEN].value, "add") == 0 && (comm = NREAD_ADD)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "set") == 0 && (comm = NREAD_SET)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "replace") == 0 && (comm = NREAD_REPLACE)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "prepend") == 0 && (comm = NREAD_PREPEND)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "append") == 0 && (comm = NREAD_APPEND)) )) {

		//add/set/replace/prepend/append为“更新”命令，调用同一个函数执行命令
        process_update_command(c, tokens, ntokens, comm, false);

    } else if() {
    	...
    } else {
        out_string(c, "ERROR");
    }
    return;
}
```

process_get_command 处理get请求，并将连接状态设置为conn_mwrite  

```
static inline void process_get_command(conn *c, token_t *tokens, size_t ntokens, bool return_cas) {
    ...
    conn_set_state(c, conn_mwrite);
    c->msgcurr = 0;
}
```

process_update_command 处理set，add，replace等写入请求，并将连接状态设置为conn_nread，进一步读取数据  

```
static void process_update_command(conn *c, token_t *tokens, const size_t ntokens, int comm, bool handle_cas) {
    conn_set_state(c, conn_nread);	
}
```

### conn_nread

连接在状态process_update_command进行解析命令，更具解析的结果决定是需要进一步读取数据，还是执行操作返回结果。  
对于二进制协议，conn_read状态只读取协议头部分，对协议头进行解析后，进入conn_nread状态读取body的内容。  
对于ascii协议，conn_read状态读取一行的内容，get命令在解析后即可执行并返回结果，而set，add等则需进一步读取value的内容。  

```
case conn_nread:
	//当rlbytes为0，表示读取完毕,rlbytes表示要读取的"value"数据还剩下多少字节
    if (c->rlbytes == 0) {
		//complete_nread()做一些收尾工作
		complete_nread(c);
		break;
	}

	//如果还有数据没有读完，则继续从buffer中读取数据向item里填充
	//当rlbytes为0，表示读取完毕, rlbytes表示要读取的"value"数据还剩下多少字节
	//状态机会一直保持conn_nread状态一只读取剩下的数据，知道rlbytes读取完毕
	if (c->rbytes > 0) {
		...
	}

	//接着从socket中读取
	res = read(c->sfd, c->ritem, c->rlbytes);
	if (res > 0) {
		...
		break;
	}
	if (res == 0) { /* end of stream */
		...
	}
	if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		...
	}
	conn_set_state(c, conn_closing);
	break;
```

```
static void complete_nread(conn *c) {
    if (c->protocol == ascii_prot) {
        complete_nread_ascii(c);
    } else if (c->protocol == binary_prot) {
        complete_nread_binary(c);
    }
}
```

complete_nread_ascii() 存储value，并向客户端返回结果 

```
static void complete_nread_ascii(conn *c) {
    if (strncmp(ITEM_data(it) + it->nbytes - 2, "\r\n", 2) != 0) {
        out_string(c, "CLIENT_ERROR bad data chunk");
    } else {
      ret = store_item(it, comm, c);

      switch (ret) {
      case STORED:
          out_string(c, "STORED");
          break;
      case EXISTS:
          out_string(c, "EXISTS");
          break;
      ...
      default:
          out_string(c, "SERVER_ERROR Unhandled storage type.");
      }

    }

	//释放引用。
    item_remove(c->item); 
    c->item = 0;
}
```

out_string()将需要输出的字符串放入wbuf中，并将连接状态设置为conn_write.  

```
static void out_string(conn *c, const char *str) {
    size_t len;
    c->msgcurr = 0;
    c->msgused = 0;
    c->iovused = 0;
    add_msghdr(c);  //添加一个msghdr

    len = strlen(str);
    if ((len + 2) > c->wsize) {
        ...
    }

    memcpy(c->wbuf, str, len);  //把要发送的字符串写入wbuf字段中
    memcpy(c->wbuf + len, "\r\n", 2);  //添加换行回车符
    c->wbytes = len + 2;
    c->wcurr = c->wbuf;

	//把连接状态设置为conn_write，状态机进入conn_write执行输出
    conn_set_state(c, conn_write);
	//完成输出后，将状态切换为conn_new_cmd
    c->write_and_go = conn_new_cmd;
    return;
}
```

### conn_write

```
case conn_write:
	if (c->iovused == 0 || (IS_UDP(c->transport) && c->iovused == 1)) {
    	if (add_iov(c, c->wcurr, c->wbytes) != 0) {
        	conn_set_state(c, conn_closing);
        	break;
        }
    }
```

add_iov()用来拼接返回给客户端的数据结构 

```
static int add_iov(conn *c, const void *buf, int len) {
    do {
    	...
        buf = ((char *)buf) + len;
        len = leftover;
    } while (leftover > 0);

    return 0;
}
```

### conn_mwrite

conn_mwrite状态调用transmit（）将数据传输到客户端，传输完毕后，将状态重新设置为conn_new_cmd。

```
case conn_mwrite:
    //执行transmit()发送数据到client
    switch (transmit(c)) {
    case TRANSMIT_COMPLETE:
		if (c->state == conn_mwrite) {
            conn_release_items(c);
            if(c->protocol == binary_prot) {
                 conn_set_state(c, c->write_and_go);
            } else {
                 //重新将状态切换到conn_new_cmd等待客户端新的数据
                 conn_set_state(c, conn_new_cmd);
            }
        } else if (c->state == conn_write) {
            if (c->write_and_free) {
                 free(c->write_and_free);
                 c->write_and_free = 0;
            }
            conn_set_state(c, c->write_and_go);
        } else {
            ...
        }
     	break;

   	case TRANSMIT_INCOMPLETE:
    case TRANSMIT_HARD_ERROR:
        break;             
     
    case TRANSMIT_SOFT_ERROR:
        stop = true;
        break;
    }
    break;
```


transmit() 调用sendmsg()方法将数据传输到客户端  
当msgcurr < msgused时，表示尚有数据未传输完，这时会返回TRANSMIT_INCOMPLETE，随后连接仍然进入conn_mwrite状态继续传输，直到所有数据都传输完毕。

```
static enum transmit_result transmit(conn *c) {
    if (c->msgcurr < c->msgused) {
        ssize_t res;
        struct msghdr *m = &c->msglist[c->msgcurr];

        res = sendmsg(c->sfd, m, 0);
        if (res > 0) {
            ...
            return TRANSMIT_INCOMPLETE;
        }
        if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            ...
            return TRANSMIT_SOFT_ERROR;
        }
        if (IS_UDP(c->transport))
            conn_set_state(c, conn_read);
        else
            conn_set_state(c, conn_closing);
        return TRANSMIT_HARD_ERROR;
    } else {
        return TRANSMIT_COMPLETE;
    }
}
```