# 内存模型

#### 内存分配
1. Memcached的内存分配是以slab为单位的。默认情况下，每个slab大小为1M。
2. slabclass数组初始化的时候，每个slabclass_t都会分配一个1M大小的slab。
3. 当某个slabclass_t结构上的内存不够的时候（freelist空闲列表为空），则会分配一个slab给这个slabclass_t结构。
4. 一旦slab分配后，不可回收。
5. slab会被切分为N个小的内存块，这个小的内存块的大小取决于slabclass_t结构上的size的大小。例如slabclass[0]上的size为103，则每个小的内存块大小为103byte。
6. 这些被切割的小的内存块，主要用来存储item。但是，存储的item，可能会比切割出来的内存块会小。因为这是为了防止内存碎片，虽然有一些内存的浪费。

## 数据结构

#### slab_class

```
typedef struct {  
    unsigned int size;   //chunk的大小
    unsigned int perslab;   //每个slab包含的chunk数，每个slab大小为1M，可以存储的item个数由size决定
  
    void *slots;      //当前slabclass的（空闲item列表）freelist 的链表头部地址  
    unsigned int sl_curr;  //空闲item列表所含的元素数 
  
    unsigned int slabs;     //总共分配多少个slabs  
    void **slab_list;       //分配的slab链表  
    unsigned int list_size; //slab链表的长度，这里时总的slab数，slabs是已分配出去的slab数 
  
    unsigned int killing;  /* index+1 of dying slab, or zero if none */   
    size_t requested; 		 //总共申请的总字节数
} slabclass_t;  

//定义一个slabclass数组，用于存储最大200个的slabclass_t的结构。  
static slabclass_t slabclass[MAX_NUMBER_OF_SLAB_CLASSES];  
```

#### item

item是memcached中存放数据的单元。

```
typedef struct _stritem {  
     
    struct _stritem *next;  	//记录下一个item的地址,用于LRU链表或freeslots链表
    struct _stritem *prev;  	//记录上一个item的地址,用于LRU链表或freeslots链表
    struct _stritem *h_next;   //记录HashTable的下一个Item的地址
    rel_time_t      time;      //最近访问时间
    rel_time_t      exptime;   //过期时间，为0时表示永久有效  
    int             nbytes;    //value数据的大小 
    unsigned short  refcount;  //引用计数，用于判断item是否被其它的线程在操作中，只有refcount＝1的时候才能被删除  
    uint8_t         nsuffix;   //后缀长度  
    uint8_t         it_flags;  //标记  
    uint8_t         slabs_clsid;	//item所在的slab_id 
    uint8_t         nkey;      //键长  
    union {  
        uint64_t cas;  
        char end;  
    } data[];  		//数据，由4部分“拼”成：CAS(可选)，KEY，后缀，VALUE
} item;  
```

#### lru链表

```
static item *heads[LARGEST_ID];  //各个slabclass的lru队列头指针数组
static item *tails[LARGEST_ID];  //各个slabclass的lru队列尾指针数组
static crawler crawlers[LARGEST_ID];	//各个slabclass的item爬虫数组
static itemstats_t itemstats[LARGEST_ID];  //各个slabclass的item统计数组
static unsigned int sizes[LARGEST_ID];  //各个slabclass的chunk大小数组
```

#### hash表

```
static item** primary_hashtable = 0;  //主hash表，用于根据key查找item
static item** old_hashtable = 0;      //旧的hash表，在扩展hash表时用到
```

## slab管理

#### slabclass初始化

主线程在启动main方法中，会调用slabs_init()方法初始化slabclass  
slabs_init(settings.maxbytes, settings.factor, preallocate); (maxbytes默认64M，facotr默认1.25， preallocate默认为true)

```
void slabs_init(const size_t limit, const double factor, const bool prealloc) {
    int i = POWER_SMALLEST - 1;
    unsigned int size = sizeof(item) + settings.chunk_size;

    mem_limit = limit;  //limit为启动时设置的内存大小，默认为64M
    //如果开启预分配（默认开启），则先申请一块内存空间用于预分配
    if (prealloc) {
        mem_base = malloc(mem_limit);
        if (mem_base != NULL) {
            mem_current = mem_base;
            mem_avail = mem_limit;
        } else {
        	...
        }
    }
    memset(slabclass, 0, sizeof(slabclass));

    //初始化slabclass，factor默认等于1.25，
    //item_size_max默认为1M，即mc单个item最大不能超过1M
    while (++i < POWER_LARGEST && size <= settings.item_size_max / factor) {
        if (size % CHUNK_ALIGN_BYTES)	//字节对齐
            size += CHUNK_ALIGN_BYTES - (size % CHUNK_ALIGN_BYTES);

        slabclass[i].size = size;
        slabclass[i].perslab = settings.item_size_max / slabclass[i].size;
        size *= factor;
    }

    power_largest = i;
    slabclass[power_largest].size = settings.item_size_max;
    slabclass[power_largest].perslab = 1;

	...
    //为每一个slabclass_t结构分配一个slab内存块（默认1m）
    if (prealloc) {
        slabs_preallocate(power_largest);
    }
}
```

在初始化slabclass时，默认会进行内存预分配，为每个slabclass分配一个slab（默认为1M）
```
static void slabs_preallocate (const unsigned int maxslabs) {
    int i;
    unsigned int prealloc = 0;

    for (i = POWER_SMALLEST; i <= POWER_LARGEST; i++) {
        if (++prealloc > maxslabs)
            return;
        if (do_slabs_newslab(i) == 0) {
        	...
        }
    }

}
```

slabs_preallocate()方法中，会为每个slabclass分别调用do_slabs_newslab()分配一个新的slab

```
static int do_slabs_newslab(const unsigned int id) {
    slabclass_t *p = &slabclass[id];
    //确定slab的大小
    //如果开启了自定义slab大小，则使用定义的大小；未定义的情况，使用默认大小（1M）
    int len = settings.slab_reassign ? settings.item_size_max
        : p->size * p->perslab;
    char *ptr;

  	//检查内存是否超过限制；如未超限，调用grow_slab_list()检查是否需要对slab_list链表进行扩容
  	//前两步成功以后为slab分配空间
    if ((mem_limit && mem_malloced + len > mem_limit && p->slabs > 0) ||
        (grow_slab_list(id) == 0) ||
        ((ptr = memory_allocate((size_t)len)) == 0)) {

        MEMCACHED_SLABS_SLABCLASS_ALLOCATE_FAILED(id);
        return 0;
    }

    memset(ptr, 0, (size_t)len);  //初始化内存空间
    split_slab_page_into_freelist(ptr, id);  //把新申请的slab分拆为一个个chunk放到slots中去
    p->slab_list[p->slabs++] = ptr; //把新的slab加到slab_list数组中
    mem_malloced += len;  //记下已分配的空间大小
    MEMCACHED_SLABS_SLABCLASS_ALLOCATE(id);

    return 1;
}
```

grow_slab_list() 用于检查是否需要对slab_list进行扩容，不需要扩容和扩容成功都返回1，扩容失败返回0.

```
static int grow_slab_list (const unsigned int id) {
    slabclass_t *p = &slabclass[id];
	//p->slab_list是一个空间大小固定的数组，list_size是这个数组的长度，p->slabs代表已经分配出去的slab数目
	//如果slabs==list_size，说明需要进行扩容
    if (p->slabs == p->list_size) {
    	//list_size初始化大小为16，每次扩容大小翻倍
        size_t new_size =  (p->list_size != 0) ? p->list_size * 2 : 16; 
        void *new_list = realloc(p->slab_list, new_size * sizeof(void *));
        if (new_list == 0) return 0;
        p->list_size = new_size;
        p->slab_list = new_list;
    }
    return 1;
}
```

split_slab_page_into_freelist()将slab分拆为一个个chunk，并放入相应的slots链表中

```
static void split_slab_page_into_freelist(char *ptr, const unsigned int id) {
    slabclass_t *p = &slabclass[id];
    int x;
    for (x = 0; x < p->perslab; x++) { //p->perslab为slab所包含的chunk数
        do_slabs_free(ptr, 0, id);		//加入slots链表
        ptr += p->size;
    }
}
```

do_slabs_free() 方法将一个chunk 放入到空闲slots链表中。

```
static void do_slabs_free(void *ptr, const size_t size, unsigned int id) {
    slabclass_t *p;
    item *it;

    assert(((item *)ptr)->slabs_clsid == 0);
    assert(id >= POWER_SMALLEST && id <= power_largest);
    if (id < POWER_SMALLEST || id > power_largest)
        return;

    MEMCACHED_SLABS_FREE(size, id, ptr);
    p = &slabclass[id];

    it = (item *)ptr;
    it->it_flags |= ITEM_SLABBED;  //把item标记为slabbed状态
    it->prev = 0;
    it->next = p->slots;  //插入到slots链表中
    if (it->next) it->next->prev = it;
    p->slots = it;

    p->sl_curr++; //空闲item数加1
    p->requested -= size;
    return;
}
```

#### slab_alloc

slab_alloc在slab中分配一个item

```
void *slabs_alloc(size_t size, unsigned int id) {
    void *ret;

    pthread_mutex_lock(&slabs_lock);
    ret = do_slabs_alloc(size, id);
    pthread_mutex_unlock(&slabs_lock);
    return ret;
}
```

```
static void *do_slabs_alloc(const size_t size, unsigned int id) {
    slabclass_t *p;
    void *ret = NULL;
    item *it = NULL;

    if (id < POWER_SMALLEST || id > power_largest) { //slab_id不合法，返回null
        MEMCACHED_SLABS_ALLOCATE_FAILED(size, 0);
        return NULL;
    }

    p = &slabclass[id];  //取得当前id对应的slabclass
    assert(p->sl_curr == 0 || ((item *)p->slots)->slabs_clsid == 0);

    //如果slots链表中没有空闲的空间，则执行do_slabs_newslab分配新的slab
	if (! (p->sl_curr != 0 || do_slabs_newslab(id) != 0)) {
        ret = NULL;
    }
	//如果slots链表还有空闲的空间，把空闲的item分配出去
	else if (p->sl_curr != 0) {
        it = (item *)p->slots;
        p->slots = it->next;
        if (it->next) it->next->prev = 0;
        p->sl_curr--;
        ret = (void *)it;
    }

    if (ret) {
        p->requested += size;  //分配成功，记录已分配的字节数
        MEMCACHED_SLABS_ALLOCATE(size, id, p->size, ret);
    } else {
        MEMCACHED_SLABS_ALLOCATE_FAILED(size, id);
    }

    return ret;
}
```

#### slab_free

slabs_free() 在slab清理一个item，也就是将item放入slab的freeslots链表中。具体操作调用do_slabs_free()方法完成（见上）。

```
void slabs_free(void *ptr, size_t size, unsigned int id) {
    pthread_mutex_lock(&slabs_lock);
    do_slabs_free(ptr, size, id);
    pthread_mutex_unlock(&slabs_lock);
}
```

## item分配

#### item_alloc

对于memcahced的SET命令，会调用item_alloc()函数执行内存分配的工作。

```
item *item_alloc(char *key, size_t nkey, int flags, rel_time_t exptime, int nbytes) {
    item *it;
    it = do_item_alloc(key, nkey, flags, exptime, nbytes, 0);
    return it;
}
```

do_item_alloc() 具体负责分配一个item。  
具体策略为，首先调用slabs_clsid() 方法根据item的大小查找一个合适的slabclass。  
接着从lru链表尾部（即最久未使用的item）开始查找没有被其他线程引用的item，最多查找5次。  
如果找到未被其他线程引用的item，判断这个item是否过期，如果过期了，就调用slabs_adjust_mem_requested()更新slab申请的字节数，再调用do_item_unlink_nolock()将旧的item从lru链表和hash表中移除，使用这个item的trunk空间。  
如果找到的item没有过期，则调用slabs_alloc()从slab中分配一个新的trunk，将item放入。  
item内存空间分配好以后，还需要做一些初始化工作就可以返回了。

```
item *do_item_alloc(char *key, const size_t nkey, const int flags,
                    const rel_time_t exptime, const int nbytes,
                    const uint32_t cur_hv) {
    uint8_t nsuffix;
    item *it = NULL;
    char suffix[40];
    //计算item总大小
    size_t ntotal = item_make_header(nkey + 1, flags, nbytes, suffix, &nsuffix);     
    if (settings.use_cas) {
        ntotal += sizeof(uint64_t);   //如果有用到cas，那么item大小还要加上unit64_t的size
    }

    unsigned int id = slabs_clsid(ntotal); //根据item的大小，找到适合的slabclass
    if (id == 0)
        return 0;

    mutex_lock(&cache_lock); //cache锁
    int tries = 5;
    int tried_alloc = 0;
    item *search;
    void *hold_lock = NULL;
    rel_time_t oldest_live = settings.oldest_live;

    search = tails[id]; //全局变量，tails[x]是id为x的slabclass lru链表的尾部
    //首先从lru链表尾部查找有没有过期的item，tries = 5，最多循环5次
    //注意这里是最多查找5次，只要找到一个没有被其他地方引用的item，那么就不再继续查找，如果这个item过期，就使用这个item的空间，否则创建新的slab
	for (; tries > 0 && search != NULL; tries--, search=search->prev) {
        if (search->nbytes == 0 && search->nkey == 0 && search->it_flags == 1) {
            tries++;   //这里只是搜索过期的item，对于异常的item，直接忽略继续查找
            continue;
        }
		//计算item的hash值，hv有两个作用：1.用于hash表保存item 2.用于item lock表中锁住item，通过hv计算出item_lock中哪个锁对当前item加锁
		//不同item的hash值可能相同，hash表中用链表的方式解决冲突；item lock中多个item共享一个锁
        uint32_t hv = hash(ITEM_key(search), search->nkey);
        //锁住当前item
        if (hv == cur_hv || (hold_lock = item_trylock(hv)) == NULL)
            continue;
        //检查这个指向的这个item是否被其他线程引用，如果是的话，继续向前查找
        if (refcount_incr(&search->refcount) != 2) { 
            refcount_decr(&search->refcount);
            ...
            if (hold_lock)
                item_trylock_unlock(hold_lock);
            continue;
        }

		//如果item过期了或被flush刷新了
        if ((search->exptime != 0 && search->exptime < current_time)
            || (search->time <= oldest_live && oldest_live <= current_time)) {
            itemstats[id].reclaimed++;
            if ((search->it_flags & ITEM_FETCHED) == 0) {
                itemstats[id].expired_unfetched++;
            }
            it = search;
            slabs_adjust_mem_requested(it->slabs_clsid, ITEM_ntotal(it), ntotal); //更新slab申请的字节数
            do_item_unlink_nolock(it, hv);  //把旧的item从hash表和LRU链表中移除
            it->slabs_clsid = 0;
        }
		//如果的item没有过期，则调用slabs_alloc分配一个空的trunk
		//如果slabs_alloc返回null，表示分配失败，内存空间已满，需要按LRU进行淘汰
		else if ((it = slabs_alloc(ntotal, id)) == NULL) {
            tried_alloc = 1;  //标记一下，表示有尝试调用slabs_alloc分配空间
            //记录被淘汰item的信息, 使用memcached经常会查看的evicted_time就是在这里赋值的
			if (settings.evict_to_free == 0) {
                itemstats[id].outofmemory++;
            } else {
                itemstats[id].evicted++;
                itemstats[id].evicted_time = current_time - search->time; //被淘汰item距离上次使用的时间
                if (search->exptime != 0)
                    itemstats[id].evicted_nonzero++;
                if ((search->it_flags & ITEM_FETCHED) == 0) {
                    itemstats[id].evicted_unfetched++;
                }
                it = search;
                slabs_adjust_mem_requested(it->slabs_clsid, ITEM_ntotal(it), ntotal); //更新slab申请的字节数
                do_item_unlink_nolock(it, hv);  //从hash表和LRU链表中移除
                it->slabs_clsid = 0;
				//默认情况下，slab_automove=1，会合理地更具淘汰统计数据来分析怎么进行slabclass空间的分配
				//如果slab_automove=2，只要分配失败了，马上进行slabclass空间的重分配
                if (settings.slab_automove == 2)
                    slabs_reassign(-1, id);
            }
        }

        refcount_decr(&search->refcount);
        if (hold_lock)
            item_trylock_unlock(hold_lock);
        break;
    }

    //查找5次item都被其他线程引用了，则再次尝试分配新的内存空间
    if (!tried_alloc && (tries == 0 || search == NULL))
        it = slabs_alloc(ntotal, id);

	//分配失败，返回null
    if (it == NULL) {
        itemstats[id].outofmemory++;
        mutex_unlock(&cache_lock);
        return NULL;
    }

    assert(it->slabs_clsid == 0);
    assert(it != heads[id]);
    
	//item内存空间分配成功，做一些初始化工作
    it->refcount = 1;     
    mutex_unlock(&cache_lock);
    it->next = it->prev = it->h_next = 0;
    it->slabs_clsid = id;

    DEBUG_REFCNT(it, '*');
    it->it_flags = settings.use_cas ? ITEM_CAS : 0;
    it->nkey = nkey;
    it->nbytes = nbytes;
    memcpy(ITEM_key(it), key, nkey);
    it->exptime = exptime;
    memcpy(ITEM_suffix(it), suffix, (size_t)nsuffix);
    it->nsuffix = nsuffix;
    return it;
}
```

slabs_clsid() 方法根据item的大小查找一个合适的slabclass。

```
unsigned int slabs_clsid(const size_t size) {
    int res = POWER_SMALLEST;

    if (size == 0)
        return 0;
    while (size > slabclass[res].size)
        if (res++ == power_largest)    //如果最大的slabclass也放不下，则返回0
            return 0;
    return res;
}
```

slabs_adjust_mem_requested() 方法用于在淘汰旧的item前更新slab申请的字节数，减去旧的item字节数，加上新的item字节数。

```
void slabs_adjust_mem_requested(unsigned int id, size_t old, size_t ntotal)
{
    pthread_mutex_lock(&slabs_lock);
    slabclass_t *p;
    if (id < POWER_SMALLEST || id > power_largest) {
        fprintf(stderr, "Internal error! Invalid slab class\n");
        abort();
    }

    p = &slabclass[id];
    p->requested = p->requested - old + ntotal;
    pthread_mutex_unlock(&slabs_lock);
}
```

do_item_unlink_nolock()方法淘汰一个旧的item，将其从hash表和LRU链表中移除

```
void do_item_unlink_nolock(item *it, const uint32_t hv) {
    MEMCACHED_ITEM_UNLINK(ITEM_key(it), it->nkey, it->nbytes);
    if ((it->it_flags & ITEM_LINKED) != 0) {
        it->it_flags &= ~ITEM_LINKED;
        STATS_LOCK();
        stats.curr_bytes -= ITEM_ntotal(it);
        stats.curr_items -= 1;
        STATS_UNLOCK();
        assoc_delete(ITEM_key(it), it->nkey, hv);  //将item从hash表中删除
        item_unlink_q(it);    //将item从lru链表中删除
        do_item_remove(it);   //将item的引用计数减1
    }
}
```

```
//将item从slabclass lru链表中删除
static void item_unlink_q(item *it) {
    item **head, **tail;
    assert(it->slabs_clsid < LARGEST_ID);
    head = &heads[it->slabs_clsid];
    tail = &tails[it->slabs_clsid];

    if (*head == it) {
        assert(it->prev == 0);
        *head = it->next;
    }
    if (*tail == it) {
        assert(it->next == 0);
        *tail = it->prev;
    }
    assert(it->next != it);
    assert(it->prev != it);

    if (it->next) it->next->prev = it->prev;
    if (it->prev) it->prev->next = it->next;
    sizes[it->slabs_clsid]--;
    return;
}
```
do_item_remove()将item的引用计数减1；当引用计数为0时，将item放入freeslots链表中。
在使用旧的item空间时，item的引用计数减1后为1，不满足条件，因此不会清理这个item。

```
void do_item_remove(item *it) {
    MEMCACHED_ITEM_REMOVE(ITEM_key(it), it->nkey, it->nbytes);
    assert((it->it_flags & ITEM_SLABBED) == 0);
    assert(it->refcount > 0);

	//引用计数减1，当引用计数为0时，清理这个item
    if (refcount_decr(&it->refcount) == 0) {
        item_free(it);
    }
}
```

item_free() 清理item，这里不是要清理内存，memcached内存一旦分配，便不会被清理；这个方法是将item放入slab的freeslots链表中。

```
void item_free(item *it) {
    size_t ntotal = ITEM_ntotal(it);
    unsigned int clsid;
    assert((it->it_flags & ITEM_LINKED) == 0);
    assert(it != heads[it->slabs_clsid]);
    assert(it != tails[it->slabs_clsid]);
    assert(it->refcount == 0);

    clsid = it->slabs_clsid;
    it->slabs_clsid = 0;  //free掉的 item的slabs_clsid设为0
    DEBUG_REFCNT(it, 'F');
    slabs_free(it, ntotal, clsid);
}
```

#### store_item

item_alloc()方法只是为item分配了空间，后续需要调用store_item()方法，设置好value以后，将item放入lru链表和hash表中。

```
enum store_item_type store_item(item *item, int comm, conn* c) {
    enum store_item_type ret;
    uint32_t hv;

    hv = hash(ITEM_key(item), item->nkey);
    item_lock(hv);
    ret = do_store_item(item, comm, c, hv);
    item_unlock(hv);
    return ret;
}
```
do_store_item()方法首先调用do_item_get()方法根据item的key找到已存在的item，然后根据具体指令comm的不同进行不同的操作。  
对于set命令，如果要SET的key已经存在，调用item_replace()方法覆盖旧的value；如果key不存在，调用do_item_link()方法添加新的item（将item加入lru和hash表）。


```
enum store_item_type do_store_item(item *it, int comm, conn *c, const uint32_t hv) {
    char *key = ITEM_key(it);
    item *old_it = do_item_get(key, it->nkey, hv);  //取出旧的item
    enum store_item_type stored = NOT_STORED;

    item *new_it = NULL;
    int flags;

	//根据具体指令comm的不同进行不同的操作
    if (old_it != NULL && comm == NREAD_ADD) {
        do_item_update(old_it);  //更新item信息，主要是lru链表
    } else if (!old_it && (comm == NREAD_REPLACE
        || comm == NREAD_APPEND || comm == NREAD_PREPEND))
    {
    } else if (comm == NREAD_CAS) {
        if(old_it == NULL) {
            stored = NOT_FOUND;
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.cas_misses++;
            pthread_mutex_unlock(&c->thread->stats.mutex);
        }
        else if (ITEM_get_cas(it) == ITEM_get_cas(old_it)) {
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.slab_stats[old_it->slabs_clsid].cas_hits++;
            pthread_mutex_unlock(&c->thread->stats.mutex);

            item_replace(old_it, it, hv);
            stored = STORED;
        } else {
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.slab_stats[old_it->slabs_clsid].cas_badval++;
            pthread_mutex_unlock(&c->thread->stats.mutex);
            stored = EXISTS;
        }
    } 
    else {   //设置命令（如set...）
        if (comm == NREAD_APPEND || comm == NREAD_PREPEND) {
            ...
        }

		//SET命令会进入这里
        if (stored == NOT_STORED) {
            if (old_it != NULL)
				//如果要SET的key已经存在，使用新的item覆盖旧的
                item_replace(old_it, it, hv);
            else
				//如果要SET的key不存在，则插入新的item
                do_item_link(it, hv);

            c->cas = ITEM_get_cas(it);

            stored = STORED;
        }
    }

    if (old_it != NULL)
        do_item_remove(old_it); 
    if (new_it != NULL)
        do_item_remove(new_it);

    if (stored == STORED) {
        c->cas = ITEM_get_cas(it);
    }

    return stored;
}
```

item_replace()方法覆盖旧的value

```
int do_item_replace(item *it, item *new_it, const uint32_t hv) {
    MEMCACHED_ITEM_REPLACE(ITEM_key(it), it->nkey, it->nbytes,
                           ITEM_key(new_it), new_it->nkey, new_it->nbytes);
    assert((it->it_flags & ITEM_SLABBED) == 0);

    do_item_unlink(it, hv);
    return do_item_link(new_it, hv);
}
```

#### item_get

do_item_get() 方法，根据key查找item。
memcached没有实时或定时处理超时的item，因此找到item后，需要判断item是否失效（被flush刷新过或者过期了），如果没有失效，返回item。

```
item *do_item_get(const char *key, const size_t nkey, const uint32_t hv) {
    item *it = assoc_find(key, nkey, hv); //在hash表中查找item
    if (it != NULL) {
        refcount_incr(&it->refcount);
        if (slab_rebalance_signal &&
            ((void *)it >= slab_rebal.slab_start && (void *)it < slab_rebal.slab_end)) {
            do_item_unlink_nolock(it, hv);
            do_item_remove(it);
            it = NULL;
        }
    }
    int was_found = 0;

    if (it != NULL) {
        if (settings.oldest_live != 0 && settings.oldest_live <= current_time &&
            it->time <= settings.oldest_live) { //判断是否被flush过
            do_item_unlink(it, hv);
            do_item_remove(it);
            it = NULL;
            if (was_found) {
                fprintf(stderr, " -nuked by flush");
            }
        } else if (it->exptime != 0 && it->exptime <= current_time) {  //判断是否过期
            do_item_unlink(it, hv);
            do_item_remove(it);
            it = NULL;
            if (was_found) {
                fprintf(stderr, " -nuked by expire");
            }
        } else {
            it->it_flags |= ITEM_FETCHED;
            DEBUG_REFCNT(it, '+');
        }
    }
    return it;
}
```

#### item_linkd & unlink

do_item_link()方法将item加入hash表和lru链表，并更新统计数据。

```
int do_item_link(item *it, const uint32_t hv) {
    MEMCACHED_ITEM_LINK(ITEM_key(it), it->nkey, it->nbytes);
    assert((it->it_flags & (ITEM_LINKED|ITEM_SLABBED)) == 0);
    mutex_lock(&cache_lock);
    it->it_flags |= ITEM_LINKED;
    it->time = current_time;

    STATS_LOCK();
    stats.curr_bytes += ITEM_ntotal(it);
    stats.curr_items += 1;
    stats.total_items += 1;
    STATS_UNLOCK();

    ITEM_set_cas(it, (settings.use_cas) ? get_cas_id() : 0);
    assoc_insert(it, hv);  //插入hash表
    item_link_q(it);  //插入lru链表
    refcount_incr(&it->refcount);
    mutex_unlock(&cache_lock);

    return 1;
}
```

do_item_unlink()方法将item从hash表和lru链表删除，并更新统计数据。

```
void do_item_unlink(item *it, const uint32_t hv) {
    MEMCACHED_ITEM_UNLINK(ITEM_key(it), it->nkey, it->nbytes);
    mutex_lock(&cache_lock);
    if ((it->it_flags & ITEM_LINKED) != 0) {
        it->it_flags &= ~ITEM_LINKED;
        STATS_LOCK();
        stats.curr_bytes -= ITEM_ntotal(it);
        stats.curr_items -= 1;
        STATS_UNLOCK();
        assoc_delete(ITEM_key(it), it->nkey, hv);
        item_unlink_q(it);
        do_item_remove(it);
    }
    mutex_unlock(&cache_lock);
}
```

## hash表管理
#### assoc_init
assoc_init()方法负责初始化hash表

```
void assoc_init(const int hashtable_init) {
    if (hashtable_init) {
        hashpower = hashtable_init;
    }
    primary_hashtable = calloc(hashsize(hashpower), sizeof(void *));
    if (! primary_hashtable) {
        exit(EXIT_FAILURE);
    }
    STATS_LOCK();
    stats.hash_power_level = hashpower;  //hash表的指数（默认为16，即hash表大小默认为2^16）
    stats.hash_bytes = hashsize(hashpower) * sizeof(void *);
    STATS_UNLOCK();
}
```
memcached在启动时，会初始化全局hash表，同时会调用start_assoc_maintenance_thread()方法启动hash表维护线程，负责hash表的扩展操作。

```
//启动hash表维护线程
int start_assoc_maintenance_thread() {
    int ret;
    char *env = getenv("MEMCACHED_HASH_BULK_MOVE");
    if (env != NULL) {
        hash_bulk_move = atoi(env);
        if (hash_bulk_move == 0) {
            hash_bulk_move = DEFAULT_HASH_BULK_MOVE;
        }
    }
	//assoc_maintenance_thread为线程执行入口
    if ((ret = pthread_create(&maintenance_tid, NULL,
                              assoc_maintenance_thread, NULL)) != 0) {
        return -1;
    }
    return 0;
}
```

#### assoc_find
assoc_find()方法通过key查找item。

```
item *assoc_find(const char *key, const size_t nkey, const uint32_t hv) {
    item *it;
    unsigned int oldbucket;

	//hv & hashmask(hashpower - 1) 得到的是桶在hash表中的下标
    if (expanding &&
        (oldbucket = (hv & hashmask(hashpower - 1))) >= expand_bucket)
    {
        it = old_hashtable[oldbucket];
    } else {
		//找到item所在的桶的链表的表头item
        it = primary_hashtable[hv & hashmask(hashpower)];
    }

    item *ret = NULL;
    int depth = 0;
	//遍历桶的链表，直到找到指定的item
    while (it) {
        if ((nkey == it->nkey) && (memcmp(key, ITEM_key(it), nkey) == 0)) {
            ret = it;
            break;
        }
        it = it->h_next;
        ++depth;
    }
    MEMCACHED_ASSOC_FIND(key, nkey, depth);
    return ret;
}
```

#### assoc_insert

assoc_insert()方法把item插入hash表

```
int assoc_insert(item *it, const uint32_t hv) {
    unsigned int oldbucket;
 
	if (expanding &&
        (oldbucket = (hv & hashmask(hashpower - 1))) >= expand_bucket)
    {
        it->h_next = old_hashtable[oldbucket];
        old_hashtable[oldbucket] = it;
    } else {
		//hv & hashmask(hashpower) 取得桶在hash表中的下标
		//hash表冲突时，使用链表保存相同桶下标的item
		//这里把新的item放到桶的链表头
        it->h_next = primary_hashtable[hv & hashmask(hashpower)];
        primary_hashtable[hv & hashmask(hashpower)] = it;
    }

    hash_items++;
    if (! expanding && hash_items > (hashsize(hashpower) * 3) / 2) {
		//当hash表中的item数大于hash表桶数的1.5倍时，开始扩展hash表
		assoc_start_expand();
    }

    MEMCACHED_ASSOC_INSERT(ITEM_key(it), it->nkey, hash_items);
    return 1;
}
```

#### assoc_delete
assoc_delete() 方法从hash表中删除item

```
void assoc_delete(const char *key, const size_t nkey, const uint32_t hv) {
    //取得指向当前item的上一个item的h_next指针
	item **before = _hashitem_before(key, nkey, hv);

	//利用before指针，把当前item的h_next指向0，把上一个item的h_next指向原来before的h_next达到删除作用
    if (*before) {
        item *nxt;
        hash_items--;
        MEMCACHED_ASSOC_DELETE(key, nkey, hash_items);
        nxt = (*before)->h_next;
        (*before)->h_next = 0;  
        *before = nxt;
        return;
    }
    assert(*before != 0);
}
```

#### rehash

在调用assoc_insert()方法向hash表中插入数据时，如果hash表中的item数大于hash表桶数的1.5倍时，开始调用assoc_start_expand()方法扩展hash表  

* int hash_bulk_move = DEFAULT_HASH_BULK_MOVE; //用于记录每次扩容时rehash几个桶的数据，默认为1  
* static unsigned int expand_bucket = 0;  //用于扩容时下一个需要进行rehash的桶的位置  
在查找、插入和删除时，根据hash值和expand_bucket值的比较，决定是操作旧的hash表还是新的hash表。  
* static bool expanding = false;  //是否正在扩展hash表  
* static bool started_expanding = false;  //是否开始扩展hash表

```
static void assoc_start_expand(void) {
    if (started_expanding)
        return;
    started_expanding = true;
	//发送一个信号给正处于阻塞等待状态的hash表维护线程，见assoc_maintenance_thread
    pthread_cond_signal(&maintenance_cond);
}
```

```
static void *assoc_maintenance_thread(void *arg) {

    while (do_run_maintenance_thread) {
        int ii = 0;

        item_lock_global();
        mutex_lock(&cache_lock);

        for (ii = 0; ii < hash_bulk_move && expanding; ++ii) {
            item *it, *next;
            int bucket;
            
            //遍历扩容时需要进行rehash的桶中的元素，将其放入新的hash表中
            for (it = old_hashtable[expand_bucket]; NULL != it; it = next) {
                next = it->h_next;

                bucket = hash(ITEM_key(it), it->nkey) & hashmask(hashpower);
                it->h_next = primary_hashtable[bucket];
                primary_hashtable[bucket] = it;
            }

            old_hashtable[expand_bucket] = NULL; //释放原hash表中完成rehash的桶链表

            expand_bucket++; 
            //expand_bucket等于原hash表长度时，整个rehash的工作已经完成了
            if (expand_bucket == hashsize(hashpower - 1)) { 
                expanding = false;
                free(old_hashtable);  //释放原hash表空间
                stats.hash_bytes -= hashsize(hashpower - 1) * sizeof(void *);
                stats.hash_is_expanding = 0;
            }
        }

        if (!expanding) {  
            slabs_rebalancer_resume();
            started_expanding = false;
			//等待条件变量，当条件到达时唤醒线程继续往下执行
            pthread_cond_wait(&maintenance_cond, &cache_lock);
            slabs_rebalancer_pause();
            assoc_expand();
        }
    }
    return NULL;
}
```

```
static void assoc_expand(void) {
    old_hashtable = primary_hashtable;  //将现在的hash表设为旧的hash表

	//为新的hash表申请空间，新的hash表长度是旧hash表的两倍
    primary_hashtable = calloc(hashsize(hashpower + 1), sizeof(void *)); 
    if (primary_hashtable) {
        hashpower++;
        expanding = true;
        expand_bucket = 0;
        stats.hash_power_level = hashpower;
        stats.hash_bytes += hashsize(hashpower) * sizeof(void *);
        stats.hash_is_expanding = 1;
    } else {
        primary_hashtable = old_hashtable;
    }
}
```
