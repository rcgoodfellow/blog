---
title: "Linux Networking Internals: Tracing Muffins"
date: 2018-03-20T10:47:00
disqusid: 1947
series: lni
categories: Linux Network Internals
---

This post is a first in a series about Linux networking internals. The goal is very simple, send the string "muffin" from one machine to another, tracing its path from the source user space program, down through the source computers network stack, across a whitebox switch runnign Cumulus Linux, back up the network stack of the receiving computer and finally to its destination in the receiving user space program.

## User Space Program
We begin our journey with the userspace program. This program essentially does four things

1. resolves the address of where we are sending the muffin to
2. opens a socket to shove the muffin through
3. connects said socket to the destination of the muffin
4. shoves the muffin through the socket

{{< highlight c "linenos=inline" >}}
#include <string.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {

  struct addrinfo hints, *server_info=NULL, *server=NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;          //ipv4
  hints.ai_socktype = SOCK_STREAM;    //tcp
  hints.ai_flags = AI_NUMERICSERV;    //use numeric port number
  const char *port_num = "4747";

  if( getaddrinfo("b", port_num, &hints, &server_info) != 0 ) {
    printf("could not get addrinfo for b\n");
    exit(1);
  }

  int fd;
  for(server = server_info; server != NULL; server = server->ai_next) {
    fd = socket(server->ai_family, server->ai_socktype, server->ai_protocol);
    if(fd == -1) {
      continue;
    }
    if(connect(fd, server->ai_addr, server->ai_addrlen) != -1) {
      break;
    }
    //connection unsuccessfull if we are here
    close(fd);
  }

  if(server == NULL) {
    printf("could not connect to server b\n");
    exit(1);
  }

  freeaddrinfo(server_info);

  const char* message = "muffin";
  if(write(fd, message, strlen(message)) != strlen(message)) {
    printf("short write :(\n");
  }

  printf("muffin sent :)\n");

  close(fd);
  freeaddrinfo(server);

  return 0;

}
{{< /highlight >}}

### Opening A Socket

We will not be covering address resolution in this post, so the first place we start to dig in is the `socket` invocation on line 23. `socket` is a part of libc. Most linux distros use [glibc](https://www.gnu.org/software/libc/), so that is the code we will walk through here. The implementation of the `socket` function for Linux is found [here](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/socket.c;h=e4cf7d0ff6fdbdd3329e8cf93406bebc069d9fff;hb=HEAD#l27). And as we can see this is just a simple passthrough to a syscall wrapper to call down into ther kernel to allocate a new socket. One step further into the definition for `INLINE_SYSCALL` lands us [here](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/x86_64/sysdep.h;h=1ef0f742aefb849b234a3695c21f987a2926bd07;hb=HEAD#l193) which is a rather cumbersome set of recursive macro expansions. 

Rather than wade through the macro expansions, we can have `gcc` just expand them for us using the `gcc -E` function. We can write a simple little program `mysock.c` like so

```c
#include "sysdep.h"

int main() {
  my__socket(1, 2, 3); 
}

int my__socket(int fd, int type, int domain) {
  return INLINE_SYSCALL(socket, 3, fd, type, domain);
}
```

which expands into the following via  `gcc -E mysock.c`

```c
int main() {
  my__socket(1, 2, 3);
}

int my__socket(int fd, int type, int domain) {

  return ({ 
    unsigned long int resultvar = ({ 
      unsigned long int resultvar; 
      long int __arg3 = (long int) (domain); 
      long int __arg2 = (long int) (type); 
      long int __arg1 = (long int) (fd); 
      register long int _a3 asm ("rdx") = __arg3; 
      register long int _a2 asm ("rsi") = __arg2; 
      register long int _a1 asm ("rdi") = __arg1; 
      asm volatile ( 
          "syscall\n\t" 
          : "=a" (resultvar) 
          : "0" (__NR_socket) , "r" (_a1), "r" (_a2), "r" (_a3) 
          : "memory", "cc", "r11", "cx"
      ); 
      (long int) resultvar; 
    }); 

    if (__glibc_unlikely (((unsigned long int) (long int) (resultvar) >= -4095L))) { 
    __set_errno ((-(resultvar))); resultvar = (unsigned long int) -1; 
    } 
    (long int) resultvar; 
  });

}
```
So now we can clearly see with `glibc` is doing, setting up the arguments for the socket syscall in the `rdx`, `rsi` and `rdi` registers and passing the `__NR_socket` as the syscall number. `__NR_socket` the syscall number associated with the symbol `__NR_socket` is defined [here](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/arch/x86/entry/syscalls/syscall_64.tbl?h=v4.15.11#n50) and put into the header `/arch/x86/include/generated/uapi/asm/unistd_64.h` by [this script](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/arch/x86/entry/syscalls/syscallhdr.sh?h=v4.15.11). That header is read by glibc when making the syscall to supply the appropriate syscall number.

So once our syscall has been thrown over the fence to the kernel, it lands at the _assembly_ [syscall entry-point](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/arch/x86/entry/entry_64.S?h=v4.15.11#n206) which is a bit of assembly code to set up the [`pt_regs`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/arch/x86/include/asm/ptrace.h?h=v4.15.11#n12) data structure and pass it into the _c_ [syscall entry-point](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/arch/x86/entry/common.c?h=v4.15.11#n269) which then looks up the system call in the `sys_call_table` ultimately landing us at the [socket syscall handler implementation](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/socket.c?h=v4.15.11#n1317). Here a socket is created through [`__sock_create`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/socket.c?h=v4.15.11#n1196), and its integer identifier returned back through the syscall chain.
