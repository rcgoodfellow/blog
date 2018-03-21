---
title: "Linux Networking Internals: Tracing Muffins"
date: 2018-03-20T10:47:00
disqusid: 1947
series: lni
categories: Linux Network Internals
---

This post is a first in a series about Linux networking internals. The goal is very simple, send the string "muffin" from one machine to another, tracing its path from the source user space program, down through the source computers network stack, across a whitebox switch runnign Cumulus Linux, back up the network stack of the receiving computer and finally to its destination in the receiving user space program.

## User Space Program
We begin our journey with the userspace program. This program essentially does three things

1. resolves the address of where we are sending the muffin to
2. opens a socket to shove the muffin through
3. shoves the muffin through the socket

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
  hints.ai_socktype = SOCK_DGRAM;     //udp
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
    break;
  }

  if(server == NULL) {
    printf("could not reslove server b\n");
    exit(1);
  }

  freeaddrinfo(server_info);

  const char* message = "muffin";
  size_t sz = strlen(message);
  size_t n = sendto(fd, message, sz, 0, server->ai_addr, sizeof(*server->ai_addr));
  if(n < sz) 
  {
    printf("short write :(\n");
  }

  printf("muffin sent :)\n");

  close(fd);
  freeaddrinfo(server);

  return 0;

}
{{< /highlight >}}

### Opening A Socket

We will not be covering address resolution in this post, so the first place we start to dig in is the `socket` invocation on line 23. `socket` is a part of libc. Most linux distros use [glibc](https://www.gnu.org/software/libc/), so that is the code we will walk through here. The implementation of the `socket` function for Linux is found in [sysdeps/unix/sysv/linux/socket.c](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/socket.c;h=e4cf7d0ff6fdbdd3329e8cf93406bebc069d9fff;hb=HEAD#l27). 

```c
int __socket (int fd, int type, int domain)
{
#ifdef __ASSUME_SOCKET_SYSCALL
  return INLINE_SYSCALL (socket, 3, fd, type, domain);
#else
  return SOCKETCALL (socket, fd, type, domain);
#endif
}
```

And as we can see this is just a simple passthrough to a syscall wrapper to call down into ther kernel to allocate a new socket. One step further into the definition for `INLINE_SYSCALL` lands us at [sysdeps/unix/sysv/linux/x86_64/sysdep.h](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/x86_64/sysdep.h;h=1ef0f742aefb849b234a3695c21f987a2926bd07;hb=HEAD#l193) which is a rather cumbersome set of recursive macro expansions. 

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

So once our syscall has been thrown over the fence to the kernel, it lands at the _assembly_ syscall entry-point [arch/x86/entry/entry_64.S](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/arch/x86/entry/entry_64.S?h=v4.15.11#n206) 
```as
ENTRY(entry_SYSCALL_64)
	UNWIND_HINT_EMPTY
	/*
	 * Interrupts are off on entry.
	 * We do not frame this tiny irq-off block with TRACE_IRQS_OFF/ON,
	 * it is too small to ever cause noticeable irq latency.
	 */

	swapgs
	/*
	 * This path is only taken when PAGE_TABLE_ISOLATION is disabled so it
	 * is not required to switch CR3.
	 */
	movq	%rsp, PER_CPU_VAR(rsp_scratch)
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

	/* Construct struct pt_regs on stack */
	pushq	$__USER_DS			/* pt_regs->ss */
	pushq	PER_CPU_VAR(rsp_scratch)	/* pt_regs->sp */
	pushq	%r11				/* pt_regs->flags */
	pushq	$__USER_CS			/* pt_regs->cs */
	pushq	%rcx				/* pt_regs->ip */
GLOBAL(entry_SYSCALL_64_after_hwframe)
	pushq	%rax				/* pt_regs->orig_ax */

	PUSH_AND_CLEAR_REGS rax=$-ENOSYS

	TRACE_IRQS_OFF

	/* IRQs are off. */
	movq	%rsp, %rdi
	call	do_syscall_64		/* returns with IRQs disabled */
```


which is a bit of assembly code to set up the [`pt_regs`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/arch/x86/include/asm/ptrace.h?h=v4.15.11#n12) data structure and pass it into the _c_ syscall entry-point [arch/x86/entry/common.c](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/arch/x86/entry/common.c?h=v4.15.11#n269) 
```c
__visible void do_syscall_64(struct pt_regs *regs)
{
	struct thread_info *ti = current_thread_info();
	unsigned long nr = regs->orig_ax;

	enter_from_user_mode();
	local_irq_enable();

	if (READ_ONCE(ti->flags) & _TIF_WORK_SYSCALL_ENTRY)
		nr = syscall_trace_enter(regs);

	/*
	 * NB: Native and x32 syscalls are dispatched from the same
	 * table.  The only functional difference is the x32 bit in
	 * regs->orig_ax, which changes the behavior of some syscalls.
	 */
	if (likely((nr & __SYSCALL_MASK) < NR_syscalls)) {
		nr = array_index_nospec(nr & __SYSCALL_MASK, NR_syscalls);
		regs->ax = sys_call_table[nr](
			regs->di, regs->si, regs->dx,
			regs->r10, regs->r8, regs->r9);
	}

	syscall_return_slowpath(regs);
}
```

which then looks up the system call in the `sys_call_table` ultimately landing us at the socket syscall handler implementation [net/socket.c](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/socket.c?h=v4.15.11#n1317). 
```c
SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
	int retval;
	struct socket *sock;
	int flags;

	/* Check the SOCK_* constants for consistency.  */
	BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON((SOCK_MAX | SOCK_TYPE_MASK) != SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_CLOEXEC & SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_NONBLOCK & SOCK_TYPE_MASK);

	flags = type & ~SOCK_TYPE_MASK;
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;
	type &= SOCK_TYPE_MASK;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	retval = sock_create(family, type, protocol, &sock);
	if (retval < 0)
		return retval;

	return sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
}
```
The socket is created through [`__sock_create`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/socket.c?h=v4.15.11#n1196), and its integer identifier returned back through the syscall chain.

### Shoving Muffin Through Socket

The invocation of

```c
sendto(fd, message, sz, 0, server->ai_addr, sizeof(*server->ai_addr));
```

from line 39 in the muffin-send.c client code above follows an almost identical path to the syscall handler site in the kernel as opening the socket.

- [sysdeps/unix/sysv/linux/sendto.c](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/sendto.c;h=7dbf214a267af1e2bd60f020e4debb085c29eecb;hb=HEAD#l23)

```c
ssize_t
__libc_sendto (int fd, const void *buf, size_t len, int flags,
	       __CONST_SOCKADDR_ARG addr, socklen_t addrlen)
{
#ifdef __ASSUME_SENDTO_SYSCALL
  return SYSCALL_CANCEL (sendto, fd, buf, len, flags, addr.__sockaddr__,
                         addrlen);
#else
  return SOCKETCALL_CANCEL (sendto, fd, buf, len, flags, addr.__sockaddr__,
			    addrlen);
#endif
}
```

Followed by a pile of macros that ultimately brings us to the same place as the `socket` call, with one extra stop along the way in this case in `sysdep.h` to manage rentrancy issues.

- [sysdep/unix/sysdep.h](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysdep.h;h=aac93039de1ac5d7467c6924778192033d0a6aff;hb=HEAD)
- [sysdeps/unix/sysv/linux/x86_64/sysdep.h](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/x86_64/sysdep.h;h=1ef0f742aefb849b234a3695c21f987a2926bd07;hb=HEAD#l193)

Via the syscall hadlers, we land at the sendto handler in [net/socket.c](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/socket.c?h=v4.15.11#n1697)

{{< highlight c "linenos=inline" >}}
SYSCALL_DEFINE6(sendto, int, fd, void __user *, buff, size_t, len,
		unsigned int, flags, struct sockaddr __user *, addr,
		int, addr_len)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int err;
	struct msghdr msg;
	struct iovec iov;
	int fput_needed;

	err = import_single_range(WRITE, buff, len, &iov, &msg.msg_iter);
	if (unlikely(err))
		return err;
	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;

	msg.msg_name = NULL;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_namelen = 0;
	if (addr) {
		err = move_addr_to_kernel(addr, addr_len, &address);
		if (err < 0)
			goto out_put;
		msg.msg_name = (struct sockaddr *)&address;
		msg.msg_namelen = addr_len;
	}
	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	msg.msg_flags = flags;
	err = sock_sendmsg(sock, &msg);

out_put:
	fput_light(sock->file, fput_needed);
out:
	return err;
}
{{</highlight>}}

We will now focus on the actual sending of the muffin at line 33. `sock_sendmsg` is implemented in [net/socket.c](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/socket.c?h=v4.15.11#n643)

```c
int sock_sendmsg(struct socket *sock, struct msghdr *msg)
{
	int err = security_socket_sendmsg(sock, msg,
					  msg_data_left(msg));

	return err ?: sock_sendmsg_nosec(sock, msg);
}
```

#### Linux Security Module Plumbing

Calls to sendmsg go through the [Linux Security Modules Framework (LSM)](https://en.wikipedia.org/wiki/Linux_Security_Modules). LSM allows security to be plugged into the kernel through the module mechanism. The code above basically says, call the security hook, if there is no error then send the message via `sock_sendmsg_nosec`. Digging a bit deeper into the hook, the path is fairly straight forward. `security_socket_sendmsg` is found at [security/security.c](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/security/security.c?h=v4.15.11#n1368)

```c
int security_socket_sendmsg(struct socket *sock, struct msghdr *msg, int size)
{
	return call_int_hook(socket_sendmsg, 0, sock, msg, size);
}
```

and `call_int_hook` also in [security/security.c](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/security/security.c?h=v4.15.11#n208)

```c
#define call_int_hook(FUNC, IRC, ...) ({                    \
 int RC = IRC;                                              \
 do {                                                       \
  struct security_hook_list *P;                             \
                                                            \
  list_for_each_entry(P, &security_hook_heads.FUNC, list) { \
   RC = P->hook.FUNC(__VA_ARGS__);                          \
   if (RC != 0)                                             \
    break;                                                  \
  }                                                         \
 } while (0);                                               \
 RC;                                                        \
})
```
The `security_hook_heads` structure is defined in [include/linux/lsm_hooks.h](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/lsm_hooks.h?h=v4.15.11#n1732). Note that if the list referenced by the macro above is empty (no security module is loaded), and initial return code (`IRC`) is 0, then a 0 will be returned and the logic in the body of the `sock_sendmsg` function will go on it's merry way of sending the message. Alternatively, if there is a security module loaded then its hook will be called. If the hook returns an error it will be returned and the logic in `sock_sendmsg` will not actually send the message, it will just return the error code reported by the first module that gives an error. Note that each hook is a list, so multiple security modules can run side by side at the same time.

If we had SELinux running, the security hook for `sock_sendmsg` would be [initialized](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/security/selinux/hooks.c?h=v4.15.11#n6550) 

```c
LSM_HOOK_INIT(socket_sendmsg, selinux_socket_sendmsg)
```

and [implemented](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/security/selinux/hooks.c?h=v4.15.11#n4604) 

```c
static int selinux_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				  int size)
{
	return sock_has_perm(sock->sk, SOCKET__WRITE);
}
```
in [security/selinux/hooks.c](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/security/selinux/hooks.c?h=v4.15.11)

Ok, now back to actual muffin pushing. Lets take a look at `sock_sendmsg_nosec` in [net/socket.c](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/security/selinux/hooks.c?h=v4.15.11) referenced from `sock_sendmsg` above.

```c
static inline int sock_sendmsg_nosec(struct socket *sock, struct msghdr *msg)
{
	int ret = sock->ops->sendmsg(sock, msg, msg_data_left(msg));
	BUG_ON(ret == -EIOCBQUEUED);
	return ret;
}
```

The kernel is using the socket we created earlier with the socket syscall to send the muffin. In order to see what is going on here, we have to take a look at how the socket gets initialized in [`__sock_create`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/socket.c?h=v4.15.11#n1196) more detail. `__sock_create` is essentially doing 3 things

- checking security constraints on the creation of the socket
- allocating a socket in the filesystem
- _**initializing the socket according to it's specified protocol family**_

We are going to have a look at the protocol initialization bits in order to understand what the `sock->ops->sendmsg` acutally maps to. Here are the interesting bits from [`__sock_create`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/socket.c?h=v4.15.11#n1196) we will be looking at. 

{{< highlight c "linenos=inline,linenostart=1252" >}}
  pf = rcu_dereference(net_families[family]);
	err = -EAFNOSUPPORT;
	if (!pf)
		goto out_release;

	/*
	 * We will call the ->create function, that possibly is in a loadable
	 * module, so we have to bump that loadable module refcnt first.
	 */
	if (!try_module_get(pf->owner))
		goto out_release;

	/* Now protected by module ref count */
	rcu_read_unlock();

	err = pf->create(net, sock, protocol, kern);
	if (err < 0)
		goto out_module_put;
{{</highlight>}}

The first thing happening here is the protocol family is being accessed. The `net_families` array is populated by a special registration function called [`sock_register`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/socket.c?h=v4.15.11#n2512)

```c
/**
 *	sock_register - add a socket protocol handler
 *	@ops: description of protocol
 *
 *	This function is called by a protocol handler that wants to
 *	advertise its address family, and have it linked into the
 *	socket interface. The value ops->family corresponds to the
 *	socket system call protocol family.
 */
int sock_register(const struct net_proto_family *ops)
{
	int err;

	if (ops->family >= NPROTO) {
		pr_crit("protocol %d >= NPROTO(%d)\n", ops->family, NPROTO);
		return -ENOBUFS;
	}

	spin_lock(&net_family_lock);
	if (rcu_dereference_protected(net_families[ops->family],
				      lockdep_is_held(&net_family_lock)))
		err = -EEXIST;
	else {
		rcu_assign_pointer(net_families[ops->family], ops);
		err = 0;
	}
	spin_unlock(&net_family_lock);

	pr_info("NET: Registered protocol family %d\n", ops->family);
	return err;
}
EXPORT_SYMBOL(sock_register);
```

The IPv4 protocol family is [defined](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/af_inet.c?h=v4.15.11#n1018) 
```c
static const struct net_proto_family inet_family_ops = {
	.family = PF_INET,
	.create = inet_create,
	.owner	= THIS_MODULE,
};
```

and [registered](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/af_inet.c?h=v4.15.11#n1843) 

```c
/*
*	Tell SOCKET that we are alive...
*/

(void)sock_register(&inet_family_ops);

```

in `net/ipv4/af_inet.c`. Sockets in this family are created through the [inet_create](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/af_inet.c?h=v4.15.11#n245) function that is mapped into the protocol family structure above. The first part of this function looks up the potocol within IPv4 being used putting the `answer` in a [proto struct](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/net/sock.h?h=v4.15.11#n1024).

```c
list_for_each_entry_rcu(answer, &inetsw[sock->type], list) {
		err = 0;
		/* Check the non-wild match. */
		if (protocol == answer->protocol) {
			if (protocol != IPPROTO_IP)
				break;
		} else {
			/* Check for the two wild cases. */
			if (IPPROTO_IP == protocol) {
				protocol = answer->protocol;
				break;
			}
			if (IPPROTO_IP == answer->protocol)
				break;
		}
		err = -EPROTONOSUPPORT;
	}
  /// some error handling code not shown ...
  sock->ops = answer->ops;
```

from the [list of available IPv4 family protocols](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/af_inet.c?h=v4.15.11#n1027)

```c
static struct inet_protosw inetsw_array[] =
{
  {
    .type =       SOCK_STREAM,
    .protocol =   IPPROTO_TCP,
    .prot =       &tcp_prot,
    .ops =        &inet_stream_ops,
    .flags =      INET_PROTOSW_PERMANENT |
                  INET_PROTOSW_ICSK,
  },

  {
    .type =       SOCK_DGRAM,
    .protocol =   IPPROTO_UDP,
    .prot =       &udp_prot,
    .ops =        &inet_dgram_ops,
    .flags =      INET_PROTOSW_PERMANENT,
  },

  {
    .type =       SOCK_DGRAM,
    .protocol =   IPPROTO_ICMP,
    .prot =       &ping_prot,
    .ops =        &inet_sockraw_ops,
    .flags =      INET_PROTOSW_REUSE,
  },

  {
    .type =       SOCK_RAW,
    .protocol =   IPPROTO_IP,  /* wild card */
    .prot =       &raw_prot,
    .ops =        &inet_sockraw_ops,
    .flags =      INET_PROTOSW_REUSE,
  }
}
```


Now we can see where the implemntatin of the `ops` structure referenced in the `sock_sendmsg_nosec` comes from in the case of IPv4. We used UDP in our sending userpsace application, so let's take a look at the [`inet_dgram_ops`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/af_inet.c?h=v4.15.11#n960) structure.
```c
const struct proto_ops inet_dgram_ops = {
	.family		   = PF_INET,
	.owner		   = THIS_MODULE,
	.release	   = inet_release,
	.bind		   = inet_bind,
	.connect	   = inet_dgram_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = sock_no_accept,
	.getname	   = inet_getname,
	.poll		   = udp_poll,
	.ioctl		   = inet_ioctl,
	.listen		   = sock_no_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = inet_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = inet_sendpage,
	.set_peek_off	   = sk_set_peek_off,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
	.compat_ioctl	   = inet_compat_ioctl,
#endif
};
```
So the call finally resolves to the [`inet_sendmsg`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/af_inet.c?h=v4.15.11#n752) function.

```c
int inet_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	sock_rps_record_flow(sk);

	/* We may need to bind the socket. */
	if (!inet_sk(sk)->inet_num && !sk->sk_prot->no_autobind &&
	    inet_autobind(sk))
		return -EAGAIN;

	return sk->sk_prot->sendmsg(sk, msg, size);
}
```

The `sk->sk_prot` pointer is defined in the [list of available IPv4 family protocols](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/af_inet.c?h=v4.15.11#n1027) above. The `udp_prot` member is found in [net/ipv4/udp.c](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/udp.c?h=v4.15.11#n2544)
```c
struct proto udp_prot = {
	.name		   = "UDP",
	.owner		   = THIS_MODULE,
	.close		   = udp_lib_close,
	.connect	   = ip4_datagram_connect,
	.disconnect	   = udp_disconnect,
	.ioctl		   = udp_ioctl,
	.init		   = udp_init_sock,
	.destroy	   = udp_destroy_sock,
	.setsockopt	   = udp_setsockopt,
	.getsockopt	   = udp_getsockopt,
	.sendmsg	   = udp_sendmsg,
	.recvmsg	   = udp_recvmsg,
	.sendpage	   = udp_sendpage,
	.release_cb	   = ip4_datagram_release_cb,
	.hash		   = udp_lib_hash,
	.unhash		   = udp_lib_unhash,
	.rehash		   = udp_v4_rehash,
	.get_port	   = udp_v4_get_port,
	.memory_allocated  = &udp_memory_allocated,
	.sysctl_mem	   = sysctl_udp_mem,
	.sysctl_wmem	   = &sysctl_udp_wmem_min,
	.sysctl_rmem	   = &sysctl_udp_rmem_min,
	.obj_size	   = sizeof(struct udp_sock),
	.h.udp_table	   = &udp_table,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_udp_setsockopt,
	.compat_getsockopt = compat_udp_getsockopt,
#endif
	.diag_destroy	   = udp_abort,
};
```
along with [udp_sendmsg](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/udp.c?h=v4.15.11#n866).
