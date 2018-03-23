---
title: "Tracing Muffins: Part 1 Sending"
date: 2018-03-20T10:47:00
disqusid: 1947
series: lni
categories: Linux Network Internals
---

This post is a first in a series about Linux networking internals. The goal for the first part of this series is very simple, send the string "muffin" from one machine to another, tracing its path from the source user space program, down through the source computers network stack, across a whitebox switch running Cumulus Linux, back up the network stack of the receiving computer and finally to its destination in the receiving user space program.

It turns out this will take several articles to cover. In this first article we trace the path of the muffin from the originating user space program all the way until it is delivered to the network device driver responsible for physically transporting the muffin's bit signal to the next hop.

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

And as we can see this is just a simple pass-through to a syscall wrapper to call down into their kernel to allocate a new socket. One step further into the definition for `INLINE_SYSCALL` lands us at [sysdeps/unix/sysv/linux/x86_64/sysdep.h](https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/unix/sysv/linux/x86_64/sysdep.h;h=1ef0f742aefb849b234a3695c21f987a2926bd07;hb=HEAD#l193) which is a rather cumbersome set of recursive macro expansions. 

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

Jumping into [`sock_create`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/socket.c?h=v4.15.11#n1305) 
```c
int sock_create(int family, int type, int protocol, struct socket **res)
{
	return __sock_create(current->nsproxy->net_ns, family, type, protocol, res, 0);
}
```
We see an additional piece of information being injected into the call chain, `current->nsproxy->net_ns`. Current is a pointer to the current [`task_struct`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/sched.h?h=v4.15.11#n520) from [arch/x86/include/asm/current.h](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/arch/x86/include/asm/current.h?h=v4.15.11#n18).

```c
struct task_struct {
  // a great many things skipped over ....

  /* Namespaces: */
	struct nsproxy			*nsproxy;

  // a great many more things skipped over ....
}
```

The `nsproxy` struct is defined in [include/linux/nsproxy.h](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/nsproxy.h?h=v4.15.11#n31) and looks like this

```c
/*
 * A structure to contain pointers to all per-process
 * namespaces - fs (mount), uts, network, sysvipc, etc.
 *
 * The pid namespace is an exception -- it's accessed using
 * task_active_pid_ns.  The pid namespace here is the
 * namespace that children will use.
 *
 * 'count' is the number of tasks holding a reference.
 * The count for each namespace, then, will be the number
 * of nsproxies pointing to it, not the number of tasks.
 *
 * The nsproxy is shared by tasks which share all namespaces.
 * As soon as a single namespace is cloned or unshared, the
 * nsproxy is copied.
 */
struct nsproxy {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net 	     *net_ns;
	struct cgroup_namespace *cgroup_ns;
};
```

The network namespace structure `net` is defined in [include/net/net_namespace.h](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/net/net_namespace.h?h=v4.15.11#n50). It's probably one of the most imporant structures in the Linux network internals, so we show it in all it's glory here. Namespaces are the basis for kernel level isolation technologies such as Docker, providing individual processes with a segmented view of the kernel and system resources.

```c
struct net {
  refcount_t              passive;          /* To decided when the network
                                             * namespace should be freed.
                                             */
  atomic_t                count;            /* To decided when the network
                                             *  namespace should be shut down.
                                             */
  spinlock_t              rules_mod_lock;

  atomic64_t              cookie_gen;

  struct list_head        list;             /* list of network namespaces */
  struct list_head        cleanup_list;     /* namespaces on death row */
  struct list_head        exit_list;        /* Use only net_mutex */

  struct user_namespace   *user_ns;         /* Owning user namespace */
  struct ucounts          *ucounts;
  spinlock_t              nsid_lock;
  struct idr              netns_ids;

  struct ns_common        ns;

  struct proc_dir_entry   *proc_net;
  struct proc_dir_entry   *proc_net_stat;

#ifdef CONFIG_SYSCTL
  struct ctl_table_set    sysctls;
#endif

  struct sock             *rtnl;           /* rtnetlink socket */
  struct sock             *genl_sock;

  struct list_head        dev_base_head;
  struct hlist_head       *dev_name_head;
  struct hlist_head       *dev_index_head;
  unsigned int            dev_base_seq;   /* protected by rtnl_mutex */
  int                     ifindex;
  unsigned int            dev_unreg_count;

  /* core fib_rules */
  struct list_head        rules_ops;

  struct list_head        fib_notifier_ops;       /* protected by net_mutex */

  struct net_device       *loopback_dev;    /* The loopback */
  struct netns_core       core;
  struct netns_mib        mib;
  struct netns_packet     packet;
  struct netns_unix       unx;
  struct netns_ipv4       ipv4;
#if IS_ENABLED(CONFIG_IPV6)
  struct netns_ipv6       ipv6;
#endif
#if IS_ENABLED(CONFIG_IEEE802154_6LOWPAN)
  struct 
  netns_ieee802154_lowpan ieee802154_lowpan;
#endif
#if defined(CONFIG_IP_SCTP) || defined(CONFIG_IP_SCTP_MODULE)
  struct netns_sctp       sctp;
#endif
#if defined(CONFIG_IP_DCCP) || defined(CONFIG_IP_DCCP_MODULE)
  struct netns_dccp       dccp;
#endif
#ifdef CONFIG_NETFILTER
  struct netns_nf         nf;
  struct netns_xt         xt;
#if defined(CONFIG_NF_CONNTRACK) || defined(CONFIG_NF_CONNTRACK_MODULE)
  struct netns_ct         ct;
#endif
#if defined(CONFIG_NF_TABLES) || defined(CONFIG_NF_TABLES_MODULE)
  struct netns_nftables   nft;
#endif
#if IS_ENABLED(CONFIG_NF_DEFRAG_IPV6)
  struct netns_nf_frag    nf_frag;
#endif
  struct sock             *nfnl;
  struct sock             *nfnl_stash;
#if IS_ENABLED(CONFIG_NETFILTER_NETLINK_ACCT)
  struct list_head        nfnl_acct_list;
#endif
#if IS_ENABLED(CONFIG_NF_CT_NETLINK_TIMEOUT)
  struct list_head        nfct_timeout_list;
#endif
#endif
#ifdef CONFIG_WEXT_CORE
  struct sk_buff_head     wext_nlevents;
#endif
  struct 
  net_generic __rcu       *gen;

  /* Note : following structs are cache line aligned */
#ifdef CONFIG_XFRM
  struct netns_xfrm       xfrm;
#endif
#if IS_ENABLED(CONFIG_IP_VS)
  struct netns_ipvs       *ipvs;
#endif
#if IS_ENABLED(CONFIG_MPLS)
  struct netns_mpls       mpls;
#endif
#if IS_ENABLED(CONFIG_CAN)
  struct netns_can        can;
#endif
  struct sock             *diag_nlsk;
  atomic_t                fnhe_genid;
} __randomize_layout;
```

Using these data structures, the socket then is created through [`__sock_create`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/socket.c?h=v4.15.11#n1196), and its integer identifier returned back through the syscall chain. We'll go into more detail on what information is encapsulated into the sock struct later when it is required to understand packet routing inside the kernel. The part we will be most concerned with here is the struct member
```c
struct netns_ipv4 ipv4;
```

The `netns_ipv4` struct is defined in [include/net//netns/ipv4](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/net/netns/ipv4.h?h=v4.15.11#n42).

### Shoving Muffin Through Socket

Now that we have a socket, let's shove our muffin through it. The invocation of

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

Followed by a pile of macros that ultimately brings us to the same place as the `socket` call, with one extra stop along the way in this case in `sysdep.h` to manage reentrancy issues.

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

Calls to `sendmsg` go through the [Linux Security Modules Framework (LSM)](https://en.wikipedia.org/wiki/Linux_Security_Modules). LSM allows security to be plugged into the kernel through the module mechanism. The code above basically says, call the security hook first, and if there is no error then send the message via `sock_sendmsg_nosec`. Digging a bit deeper into the hook, the path is fairly straight forward. `security_socket_sendmsg` is found at [security/security.c](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/security/security.c?h=v4.15.11#n1368)

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
The `security_hook_heads` structure is defined in [include/linux/lsm_hooks.h](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/lsm_hooks.h?h=v4.15.11#n1732). Note that if the list referenced by the macro above is empty (no security module is loaded), and initial return code (`IRC`) is 0, then a 0 will be returned and the logic in the body of the `sock_sendmsg` function will go on it's merry way of sending the message through `sock_sendmsg_nosec`. Alternatively, if there is a security module loaded then its hook will be called. If the hook returns an error it will be returned and the logic in `sock_sendmsg` will not actually send the message, it will just return the error code reported by the first module that gives an error. Note that each hook is a list, so multiple security modules can run side by side at the same time.

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

We are going to have a look at the protocol initialization bits in order to understand what the `sock->ops->sendmsg` actually maps to. Here are the interesting bits from [`__sock_create`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/socket.c?h=v4.15.11#n1196) we will be looking at. 

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

in `net/ipv4/af_inet.c`. Sockets in this family are created through the [inet_create](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/af_inet.c?h=v4.15.11#n245) function that is mapped into the protocol family structure above. The first part of this function looks up the protocol within IPv4 being used putting the `answer` in a [proto struct](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/net/sock.h?h=v4.15.11#n1024).

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


Now we can see where the implementation of the `ops` structure referenced in the `sock_sendmsg_nosec` comes from in the case of IPv4. We used UDP in our sending userspace application, so let's take a look at the [`inet_dgram_ops`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/af_inet.c?h=v4.15.11#n960) structure.
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

Now we focus in on the parts of `udp_sendmsg` that actually do the sending, assuming the [UDP_CORK](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/uapi/linux/udp.h?h=v4.15.11#n31) is not set.

{{< highlight c "linenos=inline,linenostart=1006" >}}
if (!rt) {
		struct net *net = sock_net(sk);
		__u8 flow_flags = inet_sk_flowi_flags(sk);

		fl4 = &fl4_stack;

		flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
				   RT_SCOPE_UNIVERSE, sk->sk_protocol,
				   flow_flags,
				   faddr, saddr, dport, inet->inet_sport,
				   sk->sk_uid);

		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));
		rt = ip_route_output_flow(net, fl4, sk);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			rt = NULL;
			if (err == -ENETUNREACH)
				IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}

		err = -EACCES;
		if ((rt->rt_flags & RTCF_BROADCAST) &&
		    !sock_flag(sk, SOCK_BROADCAST))
			goto out;
		if (connected)
			sk_dst_set(sk, dst_clone(&rt->dst));
	}

	if (msg->msg_flags&MSG_CONFIRM)
		goto do_confirm;
back_from_confirm:

	saddr = fl4->saddr;
	if (!ipc.addr)
		daddr = ipc.addr = fl4->daddr;

	/* Lockless fast path for the non-corking case. */
	if (!corkreq) {
		skb = ip_make_skb(sk, fl4, getfrag, msg, ulen,
				  sizeof(struct udphdr), &ipc, &rt,
				  msg->msg_flags);
		err = PTR_ERR(skb);
		if (!IS_ERR_OR_NULL(skb))
			err = udp_send_skb(skb, fl4);
		goto out;
	}
{{</highlight>}}

There are three things going on here we will be focusing on. 

- get a reference to the kernels routing table ~ line 1019
- create a socket buffer with the data we want to send ~ line 1046
- send the socket buffer full of data `udp_send_skb` using a flow table constructed from the kernels routing table.

#### Routing - Figuring Out the Next Hop

The first stop for getting the kernel routing table reference is [`ip_route_output_flow`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/route.c?h=v4.15.11#n2555). For simplicity we assume that [xfrm](http://man7.org/linux/man-pages/man8/ip-xfrm.8.html) is not in play so we sill just focus on `__ip_route_output_key`.

```c
struct rtable *ip_route_output_flow(struct net *net, struct flowi4 *flp4,
				    const struct sock *sk)
{
	struct rtable *rt = __ip_route_output_key(net, flp4);

	if (IS_ERR(rt))
		return rt;

	if (flp4->flowi4_proto)
		rt = (struct rtable *)xfrm_lookup_route(net, &rt->dst,
							flowi4_to_flowi(flp4),
							sk, 0);

	return rt;
}
```

[`__ip_route_output_key`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/net/route.h?h=v4.15.11#n122)
```c
static inline struct rtable *__ip_route_output_key(struct net *net,
						   struct flowi4 *flp)
{
	return ip_route_output_key_hash(net, flp, NULL);
}
```

This lands us at [`ip_route_output_key_hash`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/route.c?h=v4.15.11#n2287)
```c
struct rtable *ip_route_output_key_hash(struct net *net, struct flowi4 *fl4,
					const struct sk_buff *skb)
{
	__u8 tos = RT_FL_TOS(fl4);
	struct fib_result res;
	struct rtable *rth;

	res.tclassid	= 0;
	res.fi		= NULL;
	res.table	= NULL;

	fl4->flowi4_iif = LOOPBACK_IFINDEX;
	fl4->flowi4_tos = tos & IPTOS_RT_MASK;
	fl4->flowi4_scope = ((tos & RTO_ONLINK) ?
			 RT_SCOPE_LINK : RT_SCOPE_UNIVERSE);

	rcu_read_lock();
	rth = ip_route_output_key_hash_rcu(net, fl4, &res, skb);
	rcu_read_unlock();

	return rth;
}
```

which is really just preparing arguments for [`ip_route_output_key_hash_rcu`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/route.c?h=v4.15.11#n2311). In our muffin pushing client code, we are using a unicast address and have done nothing to tell the kernel, as of yet, what interface the socket is associated with. So our starting point of interest in `ip_route_ouput_key_hash_rcu` is the `fib_lookup` at line 2411

```c
  err = fib_lookup(net, fl4, res, 0);
  if (err) {
    // error handling omitted  
  }

  // loopback case handling omitted

  fib_select_path(net, res, fl4, skb);

  dev_out = FIB_RES_DEV(*res);
  fl4->flowi4_oif = dev_out->ifindex;

make_route:
  rth = __mkroute_output(res, fl4, orig_oif, dev_out, flags);

out:
  return rth;
```

Finding the output device requires looking into the forwarding information base (FIB). The [`fib_lookup`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/net/ip_fib.h?h=v4.15.11#n261) code is the following
```c
static inline int fib_lookup(struct net *net, const struct flowi4 *flp,
			     struct fib_result *res, unsigned int flags)
{
	struct fib_table *tb;
	int err = -ENETUNREACH;

	rcu_read_lock();

	tb = fib_get_table(net, RT_TABLE_MAIN);
	if (tb)
		err = fib_table_lookup(tb, flp, res, flags | FIB_LOOKUP_NOREF);

	if (err == -EAGAIN)
		err = -ENETUNREACH;

	rcu_read_unlock();

	return err;
}
```

Lets take a look at a **_very simplified_** version of [`fib_get_table`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/fib_trie.c?h=v4.15.11#n1296), note that all of the error handling and backtrace code has been removed from the code below. Only the parts necessary to understand the **_normal_** case are shown so we can get an immediate picture of what is going on.

{{< highlight c "linenos=inline" >}}
int fib_table_lookup(struct fib_table *tb, const struct flowi4 *flp,
         struct fib_result *res, int fib_flags)
{
  struct trie *t = (struct trie *) tb->tb_data;
  const t_key key = ntohl(flp->daddr);
  struct key_vector *n, *pn;
  struct fib_alias *fa;
  unsigned long index;
  t_key cindex;

  pn = t->kv;
  cindex = 0;

  n = get_child_rcu(pn, cindex);

  /* Travel to the longest prefix match in the trie */
  for (;;) {
    index = get_cindex(key, n);

    /* we have found a leaf. Prefixes have already been compared */
    if (IS_LEAF(n))
      goto found;

    n = get_child_rcu(n, index);
  }

found:
  /* Process the leaf, if that fails fall back to backtracing */
  hlist_for_each_entry_rcu(fa, &n->leaf, fa_list) {
    struct fib_info *fi = fa->fa_info;
    int nhsel, err;

    if (fi->fib_dead)
      continue;

    int err = fib_props[fa->fa_type].error;

    for (nhsel = 0; nhsel < fi->fib_nhs; nhsel++) {
      const struct fib_nh *nh = &fi->fib_nh[nhsel];
      struct in_device *in_dev = __in_dev_get_rcu(nh->nh_dev);

      if (in_dev && nh->nh_flags & RTNH_F_LINKDOWN)
        continue;

      res->prefix = htonl(n->key);
      res->prefixlen = KEYLENGTH - fa->fa_slen;
      res->nh_sel = nhsel;
      res->type = fa->fa_type;
      res->scope = fi->fib_scope;
      res->fi = fi;
      res->table = tb;
      res->fa_head = &n->leaf;

      return err;
    }
  }
}
{{</highlight>}}

The first thing to notice here is that the FIB is accessed through a [trie](https://en.wikipedia.org/wiki/Trie), where interior nodes are destination address prefixes. The trie is extracted from the `fib_table` at line 4 and we initialize the key that is used to search the tree in line 5 as the destination address for the outbound packets. Next, a reference to the first node in the vector of keys that comprises the trie is created in line 14.

The loop at line 17 iterates through the trie based on the destination-address search key, jumping to the `found` label once a leaf node has been reached. Once we arrive at `found`, we iterate through the `fib_alias` entries found at the leaf, until we find one that satisfies what we are looking for. There has been one check in this example preserved from the actual code at line 33. There are many more checks in play, consult the [actual code](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/fib_trie.c?h=v4.15.11#n1422) to see them all.

Once we have our hands on a `fib_alias` that passes the required checks, we iterate through it's next-hop entries at line 36. The `nh` in `fib_nh` [stands for next-hop](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/fib_semantics.c?h=v4.15.11#n735). The next-hop entries are checked for a number of conditions (again massively simplified here, see [actual code](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/fib_trie.c?h=v4.15.11#n1422)). If the checks pass then we fill in the `res` result structure and return.

Note in particular that on line 50, the `fib_info` struct is assigned to the result via the `fi` struct member. We can now access the device associated to the outbound path through [`FIB_RES_DEV`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/net/ip_fib.h?h=v4.15.11#n183)

```c
#define FIB_RES_DEV(res)   (FIB_RES_NH(res).nh_dev)
#define FIB_RES_NH(res)    ((res).fi->fib_nh[(res).nh_sel])
```

This gives us access to the [`net_device`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/netdevice.h?h=v4.15.11#n1443) structure. This is a rather large structure that collects most things one would need to know about a network device in order to shove muffins through it. `FIB_RES_DEV` is used by the `ip_route_output_key_hash_rcu` function code above to get a hold of the output device. Popping back up the stack to that code, the next point of interest is [`fib_select_path`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/linux/netdevice.h?h=v4.15.11#n1443)

```c
void fib_select_path(struct net *net, struct fib_result *res,
         struct flowi4 *fl4, const struct sk_buff *skb)
{
  bool oif_check;

  oif_check = (fl4->flowi4_oif == 0 ||
         fl4->flowi4_flags & FLOWI_FLAG_SKIP_NH_OIF);

#ifdef CONFIG_IP_ROUTE_MULTIPATH
  if (res->fi->fib_nhs > 1 && oif_check) {
    int h = fib_multipath_hash(res->fi, fl4, skb);

    fib_select_multipath(res, h);
  }
  else
#endif
  if (!res->prefixlen &&
      res->table->tb_num_default > 1 &&
      res->type == RTN_UNICAST && oif_check)
    fib_select_default(fl4, res);

  if (!fl4->saddr)
    fl4->saddr = FIB_RES_PREFSRC(net, *res);
}
```

This function decides which path to use from a list of `fib_alias` structures. The entire output of this process is packed up into an [`rtable`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/include/net/route.h?h=v4.15.11#n51) structure by [`__mkroute_output`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/route.c?h=v4.15.11#n2149) and returned to the `ip_route_output_key_hash_rcu` function above which is ultimately plumbed back to the `udp_sendmsg` above in the `rt` variable at line 1019. 

#### Transmission - Actually Shoving Muffins Through Socket

Next a socket buffer is created to encapsulate the muffin via [`ip_make_skb`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/ip_output.c?h=v4.15.11#n1457). Then the skb encapsulated muffin is ultimately shoved out the front door via [`udp_send_skb`](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/net/ipv4/udp.c?h=v4.15.11#n786). However, there is quite a bit that happens in between `udp_send_skb` and the muffin actually going onto the network interface card (NIC). Starting from `udp_send_skb` this is the path our muffin will be taking through the kernel code to the NIC.

| line | function call | definition | notes |
| ---:|:--- |:--- | ---:|
|`{{< krefl "net/ipv4/udp.c" 1051 >}}`|`udp_send_skb`                                       | {{< krefp "net/ipv4/udp.c" 786 >}} ||
|`{{< krefl "net/ipv4/udp.c" 829 >}}`|`ip_send_skb`                                         | {{< krefp "net/ipv4/ip_output.c" 1410 >}}||
|`{{< krefl "net/ipv4/ip_output.c" 1414 >}}`| `ip_local_out`                                | {{< krefp "net/ipv4/ip_output.c" 118 >}} ||
|`{{< krefl "net/ipv4/ip_output.c" 122 >}}`| `__ip_local_out`                               | {{< krefp "net/ipv4/ip_output.c" 97 >}} ||
|`{{< krefl "net/ipv4/ip_output.c" 113 >}}`| `nf_hook`                                      | {{< krefp "include/linux/netfilter.h" 182 >}} ||
|`{{< krefl "include/linux/netfilter.h" 205 >}}`| `nf_hook_slow`                            | {{< krefp "net/netfilter/core.c" 460 >}} ||
|`{{< krefl "net/netfilter/core.c" 478 >}}`| `nf_queue`                                     | {{< krefp "net/netfilter/nf_queue.c" 166 >}} ||
|`{{< krefl "net/netfilter/nf_queue.c" 172 >}}`| `__nf_queue`                               | {{< krefp "net/netfilter/nf_queue.c" 114 >}} ||
|`{{< krefl "net/netfilter/nf_queue.c" 151 >}}`| `qh->outfn`                                | {{< krefp "net/netfilter/nfnetlink_queue.c" 1234 >}} ||
|`{{< krefl "net/netfilter/nfnetlink_queue.c" 787 >}}`| `__nfqnl_enqueue_packet`            | {{< krefp "net/netfilter/nfnetlink_queue.c" 632 >}} ||
|`{{< krefl "net/netfilter/nfnetlink_queue.c" 665 >}}`| `nfnetlink_unicast`                 | {{< krefp "net/netfilter/nfnetlink.c" 143 >}} ||
|`{{< krefl "net/netfilter/nfnetlink.c" 146 >}}`| `netlink_unicast`                         | {{< krefp "net/netlink/af_netlink.c" 1284 >}} ||
|`{{< krefl "net/netlink/af_netlink.c" 1316 >}}`| `netlink_sendskb`                         | {{< krefp "net/netlink/af_netlink.c" 1226 >}} ||
|`{{< krefl "net/netlink/af_netlink.c" 1228 >}}`| `__netlink_sendskb`                       | {{< krefp "net/netlink/af_netlink.c" 1215 >}} ||
|`{{< krefl "net/netlink/af_netlink.c" 1219 >}}`| `netlink_deliver_tap`                     | {{< krefp "net/netlink/af_netlink.c" 295 >}} ||
|`{{< krefl "net/netlink/af_netlink.c" 300 >}}`| `__netlink_deliver_tap`                    | {{< krefp "net/netlink/af_netlink.c" 280 >}} ||
|`{{< krefl "net/netlink/af_netlink.c" 289 >}}`| `__netlink_deliver_tap_skb`                | {{< krefp "net/netlink/af_netlink.c" 249 >}} ||
|`{{< krefl "net/netlink/af_netlink.c" 271 >}}`| `dev_queue_xmit`                           | {{< krefp "net/core/dev.c" 3549 >}} ||
|`{{< krefl "net/core/dev.c" 3551 >}}`| `__dev_queue_xmit`                                  | {{< krefp "net/core/dev.c" 3443 >}} ||
|`{{< krefl "net/core/dev.c" 3486 >}}`| `__dev_xmit_skb`                                    | {{< krefp "net/core/dev.c" 3185 >}} ||
|`{{< krefl "net/core/dev.c" 3518 >}}`| `dev_hard_start_xmit`                               | {{< krefp "net/core/dev.c" 3016 >}} | 1 |
|`{{< krefl "net/core/dev.c" 3026 >}}`| `xmit_one`                                          | {{< krefp "net/core/dev.c" 2999 >}} ||
|`{{< krefl "net/core/dev.c" 3010 >}}`| `netdev_start_xmit`                                 | {{< krefp "include/linux/netdevice.h" 4045 >}} ||
|`{{< krefl "include/linux/netdevice.h" 4051 >}}`| `__netdev_start_xmit`                    | {{< krefp "include/linux/netdevice.h" 4037 >}} ||
|`{{< krefl "include/linux/netdevice.h" 4042 >}}`| `ops->ndo_start_xmit`                    | {{< krefp "drivers/net/ethernet/intel/e1000/e1000_main.c" 854 >}} | 2 |
|`{{< krefl "drivers/net/ethernet/intel/e1000/e1000_main.c" 854 >}}`| `e1000_xmit_frame`    | {{< krefp "drivers/net/ethernet/intel/e1000/e1000_main.c" 3125 >}} ||

```
1. chose the non queue-based path, queue based path starts at 3517
2. chose e1000 device b/c that is what we are using in testing environment
```

As you can see from the trace above, the socket buffer traverses 5 major Linux kernel subsystems from the UDP subsystem to the NIC driver that ultimately launches the muffin out the front door.

1. net/ipv4/udp
2. [net/netfilter](https://www.netfilter.org/)
3. [net/netlink](https://en.wikipedia.org/wiki/Netlink)
4. net/core
5. drivers/net/ethernet/intel/e1000

Our originating `sendto` syscall landed us in the UDP subsystem. The `net/ipv4` subsystem uses netfilter as a means to deliver socket buffers to the appropriate output queues. Netfilter then notifies netlink of the queued up socket buffers which will call down into the core network subsystem to tell the NIC device transmit (xmit) the contents of the socket buffer. A pointer to the appropriate device is already resident in the socket buffer (`sk_buff`) from the information provided by the FIB table earlier. When the socket buffer arrives at the network core subsystem, all the core has to do is call `ndo_start_xmit` on the driver associated with the device and that driver will handle actually launching the muffin out the front door.

Lets take a look at some of the code from the trace above, many interesting things are happening. Starting with `udp_send_skb`.

```c
static int udp_send_skb(struct sk_buff *skb, struct flowi4 *fl4)
{
	struct sock *sk = skb->sk;
	struct inet_sock *inet = inet_sk(sk);
	struct udphdr *uh;
	int err = 0;
	int is_udplite = IS_UDPLITE(sk);
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	__wsum csum = 0;

	/*
	 * Create a UDP header
	 */
	uh = udp_hdr(skb);
	uh->source = inet->inet_sport;
	uh->dest = fl4->fl4_dport;
	uh->len = htons(len);
	uh->check = 0;

	if (is_udplite)  				 /*     UDP-Lite      */
		csum = udplite_csum(skb);

	else if (sk->sk_no_check_tx) {			 /* UDP csum off */

		skb->ip_summed = CHECKSUM_NONE;
		goto send;

	} else if (skb->ip_summed == CHECKSUM_PARTIAL) { /* UDP hardware csum */

		udp4_hwcsum(skb, fl4->saddr, fl4->daddr);
		goto send;

	} else
		csum = udp_csum(skb);

	/* add protocol-dependent pseudo-header */
	uh->check = csum_tcpudp_magic(fl4->saddr, fl4->daddr, len,
				      sk->sk_protocol, csum);
	if (uh->check == 0)
		uh->check = CSUM_MANGLED_0;

send:
	err = ip_send_skb(sock_net(sk), skb);
	if (err) {
		if (err == -ENOBUFS && !inet->recverr) {
			UDP_INC_STATS(sock_net(sk),
				      UDP_MIB_SNDBUFERRORS, is_udplite);
			err = 0;
		}
	} else
		UDP_INC_STATS(sock_net(sk),
			      UDP_MIB_OUTDATAGRAMS, is_udplite);
	return err;
}

```

The primary thing that is happening here is the creation of the [UDP header](https://en.wikipedia.org/wiki/User_Datagram_Protocol#Packet_structure). Next we follow the `ip_send_skb` through the `nf_hook` call site in `__ip_local_out` (the intermediary steps are just plumbing).

```c
int __ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	iph->tot_len = htons(skb->len);
	ip_send_check(iph);

	/* if egress device is enslaved to an L3 master device pass the
	 * skb to its handler for processing
	 */
	skb = l3mdev_ip_out(sk, skb);
	if (unlikely(!skb))
		return 0;

	skb->protocol = htons(ETH_P_IP);

	return nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT,
		       net, sk, skb, NULL, skb_dst(skb)->dev,
		       dst_output);
}
```

This is our transition from the UDP subsystem into netfilter. Our first interesting stop in netfilter is `__nf_queue`. This function gets a pointer to the queue handler that our muffin will be shoved into and calls the `outfn` on that queue with our socket buffer encapsulated muffin further encapsulated in a netfilter queue entry (`nf_queue_entry`).

```c
static int __nf_queue(struct sk_buff *skb, const struct nf_hook_state *state,
		      const struct nf_hook_entries *entries,
		      unsigned int index, unsigned int queuenum)
{
	int status = -ENOENT;
	struct nf_queue_entry *entry = NULL;
	const struct nf_afinfo *afinfo;
	const struct nf_queue_handler *qh;
	struct net *net = state->net;

	/* QUEUE == DROP if no one is waiting, to be safe. */
	qh = rcu_dereference(net->nf.queue_handler);
	if (!qh) {
		status = -ESRCH;
		goto err;
	}

	afinfo = nf_get_afinfo(state->pf);
	if (!afinfo)
		goto err;

	entry = kmalloc(sizeof(*entry) + afinfo->route_key_size, GFP_ATOMIC);
	if (!entry) {
		status = -ENOMEM;
		goto err;
	}

	*entry = (struct nf_queue_entry) {
		.skb	= skb,
		.state	= *state,
		.hook_index = index,
		.size	= sizeof(*entry) + afinfo->route_key_size,
	};

	nf_queue_entry_get_refs(entry);
	skb_dst_force(skb);
	afinfo->saveroute(skb, entry);
	status = qh->outfn(entry, queuenum);

	if (status < 0) {
		nf_queue_entry_release_refs(entry);
		goto err;
	}

	return 0;

err:
	kfree(entry);
	return status;
}
```

Next we arrive at the boundary between netfilter and netlink in `__nfqnl_enqueue_packet`. For brevity the error handling portions of this code have been omitted, for the full version see the link in the trace table above.

```c
static int
__nfqnl_enqueue_packet(struct net *net, struct nfqnl_instance *queue,
			struct nf_queue_entry *entry)
{
	struct sk_buff *nskb;
	int err = -ENOBUFS;
	__be32 *packet_id_ptr;
	int failopen = 0;

	nskb = nfqnl_build_packet_message(net, queue, entry, &packet_id_ptr);
	spin_lock_bh(&queue->lock);

	entry->id = ++queue->id_sequence;
	*packet_id_ptr = htonl(entry->id);

	/* nfnetlink_unicast will either free the nskb or add it to a socket */
	err = nfnetlink_unicast(nskb, net, queue->peer_portid, MSG_DONTWAIT);

	__enqueue_entry(queue, entry);

	spin_unlock_bh(&queue->lock);
	return 0;

err_out_free_nskb:
	kfree_skb(nskb);
err_out_unlock:
	spin_unlock_bh(&queue->lock);
err_out:
	return err;
}
```

The first point of interest in the netlink subsystem is where netlink decides what tap devices to send the socket buffer to. This is a two phase process. The first phase is a sort of tap-broadcast phase there `__netlink_deliver_tap` simply attempts to deliver the socket buffer to all taps.

```c
static void __netlink_deliver_tap(struct sk_buff *skb)
{
	int ret;
	struct netlink_tap *tmp;

	if (!netlink_filter_tap(skb))
		return;

	list_for_each_entry_rcu(tmp, &netlink_tap_all, list) {
		ret = __netlink_deliver_tap_skb(skb, tmp->dev);
		if (unlikely(ret))
			break;
	}
}
```

The next phase determines whether the tap device should actually handle the socket buffer and if so transmits it on that device. This is also the boundary between netlink and the kernel core network code. Once we call `dev_queue_xmit` we are back in the kernel core.

```c
static int __netlink_deliver_tap_skb(struct sk_buff *skb,
				     struct net_device *dev)
{
	struct sk_buff *nskb;
	struct sock *sk = skb->sk;
	int ret = -ENOMEM;

	if (!net_eq(dev_net(dev), sock_net(sk)))
		return 0;

	dev_hold(dev);

	if (is_vmalloc_addr(skb->head))
		nskb = netlink_to_full_skb(skb, GFP_ATOMIC);
	else
		nskb = skb_clone(skb, GFP_ATOMIC);
	if (nskb) {
		nskb->dev = dev;
		nskb->protocol = htons((u16) sk->sk_protocol);
		nskb->pkt_type = netlink_is_kernel(sk) ?
				 PACKET_KERNEL : PACKET_USER;
		skb_reset_network_header(nskb);
		ret = dev_queue_xmit(nskb);
		if (unlikely(ret > 0))
			ret = net_xmit_errno(ret);
	}

	dev_put(dev);
	return ret;
}
```

In the core kernel network code that follows, the decision is made whether or not this device has an actual queue to shove the hyper-encapsulated muffin into or if we shall just transmit to the device directly. In this article we assume the direct transmission path (you can fully follow this logic in the `__dev_queue_xmit` and `dev_xmit_skb` function pointers above). Assuming the direct device call path we land at `__netdev_start_xmit`.

```c
static inline netdev_tx_t __netdev_start_xmit(const struct net_device_ops *ops,
					      struct sk_buff *skb, struct net_device *dev,
					      bool more)
{
	skb->xmit_more = more ? 1 : 0;
	return ops->ndo_start_xmit(skb, dev);
}
```

This is the boundary between the core kernel network subsystem and the device driver that will be actually sending our muffin into hyperspace. The device was extracted from the socket buffer in `_def_queue_xmit` earlier. Recall that the information that defines where the socket buffer was computed using the FIB code much earlier. In particular line {{<krefl "net/ipv4/udp.c" 1019>}} in `net/ipv4/udp.c` in the `udp_sendmsg` function collected the kernels internal routing/forwarding information and used that information in line {{<krefl "net/ipv4/udp.c" 1046>}} to create the socket buffer with the appropriate device information.

In our case we are testing on a virtual machine inside [qemu](https://qemu.org) that uses a driver that emulates the [intel e1000](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git/tree/drivers/net/ethernet/intel/e1000?h=v4.15.11) NIC. So the call to `ndo_start_xmit` lands us in the device operations for the Intel e1000 NIC.

```c
static const struct net_device_ops e1000_netdev_ops = {
	.ndo_open		= e1000_open,
	.ndo_stop		= e1000_close,
	.ndo_start_xmit		= e1000_xmit_frame,
	.ndo_set_rx_mode	= e1000_set_rx_mode,
	.ndo_set_mac_address	= e1000_set_mac,
	.ndo_tx_timeout		= e1000_tx_timeout,
	.ndo_change_mtu		= e1000_change_mtu,
	.ndo_do_ioctl		= e1000_ioctl,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_vlan_rx_add_vid	= e1000_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= e1000_vlan_rx_kill_vid,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= e1000_netpoll,
#endif
	.ndo_fix_features	= e1000_fix_features,
	.ndo_set_features	= e1000_set_features,
};
```

where the `ndo_start_xmit` function pointer which maps to {{<krefp "drivers/net/ethernet/intel/e1000/e1000_main.c" 3124>}}. The muffin has been successfully delivered from the core kernel to the network device driver responsible for transmitting it to its next hop. In the next article I will cover the device driver code that actually transmits the muffin!
