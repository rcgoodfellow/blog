---
title: "Truly Networked Booting with Pxelinux"
date: 2017-03-13T18:00:00
disqusid: 1950
series: sysprog
categories: Systems-Programming
---


This article covers some extensions to pxelinux to expose both UDP and TCP sockets in 'userspace'. The motivation for extending pxelinux in this way is building a new stage 0 bootloader for [Deter](https://www.deter-project.org). 

<img class="center-image" src="/img/netboot.png" />

For those unfamiliar with Deter, it is a network testbed that allows one to design arbitrarily complex IP networks and realize an emulated version of them using the underlying hardware that the testbed presides over. You can think of it as a sort of cloud for network systems design and experimentation with a particular focus on cybersecurity. 

All Deter nodes start life in our very custom pxe bootloader. Up till now, this was a hand customized FreeBSD BTX bootloader. Each time the bootloader comes up, it engages in a protocol we call `bootinfo` with the testbed master controller to figure out what it needs to boot. This can be anything from loading a memory based file system over the network to simply chain loading another bootloader that is already resident on one of the disks.

We decided to move from BTX to pxelinux because pxelinux has a nice modular architecture where we can add our functionality without having to modify pxelinux itself. Well, kinda. I had to plumb the TCP and UDP socket API into userspace to get full network functionality. But modulo that plumbing which I am working to push back upstream to the pxelinux folks, the Deter specific code is self contained within a pxelinux module.

## Pxelinux basics
[Pxelinux](http://www.syslinux.org/wiki/index.php?title=PXELINUX) is a part of the [syslinux](http://syslinux.org) family of bootloaders. The specialty of pxelinux is booting over a network using the [preboot execution environment](https://en.wikipedia.org/wiki/Preboot_Execution_Environment). Under the hood pxelinux uses [LwIP](http://savannah.nongnu.org/projects/lwip/) under the hood to realize a network environment that is amazingly close to a real Linux/BSD sockets API atop PXE. Pxelinux also has native support for HTTP, FTP and a few other higher level protocols.

The [bootloader I developed for deter](https://github.com/deter-project/deterboot) requires a UDP socket interface. Currently the LwIP socket API is not exposed to pxelinux userspace. The notion of userspace in pxelinux is the separation between module code and the core pxelinux code. This boundary is enforced by how C functions are exported from the core. This actually make it incredibly easy to do the plumbing. All I had to do was export the socket API functions from the core using the syslinux `__export` macro, and set a few options in `lwipopts.h` to enable conditional compilation for the socket API itself and ... kaboom pxelinux modules now have a full blown socket API (well I selectively exported only what I needed, further testing will need to be done for other API functions). Most of the work is in [this commit](https://github.com/deter-project/deterboot/commit/fefda68aaa9502af60987d12fa4254728e13b33b).

# Writing network code in pxelinux

Once the LwIP socket API has been plumbed, writing network code delightfully looks and feels pretty much like Linux. Here is a nice mostly self contained little chuck of code from [here](https://github.com/deter-project/deterboot/blob/master/com32/deterboot/deterboot.c#L63) to ask a question over UDP (sendto + recvfrom)

```c
size_t ask(struct Question *q)
{
  struct sockaddr_in dest;
  dest.sin_family = AF_INET;
  dest.sin_port = htons(q->port);
  dest.sin_addr = q->who;
  int sock = socket(AF_INET, SOCK_DGRAM, 0);

  struct sockaddr_in reply;
  reply.sin_family = AF_INET;
  reply.sin_port = htons(q->response_port);
  reply.sin_addr = q->me;
  int rsock = socket(AF_INET, SOCK_DGRAM, 0);
  
  int result = QUESTION_OK;

  bind(rsock, (struct sockaddr*)&reply, sizeof(reply));

  q->out_sz = sendto(
      sock, 
      q->what, 
      q->what_size, 
      0, 
      (struct sockaddr*)&dest, 
      sizeof(dest));

  if(q->out_sz < q->what_size)
  {
    result |= QUESTION_PARTIAL_SEND;
  }

  dest.sin_family = AF_INET;
  dest.sin_port = htons(q->port);
  dest.sin_addr = q->who;
  socklen_t dest_sz = sizeof(dest);
  q->in_sz = recvfrom(
      rsock, 
      q->response, 
      q->response_size, 
      0, 
      (struct sockaddr*)&dest, 
      &dest_sz);

  closesocket(sock);
  closesocket(rsock);

  return result;
}
```

## Actually booting stuff
Pxelinux already comes with everything we need to actually boot an operating system. Booting over the network and from a resident disk is really easy from your own module code is really easy here are some examples.

# Network booting
The code below loads a Linux kernel and memory file system over a network. It assumes that the bzImage (the zipped up kernel) and the rtoofs.cpio (initial ram disk) can be loaded given the path. The __really cool thing__ is that the path can use a variety of network protocols for example it could be `http://bootserver/images` or `ftp://bootserver/images`. This allows for an extreme level of flexibility for networked booting. You can change things around server-side any time and as long as you give consistent information to the bootloader over the network, it really doesn't care where the path points to, just that it can reach it.

We are using the linux.c32 module that comes with the syslinux distribution to do the heavy lifting here.

```c
int bootMFS(const void *path)
{
  const char *fmt =
    "linux.c32 %s/bzImage initrd=%s/rootfs.cpio BOOT=live console=tty1 quiet";

  size_t sz = snprintf(NULL, 0, fmt, path, path);
  char *cmd = malloc(sz+1);
  snprintf(cmd, sz+1, fmt, path, path);
  cmd[sz] = 0;

  int result = syslinux_run_command(cmd);
  free(cmd);
  return result;
}
```

# Chain loading
Chain loading into a disk resident bootloader such as Grub or FreeBSD loader is also super easy. We just need to know what disk and what partition the bootloader is on and we can call down into the chain.c32 module that comes with the syslinux distribution to do the heavy lifting.

```c
int chainBoot(const char *disk, int partition)
{
  const char *fmt = "chain.c32 %s %d";
  size_t sz = snprintf(NULL, 0, fmt, disk, partition);
  char *cmd = malloc(sz+1);
  snprintf(cmd, sz+1, fmt, disk, partition);
  cmd[sz] = 0;

  int result = syslinux_run_command(cmd);
  free(cmd);
  return result;
}
```

