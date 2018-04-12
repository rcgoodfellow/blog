---
title: "Getting Started with Netronome on Linux"
date: 2018-04-11T10:47:00
disqusid: 1955
series: networking
categories: Networking
---

This is a simple getting started guide for using Netronome NFPs on Linux. The resources needed to get started with a Netronome card on Linux are scattered around the Internet, and there is seemingly no concise guide on how to get going. These notes are based on my experience in Fedora 27.

## Install the device firmware
The Netronome firmware is located in the [linux-firmware](https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git) git repo. Clone this repo and install the Netronome firmware.

1. `git clone git://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git`
2. `cd linux-firmware/netronome`
3. `cp -r * /lib/firmware/netronome`

## Install the current kernel module
The DKMS-based kernel module you will find at [support.netronome.com](https://support.netronome.com) is made of poo. It only works for old versions of RHEL and Ubuntu. The current kernel module that actually does work is located in [this GitHub repo](https://github.com/Netronome/nfp-drv-kmods).

1. clone the repo
2. build the module
3. remove the nfp module that is resident in the upstream kernel source

```shell
sudo rmmod nfp
```

4. insert the kernel module you just built with the `nfp_dev_cpp` option set.

```shell
sudo insmod nfp-drv-kmods/src/nfp.ko nfp_dev_cpp
```

You can check to see if the kernel module was inserted correctly by looking for the NIC on the system.

``` shell
ip link
```

Which should show something like the following for the Netronome card.

```shell
12: enp10s0np0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state DOWN mode DEFAULT group default qlen 1000
    link/ether 00:15:4d:12:17:45 brd ff:ff:ff:ff:ff:ff
```

`ethtool` can also be helpful here.

```shell
ethtool -i enp10s0np0
```

Should show something like the following, in particular the `driver` shows `nfp`.

```shell
driver: nfp
version: 210587a (o-o-t)
firmware-version: 0.0.3.5 0.21 nic-2.0.7 nic
expansion-rom-version:
bus-info: 0000:0a:00.0
supports-statistics: yes
supports-test: no
supports-eeprom-access: no
supports-register-dump: yes
supports-priv-flags: no

```

You should also check that the supplied parameter was applied

```shell
cat  /sys/module/nfp/parameters/nfp_dev_cpp
```
This should return a value of `1`.

## Install the board support packages
The board support package contains tools to interact with your Netronome card from the host system. The board support packages can be found in the Agilio OVS software which is downloadable from support.netronome.com once you set up an account that is linked to the card you purchased. You will need to fill in the values for `version` in the instructions below according to the version you have downloaded. Installation of the full RPM does not work on current Fedora so I elected to use the source package and selectively install the required RPMs as outlined below.

1. downloaded the Agilio-OVS software tarball 
2. unpack it to a directory called `agilio-ovs` 
3. cd to `agilio-ovs/sdn-<version>/nfp-bsp`
4. install the base board support package

```shell
sudo dnf install nfp-bsp-6000-b0_<version>.rpm
```

4. install the development board support package

```shell
sudo dnf install nfp-bsp-6000-b0-dev_<version>.rpm` 
```

This will install all of the board support tools to `/opt/netronome`. At this point it's useful to augment your `PATH` with `/opt/netronome/bin`. Many of the Netronome commands require root privilege so its also useful to add `/opt/netronome/bin` to the secure path in `/etc/sudoers`.

To test your installation run

```shell
sudo /opt/netronome/bin/nfp-hwinfo
```

This should output a bunch of information about your Netronome card on the command line.

## Install the SDK
The SDK contains the tools required to build programs to run on the Netronome. The SDK is also found at [support.netronome.com](https://support.netronome.com).

1. download the nfp-sdk appropriate to your distro and architecture, this is located in the 'NFP SDK for Open-NFP.org' section. The file that you want is the marked 'Hosted Toolchain for use with BSP on hardware'
2. install the sdk

```shell
sudo dnf install nfp-sdk-<version>.rpm
```

This will also install things into `/opt/netronome`, notably the compiler `nfcc` is now in `/opt/netronome/bin` along with a host of other development tools.

## Run Hello World
Your system should now be sufficiently set up to run [this hello world exercise](https://github.com/open-nfpsw/c_packetprocessing/tree/master/apps/lab4_cli).

### glhf
