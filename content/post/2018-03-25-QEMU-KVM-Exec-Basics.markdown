---
title: "QEMU/KVM VM Execution Basics"
date: 2018-03-25T10:47:00
disqusid: 1954
series: emu
categories: QEMU Internals
---

This post walks through the code that makes a simple QEMU/KVM virtual machine run.  When you execute one of the `qemu-system-*` commands, QEMU initializes a model of the machine that you asked for. Machines are compositions of devices and their interconnections through buses. Machines, Devices and Buses are central abstractions in the QEMU codebase and go by the names [MachineClass](https://git.qemu.org/?p=qemu.git;a=blob;f=include/hw/boards.h;h=156b16f7a6b5e10ae2c7f4d3574ca0b1b74a88d9;hb=refs/heads/stable-2.11#l103), [DeviceClass](https://git.qemu.org/?p=qemu.git;a=blob;f=include/hw/qdev-core.h;h=0a71bf83f04700af621e00949695a5ea53345e14;hb=refs/heads/stable-2.11#l43) and [BusClass](
https://git.qemu.org/?p=qemu.git;a=blob;f=include/hw/qdev-core.h;h=0a71bf83f04700af621e00949695a5ea53345e14;hb=refs/heads/stable-2.11#l180) respectively.


<img class="center-image" src="/img/qemu-kvm-basics/objects.png" width="65%" />


The entry-point for the QEMU system emulator is [vl.c](https://git.qemu.org/?p=qemu.git;a=blob;f=vl.c;h=1ad1c0463757a0c82c47b4d01d69c6fa72e1a645;hb=refs/heads/stable-2.11#l3091). This is a rather large main function that spends most of its energy parsing and dealing with command line arguments. Our starting point of interest for understanding QEMU/KVM execution is at the [`machine_run_board_init`](https://git.qemu.org/?p=qemu.git;a=blob;f=vl.c;h=1ad1c0463757a0c82c47b4d01d69c6fa72e1a645;hb=refs/heads/stable-2.11#l4753) function call. `machine_run_board_init` does a few sanity checks, like ensuring that the requested machine can support the requested processor types and then calls the initialization function for the machine type requested via `machine_class->init`. 

There are many different machine models that come stock with QEMU. In this article, we will be using the default x86\_64 machine model which goes by the name  `pc-i440fx`. Its initialization function is called [`pc_init1`](https://git.qemu.org/?p=qemu.git;a=blob;f=hw/i386/pc_piix.c;h=5e47528993c9dfbc930857abac667d1475ccb615;hb=refs/heads/stable-2.11#l67). To understand how this function gets mapped into the `init` member of the `machine_class` instance found in `machine_run_board_init` have a look at the [`DEFINE_I440FX_MACHINE`](https://git.qemu.org/?p=qemu.git;a=blob;f=hw/i386/pc_piix.c;h=5e47528993c9dfbc930857abac667d1475ccb615;hb=refs/heads/stable-2.11#l413) and [`DEFINE_PC_MACHINE`](https://git.qemu.org/?p=qemu.git;a=blob;f=hw/i386/pc_piix.c;h=5e47528993c9dfbc930857abac667d1475ccb615;hb=refs/heads/stable-2.11#l413) macros

```c 
#define DEFINE_I440FX_MACHINE(suffix, name, compatfn, optionfn) \
  static void pc_init_##suffix(MachineState *machine)           \
  {                                                             \
    void (*compat)(MachineState *m) = (compatfn);               \
    if (compat) {                                               \
        compat(machine);                                        \
    }                                                           \
    pc_init1(machine, TYPE_I440FX_PCI_HOST_BRIDGE,              \
              TYPE_I440FX_PCI_DEVICE);                          \
  }                                                             \
  DEFINE_PC_MACHINE(suffix, name, pc_init_##suffix, optionfn)
```

```c
define DEFINE_PC_MACHINE(suffix, namestr, initfn, optsfn)                   \
  static void pc_machine_##suffix##_class_init(ObjectClass *oc, void *data) \
  {                                                                         \
    MachineClass *mc = MACHINE_CLASS(oc);                                   \
    optsfn(mc);                                                             \
    mc->init = initfn;                                                      \
  }                                                                         \
  static const TypeInfo pc_machine_type_##suffix = {                        \
    .name       = namestr TYPE_MACHINE_SUFFIX,                              \
    .parent     = TYPE_PC_MACHINE,                                          \
    .class_init = pc_machine_##suffix##_class_init,                         \
  };                                                                        \
  static void pc_machine_init_##suffix(void)                                \
  {                                                                         \
      type_register(&pc_machine_type_##suffix);                             \
  }                                                                         \
  type_init(pc_machine_init_##suffix)
```

So we can see here that the init function for the i440fx is synthesized on the fly at compile time by the macro, but the real work is done by the `pc_init1` function within the synthesized function. 

## VCPU Initialization
Our first point of focus in the `pc_init1` function will be the [call](https://git.qemu.org/?p=qemu.git;a=blob;f=hw/i386/pc_piix.c;h=5e47528993c9dfbc930857abac667d1475ccb615;hb=refs/heads/stable-2.11#l151) to [`pc_cpus_init`](https://git.qemu.org/?p=qemu.git;a=blob;f=hw/i386/pc.c;h=186545d2a4e56d874eebb542bf61bb5f59618e36;hb=refs/heads/stable-2.11#l1133)

```c
void pc_cpus_init(PCMachineState *pcms)
{
  int i;
  const CPUArchIdList *possible_cpus;
  MachineState *ms = MACHINE(pcms);
  MachineClass *mc = MACHINE_GET_CLASS(pcms);

  pcms->apic_id_limit = x86_cpu_apic_id_from_index(max_cpus - 1) + 1;
  possible_cpus = mc->possible_cpu_arch_ids(ms);
  for (i = 0; i < smp_cpus; i++) {
    pc_new_cpu(possible_cpus->cpus[i].type, possible_cpus->cpus[i].arch_id,
        &error_fatal);
  }
}
```
Here we can see the machine initialization code, reading the smp topology information provided by the user (either explicitly through the `-smp` argument of `qemu-system` or implicitly through defaults) to create the correct number of virtual cpus (VCPU). The [`pc_new_cpu`](https://git.qemu.org/?p=qemu.git;a=blob;f=hw/i386/pc.c;h=186545d2a4e56d874eebb542bf61bb5f59618e36;hb=refs/heads/stable-2.11#l1094) follows

```c
static void pc_new_cpu(const char *typename, int64_t apic_id, Error **errp)
{
    Object *cpu = NULL;
    Error *local_err = NULL;

    cpu = object_new(typename);

    object_property_set_uint(cpu, apic_id, "apic-id", &local_err);
    object_property_set_bool(cpu, true, "realized", &local_err);

    object_unref(cpu);
    error_propagate(errp, local_err);
}
```

Notice a few things, the CPU device is not special. It's just a regular qemu device (qdev) created through the `object_new` factory with a typename. Notice also that we do not see a specific call to `realize` here. This is because what we have created is the most generic type of object called [`Object`](https://git.qemu.org/?p=qemu.git;a=blob;f=include/qom/object.h;h=dc73d59660c2b501062c41c1aae74488fbad8fc4;hb=refs/heads/stable-2.11#l405). Objects support an arbitrary set of properties that come with getters and setters, so they are quite extensible. Here we focus on the setting of the boolean property "realized" on the `cpu` object in the code above.

The cpu is s special type of object called a `qdev`. All `qdev` devices are initialized with a few basic properties through their initializer function [`device_initfn`](https://git.qemu.org/?p=qemu.git;a=blob;f=hw/core/qdev.c;h=11112951a52278c1cbf849314fe5b5503b5841b5;hb=refs/heads/stable-2.11#l1024)

{{<highlight c "linenos=inline">}}
static void device_initfn(Object *obj)
{
    DeviceState *dev = DEVICE(obj);
    ObjectClass *class;
    Property *prop;

    if (qdev_hotplug) {
        dev->hotplugged = 1;
        qdev_hot_added = true;
    }

    dev->instance_id_alias = -1;
    dev->realized = false;

    object_property_add_bool(obj, "realized",
                             device_get_realized, device_set_realized, NULL);
    object_property_add_bool(obj, "hotpluggable",
                             device_get_hotpluggable, NULL, NULL);
    object_property_add_bool(obj, "hotplugged",
                             device_get_hotplugged, NULL,
                             &error_abort);

    class = object_get_class(OBJECT(dev));
    do {
        for (prop = DEVICE_CLASS(class)->props; prop && prop->name; prop++) {
            qdev_property_add_legacy(dev, prop, &error_abort);
            qdev_property_add_static(dev, prop, &error_abort);
        }
        class = object_class_get_parent(class);
    } while (class != object_class_by_name(TYPE_DEVICE));

    object_property_add_link(OBJECT(dev), "parent_bus", TYPE_BUS,
                             (Object **)&dev->parent_bus, NULL, 0,
                             &error_abort);
    QLIST_INIT(&dev->gpios);
}
{{</highlight>}}

The particular object property we are interested in is the "realized" property on line 15. Here we see that the setter function provided is [`device_set_realized`](https://git.qemu.org/?p=qemu.git;a=blob;f=hw/core/qdev.c;h=11112951a52278c1cbf849314fe5b5503b5841b5;hb=refs/heads/stable-2.11#l875). There is quite a bit going on in `device_set_realized` the particular bits we are interested in are the actual call to the realization of the device which happens at line 913.

{{<highlight c "hl_lines=39-41">}}
static void device_set_realized(Object *obj, bool value, Error **errp)
{
  DeviceState *dev = DEVICE(obj);
  DeviceClass *dc = DEVICE_GET_CLASS(dev);
  HotplugHandler *hotplug_ctrl;
  BusState *bus;
  Error *local_err = NULL;
  bool unattached_parent = false;
  static int unattached_count;

  if (dev->hotplugged && !dc->hotpluggable) {
    error_setg(errp, QERR_DEVICE_NO_HOTPLUG, object_get_typename(obj));
    return;
  }

  if (value && !dev->realized) {
    if (!check_only_migratable(obj, &local_err)) {
      goto fail;
    }

    if (!obj->parent) {
      gchar *name = g_strdup_printf("device[%d]", unattached_count++);

      object_property_add_child(container_get(qdev_get_machine(),
            "/unattached"),
          name, obj, &error_abort);
      unattached_parent = true;
      g_free(name);
    }

    hotplug_ctrl = qdev_get_hotplug_handler(dev);
    if (hotplug_ctrl) {
      hotplug_handler_pre_plug(hotplug_ctrl, dev, &local_err);
      if (local_err != NULL) {
        goto fail;
      }
    }

    if (dc->realize) {
      dc->realize(dev, &local_err);
    }

    // ...
{{</highlight>}}

Now the question arises, what does this realize function actually do. To find out, lets first take a look at how the realize function of the x86 cpu is plumbed. This takes place in [`target/i386/cpu.c`](https://git.qemu.org/?p=qemu.git;a=blob;f=target/i386/cpu.c;h=70c8ae82d5db335e75119b549d280651fb2a0fda;hb=refs/heads/stable-2.11#l4632)


{{<highlight c "hl_lines=9">}}
static void x86_cpu_common_class_init(ObjectClass *oc, void *data)
{
     X86CPUClass *xcc = X86_CPU_CLASS(oc);
     CPUClass *cc = CPU_CLASS(oc);
     DeviceClass *dc = DEVICE_CLASS(oc);

     xcc->parent_realize = dc->realize;
     xcc->parent_unrealize = dc->unrealize;
     dc->realize = x86_cpu_realizefn;
     dc->unrealize = x86_cpu_unrealizefn;
     dc->props = x86_cpu_properties;
     
     //...
}
{{</highlight>}}

Here we can see that the device class `realize` function points to `x86_cpu_realizefn`. Through this `x86_cpu_realizefn`, we take a look at how VCPUs are actually created. QEMU can implement the VCPUs in many ways. On Linux systems with processors that support hardware virtualization (the vast majority of processors found in workstations and servers these days) the common choice is [KVM](https://www.linux-kvm.org). KVM is a Linux kernel module that provides, among other things, highly efficient VCPUs for virtual machines that take advantage instructions in modern processors specifically designed to support efficient virtualization. KVM is the mechanism we will be looking at here.

The code path that creates a KVM VCPU from QEMU is the following.

<pre>
| target/i386/cpu.c          | {{<qreff "target/i386/cpu.c" 4054 "x86_cpu_realizefn">}}
| target/i386/cpu.c          | {{<qreff "target/i386/cpu.c" 4217 "qemu_init_vcpu">}}
| cpus.c                     | {{<qreff "cpus.c" 1789 "qemu_kvm_start_vcpu">}}
| cpus.c                     | {{<qreff "cpus.c" 1748 "qemu_thread_create">}}
| util/qemu-thread-posix.c   | {{<qreff "util/qemu-thread-posix.c" 508 "pthread_create">}}
| ~~>  cpus.c                | {{<qreff "cpus.c" 1101 "qemu_kvm_cpu_thread_fn">}}     # passed as parameter to qemu_thread_create
|      cpus.c                | {{<qreff "cpus.c" 1114 "kvm_init_vcpu">}}
|      cpus.c                | {{<qreff "cpus.c" 1120 "kvm_init_cpu_signals">}}
|   -->cpus.c                | {{<qreff "cpus.c" 1127 "cpu_can_run">}}
|   :  cpus.c                | {{<qreff "cpus.c" 1128 "kvm_cpu_exec">}}
|   :  cpus.c                | {{<qreff "cpus.c" 1133 "qemu_wait_io_event">}}
|   ---cpus.c                | {{<qreff "cpus.c" 1134 "cpu_can_run">}}
</pre>

