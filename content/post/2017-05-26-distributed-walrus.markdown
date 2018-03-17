---
title: "Distributed Systems Testing with Walrus and Raven"
date: 2017-05-26T18:00:00
disqusid: 1952
series: testbed
categories: Testbed
---

## Introduction

Testing distributed systems is hard. In this article I will cover the approach and supporting technologies we are using to conduct rapid and effective distributed systems testing for [Deter](https://deter-project.org).

Consider the following workflow.

<img class="center-image" src="/img/dt-lifecycle.png" />

The first thing to be aware of when testing a distributed system is the _**environment**_ in which the testing itself will taking place. Here I define an environment as _the interconnection and configuration of hosts and network appliances_  e.g., computers, phones, switches, routers, access points etc. - and how they are connected.

- What does the network infrastructure look like in the target deployment environment? 
- What are the salient aspects of that environment relative to the testing that we need to accomplish?
- Is the environment itself dynamic?

The underlying engineering question we must answer to get started down the path to effective testing is: 
- How do we capture answers to these questions in a _**model**_?

Once we can concretely express a model of our network environment to test our distributed system in, we can move on to considering how to _**materialize**_ that model.

- How does one go from a model of an _interconnected topology_ to a realization?
  + Host & network appliance provisioning
  + Network plumbing
  + Host & network appliance configuration
- Can the environment be realized purely through virtualization technologies?
- How to differentiate between the network infrastructure that supports the use of the realization (ssh access, remote SCM such as Ansible) versus the infrastructure under test?

The focus on holistic models of _interconnected topologies_ as opposed small groups of hand wired machines is what sets the [Raven](https://github.com/rcgoodfellow/raven) virtualization technology apart from others.

Once a model has been materialized and it's elements configured, we must _**mount**_ our software within that environment. As developers, we typically have a machine set up to modify and build code on.

- How do we synchronize build artifacts from our development environment with installation locations within the environment under test?

The idea is that we want to build like usual and have the testing infrastructure automatically deploy build artifacts into the testing environment. This way we can run tests immediately upon successful build without having to specialize the build for the testing envrironment, ultimately leading to a _**virtuous build-test-modify cycle**_.

But wait, what about distributed testing? There isn't much out there in the way of multi-language frameworks to help out with this. This article will also introduce the [Walrus Testing Framework](https://github.com/rcgoodfellow/walrustf) that is designed specifically for that purpose.

In the article that follows, I am going to walk through a complete example of modeling, materializing, mounting, building and testing a small distributed system that is itself a network infrastructure system.

## Tutorial

# System Under Test
The system under test is a [VLAN](https://en.wikipedia.org/wiki/Virtual_LAN) management system for [Cumulus Linux](https://cumulusnetworks.com/products/cumulus-linux/). Here is the system diagram.

<img src="/img/2net-sys.png" class="center-image" style="width: 50%" />

The basic function of this system is to regulate connectivity between hosts on a network through virtual LANs. The implementation is distributed across a control agent and an implementation agent. The control agent issues the commands required to achieve a desired virtual LAN setup (using the [QBridge](https://tools.ietf.org/html/rfc4363) protocol) and the implementation agent carries out those commands by configuring the Cumulus switch using [Netlink](https://wiki.linuxfoundation.org/networking/netlink). The control agent can exist anywhere on the network and there is one implementation agent per switch.

# Model
The first step is creating model of this system. The model is composed of

- Network topology
- Host & network appliance configurations

The topology defines our components and their interconnections, and the configurations contain the scripts and files necessary to bring up each element of the topology to a state that is functional w.r.t. our test goals.

#### Network Topology
The network topology is written in Javascript. [Here](https://github.com/rcgoodfellow/raven/blob/master/models/2net/model.js) is the full code for the example we are going to go over here.

The first thing we need to do is define our nodes. Nodes and switches are defined in the exact same way. Consider the definition of the controller and the Cumulus switch below.
```javascript
controller = {
  "name": "control", "image": "debian-stretch", "os": "linux", "level": 1,
  "mounts": [
    { "source": "/space/switch-drivers", "point": "/opt/switch-drivers"},
    { "source": conf_dir+"/controller",  "point": "/tmp/config" }
  ]
}

zwitch = {
  "name": "nimbus", "image": "cumulus-latest", "os": "linux", "level": 2,
  "mounts": [
    { "source": "/space/agx",                     "point": "/opt/agx" },
    { "source": "/space/netlink",                 "point": "/opt/netlink" },
    { "source": workspace+"/config/files/nimbus", "point": "/tmp/config" }
  ]
};
```
This code defines nodes in terms of their operating system images and what mounts we would like created.

The next step is to define links between nodes. This is done as follows. This code uses more nodes than we defined above, reference the [full source](https://github.com/rcgoodfellow/raven/blob/master/models/2net/model.js) for details.

```javascript
links = [
  Link("walrus", "eth0", "nimbus", "swp1"),
  Link("control", "eth0", "nimbus", "swp2"),
  ...Range(2).map(i => Link(`n${i}`, "eth0", "nimbus", `swp${i+3}`)),
]
```

And finally we must define a topology object which is a composition of all of the above.

```javascript
topo = {
  "name": "2net",
  "nodes":[controller, walrus, ...nodes],
  "switches": [zwitch],
  "links": links
};
```

#### Configuration
The Raven configuration subsystem uses [Ansible](https://www.ansible.com). Raven projects are based on workspaces. A workspace is simply a directory that contains a file named `model.js` that contains the components discussed above and directory called `config` that contains a set of Ansible playbooks. Any Ansible playbook that corresponds to the name of a node will be automatically launched on that node by Raven. See [this directory](https://github.com/rcgoodfellow/raven/tree/master/models/2net/config) for example. The file named `nimbus.yml` will be run on node start up by Raven on the nimbus node.

#### Materialization
This assumes you have set up Raven on your system. [Getting setup](https://github.com/rcgoodfellow/raven/blob/master/README.md#installing) is pretty simple. 

Here is a quick rundown of how to start the raven system that is described in this post and also included in the raven sources as an example.

```shell
sudo su
cd raven/models/2net

# grab the source code required for this model and set the mapping environment variables
source fetch.sh

# build the raven system (creates virtual machines and network descriptions)
rvn build

# deploy the virtual system
rvn deploy

# show the status of the virtual nodes
rvn status

# wait for the virtual nodes and switches to come up
rvn pingwait control walrus nimbus n0 n1

# show the status of the virtual nodes now that they are up (you will see IP addresses)
rvn status

# configure the virtual nodes and switches
rvn configure

# while configure is running, you can open up another shell window and type in
# rvn status to see how things are progressing

# run some ad-hoc config on a node
rvn ansible n1 config/n1.yml

# ssh into a node
eval $(rvn ssh walrus)
```

This particular model assumes that we have the following code repositories in a top level directory called `/space`. The `fetch.sh` script referenced above will do this for you.

- **walrustf** - [github.com/rcgoodfellow/walrustf](https://github.com/rcgoodfellow/walrustf)
- **agx** - [github.com/rcgoodfellow/agx](https://github.com/rcgoodfellow/agx)
- **netlink** - [github.com/rcgoodfellow/netlink](https://github.com/rcgoodfellow/netlink)
- **switch-drivers** - [github.com/deter-project/switch-drivers](https://github.com/deter-project/switch-drivers)

You will need to clone these projects into `/space` for this tutorial to work.

Go through the following sequence to bring up the environment.
- **push** - create a definition of the system in the virtualization back end
- **launch** - materialize the system
- **configure** - configure the nodes and switches in the model

Once these steps complete we will be in a position to test the system!

#### Testing

The testing we are going to show here for the VLAN management system, tests that connectivity between the two nodes `n0` and `n1` can be effectively managed by the controlling agent via the implementation agent. We are using the [walrus testing framework](https://github.com/rcgoodfellow/walrustf). The first part of the test is the test definition file. This is a JSON file that defines the tests that we are going to run. Here is a snippet from the [actual test file](https://github.com/rcgoodfellow/raven/blob/master/models/2net/config/files/walrus/test.yml) in the Raven project.

```json
[    
  {
    "launch": "ansible-playbook test.yml --tags vpath-create",
    "name": "vpath-create",
    "timeout": 3600,
    "success": [
      {"status": "ok", "who": "n0", "message": "ping-success"},
      {"status": "ok", "who": "n1", "message": "ping-success"}
    ],
    "fail": [
      {"status": "error", "who": "*", "message": "*"}
    ]
  }
]
```

Each test has:

- **launch command** - typically an Ansible playbook
- **name**
- **timeout** - in seconds
- **success criteria** - 3 valued tuple containing
  + **status**: a diagnostic level that is one of `[error, warning, ok]`
  + **who**: the participant within the distributed system that produced the message
  + **message**: a diagnostic string
- **failure criteria** - same format as success criteria

When all of the success criteria are observable by the test runner, the test is considered to be a success. If any of the failure criteria are observable by the test runner, the test is considered to have failed. Collectively each triple is referred to as a test diagnostic. Diagnostics are visible to the test runner when it can see them in the Walrus collector. A collector is simply a [Redis](https://redis.io) database with a few [associated conventions](https://github.com/rcgoodfellow/walrustf/blob/master/doc/dspec.md) to support the Walrus test semantics. The Walrus test framework comes with a test runner called [wtf](https://github.com/rcgoodfellow/walrustf/blob/master/wtf/wtf.go) that is used to run tests. Just point it at you test JSON file and let it run. The output looks like this

<img src="https://mirror.deterlab.net/rvn/doc/walrus-out.png" style="width:50%" class="center-image" />

WalrusTF adopts a driver model when it comes to language support. Right now there are drivers for C, Python, Perl and Bash. Contributions for other new languages are always welcome! The test we are working with now uses the Bash driver on the `n0` and `n1` nodes. The [code](https://github.com/rcgoodfellow/raven/blob/master/models/2net/config/files/node/pingtest.sh) is very simple, it just tries to ping some node repeatedly on a 1 second interval. If the ping is successful, an `ok` diagnostic is sent to walrus with the hostname of the participant running the test. If the ping is not successful a `warning` diagnostic is sent.

```shell
echo "starting ping test"
trap "exit" INT
while true; do
  ping -q -w 1 $target &> /dev/null
  if [[ "$?" -ne 0 ]]; then
    $wtf walrus warning $testid $hostname 0 ping-failed
    printf ". "
  else
    $wtf walrus ok $testid $hostname 0 ping-success
    printf "+"
  fi
  i=$((i+1))
done
```

In concert with the [ansible test launch script](https://github.com/rcgoodfellow/raven/blob/master/models/2net/config/files/walrus/test.yml), the walrus test definition script now asses whether or not the VLAN control system is doing its job by attempting to create and then destroy virtual network paths between `n0` and `n1` and observing the results of the ping tests. The walrus test definition wraps all this up in an automated easy to launch and observe test case.

## GLHF

What we have shown here today is a way to rapidly model, materialize and enter the code-build-test cycle for distributed systems.

<img src="https://mirror.deterlab.net/rvn/doc/codable-env.png" class="center-image" style="width: 90%" />

Please check out the [raven](https://github.com/rcgoodfellow/raven) and [walrustf](https://github.com/rcgoodfellow/walrus) projects and try them out for your own distributed systems engineering problems. Contributions and comments welcome. 
