Ansible Connection Plugin - `machinectl`
========================================

Ansible plugin that uses `systemd`'s
[`machinectl`](https://www.freedesktop.org/software/systemd/man/machinectl.html)
to communicate with virtual machines and containers managed by
[`systemd-machined`](https://www.freedesktop.org/software/systemd/man/systemd-machined.service.html).

Requirements
------------

This plugin relies on `machinectl`'s `shell` subcommand, which was introduced
in `systemd` version 225; see the [release
notes](https://github.com/systemd/systemd/blob/master/NEWS#L1233-L1241)
([permalink](https://github.com/systemd/systemd/blob/3dea75dead5d3b229c9780de63479ea0aa655ba5/NEWS#L1233-L1241)).

Installation
------------

This plugin can be installed by running `ansible-galaxy install
tomeon.ansible_connection_machinectl`, or by directly cloning this repository.
You will need to move
[`connection_plugins/machinectl.py`](connection_plugins/machinectl.py) into one
of the `connection_plugins` directories configured in your `ansible.cfg`.

Connection Variables
--------------------

None at the moment.

Example Usage
-------------

Simply pass the `-c`|`--connection=` option to Ansible along with the machine
name.  Given the machine `ansible-nspawn` (in a typical setup, this would refer
to a chroot located at `/var/lib/machines/ansible-nspawn`):

```sh
$ ansible -c machinectl -m setup ansible-nspawn
archlinux-ansible | SUCCESS => {
    "ansible_facts": {
        # <snip>
        "ansible_virtualization_type": "systemd-nspawn",
        # <snip>
    },
    "changed": false
}
```

Caveats
-------

`machinectl` requires superuser privileges when running the `shell` subcommand.
There's no straightforward way to piggyback on Ansible's `become` logic, as
this would mean distinguishing between whether the user wants to (1) acquire
superuser privileges on the control machine, or (2) acquire superuser
privileges within the target machine.

For the moment, this means that Ansible must be run with superuser privileges
in order to use this connection type.  The plan is to add connection
configuration parameters for specifying the local user and their password when
running `machinectl`; at the moment, do:

```sh
# Preserve your environment when escalating privileges
$ sudo -E ansible -c machinectl -m setup <target-machine>
```

License
-------

BSD
