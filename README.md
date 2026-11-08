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

Known issues
------------

- AlmaLinux 9 guests do not work when the host runs systemd 255 (as on
  Ubuntu 24.04): commands succeed, but none of their output reaches the host,
  so Ansible cannot read module results.  The same guests work with systemd
  249 (Ubuntu 22.04) and 259 (Ubuntu 26.04) on the host.  The likely cause is
  that systemd-machined 255 sets `TTYPath=` on the guest's shell unit, and
  that the guest's systemd resets (and thereby flushes) that terminal when the
  unit stops, before the host has read the output.  The tests skip this
  combination.
- With systemd 249 on the host (as on Ubuntu 22.04), a command occasionally
  fails with `Failed to get shell PTY: Unit container-shell@N.service already
  exists`.  systemd-machined names the guest's shell unit after its terminal
  number, and the previous unit of that name had not yet been cleaned up.
  Running the task again works.  In CI this has only happened with Ubuntu
  22.04 guests, about once in 14 jobs, so the tests skip that combination.

Testing
-------

The integration tests in [`tests/test.yml`](tests/test.yml) run against
`systemd-nspawn` guests built from distribution container images, using the
dynamic inventory in [`contrib/inventory`](contrib/inventory).  Running them
needs a host booted with `systemd` that has `machinectl` and `systemd-nspawn`
(the `systemd-container` package on Debian and Ubuntu), Docker with BuildKit
(only for building guest images), and [tox](https://tox.wiki/) with
[tox-uv](https://github.com/tox-dev/tox-uv).  With
[GNU parallel](https://www.gnu.org/software/parallel/) or
[moreutils](https://joeyh.name/code/moreutils/)' `parallel` installed, the
guests are built and imported in parallel; otherwise one after another.

```sh
# Build a root filesystem tarball for each guest in tests/guests/images
$ scripts/build-guest-images ./guests

# Import and boot the guests, run the tests in one tox environment (see
# `tox list`) or all of them, then remove the guests again
$ sudo env "PATH=$PATH" scripts/run-tests ./guests -e py314-ansible221
```

`scripts/run-tests` imports the guests under names unique to the run (e.g.
`debian-12-1a2b3c4d`), and the tests target only those, so other machines on
the host are left alone.  When the run ends, whether or not the tests pass,
it stops and removes the guests; set `KEEP_GUESTS=1` to keep them for
inspection, and remove them later with `sudo scripts/remove-guests RUN_ID`.
On hosts with systemd older than 255, it also adds per-guest settings under
`/run` (see `scripts/import-guest-images`), which are removed along with the
guests.

[CI](.github/workflows/ci.yml) does the same on GitHub's Ubuntu 22.04, 24.04
and 26.04 runners, on both x86-64 and arm64, for ansible-core 2.16 through
2.22.

License
-------

BSD
