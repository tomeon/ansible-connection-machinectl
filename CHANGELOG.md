# Changelog for `tomeon.ansible_connection_machinectl`

## [Unreleased]

### Added

- GitHub Actions CI, running directly on GitHub's Ubuntu 22.04, 24.04 and
  26.04 runners (x86-64 and arm64) against ansible-core 2.16 through 2.22.
  Guests are Debian 12 and 13, Ubuntu 22.04, 24.04 and 26.04, the latest
  Fedora, AlmaLinux 9 and 10, openSUSE Leap 16 and Tumbleweed, and Arch Linux
  (x86-64 only). (#6)
- Scripts for building guest images from distribution container images, and
  for importing and booting them.
- tox-based testing setup for running tests against multiple versions of
  ansible-core.
- Add `machined_config` structure to hostvars, representing the output of
  `machinectl show`.
- Tests for file transfer and deletion, and for command execution.

### Changed

- Locate `machinectl` with `shutil.which` instead of
  `distutils.spawn.find_executable`, as `distutils` is gone as of Python 3.12.
- Import `to_bytes` and `to_native` from
  `ansible.module_utils.common.text.converters` when available, as
  `ansible.module_utils._text` is deprecated in ansible-core 2.22.

- Expand `ansible-galaxy`-based installation instructions, explicitly
  mentioning the "role" name. (#5)
- Account for restructuring of Ansible's text-handling libraries by tring to
  import `to_bytes` and `to_native` from `ansible.module_utils._text`, falling
  back to importing `to_bytes` and `to_str` from `ansible.utils.unicode` (and
  aliasing `to_str` to `to_native`). (#4)
- Open `machinectl` connection's standard input in binary mode and convert data
  read from standard output and standard error to the correct native Python
  representation via the `to_native` function. (#4)
- Don't limit the number of fields returned by `str.split` when parsing the
  output of `machinectl list`.
- Place per-container hostvars under `machine_config` key, representing the
  output of `machinectl show <container>`.
- Properly extract hostvars for named host when running dynamic inventory with
  the `--host` flag.

### Fixed

- Raise `AnsibleFileNotFound` (which was used but not imported) when the file
  passed to `put_file` does not exist.
- Report failures to query the `machinectl` version on Python 3, where
  `CalledProcessError` has no `message` attribute.
- Run `machinectl shell` with `TERM=dumb`, so that guests running systemd 258
  or later don't prefix command output with OSC 3008 context sequences when
  the host's `machinectl` passes them through (e.g. systemd 255).

### Removed

- Travis CI configuration, Docker images, [dobi](https://github.com/dnephin/dobi)
  build specification, Vagrant setup and mkosi configuration, all of which
  existed to run `systemd` inside a privileged Docker container. (#6)
