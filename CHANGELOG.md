# Changelog for `tomeon.ansible_connection_machinectl`

## [Unreleased]

### Added

- Docker build assets and [dobi](https://github.com/dnephin/dobi) build
  specification.
- Vagrant setup that mimics a stripped-down Travis build environment.
- tox-based testing setup for running tests against multiple versions of Python
  and Ansible.
- Add `machined_config` structure to hostvars, representing the output of
  `machinectl show`.
- Tests for file transfer and deletion, and for command execution.

### Changed

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
