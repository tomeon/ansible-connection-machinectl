#!/usr/bin/env python2

from subprocess import Popen, PIPE
import os
import pprint

def pipeit(cmd, data=None):
    #env = dict(os.environ, SYSTEMD_LOG_LEVEL='notice')
    p = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate(data)
    return (p.returncode, stdout, stderr)

def systemd_run(machine, cmd, data=None):
    full_cmd = ['systemd-run', '-M', machine, '--pty', '--quiet'] + cmd
    pprint.pprint(full_cmd)
    return pipeit(full_cmd, data)

def machinectl_shell(machine, cmd, data=None):
    full_cmd = ['machinectl', 'shell', machine]
    pprint.pprint(full_cmd)
    return pipeit(full_cmd, data)

if __name__ == '__main__':
    pprint.pprint(machinectl_shell('archlinux-ansible', ['/bin/sh', '-c', 'echo HELLO']))
    pprint.pprint(systemd_run('archlinux-ansible', ['/bin/sh', '-c', 'echo HELLO']))
    pprint.pprint(Popen(['systemd-run', '-M', 'archlinux-ansible', '--pty', '--quiet', '/bin/sh', '-c', 'echo WAT DA EFFING EFF'], shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE).communicate())
