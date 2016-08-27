# Inspired by, but since deviated entirely from, the nsenter connection plugin
# (c) 2015, Tomohiro NAKAMURA <quickness.net@gmail.com>
# Permalink: https://github.com/jptomo/ansible-connection-nsenter/blob/4ab713b061c92eaf2553a5c826cd26266e932b09/nsenter.py
#
# The polling loop in Connection.exec_command was adapted from local.py
# (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
# (c) 2015 Toshio Kuratomi <tkuratomi@ansible.com>
# Permalink: https://github.com/ansible/ansible/blob/a9d5bf717c200126c46433de1a833f2dd34397f6/lib/ansible/plugins/connection/ssh.py#L332-L340
#
# The pty.getpty() code in Connection.exec_command was adapated from ssh.py
# (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
# Copyright 2015 Abhijit Menon-Sen <ams@2ndQuadrant.com>
# Permalink: https://github.com/ansible/ansible/blob/a9d5bf717c200126c46433de1a833f2dd34397f6/lib/ansible/plugins/connection/ssh.py#L332-L340
#
# Connection plugin for machinectl virtual machines and containers
# (c) 2016, Matt Schreiber <schreibah@gmail.com>
#
# machinectl is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import distutils.spawn
import fcntl
import os
import pty
import pwd
import re
import select
import shlex
import subprocess

from ansible.errors import AnsibleError
from ansible.plugins.connection import ConnectionBase
from ansible.utils.vars import merge_hash
from ansible.utils.unicode import to_bytes

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display
    display = Display()


class MachineCtl(object):

    MACHINECTL_ALLOWED_COMMANDS = frozenset([
        'list',
        'status',
        'show',
        'login',
        'shell',
        'kill',
        'copy-to',
        'copy-from',
        'bind'
    ])

    # Suppress some diagnostic info that is not relevant when running
    # non-interactively.  This is one notch below the default 'info' level; see
    # `man 1 systemd'.
    SYSTEMD_LOG_LEVEL = 'notice'


    # Prior to version 230, `machinectl' consumed all flags in the `shell'
    # invocation, including those intended for the executed command.  See:
    # https://github.com/systemd/systemd/issues/2420
    MACHINECTL_GETOPT_FIX_VERSION = '230'

    def __init__(self, machinectl_command=None, **kwargs):
        if machinectl_command is not None:
            self.machinectl_cmd = kwargs['machinectl_command']
        else:
            self.machinectl_cmd = distutils.spawn.find_executable('machinectl')
            if not self.machinectl_cmd:
                raise AnsibleError('machinectl command not found in PATH')

        self.machinectl_version = self._machinectl_version()

    @classmethod
    def machinectl_env(cls, **kwargs):
        ''' Copy the current environment, merging keyword arguments and setting
            the systemd log level
        '''
        return dict(merge_hash(os.environ, kwargs), SYSTEMD_LOG_LEVEL=cls.SYSTEMD_LOG_LEVEL)

    def _machinectl_version(self):
        try:
            machinectl_version_output = subprocess.check_output([self.machinectl_cmd, '--version'])
            matched = re.match(r'\Asystemd\s+(\d+)\D', machinectl_version_output)
            return (matched.groups())[0]
        except subprocess.CalledProcessError as e:
            raise AnsibleError('failed to retrieve machinectl version: {0}'.format(e.message))

    def property(self, wanted, machine=None):
        for prop, value in self.show(machine, '--property={0}'.format(wanted)):
            if wanted == prop:
                return value

    def build_command(self, action, machinectl_flags=[], args=[], machine=None):
        if action not in self.MACHINECTL_ALLOWED_COMMANDS:
            raise AnsibleError('{0} is not a valid machinectl command'.format(cmd))

        local_cmd = [self.machinectl_cmd] + machinectl_flags + [action]
        if machine is not None:
            local_cmd.append(machine)
        if self.machinectl_version < self.MACHINECTL_GETOPT_FIX_VERSION:
            local_cmd.append('--')

        return local_cmd + args

    def popen_command(self, action, machinectl_flags=[], args=[], machine=None, **kwargs):
        ''' run a command on the machine '''

        machinectl_env = self.machinectl_env()
        local_cmd = self.build_command(action, machinectl_flags=machinectl_flags, args=args, machine=machine)

        display.vvv(u'EXEC {0}'.format(local_cmd,), host=(machine or 'NONE'))

        local_cmd = [to_bytes(i, errors='strict') for i in local_cmd]

        stdin = kwargs.get('stdin', None)
        stdout = kwargs.get('stdout', subprocess.PIPE)
        stderr = kwargs.get('stderr', subprocess.PIPE)

        # TODO why can't we set stdin to a pipe?
        return subprocess.Popen(local_cmd, env=machinectl_env, shell=False,
                                stdin=stdin, stdout=stdout, stderr=stderr)

    def run_command(self, action, machinectl_flags=[], args=[], machine=None, in_data=None):
        p = self.popen_command(action, machinectl_flags=machinectl_flags, args=args, machine=machine)
        stdout, stderr = p.communicate(in_data)
        return (p.returncode, stdout, stderr)

    def list(self):
        ''' Returns a list of machine names '''
        returncode, stdout, stderr = self.run_command('list', machinectl_flags=['--no-legend'])

        for i in stdout.strip().splitlines():
            yield re.split(r'\s+', i, 3)

    def show(self, machine=None, *args):
        ''' Yields machine properties in key-value pairs '''
        returncode, stdout, stderr = self.run_command('show', machine=machine)

        for line in stdout.splitlines():
            yield line.strip().split('=', 2)


class Connection(ConnectionBase):
    ''' Local connection based on systemd's machinectl.
        Supports "become", but handles this via the --uid option.
    '''

    transport = 'machinectl'
    has_pipelining = True

    def __init__(self, play_context, new_stdin, *args, **kwargs):
        super(Connection, self).__init__(play_context, new_stdin, *args, **kwargs)

        if os.geteuid() != 0:
            raise errors.AnsibleError('machinectl connection requires running as root')

        self.machinectl = MachineCtl(kwargs.get('machinectl_command'))
        self.remote_uid = None
        self.remote_gid = None

    def _parse_passwd(self, entry):
        if entry is None:
            return entry
        return entry.split(':')

    def _remote_passwd(self, user, passwd_path=None):
        if user is None:
            user = self._play_context.remote_user

        if user is None:
            return

        for getent in ['/bin/getent', '/usr/bin/getent']:
            try:
                returncode, stdout, stderr = self._run_command('shell', args=[getent, 'passwd', user])
            except AnsibleError:
                pass

            if returncode == 0:
                return self._parse_passwd(stdout)

        try:
            if passwd_path is None:
                passwd_path = os.path.join(self.chroot, 'etc/passwd')

            with open(passwd_path, 'r') as passwdf:
                for entry in passwdf.readlines():
                    parsed = self._parse_entry()
                    if parsed[0] == self._play_context.remote_user:
                        return parsed
        except IOError:
            pass

    def _connect(self):
        ''' Connection ain't real '''
        super(Connection, self)._connect()

        if not self._connected:
            self.machine = self._play_context.remote_addr

            display.vvv(u'ESTABLISH MACHINECTL VERSION {0} CONNECTION FOR USER: {1}'.format(
                self.machinectl.machinectl_version,
                self._play_context.remote_user or '?'), host=self.machine
            )

            if self.machinectl.property('State', self.machine) != 'running':
                raise AnsibleError('machine {0} is not running'.format(self.machine))

            self.chroot = self.machinectl.property('RootDirectory', self.machine)

            if self._play_context.remote_user is not None:
                self.chown_files = True

                remote_passwd = self._remote_passwd(self._play_context.remote_user)
                if remote_passwd is not None:
                    self.remote_uid = int(remote_passwd[2])
                    self.remote_gid = int(remote_passwd[3] or -1)
                else:
                    raise AnsibleError('Failed to find UID or GID for {0}'.format(self._play_context.remote_user))
            else:
                self.chown_files = False

            display.vvv(u'UID: {0} GID: {1}'.format(self.remote_uid, self.remote_gid), host=self.machine)

            display.vvv(u'MACHINE RUNNING FROM HOST DIRECTORY {0}'.format(self.chroot), host=self.machine)

            self._connected = True

    def close(self):
        ''' Again, connection ain't real '''
        super(Connection, self).close()
        self._connected = False

    def _prefix_login_path(self, remote_path):
        ''' Make sure that we put files into a standard path

            If a path is relative, then we need to choose where to put it.
            ssh chooses $HOME but we aren't guaranteed that a home dir will
            exist in any given chroot.  So for now we're choosing "/" instead.
            This also happens to be the former default.

            Can revisit using $HOME instead if it's a problem
        '''
        if not remote_path.startswith(os.path.sep):
            remote_path = os.path.join(os.path.sep, remote_path)

        return os.path.normpath(remote_path)

    def _popen_command(self, action, machinectl_flags=[], args=[], machine=None, **kwargs):
        machinectl_flags = []

        if self.remote_uid is not None:
            display.vvv(u'RUN AS {0} (UID {1})'.format(self._play_context.remote_user, self.remote_uid))
            machinectl_flags = ['--uid={0}'.format(self.remote_uid)]

        return self.machinectl.popen_command(action, machinectl_flags=machinectl_flags, args=args, machine=self.machine, **kwargs)


    def _run_command(self, action, machinectl_flags=[], args=[], machine=None, in_data=None):
        p = self._popen_command(action, machinectl_flags=machinectl_flags, args=args, machine=machine)

        stdout, stderr = p.communicate(in_data)

        return (p.returncode, stdout, stderr)

    def exec_command(self, cmd, in_data=None, sudoable=False):
        super(Connection, self).exec_command(cmd, in_data=in_data, sudoable=sudoable)

        master, slave = pty.openpty()
        p = self._popen_command('shell', args=shlex.split(cmd), machine=self.machine, stdin=slave)
        os.close(slave)
        stdin = os.fdopen(master, 'w', 0)

        if self._play_context.prompt and sudoable:
            fcntl.fcntl(p.stdout, fcntl.F_SETFL, fcntl.fcntl(p.stdout, fcntl.F_GETFL) | os.O_NONBLOCK)
            fcntl.fcntl(p.stderr, fcntl.F_SETFL, fcntl.fcntl(p.stderr, fcntl.F_GETFL) | os.O_NONBLOCK)
            become_output = ''
            while not self.check_become_success(become_output) and not self.check_password_prompt(become_output):

                rfd, wfd, efd = select.select([p.stdout, p.stderr], [], [p.stdout, p.stderr], self._play_context.timeout)
                if p.stdout in rfd:
                    chunk = p.stdout.read()
                elif p.stderr in rfd:
                    chunk = p.stderr.read()
                else:
                    stdout, stderr = p.communicate()
                    raise AnsibleError('timeout waiting for privilege escalation password prompt:\n' + become_output)
                if not chunk:
                    stdout, stderr = p.communicate()
                    raise AnsibleError('privilege output closed while waiting for password prompt:\n' + become_output)
                become_output += chunk
            if not self.check_become_success(become_output):
                stdin.write(self._play_context.become_pass + '\n')
            fcntl.fcntl(p.stdout, fcntl.F_SETFL, fcntl.fcntl(p.stdout, fcntl.F_GETFL) & ~os.O_NONBLOCK)
            fcntl.fcntl(p.stderr, fcntl.F_SETFL, fcntl.fcntl(p.stderr, fcntl.F_GETFL) & ~os.O_NONBLOCK)

        display.debug("getting output with communicate()")
        stdout, stderr = p.communicate(in_data)
        display.debug("done communicating")

        display.debug("done with local.exec_command()")
        return (p.returncode, stdout, stderr)

    def put_file(self, in_path, out_path):
        super(Connection, self).put_file(in_path, out_path)
        display.vvv(u'PUT {0} TO {1}'.format(in_path, out_path), host=self.machine)

        # Set file permissions prior to transfer so that they will be correct
        # on the container
        try:
            if self.remote_uid is not None:
                os.chown(in_path, self.remote_uid, self.remote_gid or -1)
        except OSError:
            raise AnsibleError('failed to change ownership on file {0} to user {1}'.format(in_path, self._play_context.remote_user))

        out_path = self._prefix_login_path(out_path)
        if not os.path.exists(to_bytes(in_path, errors='strict')):
            raise AnsibleFileNotFound('file or module does not exist: {0}'.format(in_path))

        returncode, stdout, stderr = self._run_command('copy-to', args=[in_path, out_path], machine=self.machine)

        if returncode != 0:
            raise AnsibleError('failed to transfer file {0} to {1}:\n{2}\n{3}'.format(in_path, out_path, stdout, stderr))


    def fetch_file(self, in_path, out_path):
        super(Connection, self).put_file(in_path, out_path)
        display.vvv(u'FETCH {0} TO {1}'.format(in_path, out_path), host=self.machine)

        in_path = self._prefix_login_path(in_path)

        returncode, stdout, stderr = self._run_command('copy-from', args=[in_path, out_path], machine=self.machine)

        if returncode != 0:
            raise AnsibleError('failed to transfer file {0} from {1}:\n{2}\n{3}'.format(out_path, in_path, stdout, stderr))

        # TODO might not be necessary?
        # Reset file permissions to current user after transferring from
        # container
        try:
            if self.remote_uid is not None:
                os.chown(out_path, os.geteuid(), os.getegid() or -1)
        except OSError:
            raise AnsibleError('failed to change ownership on file {0} to user {1}'.format(out_path, os.getlogin()))
