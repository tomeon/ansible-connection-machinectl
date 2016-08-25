# Inspired by, but since deviated entirely from, the nsenter connection by
# Tomohiro NAKAMURA
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
import os
import pwd
import re
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

    def __init__(self, machinectl_command=None):
        if machinectl_command is not None:
            self.machinectl_cmd = kwargs['machinectl_command']
        else:
            self.machinectl_cmd = distutils.spawn.find_executable('machinectl')
            if not self.machinectl_cmd:
                raise AnsibleError('machinectl command not found in PATH')

    @staticmethod
    def _match_machine_name(line):
        ''' See `man machinectl', section "Machine and Image Names"
            Machine names may contain alphanumeric characters and dashes.
            TODO can the first or last character be a dash?
        '''
        matched = re.match(r'([\w-]+(?:\.[\w-]+)*)', line)
        if matched is not None:
            return (matched.groups())[0]

    @classmethod
    def machinectl_env(cls, **kwargs):
        ''' Copy the current environment, merging keyword arguments and setting
            the systemd log level
        '''
        return dict(merge_hash(os.environ, kwargs), SYSTEMD_LOG_LEVEL=cls.SYSTEMD_LOG_LEVEL)

    def property(self, wanted, machine=None):
        for prop, value in self.show(machine, '--property={0}'.format(wanted)):
            if wanted == prop:
                return value

    def build_command(self, action, args=[], machine=None):
        if action not in self.MACHINECTL_ALLOWED_COMMANDS:
            raise AnsibleError('{0} is not a valid machinectl command'.format(cmd))

        local_cmd = [self.machinectl_cmd, action]
        if machine is not None:
            local_cmd.append(machine)

        return local_cmd + args

    def run_command(self, action, args=[], machine=None, in_data=None, sudoable=False):
        ''' run a command on the machine '''

        # TODO handle flags -- see
        # https://github.com/systemd/systemd/issues/2420
        machinectl_env = self.machinectl_env()
        local_cmd = self.build_command(action, args, machine)

        display.vvv(u'EXEC {0}'.format(local_cmd,), host=(machine or 'NONE'))

        local_cmd = [to_bytes(i, errors='strict') for i in local_cmd]

        display.debug(u'Opening command with Popen()')

        # TODO why can't we set stdin to a pipe?
        p = subprocess.Popen(local_cmd, env=machinectl_env, shell=False,
                             stdin=None, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        stdout, stderr = p.communicate(in_data)

        display.debug(u'Done running command with Popen()')

        return (p.returncode, stdout, stderr)

    def list(self):
        ''' Returns a list of machine names '''
        list_args = ['list', '--no-legend']
        returncode, stdout, stderr = self.run_command('list', ['--no-legend'])

        for i in stdout.strip().splitlines():
            yield re.split(r'\s+', i, 3)

    def show(self, machine=None, *args):
        ''' Yields machine properties in key-value pairs '''
        returncode, stdout, stderr = self.run_command('show', [], machine)

        for line in stdout.splitlines():
            yield line.strip().split('=', 2)


class Connection(ConnectionBase):

    transport = 'machinectl'
    has_pipelining = False

    def __init__(self, play_context, new_stdin, *args, **kwargs):
        super(Connection, self).__init__(play_context, new_stdin, *args, **kwargs)

        if (not (self._play_context.become and self._play_context.become_user == 'root') and os.geteuid() != 0):
            raise errors.AnsibleError('machinectl connection requires running as root or become')

        self.machinectl = MachineCtl(kwargs.get('machinectl_command'))

    def _connect(self):
        ''' Connection ain't real '''
        super(Connection, self)._connect()

        if not self._connected:
            self.machine = self._play_context.remote_addr

            display.vvv(u'ESTABLISH MACHINECTL CONNECTION FOR USER: {0}'.format(
                self._play_context.remote_user or '?'), host=self.machine
            )

            if self.machinectl.property('State', self.machine) != 'running':
                raise AnsibleError('machine {0} is not running'.format(self.machine))

            display.vvv(u'MACHINE RUNNING FROM HOST DIRECTORY {0}'.format(
                self.machinectl.property('RootDirectory', self.machine)), host=self.machine
            )

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

    def exec_command(self, cmd, in_data=None, sudoable=False):
        super(Connection, self).exec_command(cmd, in_data=in_data, sudoable=sudoable)

        local_cmd = shlex.split(cmd)

        if self._play_context.become:
            try:
                become_uid = pwd.getpwnam(self._play_context.become_user)
                display.vvv(u'BECOME {0} (uid {1})'.format(self._play_context.become_user, become_uid))
                local_cmd = ['--uid={0}'.format(become_uid)] + local_cmd
            except KeyError:
                raise AnsibleError('become failed: failed to look up user {0}'.format(self._play_context.become_user))

        return self.machinectl.run_command('shell', shlex.split(cmd), self.machine, in_data=in_data, sudoable=sudoable)

    def put_file(self, in_path, out_path):
        # TODO error handling
        super(Connection, self).put_file(in_path, out_path)
        display.vvv(u'PUT {0} TO {1}'.format(in_path, out_path), host=self.machine)

        out_path = self._prefix_login_path(out_path)
        if not os.path.exists(to_bytes(in_path, errors='strict')):
            raise AnsibleFileNotFound('file or module does not exist: {0}'.format(in_path))

        returncode, stdout, stderr = self.machinectl.run_command('copy-to', [in_path, out_path], self.machine)

        if returncode != 0:
            raise AnsibleError('failed to transfer file {0} to {1}:\n{2}\n{3}'.format(in_path, out_path, stdout, stderr))

    def fetch_file(self, in_path, out_path):
        # TODO error handling
        super(Connection, self).put_file(in_path, out_path)
        display.vvv(u'FETCH {0} TO {1}'.format(in_path, out_path), host=self.machine)

        in_path = self._prefix_login_path(in_path)

        self.machinectl.run_command('copy-from', [in_path, out_path], self.machine)
