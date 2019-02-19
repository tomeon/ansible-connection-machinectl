unless Vagrant.has_plugin? 'vagrant-sshfs'
  abort 'Plugins must be enabled and the vagrant-sshfs plugin must be installed.'
end

$docker_host ||= '0.0.0.0'
$docker_port ||= 6379

$docker_forwarded_host ||= '127.0.0.1'
$docker_forwarded_port ||= 63790

$host_to_docker_daemon_conf ||= {
  trusty: {
    'hosts' => [
      "tcp://#{$docker_host}:#{$docker_port}",
      'unix://'
    ],
    'storage-driver' => 'devicemapper'
  },
  xenial: {
    'storage-driver' => 'overlay2'
  },
}

Vagrant.configure(2) do |config|
  $host_to_docker_daemon_conf.sort.each_with_index do |(ubuntu_release, docker_daemon_conf), i|
    config.vm.define ubuntu_release do |ubuntu|
      ubuntu.vm.box = "ubuntu/#{ubuntu_release}64"

      ubuntu.vm.provider :virtualbox do |v|
        v.memory = 2048
      end

      ubuntu.vm.synced_folder '.', '/vagrant', disabled: true

      # Installs docker; does nothing else
      ubuntu.vm.provision :docker do |d|
        d.post_install_provision 'configure-docker', type: :shell do |s|
          require 'json'
          s.args = [JSON.pretty_generate(docker_daemon_conf)]
          s.path = 'scripts/configure-docker'
        end
      end

      ubuntu.vm.network :forwarded_port, guest: $docker_port, host: $docker_forwarded_port + i, host_ip: $docker_forwarded_host
    end

    config.vm.define "#{ubuntu_release}-builder" do |fedora|
      fedora.vm.synced_folder '.', '/vagrant', type: 'sshfs'

      fedora.vm.provider :docker do |d|
        d.image               = 'tomeon/fedora-mkosi:29-vagrant'
        d.cmd                 = %w[/usr/sbin/init]
        d.create_args         = %w[
                                  --cap-add SYS_ADMIN
                                  --tmpfs /run:exec
                                  --tmpfs /tmp:exec
                                  -v /sys/fs/cgroup:/sys/fs/cgroup:ro
                                ]
        d.force_host_vm       = true
        d.privileged          = true
        d.has_ssh             = true
        d.remains_running     = true
        d.vagrant_machine     = ubuntu_release
        d.vagrant_vagrantfile = __FILE__
      end

      fedora.vm.provision 'test-make-hardlinks', type: :shell do |s|
        s.path = 'scripts/test-make-hardlinks'
        s.args = %w[/vagrant]
      end

      fedora.vm.provision 'wait-is-system-running', type: :shell do |s|
        s.path = 'scripts/wait-is-system-running'
      end

      fedora.vm.provision 'resize-machine-btrfs-partition', type: :shell do |s|
        s.path       = 'scripts/resize-machine-btrfs-partition'
        s.privileged = true
      end

      fedora.vm.provision 'build-images', type: :shell, run: :never do |s|
        s.path       = 'scripts/build-images'
        s.args       = %w[-a --checksum]
        s.privileged = true
      end

      fedora.vm.provision 'download-images', type: :shell do |s|
        mkosi_files  = Pathname.new('mkosi/mkosi.files').expand_path(__dir__).children(false)
        images       = mkosi_files.map(&:to_s).select { |d| d.start_with? 'mkosi.' }.map { |d| d.sub('mkosi.', '') }
        s.path       = 'scripts/download-images'
        s.args       = images
        s.privileged = true
      end

      fedora.vm.provision 'spawn-containers', type: :shell do |s|
        s.path       = 'scripts/spawn-containers'
        s.privileged = true
      end

      fedora.vm.provision 'run-tests', type: :shell, run: :never do |s|
        s.path       = 'scripts/run-tests'
        s.args       = '/vagrant'
        s.privileged = true
      end
    end
  end
end
