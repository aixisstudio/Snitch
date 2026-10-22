# Snitch — Puppet module skeleton (community maintained, help wanted)
# EN: Same three primitives as the Ansible role — deploy the backend
#     tree, render /etc/snitch/snitch.toml, manage snitch.service.
#     Extend with Hiera keys (snitch::syslog_addr, snitch::peers…) as
#     your fleet needs; PRs welcome.
# FR: Mêmes trois primitives que le rôle Ansible — déployer le backend,
#     rendre /etc/snitch/snitch.toml, gérer snitch.service. Étendre avec
#     des clés Hiera selon la flotte ; PR bienvenues.
class snitch (
  String  $install_dir   = '/opt/snitch',
  String  $config_dir    = '/etc/snitch',
  String  $user          = 'snitch',
  Boolean $manage_service = true,
) {
  user { $user:
    ensure     => present,
    system     => true,
    managehome => false,
    shell      => '/usr/sbin/nologin',
  }

  file { [$install_dir, "${install_dir}/backend", $config_dir,
          '/var/lib/snitch']:
    ensure => directory,
  }

  # EN: Push the checked-out backend/ tree (or swap for a release tarball
  #     via the `source` param of your file resource / an archive module).
  # FR: Pousser l'arbre backend/ (ou un tarball de release via `source`).
  file { "${install_dir}/backend":
    ensure  => directory,
    source  => 'puppet:///modules/snitch/backend',
    recurse => true,
    owner   => 'root',
    group   => $user,
    mode    => '0644',
  }

  file { "${config_dir}/snitch.toml":
    ensure  => file,
    content => template('snitch/snitch.toml.erb'),
    owner   => 'root',
    group   => $user,
    mode    => '0640',
    notify  => Service['snitch'],
  }

  file { '/etc/systemd/system/snitch.service':
    ensure => file,
    source => 'puppet:///modules/snitch/snitch.service',
    mode   => '0644',
    notify => Exec['systemd-reload'],
  }

  exec { 'systemd-reload':
    command     => '/bin/systemctl daemon-reload',
    refreshonly => true,
  }

  if $manage_service {
    service { 'snitch':
      ensure    => running,
      enable    => true,
      subscribe => [File['/etc/systemd/system/snitch.service'],
                    File["${config_dir}/snitch.toml"]],
    }
  }
}
