# Snitch — SaltStack state skeleton (community maintained, help wanted)
# EN: Same three primitives — user, tree + venv, snitch.toml, unit.
#     Pillar keys: snitch:syslog_addr, snitch:peers, …
# FR: Mêmes trois primitives — utilisateur, arbre + venv, snitch.toml,
#     unité. Clés pillar : snitch:syslog_addr, snitch:peers, …

snitch-user:
  user.present:
    - name: snitch
    - system: True
    - createhome: False
    - shell: /usr/sbin/nologin

snitch-dirs:
  file.directory:
    - names:
      - /opt/snitch
      - /etc/snitch
      - /var/lib/snitch
    - require:
      - user: snitch-user

snitch-backend:
  file.recurse:
    - name: /opt/snitch/backend
    - source: salt://snitch/backend
    - dir_mode: "0755"
    - file_mode: "0644"
    - require:
      - file: snitch-dirs

snitch-venv:
  virtualenv.managed:
    - name: /opt/snitch/backend/env
    - requirements: /opt/snitch/backend/requirements.txt
    - require:
      - file: snitch-backend

snitch-config:
  file.managed:
    - name: /etc/snitch/snitch.toml
    - source: salt://snitch/files/snitch.toml.jinja
    - template: jinja
    - mode: "0640"
    - user: root
    - group: snitch
    - watch_in:
      - service: snitch-service

snitch-unit:
  file.managed:
    - name: /etc/systemd/system/snitch.service
    - source: salt://snitch/files/snitch.service
    - mode: "0644"
    - require:
      - file: snitch-dirs
  module.run:
    - name: service.systemctl_reload
    - onchanges:
      - file: snitch-unit

snitch-service:
  service.running:
    - name: snitch
    - enable: True
    - require:
      - virtualenv: snitch-venv
      - file: snitch-config
      - module: snitch-unit
