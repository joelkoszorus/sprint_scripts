# Sprint 5 — Ansible Automated Deployment of HealthMon

## Project Overview

Sprint 5 takes the **HealthMon** system-health monitoring tool built in Sprint 4
and automates its provisioning and deployment across multiple AWS Linux servers
using **Ansible**. Instead of configuring each host by hand, a single control
node manages both servers through two idempotent playbooks:

- **`configure.yml`** — prepares a fresh server for production (packages, a
  dedicated service account, timezone, SSH hardening, and logging).
- **`deploy.yml`** — deploys the Sprint 4 monitoring scripts, installs their
  Python dependencies, sets permissions, and schedules them via cron.

Running the same playbook twice produces changes only on the first run and
**zero changes** on the second, demonstrating full idempotency.

## Architecture

```
                +------------------------+
                |     Control Node       |
                |  (Ansible installed)   |
                |  inventory.ini         |
                |  configure.yml         |
                |  deploy.yml            |
                +-----------+------------+
                            | SSH (key-based)
            +---------------+----------------+
            |                                |
   +--------v---------+            +---------v--------+
   |   AWS Server 1   |            |   AWS Server 2   |
   |   (server1)      |            |   (server2)      |
   |  HealthMon +     |            |  HealthMon +     |
   |  cron schedule   |            |  cron schedule   |
   +------------------+            +------------------+
```

- **Control node** — runs Ansible and holds the playbooks and inventory. It
  connects to both managed servers over SSH using a private key.
- **AWS server 1 (`server1`)** — managed target; receives the full
  configuration and HealthMon deployment.
- **AWS server 2 (`server2`)** — identical managed target. Both hosts belong to
  the `aws_servers` group so every play targets both at once.

## Files

| File            | Purpose                                                                 |
|-----------------|-------------------------------------------------------------------------|
| `inventory.ini` | Defines the `aws_servers` group, host IPs, and the SSH connection user. |
| `configure.yml` | Baseline server hardening and preparation playbook.                     |
| `deploy.yml`    | Deploys the HealthMon scripts, dependencies, and cron schedule.         |
| `README.md`     | This document.                                                          |

The Sprint 4 source files (`healthmon.py`, `config.json`) are read from the
neighboring `../sprint4/` directory by `deploy.yml` via the `source_dir`
variable.

## Prerequisites

- **Ansible** installed on the control node (`ansible --version`), including the
  `community.general` collection used by the `timezone` module:
  ```bash
  ansible-galaxy collection install community.general
  ```
- **SSH key access** from the control node to both servers. Verify with:
  ```bash
  ansible all -i inventory.ini -m ping
  ```
- **Python 3** present on the managed hosts (default on Ubuntu/Amazon Linux).

## Inventory Setup

Edit `inventory.ini` and replace the placeholders with your real values:

```ini
[servers]
linux1 ansible_host=172.31.26.210 ansible_connection=local
linux2 ansible_host=172.31.26.22 ansible_user=ubuntu

[servers:vars]
ansible_ssh_private_key_file=~/.ssh/id_ed25519
ansible_python_interpreter=/usr/bin/python3
```

Use `ansible_user=ubuntu` for Ubuntu AMIs or `ansible_user=ec2-user` for
Amazon Linux.

## Running the Playbooks

Run the configuration playbook first, then the deployment playbook:

```bash
ansible-playbook -i inventory.ini configure.yml

ansible-playbook -i inventory.ini deploy.yml
```

## Idempotency Demonstration

Both playbooks are written to be fully idempotent.

**First run** — Ansible applies the desired state; tasks report `changed`:

```
PLAY RECAP *********************************************************************
server1 : ok=10  changed=8  unreachable=0  failed=0
server2 : ok=10  changed=8  unreachable=0  failed=0
```

**Second run** — the state already matches, so every task reports `ok` and
nothing changes:

```
PLAY RECAP *********************************************************************
server1 : ok=10  changed=0  unreachable=0  failed=0
server2 : ok=10  changed=0  unreachable=0  failed=0
```

> **Screenshots:** Insert your first-run and second-run `PLAY RECAP` screenshots
> here for both `configure.yml` and `deploy.yml`.
>
> - _configure.yml — first run (changed > 0):_ **[screenshot here]**
> - _configure.yml — second run (changed = 0):_ **[screenshot here]**
> - _deploy.yml — first run (changed > 0):_ **[screenshot here]**
> - _deploy.yml — second run (changed = 0):_ **[screenshot here]**

## Verification

After running both playbooks, confirm the results on a managed host
(`ssh ubuntu@<server-ip>`):

```bash
# Service account exists
getent passwd healthmon

# rsyslog is enabled and running
systemctl status rsyslog

# Cron job is installed for the healthmon user
sudo crontab -l -u healthmon

# Deployment files were copied with correct ownership/permissions
ls -l /opt/healthmon /opt/healthmon/config
```

You can also re-run the playbooks with `--check --diff` to preview state without
making changes:

```bash
ansible-playbook -i inventory.ini deploy.yml --check --diff
```

## Troubleshooting

| Symptom                                   | Likely cause / fix                                                                 |
|-------------------------------------------|------------------------------------------------------------------------------------|
| `UNREACHABLE` / SSH timeout               | Wrong IP, security group blocking port 22, or wrong key. Check `inventory.ini`.    |
| `Permission denied (publickey)`           | Wrong `ansible_user` or `ansible_ssh_private_key_file`. Verify key permissions `600`. |
| `Missing sudo password`                   | Add `--ask-become-pass` or configure passwordless sudo for the SSH user.           |
| `couldn't resolve module timezone`        | Install the collection: `ansible-galaxy collection install community.general`.     |
| `pip3: command not found`                 | Run `configure.yml` first — it installs `python3-pip`.                             |
| SSH hardening locked you out              | Confirm your public key is in `~/.ssh/authorized_keys` **before** disabling password auth. The `sshd -t` validation prevents writing a broken config. |
| Cron job not running                      | Check `/opt/healthmon/logs/cron.log` and `sudo crontab -l -u healthmon`.            |