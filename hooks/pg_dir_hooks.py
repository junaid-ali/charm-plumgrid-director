#!/usr/bin/python

# Copyright (c) 2015, PLUMgrid Inc, http://plumgrid.com

# The hooks of this charm have been symlinked to functions
# in this file.

import sys
import time
from charmhelpers.core.host import service_running
from charmhelpers.contrib.network.ip import is_ip

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    log,
    config,
    relation_set,
    relation_ids
)

from charmhelpers.fetch import (
    apt_install,
    configure_sources,
)

from pg_dir_utils import (
    register_configs,
    restart_pg,
    restart_map,
    stop_pg,
    determine_packages,
    load_iovisor,
    remove_iovisor,
    ensure_mtu,
    add_lcm_key,
    post_pg_license,
    fabric_interface_changed,
    load_iptables,
    restart_on_change,
    director_cluster_ready
)

hooks = Hooks()
CONFIGS = register_configs()


@hooks.hook()
def install():
    '''
    Install hook is run when the charm is first deployed on a node.
    '''
    load_iptables()
    configure_sources(update=True)
    pkgs = determine_packages()
    for pkg in pkgs:
        apt_install(pkg, options=['--force-yes'], fatal=True)
    load_iovisor()
    ensure_mtu()
    CONFIGS.write_all()


@hooks.hook('director-relation-joined')
@restart_on_change(restart_map())
def dir_joined():
    '''
    This hook is run when a unit of director is added.
    '''
    if director_cluster_ready():
        ensure_mtu()
        CONFIGS.write_all()


@hooks.hook('plumgrid-relation-joined')
def plumgrid_joined(relation_id=None):
    '''
    This hook is run when relation with edge or gateway is created.
    '''
    opsvm_ip = config('opsvm-ip')
    if not is_ip(opsvm_ip):
        raise ValueError('Incorrect OPSVM IP specified')
    else:
        relation_set(relation_id=relation_id, opsvm_ip=opsvm_ip)


@hooks.hook('config-changed')
def config_changed():
    '''
    This hook is run when a config parameter is changed.
    It also runs on node reboot.
    '''
    charm_config = config()
    if charm_config.changed('lcm-ssh-key'):
        if add_lcm_key():
            log("PLUMgrid LCM Key added")
    if charm_config.changed('plumgrid-license-key'):
        if post_pg_license():
            log("PLUMgrid License Posted")
    if charm_config.changed('fabric-interfaces'):
        if not fabric_interface_changed():
            log("Fabric interface already set")
        else:
            stop_pg()
    if charm_config.changed('plumgrid-virtual-ip'):
        CONFIGS.write_all()
        stop_pg()
    if (charm_config.changed('install_sources') or
        charm_config.changed('plumgrid-build') or
        charm_config.changed('install_keys') or
            charm_config.changed('iovisor-build')):
        stop_pg()
        configure_sources(update=True)
        pkgs = determine_packages()
        for pkg in pkgs:
            apt_install(pkg, options=['--force-yes'], fatal=True)
            remove_iovisor()
            load_iovisor()
    if charm_config.changed('opsvm-ip'):
        for rid in relation_ids('plumgrid'):
            plumgrid_joined(rid)
        stop_pg()
    ensure_mtu()
    CONFIGS.write_all()
    if not service_running('plumgrid'):
        restart_pg()


@hooks.hook('start')
def start():
    '''
    This hook is run when the charm is started.
    '''
    if config('plumgrid-license-key') is not None:
        count = 0
        while (count < 10):
            if post_pg_license():
                break
            count += 1
            time.sleep(15)


@hooks.hook('upgrade-charm')
@restart_on_change(restart_map())
def upgrade_charm():
    '''
    This hook is run when the charm is upgraded
    '''
    ensure_mtu()
    CONFIGS.write_all()


@hooks.hook('stop')
def stop():
    '''
    This hook is run when the charm is destroyed.
    '''
    stop_pg()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
