# Copyright (c) 2015, PLUMgrid Inc, http://plumgrid.com

# This file contains functions used by the hooks to deploy PLUMgrid Director.

import pg_dir_context
import subprocess
import time
import os
import platform
import json
from collections import OrderedDict
from socket import gethostname as get_unit_hostname
from copy import deepcopy
from charmhelpers.contrib.openstack.neutron import neutron_plugin_attribute
from charmhelpers.contrib.openstack import templating
from charmhelpers.contrib.storage.linux.ceph import modprobe
from charmhelpers.core.hookenv import (
    log,
    config,
    unit_get,
    network_get_primary_address,
    status_set
)
from charmhelpers.contrib.network.ip import (
    get_iface_from_addr,
    get_bridges,
    get_bridge_nics,
    is_ip,
    get_iface_addr,
    get_host_ip
)
from charmhelpers.core.host import (
    service_start,
    service_stop,
    service_running,
    path_hash,
    set_nic_mtu,
    lsb_release
)
from charmhelpers.fetch import (
    apt_cache,
    apt_install
)
from charmhelpers.contrib.openstack.utils import (
    os_release,
)
from pg_dir_context import (
    _pg_dir_ips,
    _pg_edge_ips,
    _pg_gateway_ips
)

SOURCES_LIST = '/etc/apt/sources.list'
TEMPLATES = 'templates/'
PG_DATA_PATH = '/var/lib/plumgrid/plumgrid-data'
# TODO: this path should be updated once SOL-1261 is resolved
# workaround: shouldn't set plumgrid-license-key via config
# it will fail
PG_LXC_PATH = '/var/lib/libvirt/filesystems/plumgrid'
PG_CONF = '%s/conf/pg/plumgrid.conf' % PG_DATA_PATH
PG_KA_CONF = '%s/conf/etc/keepalived.conf' % PG_DATA_PATH
PG_DEF_CONF = '%s/conf/pg/nginx.conf' % PG_DATA_PATH
PG_HN_CONF = '%s/conf/etc/hostname' % PG_DATA_PATH
PG_HS_CONF = '%s/conf/etc/hosts' % PG_DATA_PATH
PG_IFCS_CONF = '%s/conf/pg/ifcs.conf' % PG_DATA_PATH
OPS_CONF = '%s/conf/etc/00-pg.conf' % PG_DATA_PATH
AUTH_KEY_PATH = '%s/root/.ssh/authorized_keys' % PG_DATA_PATH
TEMP_LICENSE_FILE = '/tmp/license'
IFC_LIST_GW = '/var/run/plumgrid/ifc_list_gateway'

BASE_RESOURCE_MAP = OrderedDict([
    (PG_KA_CONF, {
        'services': ['plumgrid'],
        'contexts': [pg_dir_context.PGDirContext()],
    }),
    (PG_CONF, {
        'services': ['plumgrid'],
        'contexts': [pg_dir_context.PGDirContext()],
    }),
    (PG_DEF_CONF, {
        'services': ['plumgrid'],
        'contexts': [pg_dir_context.PGDirContext()],
    }),
    (PG_HN_CONF, {
        'services': ['plumgrid'],
        'contexts': [pg_dir_context.PGDirContext()],
    }),
    (PG_HS_CONF, {
        'services': ['plumgrid'],
        'contexts': [pg_dir_context.PGDirContext()],
    }),
    (OPS_CONF, {
        'services': ['plumgrid'],
        'contexts': [pg_dir_context.PGDirContext()],
    }),
    (PG_IFCS_CONF, {
        'services': [],
        'contexts': [pg_dir_context.PGDirContext()],
    }),
])

PG_DOCKERS = [
    'plumgrid-util',
    'plumgrid-logger',
    'plumgrid-core',
    'plumgrid-sal',
    'plumgrid'
]


def configure_pg_sources():
    '''
    Returns true if install sources is updated in sources.list file
    '''
    try:
        with open(SOURCES_LIST, 'r+') as sources:
            all_lines = sources.readlines()
            sources.seek(0)
            for i in (line for line in all_lines if "plumgrid" not in line):
                sources.write(i)
            sources.truncate()
        sources.close()
    except IOError:
        log('Unable to update /etc/apt/sources.list')


def determine_packages():
    '''
    Returns list of packages required by PLUMgrid director as specified
    in the neutron_plugins dictionary in charmhelpers.
    '''
    pkgs = []
    tag = 'latest'
    for pkg in neutron_plugin_attribute('plumgrid', 'packages', 'neutron'):
        if 'plumgrid' in pkg:
            tag = config('plumgrid-build')
        elif pkg == 'iovisor-dkms':
            tag = config('iovisor-build')

        if tag == 'latest':
            pkgs.append(pkg)
        else:
            if tag in [i.ver_str for i in apt_cache()[pkg].version_list]:
                pkgs.append('%s=%s' % (pkg, tag))
            else:
                error_msg = \
                    "Build version '%s' for package '%s' not available" \
                    % (tag, pkg)
                raise ValueError(error_msg)
    return pkgs


def get_unit_address(binding='internal'):
    '''
    Returns the unit's PLUMgrid Management/Fabric IP
    '''
    try:
        # Using Juju 2.0 network spaces feature
        return network_get_primary_address(binding)
    except NotImplementedError:
        # Falling back to private-address
        return get_host_ip(unit_get('private-address'))


def docker_dependencies():
    '''
    Returns a list of packages to be installed for docker engine
    '''
    kver = platform.release()
    return ['apt-transport-https', 'ca-certificates', 'apparmor',
            'linux-image-extra-{}'.format(kver)]


def docker_configure_sources():
    '''
    Imports GPG key and updates apt source for docker engine
    '''
    ubuntu_rel = lsb_release()['DISTRIB_CODENAME']
    DOCKER_SOURCE = ('deb https://apt.dockerproject.org/repo ubuntu-%s'
                     ' main')
    log('Importing GPG Key for docker engine')
    _exec_cmd(['apt-key', 'adv', '--keyserver',
               'hkp://p80.pool.sks-keyservers.net:80',
               '--recv-keys', '58118E89F3A912897C070ADBF76221572C52609D'])
    try:
        with open('/etc/apt/sources.list.d/docker.list', 'w') as f:
            f.write(DOCKER_SOURCE % ubuntu_rel)
        f.close()
    except:
        raise ValueError('Unable to update /etc/apt/sources.list.d/'
                         'docker.list')


def register_configs(release=None):
    '''
    Returns an object of the Openstack Tempating Class which contains the
    the context required for all templates of this charm.
    '''
    release = release or os_release('neutron-common', base='kilo')
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)
    for cfg, rscs in resource_map().iteritems():
        configs.register(cfg, rscs['contexts'])
    return configs


def resource_map():
    '''
    Dynamically generate a map of resources that will be managed for a single
    hook execution.
    '''
    resource_map = deepcopy(BASE_RESOURCE_MAP)
    return resource_map


def restart_map():
    '''
    Constructs a restart map based on charm config settings and relation
    state.
    '''
    return {cfg: rscs['services'] for cfg, rscs in resource_map().iteritems()}


def restart_pg():
    '''
    Stops and Starts PLUMgrid service after flushing iptables.
    '''
    stop_pg()
    start_pg()
    status, service = service_running_pg()
    if not status:
        if service_running('docker'):
            raise ValueError("{} service couldn't be started!".format(service))
        else:
            if service_start('docker'):
                time.sleep(8)
                start_pg()
                status, service = service_running_pg()
                if not status:
                    status_set('blocked', '{} service not \
                               not running'.format(service))
                    raise ValueError("{} service couldn't \
                                     be started!".format(service))
            else:
                status_set('blocked', 'docker service not running')
                raise ValueError("docker service couldn't be started!")
    status_set('active', 'Unit is ready')


def stop_pg():
    '''
    Stops PLUMgrid services.
    '''
    for service in PG_DOCKERS:
        service_stop(service)
    time.sleep(5)


def start_pg():
    '''
    Starts PLUMgrid services.
    '''
    for service in PG_DOCKERS:
        service_start(service)
    time.sleep(5)


def service_running_pg():
    '''
    Returns a tuple comrising of status code '0' and PLUMgrid service
    name that is stopped. Else it will return 1 as a status code and 1
    in place of service name to maintain consistency in return values
    '''
    for service in PG_DOCKERS:
        if not service_running(service):
            return 0, service
    return 1, 1


def load_iovisor():
    '''
    Loads iovisor kernel module.
    '''
    modprobe('iovisor')


def remove_iovisor():
    '''
    Removes iovisor kernel module.
    '''
    _exec_cmd(cmd=['rmmod', 'iovisor'],
              error_msg='Error Removing IOVisor Kernel Module')
    time.sleep(1)


def interface_exists(interface):
    '''
    Checks if interface exists on node.
    '''
    try:
        subprocess.check_call(['ip', 'link', 'show', interface],
                              stdout=open(os.devnull, 'w'),
                              stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        return False
    return True


def get_mgmt_interface():
    '''
    Returns the managment interface.
    '''
    mgmt_interface = config('mgmt-interface')
    if not mgmt_interface:
        try:
            return get_iface_from_addr(get_unit_address('internal'))
        except:
            # workaroud if get_unit_address returns hostname
            # also workaround the curtin issue where the
            # interface on which bridge is created also gets
            # an ip
            for bridge_interface in get_bridges():
                if (get_unit_address()
                        in get_iface_addr(bridge_interface)):
                    return bridge_interface
    elif interface_exists(mgmt_interface):
        return mgmt_interface
    else:
        log('Provided managment interface %s does not exist'
            % mgmt_interface)
        return get_iface_from_addr(get_unit_address())


def fabric_interface_changed():
    '''
    Returns true if interface for node changed.
    '''
    fabric_interface = get_fabric_interface()
    try:
        with open(PG_IFCS_CONF, 'r') as ifcs:
            for line in ifcs:
                if 'fabric_core' in line:
                    if line.split()[0] == fabric_interface:
                        return False
    except IOError:
        return True
    return True


def remove_ifc_list():
    '''
    Removes ifc_list_gateway file if fabric interface is changed
    '''
    _exec_cmd(cmd=['rm', '-f', IFC_LIST_GW])


def get_fabric_interface():
    '''
    Returns the fabric interface.
    '''
    fabric_interfaces = config('fabric-interfaces')
    if not fabric_interfaces:
        try:
            fabric_ip = get_unit_address('compute-data')
            mgmt_ip = get_unit_address('internal')
        except:
            raise ValueError('Unable to get interface using \'fabric\' \
                              binding! Ensure fabric interface has IP \
                              assigned.')
        if fabric_ip == mgmt_ip:
            return get_mgmt_interface()
        else:
            return get_iface_from_addr(fabric_ip)
    else:
        try:
            all_fabric_interfaces = json.loads(fabric_interfaces)
        except ValueError:
            raise ValueError('Invalid json provided for fabric interfaces')
    hostname = get_unit_hostname()
    if hostname in all_fabric_interfaces:
        node_fabric_interface = all_fabric_interfaces[hostname]
    elif 'DEFAULT' in all_fabric_interfaces:
        node_fabric_interface = all_fabric_interfaces['DEFAULT']
    else:
        raise ValueError('No fabric interface provided for node')
    if interface_exists(node_fabric_interface):
        return node_fabric_interface
    else:
        log('Provided fabric interface %s does not exist'
            % node_fabric_interface)
        raise ValueError('Provided fabric interface does not exist')
    return node_fabric_interface


def ensure_mtu():
    '''
    Ensures required MTU of the underlying networking of the node.
    '''
    interface_mtu = config('network-device-mtu')
    fabric_interface = get_fabric_interface()
    if fabric_interface in get_bridges():
        attached_interfaces = get_bridge_nics(fabric_interface)
        for interface in attached_interfaces:
            set_nic_mtu(interface, interface_mtu)
    set_nic_mtu(fabric_interface, interface_mtu)


def _exec_cmd(cmd=None, error_msg='Command exited with ERRORs', fatal=False):
    '''
    Function to execute any bash command on the node.
    '''
    if cmd is None:
        log("No command specified")
    else:
        if fatal:
            subprocess.check_call(cmd)
        else:
            try:
                subprocess.check_call(cmd)
            except subprocess.CalledProcessError:
                log(error_msg)


def add_lcm_key():
    '''
    Adds public key of PLUMgrid-lcm to authorized keys of PLUMgrid Director.
    '''
    key = config('lcm-ssh-key')
    if key == 'null':
        log('lcm key not specified')
        return 0
    file_write_type = 'w+'
    if os.path.isfile(AUTH_KEY_PATH):
        file_write_type = 'a'
        try:
            fr = open(AUTH_KEY_PATH, 'r')
        except IOError:
            log('plumgrid-lxc not installed yet')
            return 0
        for line in fr:
            if key in line:
                log('key already added')
                return 0
    try:
        fa = open(AUTH_KEY_PATH, file_write_type)
    except IOError:
        log('Error opening file to append')
        return 0
    fa.write(key)
    fa.write('\n')
    fa.close()
    return 1


def post_pg_license():
    '''
    Posts PLUMgrid License if it hasnt been posted already.
    '''
    key = config('plumgrid-license-key')
    if key is None:
        log('PLUMgrid License Key not specified')
        return 0
    PG_VIP = config('plumgrid-virtual-ip')
    if not is_ip(PG_VIP):
        raise ValueError('Invalid IP Provided')
    LICENSE_POST_PATH = 'https://%s/0/tenant_manager/license_key' % PG_VIP
    LICENSE_GET_PATH = 'https://%s/0/tenant_manager/licenses' % PG_VIP
    PG_CURL = '%s/opt/pg/scripts/pg_curl.sh' % PG_LXC_PATH
    license = {"key1": {"license": key}}
    licence_post_cmd = [
        PG_CURL,
        '-u',
        'plumgrid:plumgrid',
        LICENSE_POST_PATH,
        '-d',
        json.dumps(license)]
    licence_get_cmd = [PG_CURL, '-u', 'plumgrid:plumgrid', LICENSE_GET_PATH]
    try:
        old_license = subprocess.check_output(licence_get_cmd)
    except subprocess.CalledProcessError:
        log('No response from specified virtual IP')
        return 0
    _exec_cmd(cmd=licence_post_cmd,
              error_msg='Unable to post License', fatal=False)
    new_license = subprocess.check_output(licence_get_cmd)
    if old_license == new_license:
        log('No change in PLUMgrid License')
        return 0
    return 1


def sapi_post_ips():
    """
    Posts PLUMgrid nodes IPs to solutions api server.
    """
    if not config('enable-sapi'):
        log('Solutions API support is disabled!')
        return 1
    pg_edge_ips = _pg_edge_ips()
    pg_dir_ips = _pg_dir_ips()
    pg_gateway_ips = _pg_gateway_ips()
    pg_dir_ips.append(get_unit_address())
    pg_edge_ips = '"edge_ips"' + ':' \
        + '"{}"'.format(','.join(str(i) for i in pg_edge_ips))
    pg_dir_ips = '"director_ips"' + ':' \
        + '"{}"'.format(','.join(str(i) for i in pg_dir_ips))
    pg_gateway_ips = '"gateway_ips"' + ':' \
        + '"{}"'.format(','.join(str(i) for i in pg_gateway_ips))
    opsvm_ip = '"opsvm_ip"' + ':' + '"{}"'.format(config('opsvm-ip'))
    virtual_ip = '"virtual_ip"' + ':' \
        + '"{}"'.format(config('plumgrid-virtual-ip'))
    JSON_IPS = ','.join([pg_dir_ips, pg_edge_ips, pg_gateway_ips,
                        opsvm_ip, virtual_ip])
    status = (
        'curl -H \'Content-Type: application/json\' -X '
        'PUT -d \'{{{0}}}\' http://{1}' + ':' + '{2}/v1/zones/{3}/allIps'
    ).format(JSON_IPS, config('lcm-ip'), config('sapi-port'),
             config('sapi-zone'))
    POST_ZONE_IPs = _exec_cmd_output(
        status,
        'Posting Zone IPs to Solutions API server failed!')
    if POST_ZONE_IPs:
        if 'success' in POST_ZONE_IPs:
            log('Successfully posted Zone IPs to Solutions API server!')
        log(POST_ZONE_IPs)


def _exec_cmd_output(cmd=None, error_msg='Command exited with ERRORs',
                     fatal=False):
    '''
    Function to get output from bash command executed on the node.
    '''
    if cmd is None:
        log("No command specified")
    else:
        if fatal:
            return subprocess.check_output(cmd, shell=True)
        else:
            try:
                return subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError:
                log(error_msg)
                return None


def sapi_post_license():
    '''
    Posts PLUMgrid License to solutions api server
    '''
    if not config('enable-sapi'):
        log('Solutions API support is disabled!')
        return 1
    username = '"user_name":' + '"{}"'.format(config('plumgrid-username'))
    password = '"password":' + '"{}"'.format(config('plumgrid-password'))
    license = '"license":' + '"{}"'.format(config('plumgrid-license-key'))
    JSON_LICENSE = ','.join([username, password, license])
    status = (
        'curl -H \'Content-Type: application/json\' -X '
        'PUT -d \'{{{0}}}\' http://{1}' + ':' + '{2}/v1/zones/{3}/pgLicense'
    ).format(JSON_LICENSE, config('lcm-ip'), config('sapi-port'),
             config('sapi-zone'))
    POST_LICENSE = _exec_cmd_output(
        status,
        'Posting PLUMgrid License to Solutions API server failed!')
    if POST_LICENSE:
        if 'success' in POST_LICENSE:
            log('Successfully posted license file for zone "{}"!'
                .format(config('sapi-zone')))
        log(POST_LICENSE)


def get_pg_ons_version():
    '''
    Returns PG ONS version installed
    '''
    package_version = ''
    for pkg in neutron_plugin_attribute('plumgrid', 'packages', 'neutron'):
        if 'plumgrid' in pkg:
            try:
                # Fetch plumgrid package version installed. If there are
                # multiple plumgrid packages installed, first package will
                # be used to fetch the version
                package_version = apt_cache()[pkg].current_ver.ver_str
                break
            except:
                log('Unable to find the installed package: {}. Posting Zone \
                     Info to Solutions API server will fail.'.format(pkg))
                return None
    return package_version.replace('-', '.', 1).split('-')[0]


def sapi_post_zone_info():
    '''
    Posts zone information to solutions api server
    '''
    if not config('enable-sapi'):
        log('Solutions API support is disabled!')
        return 1
    sol_name = '"solution_name":"Ubuntu OpenStack"'
    # As there is no solution version in Canonical OpenStack,
    # setting its value to release number of distribution
    sol_version = lsb_release()['DISTRIB_RELEASE']
    sol_version = '"solution_version":"{}"'.format(sol_version)
    pg_ons_version = get_pg_ons_version()
    pg_ons_version = \
        '"pg_ons_version":"{}"'.format(pg_ons_version)
    hypervisor = '"hypervisor":"Ubuntu"'
    hypervisor_version = lsb_release()['DISTRIB_RELEASE']
    hypervisor_version = '"hypervisor_version":"{}"' \
                         .format(hypervisor_version)
    kernel_version = platform.release()
    kernel_version = \
        '"kernel_version":"{}"'.format(kernel_version)
    pg_cloudapex_version = 'docker exec -t plumgrid-util /usr/bin/dpkg '\
        + '-l | grep plumgrid-cloud | awk ' \
        + '\'{print $3}\' | tr \'-\' \' \' | awk \'{print $1}\''
    pg_cloudapex_version = \
        _exec_cmd_output(pg_cloudapex_version,
                         'Unable to retrieve CloudApex version'
                         ).replace('\n', '')
    if not pg_cloudapex_version:
        log('CloudApex not installed!')
    pg_cloudapex_version = \
        '"pg_cloudapex_version":"{}"'.format(pg_cloudapex_version)
    JSON_ZONE_INFO = ','.join([
        sol_name,
        sol_version,
        pg_ons_version,
        hypervisor,
        hypervisor_version,
        kernel_version,
        pg_cloudapex_version,
    ])
    status = (
        'curl -H \'Content-Type: application/json\' -X '
        'PUT -d \'{{{0}}}\' http://{1}:{2}/v1/zones/{3}/zoneinfo'
    ).format(JSON_ZONE_INFO, config('lcm-ip'), config('sapi-port'),
             config('sapi-zone'))
    POST_ZONE_INFO = _exec_cmd_output(
        status,
        'Posting Zone Information to Solutions API server failed!')
    if POST_ZONE_INFO:
        if 'success' in POST_ZONE_INFO:
            log('Successfully posted Zone information to Solutions API'
                ' server!')
        log(POST_ZONE_INFO)


def load_iptables():
    '''
    Loads iptables rules to allow all PLUMgrid communication.
    '''
    network = get_cidr_from_iface(get_mgmt_interface())
    if network:
        _exec_cmd(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp',
                   '-j', 'ACCEPT', '-s', network, '-d',
                   network, '-m', 'state', '--state', 'NEW'])
        _exec_cmd(['sudo', 'iptables', '-A', 'INPUT', '-p', 'udp', '-j',
                   'ACCEPT', '-s', network, '-d', network,
                   '-m', 'state', '--state', 'NEW'])
        _exec_cmd(['sudo', 'iptables', '-I', 'INPUT', '-s', network,
                   '-d', '224.0.0.18/32', '-j', 'ACCEPT'])
    _exec_cmd(['sudo', 'iptables', '-I', 'INPUT', '-p', 'vrrp', '-j',
               'ACCEPT'])
    _exec_cmd(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '-j',
               'ACCEPT', '-d', config('plumgrid-virtual-ip'), '-m',
               'state', '--state', 'NEW'])
    apt_install('iptables-persistent')


def get_cidr_from_iface(interface):
    '''
    Determines Network CIDR from interface.
    '''
    if not interface:
        return None
    apt_install('ohai')
    try:
        os_info = subprocess.check_output(['ohai', '-l', 'fatal'])
    except OSError:
        log('Unable to get operating system information')
        return None
    try:
        os_info_json = json.loads(os_info)
    except ValueError:
        log('Unable to determine network')
        return None
    device = os_info_json['network']['interfaces'].get(interface)
    if device is not None:
        if device.get('routes'):
            routes = device['routes']
            for net in routes:
                if 'scope' in net:
                    return net.get('destination')
        else:
            return None
    else:
        return None


def director_cluster_ready():
    dirs_count = len(pg_dir_context._pg_dir_ips())
    return True if dirs_count == 2 else False


def restart_on_change(restart_map):
    """
    Restart services based on configuration files changing
    """
    def wrap(f):
        def wrapped_f(*args, **kwargs):
            checksums = {path: path_hash(path) for path in restart_map}
            f(*args, **kwargs)
            for path in restart_map:
                if path_hash(path) != checksums[path]:
                    restart_pg()
                    break
        return wrapped_f
    return wrap
