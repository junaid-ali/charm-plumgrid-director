
# About the PLUMgrid Platform

The [PLUMgrid Platform](http://www.plumgrid.com/technology/plumgrid-platform/) is a software-only solution that provides a rich set of distributed network functions such as routers, switches, NAT, IPAM, DHCP, and it also supports security policies, end-to-end encryption, and third party Layer 4-7 service insertion.

## About Plumgrid Director

The Director is the brain of the PLUMgrid Platform. It is responsible for coordinating and managing all the other platform components. Based on PLUMgrid's distributed system architecture, it provides built-in high availability and scaling. The Director allows you to create Virtual Domains on a per tenant or application basis.


# Overview

Once deployed this charm performs the configurations required for a PLUMgrid Director and starts the essential services on the node.


# Usage

Instructions on using the charm:

    juju deploy neutron-api
    juju deploy neutron-api-plumgrid
    juju deploy plumgrid-director

    juju add-relation neutron-api neutron-api-plumgrid

For plumgrid-director to work make the configuration in the neutron-api and neutron-api-plumgrid charms as specified in the configuration section below.

# Configuration

Example Config

    plumgrid-director:
        plumgrid-virtual-ip: "192.168.100.250"
        install_sources: 'ppa:plumgrid-team/stable'
        install_keys: 'null'
    neutron-api-plumgrid:
        install_sources: 'ppa:plumgrid-team/stable'
        install_keys: 'null'
        enable-metadata: True
        manage-neutron-plugin-legacy-mode: True

Provide the virtual IP you want PLUMgrid GUI to be accessible.
Make sure that it is the same IP specified in the neutron-api charm configuration for PLUMgrid.
The virtual IP passed on in the neutron-api charm has to be same as the one passed in the plumgrid-director charm.
Provide the source repo path for PLUMgrid Debs in 'install_sources' and the corresponding keys in 'install_keys'.

You can access the PG Console at https://192.168.100.250

In order to configure networking, PLUMgrid License needs to be posted.

    juju set plumgrid-director plumgrid-license-key="$LICENSE_KEY"

#Network Space support

This charm supports the use of Juju Network Spaces, allowing the charm to be bound to network space configurations managed directly by Juju.  This is only supported with Juju 2.0 and above.

To use this feature, use the --bind option when deploying the charm:

    juju deploy plumgrid-director --bind "internal=internal-space fabric=fabric-space"

alternatively these can also be provided as part of a juju native bundle configuration:

    plumgrid-director:
      charm: cs:plumgrid-director
      num_units: 1
      bindings:
        internal: internal-space
        fabric: fabric-space

NOTE: Spaces must be configured in the underlying provider prior to attempting to use them. 'internal' binding is mapped onto OpenStack internal-api endpoint while 'fabric' is mapped to OpenStack tenant-data-api endpoint.

# Contact Information

Bilal Baqar <bbaqar@plumgrid.com>
Javeria Khan <javeriak@plumgrid.com>
Junaid Ali <junaidali@plumgrid.com>
