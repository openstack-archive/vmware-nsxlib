# Copyright 2017 VMware, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import abc

import six

from vmware_nsxlib.v3 import utils

from vmware_nsxlib.v3.policy import constants

TENANTS_PATH_PATTERN = "%s/"
DOMAINS_PATH_PATTERN = TENANTS_PATH_PATTERN + "domains/"
IP_BLOCKS_PATH_PATTERN = TENANTS_PATH_PATTERN + "ip-blocks/"
IP_POOLS_PATH_PATTERN = TENANTS_PATH_PATTERN + "ip-pools/"
SEGMENTS_PATH_PATTERN = TENANTS_PATH_PATTERN + "segments/"
PROVIDERS_PATH_PATTERN = TENANTS_PATH_PATTERN + "providers/"
TIER0S_PATH_PATTERN = TENANTS_PATH_PATTERN + "tier-0s/"
TIER1S_PATH_PATTERN = TENANTS_PATH_PATTERN + "tier-1s/"
SERVICES_PATH_PATTERN = TENANTS_PATH_PATTERN + "services/"
ENFORCEMENT_POINT_PATTERN = (TENANTS_PATH_PATTERN +
                             "sites/default/enforcement-points/")
TRANSPORT_ZONE_PATTERN = ENFORCEMENT_POINT_PATTERN + "%s/transport-zones/"
EDGE_CLUSTER_PATTERN = ENFORCEMENT_POINT_PATTERN + "%s/edge-clusters/"

SEGMENT_SECURITY_PROFILES_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                                          "segment-security-profiles/")
QOS_PROFILES_PATH_PATTERN = TENANTS_PATH_PATTERN + "qos-profiles/"
SPOOFGUARD_PROFILES_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                                    "spoofguard-profiles/")
IP_DISCOVERY_PROFILES_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                                      "ip-discovery-profiles/")
MAC_DISCOVERY_PROFILES_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                                       "mac-discovery-profiles/")
IPV6_NDRA_PROFILES_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                                   "ipv6-ndra-profiles/")
WAF_PROFILES_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                             "waf-profiles/")
CERTIFICATE_PATH_PATTERN = TENANTS_PATH_PATTERN + "certificates/"
EXCLUDE_LIST_PATH_PATTERN = (TENANTS_PATH_PATTERN +
                             "settings/firewall/security/exclude-list")

REALIZATION_PATH = "infra/realized-state/realized-entities?intent_path=%s"
DHCP_REALY_PATTERN = TENANTS_PATH_PATTERN + "dhcp-relay-configs/"


@six.add_metaclass(abc.ABCMeta)
class ResourceDef(object):
    def __init__(self, **kwargs):
        self.attrs = kwargs

        # init default tenant
        self.attrs['tenant'] = self.get_tenant()

        self.body = {}

        # As of now, for some defs (ex: services) child entry is required,
        # meaning parent creation will fail without the child.
        # Unfortunately in transactional API policy still fails us, even if
        # child is specified as ChildEntry in same transaction.
        # To provide a workaround, we need keep reference to the child and
        # populate child entry inside parent clause in transactional API.
        # TODO(annak): remove this if/when policy solves this
        self.mandatory_child_def = None

    def get_obj_dict(self):
        body = self.body if self.body else {}
        if self.resource_type():
            body['resource_type'] = self.resource_type()

        self._set_attr_if_specified(body, 'name', 'display_name')
        self._set_attrs_if_specified(body, ['description', 'tags'])

        resource_id = self.get_id()
        if resource_id:
            body['id'] = resource_id
        return body

    # This is needed for sake of update due to policy issue.
    # Policy refuses to update without requires attributes provided,
    # so we need to run an extra GET to acquire these.
    # This should be removed when/if this issue is fixed on backend.
    def set_obj_dict(self, obj_dict):
        self.body = obj_dict

    @abc.abstractproperty
    def path_pattern(self):
        pass

    @abc.abstractproperty
    def path_ids(self):
        pass

    @staticmethod
    def resource_type():
        pass

    @classmethod
    def resource_class(cls):
        # Returns base resource type for polymorphic objects
        # if not overriden, would return resource_type
        return cls.resource_type()

    @staticmethod
    def resource_use_cache():
        return False

    def path_defs(self):
        pass

    def get_id(self):
        if self.attrs and self.path_ids:
            return self.attrs.get(self.path_ids[-1])

    def get_attr(self, attr):
        return self.attrs.get(attr)

    def has_attr(self, attr):
        return attr in self.attrs

    def get_tenant(self):
        if self.attrs.get('tenant'):
            return self.attrs.get('tenant')

        return constants.POLICY_INFRA_TENANT

    def get_section_path(self):
        path_ids = [self.get_attr(path_id) for path_id in self.path_ids[:-1]]
        return self.path_pattern % (tuple(path_ids))

    def get_resource_path(self):
        resource_id = self.get_id()
        if resource_id:
            return self.get_section_path() + resource_id
        return self.get_section_path()

    def get_resource_full_path(self):
        return '/' + self.get_resource_path()

    @property
    def get_last_section_dict_key(self):
        last_section = self.path_pattern.split("/")[-2]
        return last_section.replace('-', '_')

    @staticmethod
    def sub_entries_path():
        pass

    def _get_body_from_kwargs(self, **kwargs):
        if 'body' in kwargs:
            body = kwargs['body']
        else:
            body = {}
        return body

    # Helper to set attr in body if user specified it
    # Can be used if body name is different than attr name
    # If value is different than self.get_attr(attr), it can be set in arg
    def _set_attr_if_specified(self, body, attr,
                               body_attr=None, value=None):
        if self.has_attr(attr):
            value = value if value is not None else self.get_attr(attr)
            if body_attr:
                # Body attr is different that attr exposed by resource def
                body[body_attr] = value
            else:
                # Body attr is the same
                body[attr] = value

    # Helper to set attrs in body if user specified them
    # Body name must match attr name
    def _set_attrs_if_specified(self, body, attr_list):
        for attr in attr_list:
            self._set_attr_if_specified(body, attr)

    @classmethod
    def get_single_entry(cls, obj_body):
        """Return the single sub-entry from the object body.

        If there are no entries, or more than 1 - return None.
        """
        entries_path = cls.sub_entries_path()
        if not entries_path:
            # This sub class doesn't support this
            return

        if (entries_path not in obj_body or
            len(obj_body[entries_path]) != 1):
            return

        return obj_body[entries_path][0]

    def bodyless(self):
        """Return True if args contain only keys and meta attrs"""

        meta = ['resource_type']
        meta.extend(self.path_ids)
        body_args = [key for key in self.attrs.keys()
                     if key not in meta]
        return len(body_args) == 0


class TenantDef(ResourceDef):
    @property
    def path_pattern(self):
        return TENANTS_PATH_PATTERN

    @staticmethod
    def resource_type():
        return 'Infra'

    def path_defs(self):
        return ()

    @property
    def path_ids(self):
        return ('tenant',)

    def get_resource_path(self):
        return 'infra/'

    def get_section_path(self):
        return 'infra/'


class DomainDef(ResourceDef):

    @property
    def path_pattern(self):
        return DOMAINS_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'domain_id')

    @staticmethod
    def resource_type():
        return 'Domain'

    def path_defs(self):
        return (TenantDef,)


class RouteAdvertisement(object):

    types = {'static_routes': 'TIER1_STATIC_ROUTES',
             'subnets': 'TIER1_CONNECTED',
             'nat': 'TIER1_NAT',
             'lb_vip': 'TIER1_LB_VIP',
             'lb_snat': 'TIER1_LB_SNAT',
             'dns_forwarder_ip': 'TIER1_DNS_FORWARDER_IP'}

    def __init__(self, **kwargs):
        self.attrs = kwargs

    def get_obj_dict(self):
        return [value for key, value in self.types.items()
                if self.attrs.get(key) is True]

    def set_obj_dict(self, obj_dict):
        # This initializes object based on list coming from backend
        # f.e. [TIER1_NAT, TIER1_LB_SNAT]

        # TODO(annak): for now platform does not return adv types
        # check this when issue is fixed
        for key, value in self.types.items():
            self.attrs[key] = value in obj_dict

    def update(self, **kwargs):
        # "None" will be passed as value when user does not specify adv type
        # True/False will be passed when user wants to switch adv ON/OFF
        for key, value in kwargs.items():
            if value is not None:
                self.attrs[key] = value


class RouterDef(ResourceDef):
    def path_defs(self):
        return (TenantDef,)

    def get_obj_dict(self):
        body = super(RouterDef, self).get_obj_dict()

        self._set_attrs_if_specified(body, ['failover_mode',
                                            'force_whitelisting',
                                            'default_rule_logging',
                                            'disable_firewall'])

        # Add dhcp relay config
        # TODO(asarfaty): this can be either dhcp or dhcp relay config
        if self.has_attr('dhcp_config'):
            paths = None
            if self.get_attr('dhcp_config'):
                dhcp_conf = DhcpRelayConfigDef(
                    config_id=self.get_attr('dhcp_config'),
                    tenant=self.get_tenant())
                paths = [dhcp_conf.get_resource_full_path()]
            self._set_attr_if_specified(body, 'dhcp_config',
                                        body_attr='dhcp_config_paths',
                                        value=paths)

        if self.has_attr('ipv6_ndra_profile_id'):
            paths = None
            if self.get_attr('ipv6_ndra_profile_id'):
                ndra_profile = Ipv6NdraProfileDef(
                    profile_id=self.get_attr('ipv6_ndra_profile_id'),
                    tenant=self.get_tenant())
                paths = [ndra_profile.get_resource_full_path()]

            self._set_attr_if_specified(body, 'ipv6_ndra_profile_id',
                                        body_attr='ipv6_profile_paths',
                                        value=paths)

        return body


class Tier0Def(RouterDef):

    @property
    def path_pattern(self):
        return TIER0S_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'tier0_id')

    @staticmethod
    def resource_type():
        return 'Tier0'

    @staticmethod
    def resource_use_cache():
        return True

    def get_obj_dict(self):
        body = super(Tier0Def, self).get_obj_dict()

        self._set_attrs_if_specified(body, ['ha_mode', 'transit_subnets'])

        return body


class Tier1Def(RouterDef):

    @property
    def path_pattern(self):
        return TIER1S_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'tier1_id')

    @staticmethod
    def resource_type():
        return 'Tier1'

    def get_obj_dict(self):
        body = super(Tier1Def, self).get_obj_dict()

        # TODO(annak): replace with provider path when provider is exposed
        if self.has_attr('tier0'):
            tier0 = self.get_attr('tier0')
            tier0_path = None
            if tier0:
                tenant = TENANTS_PATH_PATTERN % self.get_tenant()
                tier0_path = "/%stier-0s/%s" % (tenant, tier0)

            self._set_attr_if_specified(body, 'tier0',
                                        body_attr='tier0_path',
                                        value=tier0_path)

        if self.has_attr('route_advertisement'):
            body['route_advertisement_types'] = self.get_attr(
                'route_advertisement').get_obj_dict()

        self._set_attrs_if_specified(body, ['enable_standby_relocation'])

        return body

    @staticmethod
    def get_route_adv(obj_dict):
        route_adv = RouteAdvertisement()
        if 'route_advertisement_types' in obj_dict:
            route_adv.set_obj_dict(obj_dict['route_advertisement_types'])
        return route_adv


class RouterLocaleServiceDef(ResourceDef):

    @staticmethod
    def resource_type():
        return 'LocaleServices'

    def get_obj_dict(self):
        body = super(RouterLocaleServiceDef, self).get_obj_dict()
        self._set_attr_if_specified(body, 'edge_cluster_path')
        return body


class Tier0LocaleServiceDef(RouterLocaleServiceDef):

    @property
    def path_pattern(self):
        return TIER0S_PATH_PATTERN + "%s/locale-services/"

    @property
    def path_ids(self):
        return ('tenant', 'tier0_id', 'service_id')


class Tier1LocaleServiceDef(RouterLocaleServiceDef):

    @property
    def path_pattern(self):
        return TIER1S_PATH_PATTERN + "%s/locale-services/"

    @property
    def path_ids(self):
        return ('tenant', 'tier1_id', 'service_id')


class Tier0InterfaceDef(ResourceDef):

    @staticmethod
    def resource_type():
        return 'Tier0Interface'

    @property
    def path_pattern(self):
        return TIER0S_PATH_PATTERN + "%s/locale-services/%s/interfaces/"

    @property
    def path_ids(self):
        return ('tenant', 'tier0_id', 'service_id', 'interface_id')


class Tier1InterfaceDef(ResourceDef):

    @staticmethod
    def resource_type():
        return 'Tier1Interface'

    @property
    def path_pattern(self):
        return TIER1S_PATH_PATTERN + "%s/locale-services/%s/interfaces/"

    def get_obj_dict(self):
        body = super(Tier1InterfaceDef, self).get_obj_dict()
        if self.has_attr('subnets'):
            # subnets expected to be of type InterfaceSubnet
            if self.get_attr('subnets'):
                subnets = [subnet.get_obj_dict()
                           for subnet in self.get_attr('subnets')]
                self._set_attr_if_specified(body, 'subnets',
                                            value=subnets)

        if self.has_attr('segment_id'):
            path = ""
            if self.get_attr('segment_id'):
                tier1 = SegmentDef(segment_id=self.get_attr('segment_id'),
                                   tenant=self.get_tenant())
                path = tier1.get_resource_full_path()
            self._set_attr_if_specified(body, 'segment_id',
                                        body_attr='segment_path',
                                        value=path)
        return body

    @property
    def path_ids(self):
        return ('tenant', 'tier1_id', 'service_id', 'interface_id')


class RouterNatRule(ResourceDef):

    @staticmethod
    def resource_type():
        return 'PolicyNatRule'

    def get_obj_dict(self):
        body = super(RouterNatRule, self).get_obj_dict()
        self._set_attrs_if_specified(body, ['action',
                                            'source_network',
                                            'destination_network',
                                            'translated_network',
                                            'firewall_match',
                                            'log',
                                            'sequence_number',
                                            'enabled'])
        return body


class Tier1NatRule(RouterNatRule):

    @property
    def path_pattern(self):
        return TIER1S_PATH_PATTERN + "%s/nat/%s/nat-rules/"

    @property
    def path_ids(self):
        return ('tenant', 'tier1_id', 'nat_id', 'nat_rule_id')

    def path_defs(self):
        return (TenantDef, Tier1Def)


class RouterStaticRoute(ResourceDef):

    @staticmethod
    def resource_type():
        return 'StaticRoutes'

    def get_obj_dict(self):
        body = super(RouterStaticRoute, self).get_obj_dict()
        self._set_attrs_if_specified(body, ['network'])

        # next hops
        if self.has_attr('next_hop'):
            next_hop = self.get_attr('next_hop')
            next_hops = [{'ip_address': next_hop}]
            self._set_attr_if_specified(body, 'next_hop',
                                        body_attr='next_hops',
                                        value=next_hops)
        return body


class Tier1StaticRoute(RouterStaticRoute):

    @property
    def path_pattern(self):
        return TIER1S_PATH_PATTERN + "%s/static-routes/"

    @property
    def path_ids(self):
        return ('tenant', 'tier1_id', 'static_route_id')

    def path_defs(self):
        return (TenantDef, Tier1Def)


class Tier0StaticRoute(RouterStaticRoute):

    @property
    def path_pattern(self):
        return TIER0S_PATH_PATTERN + "%s/static-routes/"

    @property
    def path_ids(self):
        return ('tenant', 'tier0_id', 'static_route_id')

    def path_defs(self):
        return (TenantDef, Tier0Def)


class Tier0NatRule(RouterNatRule):

    @property
    def path_pattern(self):
        return TIER0S_PATH_PATTERN + "%s/nat/%s/nat-rules/"

    @property
    def path_ids(self):
        return ('tenant', 'tier0_id', 'nat_id', 'nat_rule_id')

    def path_defs(self):
        return (TenantDef, Tier0Def)


class Subnet(object):
    def __init__(self, gateway_address, dhcp_ranges=None):
        self.gateway_address = gateway_address
        self.dhcp_ranges = dhcp_ranges

    def get_obj_dict(self):
        body = {'gateway_address': self.gateway_address}
        if self.dhcp_ranges:
            body['dhcp_ranges'] = self.dhcp_ranges

        return body


class InterfaceSubnet(object):
    def __init__(self, ip_addresses, prefix_len):
        self.ip_addresses = ip_addresses
        self.prefix_len = prefix_len

    def get_obj_dict(self):
        body = {'ip_addresses': self.ip_addresses,
                'prefix_len': self.prefix_len}
        return body


class BaseSegmentDef(ResourceDef):

    def get_obj_dict(self):
        body = super(BaseSegmentDef, self).get_obj_dict()
        if self.has_attr('subnets'):
            # Note(asarfaty): removing subnets through PATCH api is not
            # supported
            if self.get_attr('subnets'):
                subnets = [subnet.get_obj_dict()
                           for subnet in self.get_attr('subnets')]
                self._set_attr_if_specified(body, 'subnets',
                                            value=subnets)
        if self.has_attr('ip_pool_id'):
            ip_pool_id = self.get_attr('ip_pool_id')
            adv_cfg = self._get_adv_config(ip_pool_id)
            self._set_attr_if_specified(body, 'ip_pool_id',
                                        body_attr='advanced_config',
                                        value=adv_cfg)
        self._set_attrs_if_specified(body, ['domain_name', 'vlan_ids'])
        return body

    @staticmethod
    def resource_type():
        return 'Segment'

    def _get_adv_config(self, ip_pool_id):
        ip_pool_def = IpPoolDef(ip_pool_id=ip_pool_id)
        ip_pool_path = ip_pool_def.get_resource_full_path()
        return {'address_pool_paths': [ip_pool_path]}


class Tier1SegmentDef(BaseSegmentDef):
    '''Tier1 segments can not move to different tier1 '''

    @property
    def path_pattern(self):
        return TIER1S_PATH_PATTERN + "%s/segments/"

    @property
    def path_ids(self):
        return ('tenant', 'tier1_id', 'segment_id')

    def path_defs(self):
        return (TenantDef, Tier1Def)


class SegmentDef(BaseSegmentDef):
    '''These segments don't belong to particular tier1.

       And can be attached and re-attached to different tier1s
    '''

    @property
    def path_pattern(self):
        return SEGMENTS_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'segment_id')

    def path_defs(self):
        return (TenantDef,)

    def get_obj_dict(self):
        body = super(SegmentDef, self).get_obj_dict()
        if self.has_attr('tier1_id'):
            path = ""
            if self.get_attr('tier1_id'):
                tier1 = Tier1Def(tier1_id=self.get_attr('tier1_id'),
                                 tenant=self.get_tenant())
                path = tier1.get_resource_full_path()
            self._set_attr_if_specified(body, 'tier1_id',
                                        body_attr='connectivity_path',
                                        value=path)

        if self.has_attr('transport_zone_id'):
            path = ""
            if self.get_attr('transport_zone_id'):
                tz = TransportZoneDef(
                    tz_id=self.get_attr('transport_zone_id'),
                    ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
                    tenant=self.get_tenant())
                path = tz.get_resource_full_path()
            self._set_attr_if_specified(body, 'transport_zone_id',
                                        body_attr='transport_zone_path',
                                        value=path)

        # TODO(annak): support also tier0
        return body


class PortAddressBinding(object):
    def __init__(self, ip_address, mac_address, vlan_id=None):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.vlan_id = vlan_id

    def get_obj_dict(self):
        return {'ip_address': self.ip_address,
                'mac_address': self.mac_address,
                'vlan_id': self.vlan_id}


class SegmentPortDef(ResourceDef):
    '''Infra segment port'''

    @property
    def path_pattern(self):
        return SEGMENTS_PATH_PATTERN + "%s/ports/"

    @property
    def path_ids(self):
        return ('tenant', 'segment_id', 'port_id')

    @staticmethod
    def resource_type():
        return 'SegmentPort'

    def path_defs(self):
        return (TenantDef, SegmentDef)

    def get_obj_dict(self):
        body = super(SegmentPortDef, self).get_obj_dict()
        address_bindings = self.get_attr('address_bindings')
        if address_bindings:
            body['address_bindings'] = [binding.get_obj_dict()
                                        for binding in address_bindings]
        if self.has_attr('attachment_type') or self.has_attr('vif_id'):
            if (not self.get_attr('attachment_type') and
                not self.get_attr('vif_id')):
                # detach operation
                body['attachment'] = None
            else:
                attachment = {}
                if self.get_attr('attachment_type'):
                    attachment['type'] = self.get_attr('attachment_type')
                if self.get_attr('vif_id'):
                    attachment['id'] = self.get_attr('vif_id')

                self._set_attrs_if_specified(attachment,
                                             ['context_id',
                                              'app_id',
                                              'traffic_tag',
                                              'allocate_addresses'])
                body['attachment'] = attachment

        return body


class SegmentPortBindingMapDefBase(ResourceDef):

    @property
    def path_ids(self):
        return ('tenant', 'segment_id', 'port_id', 'map_id')

    def path_defs(self):
        return (TenantDef, SegmentDef, SegmentPortDef)


class SegmentPortSecProfilesBindingMapDef(SegmentPortBindingMapDefBase):
    @property
    def path_pattern(self):
        return (SEGMENTS_PATH_PATTERN +
                "%s/ports/%s/port-security-profile-binding-maps/")

    @staticmethod
    def resource_type():
        return 'PortSecurityProfileBindingMap'

    def get_obj_dict(self):
        body = super(SegmentPortSecProfilesBindingMapDef, self).get_obj_dict()

        if self.has_attr('segment_security_profile_id'):
            path = None
            if self.get_attr('segment_security_profile_id'):
                profile = SegmentSecurityProfileDef(
                    profile_id=self.get_attr('segment_security_profile_id'),
                    tenant=self.get_tenant())
                path = profile.get_resource_full_path()
            self._set_attr_if_specified(
                body, 'segment_security_profile_id',
                body_attr='segment_security_profile_path',
                value=path)

        if self.has_attr('spoofguard_profile_id'):
            path = None
            if self.get_attr('spoofguard_profile_id'):
                profile = SpoofguardProfileDef(
                    profile_id=self.get_attr('spoofguard_profile_id'),
                    tenant=self.get_tenant())
                path = profile.get_resource_full_path()
            self._set_attr_if_specified(
                body, 'spoofguard_profile_id',
                body_attr='spoofguard_profile_path',
                value=path)

        return body


class SegmentPortDiscoveryProfilesBindingMapDef(SegmentPortBindingMapDefBase):
    @property
    def path_pattern(self):
        return (SEGMENTS_PATH_PATTERN +
                "%s/ports/%s/port-discovery-profile-binding-maps/")

    @staticmethod
    def resource_type():
        return 'PortDiscoveryProfileBindingMap'

    def get_obj_dict(self):
        body = super(SegmentPortDiscoveryProfilesBindingMapDef,
                     self).get_obj_dict()

        if self.has_attr('mac_discovery_profile_id'):
            path = None
            if self.get_attr('mac_discovery_profile_id'):
                profile = MacDiscoveryProfileDef(
                    profile_id=self.get_attr('mac_discovery_profile_id'),
                    tenant=self.get_tenant())
                path = profile.get_resource_full_path()
            self._set_attr_if_specified(
                body, 'mac_discovery_profile_id',
                body_attr='mac_discovery_profile_path',
                value=path)

        if self.has_attr('ip_discovery_profile_id'):
            path = None
            if self.get_attr('ip_discovery_profile_id'):
                profile = IpDiscoveryProfileDef(
                    profile_id=self.get_attr('ip_discovery_profile_id'),
                    tenant=self.get_tenant())
                path = profile.get_resource_full_path()
            self._set_attr_if_specified(
                body, 'ip_discovery_profile_id',
                body_attr='ip_discovery_profile_path',
                value=path)

        return body


class SegmentPortQoSProfilesBindingMapDef(SegmentPortBindingMapDefBase):
    @property
    def path_pattern(self):
        return (SEGMENTS_PATH_PATTERN +
                "%s/ports/%s/port-qos-profile-binding-maps/")

    @staticmethod
    def resource_type():
        return 'PortQoSProfileBindingMap'

    def get_obj_dict(self):
        body = super(SegmentPortQoSProfilesBindingMapDef,
                     self).get_obj_dict()

        if self.has_attr('qos_profile_id'):
            path = None
            if self.get_attr('qos_profile_id'):
                profile = QosProfileDef(
                    profile_id=self.get_attr('qos_profile_id'),
                    tenant=self.get_tenant())
                path = profile.get_resource_full_path()
            self._set_attr_if_specified(
                body, 'qos_profile_id',
                body_attr='qos_profile_path',
                value=path)

        return body


class Tier1SegmentPortDef(SegmentPortDef):
    '''Tier1 segment port'''

    @property
    def path_pattern(self):
        return TIER1S_PATH_PATTERN + "%s/segments/%s/ports/"

    @property
    def path_ids(self):
        return ('tenant', 'tier1_id', 'segment_id', 'port_id')

    def path_defs(self):
        return (TenantDef, Tier1Def, SegmentDef)


class IpBlockDef(ResourceDef):
    '''Infra IpBlock'''

    @property
    def path_pattern(self):
        return IP_BLOCKS_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'ip_block_id')

    @staticmethod
    def resource_type():
        return 'IpAddressBlock'

    def path_defs(self):
        return (TenantDef,)

    def get_obj_dict(self):
        body = super(IpBlockDef, self).get_obj_dict()
        self._set_attr_if_specified(body, 'cidr')
        return body


class IpPoolDef(ResourceDef):
    '''Infra IpPool'''

    @property
    def path_pattern(self):
        return IP_POOLS_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'ip_pool_id')

    @staticmethod
    def resource_type():
        return 'IpAddressPool'

    def path_defs(self):
        return (TenantDef,)


class IpPoolAllocationDef(ResourceDef):
    '''Infra IpPoolAllocation'''

    @property
    def path_pattern(self):
        return IP_POOLS_PATH_PATTERN + "%s/ip-allocations/"

    @property
    def path_ids(self):
        return ('tenant', 'ip_pool_id', 'ip_allocation_id')

    @staticmethod
    def resource_type():
        return 'IpAddressAllocation'

    def path_defs(self):
        return (TenantDef, IpPoolDef)

    def get_obj_dict(self):
        body = super(IpPoolAllocationDef, self).get_obj_dict()
        self._set_attr_if_specified(body, 'allocation_ip')
        return body


class IpPoolSubnetDef(ResourceDef):
    '''Infra IpPool Subnet'''

    @property
    def path_pattern(self):
        return IP_POOLS_PATH_PATTERN + "%s/ip-subnets/"

    @property
    def path_ids(self):
        return ('tenant', 'ip_pool_id', 'ip_subnet_id')

    @classmethod
    def resource_class(cls):
        return 'IpAddressPoolSubnet'

    def path_defs(self):
        return (TenantDef, IpPoolDef)


class IpPoolBlockSubnetDef(IpPoolSubnetDef):
    '''Infra IpPoolSubnet belonging to IpBlock'''

    @staticmethod
    def resource_type():
        return 'IpAddressPoolBlockSubnet'

    def get_obj_dict(self):
        body = super(IpPoolBlockSubnetDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ['auto_assign_gateway', 'size'])
        if self.has_attr('ip_block_id'):
            # Format the IP Block ID to its path
            ip_block_id = self.get_attr('ip_block_id')
            ip_block_def = IpBlockDef(ip_block_id=ip_block_id,
                                      tenant=self.get_tenant())
            ip_block_path = ip_block_def.get_resource_full_path()
            self._set_attr_if_specified(
                body, 'ip_block_id', body_attr='ip_block_path',
                value=ip_block_path)
        return body


class IpPoolStaticSubnetDef(IpPoolSubnetDef):
    '''Infra IpPool static subnet'''

    @staticmethod
    def resource_type():
        return 'IpAddressPoolStaticSubnet'

    def get_obj_dict(self):
        body = super(IpPoolStaticSubnetDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ['cidr',
                                            'allocation_ranges',
                                            'gateway_ip'])
        return body


class Condition(object):
    def __init__(self, value, key=constants.CONDITION_KEY_TAG,
                 member_type=constants.CONDITION_MEMBER_PORT,
                 operator=constants.CONDITION_OP_EQUALS):
        self.value = value
        self.key = key
        self.member_type = member_type
        self.operator = operator

    def get_obj_dict(self):
        return {'resource_type': 'Condition',
                'member_type': self.member_type,
                'key': self.key,
                'value': self.value,
                'operator': self.operator}


class IPAddressExpression(object):
    def __init__(self, ip_addresses):
        self.ip_addresses = ip_addresses

    def get_obj_dict(self):
        return {'resource_type': 'IPAddressExpression',
                'ip_addresses': self.ip_addresses}


class PathExpression(object):
    def __init__(self, paths):
        self.paths = paths

    def get_obj_dict(self):
        return {'resource_type': 'PathExpression',
                'paths': self.paths}


class ConjunctionOperator(object):
    def __init__(self, operator=constants.CONDITION_OP_AND):
        self.operator = operator

    def get_obj_dict(self):
        return {'resource_type': 'ConjunctionOperator',
                'conjunction_operator': self.operator}


class NestedExpression(object):
    def __init__(self, expressions=None):
        self.expressions = expressions or []

    def get_obj_dict(self):
        return {'resource_type': 'NestedExpression',
                'expressions': [ex.get_obj_dict() for ex in self.expressions]}


class GroupDef(ResourceDef):

    @property
    def path_pattern(self):
        return DOMAINS_PATH_PATTERN + "%s/groups/"

    @property
    def path_ids(self):
        return ('tenant', 'domain_id', 'group_id')

    @staticmethod
    def resource_type():
        return 'Group'

    def path_defs(self):
        return (TenantDef, DomainDef)

    def get_obj_dict(self):
        body = super(GroupDef, self).get_obj_dict()
        conds = self.get_attr('conditions')
        if conds:
            conds = conds if isinstance(conds, list) else [conds]
            if conds:
                body['expression'] = [condition.get_obj_dict()
                                      for condition in conds]
        return body


class ServiceDef(ResourceDef):
    def __init__(self, **kwargs):
        super(ServiceDef, self).__init__(**kwargs)
        self.service_entries = []

    @property
    def path_pattern(self):
        return SERVICES_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'service_id')

    @staticmethod
    def resource_type():
        return 'Service'

    def path_defs(self):
        return (TenantDef,)

    def get_obj_dict(self):
        body = super(ServiceDef, self).get_obj_dict()
        entries = [entry.get_obj_dict()
                   for entry in self.service_entries]
        if entries:
            body['service_entries'] = entries
        return body

    @staticmethod
    def sub_entries_path():
        return ServiceEntryDef().get_last_section_dict_key


class ServiceEntryDef(ResourceDef):

    @property
    def path_pattern(self):
        return SERVICES_PATH_PATTERN + "%s/service-entries/"

    @property
    def path_ids(self):
        return ('tenant', 'service_id', 'entry_id')

    def path_defs(self):
        return (TenantDef, ServiceDef)

    @classmethod
    def resource_class(cls):
        return 'ServiceEntry'


class L4ServiceEntryDef(ServiceEntryDef):

    @staticmethod
    def resource_type():
        return 'L4PortSetServiceEntry'

    def get_obj_dict(self):
        body = super(L4ServiceEntryDef, self).get_obj_dict()

        self._set_attr_if_specified(body, 'protocol', 'l4_protocol')
        self._set_attr_if_specified(body, 'dest_ports', 'destination_ports')
        self._set_attr_if_specified(body, 'source_ports', 'source_ports')
        return body


class IcmpServiceEntryDef(ServiceEntryDef):

    @staticmethod
    def resource_type():
        return 'ICMPTypeServiceEntry'

    def get_obj_dict(self):
        body = super(IcmpServiceEntryDef, self).get_obj_dict()

        if self.get_attr('version'):
            body['protocol'] = 'ICMPv' + str(self.get_attr('version'))

        for attr in ('icmp_type', 'icmp_code'):
            # Note that icmp_type and icmp_code could be 0.
            if self.get_attr(attr) is not None:
                body[attr] = self.get_attr(attr)
        return body


class IPProtocolServiceEntryDef(ServiceEntryDef):

    @staticmethod
    def resource_type():
        return 'IPProtocolServiceEntry'

    def get_obj_dict(self):
        body = super(IPProtocolServiceEntryDef, self).get_obj_dict()
        if self.get_attr('protocol_number') is not None:
            # Note that protocol_number could be 0.
            body['protocol_number'] = self.get_attr('protocol_number')
        return body


class SecurityPolicyBaseDef(ResourceDef):

    @property
    def path_ids(self):
        return ('tenant', 'domain_id', 'map_id')

    def path_defs(self):
        return (TenantDef, DomainDef)

    def get_obj_dict(self):
        body = super(SecurityPolicyBaseDef, self).get_obj_dict()
        self._set_attr_if_specified(body, 'category')
        if self.has_attr('map_sequence_number'):
            seq_number = self.get_attr('map_sequence_number')
            self._set_attr_if_specified(body, 'map_sequence_number',
                                        body_attr='sequence_number',
                                        value=seq_number)
        return body


class CommunicationMapDef(SecurityPolicyBaseDef):
    """AKA security policy"""
    @property
    def path_pattern(self):
        return (DOMAINS_PATH_PATTERN + "%s/security-policies/")

    @staticmethod
    def resource_type():
        return 'SecurityPolicy'

    @staticmethod
    def sub_entries_path():
        return CommunicationMapEntryDef().get_last_section_dict_key


class GatewayPolicyDef(SecurityPolicyBaseDef):
    @property
    def path_pattern(self):
        return (DOMAINS_PATH_PATTERN + "%s/gateway-policies/")

    @staticmethod
    def resource_type():
        return 'GatewayPolicy'

    @staticmethod
    def sub_entries_path():
        return GatewayPolicyRuleDef().get_last_section_dict_key


class SecurityPolicyRuleBaseDef(ResourceDef):
    def get_groups_path(self, domain_id, group_ids):
        if not group_ids:
            return [constants.ANY_GROUP]
        return [GroupDef(domain_id=domain_id,
                         group_id=group_id,
                         tenant=self.get_tenant()).get_resource_full_path()
                for group_id in group_ids]

    def get_service_path(self, service_id):
        return ServiceDef(
            service_id=service_id,
            tenant=self.get_tenant()).get_resource_full_path()

    def get_services_path(self, service_ids):
        if service_ids:
            return [self.get_service_path(service_id)
                    for service_id in service_ids]

        return [constants.ANY_SERVICE]

    @property
    def path_ids(self):
        return ('tenant', 'domain_id', 'map_id', 'entry_id')

    @staticmethod
    def resource_type():
        return 'Rule'

    def get_obj_dict(self):
        body = super(SecurityPolicyRuleBaseDef, self).get_obj_dict()
        domain_id = self.get_attr('domain_id')
        if self.has_attr('source_groups'):
            body['source_groups'] = self.get_groups_path(
                domain_id, self.get_attr('source_groups'))
        if self.has_attr('dest_groups'):
            body['destination_groups'] = self.get_groups_path(
                domain_id, self.get_attr('dest_groups'))

        self._set_attrs_if_specified(body, ['sequence_number', 'scope',
                                            'action', 'direction', 'logged',
                                            'ip_protocol'])

        if self.has_attr('service_ids'):
            service_ids = self.get_attr('service_ids')
            body['services'] = self.get_services_path(service_ids)
        return body


class CommunicationMapEntryDef(SecurityPolicyRuleBaseDef):

    @property
    def path_pattern(self):
        return (DOMAINS_PATH_PATTERN +
                "%s/security-policies/%s/rules/")

    def path_defs(self):
        return (TenantDef, DomainDef, CommunicationMapDef)


class GatewayPolicyRuleDef(SecurityPolicyRuleBaseDef):

    @property
    def path_pattern(self):
        return (DOMAINS_PATH_PATTERN +
                "%s/gateway-policies/%s/rules/")

    def path_defs(self):
        return (TenantDef, DomainDef, GatewayPolicyDef)


# Currently supports only NSXT
class EnforcementPointDef(ResourceDef):

    @property
    def path_pattern(self):
        return ENFORCEMENT_POINT_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'ep_id')

    @staticmethod
    def resource_type():
        return 'EnforcementPoint'

    def path_defs(self):
        return (TenantDef,)

    def get_obj_dict(self):
        body = super(EnforcementPointDef, self).get_obj_dict()
        body['id'] = self.get_id()
        if 'connection_info' not in body:
            body['connection_info'] = {'resource_type': 'NSXTConnectionInfo'}

        info = body['connection_info']
        self._set_attrs_if_specified(info,
                                     ['thumbprint', 'username', 'password',
                                      'ip_address'])

        if self.get_attr('ip_address'):
            info['enforcement_point_address'] = self.get_attr('ip_address')

        if self.get_attr('edge_cluster_id'):
            body['connection_info']['edge_cluster_ids'] = [
                self.get_attr('edge_cluster_id')]

        if self.get_attr('transport_zone_id'):
            body['connection_info']['transport_zone_ids'] = [
                self.get_attr('transport_zone_id')]

        return body


class TransportZoneDef(ResourceDef):

    @property
    def path_pattern(self):
        return TRANSPORT_ZONE_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'ep_id', 'tz_id')

    @staticmethod
    def resource_type():
        return 'PolicyTransportZone'

    @staticmethod
    def resource_use_cache():
        return True


class EdgeClusterDef(ResourceDef):

    @property
    def path_pattern(self):
        return EDGE_CLUSTER_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'ep_id', 'ec_id')

    @staticmethod
    def resource_type():
        return 'PolicyEdgeCluster'

    @staticmethod
    def resource_use_cache():
        return True


# Currently assumes one deployment point per id
class DeploymentMapDef(ResourceDef):

    @property
    def path_pattern(self):
        return (DOMAINS_PATH_PATTERN + '%s/domain-deployment-maps/')

    @property
    def path_ids(self):
        return ('tenant', 'domain_id', 'map_id')

    @staticmethod
    def resource_type():
        return 'DeploymentMap'

    def path_defs(self):
        return (TenantDef, DomainDef)

    def get_obj_dict(self):
        body = super(DeploymentMapDef, self).get_obj_dict()
        body['id'] = self.get_id()
        ep_id = self.get_attr('ep_id')
        tenant = self.get_tenant()
        body['enforcement_point_path'] = EnforcementPointDef(
            ep_id=ep_id,
            tenant=tenant).get_resource_full_path() if ep_id else None
        return body


class SegmentSecurityProfileDef(ResourceDef):
    DEFAULT_PROFILE = 'default-segment-security-profile'

    @property
    def path_pattern(self):
        return SEGMENT_SECURITY_PROFILES_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'profile_id')

    @staticmethod
    def resource_type():
        return 'SegmentSecurityProfile'

    def path_defs(self):
        return (TenantDef,)

    def get_obj_dict(self):
        body = super(SegmentSecurityProfileDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ['bpdu_filter_enable',
                                            'dhcp_client_block_enabled',
                                            'dhcp_client_block_v6_enabled',
                                            'dhcp_server_block_enabled',
                                            'dhcp_server_block_v6_enabled',
                                            'non_ip_traffic_block_enabled',
                                            'ra_guard_enabled',
                                            'rate_limits_enabled'])
        return body


class QoSObjectBase(object):

    keys = []

    def __init__(self, **kwargs):
        self.attrs = kwargs

    def get_obj_dict(self):
        obj_dict = {}
        for key in self.attrs:
            if key in self.keys:
                obj_dict[key] = self.attrs[key]
        return obj_dict


class QoSRateLimiter(QoSObjectBase):

    INGRESS_RATE_LIMITER_TYPE = 'IngressRateLimiter'
    EGRESS_RATE_LIMITER_TYPE = 'EgressRateLimiter'
    INGRESS_BRD_RATE_LIMITER_TYPE = 'IngressBroadcastRateLimiter'

    keys = ['resource_type',
            'average_bandwidth',  # Mb/s
            'peak_bandwidth',  # Mb/s
            'burst_size',  # byes
            'enabled'
            ]


class QoSDscp(QoSObjectBase):
    QOS_DSCP_TRUSTED = 'TRUSTED'
    QOS_DSCP_UNTRUSTED = 'UNTRUSTED'
    keys = ['mode', 'priority']


class QosProfileDef(ResourceDef):
    @property
    def path_pattern(self):
        return QOS_PROFILES_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'profile_id')

    @staticmethod
    def resource_type():
        return 'QoSProfile'

    def path_defs(self):
        return (TenantDef,)

    def get_obj_dict(self):
        body = super(QosProfileDef, self).get_obj_dict()

        self._set_attr_if_specified(body, 'class_of_service')

        if self.has_attr('dscp'):
            value = None
            if self.get_attr('dscp'):
                value = self.get_attr('dscp').get_obj_dict()
            self._set_attr_if_specified(body, 'dscp', value=value)

        if self.has_attr('shaper_configurations'):
            value = None
            if self.get_attr('shaper_configurations'):
                value = [s.get_obj_dict()
                         for s in self.get_attr('shaper_configurations')]
            self._set_attr_if_specified(body, 'shaper_configurations',
                                        value=value)

        return body


class SpoofguardProfileDef(ResourceDef):
    DEFAULT_PROFILE = 'default-spoofguard-profile'

    @property
    def path_pattern(self):
        return SPOOFGUARD_PROFILES_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'profile_id')

    @staticmethod
    def resource_type():
        return 'SpoofGuardProfile'

    def path_defs(self):
        return (TenantDef,)

    def get_obj_dict(self):
        body = super(SpoofguardProfileDef, self).get_obj_dict()
        # TODO(asarfaty): add all attributes here
        self._set_attr_if_specified(body, 'address_binding_whitelist')
        return body


class IpDiscoveryProfileDef(ResourceDef):
    DEFAULT_PROFILE = 'default-ip-discovery-profile'

    @property
    def path_pattern(self):
        return IP_DISCOVERY_PROFILES_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'profile_id')

    @staticmethod
    def resource_type():
        return 'IPDiscoveryProfile'

    def path_defs(self):
        return (TenantDef,)

    def get_obj_dict(self):
        body = super(IpDiscoveryProfileDef, self).get_obj_dict()
        # TODO(asarfaty): add all attributes here. currently used for read only
        return body


class MacDiscoveryProfileDef(ResourceDef):
    DEFAULT_PROFILE = 'default-mac-discovery-profile'

    @property
    def path_pattern(self):
        return MAC_DISCOVERY_PROFILES_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'profile_id')

    @staticmethod
    def resource_type():
        return 'MacDiscoveryProfile'

    def path_defs(self):
        return (TenantDef,)

    def get_obj_dict(self):
        body = super(MacDiscoveryProfileDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ['mac_change_enabled',
                                            'mac_learning_enabled',
                                            'unknown_unicast_flooding_enabled',
                                            'mac_limit_policy', 'mac_limit'])
        return body


class Ipv6NdraProfileDef(ResourceDef):

    @property
    def path_pattern(self):
        return IPV6_NDRA_PROFILES_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'profile_id')

    @staticmethod
    def resource_type():
        return 'Ipv6NdraProfile'

    def path_defs(self):
        return (TenantDef,)

    def get_obj_dict(self):
        body = super(Ipv6NdraProfileDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ['ra_mode',
                                            'reachable_timer',
                                            'retransmit_interval'])
        # Use default settings for dns and RA for now
        # TODO(annak): expose when required
        body['dns_config'] = {}
        body['ra_config'] = {}
        return body


class DhcpRelayConfigDef(ResourceDef):

    @property
    def path_pattern(self):
        return DHCP_REALY_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'config_id')

    @staticmethod
    def resource_type():
        return 'DhcpRelayConfig'

    def path_defs(self):
        return (TenantDef,)

    def get_obj_dict(self):
        body = super(DhcpRelayConfigDef, self).get_obj_dict()
        self._set_attr_if_specified(body, 'server_addresses')
        return body


class WAFProfileDef(ResourceDef):
    @property
    def path_pattern(self):
        return WAF_PROFILES_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'profile_id')

    @staticmethod
    def resource_type():
        return 'WAFProfile'

    def path_defs(self):
        return (TenantDef,)

    def get_obj_dict(self):
        body = super(WAFProfileDef, self).get_obj_dict()
        # TODO(asarfaty): add all attributes here.
        # Currently used for read only
        return body


class CertificateDef(ResourceDef):

    @property
    def path_pattern(self):
        return CERTIFICATE_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'certificate_id')

    @staticmethod
    def resource_type():
        return "TlsTrustData"

    def get_obj_dict(self):
        body = super(CertificateDef, self).get_obj_dict()
        self._set_attrs_if_specified(body, ['pem_encoded', 'key_algo',
                                            'private_key', 'passphrase'])
        return body


class ExcludeListDef(ResourceDef):

    @property
    def path_pattern(self):
        return EXCLUDE_LIST_PATH_PATTERN

    @property
    def path_ids(self):
        # Adding dummy 2nd key to satisfy get_section_path
        # This resource has no keys, since it is a single object
        return ('tenant', 'Dummy')

    @staticmethod
    def resource_type():
        return "PolicyExcludeList"

    def get_obj_dict(self):
        body = super(ExcludeListDef, self).get_obj_dict()
        self._set_attr_if_specified(body, 'members')
        return body


class NsxPolicyApi(object):

    def __init__(self, client):
        self.client = client
        self.cache = utils.NsxLibCache(utils.DEFAULT_CACHE_AGE_SEC)

    def create_or_update(self, resource_def):
        """Create or update a policy object.

        This api will update an existing object, or create a new one if it
        doesn't exist.
        The policy API supports PATCH for create/update operations
        """
        path = resource_def.get_resource_path()
        if resource_def.resource_use_cache():
            self.cache.remove(path)
        body = resource_def.body
        if not body:
            body = resource_def.get_obj_dict()
        self.client.patch(path, body)

    def create_with_parent(self, parent_def, resource_def):
        path = parent_def.get_resource_path()
        body = parent_def.get_obj_dict()
        if isinstance(resource_def, list):
            child_dict_key = resource_def[0].get_last_section_dict_key
            body[child_dict_key] = [r.get_obj_dict() for r in resource_def]
        else:
            child_dict_key = resource_def.get_last_section_dict_key
            body[child_dict_key] = [resource_def.get_obj_dict()]
        self.client.patch(path, body)

    def delete(self, resource_def):
        path = resource_def.get_resource_path()
        if resource_def.resource_use_cache():
            self.cache.remove(path)
        self.client.delete(path)

    def get(self, resource_def, silent=False):
        path = resource_def.get_resource_path()
        if resource_def.resource_use_cache():
            # try to get it from the cache
            result = self.cache.get(path)
            if result:
                return result
        # call the client
        result = self.client.get(path, silent=silent)
        if resource_def.resource_use_cache():
            # add the result to the cache
            self.cache.update(path, result)
        return result

    def list(self, resource_def, silent=False):
        path = resource_def.get_section_path()
        return self.client.list(path, silent=silent)

    def get_realized_entities(self, path, silent=False):
        return self.client.list(REALIZATION_PATH % path,
                                silent=silent)['results']

    def get_realized_entity(self, path, silent=False):
        # Return first realization entity if exists
        # Useful for resources with single realization entity
        entities = self.get_realized_entities(path, silent=silent)
        if entities:
            return entities[0]

    def get_realized_state(self, path, silent=False):
        entity = self.get_realized_entity(path, silent=silent)
        if entity:
            return entity['state']
