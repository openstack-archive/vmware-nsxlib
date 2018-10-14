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

from vmware_nsxlib.v3 import policy_constants

TENANTS_PATH_PATTERN = "%s/"
DOMAINS_PATH_PATTERN = TENANTS_PATH_PATTERN + "domains/"
SEGMENTS_PATH_PATTERN = TENANTS_PATH_PATTERN + "segments/"
PROVIDERS_PATH_PATTERN = TENANTS_PATH_PATTERN + "providers/"
TIER0S_PATH_PATTERN = TENANTS_PATH_PATTERN + "tier-0s/"
TIER1S_PATH_PATTERN = TENANTS_PATH_PATTERN + "tier-1s/"
SERVICES_PATH_PATTERN = TENANTS_PATH_PATTERN + "services/"
REALIZED_STATE_EF = (TENANTS_PATH_PATTERN +
                     "realized-state/enforcement-points/%s/")
REALIZED_STATE_GROUP = REALIZED_STATE_EF + "groups/nsgroups/DOMAIN-%s-%s"
REALIZED_STATE_COMM_MAP = (REALIZED_STATE_EF +
                           "firewalls/firewall-sections/%s.%s")
REALIZED_STATE_SERVICE = REALIZED_STATE_EF + "services/nsservices/services:%s"


@six.add_metaclass(abc.ABCMeta)
class ResourceDef(object):
    def __init__(self, **kwargs):
        self.attrs = kwargs

        # init default tenant
        self.attrs['tenant'] = self.get_tenant()

        self.body = {}

    def get_obj_dict(self):
        body = {}
        if 'name' in self.attrs:
            body['display_name'] = self.attrs['name']

        for attr in ('description', 'tags'):
            if self.get_attr(attr):
                body[attr] = self.attrs[attr]
        resource_id = self.get_id()
        if resource_id:
            body['id'] = resource_id
        return body

    @abc.abstractproperty
    def path_pattern(self):
        pass

    @abc.abstractproperty
    def path_ids(self):
        pass

    def get_id(self):
        if self.attrs and self.path_ids:
            return self.attrs.get(self.path_ids[-1])

    def get_attr(self, attr):
        return self.attrs.get(attr)

    def get_tenant(self):
        if self.attrs.get('tenant'):
            return self.attrs.get('tenant')

        return policy_constants.POLICY_INFRA_TENANT

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

    def update_attributes_in_body(self, **kwargs):
        self.body = self._get_body_from_kwargs(**kwargs)
        if 'body' in kwargs:
            del kwargs['body']
        for key, value in six.iteritems(kwargs):
            if key == 'body':
                continue
            if value is not None:
                if key == 'name':
                    self.body['display_name'] = value
                else:
                    self.body[key] = value
        entries_path = self.sub_entries_path()
        # make sure service entries are there
        if entries_path and entries_path not in self.body:
            self.body[entries_path] = []

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


class DomainDef(ResourceDef):

    @property
    def path_pattern(self):
        return DOMAINS_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'domain_id')


class RouteAdvertisement(object):

    types = {'static_routes': 'TIER1_STATIC_ROUTES',
             'subnets': 'TIER1_SUBNETS',
             'nat': 'TIER1_NAT',
             'lb_vip': 'TIER1_LB_VIP',
             'lb_snat': 'TIER1_LB_SNAT'}

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


class Tier0Def(ResourceDef):

    @property
    def path_pattern(self):
        return TIER0S_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'tier0_id')

    def get_obj_dict(self):
        body = super(Tier0Def, self).get_obj_dict()

        for attr in ('ha_mode', 'failover_mode', 'force_whitelisting',
                     'default_rule_logging', 'transit_subnets'):
            body[attr] = self.get_attr(attr)

        # TODO(annak): path of dhcp config
        if self.get_attr('dhcp_config'):
            body['dhcp_config_path'] = self.get_attr(
                'dhcp_config').get_obj_dict()

        return body


class Tier1Def(ResourceDef):

    @property
    def path_pattern(self):
        return TIER1S_PATH_PATTERN

    @property
    def path_ids(self):
        return ('tenant', 'tier1_id')

    def get_obj_dict(self):
        body = super(Tier1Def, self).get_obj_dict()

        # TODO(annak): replace with provider path when provider is exposed
        tier0 = self.get_attr('tier0')
        if tier0:
            tenant = TENANTS_PATH_PATTERN % self.get_tenant()
            body['tier0_path'] = "/%stier-0s/%s" % (tenant, tier0)

        for attr in ('failover_mode', 'force_whitelisting'):
            body[attr] = self.get_attr(attr)

        if self.get_attr('route_adv'):
            body['route_advertisement_types'] = self.get_attr(
                'route_adv').get_obj_dict()

        return body

    @staticmethod
    def get_route_adv(obj_dict):
        route_adv = RouteAdvertisement()
        if 'route_advertisement_types' in obj_dict:
            route_adv.set_obj_dict(obj_dict['route_advertisement_types'])
        return route_adv


class Subnet(object):
    def __init__(self, gateway_address, dhcp_ranges=None):
        self.gateway_address = gateway_address
        self.dhcp_ranges = dhcp_ranges

    def get_obj_dict(self):
        body = {'gateway_address': self.gateway_address}
        if self.dhcp_ranges:
            body['dhcp_ranges'] = self.dhcp_ranges

        return body


# TODO(annak) - add advanced config when supported by platform
class BaseSegmentDef(ResourceDef):

    def get_obj_dict(self):
        body = super(BaseSegmentDef, self).get_obj_dict()
        if self.get_attr('subnets'):
            body['subnets'] = [subnet.get_obj_dict()
                               for subnet in self.get_attr('subnets')]
        for attr in ('domain_name', 'vlan_ids'):
            if self.get_attr(attr):
                body[attr] = self.get_attr(attr)
        return body


class Tier1SegmentDef(BaseSegmentDef):
    '''Tier1 segments can not move to different tier1 '''

    @property
    def path_pattern(self):
        return TIER1S_PATH_PATTERN + "%s/segments/"

    @property
    def path_ids(self):
        return ('tenant', 'tier1_id', 'segment_id')


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

    def get_obj_dict(self):
        body = super(SegmentDef, self).get_obj_dict()
        if self.get_attr('tier1_id'):
            tier1 = Tier1Def(tier1_id=self.get_attr('tier1_id'),
                             tenant=self.get_tenant())
            body['connectivity_path'] = tier1.get_resource_full_path()
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

    def get_obj_dict(self):
        body = super(SegmentPortDef, self).get_obj_dict()
        address_bindings = self.get_attr('address_bindings')
        if address_bindings:
            body['address_bindings'] = [binding.get_obj_dict()
                                        for binding in address_bindings]
        attachment = {}
        if self.get_attr('attachment_type'):
            # TODO(annak): add validations when we understand all
            # use cases. Consider child classes for different
            # attachment types.
            attachment = {'type': self.get_attr('attachment_type')}
        if self.get_attr('vif_id'):
            attachment['id'] = self.get_attr('vif_id')
        for attr in ('context_id', 'app_id', 'traffic_tag'):
            if self.get_attr(attr):
                attachment[attr] = self.get_attr(attr)

        if attachment:
            body['attachment'] = attachment
        return body


class Condition(object):
    def __init__(self, value, key=policy_constants.CONDITION_KEY_TAG,
                 member_type=policy_constants.CONDITION_MEMBER_PORT,
                 operator=policy_constants.CONDITION_OP_EQUALS):
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


class ConjunctionOperator(object):
    def __init__(self, operator=policy_constants.CONDITION_OP_AND):
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

    def get_obj_dict(self):
        body = super(GroupDef, self).get_obj_dict()
        conds = self.get_attr('conditions')
        if conds:
            conds = conds if isinstance(conds, list) else [conds]
            if conds:
                body['expression'] = [condition.get_obj_dict()
                                      for condition in conds]
        return body

    def update_attributes_in_body(self, **kwargs):
        body = self._get_body_from_kwargs(**kwargs)
        if 'body' in kwargs:
            del kwargs['body']
        # Fix params that need special conversions
        if kwargs.get('conditions') is not None:
            body['expression'] = [cond.get_obj_dict()
                                  for cond in kwargs['conditions']]
            del kwargs['conditions']
        super(GroupDef, self).update_attributes_in_body(body=body, **kwargs)

    def get_realized_state_path(self, ep_id):
        return REALIZED_STATE_GROUP % (self.get_tenant(), ep_id,
                                       self.get_attr('domain_id'),
                                       self.get_id())


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

    def get_obj_dict(self):
        body = super(ServiceDef, self).get_obj_dict()
        body['service_entries'] = [entry.get_obj_dict()
                                   for entry in self.service_entries]
        return body

    @staticmethod
    def sub_entries_path():
        return ServiceEntryDef().get_last_section_dict_key

    def get_realized_state_path(self, ep_id):
        return REALIZED_STATE_SERVICE % (self.get_tenant(), ep_id,
                                         self.get_id())


class ServiceEntryDef(ResourceDef):

    @property
    def path_pattern(self):
        return SERVICES_PATH_PATTERN + "%s/service-entries/"

    @property
    def path_ids(self):
        return ('tenant', 'service_id', 'entry_id')


class L4ServiceEntryDef(ServiceEntryDef):

    def get_obj_dict(self):
        body = super(L4ServiceEntryDef, self).get_obj_dict()
        body['resource_type'] = 'L4PortSetServiceEntry'
        body['l4_protocol'] = self.attrs.get('protocol', 'TCP')
        if self.get_attr('dest_ports'):
            body['destination_ports'] = self.get_attr('dest_ports')
        return body

    def update_attributes_in_body(self, **kwargs):
        # Fix params that need special conversions
        body = self._get_body_from_kwargs(**kwargs)
        if 'body' in kwargs:
            del kwargs['body']

        if kwargs.get('protocol') is not None:
            body['l4_protocol'] = kwargs['protocol'].upper()
            del kwargs['protocol']
        if kwargs.get('dest_ports') is not None:
            body['destination_ports'] = kwargs['dest_ports']
            del kwargs['dest_ports']
        super(L4ServiceEntryDef, self).update_attributes_in_body(
            body=body, **kwargs)


class IcmpServiceEntryDef(ServiceEntryDef):

    def get_obj_dict(self):
        body = super(IcmpServiceEntryDef, self).get_obj_dict()
        body['resource_type'] = 'ICMPTypeServiceEntry'
        body['protocol'] = 'ICMPv' + str(self.attrs.get('version', '4'))
        for attr in ('icmp_type', 'icmp_code'):
            if self.get_attr(attr):
                body[attr] = self.get_attr(attr)
        return body

    def update_attributes_in_body(self, **kwargs):
        # Fix params that need special conversions
        body = self._get_body_from_kwargs(**kwargs)
        if 'body' in kwargs:
            del kwargs['body']

        if kwargs.get('version') is not None:
            body['protocol'] = 'ICMPv' + str(kwargs.get('version'))
            del kwargs['version']
        super(IcmpServiceEntryDef, self).update_attributes_in_body(
            body=body, **kwargs)


class IPProtocolServiceEntryDef(ServiceEntryDef):

    def get_obj_dict(self):
        body = super(IPProtocolServiceEntryDef, self).get_obj_dict()
        body['resource_type'] = 'IPProtocolServiceEntry'
        body['protocol_number'] = self.get_attr('protocol_number')
        return body

    def update_attributes_in_body(self, **kwargs):
        # Fix params that need special conversions
        body = self._get_body_from_kwargs(**kwargs)
        if 'body' in kwargs:
            del kwargs['body']

        super(IPProtocolServiceEntryDef, self).update_attributes_in_body(
            body=body, **kwargs)


class CommunicationMapDef(ResourceDef):

    @property
    def path_pattern(self):
        return (DOMAINS_PATH_PATTERN + "%s/communication-maps/")

    @property
    def path_ids(self):
        return ('tenant', 'domain_id', 'map_id')

    def get_realized_state_path(self, ep_id):
        return REALIZED_STATE_COMM_MAP % (self.get_tenant(), ep_id,
                                          self.get_attr('domain_id'),
                                          self.get_id())

    def get_obj_dict(self):
        body = super(CommunicationMapDef, self).get_obj_dict()
        for attr in ('category', 'precedence'):
            if self.get_attr(attr):
                body[attr] = self.get_attr(attr)

        return body

    @staticmethod
    def sub_entries_path():
        return CommunicationMapEntryDef().get_last_section_dict_key


class CommunicationMapEntryDef(ResourceDef):
    def get_groups_path(self, domain_id, group_ids):
        if not group_ids:
            return [policy_constants.ANY_GROUP]
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

        return [policy_constants.ANY_SERVICE]

    @property
    def path_pattern(self):
        return (DOMAINS_PATH_PATTERN +
                "%s/communication-maps/%s/communication-entries/")

    @property
    def path_ids(self):
        return ('tenant', 'domain_id', 'map_id', 'entry_id')

    def get_obj_dict(self):
        body = super(CommunicationMapEntryDef, self).get_obj_dict()
        domain_id = self.get_attr('domain_id')
        body['source_groups'] = self.get_groups_path(
            domain_id, self.get_attr('source_groups'))
        body['destination_groups'] = self.get_groups_path(
            domain_id, self.get_attr('dest_groups'))

        for attr in ('sequence_number', 'services', 'scope',
                     'action', 'direction', 'logged'):
            if self.get_attr(attr):
                body[attr] = self.get_attr(attr)

        service_ids = self.get_attr('service_ids')
        body['services'] = self.get_services_path(service_ids)
        return body

    def update_attributes_in_body(self, **kwargs):
        body = self._get_body_from_kwargs(**kwargs)
        if 'body' in kwargs:
            del kwargs['body']
        # Fix params that need special conversions
        if kwargs.get('service_ids') is not None:
            body['services'] = [self.get_service_path(service_id) for
                                service_id in kwargs['service_ids']]
            del kwargs['service_ids']

        if kwargs.get('dest_groups') is not None:
            groups = self.get_groups_path(
                self.domain_id, kwargs['dest_groups'])
            body['destination_groups'] = groups
            del kwargs['dest_groups']

        if kwargs.get('source_groups') is not None:
            groups = self.get_groups_path(
                self.domain_id, kwargs['source_groups'])
            body['source_groups'] = groups
            del kwargs['source_groups']

        if kwargs.get('scope') is not None:
            body['scope'] = [kwargs['scope']]
            del kwargs['scope']

        if kwargs.get('direction') is not None:
            body['direction'] = [kwargs['direction']]
            del kwargs['direction']

        super(CommunicationMapEntryDef, self).update_attributes_in_body(
            body=body, **kwargs)


# Currently supports only NSXT
class EnforcementPointDef(ResourceDef):

    @property
    def path_pattern(self):
        return (TENANTS_PATH_PATTERN +
                'sites/default/enforcement-points/')

    @property
    def path_ids(self):
        return ('tenant', 'ep_id')

    def get_obj_dict(self):
        body = super(EnforcementPointDef, self).get_obj_dict()
        body['id'] = self.get_id()
        body['connection_info'] = {
            'thumbprint': self.get_attr('thumbprint'),
            'username': self.get_attr('username'),
            'password': self.get_attr('password'),
            'enforcement_point_address': self.get_attr('ip_address'),
            'resource_type': 'NSXTConnectionInfo'}

        if self.get_attr('edge_cluster_id'):
            body['connection_info']['edge_cluster_ids'] = [
                self.get_attr('edge_cluster_id')]

        if self.get_attr('transport_zone_id'):
            body['connection_info']['transport_zone_ids'] = [
                self.get_attr('transport_zone_id')]

        body['resource_type'] = 'EnforcementPoint'
        return body

    def update_attributes_in_body(self, **kwargs):
        body = self._get_body_from_kwargs(**kwargs)
        if 'body' in kwargs:
            del kwargs['body']
        # Fix params that need special conversions
        if not body.get('connection_info'):
            body['connection_info'] = {}
        body['connection_info']['resource_type'] = 'NSXTConnectionInfo'
        body['resource_type'] = 'EnforcementPoint'

        for attr in ('username', 'password', 'ip_address', 'thumbprint'):
            if kwargs.get(attr) is not None:
                body_attr = attr
                if attr == 'ip_address':
                    body_attr = 'enforcement_point_address'
                body['connection_info'][body_attr] = kwargs[attr]
                del kwargs[attr]

        for attr in ('edge_cluster_id', 'transport_zone_id'):
            if kwargs.get(attr) is not None:
                body_attr = attr + 's'
                body['connection_info'][body_attr] = [kwargs[attr]]
                del kwargs[attr]

        super(EnforcementPointDef, self).update_attributes_in_body(
            body=body, **kwargs)

    def get_realized_state_path(self):
        return REALIZED_STATE_EF % (self.get_tenant(), self.get_id())


# Currently assumes one deployment point per id
class DeploymentMapDef(ResourceDef):

    @property
    def path_pattern(self):
        return (DOMAINS_PATH_PATTERN + '%s/domain-deployment-maps/')

    @property
    def path_ids(self):
        return ('tenant', 'domain_id', 'map_id')

    def get_obj_dict(self):
        body = super(DeploymentMapDef, self).get_obj_dict()
        body['id'] = self.get_id()
        ep_id = self.get_attr('ep_id')
        tenant = self.get_tenant()
        body['enforcement_point_path'] = EnforcementPointDef(
            ep_id=ep_id,
            tenant=tenant).get_resource_full_path() if ep_id else None
        return body

    def update_attributes_in_body(self, **kwargs):
        body = self._get_body_from_kwargs(**kwargs)
        if 'body' in kwargs:
            del kwargs['body']
        # Fix params that need special conversions
        if kwargs.get('domain_id') is not None:
            domain_id = kwargs.get('domain_id')
            domain_path = DomainDef(
                domain_id=domain_id,
                tenant=self.get_tenant()).get_resource_full_path()
            body['parent_path'] = domain_path
            del kwargs['domain_id']

        if kwargs.get('ep_id') is not None:
            ep_id = kwargs.get('ep_id')
            ep_path = EnforcementPointDef(
                ep_id=ep_id,
                tenant=self.get_tenant()).get_resource_full_path()
            body['enforcement_point_path'] = ep_path
            del kwargs['ep_id']

        super(DeploymentMapDef, self).update_attributes_in_body(
            body=body, **kwargs)


class NsxPolicyApi(object):

    def __init__(self, client):
        self.client = client

    def create_or_update(self, resource_def):
        """Create or update a policy object.

        This api will update an existing object, or create a new one if it
        doesn't exist.
        The policy API supports PATCH for create/update operations
        """
        path = resource_def.get_resource_path()
        body = resource_def.body
        if not body:
            body = resource_def.get_obj_dict()
        self.client.patch(path, body)
        return self.client.get(path)

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
        return self.client.get(path)

    def delete(self, resource_def):
        path = resource_def.get_resource_path()
        self.client.delete(path)

    def get(self, resource_def, silent=False):
        path = resource_def.get_resource_path()
        return self.client.get(path, silent=silent)

    def list(self, resource_def):
        path = resource_def.get_section_path()
        return self.client.list(path)

    def get_by_path(self, path):
        return self.client.get(path)
