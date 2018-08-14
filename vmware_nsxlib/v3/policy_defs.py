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
PROVIDERS_PATH_PATTERN = TENANTS_PATH_PATTERN + "providers/"
NETWORKS_PATH_PATTERN = TENANTS_PATH_PATTERN + "networks/"
SEGMENTS_PATH_PATTERN = NETWORKS_PATH_PATTERN + "%s/segments/"
PORTS_PATH_PATTERN = SEGMENTS_PATH_PATTERN + "%s/ports/"
SERVICES_PATH_PATTERN = TENANTS_PATH_PATTERN + "services/"
REALIZED_STATE_EF = (TENANTS_PATH_PATTERN +
                     "realized-state/enforcement-points/%s/")
REALIZED_STATE_GROUP = REALIZED_STATE_EF + "groups/nsgroups/%s-%s"
REALIZED_STATE_COMM_MAP = (REALIZED_STATE_EF +
                           "firewalls/firewall-sections/%s.%s")
REALIZED_STATE_SERVICE = REALIZED_STATE_EF + "services/nsservices/services:%s"


@six.add_metaclass(abc.ABCMeta)
class ResourceDef(object):
    def __init__(self):
        self.tenant = None
        self.id = None
        self.name = None
        self.description = None
        self.parent_ids = None
        self.tags = None
        self.body = {}

    def get_obj_dict(self):
        body = {'display_name': self.name,
                'description': self.description}
        if self.id:
            body['id'] = self.id
        if self.tags:
            body['tags'] = self.tags
        return body

    def add_tags(self, tags):
        self.tags = tags

    @abc.abstractproperty
    def path_pattern(self):
        pass

    def get_section_path(self):
        return self.path_pattern % self.parent_ids

    def get_resource_path(self):
        if self.id:
            return self.get_section_path() + self.id
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

    def __init__(self,
                 domain_id=None,
                 name=None,
                 description=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        super(DomainDef, self).__init__()
        self.tenant = tenant
        self.id = domain_id
        self.name = name
        self.description = description
        self.parent_ids = (tenant)

    @property
    def path_pattern(self):
        return DOMAINS_PATH_PATTERN


class NetworkDef(ResourceDef):

    def __init__(self,
                 network_id=None,
                 name=None,
                 description=None,
                 provider=None,
                 ip_addresses=None,
                 ha_mode=policy_constants.ACTIVE_STANDBY,
                 force_whitelisting=False,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        super(NetworkDef, self).__init__()
        self.tenant = tenant
        self.id = network_id
        self.name = name
        self.description = description
        # TODO(annak): replace with provider path when provider is exposed
        if provider:
            self.provider = "/" + TENANTS_PATH_PATTERN % tenant + \
                            "providers/" + provider
        else:
            self.provider = None
        self.ip_addresses = ip_addresses
        self.ha_mode = ha_mode
        self.force_whitelisting = force_whitelisting
        self.parent_ids = (tenant)

    @property
    def path_pattern(self):
        return NETWORKS_PATH_PATTERN

    def get_obj_dict(self):
        body = super(NetworkDef, self).get_obj_dict()
        body['provider'] = self.provider
        body['ha_mode'] = self.ha_mode
        body['force_whitelisting'] = self.force_whitelisting
        if self.ip_addresses:
            body['ip_addresses'] = self.ip_addresses
        return body


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
class SegmentDef(ResourceDef):
    def __init__(self,
                 network_id,
                 segment_id=None,
                 name=None,
                 description=None,
                 subnets=None,
                 dns_domain_name=None,
                 vlan_ids=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        super(SegmentDef, self).__init__()
        self.tenant = tenant
        self.id = segment_id
        self.name = name
        self.description = description
        self.dns_domain_name = dns_domain_name
        self.vlan_ids = vlan_ids
        self.subnets = subnets
        self.parent_ids = (tenant, network_id)

    @property
    def path_pattern(self):
        return NETWORKS_PATH_PATTERN + "%s/segments/"

    def get_obj_dict(self):
        body = super(SegmentDef, self).get_obj_dict()
        if self.subnets:
            body['subnets'] = [subnet.get_obj_dict()
                               for subnet in self.subnets]
        if self.dns_domain_name:
            body['domain_name'] = self.dns_domain_name
        if self.vlan_ids:
            body['vlan_ids'] = self.vlan_ids
        return body


class PortDef(ResourceDef):

    def __init__(self,
                 port_id=None,
                 segment_id=None,
                 network_id=None,
                 name=None,
                 description=None,
                 app_id=None,
                 vif_type=None,
                 context_id=None,
                 allocate_addresses=None,
                 traffic_tag=None,
                 tags=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT
                 ):
        super(PortDef, self).__init__()
        self.tenant = tenant
        self.id = port_id
        self.name = name
        self.description = description
        self.app_id = app_id
        self.vif_type = vif_type
        self.context_id = context_id
        self.allocate_addresses = allocate_addresses
        self.traffic_tag = traffic_tag
        self.tags = tags
        self.parent_ids = (tenant, network_id, segment_id)

    @property
    def path_pattern(self):
        return PORTS_PATH_PATTERN

    def get_obj_dict(self):
        body = super(PortDef, self).get_obj_dict()
        port_attachment = {}
        if self.tags:
            body['tags'] = self.tags
        if self.traffic_tag:
            port_attachment['traffic_tag'] = self.traffic_tag
        if self.app_id:
            port_attachment['app_id'] = self.app_id
        if self.context_id:
            port_attachment['context_id'] = self.context_id
        if self.allocate_addresses:
            port_attachment['allocate_addresses'] = self.allocate_addresses
        if self.vif_type:
            port_attachment['type'] = self.vif_type
        if port_attachment:
            body[policy_constants.SEGMENT_PORT_ATTACHMENT] = port_attachment
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


class GroupDef(ResourceDef):
    def __init__(self,
                 domain_id=None,
                 group_id=None,
                 name=None,
                 description=None,
                 conditions=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        super(GroupDef, self).__init__()
        self.tenant = tenant
        self.id = group_id
        self.name = name
        self.description = description
        self.domain_id = domain_id
        self.parent_ids = (tenant, domain_id)
        if conditions and isinstance(conditions, Condition):
            self.conditions = [conditions]
        else:
            self.conditions = conditions

    @property
    def path_pattern(self):
        return DOMAINS_PATH_PATTERN + "%s/groups/"

    def get_obj_dict(self):
        body = super(GroupDef, self).get_obj_dict()
        if self.conditions:
            body['expression'] = [condition.get_obj_dict()
                                  for condition in self.conditions]
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
        return REALIZED_STATE_GROUP % (self.tenant, ep_id,
                                       self.domain_id, self.id)


class ServiceDef(ResourceDef):
    def __init__(self,
                 service_id=None,
                 name=None,
                 description=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        super(ServiceDef, self).__init__()
        self.tenant = tenant
        self.id = service_id
        self.name = name
        self.description = description
        self.parent_ids = (tenant)
        self.service_entries = []

    @property
    def path_pattern(self):
        return SERVICES_PATH_PATTERN

    def get_obj_dict(self):
        body = super(ServiceDef, self).get_obj_dict()
        body['service_entries'] = [entry.get_obj_dict()
                                   for entry in self.service_entries]
        return body

    @staticmethod
    def sub_entries_path():
        return ServiceEntryDef().get_last_section_dict_key

    def get_realized_state_path(self, ep_id):
        return REALIZED_STATE_SERVICE % (self.tenant, ep_id,
                                         self.id)


class ServiceEntryDef(ResourceDef):

    def __init__(self):
        super(ServiceEntryDef, self).__init__()

    @property
    def path_pattern(self):
        return SERVICES_PATH_PATTERN + "%s/service-entries/"


class L4ServiceEntryDef(ServiceEntryDef):
    def __init__(self,
                 service_id=None,
                 service_entry_id=None,
                 name=None,
                 description=None,
                 protocol=policy_constants.TCP,
                 dest_ports=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        super(L4ServiceEntryDef, self).__init__()
        self.tenant = tenant
        self.id = service_entry_id
        self.name = name
        self.description = description
        self.protocol = protocol.upper()
        self.dest_ports = dest_ports
        self.parent_ids = (tenant, service_id)

    def get_obj_dict(self):
        body = super(L4ServiceEntryDef, self).get_obj_dict()
        body['resource_type'] = 'L4PortSetServiceEntry'
        body['l4_protocol'] = self.protocol
        body['destination_ports'] = self.dest_ports
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
    def __init__(self,
                 service_id=None,
                 service_entry_id=None,
                 name=None,
                 description=None,
                 version=4,
                 icmp_type=None,
                 icmp_code=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        super(IcmpServiceEntryDef, self).__init__()
        self.tenant = tenant
        self.id = service_entry_id
        self.name = name
        self.description = description
        self.version = version
        self.icmp_type = icmp_type
        self.icmp_code = icmp_code
        self.parent_ids = (tenant, service_id)

    def get_obj_dict(self):
        body = super(IcmpServiceEntryDef, self).get_obj_dict()
        body['resource_type'] = 'ICMPTypeServiceEntry'
        body['protocol'] = 'ICMPv' + str(self.version)
        if self.icmp_type:
            body['icmp_type'] = self.icmp_type
        if self.icmp_code:
            body['icmp_code'] = self.icmp_code
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


class CommunicationMapDef(ResourceDef):
    def __init__(self,
                 map_id=None,
                 domain_id=None,
                 category=policy_constants.CATEGORY_DEFAULT,
                 name=None,
                 precedence=0,
                 description=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        super(CommunicationMapDef, self).__init__()
        self.id = map_id
        self.category = category
        self.precedence = precedence
        self.name = name
        self.description = description
        self.tenant = tenant
        self.domain_id = domain_id
        self.parent_ids = (tenant, domain_id)

    @property
    def path_pattern(self):
        return (DOMAINS_PATH_PATTERN + "%s/communication-maps/")

    def get_realized_state_path(self, ep_id):
        return REALIZED_STATE_COMM_MAP % (self.tenant, ep_id, self.domain_id,
                                          self.id)

    def get_obj_dict(self):
        body = super(CommunicationMapDef, self).get_obj_dict()
        if self.category:
            body['category'] = self.category
        if self.precedence:
            body['precedence'] = self.precedence
        return body

    @staticmethod
    def sub_entries_path():
        return CommunicationMapEntryDef().get_last_section_dict_key


class CommunicationMapEntryDef(ResourceDef):
    def __init__(self,
                 domain_id=None,
                 map_id=None,
                 entry_id=None,
                 sequence_number=None,
                 source_groups=None,
                 dest_groups=None,
                 service_ids=None,
                 action=policy_constants.ACTION_ALLOW,
                 scope="ANY",
                 name=None,
                 description=None,
                 direction=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        super(CommunicationMapEntryDef, self).__init__()
        self.tenant = tenant
        self.domain_id = domain_id
        self.map_id = map_id,
        self.id = entry_id
        self.name = name
        self.description = description
        self.sequence_number = sequence_number
        self.action = action
        self.scope = scope
        self.source_groups = self.get_groups_path(domain_id, source_groups)
        self.dest_groups = self.get_groups_path(domain_id, dest_groups)
        self.service_paths = [self.get_service_path(service_id) for service_id
                              in service_ids] if service_ids else []
        self.direction = direction
        self.parent_ids = (tenant, domain_id, map_id)

    # convert groups and services to full path
    def get_groups_path(self, domain_id, group_ids):
        if not group_ids:
            return [policy_constants.ANY_GROUP]
        return [GroupDef(domain_id,
                         group_id,
                         tenant=self.tenant).get_resource_full_path()
                for group_id in group_ids]

    def get_service_path(self, service_id):
        return ServiceDef(
            service_id,
            tenant=self.tenant).get_resource_full_path()

    @property
    def path_pattern(self):
        return (DOMAINS_PATH_PATTERN +
                "%s/communication-maps/%s/communication-entries/")

    def get_obj_dict(self):
        body = super(CommunicationMapEntryDef, self).get_obj_dict()
        body['source_groups'] = self.source_groups
        body['destination_groups'] = self.dest_groups
        body['sequence_number'] = self.sequence_number
        body['services'] = self.service_paths
        body['scope'] = [self.scope]
        body['action'] = self.action
        body['direction'] = self.direction
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

    def __init__(self, ep_id=None,
                 name=None,
                 description=None,
                 ip_address=None,
                 username=None,
                 password=None,
                 thumbprint=None,
                 edge_cluster_id=None,
                 transport_zone_id=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        super(EnforcementPointDef, self).__init__()
        self.id = ep_id
        self.name = name
        self.description = description
        self.tenant = tenant
        self.username = username
        self.password = password
        self.ip_address = ip_address
        self.thumbprint = thumbprint
        self.edge_cluster_id = edge_cluster_id
        self.transport_zone_id = transport_zone_id
        self.parent_ids = (tenant)

    @property
    def path_pattern(self):
        return (TENANTS_PATH_PATTERN +
                'deployment-zones/default/enforcement-points/')

    def get_obj_dict(self):
        body = super(EnforcementPointDef, self).get_obj_dict()
        body['id'] = self.id
        body['connection_info'] = {
            'thumbprint': self.thumbprint,
            'username': self.username,
            'password': self.password,
            'enforcement_point_address': self.ip_address,
            'resource_type': 'NSXTConnectionInfo'}
        if self.edge_cluster_id:
            body['connection_info']['edge_cluster_ids'] = [
                self.edge_cluster_id]
        if self.transport_zone_id:
            body['connection_info']['transport_zone_ids'] = [
                self.transport_zone_id]

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
        return REALIZED_STATE_EF % (self.tenant, self.id)


# Currently assumes one deployment point per id
class DeploymentMapDef(ResourceDef):

    def __init__(self, map_id=None,
                 name=None,
                 description=None,
                 domain_id=None,
                 ep_id=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        super(DeploymentMapDef, self).__init__()
        self.id = map_id
        self.name = name
        self.description = description
        # convert enforcement point id to path
        self.ep_path = EnforcementPointDef(
            ep_id,
            tenant=tenant).get_resource_full_path() if ep_id else None
        self.tenant = tenant
        self.parent_ids = (tenant, domain_id)

    @property
    def path_pattern(self):
        return (DOMAINS_PATH_PATTERN + '%s/domain-deployment-maps/')

    def get_obj_dict(self):
        body = super(DeploymentMapDef, self).get_obj_dict()
        body['id'] = self.id
        body['enforcement_point_path'] = self.ep_path
        return body

    def update_attributes_in_body(self, **kwargs):
        body = self._get_body_from_kwargs(**kwargs)
        if 'body' in kwargs:
            del kwargs['body']
        # Fix params that need special conversions
        if kwargs.get('domain_id') is not None:
            domain_id = kwargs.get('domain_id')
            domain_path = DomainDef(
                domain_id, tenant=self.tenant).get_resource_full_path()
            body['parent_path'] = domain_path
            del kwargs['domain_id']

        if kwargs.get('ep_id') is not None:
            ep_id = kwargs.get('ep_id')
            ep_path = EnforcementPointDef(
                ep_id, tenant=self.tenant).get_resource_full_path()
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

    def get(self, resource_def):
        path = resource_def.get_resource_path()
        return self.client.get(path)

    def list(self, resource_def):
        path = resource_def.get_section_path()
        return self.client.list(path)

    def get_by_path(self, path):
        return self.client.get(path)
