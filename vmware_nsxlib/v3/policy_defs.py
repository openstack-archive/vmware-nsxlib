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

# TODO(annak): /tenants soon to be removed from the URI
TENANTS_PATH_PATTERN = "%s/"
DOMAINS_PATH_PATTERN = TENANTS_PATH_PATTERN + "domains/"
CONTRACTS_PATH_PATTERN = TENANTS_PATH_PATTERN + "contracts/"
SERVICES_PATH_PATTERN = TENANTS_PATH_PATTERN + "services/"


@six.add_metaclass(abc.ABCMeta)
class ResourceDef(object):
    def __init__(self):
        self.tenant = None
        self.id = None
        self.name = None
        self.description = None
        self.parent_ids = None

    def get_obj_dict(self):
        body = {'_revision': 0,
                'display_name': self.name,
                'description': self.description}
        if self.id:
            body['id'] = self.id
        return body

    @abc.abstractproperty
    def path_pattern(self):
        pass

    def get_section_path(self):
        return self.path_pattern % self.parent_ids

    def get_resource_path(self):
        return self.get_section_path() + self.id

    def get_resource_full_path(self):
        return '/' + self.get_resource_path()

    def get_last_section_dict_key(self):
        last_section = self.path_pattern.split("/")[-2]
        return last_section.replace('-', '_')

    def update_attributes_in_body(self, body, **kwargs):
        for key, value in six.iteritems(kwargs):
            if value is not None:
                if key == 'name':
                    body['display_name'] = value
                else:
                    body[key] = value


class DomainDef(ResourceDef):

    def __init__(self,
                 domain_id=None,
                 name=None,
                 description=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        self.tenant = tenant
        self.id = domain_id
        self.name = name
        self.description = description
        self.parent_ids = (tenant)

    @property
    def path_pattern(self):
        return DOMAINS_PATH_PATTERN


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
        self.tenant = tenant
        self.id = group_id
        self.name = name
        self.description = description
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

    def update_attributes_in_body(self, body, **kwargs):
        # Fix params that need special conversions
        if kwargs.get('conditions') is not None:
            body['expression'] = [cond.get_obj_dict()
                                  for cond in kwargs['conditions']]
            del kwargs['conditions']
        super(GroupDef, self).update_attributes_in_body(body, **kwargs)


class ServiceDef(ResourceDef):
    def __init__(self,
                 service_id=None,
                 name=None,
                 description=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
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

    def update_attributes_in_body(self, body, **kwargs):
        super(ServiceDef, self).update_attributes_in_body(body, **kwargs)
        # make sure service_entries is there
        if 'service_entries' not in body:
            body['service_entries'] = []


class L4ServiceEntryDef(ResourceDef):
    def __init__(self,
                 service_id=None,
                 service_entry_id=None,
                 name=None,
                 description=None,
                 protocol=policy_constants.TCP,
                 dest_ports=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        self.tenant = tenant
        self.id = service_entry_id
        self.name = name
        self.description = description
        self.protocol = protocol.upper()
        self.dest_ports = dest_ports
        self.parent_ids = (tenant, service_id)

    @property
    def path_pattern(self):
        return SERVICES_PATH_PATTERN + "%s/service-entries/"

    def get_obj_dict(self):
        body = super(L4ServiceEntryDef, self).get_obj_dict()
        body['resource_type'] = 'L4PortSetServiceEntry'
        body['l4_protocol'] = self.protocol
        body['destination_ports'] = self.dest_ports
        return body

    def update_attributes_in_body(self, body, **kwargs):
        # Fix params that need special conversions
        if kwargs.get('protocol') is not None:
            body['l4_protocol'] = kwargs['protocol'].upper()
            del kwargs['protocol']
        if kwargs.get('dest_ports') is not None:
            body['destination_ports'] = kwargs['dest_ports']
            del kwargs['dest_ports']
        super(L4ServiceEntryDef, self).update_attributes_in_body(
            body, **kwargs)


class ContractDef(ResourceDef):
    def __init__(self,
                 contract_id=None,
                 name=None,
                 description=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        self.tenant = tenant
        self.id = contract_id
        self.name = name
        self.description = description
        self.parent_ids = (tenant)

    @property
    def path_pattern(self):
        return CONTRACTS_PATH_PATTERN

    def update_attributes_in_body(self, body, **kwargs):
        super(ContractDef, self).update_attributes_in_body(body, **kwargs)
        # make sure contract_entries is there
        if 'contract_entries' not in body:
            body['contract_entries'] = []


class ContractEntryDef(ResourceDef):
    def __init__(self,
                 contract_id=None,
                 contract_entry_id=None,
                 name=None,
                 description=None,
                 services=None,
                 action=policy_constants.CONTRACT_ALLOW,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        self.tenant = tenant
        self.id = contract_entry_id
        self.name = name
        self.description = description
        self.services = services
        self.action = action.upper()
        self.parent_ids = (tenant, contract_id)

    @property
    def path_pattern(self):
        return CONTRACTS_PATH_PATTERN + "%s/contract-entries/"

    def get_obj_dict(self):
        body = super(ContractEntryDef, self).get_obj_dict()
        body['services'] = self.services
        body['action'] = self.action
        return body

    def update_attributes_in_body(self, body, **kwargs):
        if kwargs.get('action') is not None:
            body['action'] = kwargs['action'].upper()
            del kwargs['action']
        super(ContractEntryDef, self).update_attributes_in_body(
            body, **kwargs)


class ContractMapDef(ResourceDef):
    def __init__(self,
                 domain_id=None,
                 contractmap_id=None,
                 sequence_number=None,
                 source_groups=None,
                 dest_groups=None,
                 contract_id=None,
                 name=None,
                 description=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        self.tenant = tenant
        self.domain_id = domain_id
        self.id = contractmap_id
        self.name = name
        self.description = description
        self.sequence_number = sequence_number

        self.source_groups = self.get_groups_path(domain_id, source_groups)
        self.dest_groups = self.get_groups_path(domain_id, dest_groups)
        self.contract_path = self.get_contract_path(
            contract_id) if contract_id else None
        self.parent_ids = (tenant, domain_id)

    # convert groups and contract to full path
    def get_groups_path(self, domain_id, group_ids):
        if not group_ids:
            return [policy_constants.ANY_GROUP]
        return [GroupDef(domain_id,
                         group_id,
                         tenant=self.tenant).get_resource_full_path()
                for group_id in group_ids]

    def get_contract_path(self, contract_id):
        return ContractDef(contract_id,
                           tenant=self.tenant).get_resource_full_path()

    @property
    def path_pattern(self):
        return DOMAINS_PATH_PATTERN + "%s/connectivity-rules/contract-maps/"

    def get_obj_dict(self):
        body = super(ContractMapDef, self).get_obj_dict()
        body['source_groups'] = self.source_groups
        body['destination_groups'] = self.dest_groups
        body['sequence_number'] = self.sequence_number
        body['contract_path'] = self.contract_path
        return body

    def update_attributes_in_body(self, body, **kwargs):
        # Fix params that need special conversions
        if kwargs.get('contract_id') is not None:
            contract_path = self.get_contract_path(kwargs['contract_id'])
            body['contract_path'] = contract_path
            del kwargs['contract_id']

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

        super(ContractMapDef, self).update_attributes_in_body(body, **kwargs)


class EnforcementPointDef(ResourceDef):

    def __init__(self, ep_id=None,
                 name=None,
                 ip_address=None,
                 username=None,
                 password=None,
                 ep_type='NSXT',
                 tenant=policy_constants.POLICY_INFRA_TENANT):

        self.id = ep_id
        self.name = name
        self.tenant = tenant
        self.type = ep_type
        self.username = username
        self.password = password
        self.description = None
        self.ip_address = ip_address
        self.parent_ids = (tenant)

    @property
    def path_pattern(self):
        return (TENANTS_PATH_PATTERN +
                '/deploymentzones/default-deployment-zone/enforcementpoints/')

    def get_obj_dict(self):
        body = super(EnforcementPointDef, self).get_obj_dict()
        body['id'] = self.id
        body['connection_info'] = [{'fqdn': 'abc',
                                    'thumbprint': 'abc',
                                    'username': self.username,
                                    'password': self.password,
                                    'ip_address': self.ip_address,
                                    'resource_type': 'NSXTConnectionInfo'}]
        body['enforcement_type'] = self.type
        body['resource_type'] = 'EnforcementPoint'
        return body


class NsxPolicyApi(object):

    def __init__(self, client):
        self.client = client

    def create(self, resource_def):
        path = resource_def.get_resource_path()
        return self.client.update(path, resource_def.get_obj_dict())

    def create_with_parent(self, parent_def, resource_def):
        path = parent_def.get_resource_path()
        body = parent_def.get_obj_dict()
        child_dict_key = resource_def.get_last_section_dict_key()
        body[child_dict_key] = [resource_def.get_obj_dict()]
        return self.client.update(path, body)

    def delete(self, resource_def):
        path = resource_def.get_resource_path()
        self.client.delete(path)

    def get(self, resource_def):
        path = resource_def.get_resource_path()
        return self.client.get(path)

    def list(self, resource_def):
        path = resource_def.get_section_path()
        return self.client.list(path)

    def update(self, resource_def, updated_obj_dict):
        path = resource_def.get_resource_path()
        return self.client.update(path, updated_obj_dict)
