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


@six.add_metaclass(abc.ABCMeta)
class ResourceDef(object):
    def __init__(self):
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

    def get_last_section_dict_key(self):
        last_section = self.path_pattern.split("/")[-2]
        return last_section.replace('-', '_')


# TODO(annak): /tenants soon to be removed from the URI
class DomainDef(ResourceDef):

    def __init__(self,
                 domain_id=None,
                 name=None,
                 description=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        self.id = domain_id
        self.name = name
        self.description = description
        self.parent_ids = (tenant)

    @property
    def path_pattern(self):
        return "tenants/%s/domains/"


class Condition(object):
    KEY_TAG = 'Tag'
    KEY_NAME = 'Name'

    MEMBER_VM = 'VirtualMachine'
    MEMBER_PORT = 'LogicalPort'
    MEMBER_NET = 'LogicalSwitch'

    OP_EQUALS = 'EQUALS'
    OP_CONTAINS = 'CONTAINS'
    OP_STARTS_WITH = 'STARTSWITH'

    def __init__(self, value, key=KEY_TAG,
                 member_type=MEMBER_PORT,
                 operator=OP_EQUALS):
        self.value = value
        self.key = key
        self.member_type = member_type
        self.operator = operator

    def get_obj_dict(self):
        return {'member_type': self.member_type,
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
        return "tenants/%s/domains/%s/groups/"

    def get_obj_dict(self):
        body = super(GroupDef, self).get_obj_dict()
        if self.conditions:
            body['expression'] = [condition.get_obj_dict()
                                  for condition in self.conditions]
        return body


class ServiceDef(ResourceDef):
    def __init__(self,
                 service_id=None,
                 name=None,
                 description=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        self.id = service_id
        self.name = name
        self.description = description
        self.parent_ids = (tenant)
        self.service_entries = []

    @property
    def path_pattern(self):
        return "tenants/%s/services/"

    def get_obj_dict(self):
        body = super(ServiceDef, self).get_obj_dict()
        body['service_entries'] = [entry.get_obj_dict()
                                   for entry in self.service_entries]
        return body


class L4ServiceEntryDef(ResourceDef):
    def __init__(self,
                 service_id=None,
                 service_entry_id=None,
                 name=None,
                 description=None,
                 protocol=policy_constants.TCP,
                 dest_ports=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        self.id = service_entry_id
        self.name = name
        self.description = description
        self.protocol = protocol
        self.dest_ports = dest_ports
        self.parent_ids = (tenant, service_id)

    @property
    def path_pattern(self):
        return "tenants/%s/services/%s/service-entries/"

    def get_obj_dict(self):
        body = super(L4ServiceEntryDef, self).get_obj_dict()
        body['resource_type'] = 'L4PortSetServiceEntry'
        body['l4_protocol'] = self.protocol
        body['destination_ports'] = self.dest_ports
        return body


class ContractDef(ResourceDef):
    def __init__(self,
                 contract_id=None,
                 name=None,
                 description=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        self.id = contract_id
        self.name = name
        self.description = description
        self.parent_ids = (tenant)

    @property
    def path_pattern(self):
        return "tenants/%s/contracts/"


class ContractEntryDef(ResourceDef):
    def __init__(self,
                 contract_id=None,
                 contract_entry_id=None,
                 name=None,
                 description=None,
                 services=None,
                 action=policy_constants.CONTRACT_ALLOW,
                 tenant=policy_constants.POLICY_INFRA_TENANT):
        self.id = contract_entry_id
        self.name = name
        self.description = description
        self.services = [self._service_path_from_id(service)
                         for service in services] if services else []
        self.action = action
        self.parent_ids = (tenant, contract_id)

    @staticmethod
    def _service_path_from_id(service_id):
        return '/' + ServiceDef(service_id=service_id).get_resource_path()

    @property
    def path_pattern(self):
        return "tenants/%s/contracts/%s/contract-entries/"

    def get_obj_dict(self):
        body = super(ContractEntryDef, self).get_obj_dict()
        body['services'] = self.services
        body['action'] = self.action
        return body


class ContractMapDef(ResourceDef):
    def __init__(self,
                 domain_id,
                 contract_map_id,
                 sequence_number,
                 source_groups,
                 dest_groups,
                 contract_id,
                 name=None,
                 description=None,
                 tenant=policy_constants.POLICY_INFRA_TENANT):

        self.domain_id = domain_id
        self.id = contract_map_id
        self.name = name
        self.description = description
        self.sequence_number = sequence_number

        # convert groups and contract to full path
        def get_group_path(group_id):
            return GroupDef(domain_id,
                            group_id,
                            tenant=tenant).get_resource_path()

        self.source_groups = [get_group_path(group_id)
                              for group_id in source_groups]
        self.dest_groups = [get_group_path(group_id)
                            for group_id in dest_groups]
        self.contract = ContractDef(contract_id,
                                    tenant=tenant).get_resource_path()
        self.parent_ids = (tenant, domain_id)

    @property
    def path_pattern(self):
        return "tenants/%s/domains/%s/connectivity-rules/contract-maps/"

    def get_obj_dict(self):
        body = super(ContractMapDef, self).get_obj_dict()
        body['source_groups'] = self.source_groups
        body['destination_groups'] = self.dest_groups
        body['sequence_number'] = self.sequence_number
        body['contract_path'] = self.contract
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
