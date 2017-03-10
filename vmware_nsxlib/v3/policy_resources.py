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
import uuid

from vmware_nsxlib.v3 import policy_constants
from vmware_nsxlib.v3 import policy_defs


# TODO(asarfaty): support retries
# TODO(asarfaty): support different tenants
# TODO(asarfaty): use create_with_parent
# TODO(asarfaty): use PATCH method instead of get+post for update
@six.add_metaclass(abc.ABCMeta)
class NsxPolicyResourceBase(object):
    """Abstract class for NSX policy resources

    declaring the basic apis each policy resource should support
    """
    def __init__(self, policy_api):
        self.policy_api = policy_api

    @abc.abstractmethod
    def list(self):
        pass

    @abc.abstractmethod
    def get(self, uuid):
        pass

    @abc.abstractmethod
    def delete(self, uuid):
        pass

    @abc.abstractmethod
    def create(self, *args, **kwargs):
        pass

    @abc.abstractmethod
    def update(self, uuid, *args, **kwargs):
        pass

    @staticmethod
    def _init_obj_uuid(obj_uuid):
        if not obj_uuid:
            # generate a random id
            obj_uuid = str(uuid.uuid4())
        return obj_uuid

    def get_by_name(self, name):
        # Return first match by name
        resources_list = self.list()
        for obj in resources_list:
            if obj.get('display_name') == name:
                return obj


class NsxPolicyDomainApi(NsxPolicyResourceBase):

    def create(self, name, domain_id=None, description=None):
        domain_id = self._init_obj_uuid(domain_id)
        domain_def = policy_defs.DomainDef(domain_id=domain_id,
                                           name=name,
                                           description=description)
        return self.policy_api.create(domain_def)

    def delete(self, domain_id):
        domain_def = policy_defs.DomainDef(domain_id)
        self.policy_api.delete(domain_def)

    def get(self, domain_id):
        domain_def = policy_defs.DomainDef(domain_id)
        return self.policy_api.get(domain_def)

    def list(self):
        # TODO(asarfaty) - this currently fails. Cursor issue.
        # maybe because the deleted domains are still in the list?
        domain_def = policy_defs.DomainDef()
        return self.policy_api.list(domain_def)['results']

    def update(self, domain_id, name=None, description=None):
        # Get the current data
        domain = self.get(domain_id)
        if name is not None:
            domain['display_name'] = name
        if description is not None:
            domain['description'] = description

        domain_def = policy_defs.DomainDef(domain_id=domain_id)
        return self.policy_api.update(domain_def, domain)


class NsxPolicyGroupApi(NsxPolicyResourceBase):
    def create(self, group_name, domain_id, group_id=None,
               description=None, conditions=None):
        """Create a group under a specific domain."""
        group_id = self._init_obj_uuid(group_id)
        group_def = policy_defs.GroupDef(domain_id=domain_id,
                                         group_id=group_id,
                                         name=group_name,
                                         description=description,
                                         conditions=conditions)
        return self.policy_api.create(group_def)

    def delete(self, domain_id, group_id):
        group_def = policy_defs.GroupDef(domain_id=domain_id,
                                         group_id=group_id)
        self.policy_api.delete(group_def)

    def get(self, domain_id, group_id):
        group_def = policy_defs.GroupDef(domain_id=domain_id,
                                         group_id=group_id)
        return self.policy_api.get(group_def)

    def list(self, domain_id):
        """List all the groups of a specific domain."""
        group_def = policy_defs.GroupDef(domain_id=domain_id)
        return self.policy_api.list(group_def)['results']

    def update(self, domain_id, group_id,
               group_name=None, description=None, conditions=None):
        # Get the current data
        group = self.get(domain_id, group_id)
        if group_name is not None:
            group['display_name'] = group_name
        if description is not None:
            group['description'] = description
        if conditions is not None:
            group['expression'] = conditions

        group_def = policy_defs.GroupDef(domain_id=domain_id,
                                         group_id=group_id)
        return self.policy_api.update(group_def, group)

    def get_by_name(self, domain_id, name):
        """Return first group matched by name of this domain"""
        resources_list = self.list(domain_id)
        for obj in resources_list:
            if obj.get('display_name') == name:
                return obj


class NsxPolicyL4ServiceApi(NsxPolicyResourceBase):
    """Api for handling a Service with a single L4 service entry.

    Note the nsx-policy backend supports different types of service entries,
    and multiple service entries per service.
    At this point this is not supported here.
    """
    def create(self, service_name, service_id=None,
               description=None, protocol=policy_constants.TCP,
               dest_ports=None):
        # TODO(asarfaty) this currently fails. resource type error
        service_id = self._init_obj_uuid(service_id)
        service_def = policy_defs.ServiceDef(service_id=service_id,
                                             name=service_name,
                                             description=description)
        # DEBUG ADIT need service_entry_id?
        service_entry_id = str(uuid.uuid4())
        entry_def = policy_defs.L4ServiceEntryDef(
            service_id=service_id,
            service_entry_id=service_entry_id,
            name=service_name,
            description=description,
            protocol=protocol,
            dest_ports=dest_ports)

        return self.policy_api.create_with_parent(service_def, entry_def)

    def create_without_entry(self, service_name, service_id=None,
                             description=None):
        # TODO(asarfaty) not sure this is actually needed.
        service_id = self._init_obj_uuid(service_id)
        service_def = policy_defs.ServiceDef(service_id=service_id,
                                             name=service_name,
                                             description=description)
        return self.policy_api.create(service_def)

    def delete(self, service_id):
        service_def = policy_defs.ServiceDef(service_id=service_id)
        self.policy_api.delete(service_def)

    def get(self, service_id):
        service_def = policy_defs.ServiceDef(service_id=service_id)
        return self.policy_api.get(service_def)

    def update(self, service_id, service_name=None, description=None,
               protocol=None, dest_ports=None):
        # Get the current data
        service = self.get(service_id)
        if service_name is not None:
            service['display_name'] = service_name
        if description is not None:
            service['description'] = description
        if 'service_entries' not in service:
            service['service_entries'] = []

        service_def = policy_defs.ServiceDef(service_id=service_id)
        # TODO(asarfaty): Update the service entry too
        return self.policy_api.update(service_def, service)

    def list(self):
        service_def = policy_defs.ServiceDef()
        return self.policy_api.list(service_def)['results']


class NsxContractApi(NsxPolicyResourceBase):
    """Api for handling a Contract with a single contract-entry.

    Note the nsx-policy backend supports multiple entries per contract.
    At this point this is not supported here.

    Services should be a list of service ids
    """
    def create(self, contract_name, contract_id=None, description=None,
               services=None, action=policy_constants.CONTRACT_ALLOW):
        contract_id = self._init_obj_uuid(contract_id)
        contract_def = policy_defs.ContractDef(contract_id=contract_id,
                                               name=contract_name,
                                               description=description)
        # DEBUG ADIT need contract_entry_id?
        entry_id = str(uuid.uuid4())
        entry_def = policy_defs.ContractEntryDef(contract_id=contract_id,
                                                 contract_entry_id=entry_id,
                                                 name=contract_name,
                                                 description=description,
                                                 services=services,
                                                 action=action)

        return self.policy_api.create_with_parent(contract_def, entry_def)

    def delete(self, contract_id):
        contract_def = policy_defs.ContractDef(contract_id=contract_id)
        self.policy_api.delete(contract_def)

    def get(self, contract_id):
        contract_def = policy_defs.ContractDef(contract_id=contract_id)
        return self.policy_api.get(contract_def)

    def list(self):
        # TODO(asarfaty) - this currently fails. Cursor issue.
        contract_def = policy_defs.ContractDef()
        return self.policy_api.list(contract_def)['results']

    def update(self, contract_id, contract_name=None, description=None,
               services=None, action=None):
        # Get the current data
        contract = self.get(contract_id)
        if contract_name is not None:
            contract['display_name'] = contract_name
        if description is not None:
            contract['description'] = description
        if 'contract_entries' not in contract:
            contract['contract_entries'] = []

        contract_def = policy_defs.ContractDef(contract_id=contract_id)
        # TODO(asarfaty): Update the contract entry too
        return self.policy_api.update(contract_def, contract)
