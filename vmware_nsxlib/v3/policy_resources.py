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

from oslo_log import log as logging

from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import policy_constants
from vmware_nsxlib.v3 import policy_defs

LOG = logging.getLogger(__name__)

# TODO(asarfaty): support retries?
# TODO(asarfaty): In future versions PATCH may be supported for update


@six.add_metaclass(abc.ABCMeta)
class NsxPolicyResourceBase(object):
    """Abstract class for NSX policy resources

    declaring the basic apis each policy resource should support,
    and implement some common apis and utilities
    """
    def __init__(self, policy_api):
        self.policy_api = policy_api

    @abc.abstractmethod
    def list(self, *args, **kwargs):
        pass

    @abc.abstractmethod
    def get(self, uuid, *args, **kwargs):
        pass

    @abc.abstractmethod
    def delete(self, uuid, *args, **kwargs):
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

    def get_by_name(self, name, *args, **kwargs):
        # Return first match by name
        resources_list = self.list(*args, **kwargs)
        for obj in resources_list:
            if obj.get('display_name') == name:
                return obj


class NsxPolicyDomainApi(NsxPolicyResourceBase):
    """NSX Policy Domain."""
    def create(self, name, domain_id=None, description=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        domain_id = self._init_obj_uuid(domain_id)
        domain_def = policy_defs.DomainDef(domain_id=domain_id,
                                           name=name,
                                           description=description,
                                           tenant=tenant)
        return self.policy_api.create(domain_def)

    def delete(self, domain_id, tenant=policy_constants.POLICY_INFRA_TENANT):
        domain_def = policy_defs.DomainDef(domain_id, tenant=tenant)
        self.policy_api.delete(domain_def)

    def get(self, domain_id, tenant=policy_constants.POLICY_INFRA_TENANT):
        domain_def = policy_defs.DomainDef(domain_id, tenant=tenant)
        return self.policy_api.get(domain_def)

    def list(self, tenant=policy_constants.POLICY_INFRA_TENANT):
        domain_def = policy_defs.DomainDef(tenant=tenant)
        return self.policy_api.list(domain_def)['results']

    def update(self, domain_id, name=None, description=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        domain_def = policy_defs.DomainDef(domain_id=domain_id,
                                           tenant=tenant)
        # Get the current data, and update it with the new values
        domain = self.get(domain_id, tenant=tenant)
        domain_def.update_attributes_in_body(domain,
                                             name=name,
                                             description=description)
        # update the backend
        return self.policy_api.update(domain_def, domain)


class NsxPolicyGroupApi(NsxPolicyResourceBase):
    """NSX Policy Group (under a Domain) with a single condition."""
    def create(self, name, domain_id, group_id=None,
               description=None,
               cond_val=None,
               cond_key=policy_constants.CONDITION_KEY_TAG,
               cond_op=policy_constants.CONDITION_OP_EQUALS,
               cond_member_type=policy_constants.CONDITION_MEMBER_PORT,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        """Create a group with/without a condition.

        Empty condition value will result a group with no condition.
        """

        group_id = self._init_obj_uuid(group_id)
        # Prepare the condition
        if cond_val is not None:
            condition = policy_defs.Condition(value=cond_val,
                                              key=cond_key,
                                              operator=cond_op,
                                              member_type=cond_member_type)
            conditions = [condition]
        else:
            conditions = []
        group_def = policy_defs.GroupDef(domain_id=domain_id,
                                         group_id=group_id,
                                         name=name,
                                         description=description,
                                         conditions=conditions,
                                         tenant=tenant)
        return self.policy_api.create(group_def)

    def delete(self, domain_id, group_id,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        group_def = policy_defs.GroupDef(domain_id=domain_id,
                                         group_id=group_id,
                                         tenant=tenant)
        self.policy_api.delete(group_def)

    def get(self, domain_id, group_id,
            tenant=policy_constants.POLICY_INFRA_TENANT):
        group_def = policy_defs.GroupDef(domain_id=domain_id,
                                         group_id=group_id,
                                         tenant=tenant)
        return self.policy_api.get(group_def)

    def list(self, domain_id,
             tenant=policy_constants.POLICY_INFRA_TENANT):
        """List all the groups of a specific domain."""
        group_def = policy_defs.GroupDef(domain_id=domain_id,
                                         tenant=tenant)
        return self.policy_api.list(group_def)['results']

    def get_by_name(self, domain_id, name,
                    tenant=policy_constants.POLICY_INFRA_TENANT):
        """Return first group matched by name of this domain"""
        return super(NsxPolicyGroupApi, self).get_by_name(name, domain_id,
                                                          tenant=tenant)

    def update(self, domain_id, group_id, name=None, description=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        """Update the general data of the group.

        Without changing the conditions
        """
        group_def = policy_defs.GroupDef(domain_id=domain_id,
                                         group_id=group_id,
                                         tenant=tenant)
        # Get the current data, and update it with the new values
        group = self.get(domain_id, group_id, tenant=tenant)
        group_def.update_attributes_in_body(group,
                                            name=name,
                                            description=description)
        # update the backend
        return self.policy_api.update(group_def, group)

    def update_condition(
        self, domain_id, group_id,
        cond_val=None,
        cond_key=policy_constants.CONDITION_KEY_TAG,
        cond_op=policy_constants.CONDITION_OP_EQUALS,
        cond_member_type=policy_constants.CONDITION_MEMBER_PORT,
        tenant=policy_constants.POLICY_INFRA_TENANT):
        """Update/Remove the condition of a group.

        Empty condition value will result a group with no condition.
        """
        group_def = policy_defs.GroupDef(domain_id=domain_id,
                                         group_id=group_id,
                                         tenant=tenant)

        # Prepare the condition
        if cond_val is not None:
            condition = policy_defs.Condition(value=cond_val,
                                              key=cond_key,
                                              operator=cond_op,
                                              member_type=cond_member_type)
            conditions = [condition]
        else:
            conditions = []
        # Get the current data, and update it with the new values
        group = self.get(domain_id, group_id, tenant=tenant)
        group_def.update_attributes_in_body(group,
                                            conditions=conditions)
        # update the backend
        return self.policy_api.update(group_def, group)


class NsxPolicyL4ServiceApi(NsxPolicyResourceBase):
    """NSX Policy Service (with a single L4 service entry).

    Note the nsx-policy backend supports different types of service entries,
    and multiple service entries per service.
    At this point this is not supported here.
    """
    def create(self, name, service_id=None, description=None,
               protocol=policy_constants.TCP, dest_ports=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        service_id = self._init_obj_uuid(service_id)
        service_def = policy_defs.ServiceDef(service_id=service_id,
                                             name=name,
                                             description=description,
                                             tenant=tenant)
        # NOTE(asarfaty) We set the service entry display name (which is also
        # used as the id) to be the same as the service name. In case we
        # support multiple service entries, we need the name to be unique.
        entry_def = policy_defs.L4ServiceEntryDef(
            service_id=service_id,
            name=name,
            description=description,
            protocol=protocol,
            dest_ports=dest_ports,
            tenant=tenant)

        return self.policy_api.create_with_parent(service_def, entry_def)

    def delete(self, service_id,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        service_def = policy_defs.ServiceDef(service_id=service_id,
                                             tenant=tenant)
        self.policy_api.delete(service_def)

    def get(self, service_id,
            tenant=policy_constants.POLICY_INFRA_TENANT):
        service_def = policy_defs.ServiceDef(service_id=service_id,
                                             tenant=tenant)
        return self.policy_api.get(service_def)

    def list(self, tenant=policy_constants.POLICY_INFRA_TENANT):
        service_def = policy_defs.ServiceDef(tenant=tenant)
        return self.policy_api.list(service_def)['results']

    def _update_service_entry(self, service_id, srv_entry,
                              name=None, description=None,
                              protocol=None, dest_ports=None,
                              tenant=policy_constants.POLICY_INFRA_TENANT):
        entry_id = srv_entry['id']
        entry_def = policy_defs.L4ServiceEntryDef(service_id=service_id,
                                                  service_entry_id=entry_id,
                                                  tenant=tenant)
        entry_def.update_attributes_in_body(srv_entry,
                                            name=name,
                                            description=description,
                                            protocol=protocol,
                                            dest_ports=dest_ports)

        self.policy_api.update(entry_def, srv_entry)

    def update(self, service_id, name=None, description=None,
               protocol=None, dest_ports=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        # Get the current data of service & its' service entry
        service = self.get(service_id, tenant=tenant)

        # update the service itself:
        if name is not None or description is not None:
            # update the service itself
            service_def = policy_defs.ServiceDef(service_id=service_id,
                                                 tenant=tenant)
            service_def.update_attributes_in_body(service,
                                                  name=name,
                                                  description=description)

            # update the backend
            updated_service = self.policy_api.update(service_def, service)
        else:
            updated_service = service

        # update the service entry if it exists
        if ('service_entries' not in service or
            len(service['service_entries']) != 1):
            LOG.error("Cannot update service %s - expected 1 service "
                      "entry", service_id)
            return updated_service

        service_entry = service['service_entries'][0]
        self._update_service_entry(
            service_id, service_entry,
            name=name, description=description,
            protocol=protocol, dest_ports=dest_ports,
            tenant=tenant)

        # re-read the service from the backend to return the current data
        updated_service = self.get(service_id, tenant=tenant)
        return updated_service


class NsxContractApi(NsxPolicyResourceBase):
    """NSX Policy Contract (with a single contract-entry).

    Note the nsx-policy backend supports multiple entries per contract.
    At this point this is not supported here.
    """
    def create(self, name, contract_id=None, description=None,
               services=None, action=policy_constants.CONTRACT_ALLOW,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        """Create a Contract with a single entry.

        Services should be a list of service ids
        """
        contract_id = self._init_obj_uuid(contract_id)
        contract_def = policy_defs.ContractDef(contract_id=contract_id,
                                               name=name,
                                               description=description,
                                               tenant=tenant)
        # NOTE(asarfaty) We set the contract entry display name (which is also
        # used as the id) to be the same as the contract name. In case we
        # support multiple contract entries, we need the name to be unique.
        entry_def = policy_defs.ContractEntryDef(contract_id=contract_id,
                                                 name=name,
                                                 description=description,
                                                 services=services,
                                                 action=action,
                                                 tenant=tenant)

        return self.policy_api.create_with_parent(contract_def, entry_def)

    def delete(self, contract_id,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        contract_def = policy_defs.ContractDef(contract_id=contract_id,
                                               tenant=tenant)
        self.policy_api.delete(contract_def)

    def get(self, contract_id,
            tenant=policy_constants.POLICY_INFRA_TENANT):
        contract_def = policy_defs.ContractDef(contract_id=contract_id,
                                               tenant=tenant)
        return self.policy_api.get(contract_def)

    def list(self, tenant=policy_constants.POLICY_INFRA_TENANT):
        contract_def = policy_defs.ContractDef(tenant=tenant)
        return self.policy_api.list(contract_def)['results']

    def _update_contract_entry(self, contract_id, contract_entry,
                               name=None, description=None,
                               services=None, action=None,
                               tenant=policy_constants.POLICY_INFRA_TENANT):
        entry_id = contract_entry['id']
        entry_def = policy_defs.ContractEntryDef(contract_id=contract_id,
                                                 contract_entry_id=entry_id,
                                                 tenant=tenant)
        entry_def.update_attributes_in_body(contract_entry,
                                            name=name,
                                            description=description,
                                            services=services,
                                            action=action)

        self.policy_api.update(entry_def, contract_entry)

    def update(self, contract_id, name=None, description=None,
               services=None, action=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        # Get the current data of the contract & its' entry
        contract = self.get(contract_id, tenant=tenant)

        if name is not None or description is not None:
            # update the contract itself
            contract_def = policy_defs.ContractDef(contract_id=contract_id,
                                                   tenant=tenant)
            contract_def.update_attributes_in_body(contract,
                                                   name=name,
                                                   description=description)

            # update the backend
            updated_contract = self.policy_api.update(contract_def, contract)
        else:
            updated_contract = contract

        # update the contract entry if it exists
        if ('contract_entries' not in contract or
            len(contract['contract_entries']) != 1):
            LOG.error("Cannot update contract %s - expected 1 contract "
                      "entry", contract_id)
            return updated_contract

        contract_entry = contract['contract_entries'][0]
        self._update_contract_entry(
            contract_id, contract_entry,
            name=name, description=description,
            services=services, action=action,
            tenant=tenant)

        # re-read the contract from the backend to return the current data
        updated_contract = self.get(contract_id, tenant=tenant)
        return updated_contract


class NsxContractMapApi(NsxPolicyResourceBase):
    """NSX Policy ContractMap (Under a Domain)."""
    def _get_next_seq_num(self, domain_id,
                          tenant=policy_constants.POLICY_INFRA_TENANT):
        # get the current entries, and choose the next unused sequence number
        contract_maps = self.list(domain_id, tenant=tenant)
        if not contract_maps:
            return 0

        seq_nums = [int(cm['sequence_number']) for cm in contract_maps]
        seq_nums.sort()
        return seq_nums[-1] + 1

    def create(self, name, domain_id, contractmap_id=None,
               description=None, sequence_number=None, contract_id=None,
               source_groups=None, dest_groups=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        """Create a ContractMap.

        source_groups/dest_groups should be a list of group ids belonging
        to the domain.
        """
        # Validate and convert inputs
        contractmap_id = self._init_obj_uuid(contractmap_id)
        if not contract_id:
            # contract_id must be provided
            err_msg = (_("Cannot create a contract map %(name)s without "
                         "contract id") % {'name': name})
            raise exceptions.ManagerError(details=err_msg)
        if sequence_number is None:
            # get the next available sequence number
            sequence_number = self._get_next_seq_num(domain_id, tenant=tenant)

        contractmap_def = policy_defs.ContractMapDef(
            domain_id=domain_id,
            contractmap_id=contractmap_id,
            name=name,
            description=description,
            sequence_number=sequence_number,
            source_groups=source_groups,
            dest_groups=dest_groups,
            contract_id=contract_id,
            tenant=tenant)
        return self.policy_api.create(contractmap_def)

    def delete(self, domain_id, contractmap_id,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        contractmap_def = policy_defs.ContractMapDef(
            domain_id=domain_id,
            contractmap_id=contractmap_id,
            tenant=tenant)
        self.policy_api.delete(contractmap_def)

    def get(self, domain_id, contractmap_id,
            tenant=policy_constants.POLICY_INFRA_TENANT):
        contractmap_def = policy_defs.ContractMapDef(
            domain_id=domain_id,
            contractmap_id=contractmap_id,
            tenant=tenant)
        return self.policy_api.get(contractmap_def)

    def get_by_name(self, domain_id, name,
                    tenant=policy_constants.POLICY_INFRA_TENANT):
        """Return first contract map matched by name of this domain"""
        return super(NsxContractMapApi, self).get_by_name(name, domain_id,
                                                          tenant=tenant)

    def list(self, domain_id,
             tenant=policy_constants.POLICY_INFRA_TENANT):
        """List all the groups of a specific domain."""
        contractmap_def = policy_defs.ContractMapDef(
            domain_id=domain_id,
            tenant=tenant)
        return self.policy_api.list(contractmap_def)['results']

    def update(self, domain_id, contractmap_id, name=None,
               description=None, sequence_number=None, contract_id=None,
               source_groups=None, dest_groups=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        contractmap_def = policy_defs.ContractMapDef(
            domain_id=domain_id,
            contractmap_id=contractmap_id,
            tenant=tenant)
        # Get the current data, and update it with the new values
        contractmap = self.get(domain_id, contractmap_id, tenant=tenant)
        contractmap_def.update_attributes_in_body(
            contractmap,
            name=name,
            description=description,
            sequence_number=sequence_number,
            contract_id=contract_id,
            source_groups=source_groups,
            dest_groups=dest_groups)

        # update the backend
        return self.policy_api.update(contractmap_def, contractmap)
