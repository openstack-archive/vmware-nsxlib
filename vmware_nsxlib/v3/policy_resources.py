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
import uuid

from oslo_log import log as logging
import six

from vmware_nsxlib._i18n import _
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
    def create_or_overwrite(self, *args, **kwargs):
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

    def _get_realized_state(self, path):
        try:
            result = self.policy_api.get_by_path(path)
            if result and result.get('state'):
                return result['state']
        except exceptions.BackendResourceNotFound:
            # resource not deployed yet
            LOG.warning("No realized state found for %s", path)


class NsxPolicyDomainApi(NsxPolicyResourceBase):
    """NSX Policy Domain."""
    def create_or_overwrite(self, name, domain_id=None, description=None,
                            tenant=policy_constants.POLICY_INFRA_TENANT):
        domain_id = self._init_obj_uuid(domain_id)
        domain_def = policy_defs.DomainDef(domain_id=domain_id,
                                           name=name,
                                           description=description,
                                           tenant=tenant)
        return self.policy_api.create_or_update(domain_def)

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
        domain_def.update_attributes_in_body(name=name,
                                             description=description)
        # update the backend
        return self.policy_api.create_or_update(domain_def)


class NsxPolicyGroupApi(NsxPolicyResourceBase):
    """NSX Policy Group (under a Domain) with a single condition."""
    def create_or_overwrite(
        self, name, domain_id, group_id=None,
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
        return self.policy_api.create_or_update(group_def)

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
        group_def.update_attributes_in_body(name=name,
                                            description=description)
        # update the backend
        return self.policy_api.create_or_update(group_def)

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
        # We need to do that here because of the conditions data
        group = self.get(domain_id, group_id, tenant=tenant)
        group_def.update_attributes_in_body(body=group, conditions=conditions)
        # update the backend
        return self.policy_api.create_or_update(group_def)

    def get_realized_state(self, domain_id, group_id, ep_id,
                           tenant=policy_constants.POLICY_INFRA_TENANT):
        group_def = policy_defs.GroupDef(domain_id=domain_id,
                                         group_id=group_id,
                                         tenant=tenant)
        path = group_def.get_realized_state_path(ep_id)
        return self._get_realized_state(path)


class NsxPolicyServiceBase(NsxPolicyResourceBase):
    """Base class for NSX Policy Service with a single entry.

    Note the nsx-policy backend supports multiple service entries per service.
    At this point this is not supported here.
    """
    def delete(self, service_id,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        """Delete the service with all its entries"""
        service_def = policy_defs.ServiceDef(service_id=service_id,
                                             tenant=tenant)
        service = self.policy_api.get(service_def)
        # first delete all the service entries
        if 'service_entries' in service:
            for entry in service['service_entries']:
                entry_def = self.entry_def(
                    service_id=service_id,
                    service_entry_id=entry['id'],
                    tenant=tenant)
                self.policy_api.delete(entry_def)
        self.policy_api.delete(service_def)

    def get(self, service_id,
            tenant=policy_constants.POLICY_INFRA_TENANT):
        service_def = policy_defs.ServiceDef(service_id=service_id,
                                             tenant=tenant)
        return self.policy_api.get(service_def)

    def list(self, tenant=policy_constants.POLICY_INFRA_TENANT):
        service_def = policy_defs.ServiceDef(tenant=tenant)
        return self.policy_api.list(service_def)['results']

    def get_realized_state(self, service_id, ep_id,
                           tenant=policy_constants.POLICY_INFRA_TENANT):
        service_def = policy_defs.ServiceDef(service_id=service_id,
                                             tenant=tenant)
        path = service_def.get_realized_state_path(ep_id)
        return self._get_realized_state(path)

    @property
    def entry_def(self):
        pass


class NsxPolicyL4ServiceApi(NsxPolicyServiceBase):
    """NSX Policy Service with a single L4 service entry.

    Note the nsx-policy backend supports multiple service entries per service.
    At this point this is not supported here.
    """
    @property
    def entry_def(self):
        return policy_defs.L4ServiceEntryDef

    def create_or_overwrite(self, name, service_id=None, description=None,
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

    def _update_service_entry(self, service_id, srv_entry,
                              name=None, description=None,
                              protocol=None, dest_ports=None,
                              tenant=policy_constants.POLICY_INFRA_TENANT):
        entry_id = srv_entry['id']
        entry_def = policy_defs.L4ServiceEntryDef(service_id=service_id,
                                                  service_entry_id=entry_id,
                                                  tenant=tenant)
        entry_def.update_attributes_in_body(body=srv_entry, name=name,
                                            description=description,
                                            protocol=protocol,
                                            dest_ports=dest_ports)

        self.policy_api.create_or_update(entry_def)

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
            service_def.update_attributes_in_body(name=name,
                                                  description=description)

            # update the backend
            updated_service = self.policy_api.create_or_update(service_def)
        else:
            updated_service = service

        # update the service entry if it exists
        service_entry = policy_defs.ServiceDef.get_single_entry(service)
        if not service_entry:
            LOG.error("Cannot update service %s - expected 1 service "
                      "entry", service_id)
            return updated_service

        self._update_service_entry(
            service_id, service_entry,
            name=name, description=description,
            protocol=protocol, dest_ports=dest_ports,
            tenant=tenant)

        # re-read the service from the backend to return the current data
        return self.get(service_id, tenant=tenant)


class NsxPolicyIcmpServiceApi(NsxPolicyServiceBase):
    """NSX Policy Service with a single ICMP service entry.

    Note the nsx-policy backend supports multiple service entries per service.
    At this point this is not supported here.
    """
    @property
    def entry_def(self):
        return policy_defs.IcmpServiceEntryDef

    def create_or_overwrite(self, name, service_id=None, description=None,
                            version=4, icmp_type=None, icmp_code=None,
                            tenant=policy_constants.POLICY_INFRA_TENANT):
        service_id = self._init_obj_uuid(service_id)
        service_def = policy_defs.ServiceDef(service_id=service_id,
                                             name=name,
                                             description=description,
                                             tenant=tenant)
        # NOTE(asarfaty) We set the service entry display name (which is also
        # used as the id) to be the same as the service name. In case we
        # support multiple service entries, we need the name to be unique.
        entry_def = policy_defs.IcmpServiceEntryDef(
            service_id=service_id,
            name=name,
            description=description,
            version=version,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            tenant=tenant)

        return self.policy_api.create_with_parent(service_def, entry_def)

    def _update_service_entry(self, service_id, srv_entry,
                              name=None, description=None,
                              version=None, icmp_type=None, icmp_code=None,
                              tenant=policy_constants.POLICY_INFRA_TENANT):
        entry_id = srv_entry['id']
        entry_def = policy_defs.IcmpServiceEntryDef(service_id=service_id,
                                                    service_entry_id=entry_id,
                                                    tenant=tenant)
        entry_def.update_attributes_in_body(body=srv_entry, name=name,
                                            description=description,
                                            version=version,
                                            icmp_type=icmp_type,
                                            icmp_code=icmp_code)

        self.policy_api.create_or_update(entry_def)

    def update(self, service_id, name=None, description=None,
               version=None, icmp_type=None, icmp_code=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        # Get the current data of service & its' service entry
        service = self.get(service_id, tenant=tenant)

        # update the service itself:
        if name is not None or description is not None:
            # update the service itself
            service_def = policy_defs.ServiceDef(service_id=service_id,
                                                 tenant=tenant)
            service_def.update_attributes_in_body(name=name,
                                                  description=description)

            # update the backend
            updated_service = self.policy_api.create_or_update(service_def)
        else:
            updated_service = service

        # update the service entry if it exists
        service_entry = policy_defs.ServiceDef.get_single_entry(service)
        if not service_entry:
            LOG.error("Cannot update service %s - expected 1 service "
                      "entry", service_id)
            return updated_service

        self._update_service_entry(
            service_id, service_entry,
            name=name, description=description,
            version=version, icmp_type=icmp_type, icmp_code=icmp_code,
            tenant=tenant)

        # re-read the service from the backend to return the current data
        return self.get(service_id, tenant=tenant)


class NsxPolicyCommunicationProfileApi(NsxPolicyResourceBase):
    """NSX Policy Communication profile (with a single entry).

    Note the nsx-policy backend supports multiple entries per communication
    profile.
    At this point this is not supported here.
    """
    def create_or_overwrite(self, name, profile_id=None, description=None,
                            services=None,
                            action=policy_constants.ACTION_ALLOW,
                            tenant=policy_constants.POLICY_INFRA_TENANT):
        """Create a Communication profile with a single entry.

        Services should be a list of service ids
        """
        profile_id = self._init_obj_uuid(profile_id)
        profile_def = policy_defs.CommunicationProfileDef(
            profile_id=profile_id,
            name=name,
            description=description,
            tenant=tenant)
        # NOTE(asarfaty) We set the profile entry display name (which is also
        # used as the id) to be the same as the profile name. In case we
        # support multiple entries, we need the name to be unique.
        entry_def = policy_defs.CommunicationProfileEntryDef(
            profile_id=profile_id,
            name=name,
            description=description,
            services=services,
            action=action,
            tenant=tenant)

        return self.policy_api.create_with_parent(profile_def, entry_def)

    def delete(self, profile_id,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        """Delete the Communication profile with all the entries"""
        # first delete the entries, or else the profile deletion will fail
        profile_def = policy_defs.CommunicationProfileDef(
            profile_id=profile_id, tenant=tenant)
        prof = self.policy_api.get(profile_def)
        if 'communication_profile_entries' in prof:
            for entry in prof['communication_profile_entries']:
                entry_def = policy_defs.CommunicationProfileEntryDef(
                    profile_id=profile_id,
                    profile_entry_id=entry['id'],
                    tenant=tenant)
                self.policy_api.delete(entry_def)
        self.policy_api.delete(profile_def)

    def get(self, profile_id,
            tenant=policy_constants.POLICY_INFRA_TENANT):
        profile_def = policy_defs.CommunicationProfileDef(
            profile_id=profile_id, tenant=tenant)
        return self.policy_api.get(profile_def)

    def list(self, tenant=policy_constants.POLICY_INFRA_TENANT):
        profile_def = policy_defs.CommunicationProfileDef(tenant=tenant)
        return self.policy_api.list(profile_def)['results']

    def _update_profile_entry(self, profile_id, profile_entry,
                              name=None, description=None,
                              services=None, action=None,
                              tenant=policy_constants.POLICY_INFRA_TENANT):
        entry_id = profile_entry['id']
        entry_def = policy_defs.CommunicationProfileEntryDef(
            profile_id=profile_id,
            profile_entry_id=entry_id,
            tenant=tenant)
        entry_def.update_attributes_in_body(body=profile_entry,
                                            name=name,
                                            description=description,
                                            services=services,
                                            action=action)

        self.policy_api.create_or_update(entry_def)

    def update(self, profile_id, name=None, description=None,
               services=None, action=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        # Get the current data of the profile & its' entry
        profile = self.get(profile_id, tenant=tenant)

        if name is not None or description is not None:
            # update the profile itself
            profile_def = policy_defs.CommunicationProfileDef(
                profile_id=profile_id, tenant=tenant)
            profile_def.update_attributes_in_body(name=name,
                                                  description=description)

            # update the backend
            updated_profile = self.policy_api.create_or_update(profile_def)
        else:
            updated_profile = profile

        # update the profile entry if it exists
        profile_entry = policy_defs.CommunicationProfileDef.get_single_entry(
            profile)
        if not profile_entry:
            LOG.error("Cannot update communication profile %s - expected 1 "
                      "profile entry", profile_id)
            return updated_profile

        self._update_profile_entry(
            profile_id, profile_entry,
            name=name, description=description,
            services=services, action=action,
            tenant=tenant)

        # re-read the profile from the backend to return the current data
        return self.get(profile_id, tenant=tenant)


class NsxPolicyCommunicationMapApi(NsxPolicyResourceBase):
    """NSX Policy CommunicationMap (Under a Domain)."""
    def _get_last_seq_num(self, domain_id,
                          tenant=policy_constants.POLICY_INFRA_TENANT):
        # get the current entries, and choose the next unused sequence number
        try:
            com_entries = self.list(domain_id, tenant=tenant)
        except exceptions.ResourceNotFound:
            return -1
        if not com_entries:
            return 0
        seq_nums = [int(cm['sequence_number']) for cm in com_entries]
        seq_nums.sort()
        return seq_nums[-1]

    def create_or_overwrite(self, name, domain_id, map_id=None,
                            description=None, sequence_number=None,
                            profile_id=None,
                            source_groups=None, dest_groups=None,
                            tenant=policy_constants.POLICY_INFRA_TENANT):
        """Create CommunicationMapEntry.

        source_groups/dest_groups should be a list of group ids belonging
        to the domain.
        NOTE: In multi-connection environment, it is recommended to execute
        this call under lock to prevent race condition where two entries
        end up with same sequence number.
        """
        # Validate and convert inputs
        map_id = self._init_obj_uuid(map_id)
        if not profile_id:
            # profile-id must be provided
            err_msg = (_("Cannot create a communication map %(name)s without "
                         "communication profile id") % {'name': name})
            raise exceptions.ManagerError(details=err_msg)

        # get the next available sequence number
        last_sequence = self._get_last_seq_num(domain_id, tenant=tenant)
        if not sequence_number:
            if last_sequence < 0:
                sequence_number = 1
            else:
                sequence_number = last_sequence + 1

        entry_def = policy_defs.CommunicationMapEntryDef(
            domain_id=domain_id,
            map_id=map_id,
            name=name,
            description=description,
            sequence_number=sequence_number,
            source_groups=source_groups,
            dest_groups=dest_groups,
            profile_id=profile_id,
            tenant=tenant)

        if last_sequence < 0:
            # if communication map is absent, we need to create it
            map_def = policy_defs.CommunicationMapDef(domain_id, tenant)
            map_result = self.policy_api.create_with_parent(map_def, entry_def)
            # return the created entry
            return map_result['communication_entries'][0]

        return self.policy_api.create_or_update(entry_def)

    def delete(self, domain_id, map_id,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        map_def = policy_defs.CommunicationMapEntryDef(
            domain_id=domain_id,
            map_id=map_id,
            tenant=tenant)
        self.policy_api.delete(map_def)

    def get(self, domain_id, map_id,
            tenant=policy_constants.POLICY_INFRA_TENANT):
        map_def = policy_defs.CommunicationMapEntryDef(
            domain_id=domain_id,
            map_id=map_id,
            tenant=tenant)
        return self.policy_api.get(map_def)

    def get_by_name(self, domain_id, name,
                    tenant=policy_constants.POLICY_INFRA_TENANT):
        """Return first communication map entry matched by name"""
        return super(NsxPolicyCommunicationMapApi, self).get_by_name(
            name, domain_id, tenant=tenant)

    def list(self, domain_id,
             tenant=policy_constants.POLICY_INFRA_TENANT):
        """List all the map entries of a specific domain."""
        map_def = policy_defs.CommunicationMapEntryDef(
            domain_id=domain_id,
            tenant=tenant)
        return self.policy_api.list(map_def)['results']

    def update(self, domain_id, map_id, name=None, description=None,
               sequence_number=None, profile_id=None,
               source_groups=None, dest_groups=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        map_def = policy_defs.CommunicationMapEntryDef(
            domain_id=domain_id,
            map_id=map_id,
            tenant=tenant)

        # Get the current data, and update it with the new values
        try:
            comm_map = self.get(domain_id, map_id, tenant=tenant)
        except exceptions.ResourceNotFound:
            return self.create_or_overwrite(name, domain_id, map_id,
                                            description, sequence_number,
                                            profile_id, source_groups,
                                            dest_groups, tenant)

        map_def.update_attributes_in_body(
            body=comm_map,
            name=name,
            description=description,
            sequence_number=sequence_number,
            profile_id=profile_id,
            source_groups=source_groups,
            dest_groups=dest_groups)

        # update the backend
        return self.policy_api.create_or_update(map_def)

    def get_realized_state(self, domain_id, ep_id,
                           tenant=policy_constants.POLICY_INFRA_TENANT):
        map_def = policy_defs.CommunicationMapDef(domain_id, tenant)
        path = map_def.get_realized_state_path(ep_id)
        return self._get_realized_state(path)


class NsxPolicyEnforcementPointApi(NsxPolicyResourceBase):
    """NSX Policy Enforcement Point."""

    def create_or_overwrite(self, name, ep_id=None, description=None,
                            ip_address=None, username=None,
                            password=None, thumbprint=None,
                            tenant=policy_constants.POLICY_INFRA_TENANT):
        if not ip_address or not username or password is None:
            err_msg = (_("Cannot create an enforcement point without "
                         "ip_address, username and password"))
            raise exceptions.ManagerError(details=err_msg)
        ep_id = self._init_obj_uuid(ep_id)
        ep_def = policy_defs.EnforcementPointDef(
            ep_id=ep_id,
            name=name,
            description=description,
            ip_address=ip_address,
            username=username,
            password=password,
            thumbprint=thumbprint,
            tenant=tenant)
        return self.policy_api.create_or_update(ep_def)

    def delete(self, ep_id,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        ep_def = policy_defs.EnforcementPointDef(
            ep_id=ep_id, tenant=tenant)
        self.policy_api.delete(ep_def)

    def get(self, ep_id,
            tenant=policy_constants.POLICY_INFRA_TENANT):
        ep_def = policy_defs.EnforcementPointDef(
            ep_id=ep_id, tenant=tenant)
        return self.policy_api.get(ep_def)

    def list(self, tenant=policy_constants.POLICY_INFRA_TENANT):
        ep_def = policy_defs.EnforcementPointDef(tenant=tenant)
        return self.policy_api.list(ep_def)['results']

    def update(self, ep_id, name=None, description=None,
               ip_address=None, username=None,
               password=None, thumbprint=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        """Update the enforcement point.

        username & password must be defined
        """
        if not username or password is None:
            # profile-id must be provided
            err_msg = (_("Cannot update an enforcement point without "
                         "username and password"))
            raise exceptions.ManagerError(details=err_msg)

        ep_def = policy_defs.EnforcementPointDef(ep_id=ep_id, tenant=tenant)
        ep_def.update_attributes_in_body(name=name,
                                         description=description,
                                         ip_address=ip_address,
                                         username=username,
                                         password=password,
                                         thumbprint=thumbprint)
        # update the backend
        return self.policy_api.create_or_update(ep_def)

    def get_realized_state(self, ep_id,
                           tenant=policy_constants.POLICY_INFRA_TENANT):
        ep_def = policy_defs.EnforcementPointDef(ep_id=ep_id, tenant=tenant)
        path = ep_def.get_realized_state_path()
        return self._get_realized_state(path)


class NsxPolicyDeploymentMapApi(NsxPolicyResourceBase):
    """NSX Policy Deployment Map."""

    def create_or_overwrite(self, name, map_id=None, description=None,
                            ep_id=None, domain_id=None,
                            tenant=policy_constants.POLICY_INFRA_TENANT):
        map_id = self._init_obj_uuid(map_id)
        map_def = policy_defs.DeploymentMapDef(
            map_id=map_id,
            name=name,
            description=description,
            ep_id=ep_id,
            domain_id=domain_id,
            tenant=tenant)
        return self.policy_api.create_or_update(map_def)

    def delete(self, map_id, domain_id=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        if not domain_id:
            # domain_id must be provided
            err_msg = (_("Cannot delete deployment maps without a domain"))
            raise exceptions.ManagerError(details=err_msg)

        map_def = policy_defs.DeploymentMapDef(
            map_id=map_id, domain_id=domain_id, tenant=tenant)
        self.policy_api.delete(map_def)

    def get(self, map_id, domain_id=None,
            tenant=policy_constants.POLICY_INFRA_TENANT):
        if not domain_id:
            # domain_id must be provided
            err_msg = (_("Cannot get deployment maps without a domain"))
            raise exceptions.ManagerError(details=err_msg)
        map_def = policy_defs.DeploymentMapDef(
            map_id=map_id, domain_id=domain_id, tenant=tenant)
        return self.policy_api.get(map_def)

    def list(self, domain_id=None,
             tenant=policy_constants.POLICY_INFRA_TENANT):
        if not domain_id:
            # domain_id must be provided
            err_msg = (_("Cannot list deployment maps without a domain"))
            raise exceptions.ManagerError(details=err_msg)
        map_def = policy_defs.DeploymentMapDef(domain_id=domain_id,
                                               tenant=tenant)
        return self.policy_api.list(map_def)['results']

    def update(self, map_id, name=None, description=None,
               ep_id=None, domain_id=None,
               tenant=policy_constants.POLICY_INFRA_TENANT):
        map_def = policy_defs.DeploymentMapDef(
            map_id=map_id, tenant=tenant)
        map_def.update_attributes_in_body(name=name,
                                          description=description,
                                          ep_id=ep_id,
                                          domain_id=domain_id)
        # update the backend
        return self.policy_api.create_or_update(map_def)
