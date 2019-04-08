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
import sys

import decorator
import eventlet
from oslo_log import log as logging
from oslo_utils import uuidutils
import six

from vmware_nsxlib._i18n import _
from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import utils

from vmware_nsxlib.v3.policy import constants
from vmware_nsxlib.v3.policy import core_defs
from vmware_nsxlib.v3.policy import transaction as trans
from vmware_nsxlib.v3.policy import utils as p_utils

LOG = logging.getLogger(__name__)

# Sentitel object to indicate unspecified attribute value
# None value in attribute would indicate "unset" functionality,
# while "ignore" means that the value not be present in request
# body
IGNORE = object()

DEFAULT_MAP_ID = 'DEFAULT'


@decorator.decorator
def check_allowed_passthrough(f, *args, **kwargs):
    resource_api = args[0]
    if not resource_api.nsx_api:
        caller = sys._getframe(1).f_code.co_name
        LOG.error("%s failed: Passthrough api is disabled", caller)
        return

    return f(*args, **kwargs)


@six.add_metaclass(abc.ABCMeta)
class NsxPolicyResourceBase(object):
    """Abstract class for NSX policy resources

    declaring the basic apis each policy resource should support,
    and implement some common apis and utilities
    """
    SINGLE_ENTRY_ID = 'entry'

    def __init__(self, policy_api, nsx_api, version, nsxlib_config):
        self.policy_api = policy_api
        self.nsx_api = nsx_api
        self.version = version
        self.nsxlib_config = nsxlib_config

    @property
    def entry_def(self):
        pass

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
        """Create new or overwrite existing resource

           Create would list keys and attributes, set defaults and
           perform nesessary validations.
           If object with same IDs exists on backend, it will
           be overriden.
        """
        pass

    @abc.abstractmethod
    def update(self, *args, **kwargs):
        """Update existing resource

           Update is different from create since it specifies only
           attributes that need changing. Non-updateble attributes
           should not be listed as update arguments.
           Create_or_overwrite is not
           good enough since it sets defaults, and thus would return
           non-default values to default if not specified in kwargs.
        """
        pass

    def _any_arg_set(self, *args):
        """Helper to identify if user specified any of args"""
        for arg in args:
            if arg != IGNORE:
                return True

        return False

    def _get_user_args(self, **kwargs):
        return {key: value for key, value in kwargs.items()
                if value != IGNORE}

    def _init_def(self, **kwargs):
        """Helper for update function - ignore attrs without explicit value"""
        args = self._get_user_args(**kwargs)
        return self.entry_def(**args)

    def _init_parent_def(self, **kwargs):
        """Helper for update function - ignore attrs without explicit value"""
        args = self._get_user_args(**kwargs)
        return self.parent_entry_def(**args)

    def _get_and_update_def(self, **kwargs):
        """Helper for update function - ignore attrs without explicit value"""
        args = self._get_user_args(**kwargs)
        resource_def = self.entry_def(**args)
        body = self.policy_api.get(resource_def)
        if body:
            resource_def.set_obj_dict(body)

        return resource_def

    def _update(self, **kwargs):
        """Helper for update function - ignore attrs without explicit value"""

        policy_def = self._init_def(**kwargs)
        if policy_def.bodyless():
            # Nothing to update - only keys provided in kwargs
            return

        self.policy_api.create_or_update(policy_def)

    @staticmethod
    def _init_obj_uuid(obj_uuid):
        if not obj_uuid:
            # generate a random id
            obj_uuid = str(uuidutils.generate_uuid())
        return obj_uuid

    def _canonize_name(self, name):
        # remove spaces and slashes from objects names
        return name.replace(' ', '_').replace('/', '_')

    def get_by_name(self, name, *args, **kwargs):
        # Return first match by name
        resources_list = self.list(*args, **kwargs)
        for obj in resources_list:
            if obj.get('display_name') == name:
                return obj

    def _get_realization_info(self, resource_def, entity_type=None,
                              silent=False):
        entities = []
        try:
            path = resource_def.get_resource_full_path()
            entities = self.policy_api.get_realized_entities(
                path, silent=silent)
            if entities:
                if entity_type:
                    # look for the entry with the right entity_type
                    for entity in entities:
                        if entity.get('entity_type') == entity_type:
                            return entity
                else:
                    # return the first realization entry
                    # (Useful for resources with single realization entity)
                    return entities[0]
        except exceptions.ResourceNotFound:
            pass

        # If we got here the resource was not deployed yet
        if silent:
            LOG.debug("No realization info found for %(path)s type %(type)s: "
                      "%(entities)s",
                      {"path": path, "type": entity_type,
                       "entities": entities})
        else:
            LOG.warning("No realization info found for %(path)s type %(type)s",
                        {"path": path, "type": entity_type})

    def _get_realized_state(self, resource_def, entity_type=None,
                            realization_info=None):
        if not realization_info:
            realization_info = self._get_realization_info(
                resource_def, entity_type=entity_type)
        if realization_info and realization_info.get('state'):
            return realization_info['state']

    def _get_realized_id(self, resource_def, entity_type=None,
                         realization_info=None):
        if not realization_info:
            realization_info = self._get_realization_info(
                resource_def, entity_type=entity_type)
        if (realization_info and
            realization_info.get('realization_specific_identifier')):
            return realization_info['realization_specific_identifier']

    def _wait_until_realized(self, resource_def, entity_type=None,
                             sleep=None, max_attempts=None):
        """Wait until the resource has been realized

        Return the realization info, or raise an error
        """
        if sleep is None:
            sleep = self.nsxlib_config.realization_wait_sec
        if max_attempts is None:
            max_attempts = self.nsxlib_config.realization_max_attempts

        @utils.retry_upon_none_result(max_attempts, delay=sleep, random=True)
        def get_info():
            info = self._get_realization_info(
                resource_def, entity_type=entity_type, silent=True)
            if info and info['state'] == constants.STATE_REALIZED:
                return info

        try:
            return get_info()
        except Exception:
            # max retries reached
            err_msg = (_("%(type)s ID %(id)s was not realized after "
                         "%(attempts)s attempts with %(sleep)s seconds "
                         "sleep") %
                       {'type': resource_def.resource_type(),
                        'id': resource_def.get_id(),
                        'attempts': max_attempts,
                        'sleep': sleep})
            raise exceptions.ManagerError(details=err_msg)

    def _get_extended_attr_from_realized_info(self, realization_info,
                                              requested_attr):
        # Returns a list. In case a single value is expected,
        # caller must extract the first index to retrieve the value
        if realization_info:
            try:
                for attr in realization_info.get('extended_attributes', []):
                    if attr.get('key') == requested_attr:
                        return attr.get('values')
            except IndexError:
                return

    def _list(self, obj_def):
        return self.policy_api.list(obj_def).get('results', [])

    def _create_or_store(self, policy_def, child_def=None):
        transaction = trans.NsxPolicyTransaction.get_current()
        if transaction:
            # Store this def for batch apply for this transaction
            transaction.store_def(policy_def, self.policy_api.client)
            if child_def and not policy_def.mandatory_child_def:
                transaction.store_def(child_def, self.policy_api.client)
        else:
            # No transaction - apply now
            if child_def:
                self.policy_api.create_with_parent(policy_def, child_def)
            else:
                self.policy_api.create_or_update(policy_def)


class NsxPolicyDomainApi(NsxPolicyResourceBase):
    """NSX Policy Domain."""
    @property
    def entry_def(self):
        return core_defs.DomainDef

    def create_or_overwrite(self, name, domain_id=None,
                            description=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        domain_id = self._init_obj_uuid(domain_id)
        domain_def = self._init_def(domain_id=domain_id,
                                    name=name,
                                    description=description,
                                    tags=tags,
                                    tenant=tenant)

        self._create_or_store(domain_def)
        return domain_id

    def delete(self, domain_id, tenant=constants.POLICY_INFRA_TENANT):
        domain_def = core_defs.DomainDef(domain_id=domain_id, tenant=tenant)
        self.policy_api.delete(domain_def)

    def get(self, domain_id, tenant=constants.POLICY_INFRA_TENANT,
            silent=False):
        domain_def = core_defs.DomainDef(domain_id=domain_id, tenant=tenant)
        return self.policy_api.get(domain_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        domain_def = core_defs.DomainDef(tenant=tenant)
        return self._list(domain_def)

    def update(self, domain_id, name=IGNORE,
               description=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(domain_id=domain_id,
                     name=name,
                     description=description,
                     tags=tags,
                     tenant=tenant)


class NsxPolicyGroupApi(NsxPolicyResourceBase):
    """NSX Policy Group (under a Domain) with condition/s"""
    @property
    def entry_def(self):
        return core_defs.GroupDef

    def create_or_overwrite(
        self, name, domain_id, group_id=None,
        description=IGNORE,
        cond_val=None,
        cond_key=constants.CONDITION_KEY_TAG,
        cond_op=constants.CONDITION_OP_EQUALS,
        cond_member_type=constants.CONDITION_MEMBER_PORT,
        tags=IGNORE,
        tenant=constants.POLICY_INFRA_TENANT):
        """Create a group with/without a condition.

        Empty condition value will result a group with no condition.
        """

        group_id = self._init_obj_uuid(group_id)
        # Prepare the condition
        if cond_val is not None:
            condition = core_defs.Condition(value=cond_val,
                                            key=cond_key,
                                            operator=cond_op,
                                            member_type=cond_member_type)
            conditions = [condition]
        else:
            conditions = []
        group_def = self._init_def(domain_id=domain_id,
                                   group_id=group_id,
                                   name=name,
                                   description=description,
                                   conditions=conditions,
                                   tags=tags,
                                   tenant=tenant)
        self._create_or_store(group_def)
        return group_id

    def build_condition(
        self, cond_val=None,
        cond_key=constants.CONDITION_KEY_TAG,
        cond_op=constants.CONDITION_OP_EQUALS,
        cond_member_type=constants.CONDITION_MEMBER_PORT):
        return core_defs.Condition(value=cond_val,
                                   key=cond_key,
                                   operator=cond_op,
                                   member_type=cond_member_type)

    def build_ip_address_expression(self, ip_addresses):
        return core_defs.IPAddressExpression(ip_addresses)

    def build_path_expression(self, paths):
        return core_defs.PathExpression(paths)

    def build_union_condition(self, operator=constants.CONDITION_OP_OR,
                              conditions=None):
        expressions = []
        for cond in conditions:
            if len(expressions):
                expressions.append(core_defs.ConjunctionOperator(
                    operator=operator))
            expressions.append(cond)
        return expressions

    def build_nested_condition(
        self, operator=constants.CONDITION_OP_AND,
        conditions=None):
        expressions = self.build_union_condition(
            operator=operator, conditions=conditions)
        return core_defs.NestedExpression(expressions=expressions)

    def create_or_overwrite_with_conditions(
        self, name, domain_id, group_id=None,
        description=IGNORE,
        conditions=IGNORE, tags=IGNORE,
        tenant=constants.POLICY_INFRA_TENANT):
        """Create a group with a list of conditions.

        To build the conditions in the list, build_condition
        or build_nested_condition can be used
        """
        group_id = self._init_obj_uuid(group_id)
        if not conditions:
            conditions = []
        group_def = self._init_def(domain_id=domain_id,
                                   group_id=group_id,
                                   name=name,
                                   description=description,
                                   conditions=conditions,
                                   tags=tags,
                                   tenant=tenant)
        self._create_or_store(group_def)
        return group_id

    def delete(self, domain_id, group_id,
               tenant=constants.POLICY_INFRA_TENANT):
        group_def = core_defs.GroupDef(domain_id=domain_id,
                                       group_id=group_id,
                                       tenant=tenant)
        self.policy_api.delete(group_def)

    def get(self, domain_id, group_id,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        group_def = core_defs.GroupDef(domain_id=domain_id,
                                       group_id=group_id,
                                       tenant=tenant)
        return self.policy_api.get(group_def, silent=silent)

    def list(self, domain_id,
             tenant=constants.POLICY_INFRA_TENANT):
        """List all the groups of a specific domain."""
        group_def = core_defs.GroupDef(domain_id=domain_id,
                                       tenant=tenant)
        return self._list(group_def)

    def get_by_name(self, domain_id, name,
                    tenant=constants.POLICY_INFRA_TENANT):
        """Return first group matched by name of this domain"""
        return super(NsxPolicyGroupApi, self).get_by_name(name, domain_id,
                                                          tenant=tenant)

    def update(self, domain_id, group_id,
               name=IGNORE, description=IGNORE,
               tags=IGNORE, tenant=constants.POLICY_INFRA_TENANT):
        self._update(domain_id=domain_id,
                     group_id=group_id,
                     name=name,
                     description=description,
                     tags=tags,
                     tenant=tenant)

    def get_realized_state(self, domain_id, group_id, entity_type=None,
                           tenant=constants.POLICY_INFRA_TENANT,
                           realization_info=None):
        group_def = core_defs.GroupDef(domain_id=domain_id,
                                       group_id=group_id,
                                       tenant=tenant)
        return self._get_realized_state(group_def, entity_type=entity_type,
                                        realization_info=realization_info)

    def get_realized_id(self, domain_id, group_id, entity_type=None,
                        tenant=constants.POLICY_INFRA_TENANT,
                        realization_info=None):
        group_def = core_defs.GroupDef(domain_id=domain_id,
                                       group_id=group_id,
                                       tenant=tenant)
        return self._get_realized_id(group_def, entity_type=entity_type,
                                     realization_info=realization_info)

    def get_realization_info(self, domain_id, group_id, entity_type=None,
                             tenant=constants.POLICY_INFRA_TENANT):
        group_def = core_defs.GroupDef(domain_id=domain_id,
                                       group_id=group_id,
                                       tenant=tenant)
        return self._get_realization_info(group_def, entity_type=entity_type)

    def get_path(self, domain_id, group_id,
                 tenant=constants.POLICY_INFRA_TENANT):
        group_def = self.entry_def(domain_id=domain_id,
                                   group_id=group_id,
                                   tenant=tenant)
        return group_def.get_resource_full_path()

    def wait_until_realized(self, domain_id, group_id,
                            entity_type=None,
                            tenant=constants.POLICY_INFRA_TENANT,
                            sleep=None, max_attempts=None):
        group_def = self.entry_def(domain_id=domain_id, group_id=group_id,
                                   tenant=tenant)
        return self._wait_until_realized(group_def, entity_type=entity_type,
                                         sleep=sleep,
                                         max_attempts=max_attempts)


class NsxPolicyServiceBase(NsxPolicyResourceBase):
    """Base class for NSX Policy Service with a single entry.

    Note the nsx-policy backend supports multiple service entries per service.
    At this point this is not supported here.
    """

    @property
    def parent_entry_def(self):
        return core_defs.ServiceDef

    def delete(self, service_id,
               tenant=constants.POLICY_INFRA_TENANT):
        """Delete the service with all its entries"""
        service_def = core_defs.ServiceDef(service_id=service_id,
                                           tenant=tenant)
        self.policy_api.delete(service_def)

    def get(self, service_id,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        service_def = core_defs.ServiceDef(service_id=service_id,
                                           tenant=tenant)
        return self.policy_api.get(service_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        service_def = core_defs.ServiceDef(tenant=tenant)
        return self._list(service_def)

    def get_realized_state(self, service_id, entity_type=None,
                           tenant=constants.POLICY_INFRA_TENANT,
                           realization_info=None):
        service_def = core_defs.ServiceDef(service_id=service_id,
                                           tenant=tenant)
        return self._get_realized_state(service_def, entity_type=entity_type,
                                        realization_info=realization_info)

    def get_realized_id(self, service_id, entity_type=None,
                        tenant=constants.POLICY_INFRA_TENANT,
                        realization_info=None):
        service_def = core_defs.ServiceDef(service_id=service_id,
                                           tenant=tenant)
        return self._get_realized_id(service_def, entity_type=entity_type,
                                     realization_info=realization_info)

    def get_realization_info(self, service_id, entity_type=None,
                             tenant=constants.POLICY_INFRA_TENANT):
        service_def = core_defs.ServiceDef(service_id=service_id,
                                           tenant=tenant)
        return self._get_realization_info(service_def,
                                          entity_type=entity_type)


class NsxPolicyL4ServiceApi(NsxPolicyServiceBase):
    """NSX Policy Service with a single L4 service entry.

    Note the nsx-policy backend supports multiple service entries per service.
    At this point this is not supported here.
    """

    @property
    def entry_def(self):
        return core_defs.L4ServiceEntryDef

    def create_or_overwrite(self, name, service_id=None,
                            description=IGNORE,
                            protocol=constants.TCP,
                            dest_ports=IGNORE,
                            source_ports=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        service_id = self._init_obj_uuid(service_id)
        service_def = self._init_parent_def(service_id=service_id,
                                            name=name,
                                            description=description,
                                            tags=tags,
                                            tenant=tenant)
        entry_def = self._init_def(service_id=service_id,
                                   entry_id=self.SINGLE_ENTRY_ID,
                                   name=self.SINGLE_ENTRY_ID,
                                   protocol=protocol,
                                   dest_ports=dest_ports,
                                   source_ports=source_ports,
                                   tenant=tenant)

        service_def.mandatory_child_def = entry_def
        self._create_or_store(service_def, entry_def)
        return service_id

    def update(self, service_id,
               name=IGNORE, description=IGNORE,
               protocol=IGNORE, dest_ports=IGNORE, source_ports=IGNORE,
               tags=IGNORE, tenant=constants.POLICY_INFRA_TENANT):

        parent_def = self._init_parent_def(
            service_id=service_id,
            name=name,
            description=description,
            tags=tags,
            tenant=tenant)

        entry_def = self._get_and_update_def(
            service_id=service_id,
            entry_id=self.SINGLE_ENTRY_ID,
            protocol=protocol,
            dest_ports=dest_ports,
            source_ports=source_ports,
            tenant=tenant)

        self.policy_api.create_with_parent(parent_def, entry_def)

    def build_entry(self, name, service_id, entry_id,
                    description=None, protocol=None,
                    dest_ports=None, source_ports=None,
                    tags=None, tenant=constants.POLICY_INFRA_TENANT):
        return self._init_def(service_id=service_id,
                              entry_id=entry_id,
                              name=name,
                              description=description,
                              protocol=protocol,
                              dest_ports=dest_ports,
                              source_ports=source_ports,
                              tags=tags,
                              tenant=tenant)


class NsxPolicyIcmpServiceApi(NsxPolicyServiceBase):
    """NSX Policy Service with a single ICMP service entry.

    Note the nsx-policy backend supports multiple service entries per service.
    At this point this is not supported here.
    """
    @property
    def entry_def(self):
        return core_defs.IcmpServiceEntryDef

    def create_or_overwrite(self, name, service_id=None,
                            description=IGNORE,
                            version=4, icmp_type=IGNORE, icmp_code=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        service_id = self._init_obj_uuid(service_id)
        service_def = self._init_parent_def(service_id=service_id,
                                            name=name,
                                            description=description,
                                            tags=tags,
                                            tenant=tenant)
        entry_def = self._init_def(
            service_id=service_id,
            entry_id=self.SINGLE_ENTRY_ID,
            name=self.SINGLE_ENTRY_ID,
            version=version,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            tenant=tenant)

        service_def.mandatory_child_def = entry_def
        self._create_or_store(service_def, entry_def)
        return service_id

    def update(self, service_id,
               name=IGNORE, description=IGNORE,
               version=IGNORE, icmp_type=IGNORE,
               icmp_code=IGNORE, tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):

        parent_def = self._init_parent_def(
            service_id=service_id,
            name=name,
            description=description,
            tags=tags,
            tenant=tenant)

        entry_def = self._get_and_update_def(
            service_id=service_id,
            entry_id=self.SINGLE_ENTRY_ID,
            version=version,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            tenant=tenant)

        return self.policy_api.create_with_parent(parent_def, entry_def)

    def build_entry(self, name, service_id, entry_id,
                    description=None, version=4,
                    icmp_type=None, icmp_code=None,
                    tags=None, tenant=constants.POLICY_INFRA_TENANT):
        return self._init_def(service_id=service_id,
                              entry_id=entry_id,
                              name=name,
                              description=description,
                              version=version,
                              icmp_type=icmp_type,
                              icmp_code=icmp_code,
                              tags=tags,
                              tenant=tenant)


class NsxPolicyIPProtocolServiceApi(NsxPolicyServiceBase):
    """NSX Policy Service with a single IPProtocol service entry.

    Note the nsx-policy backend supports multiple service entries per service.
    At this point this is not supported here.
    """
    @property
    def entry_def(self):
        return core_defs.IPProtocolServiceEntryDef

    def create_or_overwrite(self, name, service_id=None,
                            description=IGNORE,
                            protocol_number=IGNORE, tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        service_id = self._init_obj_uuid(service_id)
        service_def = self._init_parent_def(service_id=service_id,
                                            name=name,
                                            description=description,
                                            tags=tags,
                                            tenant=tenant)
        entry_def = self._init_def(
            service_id=service_id,
            entry_id=self.SINGLE_ENTRY_ID,
            name=self.SINGLE_ENTRY_ID,
            protocol_number=protocol_number,
            tenant=tenant)

        service_def.mandatory_child_def = entry_def
        self._create_or_store(service_def, entry_def)
        return service_id

    def update(self, service_id,
               name=IGNORE, description=IGNORE,
               protocol_number=IGNORE, tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):

        parent_def = self._init_parent_def(
            service_id=service_id,
            name=name,
            description=description,
            tags=tags,
            tenant=tenant)

        entry_def = self._get_and_update_def(
            service_id=service_id,
            entry_id=self.SINGLE_ENTRY_ID,
            protocol_number=protocol_number,
            tenant=tenant)

        return self.policy_api.create_with_parent(parent_def, entry_def)

    def build_entry(self, name, service_id, entry_id,
                    description=None, protocol_number=None,
                    tags=None, tenant=constants.POLICY_INFRA_TENANT):
        return self._init_def(service_id=service_id,
                              entry_id=entry_id,
                              name=name,
                              protocol_number=protocol_number,
                              tags=tags,
                              tenant=tenant)


class NsxPolicyMixedServiceApi(NsxPolicyServiceBase):
    """NSX Policy Service with mixed service entries."""

    def create_or_overwrite(self, name, service_id,
                            description=IGNORE,
                            entries=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        service_def = self._init_parent_def(service_id=service_id,
                                            name=name,
                                            description=description,
                                            entries=entries,
                                            tags=tags,
                                            tenant=tenant)

        if entries != IGNORE:
            self._create_or_store(service_def, entries)
        else:
            self._create_or_store(service_def)
        return service_id

    def update(self, service_id,
               name=IGNORE, description=IGNORE,
               entries=IGNORE, tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):

        parent_def = self._init_parent_def(
            service_id=service_id,
            name=name,
            description=description,
            tags=tags,
            tenant=tenant)

        if entries != IGNORE:
            self.policy_api.create_with_parent(parent_def, entries)
        else:
            self.policy_api.create_or_update(parent_def)


class NsxPolicyTier1Api(NsxPolicyResourceBase):
    """NSX Tier1 API """
    LOCALE_SERVICE_SUFF = '-0'

    @property
    def entry_def(self):
        return core_defs.Tier1Def

    def build_route_advertisement(self, static_routes=False, subnets=False,
                                  nat=False, lb_vip=False, lb_snat=False):
        return core_defs.RouteAdvertisement(static_routes=static_routes,
                                            subnets=subnets,
                                            nat=nat,
                                            lb_vip=lb_vip,
                                            lb_snat=lb_snat)

    def create_or_overwrite(self, name, tier1_id=None,
                            description=IGNORE,
                            tier0=IGNORE,
                            force_whitelisting=IGNORE,
                            failover_mode=constants.NON_PREEMPTIVE,
                            route_advertisement=IGNORE,
                            dhcp_config=IGNORE,
                            disable_firewall=IGNORE,
                            ipv6_ndra_profile_id=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        tier1_id = self._init_obj_uuid(tier1_id)
        tier1_def = self._init_def(tier1_id=tier1_id,
                                   name=name,
                                   description=description,
                                   tier0=tier0,
                                   force_whitelisting=force_whitelisting,
                                   tags=tags,
                                   failover_mode=failover_mode,
                                   route_advertisement=route_advertisement,
                                   dhcp_config=dhcp_config,
                                   disable_firewall=disable_firewall,
                                   ipv6_ndra_profile_id=ipv6_ndra_profile_id,
                                   tenant=tenant)

        self._create_or_store(tier1_def)
        return tier1_id

    def delete(self, tier1_id, tenant=constants.POLICY_INFRA_TENANT):
        tier1_def = self.entry_def(tier1_id=tier1_id, tenant=tenant)
        self.policy_api.delete(tier1_def)

    def get(self, tier1_id, tenant=constants.POLICY_INFRA_TENANT,
            silent=False):
        tier1_def = self.entry_def(tier1_id=tier1_id, tenant=tenant)
        return self.policy_api.get(tier1_def, silent=silent)

    def get_path(self, tier1_id, tenant=constants.POLICY_INFRA_TENANT):
        tier1_def = self.entry_def(tier1_id=tier1_id, tenant=tenant)
        return tier1_def.get_resource_full_path()

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        tier1_def = self.entry_def(tenant=tenant)
        return self._list(tier1_def)

    def update(self, tier1_id, name=IGNORE, description=IGNORE,
               force_whitelisting=IGNORE,
               failover_mode=IGNORE, tier0=IGNORE,
               dhcp_config=IGNORE, tags=IGNORE,
               enable_standby_relocation=IGNORE,
               disable_firewall=IGNORE,
               ipv6_ndra_profile_id=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        # Note(asarfaty): L2/L3 PATCH APIs don't support partial updates yet
        # TODO(asarfaty): Remove this when supported
        if name == IGNORE or enable_standby_relocation == IGNORE:
            current_body = self.get(tier1_id, tenant=tenant)
            if name == IGNORE:
                name = current_body.get('display_name', IGNORE)
            else:
                enable_standby_relocation = current_body.get(
                    'enable_standby_relocation', IGNORE)
        self._update(tier1_id=tier1_id,
                     name=name,
                     description=description,
                     force_whitelisting=force_whitelisting,
                     failover_mode=failover_mode,
                     dhcp_config=dhcp_config,
                     tier0=tier0,
                     enable_standby_relocation=enable_standby_relocation,
                     disable_firewall=disable_firewall,
                     ipv6_ndra_profile_id=ipv6_ndra_profile_id,
                     tags=tags,
                     tenant=tenant)

    def update_route_advertisement(
        self, tier1_id,
        static_routes=None,
        subnets=None,
        nat=None,
        lb_vip=None,
        lb_snat=None,
        tenant=constants.POLICY_INFRA_TENANT):

        tier1_dict = self.get(tier1_id, tenant)
        route_adv = self.entry_def.get_route_adv(tier1_dict)
        route_adv.update(static_routes=static_routes,
                         subnets=subnets,
                         nat=nat,
                         lb_vip=lb_vip,
                         lb_snat=lb_snat)

        # Note(asarfaty) keep tier1 name and enable_standby_relocation as
        # well, as the current nsx implementation resets name to the ID and
        # enable_standby_relocation to false.
        # TODO(asarfaty): Remove this when supported
        tier1_def = self.entry_def(tier1_id=tier1_id,
                                   name=tier1_dict.get('display_name'),
                                   enable_standby_relocation=tier1_dict.get(
                                       'enable_standby_relocation'),
                                   route_advertisement=route_adv,
                                   tenant=tenant)
        self.policy_api.create_or_update(tier1_def)

    def _locale_service_id(self, tier1_id):
        # Supporting only a single locale-service per router for now
        # with the same id as the router id with a constant suffix
        return tier1_id + self.LOCALE_SERVICE_SUFF

    def set_edge_cluster_path(self, tier1_id, edge_cluster_path,
                              tenant=constants.POLICY_INFRA_TENANT):
        t1service_def = core_defs.Tier1LocaleServiceDef(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            edge_cluster_path=edge_cluster_path,
            tenant=tenant)
        self.policy_api.create_or_update(t1service_def)

    def remove_edge_cluster(self, tier1_id,
                            tenant=constants.POLICY_INFRA_TENANT):
        t1service_def = core_defs.Tier1LocaleServiceDef(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            tenant=tenant)
        self.policy_api.delete(t1service_def)

    def get_edge_cluster_path(self, tier1_id,
                              tenant=constants.POLICY_INFRA_TENANT):
        t1service_def = core_defs.Tier1LocaleServiceDef(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            tenant=tenant)
        try:
            t1service = self.policy_api.get(t1service_def)
            return t1service.get('edge_cluster_path')
        except exceptions.ResourceNotFound:
            return

    def add_segment_interface(self, tier1_id, interface_id, segment_id,
                              subnets, tenant=constants.POLICY_INFRA_TENANT):
        t1interface_def = core_defs.Tier1InterfaceDef(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            interface_id=interface_id,
            segment_id=segment_id,
            subnets=subnets,
            tenant=tenant)
        self.policy_api.create_or_update(t1interface_def)

    def remove_segment_interface(self, tier1_id, interface_id,
                                 tenant=constants.POLICY_INFRA_TENANT):
        t1interface_def = core_defs.Tier1InterfaceDef(
            tier1_id=tier1_id,
            service_id=self._locale_service_id(tier1_id),
            interface_id=interface_id,
            tenant=tenant)
        self.policy_api.delete(t1interface_def)

    def get_realized_state(self, tier1_id, entity_type=None,
                           tenant=constants.POLICY_INFRA_TENANT,
                           realization_info=None):
        tier1_def = self.entry_def(tier1_id=tier1_id, tenant=tenant)
        return self._get_realized_state(tier1_def, entity_type=entity_type,
                                        realization_info=realization_info)

    def get_realized_id(self, tier1_id, entity_type=None,
                        tenant=constants.POLICY_INFRA_TENANT,
                        realization_info=None):
        tier1_def = self.entry_def(tier1_id=tier1_id, tenant=tenant)
        return self._get_realized_id(tier1_def, entity_type=entity_type,
                                     realization_info=realization_info)

    def get_realization_info(self, tier1_id, entity_type=None,
                             tenant=constants.POLICY_INFRA_TENANT):
        tier1_def = self.entry_def(tier1_id=tier1_id, tenant=tenant)
        return self._get_realization_info(tier1_def)

    def wait_until_realized(self, tier1_id, entity_type=None,
                            tenant=constants.POLICY_INFRA_TENANT,
                            sleep=None, max_attempts=None):
        tier1_def = self.entry_def(tier1_id=tier1_id, tenant=tenant)
        return self._wait_until_realized(tier1_def, entity_type=entity_type,
                                         sleep=sleep,
                                         max_attempts=max_attempts)

    @check_allowed_passthrough
    def update_transport_zone(self, tier1_id, transport_zone_id,
                              tenant=constants.POLICY_INFRA_TENANT):
        """Use the pass-through api to update the TZ zone on the NSX router"""
        realization_info = self.wait_until_realized(
            tier1_id, entity_type='RealizedLogicalRouter', tenant=tenant)

        nsx_router_uuid = self.get_realized_id(
            tier1_id, tenant=tenant, realization_info=realization_info)
        self.nsx_api.logical_router.update(
            nsx_router_uuid,
            transport_zone_id=transport_zone_id)

    @check_allowed_passthrough
    def _get_realized_downlink_port(
        self, tier1_id, segment_id,
        tenant=constants.POLICY_INFRA_TENANT,
        sleep=None, max_attempts=None):
        """Return the realized ID of a tier1 downlink port of a segment

        If not found, wait until it has been realized
        """
        if sleep is None:
            sleep = 0.5
        if max_attempts is None:
            max_attempts = self.nsxlib_config.realization_max_attempts

        tier1_def = self.entry_def(tier1_id=tier1_id, tenant=tenant)
        path = tier1_def.get_resource_full_path()

        test_num = 0
        while test_num < max_attempts:
            # get all the realized resources of the tier1
            entities = self.policy_api.get_realized_entities(path)
            for e in entities:
                # Look for router ports
                if (e['entity_type'] == 'RealizedLogicalRouterPort' and
                    e['state'] == constants.STATE_REALIZED):
                    # Get the NSX port to check if its the downlink port
                    port = self.nsx_api.logical_router_port.get(
                        e['realization_specific_identifier'])
                    # compare the segment ID to the port display name as this
                    # is the way policy sets it
                    port_type = port.get('resource_type')
                    if (port_type == nsx_constants.LROUTERPORT_DOWNLINK and
                        segment_id in port.get('display_name', '')):
                        return port['id']
            eventlet.sleep(sleep)
            test_num += 1

        err_msg = (_("Could not find realized downlink port for tier1 "
                     "%(tier1)s and segment %(seg)s after %(attempts)s "
                     "attempts with %(sleep)s seconds sleep") %
                   {'tier1': tier1_id,
                    'seg': segment_id,
                    'attempts': max_attempts,
                    'sleep': sleep})
        raise exceptions.ManagerError(details=err_msg)

    @check_allowed_passthrough
    def set_dhcp_relay(self, tier1_id, segment_id, relay_service_uuid,
                       tenant=constants.POLICY_INFRA_TENANT):
        """Set relay service on the nsx logical router port

        Using passthrough api, as the policy api does not support this yet
        """
        downlink_port_id = self._get_realized_downlink_port(
            tier1_id, segment_id, tenant=tenant)
        self.nsx_api.logical_router_port.update(
            downlink_port_id, relay_service_uuid=relay_service_uuid)

    def set_standby_relocation(self, tier1_id,
                               enable_standby_relocation=True,
                               tenant=constants.POLICY_INFRA_TENANT):
        """Set the flag for standby relocation on the Tier1 router

        """
        return self.update(tier1_id,
                           enable_standby_relocation=enable_standby_relocation,
                           tenant=tenant)


class NsxPolicyTier0Api(NsxPolicyResourceBase):
    """NSX Tier0 API """
    @property
    def entry_def(self):
        return core_defs.Tier0Def

    def create_or_overwrite(self, name, tier0_id=None,
                            description=IGNORE,
                            ha_mode=constants.ACTIVE_ACTIVE,
                            failover_mode=constants.NON_PREEMPTIVE,
                            dhcp_config=IGNORE,
                            force_whitelisting=IGNORE,
                            default_rule_logging=IGNORE,
                            transit_subnets=IGNORE,
                            disable_firewall=IGNORE,
                            ipv6_ndra_profile_id=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        tier0_id = self._init_obj_uuid(tier0_id)
        tier0_def = self._init_def(tier0_id=tier0_id,
                                   name=name,
                                   description=description,
                                   ha_mode=ha_mode,
                                   failover_mode=failover_mode,
                                   dhcp_config=dhcp_config,
                                   force_whitelisting=force_whitelisting,
                                   default_rule_logging=default_rule_logging,
                                   transit_subnets=transit_subnets,
                                   disable_firewall=disable_firewall,
                                   ipv6_ndra_profile_id=ipv6_ndra_profile_id,
                                   tags=tags,
                                   tenant=tenant)
        self.policy_api.create_or_update(tier0_def)
        return tier0_id

    def delete(self, tier0_id, tenant=constants.POLICY_INFRA_TENANT):
        tier0_def = self.entry_def(tier0_id=tier0_id, tenant=tenant)
        self.policy_api.delete(tier0_def)

    def get(self, tier0_id, tenant=constants.POLICY_INFRA_TENANT,
            silent=False):
        tier0_def = self.entry_def(tier0_id=tier0_id, tenant=tenant)
        return self.policy_api.get(tier0_def, silent=silent)

    def get_path(self, tier0_id, tenant=constants.POLICY_INFRA_TENANT):
        tier0_def = self.entry_def(tier0_id=tier0_id, tenant=tenant)
        return tier0_def.get_resource_full_path()

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        tier0_def = self.entry_def(tenant=tenant)
        return self._list(tier0_def)

    def update(self, tier0_id, name=IGNORE, description=IGNORE,
               failover_mode=IGNORE,
               dhcp_config=IGNORE,
               force_whitelisting=IGNORE,
               default_rule_logging=IGNORE,
               transit_subnets=IGNORE,
               disable_firewall=IGNORE,
               ipv6_ndra_profile_id=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):

        self._update(tier0_id=tier0_id,
                     name=name,
                     description=description,
                     failover_mode=failover_mode,
                     dhcp_config=dhcp_config,
                     force_whitelisting=force_whitelisting,
                     default_rule_logging=default_rule_logging,
                     transit_subnets=transit_subnets,
                     disable_firewall=disable_firewall,
                     ipv6_ndra_profile_id=ipv6_ndra_profile_id,
                     tags=tags,
                     tenant=tenant)

    def get_locale_services(self, tier0_id,
                            tenant=constants.POLICY_INFRA_TENANT):
        t0service_def = core_defs.Tier0LocaleServiceDef(
            tier0_id=tier0_id,
            tenant=constants.POLICY_INFRA_TENANT)
        return self.policy_api.list(t0service_def)['results']

    def get_edge_cluster_path(self, tier0_id,
                              tenant=constants.POLICY_INFRA_TENANT):
        """Get the edge_cluster path of a Tier0 router"""
        services = self.get_locale_services(tier0_id, tenant=tenant)
        for srv in services:
            if 'edge_cluster_path' in srv:
                return srv['edge_cluster_path']

    @check_allowed_passthrough
    def get_overlay_transport_zone(
        self, tier0_id,
        tenant=constants.POLICY_INFRA_TENANT):
        """Use the pass-through api to get the TZ zone of the NSX tier0"""
        realization_info = self.wait_until_realized(
            tier0_id, entity_type='RealizedLogicalRouter', tenant=tenant)
        nsx_router_uuid = self.get_realized_id(
            tier0_id, tenant=tenant,
            realization_info=realization_info)
        return self.nsx_api.router.get_tier0_router_overlay_tz(
            nsx_router_uuid)

    def get_realized_state(self, tier0_id, entity_type=None,
                           tenant=constants.POLICY_INFRA_TENANT,
                           realization_info=None):
        tier0_def = self.entry_def(tier0_id=tier0_id, tenant=tenant)
        return self._get_realized_state(tier0_def, entity_type=entity_type,
                                        realization_info=realization_info)

    def get_realized_id(self, tier0_id, entity_type=None,
                        tenant=constants.POLICY_INFRA_TENANT,
                        realization_info=None):
        tier0_def = self.entry_def(tier0_id=tier0_id, tenant=tenant)
        return self._get_realized_id(tier0_def, entity_type=entity_type,
                                     realization_info=realization_info)

    def get_realization_info(self, tier0_id, entity_type=None,
                             tenant=constants.POLICY_INFRA_TENANT):
        tier0_def = self.entry_def(tier0_id=tier0_id, tenant=tenant)
        return self._get_realization_info(tier0_def, entity_type=entity_type)

    def wait_until_realized(self, tier0_id, entity_type=None,
                            tenant=constants.POLICY_INFRA_TENANT,
                            sleep=None, max_attempts=None):
        tier0_def = self.entry_def(tier0_id=tier0_id, tenant=tenant)
        return self._wait_until_realized(tier0_def, entity_type=entity_type,
                                         sleep=sleep,
                                         max_attempts=max_attempts)

    @check_allowed_passthrough
    def get_transport_zones(self, tier0_id,
                            tenant=constants.POLICY_INFRA_TENANT):
        """Return a list of the transport zones IDs connected to the tier0

        Currently this is supported only with the passthrough api
        """
        realization_info = self.wait_until_realized(
            tier0_id, entity_type='RealizedLogicalRouter', tenant=tenant)
        nsx_router_uuid = self.get_realized_id(
            tier0_id, tenant=tenant,
            realization_info=realization_info)
        return self.nsx_api.router.get_tier0_router_tz(
            nsx_router_uuid)

    def _get_uplink_subnets(self, tier0_id,
                            tenant=constants.POLICY_INFRA_TENANT):
        subnets = []
        services = self.get_locale_services(tier0_id, tenant=tenant)
        for srv in services:
            # get the interfaces of this service
            t0interface_def = core_defs.Tier0InterfaceDef(
                tier0_id=tier0_id,
                service_id=srv['id'],
                tenant=constants.POLICY_INFRA_TENANT)
            interfaces = self.policy_api.list(
                t0interface_def).get('results', [])
            for interface in interfaces:
                if interface.get('type') == 'EXTERNAL':
                    subnets.extend(interface.get('subnets', []))
        return subnets

    def get_uplink_ips(self, tier0_id, tenant=constants.POLICY_INFRA_TENANT):
        """Return a link of all uplink ips of this tier0 router"""
        subnets = self._get_uplink_subnets(tier0_id, tenant=tenant)
        uplink_ips = []
        for subnet in subnets:
            uplink_ips.extend(subnet.get('ip_addresses', []))
        return uplink_ips

    def get_uplink_cidrs(self, tier0_id, tenant=constants.POLICY_INFRA_TENANT):
        """Return a link of all uplink cidrs of this tier0 router"""
        subnets = self._get_uplink_subnets(tier0_id, tenant=tenant)
        cidrs = []
        for subnet in subnets:
            for ip_address in subnet.get('ip_addresses'):
                cidrs.append('%s/%s' % (ip_address,
                                        subnet.get('prefix_len')))
        return cidrs


class NsxPolicyTier0NatRuleApi(NsxPolicyResourceBase):
    DEFAULT_NAT_ID = 'USER'

    @property
    def entry_def(self):
        return core_defs.Tier0NatRule

    def create_or_overwrite(self, name, tier0_id,
                            nat_id=DEFAULT_NAT_ID,
                            nat_rule_id=None,
                            description=IGNORE,
                            source_network=IGNORE,
                            destination_network=IGNORE,
                            translated_network=IGNORE,
                            firewall_match=IGNORE,
                            action=IGNORE,
                            sequence_number=IGNORE,
                            log=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT,
                            enabled=IGNORE):

        nat_rule_id = self._init_obj_uuid(nat_rule_id)
        nat_rule_def = self._init_def(tier0_id=tier0_id,
                                      nat_id=nat_id,
                                      nat_rule_id=nat_rule_id,
                                      name=name,
                                      description=description,
                                      source_network=source_network,
                                      destination_network=destination_network,
                                      translated_network=translated_network,
                                      firewall_match=firewall_match,
                                      action=action,
                                      sequence_number=sequence_number,
                                      log=log,
                                      tags=tags,
                                      tenant=tenant,
                                      enabled=enabled)
        self._create_or_store(nat_rule_def)
        return nat_rule_id

    def delete(self, tier0_id, nat_rule_id, nat_id=DEFAULT_NAT_ID,
               tenant=constants.POLICY_INFRA_TENANT):
        nat_rule_def = self.entry_def(tier0_id=tier0_id, nat_id=nat_id,
                                      nat_rule_id=nat_rule_id, tenant=tenant)
        self.policy_api.delete(nat_rule_def)

    def get(self, tier0_id, nat_rule_id, nat_id=DEFAULT_NAT_ID,
            tenant=constants.POLICY_INFRA_TENANT):
        nat_rule_def = self.entry_def(tier0_id=tier0_id, nat_id=nat_id,
                                      nat_rule_id=nat_rule_id, tenant=tenant)
        return self.policy_api.get(nat_rule_def)

    def list(self, tier0_id, nat_id=DEFAULT_NAT_ID,
             tenant=constants.POLICY_INFRA_TENANT):
        nat_rule_def = self.entry_def(tier0_id=tier0_id, nat_id=nat_id,
                                      tenant=tenant)
        return self._list(nat_rule_def)

    def update(self, tier0_id, nat_rule_id,
               nat_id=DEFAULT_NAT_ID,
               name=IGNORE,
               description=IGNORE,
               source_network=IGNORE,
               destination_network=IGNORE,
               translated_network=IGNORE,
               action=IGNORE,
               sequence_number=IGNORE,
               log=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT,
               enabled=IGNORE):
        self._update(tier0_id=tier0_id,
                     nat_id=nat_id,
                     nat_rule_id=nat_rule_id,
                     name=name,
                     description=description,
                     source_network=source_network,
                     destination_network=destination_network,
                     translated_network=translated_network,
                     action=action,
                     sequence_number=sequence_number,
                     log=log,
                     tags=tags,
                     tenant=tenant,
                     enabled=enabled)


class NsxPolicyTier1NatRuleApi(NsxPolicyResourceBase):
    DEFAULT_NAT_ID = 'USER'

    @property
    def entry_def(self):
        return core_defs.Tier1NatRule

    def create_or_overwrite(self, name, tier1_id,
                            nat_id=DEFAULT_NAT_ID,
                            nat_rule_id=None,
                            description=IGNORE,
                            source_network=IGNORE,
                            destination_network=IGNORE,
                            translated_network=IGNORE,
                            firewall_match=IGNORE,
                            action=IGNORE,
                            sequence_number=IGNORE,
                            log=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT,
                            enabled=IGNORE):

        nat_rule_id = self._init_obj_uuid(nat_rule_id)
        nat_rule_def = self._init_def(tier1_id=tier1_id,
                                      nat_id=nat_id,
                                      nat_rule_id=nat_rule_id,
                                      name=name,
                                      description=description,
                                      source_network=source_network,
                                      destination_network=destination_network,
                                      translated_network=translated_network,
                                      firewall_match=firewall_match,
                                      action=action,
                                      sequence_number=sequence_number,
                                      log=log,
                                      tags=tags,
                                      tenant=tenant,
                                      enabled=enabled)
        self._create_or_store(nat_rule_def)
        return nat_rule_id

    def delete(self, tier1_id, nat_rule_id, nat_id=DEFAULT_NAT_ID,
               tenant=constants.POLICY_INFRA_TENANT):
        nat_rule_def = self.entry_def(tier1_id=tier1_id, nat_id=nat_id,
                                      nat_rule_id=nat_rule_id, tenant=tenant)
        self.policy_api.delete(nat_rule_def)

    def get(self, tier1_id, nat_rule_id, nat_id=DEFAULT_NAT_ID,
            tenant=constants.POLICY_INFRA_TENANT):
        nat_rule_def = self.entry_def(tier1_id=tier1_id, nat_id=nat_id,
                                      nat_rule_id=nat_rule_id, tenant=tenant)
        return self.policy_api.get(nat_rule_def)

    def list(self, tier1_id, nat_id=DEFAULT_NAT_ID,
             tenant=constants.POLICY_INFRA_TENANT):
        nat_rule_def = self.entry_def(tier1_id=tier1_id, nat_id=nat_id,
                                      tenant=tenant)
        return self._list(nat_rule_def)

    def update(self, tier1_id, nat_rule_id,
               nat_id=DEFAULT_NAT_ID,
               name=IGNORE,
               description=IGNORE,
               source_network=IGNORE,
               destination_network=IGNORE,
               translated_network=IGNORE,
               action=IGNORE,
               sequence_number=IGNORE,
               log=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT,
               enabled=IGNORE):
        self._update(tier1_id=tier1_id,
                     nat_id=nat_id,
                     nat_rule_id=nat_rule_id,
                     name=name,
                     description=description,
                     source_network=source_network,
                     destination_network=destination_network,
                     translated_network=translated_network,
                     action=action,
                     sequence_number=sequence_number,
                     log=log,
                     tags=tags,
                     tenant=tenant,
                     enabled=enabled)


class NsxPolicyTier1StaticRouteApi(NsxPolicyResourceBase):

    @property
    def entry_def(self):
        return core_defs.Tier1StaticRoute

    def create_or_overwrite(self, name, tier1_id,
                            static_route_id=None,
                            description=IGNORE,
                            network=IGNORE,
                            next_hop=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        static_route_id = self._init_obj_uuid(static_route_id)
        static_route_def = self._init_def(tier1_id=tier1_id,
                                          static_route_id=static_route_id,
                                          name=name,
                                          description=description,
                                          network=network,
                                          next_hop=next_hop,
                                          tags=tags,
                                          tenant=tenant)
        self._create_or_store(static_route_def)
        return static_route_id

    def delete(self, tier1_id, static_route_id,
               tenant=constants.POLICY_INFRA_TENANT):
        static_route_def = self.entry_def(tier1_id=tier1_id,
                                          static_route_id=static_route_id,
                                          tenant=tenant)
        self.policy_api.delete(static_route_def)

    def get(self, tier1_id, static_route_id,
            tenant=constants.POLICY_INFRA_TENANT):
        static_route_def = self.entry_def(tier1_id=tier1_id,
                                          static_route_id=static_route_id,
                                          tenant=tenant)
        return self.policy_api.get(static_route_def)

    def list(self, tier1_id,
             tenant=constants.POLICY_INFRA_TENANT):
        static_route_def = self.entry_def(tier1_id=tier1_id,
                                          tenant=tenant)
        return self._list(static_route_def)

    def update(self, tier1_id, static_route_id,
               name=IGNORE,
               description=IGNORE,
               network=IGNORE,
               next_hop=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(tier1_id=tier1_id,
                     static_route_id=static_route_id,
                     name=name,
                     description=description,
                     network=network,
                     next_hop=next_hop,
                     tags=tags,
                     tenant=tenant)


class NsxPolicyTier1SegmentApi(NsxPolicyResourceBase):
    """NSX Tier1 Segment API """
    @property
    def entry_def(self):
        return core_defs.Tier1SegmentDef

    def build_subnet(self, gateway_address, dhcp_ranges=None):
        return core_defs.Subnet(gateway_address, dhcp_ranges)

    def create_or_overwrite(self, name, tier1_id,
                            segment_id=None,
                            description=IGNORE,
                            subnets=IGNORE,
                            dhcp_config=IGNORE,
                            dns_domain_name=IGNORE,
                            vlan_ids=IGNORE,
                            default_rule_logging=IGNORE,
                            ip_pool_id=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        segment_id = self._init_obj_uuid(segment_id)
        segment_def = self._init_def(tier1_id=tier1_id,
                                     segment_id=segment_id,
                                     name=name,
                                     description=description,
                                     subnets=subnets,
                                     dhcp_config=dhcp_config,
                                     dns_domain_name=dns_domain_name,
                                     vlan_ids=vlan_ids,
                                     default_rule_logging=default_rule_logging,
                                     ip_pool_id=ip_pool_id,
                                     tags=tags,
                                     tenant=tenant)
        self._create_or_store(segment_def)
        return segment_id

    def delete(self, tier1_id, segment_id,
               tenant=constants.POLICY_INFRA_TENANT):
        segment_def = self.entry_def(tier1_id=tier1_id,
                                     segment_id=segment_id,
                                     tenant=tenant)
        self.policy_api.delete(segment_def)

    def get(self, tier1_id, segment_id,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        segment_def = self.entry_def(tier1_id=tier1_id,
                                     segment_id=segment_id,
                                     tenant=tenant)
        return self.policy_api.get(segment_def, silent=silent)

    def list(self, tier1_id, tenant=constants.POLICY_INFRA_TENANT):
        segment_def = self.entry_def(tier1_id=tier1_id, tenant=tenant)
        return self._list(segment_def)

    def update(self, tier1_id, segment_id,
               name=IGNORE,
               description=IGNORE,
               subnets=IGNORE,
               dhcp_config=IGNORE,
               dns_domain_name=IGNORE,
               vlan_ids=IGNORE,
               default_rule_logging=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):

        self._update(tier1_id=tier1_id,
                     segment_id=segment_id,
                     name=name,
                     description=description,
                     subnets=subnets,
                     dhcp_config=dhcp_config,
                     dns_domain_name=dns_domain_name,
                     vlan_ids=vlan_ids,
                     default_rule_logging=default_rule_logging,
                     tags=tags,
                     tenant=tenant)


class NsxPolicySegmentApi(NsxPolicyResourceBase):
    """NSX Infra Segment API """
    @property
    def entry_def(self):
        return core_defs.SegmentDef

    def build_subnet(self, gateway_address, dhcp_ranges=None):
        return core_defs.Subnet(gateway_address, dhcp_ranges)

    def create_or_overwrite(self, name,
                            segment_id=None,
                            tier1_id=IGNORE,
                            description=IGNORE,
                            subnets=IGNORE,
                            dns_domain_name=IGNORE,
                            vlan_ids=IGNORE,
                            transport_zone_id=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        segment_id = self._init_obj_uuid(segment_id)
        segment_def = self._init_def(segment_id=segment_id,
                                     name=name,
                                     description=description,
                                     tier1_id=tier1_id,
                                     subnets=subnets,
                                     dns_domain_name=dns_domain_name,
                                     vlan_ids=vlan_ids,
                                     transport_zone_id=transport_zone_id,
                                     tags=tags,
                                     tenant=tenant)
        self._create_or_store(segment_def)
        return segment_id

    def delete(self, segment_id,
               tenant=constants.POLICY_INFRA_TENANT):
        segment_def = self.entry_def(segment_id=segment_id, tenant=tenant)
        self.policy_api.delete(segment_def)

    def get(self, segment_id,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        segment_def = self.entry_def(segment_id=segment_id, tenant=tenant)
        return self.policy_api.get(segment_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        segment_def = self.entry_def(tenant=tenant)
        return self._list(segment_def)

    def update(self, segment_id, name=IGNORE, description=IGNORE,
               tier1_id=IGNORE, subnets=IGNORE,
               dns_domain_name=IGNORE,
               vlan_ids=IGNORE, tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        # Note(asarfaty): L2/L3 PATCH APIs don't support partial updates yet
        # TODO(asarfaty): Remove this when supported
        if name == IGNORE:
            current_body = self.get(segment_id, tenant=tenant)
            name = current_body.get('display_name', IGNORE)

        self._update(segment_id=segment_id,
                     name=name,
                     description=description,
                     tier1_id=tier1_id,
                     subnets=subnets,
                     dns_domain_name=dns_domain_name,
                     vlan_ids=vlan_ids,
                     tags=tags,
                     tenant=tenant)

    def remove_connectivity_and_subnets(
        self, segment_id,
        tenant=constants.POLICY_INFRA_TENANT):
        """Disconnect a segment from a router and remove its subnets.

        PATCH does not support this action so PUT is used for this
        """
        # Get the current segment and update it
        segment = self.get(segment_id)
        segment['subnets'] = None
        segment['connectivity_path'] = None

        segment_def = self.entry_def(segment_id=segment_id, tenant=tenant)
        path = segment_def.get_resource_path()

        self.policy_api.client.update(path, segment)

    def get_realized_state(self, segment_id, entity_type=None,
                           tenant=constants.POLICY_INFRA_TENANT,
                           realization_info=None):
        segment_def = self.entry_def(segment_id=segment_id, tenant=tenant)
        return self._get_realized_state(segment_def, entity_type=entity_type,
                                        realization_info=realization_info)

    def get_realized_id(self, segment_id, entity_type=None,
                        tenant=constants.POLICY_INFRA_TENANT,
                        realization_info=None):
        segment_def = self.entry_def(segment_id=segment_id, tenant=tenant)
        return self._get_realized_id(segment_def, entity_type=entity_type,
                                     realization_info=realization_info)

    def get_realized_logical_switch_id(
        self,
        segment_id,
        tenant=constants.POLICY_INFRA_TENANT):

        segment_def = self.entry_def(segment_id=segment_id, tenant=tenant)
        realization_info = self._wait_until_realized(
            segment_def, entity_type='RealizedLogicalSwitch')
        return self._get_realized_id(segment_def,
                                     realization_info=realization_info)

    def get_realization_info(self, segment_id, entity_type=None,
                             tenant=constants.POLICY_INFRA_TENANT):
        segment_def = self.entry_def(segment_id=segment_id, tenant=tenant)
        return self._get_realization_info(segment_def,
                                          entity_type=entity_type)

    def wait_until_realized(self, segment_id, entity_type=None,
                            tenant=constants.POLICY_INFRA_TENANT,
                            sleep=None, max_attempts=None):
        segment_def = self.entry_def(segment_id=segment_id, tenant=tenant)
        return self._wait_until_realized(segment_def, entity_type=entity_type,
                                         sleep=sleep,
                                         max_attempts=max_attempts)

    @check_allowed_passthrough
    def set_admin_state(self, segment_id, admin_state,
                        tenant=constants.POLICY_INFRA_TENANT):
        """Set the segment admin state using the passthrough api"""
        realization_info = self.wait_until_realized(
            segment_id, entity_type='RealizedLogicalSwitch', tenant=tenant)

        nsx_ls_uuid = self.get_realized_id(
            segment_id, tenant=tenant, realization_info=realization_info)
        self.nsx_api.logical_switch.update(
            nsx_ls_uuid,
            admin_state=admin_state)

    def get_transport_zone_id(self, segment_id,
                              tenant=constants.POLICY_INFRA_TENANT):
        segment = self.get(segment_id, tenant=tenant)
        tz_path = segment.get('transport_zone_path')
        if tz_path:
            return p_utils.path_to_id(tz_path)


class NsxPolicySegmentPortApi(NsxPolicyResourceBase):
    """NSX Segment Port API """
    @property
    def entry_def(self):
        return core_defs.SegmentPortDef

    def build_address_binding(self, ip_address, mac_address,
                              vlan_id=None):
        return core_defs.PortAddressBinding(ip_address,
                                            mac_address,
                                            vlan_id)

    def create_or_overwrite(self, name,
                            segment_id,
                            port_id=None,
                            description=IGNORE,
                            address_bindings=IGNORE,
                            attachment_type=IGNORE,
                            vif_id=IGNORE,
                            app_id=IGNORE,
                            context_id=IGNORE,
                            traffic_tag=IGNORE,
                            allocate_addresses=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        port_id = self._init_obj_uuid(port_id)
        port_def = self._init_def(segment_id=segment_id,
                                  port_id=port_id,
                                  name=name,
                                  description=description,
                                  address_bindings=address_bindings,
                                  attachment_type=attachment_type,
                                  vif_id=vif_id,
                                  app_id=app_id,
                                  context_id=context_id,
                                  traffic_tag=traffic_tag,
                                  allocate_addresses=allocate_addresses,
                                  tags=tags,
                                  tenant=tenant)
        self._create_or_store(port_def)
        return port_id

    def delete(self, segment_id, port_id,
               tenant=constants.POLICY_INFRA_TENANT):
        port_def = self.entry_def(segment_id=segment_id,
                                  port_id=port_id,
                                  tenant=tenant)
        self.policy_api.delete(port_def)

    def get(self, segment_id, port_id,
            tenant=constants.POLICY_INFRA_TENANT,
            silent=False):
        port_def = self.entry_def(segment_id=segment_id,
                                  port_id=port_id,
                                  tenant=tenant)
        return self.policy_api.get(port_def, silent=silent)

    def list(self, segment_id, tenant=constants.POLICY_INFRA_TENANT):
        port_def = self.entry_def(segment_id=segment_id, tenant=tenant)
        return self._list(port_def)

    def update(self, segment_id, port_id,
               name=IGNORE,
               description=IGNORE,
               address_bindings=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):

        self._update(segment_id=segment_id,
                     port_id=port_id,
                     name=name,
                     description=description,
                     address_bindings=address_bindings,
                     tags=tags,
                     tenant=tenant)

    def detach(self, segment_id, port_id,
               tenant=constants.POLICY_INFRA_TENANT):

        port_def = self.entry_def(segment_id=segment_id,
                                  port_id=port_id,
                                  attachment_type=None,
                                  tenant=tenant)
        self.policy_api.create_or_update(port_def)

    def attach(self, segment_id, port_id,
               attachment_type,
               vif_id,
               allocate_addresses,
               app_id=None,
               context_id=None,
               tenant=constants.POLICY_INFRA_TENANT):

        port_def = self.entry_def(segment_id=segment_id,
                                  port_id=port_id,
                                  attachment_type=attachment_type,
                                  allocate_addresses=allocate_addresses,
                                  vif_id=vif_id,
                                  app_id=app_id,
                                  context_id=context_id,
                                  tenant=tenant)

        self.policy_api.create_or_update(port_def)

    def get_realized_state(self, segment_id, port_id, entity_type=None,
                           tenant=constants.POLICY_INFRA_TENANT,
                           realization_info=None):
        port_def = self.entry_def(segment_id=segment_id,
                                  port_id=port_id,
                                  tenant=tenant)
        return self._get_realized_state(port_def, entity_type=entity_type,
                                        realization_info=realization_info)

    def get_realized_id(self, segment_id, port_id, entity_type=None,
                        tenant=constants.POLICY_INFRA_TENANT,
                        realization_info=None):
        port_def = self.entry_def(segment_id=segment_id,
                                  port_id=port_id,
                                  tenant=tenant)
        return self._get_realized_id(port_def, entity_type=entity_type,
                                     realization_info=realization_info)

    def get_realization_info(self, segment_id, port_id, entity_type=None,
                             tenant=constants.POLICY_INFRA_TENANT):
        port_def = self.entry_def(segment_id=segment_id,
                                  port_id=port_id,
                                  tenant=tenant)
        return self._get_realization_info(port_def, entity_type=entity_type)

    def wait_until_realized(self, segment_id, port_id, entity_type=None,
                            tenant=constants.POLICY_INFRA_TENANT,
                            sleep=None, max_attempts=None):
        port_def = self.entry_def(segment_id=segment_id, port_id=port_id,
                                  tenant=tenant)
        return self._wait_until_realized(port_def, entity_type=entity_type,
                                         sleep=sleep,
                                         max_attempts=max_attempts)

    @check_allowed_passthrough
    def set_admin_state(self, segment_id, port_id, admin_state,
                        tenant=constants.POLICY_INFRA_TENANT):
        """Set the segment port admin state using the passthrough api"""
        realization_info = self.wait_until_realized(
            segment_id, port_id, entity_type='RealizedLogicalPort',
            tenant=tenant)

        nsx_lp_uuid = self.get_realized_id(
            segment_id, port_id, tenant=tenant,
            realization_info=realization_info)
        self.nsx_api.logical_port.update(
            nsx_lp_uuid, False,
            admin_state=admin_state)


class SegmentPortProfilesBindingMapBaseApi(NsxPolicyResourceBase):

    def delete(self, segment_id, port_id, map_id=DEFAULT_MAP_ID,
               tenant=constants.POLICY_INFRA_TENANT):
        map_def = self.entry_def(segment_id=segment_id,
                                 port_id=port_id,
                                 map_id=map_id,
                                 tenant=tenant)
        self.policy_api.delete(map_def)

    def get(self, segment_id, port_id, map_id=DEFAULT_MAP_ID,
            tenant=constants.POLICY_INFRA_TENANT):
        map_def = self.entry_def(segment_id=segment_id,
                                 port_id=port_id,
                                 map_id=map_id,
                                 tenant=tenant)
        return self.policy_api.get(map_def)

    def list(self, segment_id, port_id,
             tenant=constants.POLICY_INFRA_TENANT):
        map_def = self.entry_def(segment_id=segment_id,
                                 port_id=port_id,
                                 tenant=tenant)
        return self._list(map_def)


class SegmentPortSecurityProfilesBindingMapApi(
    SegmentPortProfilesBindingMapBaseApi):

    @property
    def entry_def(self):
        return core_defs.SegmentPortSecProfilesBindingMapDef

    def create_or_overwrite(self, name, segment_id, port_id,
                            map_id=DEFAULT_MAP_ID,
                            description=IGNORE,
                            segment_security_profile_id=IGNORE,
                            spoofguard_profile_id=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        map_id = self._init_obj_uuid(map_id)
        map_def = self._init_def(
            segment_id=segment_id,
            port_id=port_id,
            map_id=map_id,
            name=name,
            description=description,
            segment_security_profile_id=segment_security_profile_id,
            spoofguard_profile_id=spoofguard_profile_id,
            tags=tags,
            tenant=tenant)
        self._create_or_store(map_def)
        return map_id

    def update(self, segment_id, port_id,
               map_id=DEFAULT_MAP_ID,
               name=IGNORE,
               description=IGNORE,
               segment_security_profile_id=IGNORE,
               spoofguard_profile_id=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            segment_id=segment_id,
            port_id=port_id,
            map_id=map_id,
            name=name,
            description=description,
            segment_security_profile_id=segment_security_profile_id,
            spoofguard_profile_id=spoofguard_profile_id,
            tags=tags,
            tenant=tenant)


class SegmentPortDiscoveryProfilesBindingMapApi(
    SegmentPortProfilesBindingMapBaseApi):

    @property
    def entry_def(self):
        return core_defs.SegmentPortDiscoveryProfilesBindingMapDef

    def create_or_overwrite(self, name, segment_id, port_id,
                            map_id=DEFAULT_MAP_ID,
                            description=IGNORE,
                            mac_discovery_profile_id=IGNORE,
                            ip_discovery_profile_id=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        map_id = self._init_obj_uuid(map_id)
        map_def = self._init_def(
            segment_id=segment_id,
            port_id=port_id,
            map_id=map_id,
            name=name,
            description=description,
            mac_discovery_profile_id=mac_discovery_profile_id,
            ip_discovery_profile_id=ip_discovery_profile_id,
            tags=tags,
            tenant=tenant)
        self._create_or_store(map_def)
        return map_id

    def update(self, segment_id, port_id,
               map_id=DEFAULT_MAP_ID,
               name=IGNORE,
               description=IGNORE,
               mac_discovery_profile_id=IGNORE,
               ip_discovery_profile_id=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            segment_id=segment_id,
            port_id=port_id,
            map_id=map_id,
            name=name,
            description=description,
            mac_discovery_profile_id=mac_discovery_profile_id,
            ip_discovery_profile_id=ip_discovery_profile_id,
            tags=tags,
            tenant=tenant)


class SegmentPortQosProfilesBindingMapApi(
    SegmentPortProfilesBindingMapBaseApi):

    @property
    def entry_def(self):
        return core_defs.SegmentPortQoSProfilesBindingMapDef

    def create_or_overwrite(self, name, segment_id, port_id,
                            map_id=DEFAULT_MAP_ID,
                            description=IGNORE,
                            qos_profile_id=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        map_id = self._init_obj_uuid(map_id)
        map_def = self._init_def(
            segment_id=segment_id,
            port_id=port_id,
            map_id=map_id,
            name=name,
            description=description,
            qos_profile_id=qos_profile_id,
            tags=tags,
            tenant=tenant)
        self._create_or_store(map_def)
        return map_id

    def update(self, segment_id, port_id,
               map_id=DEFAULT_MAP_ID,
               name=IGNORE,
               description=IGNORE,
               qos_profile_id=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(
            segment_id=segment_id,
            port_id=port_id,
            map_id=map_id,
            name=name,
            description=description,
            qos_profile_id=qos_profile_id,
            tags=tags,
            tenant=tenant)


class NsxPolicyTier1SegmentPortApi(NsxPolicyResourceBase):
    """NSX Tier1 Segment Port API """
    @property
    def entry_def(self):
        return core_defs.Tier1SegmentPortDef

    def build_address_binding(self, ip_address, mac_address,
                              vlan_id=None):
        return core_defs.PortAddressBinding(ip_address,
                                            mac_address,
                                            vlan_id)

    def create_or_overwrite(self, name,
                            tier1_id,
                            segment_id,
                            port_id=None,
                            description=IGNORE,
                            address_bindings=IGNORE,
                            attachment_type=IGNORE,
                            vif_id=IGNORE,
                            app_id=IGNORE,
                            context_id=IGNORE,
                            traffic_tag=IGNORE,
                            allocate_addresses=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        port_id = self._init_obj_uuid(port_id)
        port_def = self._init_def(segment_id=segment_id,
                                  tier1_id=tier1_id,
                                  port_id=port_id,
                                  name=name,
                                  description=description,
                                  address_bindings=address_bindings,
                                  attachment_type=attachment_type,
                                  vif_id=vif_id,
                                  app_id=app_id,
                                  context_id=context_id,
                                  traffic_tag=traffic_tag,
                                  allocate_addresses=allocate_addresses,
                                  tags=tags,
                                  tenant=tenant)
        self._create_or_store(port_def)
        return port_id

    def delete(self, tier1_id, segment_id, port_id,
               tenant=constants.POLICY_INFRA_TENANT):
        port_def = self.entry_def(segment_id=segment_id,
                                  tier1_id=tier1_id,
                                  port_id=port_id,
                                  tenant=tenant)
        self.policy_api.delete(port_def)

    def get(self, tier1_id, segment_id, port_id,
            tenant=constants.POLICY_INFRA_TENANT,
            silent=False):
        port_def = self.entry_def(segment_id=segment_id,
                                  tier1_id=tier1_id,
                                  port_id=port_id,
                                  tenant=tenant)
        return self.policy_api.get(port_def, silent=silent)

    def list(self, tier1_id, segment_id,
             tenant=constants.POLICY_INFRA_TENANT):
        port_def = self.entry_def(segment_id=segment_id, tier1_id=tier1_id,
                                  tenant=tenant)
        return self._list(port_def)

    def update(self, tier1_id, segment_id, port_id,
               name=IGNORE,
               description=IGNORE,
               address_bindings=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):

        self._update(segment_id=segment_id,
                     tier1_id=tier1_id,
                     port_id=port_id,
                     name=name,
                     description=description,
                     address_bindings=address_bindings,
                     tags=tags,
                     tenant=tenant)

    def detach(self, tier1_id, segment_id, port_id,
               tenant=constants.POLICY_INFRA_TENANT):

        port_def = self.entry_def(segment_id=segment_id,
                                  tier1_id=tier1_id,
                                  port_id=port_id,
                                  attachment_type=None,
                                  tenant=tenant)
        self.policy_api.create_or_update(port_def)

    def attach(self, tier1_id, segment_id, port_id,
               attachment_type,
               vif_id,
               allocate_addresses,
               app_id=None,
               context_id=None,
               tenant=constants.POLICY_INFRA_TENANT):

        port_def = self.entry_def(segment_id=segment_id,
                                  tier1_id=tier1_id,
                                  port_id=port_id,
                                  attachment_type=attachment_type,
                                  allocate_addresses=allocate_addresses,
                                  vif_id=vif_id,
                                  app_id=app_id,
                                  context_id=context_id,
                                  tenant=tenant)

        self.policy_api.create_or_update(port_def)

    def get_realized_state(self, tier1_id, segment_id, port_id,
                           entity_type=None,
                           tenant=constants.POLICY_INFRA_TENANT,
                           realization_info=None):
        port_def = self.entry_def(segment_id=segment_id,
                                  tier1_id=tier1_id,
                                  port_id=port_id,
                                  tenant=tenant)
        return self._get_realized_state(port_def, entity_type=entity_type,
                                        realization_info=realization_info)

    def get_realized_id(self, tier1_id, segment_id, port_id, entity_type=None,
                        tenant=constants.POLICY_INFRA_TENANT,
                        realization_info=None):
        port_def = self.entry_def(segment_id=segment_id,
                                  tier1_id=tier1_id,
                                  port_id=port_id,
                                  tenant=tenant)
        return self._get_realized_id(port_def, entity_type=entity_type,
                                     realization_info=realization_info)

    def get_realization_info(self, tier1_id, segment_id, port_id,
                             entity_type=None,
                             tenant=constants.POLICY_INFRA_TENANT):
        port_def = self.entry_def(segment_id=segment_id,
                                  tier1_id=tier1_id,
                                  port_id=port_id,
                                  tenant=tenant)
        return self._get_realization_info(port_def, entity_type=entity_type)

    def wait_until_realized(self, tier1_id, segment_id, port_id,
                            entity_type=None,
                            tenant=constants.POLICY_INFRA_TENANT,
                            sleep=None, max_attempts=None):
        port_def = self.entry_def(segment_id=segment_id, port_id=port_id,
                                  tier1_id=tier1_id, tenant=tenant)
        return self._wait_until_realized(port_def, entity_type=entity_type,
                                         sleep=sleep,
                                         max_attempts=max_attempts)


class NsxPolicyIpBlockApi(NsxPolicyResourceBase):
    """NSX Policy IP Block API"""
    @property
    def entry_def(self):
        return core_defs.IpBlockDef

    def create_or_overwrite(self, name,
                            ip_block_id=None,
                            description=IGNORE,
                            cidr=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        ip_block_id = self._init_obj_uuid(ip_block_id)
        ip_block_def = self._init_def(ip_block_id=ip_block_id,
                                      name=name,
                                      description=description,
                                      cidr=cidr,
                                      tags=tags,
                                      tenant=tenant)
        self._create_or_store(ip_block_def)
        return ip_block_id

    def delete(self, ip_block_id, tenant=constants.POLICY_INFRA_TENANT):
        ip_block_def = self.entry_def(ip_block_id=ip_block_id,
                                      tenant=tenant)
        self.policy_api.delete(ip_block_def)

    def get(self, ip_block_id, tenant=constants.POLICY_INFRA_TENANT,
            silent=False):
        ip_block_def = self.entry_def(ip_block_id=ip_block_id,
                                      tenant=tenant)
        return self.policy_api.get(ip_block_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        ip_block_def = self.entry_def(tenant=tenant)
        return self._list(ip_block_def)

    def update(self, ip_block_id, name=IGNORE, description=IGNORE,
               cidr=IGNORE, tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(ip_block_id=ip_block_id,
                     name=name,
                     description=description,
                     cidr=cidr,
                     tags=tags,
                     tenant=tenant)


class NsxPolicyIpPoolApi(NsxPolicyResourceBase):
    """NSX Policy IP Pool API"""
    @property
    def entry_def(self):
        return core_defs.IpPoolDef

    def create_or_overwrite(self, name,
                            ip_pool_id=None,
                            description=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        ip_pool_id = self._init_obj_uuid(ip_pool_id)
        ip_pool_def = self._init_def(ip_pool_id=ip_pool_id,
                                     name=name,
                                     description=description,
                                     tags=tags,
                                     tenant=tenant)
        self._create_or_store(ip_pool_def)
        return ip_pool_id

    def delete(self, ip_pool_id, tenant=constants.POLICY_INFRA_TENANT):
        ip_pool_def = self.entry_def(ip_pool_id=ip_pool_id,
                                     tenant=tenant)
        self.policy_api.delete(ip_pool_def)

    def get(self, ip_pool_id, tenant=constants.POLICY_INFRA_TENANT):
        ip_pool_def = self.entry_def(ip_pool_id=ip_pool_id,
                                     tenant=tenant)
        return self.policy_api.get(ip_pool_def)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        ip_pool_def = self.entry_def(tenant=tenant)
        return self._list(ip_pool_def)

    def update(self, ip_pool_id, name=IGNORE, description=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(ip_pool_id=ip_pool_id,
                     name=name,
                     description=description,
                     tags=tags,
                     tenant=tenant)

    def allocate_ip(self, ip_pool_id, ip_allocation_id=None, ip_address=IGNORE,
                    name=IGNORE, description=IGNORE, tags=IGNORE,
                    tenant=constants.POLICY_INFRA_TENANT):
        # If ip_address is not set, a random IP will be allocated
        # from the pool.
        ip_allocation_id = self._init_obj_uuid(ip_allocation_id)

        args = self._get_user_args(
            ip_pool_id=ip_pool_id,
            ip_allocation_id=ip_allocation_id,
            allocation_ip=ip_address,
            name=name,
            description=description,
            tags=tags,
            tenant=tenant)

        ip_allocation_def = core_defs.IpPoolAllocationDef(**args)
        self._create_or_store(ip_allocation_def)

    def release_ip(self, ip_pool_id, ip_allocation_id,
                   tenant=constants.POLICY_INFRA_TENANT):
        ip_allocation_def = core_defs.IpPoolAllocationDef(
            ip_allocation_id=ip_allocation_id,
            ip_pool_id=ip_pool_id,
            tenant=tenant)
        self.policy_api.delete(ip_allocation_def)

    def list_allocations(self, ip_pool_id,
                         tenant=constants.POLICY_INFRA_TENANT):
        ip_allocation_def = core_defs.IpPoolAllocationDef(
            ip_pool_id=ip_pool_id,
            tenant=tenant)
        return self._list(ip_allocation_def)

    def get_allocation(self, ip_pool_id, ip_allocation_id,
                       tenant=constants.POLICY_INFRA_TENANT):
        ip_allocation_def = core_defs.IpPoolAllocationDef(
            ip_pool_id=ip_pool_id,
            ip_allocation_id=ip_allocation_id,
            tenant=tenant)
        return self.policy_api.get(ip_allocation_def)

    def allocate_block_subnet(self, ip_pool_id, ip_block_id, size,
                              ip_subnet_id=None, auto_assign_gateway=IGNORE,
                              name=IGNORE, description=IGNORE, tags=IGNORE,
                              tenant=constants.POLICY_INFRA_TENANT):
        ip_subnet_id = self._init_obj_uuid(ip_subnet_id)
        args = self._get_user_args(
            ip_pool_id=ip_pool_id,
            ip_block_id=ip_block_id,
            ip_subnet_id=ip_subnet_id,
            size=size,
            auto_assign_gateway=auto_assign_gateway,
            name=name,
            description=description,
            tags=tags,
            tenant=tenant)

        ip_subnet_def = core_defs.IpPoolBlockSubnetDef(**args)
        self._create_or_store(ip_subnet_def)

    def release_block_subnet(self, ip_pool_id, ip_subnet_id,
                             tenant=constants.POLICY_INFRA_TENANT):
        ip_subnet_def = core_defs.IpPoolBlockSubnetDef(
            ip_subnet_id=ip_subnet_id,
            ip_pool_id=ip_pool_id,
            tenant=tenant)
        self.policy_api.delete(ip_subnet_def)

    def list_block_subnets(self, ip_pool_id,
                           tenant=constants.POLICY_INFRA_TENANT):
        ip_subnet_def = core_defs.IpPoolBlockSubnetDef(
            ip_pool_id=ip_pool_id,
            tenant=tenant)
        subnets = self._list(ip_subnet_def)
        block_subnets = []
        for subnet in subnets:
            if subnet['resource_type'] == ip_subnet_def.resource_type():
                block_subnets.append(subnet)
        return block_subnets

    def get_ip_block_subnet(self, ip_pool_id, ip_subnet_id,
                            tenant=constants.POLICY_INFRA_TENANT):
        ip_subnet_def = core_defs.IpPoolBlockSubnetDef(
            ip_pool_id=ip_pool_id,
            ip_subnet_id=ip_subnet_id,
            tenant=tenant)
        return self.policy_api.get(ip_subnet_def)

    def get_ip_block_subnet_cidr(self, ip_pool_id, ip_subnet_id,
                                 entity_type=None,
                                 tenant=constants.POLICY_INFRA_TENANT,
                                 wait=False, sleep=None,
                                 max_attempts=None):
        # Retrieve the allocated Subnet CIDR for Subnet ID
        # Return None in case the CIDR is not yet allocated
        realized_info = self.get_ip_subnet_realization_info(
            ip_pool_id, ip_subnet_id, entity_type, tenant, wait,
            sleep, max_attempts)
        # Returns a list of CIDRs. In case a single value is expected,
        # caller must extract the first index to retrieve the CIDR value
        return self._get_extended_attr_from_realized_info(
            realized_info, requested_attr='cidr')

    def create_or_update_static_subnet(self, ip_pool_id, cidr,
                                       allocation_ranges, ip_subnet_id=None,
                                       name=IGNORE, description=IGNORE,
                                       gateway_ip=IGNORE, tags=IGNORE,
                                       tenant=constants.POLICY_INFRA_TENANT):
        ip_subnet_id = self._init_obj_uuid(ip_subnet_id)
        args = self._get_user_args(
            ip_pool_id=ip_pool_id,
            ip_subnet_id=ip_subnet_id,
            cidr=cidr,
            allocation_ranges=allocation_ranges,
            name=name,
            description=description,
            tags=tags,
            tenant=tenant)

        ip_subnet_def = core_defs.IpPoolStaticSubnetDef(**args)
        self._create_or_store(ip_subnet_def)

    def release_static_subnet(self, ip_pool_id, ip_subnet_id,
                              tenant=constants.POLICY_INFRA_TENANT):
        ip_subnet_def = core_defs.IpPoolStaticSubnetDef(
            ip_subnet_id=ip_subnet_id,
            ip_pool_id=ip_pool_id,
            tenant=tenant)
        self.policy_api.delete(ip_subnet_def)

    def list_static_subnets(self, ip_pool_id,
                            tenant=constants.POLICY_INFRA_TENANT):
        ip_subnet_def = core_defs.IpPoolStaticSubnetDef(
            ip_pool_id=ip_pool_id,
            tenant=tenant)
        subnets = self._list(ip_subnet_def)
        static_subnets = []
        for subnet in subnets:
            if subnet['resource_type'] == ip_subnet_def.resource_type():
                static_subnets.append(subnet)
        return static_subnets

    def get_static_subnet(self, ip_pool_id, ip_subnet_id,
                          tenant=constants.POLICY_INFRA_TENANT):
        ip_subnet_def = core_defs.IpPoolStaticSubnetDef(
            ip_pool_id=ip_pool_id,
            ip_subnet_id=ip_subnet_id,
            tenant=tenant)
        return self.policy_api.get(ip_subnet_def)

    def get_ip_subnet_realization_info(
            self, ip_pool_id, ip_subnet_id,
            entity_type=None,
            tenant=constants.POLICY_INFRA_TENANT,
            wait=False, sleep=None,
            max_attempts=None,
            subnet_type=constants.IPPOOL_BLOCK_SUBNET):
        if subnet_type == constants.IPPOOL_BLOCK_SUBNET:
            ip_subnet_def = core_defs.IpPoolBlockSubnetDef(
                ip_pool_id=ip_pool_id,
                ip_subnet_id=ip_subnet_id,
                tenant=tenant)
        else:
            ip_subnet_def = core_defs.IpPoolStaticSubnetDef(
                ip_pool_id=ip_pool_id,
                ip_subnet_id=ip_subnet_id,
                tenant=tenant)
        if wait:
            return self._wait_until_realized(
                ip_subnet_def, entity_type=entity_type,
                sleep=sleep, max_attempts=max_attempts)
        return self._get_realization_info(ip_subnet_def,
                                          entity_type=entity_type)

    def get_ip_alloc_realization_info(self, ip_pool_id, ip_allocation_id,
                                      entity_type=None,
                                      tenant=constants.POLICY_INFRA_TENANT,
                                      wait=False, sleep=None,
                                      max_attempts=None):
        ip_allocation_def = core_defs.IpPoolAllocationDef(
            ip_pool_id=ip_pool_id,
            ip_allocation_id=ip_allocation_id,
            tenant=tenant)
        if wait:
            return self._wait_until_realized(
                ip_allocation_def, entity_type=entity_type,
                sleep=sleep, max_attempts=max_attempts)
        return self._get_realization_info(ip_allocation_def,
                                          entity_type=entity_type)

    def get_realized_allocated_ip(self, ip_pool_id, ip_allocation_id,
                                  entity_type=None,
                                  tenant=constants.POLICY_INFRA_TENANT,
                                  wait=False, sleep=None,
                                  max_attempts=None):
        # Retrieve the allocated IpAddress for allocation ID
        # Return None in case the IP is not yet allocated
        realized_info = self.get_ip_alloc_realization_info(
            ip_pool_id, ip_allocation_id, entity_type, tenant, wait,
            sleep, max_attempts)
        if realized_info:
            try:
                return realized_info['extended_attributes'][0].get(
                    'values')[0]
            except IndexError:
                return


class NsxPolicySecurityPolicyBaseApi(NsxPolicyResourceBase):

    def _get_last_seq_num(self, domain_id, map_id,
                          tenant=constants.POLICY_INFRA_TENANT):
        # get the current entries, and choose the next unused sequence number
        # between the entries under the same communication map
        try:
            com_map = self.get(domain_id, map_id, tenant=tenant)
            com_entries = com_map.get('rules')
        except exceptions.ResourceNotFound:
            return -1
        if not com_entries:
            return 0
        seq_nums = [int(cm['sequence_number']) for cm in com_entries]
        seq_nums.sort()
        return seq_nums[-1]

    def _get_seq_num(self, last_sequence):
        if last_sequence < 0:
            return 1
        return last_sequence + 1

    def create_or_overwrite(self, name, domain_id, map_id=None,
                            description=IGNORE,
                            category=constants.CATEGORY_APPLICATION,
                            sequence_number=None, service_ids=IGNORE,
                            action=constants.ACTION_ALLOW,
                            scope=IGNORE,
                            source_groups=IGNORE, dest_groups=IGNORE,
                            direction=nsx_constants.IN_OUT,
                            logged=IGNORE, tags=IGNORE,
                            map_sequence_number=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        """Create CommunicationMap & Entry.

        source_groups/dest_groups should be a list of group ids belonging
        to the domain.
        NOTE: In multi-connection environment, it is recommended to execute
        this call under lock to prevent race condition where two entries
        end up with same sequence number.
        """
        last_sequence = -1
        if map_id:
            if not sequence_number:
                # get the next available sequence number
                last_sequence = self._get_last_seq_num(domain_id, map_id,
                                                       tenant=tenant)
        else:
            map_id = self._init_obj_uuid(map_id)

        if not sequence_number:
            sequence_number = self._get_seq_num(last_sequence)

        # Build the communication entry. Since we currently support only one
        # it will have the same id as its parent
        entry_def = self._init_def(
            domain_id=domain_id,
            map_id=map_id,
            entry_id=self.SINGLE_ENTRY_ID,
            name=name,
            description=description,
            sequence_number=sequence_number,
            source_groups=source_groups,
            dest_groups=dest_groups,
            service_ids=service_ids,
            action=action,
            scope=scope,
            direction=direction,
            logged=logged,
            tenant=tenant)

        map_def = self._init_parent_def(
            domain_id=domain_id, map_id=map_id,
            tenant=tenant, name=name, description=description,
            category=category, tags=tags,
            map_sequence_number=map_sequence_number)

        self._create_or_store(map_def, entry_def)
        return map_id

    def create_or_overwrite_map_only(
        self, name, domain_id, map_id=None, description=IGNORE,
        category=constants.CATEGORY_APPLICATION,
        tags=IGNORE, map_sequence_number=IGNORE,
        tenant=constants.POLICY_INFRA_TENANT):
        """Create or update a CommunicationMap

        Create a communication map without any entries, or update the
        communication map itself, leaving the entries unchanged.
        """
        map_id = self._init_obj_uuid(map_id)
        map_def = self._init_parent_def(
            domain_id=domain_id, map_id=map_id,
            tenant=tenant, name=name, description=description,
            category=category, tags=tags,
            map_sequence_number=map_sequence_number)

        self._create_or_store(map_def)
        return map_id

    def build_entry(self, name, domain_id, map_id, entry_id,
                    description=None,
                    sequence_number=None, service_ids=None,
                    action=constants.ACTION_ALLOW,
                    scope=None,
                    source_groups=None, dest_groups=None,
                    direction=nsx_constants.IN_OUT, logged=False,
                    ip_protocol=nsx_constants.IPV4_IPV6,
                    tenant=constants.POLICY_INFRA_TENANT):
        """Get the definition of a single map entry"""
        return self._init_def(domain_id=domain_id,
                              map_id=map_id,
                              entry_id=entry_id,
                              name=name,
                              description=description,
                              sequence_number=sequence_number,
                              source_groups=source_groups,
                              dest_groups=dest_groups,
                              service_ids=service_ids,
                              action=action,
                              scope=scope,
                              direction=direction,
                              ip_protocol=ip_protocol,
                              logged=logged,
                              tenant=tenant)

    def create_with_entries(
        self, name, domain_id, map_id=None,
        description=IGNORE,
        category=constants.CATEGORY_APPLICATION,
        entries=None, tags=IGNORE, map_sequence_number=IGNORE,
        tenant=constants.POLICY_INFRA_TENANT):
        """Create CommunicationMap with entries"""

        map_id = self._init_obj_uuid(map_id)

        map_def = self._init_parent_def(
            domain_id=domain_id, map_id=map_id,
            tenant=tenant, name=name, description=description,
            category=category, tags=tags,
            map_sequence_number=map_sequence_number)

        self.policy_api.create_with_parent(map_def, entries)
        return map_id

    def create_entry(self, name, domain_id, map_id, entry_id=None,
                     description=None, sequence_number=None, service_ids=None,
                     action=constants.ACTION_ALLOW,
                     source_groups=None, dest_groups=None,
                     scope=None,
                     ip_protocol=nsx_constants.IPV4_IPV6,
                     direction=nsx_constants.IN_OUT,
                     logged=False,
                     tenant=constants.POLICY_INFRA_TENANT):
        """Create CommunicationMap Entry.

        source_groups/dest_groups should be a list of group ids belonging
        to the domain.
        """
        # get the next available sequence number
        if not sequence_number:
            last_sequence = self._get_last_seq_num(domain_id, map_id,
                                                   tenant=tenant)
            sequence_number = self._get_seq_num(last_sequence)
        entry_id = self._init_obj_uuid(entry_id)

        # Build the communication entry
        entry_def = self._init_def(domain_id=domain_id,
                                   map_id=map_id,
                                   entry_id=entry_id,
                                   name=name,
                                   description=description,
                                   sequence_number=sequence_number,
                                   source_groups=source_groups,
                                   dest_groups=dest_groups,
                                   service_ids=service_ids,
                                   action=action,
                                   scope=scope,
                                   ip_protocol=ip_protocol,
                                   direction=direction,
                                   logged=logged,
                                   tenant=tenant)

        self._create_or_store(entry_def)
        return entry_id

    def delete(self, domain_id, map_id,
               tenant=constants.POLICY_INFRA_TENANT):
        map_def = self._init_parent_def(
            domain_id=domain_id,
            map_id=map_id,
            tenant=tenant)
        self.policy_api.delete(map_def)

    def delete_entry(self, domain_id, map_id, entry_id,
                     tenant=constants.POLICY_INFRA_TENANT):
        entry_def = self.entry_def(
            domain_id=domain_id,
            map_id=map_id,
            entry_id=entry_id,
            tenant=tenant)
        self.policy_api.delete(entry_def)

    def get(self, domain_id, map_id,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        map_def = self.parent_entry_def(
            domain_id=domain_id,
            map_id=map_id,
            tenant=tenant)
        return self.policy_api.get(map_def, silent=silent)

    def get_entry(self, domain_id, map_id, entry_id,
                  tenant=constants.POLICY_INFRA_TENANT, silent=False):
        entry_def = self.entry_def(
            domain_id=domain_id,
            map_id=map_id,
            entry_id=entry_id,
            tenant=tenant)
        return self.policy_api.get(entry_def, silent=silent)

    def get_by_name(self, domain_id, name,
                    tenant=constants.POLICY_INFRA_TENANT):
        """Return first communication map entry matched by name"""
        return super(NsxPolicySecurityPolicyBaseApi, self).get_by_name(
            name, domain_id, tenant=tenant)

    def list(self, domain_id,
             tenant=constants.POLICY_INFRA_TENANT):
        """List all the map entries of a specific domain."""
        map_def = self.parent_entry_def(
            domain_id=domain_id,
            tenant=tenant)
        return self._list(map_def)

    def update(self, domain_id, map_id,
               name=IGNORE, description=IGNORE,
               sequence_number=IGNORE, service_ids=IGNORE,
               action=IGNORE,
               source_groups=IGNORE, dest_groups=IGNORE,
               direction=IGNORE, logged=IGNORE, tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        # Note(asarfaty): Category is mandatory in update calls for now
        # although it cannot change. Getting it from the NSX
        orig_entry = self.get(domain_id, map_id, tenant=tenant)
        category = orig_entry.get('category')
        parent_def = self._init_parent_def(
            domain_id=domain_id,
            map_id=map_id,
            name=name,
            description=description,
            category=category,
            tags=tags,
            tenant=tenant)

        if self._any_arg_set(sequence_number, service_ids,
                             action, source_groups, dest_groups,
                             direction, logged):
            # Update the entry only if relevant attributes were changed
            entry_def = self._get_and_update_def(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=self.SINGLE_ENTRY_ID,
                service_ids=service_ids,
                source_groups=source_groups,
                dest_groups=dest_groups,
                sequence_number=sequence_number,
                action=action,
                direction=direction,
                logged=logged,
                tenant=tenant)

            self.policy_api.create_with_parent(parent_def, entry_def)
        else:
            self.policy_api.create_or_update(parent_def)

    def update_entry(self, domain_id, map_id, entry_id,
                     name=IGNORE, description=IGNORE,
                     sequence_number=IGNORE, service_ids=IGNORE,
                     action=IGNORE, source_groups=IGNORE, dest_groups=IGNORE,
                     scope=IGNORE, ip_protocol=IGNORE,
                     direction=IGNORE, logged=IGNORE, tags=IGNORE,
                     tenant=constants.POLICY_INFRA_TENANT):
        if self._any_arg_set(name, description, sequence_number, service_ids,
                             action, source_groups, dest_groups, scope,
                             ip_protocol, direction, logged, tags):
            entry_def = self._get_and_update_def(
                domain_id=domain_id,
                map_id=map_id,
                entry_id=entry_id,
                name=name,
                description=description,
                sequence_number=sequence_number,
                service_ids=service_ids,
                action=action,
                source_groups=source_groups,
                dest_groups=dest_groups,
                scope=scope,
                ip_protocol=ip_protocol,
                direction=direction,
                logged=logged,
                tags=tags,
                tenant=tenant)
            self.policy_api.create_or_update(entry_def)

    def update_entries(self, domain_id, map_id, entries,
                       tenant=constants.POLICY_INFRA_TENANT):
        map_def = self.parent_entry_def(
            domain_id=domain_id,
            map_id=map_id,
            tenant=tenant)
        map_path = map_def.get_resource_path()

        def _overwrite_entries(old_entries, new_entries):
            # Replace old entries with new entries, but copy additional
            # attributes from old entries for those kept in new entries.
            old_rules = {entry["id"]: entry for entry in old_entries}
            new_rules = []
            for entry in new_entries:
                rule_id = entry.get_id()
                new_rule = entry.get_obj_dict()
                old_rule = old_rules.get(rule_id)
                if old_rule:
                    for key, value in old_rule.items():
                        if key not in new_rule:
                            new_rule[key] = value
                new_rules.append(new_rule)
            return new_rules

        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.policy_api.client.max_attempts)
        def _update():
            # Get the current data of communication map & its' entries
            comm_map = self.policy_api.get(map_def)
            comm_map['rules'] = _overwrite_entries(comm_map['rules'], entries)
            # Update the entire map at the NSX
            self.policy_api.client.update(map_path, comm_map)

        _update()

    def update_entries_logged(self, domain_id, map_id, logged,
                              tenant=constants.POLICY_INFRA_TENANT):
        """Update all communication map entries logged flags"""
        map_def = self.parent_entry_def(
            domain_id=domain_id,
            map_id=map_id,
            tenant=tenant)
        map_path = map_def.get_resource_path()

        @utils.retry_upon_exception(
            exceptions.StaleRevision,
            max_attempts=self.policy_api.client.max_attempts)
        def _update():
            # Get the current data of communication map & its' entries
            comm_map = self.policy_api.get(map_def)
            # Update the field in all the entries
            if comm_map.get('rules'):
                for comm_entry in comm_map['rules']:
                    comm_entry['logged'] = logged
            # Update the entire map at the NSX
            self.policy_api.client.update(map_path, comm_map)

        _update()

    def get_realized_state(self, domain_id, map_id, entity_type=None,
                           tenant=constants.POLICY_INFRA_TENANT,
                           realization_info=None):
        map_def = self.parent_entry_def(map_id=map_id,
                                        domain_id=domain_id,
                                        tenant=tenant)
        return self._get_realized_state(map_def, entity_type=entity_type,
                                        realization_info=realization_info)

    def get_realized_id(self, domain_id, map_id, entity_type=None,
                        tenant=constants.POLICY_INFRA_TENANT,
                        realization_info=None):
        map_def = self.parent_entry_def(map_id=map_id,
                                        domain_id=domain_id,
                                        tenant=tenant)
        return self._get_realized_id(map_def, entity_type=entity_type,
                                     realization_info=realization_info)

    def get_realization_info(self, domain_id, map_id, entity_type=None,
                             tenant=constants.POLICY_INFRA_TENANT):
        map_def = self.parent_entry_def(map_id=map_id,
                                        domain_id=domain_id,
                                        tenant=tenant)
        return self._get_realization_info(map_def, entity_type=entity_type)


class NsxPolicyCommunicationMapApi(NsxPolicySecurityPolicyBaseApi):
    """NSX Policy CommunicationMap (Under a Domain). AKA Security"""
    @property
    def entry_def(self):
        return core_defs.CommunicationMapEntryDef

    @property
    def parent_entry_def(self):
        return core_defs.CommunicationMapDef


class NsxPolicyGatewayPolicyApi(NsxPolicySecurityPolicyBaseApi):
    """NSX Policy Gateway policy (Edge firewall)"""
    @property
    def entry_def(self):
        return core_defs.GatewayPolicyRuleDef

    @property
    def parent_entry_def(self):
        return core_defs.GatewayPolicyDef


class NsxPolicyEnforcementPointApi(NsxPolicyResourceBase):
    """NSX Policy Enforcement Point."""

    @property
    def entry_def(self):
        return core_defs.EnforcementPointDef

    def create_or_overwrite(self, name, ep_id=None, description=IGNORE,
                            ip_address=IGNORE, username=IGNORE,
                            password=IGNORE, thumbprint=IGNORE,
                            edge_cluster_id=IGNORE,
                            transport_zone_id=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        if not ip_address or not username or password is None:
            err_msg = (_("Cannot create an enforcement point without "
                         "ip_address, username and password"))
            raise exceptions.ManagerError(details=err_msg)
        ep_id = self._init_obj_uuid(ep_id)
        ep_def = self._init_def(ep_id=ep_id,
                                name=name,
                                description=description,
                                ip_address=ip_address,
                                username=username,
                                password=password,
                                thumbprint=thumbprint,
                                edge_cluster_id=edge_cluster_id,
                                transport_zone_id=transport_zone_id,
                                tenant=tenant)
        self._create_or_store(ep_def)
        return ep_id

    def delete(self, ep_id,
               tenant=constants.POLICY_INFRA_TENANT):
        ep_def = core_defs.EnforcementPointDef(
            ep_id=ep_id, tenant=tenant)
        self.policy_api.delete(ep_def)

    def get(self, ep_id,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        ep_def = core_defs.EnforcementPointDef(
            ep_id=ep_id, tenant=tenant)
        return self.policy_api.get(ep_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        ep_def = core_defs.EnforcementPointDef(tenant=tenant)
        return self._list(ep_def)

    def update(self, ep_id, name=IGNORE, description=IGNORE,
               ip_address=IGNORE, username=IGNORE,
               password=IGNORE, thumbprint=IGNORE,
               edge_cluster_id=IGNORE, transport_zone_id=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        """Update the enforcement point.

        username & password must be defined
        """
        if not username or password is None:
            # username/password must be provided
            err_msg = (_("Cannot update an enforcement point without "
                         "username and password"))
            raise exceptions.ManagerError(details=err_msg)

        # Get the original body because ip & thumbprint are mandatory
        ep_def = self._get_and_update_def(ep_id=ep_id,
                                          name=name,
                                          description=description,
                                          ip_address=ip_address,
                                          username=username,
                                          password=password,
                                          edge_cluster_id=edge_cluster_id,
                                          transport_zone_id=transport_zone_id,
                                          thumbprint=thumbprint,
                                          tenant=tenant)

        self.policy_api.create_or_update(ep_def)

    def get_realized_state(self, ep_id, entity_type=None,
                           tenant=constants.POLICY_INFRA_TENANT,
                           realization_info=None):
        ep_def = core_defs.EnforcementPointDef(ep_id=ep_id, tenant=tenant)
        return self._get_realized_state(ep_def, entity_type=entity_type,
                                        realization_info=realization_info)

    def get_realization_info(self, ep_id, entity_type=None,
                             tenant=constants.POLICY_INFRA_TENANT,
                             realization_info=None):
        ep_def = core_defs.EnforcementPointDef(ep_id=ep_id, tenant=tenant)
        return self._get_realization_info(ep_def, entity_type=entity_type,
                                          realization_info=realization_info)


class NsxPolicyTransportZoneApi(NsxPolicyResourceBase):

    TZ_TYPE_OVERLAY = 'OVERLAY_STANDARD'
    TZ_TYPE_ENS = 'OVERLAY_ENS'
    TZ_TYPE_VLAN = 'VLAN_BACKED'

    @property
    def entry_def(self):
        return core_defs.TransportZoneDef

    def get(self, tz_id, ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        tz_def = core_defs.TransportZoneDef(
            ep_id=ep_id, tz_id=tz_id, tenant=tenant)
        return self.policy_api.get(tz_def, silent=silent)

    def get_tz_type(self, tz_id,
                    ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
                    tenant=constants.POLICY_INFRA_TENANT):
        tz = self.get(tz_id, ep_id=ep_id, tenant=tenant)
        return tz.get('tz_type')

    def get_transport_type(self, tz_id,
                           ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
                           tenant=constants.POLICY_INFRA_TENANT):
        """This api is consistent with the nsx manager resource api"""
        tz_type = self.get_tz_type(tz_id, ep_id=ep_id, tenant=tenant)
        if tz_type == self.TZ_TYPE_VLAN:
            return nsx_constants.TRANSPORT_TYPE_VLAN
        else:
            return nsx_constants.TRANSPORT_TYPE_OVERLAY

    def get_host_switch_mode(self, tz_id,
                             ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
                             tenant=constants.POLICY_INFRA_TENANT):
        """This api is consistent with the nsx manager resource api"""
        tz_type = self.get_tz_type(tz_id, ep_id=ep_id, tenant=tenant)
        if tz_type == self.TZ_TYPE_ENS:
            return nsx_constants.HOST_SWITCH_MODE_ENS
        else:
            return nsx_constants.HOST_SWITCH_MODE_STANDARD

    def list(self, ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
             tenant=constants.POLICY_INFRA_TENANT):
        tz_def = core_defs.TransportZoneDef(ep_id=ep_id, tenant=tenant)
        return self._list(tz_def)

    def get_by_name(self, name,
                    ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
                    tenant=constants.POLICY_INFRA_TENANT):
        """Return first group matched by name"""
        return super(NsxPolicyTransportZoneApi, self).get_by_name(
            name, ep_id, tenant=tenant)

    def create_or_overwrite(self, name, tz_id=None,
                            ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
                            tenant=constants.POLICY_INFRA_TENANT):
        err_msg = (_("This action is not supported"))
        raise exceptions.ManagerError(details=err_msg)

    def update(self, tz_id,
               ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
               tenant=constants.POLICY_INFRA_TENANT):
        err_msg = (_("This action is not supported"))
        raise exceptions.ManagerError(details=err_msg)

    def delete(self, tz_id,
               ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
               tenant=constants.POLICY_INFRA_TENANT):
        err_msg = (_("This action is not supported"))
        raise exceptions.ManagerError(details=err_msg)


class NsxPolicyEdgeClusterApi(NsxPolicyResourceBase):
    @property
    def entry_def(self):
        return core_defs.EdgeClusterDef

    def get(self, ec_id, ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        ec_def = core_defs.EdgeClusterDef(
            ep_id=ep_id, ec_id=ec_id, tenant=tenant)
        return self.policy_api.get(ec_def, silent=silent)

    def list(self, ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
             tenant=constants.POLICY_INFRA_TENANT):
        ec_def = core_defs.EdgeClusterDef(ep_id=ep_id, tenant=tenant)
        return self._list(ec_def)

    def get_by_name(self, name,
                    ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
                    tenant=constants.POLICY_INFRA_TENANT):
        """Return first group matched by name"""
        return super(NsxPolicyEdgeClusterApi, self).get_by_name(
            name, ep_id, tenant=tenant)

    def create_or_overwrite(self, name, ec_id=None,
                            ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
                            tenant=constants.POLICY_INFRA_TENANT):
        err_msg = (_("This action is not supported"))
        raise exceptions.ManagerError(details=err_msg)

    def update(self, ec_id,
               ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
               tenant=constants.POLICY_INFRA_TENANT):
        err_msg = (_("This action is not supported"))
        raise exceptions.ManagerError(details=err_msg)

    def delete(self, ec_id,
               ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
               tenant=constants.POLICY_INFRA_TENANT):
        err_msg = (_("This action is not supported"))
        raise exceptions.ManagerError(details=err_msg)

    def get_path(self, ec_id,
                 ep_id=constants.DEFAULT_ENFORCEMENT_POINT,
                 tenant=constants.POLICY_INFRA_TENANT):
        ec_def = core_defs.EdgeClusterDef(
            ep_id=ep_id, ec_id=ec_id, tenant=tenant)
        return ec_def.get_resource_full_path()


class NsxPolicyDeploymentMapApi(NsxPolicyResourceBase):
    """NSX Policy Deployment Map."""
    @property
    def entry_def(self):
        return core_defs.DeploymentMapDef

    def create_or_overwrite(self, name, map_id=None,
                            description=IGNORE,
                            ep_id=IGNORE, domain_id=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        map_id = self._init_obj_uuid(map_id)
        map_def = core_defs.DeploymentMapDef(
            map_id=map_id,
            name=name,
            description=description,
            ep_id=ep_id,
            domain_id=domain_id,
            tenant=tenant)
        self._create_or_store(map_def)
        return map_id

    def delete(self, map_id, domain_id=None,
               tenant=constants.POLICY_INFRA_TENANT):
        if not domain_id:
            # domain_id must be provided
            err_msg = (_("Cannot delete deployment maps without a domain"))
            raise exceptions.ManagerError(details=err_msg)

        map_def = core_defs.DeploymentMapDef(
            map_id=map_id, domain_id=domain_id, tenant=tenant)
        self.policy_api.delete(map_def)

    def get(self, map_id, domain_id=None,
            tenant=constants.POLICY_INFRA_TENANT, silent=False):
        if not domain_id:
            # domain_id must be provided
            err_msg = (_("Cannot get deployment maps without a domain"))
            raise exceptions.ManagerError(details=err_msg)
        map_def = core_defs.DeploymentMapDef(
            map_id=map_id, domain_id=domain_id, tenant=tenant)
        return self.policy_api.get(map_def, silent=silent)

    def list(self, domain_id=None,
             tenant=constants.POLICY_INFRA_TENANT):
        if not domain_id:
            # domain_id must be provided
            err_msg = (_("Cannot list deployment maps without a domain"))
            raise exceptions.ManagerError(details=err_msg)
        map_def = core_defs.DeploymentMapDef(domain_id=domain_id,
                                             tenant=tenant)
        return self._list(map_def)

    def update(self, map_id, name=IGNORE, description=IGNORE,
               ep_id=IGNORE, domain_id=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):

        self._update(map_id=map_id,
                     name=name,
                     description=description,
                     ep_id=ep_id,
                     domain_id=domain_id,
                     tenant=tenant)


class NsxSegmentProfileBaseApi(NsxPolicyResourceBase):
    """NSX Segment Profile base API"""

    def create_or_overwrite(self, name,
                            profile_id=None,
                            description=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        profile_id = self._init_obj_uuid(profile_id)
        profile_def = self._init_def(profile_id=profile_id,
                                     name=name,
                                     description=description,
                                     tags=tags,
                                     tenant=tenant)
        self._create_or_store(profile_def)
        return profile_id

    def delete(self, profile_id, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(profile_id=profile_id,
                                     tenant=tenant)
        self.policy_api.delete(profile_def)

    def get(self, profile_id, tenant=constants.POLICY_INFRA_TENANT,
            silent=False):
        profile_def = self.entry_def(profile_id=profile_id,
                                     tenant=tenant)
        return self.policy_api.get(profile_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(tenant=tenant)
        return self._list(profile_def)

    def get_by_name(self, name, tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxSegmentProfileBaseApi, self).get_by_name(
            name, tenant=tenant)

    def update(self, profile_id, name=IGNORE, description=IGNORE,
               tags=IGNORE, tenant=constants.POLICY_INFRA_TENANT):
        self._update(profile_id=profile_id,
                     name=name,
                     description=description,
                     tags=tags,
                     tenant=tenant)

    def get_path(self, profile_id, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(profile_id=profile_id, tenant=tenant)
        return profile_def.get_resource_full_path()


class NsxSegmentSecurityProfileApi(NsxSegmentProfileBaseApi):
    @property
    def entry_def(self):
        return core_defs.SegmentSecurityProfileDef

    def create_or_overwrite(self, name,
                            profile_id=None,
                            description=IGNORE,
                            bpdu_filter_enable=IGNORE,
                            dhcp_client_block_enabled=IGNORE,
                            dhcp_client_block_v6_enabled=IGNORE,
                            dhcp_server_block_enabled=IGNORE,
                            dhcp_server_block_v6_enabled=IGNORE,
                            non_ip_traffic_block_enabled=IGNORE,
                            ra_guard_enabled=IGNORE,
                            rate_limits_enabled=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        profile_id = self._init_obj_uuid(profile_id)
        profile_def = self._init_def(
            profile_id=profile_id,
            name=name,
            description=description,
            bpdu_filter_enable=bpdu_filter_enable,
            dhcp_client_block_enabled=dhcp_client_block_enabled,
            dhcp_client_block_v6_enabled=dhcp_client_block_v6_enabled,
            dhcp_server_block_enabled=dhcp_server_block_enabled,
            dhcp_server_block_v6_enabled=dhcp_server_block_v6_enabled,
            non_ip_traffic_block_enabled=non_ip_traffic_block_enabled,
            ra_guard_enabled=ra_guard_enabled,
            rate_limits_enabled=rate_limits_enabled,
            tags=tags,
            tenant=tenant)
        self._create_or_store(profile_def)
        return profile_id


class NsxQosProfileApi(NsxSegmentProfileBaseApi):
    @property
    def entry_def(self):
        return core_defs.QosProfileDef

    def _build_rate_limiter(self, resource_type, average_bandwidth,
                            peak_bandwidth, burst_size, enabled):
        return core_defs.QoSRateLimiter(
            resource_type=resource_type,
            average_bandwidth=average_bandwidth,
            peak_bandwidth=peak_bandwidth,
            burst_size=burst_size,
            enabled=enabled)

    def build_ingress_rate_limiter(
        self,
        average_bandwidth=None,
        peak_bandwidth=None,
        burst_size=None,
        enabled=True):
        return self._build_rate_limiter(
            resource_type=core_defs.QoSRateLimiter.INGRESS_RATE_LIMITER_TYPE,
            average_bandwidth=average_bandwidth,
            peak_bandwidth=peak_bandwidth,
            burst_size=burst_size,
            enabled=enabled)

    def build_egress_rate_limiter(
        self,
        average_bandwidth=None,
        peak_bandwidth=None,
        burst_size=None,
        enabled=True):
        return self._build_rate_limiter(
            resource_type=core_defs.QoSRateLimiter.EGRESS_RATE_LIMITER_TYPE,
            average_bandwidth=average_bandwidth,
            peak_bandwidth=peak_bandwidth,
            burst_size=burst_size,
            enabled=enabled)

    def build_dscp(self, trusted=False, priority=None):
        mode = (core_defs.QoSDscp.QOS_DSCP_TRUSTED if trusted
                else core_defs.QoSDscp.QOS_DSCP_UNTRUSTED)
        return core_defs.QoSDscp(mode=mode, priority=priority)

    def create_or_overwrite(self, name,
                            profile_id=None,
                            description=IGNORE,
                            class_of_service=IGNORE,
                            dscp=IGNORE,
                            shaper_configurations=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        profile_id = self._init_obj_uuid(profile_id)
        profile_def = self._init_def(
            profile_id=profile_id,
            name=name,
            description=description,
            class_of_service=class_of_service,
            dscp=dscp,
            shaper_configurations=shaper_configurations,
            tags=tags,
            tenant=tenant)
        self._create_or_store(profile_def)
        return profile_id


class NsxSpoofguardProfileApi(NsxSegmentProfileBaseApi):
    @property
    def entry_def(self):
        return core_defs.SpoofguardProfileDef

    def create_or_overwrite(self, name,
                            profile_id=None,
                            description=IGNORE,
                            address_binding_whitelist=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        profile_id = self._init_obj_uuid(profile_id)
        profile_def = self._init_def(
            profile_id=profile_id,
            name=name,
            description=description,
            address_binding_whitelist=address_binding_whitelist,
            tags=tags,
            tenant=tenant)
        self._create_or_store(profile_def)
        return profile_id


class NsxIpDiscoveryProfileApi(NsxSegmentProfileBaseApi):
    @property
    def entry_def(self):
        return core_defs.IpDiscoveryProfileDef


class NsxWAFProfileApi(NsxSegmentProfileBaseApi):
    @property
    def entry_def(self):
        return core_defs.WAFProfileDef


class NsxMacDiscoveryProfileApi(NsxSegmentProfileBaseApi):
    @property
    def entry_def(self):
        return core_defs.MacDiscoveryProfileDef

    def create_or_overwrite(self, name,
                            profile_id=None,
                            description=IGNORE,
                            mac_change_enabled=IGNORE,
                            mac_learning_enabled=IGNORE,
                            unknown_unicast_flooding_enabled=IGNORE,
                            mac_limit_policy=IGNORE,
                            mac_limit=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        profile_id = self._init_obj_uuid(profile_id)
        profile_def = self._init_def(
            profile_id=profile_id,
            name=name,
            description=description,
            mac_change_enabled=mac_change_enabled,
            mac_learning_enabled=mac_learning_enabled,
            unknown_unicast_flooding_enabled=unknown_unicast_flooding_enabled,
            mac_limit_policy=mac_limit_policy,
            mac_limit=mac_limit,
            tags=tags,
            tenant=tenant)
        self._create_or_store(profile_def)
        return profile_id


class NsxIpv6NdraProfileApi(NsxPolicyResourceBase):
    @property
    def entry_def(self):
        return core_defs.Ipv6NdraProfileDef

    def create_or_overwrite(self, name,
                            profile_id=None,
                            description=IGNORE,
                            ra_mode=IGNORE,
                            reachable_timer=IGNORE,
                            retransmit_interval=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        profile_id = self._init_obj_uuid(profile_id)
        profile_def = self._init_def(
            profile_id=profile_id,
            name=name,
            description=description,
            ra_mode=ra_mode,
            reachable_timer=reachable_timer,
            retransmit_interval=retransmit_interval,
            tags=tags,
            tenant=tenant)
        self._create_or_store(profile_def)
        return profile_id

    def delete(self, profile_id, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(profile_id=profile_id,
                                     tenant=tenant)
        self.policy_api.delete(profile_def)

    def get(self, profile_id, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(profile_id=profile_id,
                                     tenant=tenant)
        return self.policy_api.get(profile_def)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        profile_def = self.entry_def(tenant=tenant)
        return self._list(profile_def)

    def get_by_name(self, name, tenant=constants.POLICY_INFRA_TENANT):
        return super(NsxSegmentProfileBaseApi, self).get_by_name(
            name, tenant=tenant)

    def update(self, profile_id, name=IGNORE, description=IGNORE,
               ra_mode=IGNORE, reachable_timer=IGNORE,
               retransmit_interval=IGNORE,
               tags=IGNORE, tenant=constants.POLICY_INFRA_TENANT):
        self._update(profile_id=profile_id,
                     name=name,
                     description=description,
                     ra_mode=ra_mode,
                     reachable_timer=reachable_timer,
                     retransmit_interval=retransmit_interval,
                     tags=tags,
                     tenant=tenant)


class NsxDhcpRelayConfigApi(NsxPolicyResourceBase):
    @property
    def entry_def(self):
        return core_defs.DhcpRelayConfigDef

    def create_or_overwrite(self, name,
                            config_id=None,
                            description=None,
                            server_addresses=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):

        config_id = self._init_obj_uuid(config_id)
        config_def = self._init_def(
            config_id=config_id,
            name=name,
            description=description,
            server_addresses=server_addresses,
            tags=tags,
            tenant=tenant)
        self._create_or_store(config_def)
        return config_id

    def delete(self, config_id, tenant=constants.POLICY_INFRA_TENANT):
        config_def = self.entry_def(config_id=config_id, tenant=tenant)
        self.policy_api.delete(config_def)

    def get(self, config_id, tenant=constants.POLICY_INFRA_TENANT,
            silent=False):
        config_def = self.entry_def(config_id=config_id, tenant=tenant)
        return self.policy_api.get(config_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        config_def = self.entry_def(tenant=tenant)
        return self._list(config_def)

    def update(self, config_id, name=IGNORE,
               description=IGNORE,
               server_addresses=IGNORE,
               tags=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        self._update(config_id=config_id,
                     name=name,
                     description=description,
                     server_addresses=server_addresses,
                     tags=tags,
                     tenant=tenant)


class NsxPolicyCertApi(NsxPolicyResourceBase):
    """NSX Policy Certificate API."""
    @property
    def entry_def(self):
        return core_defs.CertificateDef

    def create_or_overwrite(self, name, certificate_id=None,
                            pem_encoded=IGNORE, private_key=IGNORE,
                            passphrase=IGNORE,
                            key_algo=IGNORE,
                            description=IGNORE,
                            tags=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        certificate_id = self._init_obj_uuid(certificate_id)
        certificate_def = self._init_def(certificate_id=certificate_id,
                                         name=name,
                                         private_key=private_key,
                                         pem_encoded=pem_encoded,
                                         passphrase=passphrase,
                                         key_algo=key_algo,
                                         description=description,
                                         tags=tags,
                                         tenant=tenant)

        self._create_or_store(certificate_def)
        return certificate_id

    def delete(self, certificate_id,
               tenant=constants.POLICY_INFRA_TENANT):
        certificate_def = self.entry_def(certificate_id=certificate_id,
                                         tenant=tenant)
        self.policy_api.delete(certificate_def)

    def get(self, certificate_id, tenant=constants.POLICY_INFRA_TENANT,
            silent=False):
        certificate_def = self.entry_def(certificate_id=certificate_id,
                                         tenant=tenant)
        return self.policy_api.get(certificate_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        certificate_def = self.entry_def(tenant=tenant)
        return self._list(certificate_def)

    def update(self, certificate_id, name=IGNORE,
               pem_encoded=IGNORE, private_key=IGNORE,
               passphrase=IGNORE, key_algo=IGNORE, description=IGNORE,
               tags=IGNORE, tenant=constants.POLICY_INFRA_TENANT):
        self._update(certificate_id=certificate_id,
                     name=name,
                     description=description,
                     tags=tags,
                     private_key=private_key,
                     pem_encoded=pem_encoded,
                     passphrase=passphrase,
                     key_algo=key_algo,
                     tenant=tenant)


class NsxPolicyExcludeListApi(NsxPolicyResourceBase):
    """NSX Policy Exclude list."""

    @property
    def entry_def(self):
        return core_defs.ExcludeListDef

    def create_or_overwrite(self, members=IGNORE,
                            tenant=constants.POLICY_INFRA_TENANT):
        exclude_list_def = self._init_def(members=members,
                                          tenant=tenant)

        self._create_or_store(exclude_list_def)

    def delete(self, tenant=constants.POLICY_INFRA_TENANT):
        err_msg = (_("This action is not supported"))
        raise exceptions.ManagerError(details=err_msg)

    def get(self, tenant=constants.POLICY_INFRA_TENANT, silent=False):
        exclude_list_def = self.entry_def(tenant=tenant)
        return self.policy_api.get(exclude_list_def, silent=silent)

    def list(self, tenant=constants.POLICY_INFRA_TENANT):
        err_msg = (_("This action is not supported"))
        raise exceptions.ManagerError(details=err_msg)

    def update(self, members=IGNORE,
               tenant=constants.POLICY_INFRA_TENANT):
        err_msg = (_("This action is not supported"))
        raise exceptions.ManagerError(details=err_msg)

    # TODO(asarfaty): Add support for add/remove member
