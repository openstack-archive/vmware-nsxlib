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

from vmware_nsxlib.v3 import policy_defs


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

    # DEBUG ADIT create_with_parent??


class NsxPolicyDomainApi(NsxPolicyResourceBase):
    def create(self, name, domain_id=None, description=None):
        if not domain_id:
            # generate a random id
            domain_id = str(uuid.uuid4())

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
        # DEBUG ADIT - this currently fails. Cursor issue.
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

    def get_by_name(self, name):
        # Return first match by name
        resources_list = self.list()
        for obj in resources_list:
            if obj.get('display_name') == name:
                return obj


class NsxPolicyGroupApi(NsxPolicyResourceBase):
    def create(self, group_name, domain_id, group_id=None,
               description=None, conditions=None):
        """Create a group under a specific domain."""
        if not group_id:
            # generate a random id
            group_id = str(uuid.uuid4())

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
