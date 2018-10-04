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

import threading

from vmware_nsxlib._i18n import _

from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import policy_constants
from vmware_nsxlib.v3 import policy_defs


class NsxPolicyTransactionException(exceptions.NsxLibException):
    message = _("Policy Transaction Error: %(msg)s")


class NsxPolicyTransaction(object):
    # stores current transaction per thread
    # nested transactions not supported

    data = threading.local()
    data.instance = None

    def __init__(self):
        # For now only infra tenant is supported
        self.defs = [policy_defs.TenantDef(
            tenant=policy_constants.POLICY_INFRA_TENANT)]

    def __enter__(self):
        if self.data.instance:
            raise NsxPolicyTransactionException(
                "Nested transactions not supported")

        self.data.instance = self
        return self

    def __exit__(self, e_type, e_value, e_traceback):
        # Always reset transaction regardless of exceptions
        self.data.instance = None

        if e_type:
            # If exception occured in the "with" block, raise it
            # without applying to backend
            return False

        # exception might happen here and will be raised
        self.apply_defs()

    def store_def(self, resource_def):
        # TODO(annak): raise exception for different tenants
        self.defs.append(resource_def)

    def _sort_defs(self):
        sorted_defs = []

        while len(sorted_defs) < len(self.defs):
            for resource_def in self.defs:
                # We want all parents to appear before the child
                parent_type = resource_def.path_defs()[-1]
                parents = [d for d in self.defs if isinstance(d, parent_type)]
                missing_parents = [d for d in parents if d not in sorted_defs]

                if not missing_parents:
                    # All parents are appended to sorted list, child can go in
                    sorted_defs.append(resource_def)

        self.defs = sorted_defs

    def _find_parent_in_dict(self, d, resource_def, level=0):

        parent_type = resource_def.path_defs()[level]
        resource_type = parent_type.resource_type()
        parent_id = resource_def.get_attr(resource_def.path_ids[level])
        if resource_type in d and d[resource_type]:
            parent = d[resource_type]
            if parent['id'] == parent_id:
                if len(resource_def) == 1:
                    return parent
                if 'children' in parent:
                    return self._find_parent_in_dict(
                        parent, resource_def[1:], level + 1)

    def apply_defs(self):
        # TODO(annak): find longest common URL, for now always
        # applying on tenant level

        if not self.defs:
            return

        self._sort_defs()

        url = self.defs[0].get_resource_path()
        body = {}
        for resource_def in self.defs[1:]:
            parent_dict = self._find_parent_in_dict(body, resource_def)

            if not parent_dict:
                parent_dict = body

            if 'children' not in parent_dict:
                parent_dict['children'] = []

            parent_dict['children'].append({
                'resource_type': 'Child%s' % resource_def.get_resource_type(),
                resource_def.get_resource_type(): resource_def.get_obj_dict()
            })

        self.client.patch(url, body)

    @staticmethod
    def get_current():
        return NsxPolicyTransaction.data.instance
