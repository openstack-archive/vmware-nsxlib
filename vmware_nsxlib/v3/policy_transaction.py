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
from vmware_nsxlib.v3 import policy_defs


class NsxPolicyTransactionException(exceptions.NsxLibException):
    message = _("Policy Transaction Error: %(msg)s")


class NsxPolicyTransaction(object):
    # stores current transaction per thread
    # nested transactions not supported

    data = threading.local()
    data.instance = None

    def __init__(self):
        self.defs = {}

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

    def apply_defs(self):
        # TODO(annak): find longest common URL, for now always
        # applying on tenant level

        if not self.defs:
            return

        url = policy_defs.TENANTS_PATH_PATTERN % self.defs[0].get_tenant()
        body = {}
        for resource_def in self.defs:
            path = resource_def.get_resource_path()
            body = resource_def.get_obj_dict()

            body['id'] = resource_def.get_id()

            # Remove tenant from URL
            url_tokens = path.split("/")[1:]
            for token in url_tokens[:-1]:
                parent_dict = {'children': body}
                body = parent_dict

                # TODO(annak): change to log and support silent
                print("Transaction body: %s" % body)

            self.client.patch(url, body)

    @staticmethod
    def get_current():
        return NsxPolicyTransaction.data.instance
