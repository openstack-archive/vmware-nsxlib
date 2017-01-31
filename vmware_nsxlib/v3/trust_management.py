# Copyright 2016 VMware, Inc.
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

from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import utils

BASE_SECTION = 'trust-management'
CERT_SECTION = BASE_SECTION + '/certificates'
ID_SECTION = BASE_SECTION + '/principal-identities'


class NsxLibTrustManagement(utils.NsxLibApiBase):

    def remove_newlines_from_pem(self, pem):
        """NSX expects pem without newlines in certificate body

        BEGIN and END sections should be separated with newlines
        """
        lines = pem.split(b'\n')
        result = lines[0] + b'\n'
        result += b''.join(lines[1:-2])
        result += b'\n' + lines[-2]
        return result

    def create_cert(self, cert_pem):
        resource = CERT_SECTION + '?action=import'
        body = {'pem_encoded': self.remove_newlines_from_pem(cert_pem)}

        results = self.client.create(resource, body)['results']
        if len(results) > 0:
            # should be only one result
            return results[0]['id']

    def get_cert(self, cert_id):
        resource = CERT_SECTION + '/' + cert_id
        return self.client.get(resource)

    def delete_cert(self, cert_id):
        resource = CERT_SECTION + '/' + cert_id
        self.client.delete(resource)

    def create_identity(self, identity, cert_id):
        body = {'name': identity, 'certificate_id': cert_id}
        self.client.create(ID_SECTION, body)

    def delete_identity(self, identity):
        resource = ID_SECTION + '/' + identity
        self.client.delete(resource)

    def get_identity_details(self, identity):
        results = self.client.get(ID_SECTION)['results']
        for result in results:
            if result['name'] == identity:
                return result

        raise nsxlib_exc.ResourceNotFound(
            manager=self.client.nsx_api_managers,
            operation="Principal identity %s not found" % identity)
