# Copyright 2015 VMware, Inc.
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

from neutron_lib import exceptions

from oslo_log import log
from oslo_serialization import jsonutils

from vmware_nsxlib.tests.unit.v3 import mocks
from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.tests.unit.v3 import test_client
from vmware_nsxlib.v3 import exceptions as nsxlib_exc

from vmware_nsxlib.v3 import client
from vmware_nsxlib.v3 import client_cert
from vmware_nsxlib.v3 import trust_management

from OpenSSL import crypto

LOG = log.getLogger(__name__)


class DummyStorageDriver(dict):
    """Storage driver simulation - just a dictionary"""

    def store_cert(self, project_id, certificate, private_key):
        self[project_id] = {}
        self[project_id]['cert'] = certificate
        self[project_id]['key'] = private_key

    def get_cert(self, project_id):
        if project_id not in self:
            return (None, None)

        return (self[project_id]['cert'], self[project_id]['key'])

    def delete_cert(self, project_id):
        del(self[project_id])

    def assert_empty(self, project_id):
        assert project_id not in self


class NsxV3ClientCertificateTestCase(nsxlib_testcase.NsxClientTestCase):

    identity = 'drumknott'
    cert_id = "00000000-1111-2222-3333-444444444444"
    identity_id = "55555555-6666-7777-8888-999999999999"

    def _get_mocked_trust(self, action):

        fake_results = {}
        resp_code = 200
        # if action is translated to 2 calls on backend,
        # we need to fake first response data since its used later on
        if action == 'create':
            # create will first import cert and return its id
            # and then bind this id to principal identity
            fake_results = [{'id': self.cert_id}]
            resp_code = 204
        if action == 'get':
            fake_results = [{'resource_type': 'Principal Identity',
                             'id': 'dont care',
                             'name': 'willikins',
                             'certificate_id': 'some other id'},
                            {'resource_type': 'Principal Identity',
                             'id': self.identity_id,
                             'name': self.identity,
                             'certificate_id': self.cert_id}]
            resp_code = 200

        mocked_response = mocks.MockRequestsResponse(
                resp_code, jsonutils.dumps({'results': fake_results}))
        mock_client = self.new_mocked_client(client.JSONRESTClient,
                url_prefix='api/v1', session_response=mocked_response)
        return trust_management.NsxLibTrustManagement(mock_client, {})

    def test_generate_cert(self):
        """Test startup without certificate + certificate generation"""

        storage_driver = DummyStorageDriver()
        # Prepare fake trust management for "cert create" requests
        mocked_trust = self._get_mocked_trust('create')
        cert = client_cert.ClientCertificateManager(self.identity,
                                                    mocked_trust,
                                                    storage_driver)
        assert not cert.exists()

        cert.generate(subject={}, key_size=2048, valid_for_days=333)

        # verify client cert was generated and makes sense
        assert cert.exists()
        self.assertEqual(332, cert.expires_in_days())
        cert_pem, key_pem = cert.get_pem()

        # verify cert ans PK were stored in storage
        stored_cert, stored_key = storage_driver.get_cert(self.identity)
        self.assertEqual(cert_pem, stored_cert)
        self.assertEqual(key_pem, stored_key)

        # verify API call to import cert on backend
        cert_pem = mocked_trust.remove_newlines_from_pem(cert_pem)
        base_uri = 'https://1.2.3.4/api/v1/trust-management'
        uri = base_uri + '/certificates?action=import'
        expected_body = {'pem_encoded': cert_pem}
        test_client.assert_json_call('post', mocked_trust.client, uri,
                                    single_call=False,
                                    data=jsonutils.dumps(expected_body))

        # verify API call to bind cert to identity on backend
        uri = base_uri + '/principal-identities'
        expected_body = {'name': self.identity,
                         'certificate_id': self.cert_id}
        test_client.assert_json_call('post', mocked_trust.client, uri,
                                    single_call=False,
                                    data=jsonutils.dumps(expected_body,
                                                         sort_keys=True))

        # try to generate cert again and fail
        self.assertRaises(nsxlib_exc.ObjectAlreadyExists,
                cert.generate, {})

    def test_load_and_delete_existing_cert(self):
        """Test startup with existing certificate + certificate deletion"""

        # prepare storage driver with existing cert and key
        # this test simulates system startup
        cert, key = client_cert.generate_self_signed_cert_pair(4096, 365,
                                                               'sha256', {})
        storage_driver = DummyStorageDriver()
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

        storage_driver.store_cert(self.identity, cert_pem, key_pem)
        # get mocked backend driver for trust management,
        # prepared for get request, that preceeds delete operation
        mocked_trust = self._get_mocked_trust('get')

        cert = client_cert.ClientCertificateManager(self.identity,
                                                    mocked_trust,
                                                    storage_driver)
        assert cert.exists()

        cert.delete()

        assert not cert.exists()
        storage_driver.assert_empty(self.identity)

        # verify API call to query identities in order to get cert id
        base_uri = 'https://1.2.3.4/api/v1/trust-management'
        uri = base_uri + '/principal-identities'
        test_client.assert_json_call('get', mocked_trust.client, uri,
                                    single_call=False)

        # verify API call to delete openstack principal identity
        uri = uri + '/' + self.identity_id
        test_client.assert_json_call('delete', mocked_trust.client, uri,
                                    single_call=False)

        # verify API call to delete certificate
        uri = base_uri + '/certificates/' + self.cert_id
        test_client.assert_json_call('delete', mocked_trust.client, uri,
                                    single_call=False)

    def test_bad_certificate_values(self):
        bad_cert_values = [{'key_size': 1024,
                            'valid_for_days': 10,
                            'signature_alg': 'sha256',
                            'subject': {}},
                           {'key_size': 4096,
                            'valid_for_days': 100,
                            'signature_alg': 'sha',
                            'subject': {}}]

        for args in bad_cert_values:
            self.assertRaises(exceptions.InvalidInput,
                    client_cert.generate_self_signed_cert_pair, **args)
