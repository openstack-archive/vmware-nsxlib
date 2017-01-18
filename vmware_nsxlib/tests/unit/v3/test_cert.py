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
from OpenSSL import crypto
from oslo_serialization import jsonutils

from vmware_nsxlib.tests.unit.v3 import mocks
from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.tests.unit.v3 import test_client
from vmware_nsxlib.v3 import client
from vmware_nsxlib.v3 import client_cert
from vmware_nsxlib.v3 import exceptions as nsxlib_exc
from vmware_nsxlib.v3 import trust_management


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

    def is_empty(self, project_id):
        return project_id not in self


class NsxV3ClientCertificateTestCase(nsxlib_testcase.NsxClientTestCase):

    identity = 'drumknott'
    cert_id = "00000000-1111-2222-3333-444444444444"
    identity_id = "55555555-6666-7777-8888-999999999999"

    def _get_mocked_response(self, status_code, results):
        return mocks.MockRequestsResponse(
            status_code,
            jsonutils.dumps({'results': results}))

    def _get_mocked_error_response(self, status_code, error_code):
        return mocks.MockRequestsResponse(
            status_code,
            jsonutils.dumps({'httpStatus': 'go away',
                             'error_code': error_code,
                             'module_name': 'never mind',
                             'error message': 'bad luck'}))

    def _get_mocked_trust(self, action):

        fake_responses = []
        if action == 'create':
            # import cert and return its id
            results = [{'id': self.cert_id}]
            fake_responses.append(self._get_mocked_response(201, results))
            # and then bind this id to principal identity
            fake_responses.append(self._get_mocked_response(201, []))

        elif action == 'retry-create':
            # simulate "identity already exists" failure
            results = [{'id': self.cert_id}]
            fake_responses.append(self._get_mocked_response(201, results))
            fake_responses.append(self._get_mocked_error_response(400, 2027))
            # after error generate code will retry identity deletion:
            # first get indentities
            results = [{'resource_type': 'Principal Identity',
                        'id': self.identity_id,
                        'name': self.identity,
                        'certificate_id': self.cert_id}]
            # then delete identity
            fake_responses.append(self._get_mocked_response(200, results))
            # then retry identity create
            fake_responses.append(self._get_mocked_response(204, []))

        elif action == 'delete':
            # get principal identities list
            results = [{'resource_type': 'Principal Identity',
                        'id': 'dont care',
                        'name': 'willikins',
                        'certificate_id': 'some other id'},
                       {'resource_type': 'Principal Identity',
                        'id': self.identity_id,
                        'name': self.identity,
                        'certificate_id': self.cert_id}]
            fake_responses.append(self._get_mocked_response(200, results))
            # delete certificate
            fake_responses.append(self._get_mocked_response(204, []))
            # delete identity
            fake_responses.append(self._get_mocked_response(204, []))

        mock_client = self.new_mocked_client(
            client.JSONRESTClient,
            url_prefix='api/v1', session_response=fake_responses)

        return trust_management.NsxLibTrustManagement(mock_client, {})

    def test_generate_cert(self):
        """Test startup without certificate + certificate generation"""

        storage_driver = DummyStorageDriver()
        # Prepare fake trust management for "cert create" requests
        mocked_trust = self._get_mocked_trust('create')
        cert = client_cert.ClientCertificateManager(self.identity,
                                                    mocked_trust,
                                                    storage_driver)
        self.assertFalse(cert.exists())

        cert.generate(subject={}, key_size=2048, valid_for_days=333)

        # verify client cert was generated and makes sense
        self.assertTrue(cert.exists())
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

    def test_generate_cert_with_retry(self):
        """Test startup without certificate + certificate generation"""

        storage_driver = DummyStorageDriver()
        # Prepare fake trust management for "cert create" requests
        mocked_trust = self._get_mocked_trust('retry-create')
        cert = client_cert.ClientCertificateManager(self.identity,
                                                    mocked_trust,
                                                    storage_driver)
        self.assertFalse(cert.exists())
        cert.generate(subject={}, key_size=4096, valid_for_days=3)

        # verify client cert was generated and makes sense
        self.assertTrue(cert.exists())

        # verify cert ans PK were stored in storage
        cert_pem, key_pem = cert.get_pem()
        stored_cert, stored_key = storage_driver.get_cert(self.identity)
        self.assertEqual(cert_pem, stored_cert)
        self.assertEqual(key_pem, stored_key)

    def _prepare_storage_with_existing_cert(self, key_size, days, alg, subj):
        # prepare storage driver with existing cert and key
        # this test simulates system startup
        cert, key = client_cert.generate_self_signed_cert_pair(key_size, days,
                                                               alg, subj)
        storage_driver = DummyStorageDriver()
        cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)

        storage_driver.store_cert(self.identity, cert_pem, key_pem)
        return storage_driver

    def test_load_and_delete_existing_cert(self):
        """Test startup with existing certificate + certificate deletion"""

        storage_driver = self._prepare_storage_with_existing_cert(4096,
                                                                  3650,
                                                                  'sha256',
                                                                  {})

        # get mocked backend driver for trust management,
        # prepared for get request, that preceeds delete operation
        mocked_trust = self._get_mocked_trust('delete')

        cert = client_cert.ClientCertificateManager(self.identity,
                                                    mocked_trust,
                                                    storage_driver)
        self.assertTrue(cert.exists())

        cert.delete()

        self.assertFalse(cert.exists())
        self.assertTrue(storage_driver.is_empty(self.identity))

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

    def test_get_certificate_details(self):
        """Test retrieving cert details for existing cert"""

        key_size = 2048
        days = 999
        alg = 'sha256'
        subj = {'country': 'CA',
                'organization': 'squirrel rights',
                'hostname': 'www.squirrels.ca',
                'unit': 'nuts',
                'state': 'BC'}

        storage_driver = self._prepare_storage_with_existing_cert(key_size,
                                                                  days, alg,
                                                                  subj)
        with client_cert.ClientCertificateManager(self.identity,
                                                  None,
                                                  storage_driver) as cert:
            self.assertTrue(cert.exists())
            self.assertEqual(days - 1, cert.expires_in_days())
            self.assertEqual(key_size, cert.get_key_size())
            cert_subj = cert.get_subject()
            self.assertEqual(subj, cert_subj)

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
                              client_cert.generate_self_signed_cert_pair,
                              **args)
