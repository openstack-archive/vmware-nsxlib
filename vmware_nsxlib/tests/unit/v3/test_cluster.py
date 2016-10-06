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
import mock
import six.moves.urllib.parse as urlparse
import unittest

from oslo_serialization import jsonutils
from requests import exceptions as requests_exceptions

from vmware_nsxlib.tests.unit.v3 import mocks
from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.v3 import client
from vmware_nsxlib.v3 import cluster
from vmware_nsxlib.v3 import exceptions as nsxlib_exc


def _validate_conn_up(*args, **kwargs):
    return


def _validate_conn_down(*args, **kwargs):
    raise requests_exceptions.ConnectionError()


class RequestsHTTPProviderTestCase(unittest.TestCase):

    def test_new_connection(self):
        mock_api = mock.Mock()
        mock_api.nsxlib_config = mock.Mock()
        mock_api.nsxlib_config.username = 'nsxuser'
        mock_api.nsxlib_config.password = 'nsxpassword'
        mock_api.nsxlib_config.retries = 100
        mock_api.nsxlib_config.insecure = True
        mock_api.nsxlib_config.ca_file = None
        mock_api.nsxlib_config.http_timeout = 99
        mock_api.nsxlib_config.conn_idle_timeout = 39
        provider = cluster.NSXRequestsHTTPProvider()
        session = provider.new_connection(
            mock_api, cluster.Provider('9.8.7.6', 'https://9.8.7.6',
                                       'nsxuser', 'nsxpassword', None))

        self.assertEqual(session.auth, ('nsxuser', 'nsxpassword'))
        self.assertEqual(session.verify, False)
        self.assertEqual(session.cert, None)
        self.assertEqual(session.adapters['https://'].max_retries.total, 100)
        self.assertEqual(session.timeout, 99)

    def test_validate_connection(self):
        self.skipTest("Revist")
        mock_conn = mocks.MockRequestSessionApi()
        mock_ep = mock.Mock()
        mock_ep.provider.url = 'https://1.2.3.4'
        provider = cluster.NSXRequestsHTTPProvider()
        self.assertRaises(nsxlib_exc.ResourceNotFound,
                          provider.validate_connection,
                          mock.Mock(), mock_ep, mock_conn)

        mock_conn.post('api/v1/transport-zones',
                       data=jsonutils.dumps({'id': 'dummy-tz'}),
                       headers=client.JSONRESTClient._DEFAULT_HEADERS)
        provider.validate_connection(mock.Mock(), mock_ep, mock_conn)


class NsxV3ClusteredAPITestCase(nsxlib_testcase.NsxClientTestCase):

    def _assert_providers(self, cluster_api, provider_tuples):
        self.assertEqual(len(cluster_api.providers), len(provider_tuples))

        def _assert_provider(pid, purl):
            for provider in cluster_api.providers:
                if provider.id == pid and provider.url == purl:
                    return
            self.fail("Provider: %s not found" % pid)

        for provider_tuple in provider_tuples:
            _assert_provider(provider_tuple[0], provider_tuple[1])

    def test_conf_providers_no_scheme(self):
        conf_managers = ['8.9.10.11', '9.10.11.12:4433']
        api = self.new_mocked_cluster(conf_managers, _validate_conn_up)

        self._assert_providers(
            api, [(p, "https://%s" % p) for p in conf_managers])

    def test_conf_providers_with_scheme(self):
        conf_managers = ['http://8.9.10.11:8080', 'https://9.10.11.12:4433']
        api = self.new_mocked_cluster(conf_managers, _validate_conn_up)

        self._assert_providers(
            api, [(urlparse.urlparse(p).netloc, p) for p in conf_managers])

    def test_http_retries(self):
        api = self.mock_nsx_clustered_api(retries=9)
        with api.endpoints['1.2.3.4'].pool.item() as session:
            self.assertEqual(
                session.adapters['https://'].max_retries.total, 9)

    def test_conns_per_pool(self):
        conf_managers = ['8.9.10.11', '9.10.11.12:4433']
        api = self.new_mocked_cluster(
            conf_managers, _validate_conn_up,
            concurrent_connections=11)

        for ep_id, ep in api.endpoints.items():
            self.assertEqual(ep.pool.max_size, 11)

    def test_timeouts(self):
        api = self.mock_nsx_clustered_api(http_read_timeout=37, http_timeout=7)
        api.get('logical-ports')
        mock_call = api.recorded_calls.method_calls[0]
        name, args, kwargs = mock_call
        self.assertEqual(kwargs['timeout'], (7, 37))


class ClusteredAPITestCase(nsxlib_testcase.NsxClientTestCase):

    def _test_health(self, validate_fn, expected_health):
        conf_managers = ['8.9.10.11', '9.10.11.12']
        api = self.new_mocked_cluster(conf_managers, validate_fn)

        self.assertEqual(api.health, expected_health)

    def test_orange_health(self):

        def _validate(cluster_api, endpoint, conn):
            if endpoint.provider.id == '8.9.10.11':
                raise Exception()

        self._test_health(_validate, cluster.ClusterHealth.ORANGE)

    def test_green_health(self):
        self._test_health(_validate_conn_up, cluster.ClusterHealth.GREEN)

    def test_red_health(self):
        self._test_health(_validate_conn_down, cluster.ClusterHealth.RED)

    def test_cluster_validate_with_exception(self):
        conf_managers = ['8.9.10.11', '9.10.11.12', '10.11.12.13']
        api = self.new_mocked_cluster(conf_managers, _validate_conn_down)

        self.assertEqual(len(api.endpoints), 3)
        self.assertRaises(nsxlib_exc.ServiceClusterUnavailable,
                          api.get, 'api/v1/transport-zones')

    def test_cluster_proxy_stale_revision(self):

        def stale_revision():
            raise nsxlib_exc.StaleRevision(manager='1.1.1.1',
                                           operation='whatever')

        api = self.mock_nsx_clustered_api(session_response=stale_revision)
        self.assertRaises(nsxlib_exc.StaleRevision,
                          api.get, 'api/v1/transport-zones')

    def test_cluster_proxy_connection_error(self):

        def connect_timeout():
            raise requests_exceptions.ConnectTimeout()

        api = self.mock_nsx_clustered_api(session_response=connect_timeout)
        api._validate = mock.Mock()
        self.assertRaises(nsxlib_exc.ServiceClusterUnavailable,
                          api.get, 'api/v1/transport-zones')

    def test_cluster_round_robin_servicing(self):
        conf_managers = ['8.9.10.11', '9.10.11.12', '10.11.12.13']
        api = self.mock_nsx_clustered_api(nsx_api_managers=conf_managers)
        api._validate = mock.Mock()

        eps = list(api._endpoints.values())

        def _get_schedule(num_eps):
            return [api._select_endpoint() for i in range(num_eps)]

        self.assertEqual(_get_schedule(3), eps)

        self.assertEqual(_get_schedule(6), [eps[0], eps[1], eps[2],
                                            eps[0], eps[1], eps[2]])

        eps[0]._state = cluster.EndpointState.DOWN
        self.assertEqual(_get_schedule(4), [eps[1], eps[2], eps[1], eps[2]])

        eps[1]._state = cluster.EndpointState.DOWN
        self.assertEqual(_get_schedule(2), [eps[2], eps[2]])

        eps[0]._state = cluster.EndpointState.UP
        self.assertEqual(_get_schedule(4), [eps[0], eps[2], eps[0], eps[2]])

    def test_reinitialize_cluster(self):
        api = self.mock_nsx_clustered_api()
        # just make sure this api is defined, and does not crash
        api._reinit_cluster()
