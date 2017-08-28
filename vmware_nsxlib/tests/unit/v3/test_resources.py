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
import copy

import mock

from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from vmware_nsxlib.tests.unit.v3 import mocks
from vmware_nsxlib.tests.unit.v3 import nsxlib_testcase
from vmware_nsxlib.tests.unit.v3 import test_client
from vmware_nsxlib.tests.unit.v3 import test_constants
from vmware_nsxlib.v3 import core_resources
from vmware_nsxlib.v3 import exceptions
from vmware_nsxlib.v3 import nsx_constants
from vmware_nsxlib.v3 import resources


CLIENT_PKG = test_client.CLIENT_PKG
profile_types = resources.SwitchingProfileTypes


class TestSwitchingProfileTestCase(nsxlib_testcase.NsxClientTestCase):

    def _mocked_switching_profile(self, session_response=None):
        return self.mocked_resource(
            resources.SwitchingProfile, session_response=session_response)

    def test_switching_profile_create(self):
        mocked_resource = self._mocked_switching_profile()

        mocked_resource.create(profile_types.PORT_MIRRORING,
                               'pm-profile', 'port mirror prof')

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps({
                'resource_type': profile_types.PORT_MIRRORING,
                'display_name': 'pm-profile',
                'description': 'port mirror prof'
            }, sort_keys=True),
            headers=self.default_headers())

    def test_switching_profile_update(self):

        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        mocked_resource = self._mocked_switching_profile()

        mocked_resource.update(
            'a12bc1', profile_types.PORT_MIRRORING, tags=tags)

        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles/a12bc1',
            data=jsonutils.dumps({
                'resource_type': profile_types.PORT_MIRRORING,
                'tags': tags
            }, sort_keys=True),
            headers=self.default_headers())

    def test_spoofgaurd_profile_create(self):

        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        mocked_resource = self._mocked_switching_profile()

        mocked_resource.create_spoofguard_profile(
            'plugin-spoof', 'spoofguard-for-plugin',
            whitelist_ports=True, tags=tags)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps({
                'resource_type': profile_types.SPOOF_GUARD,
                'display_name': 'plugin-spoof',
                'description': 'spoofguard-for-plugin',
                'white_list_providers': ['LPORT_BINDINGS'],
                'tags': tags
            }, sort_keys=True),
            headers=self.default_headers())

    def test_create_dhcp_profile(self):

        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        mocked_resource = self._mocked_switching_profile()

        mocked_resource.create_dhcp_profile(
            'plugin-dhcp', 'dhcp-for-plugin',
            tags=tags)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps({
                'bpdu_filter': {
                    'enabled': True,
                    'white_list': []
                },
                'resource_type': profile_types.SWITCH_SECURITY,
                'display_name': 'plugin-dhcp',
                'description': 'dhcp-for-plugin',
                'tags': tags,
                'dhcp_filter': {
                    'client_block_enabled': True,
                    'server_block_enabled': False
                },
                'rate_limits': {
                    'enabled': False,
                    'rx_broadcast': 0,
                    'tx_broadcast': 0,
                    'rx_multicast': 0,
                    'tx_multicast': 0
                },
                'block_non_ip_traffic': True
            }, sort_keys=True),
            headers=self.default_headers())

    def test_create_mac_learning_profile(self):

        tags = [
            {
                'scope': 'os-project-id',
                'tag': 'project-1'
            },
            {
                'scope': 'os-api-version',
                'tag': '2.1.1.0'
            }
        ]

        mocked_resource = self._mocked_switching_profile()

        mocked_resource.create_mac_learning_profile(
            'plugin-mac-learning', 'mac-learning-for-plugin',
            tags=tags)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles',
            data=jsonutils.dumps({
                'mac_learning': {
                    'enabled': True,
                },
                'resource_type': profile_types.MAC_LEARNING,
                'display_name': 'plugin-mac-learning',
                'description': 'mac-learning-for-plugin',
                'tags': tags,
                'mac_change_allowed': True,
            }, sort_keys=True),
            headers=self.default_headers())

    def test_find_by_display_name(self):
        resp_resources = {
            'results': [
                {'display_name': 'resource-1'},
                {'display_name': 'resource-2'},
                {'display_name': 'resource-3'}
            ]
        }
        session_response = mocks.MockRequestsResponse(
            200, jsonutils.dumps(resp_resources))
        mocked_resource = self._mocked_switching_profile(
            session_response=[session_response] * 3)

        self.assertEqual([{'display_name': 'resource-1'}],
                         mocked_resource.find_by_display_name('resource-1'))
        self.assertEqual([{'display_name': 'resource-2'}],
                         mocked_resource.find_by_display_name('resource-2'))
        self.assertEqual([{'display_name': 'resource-3'}],
                         mocked_resource.find_by_display_name('resource-3'))

        resp_resources = {
            'results': [
                {'display_name': 'resource-1'},
                {'display_name': 'resource-1'},
                {'display_name': 'resource-1'}
            ]
        }
        session_response = mocks.MockRequestsResponse(
            200, jsonutils.dumps(resp_resources))
        mocked_resource = self._mocked_switching_profile(
            session_response=session_response)
        self.assertEqual(resp_resources['results'],
                         mocked_resource.find_by_display_name('resource-1'))

    def test_list_all_profiles(self):
        mocked_resource = self._mocked_switching_profile()
        mocked_resource.list()
        test_client.assert_json_call(
            'get', mocked_resource,
            'https://1.2.3.4/api/v1/switching-profiles/'
            '?include_system_owned=True',
            data=None,
            headers=self.default_headers())


class LogicalPortTestCase(nsxlib_testcase.NsxClientTestCase):

    def _mocked_lport(self, mock_validate=True, session_response=None):
        return self.mocked_resource(
            resources.LogicalPort, mock_validate=True,
            session_response=session_response)

    def _get_profile_dicts(self, fake_port):
        fake_profile_dicts = []
        for profile_id in fake_port['switching_profile_ids']:
            fake_profile_dicts.append({'resource_type': profile_id['key'],
                                       'id': profile_id['value']})
        return fake_profile_dicts

    def _get_pktcls_bindings(self):
        fake_pkt_classifiers = []
        fake_binding_repr = []
        for i in range(0, 3):
            ip = "9.10.11.%s" % i
            mac = "00:0c:29:35:4a:%sc" % i
            fake_pkt_classifiers.append(resources.PacketAddressClassifier(
                ip, mac, None))
            fake_binding_repr.append({
                'ip_address': ip,
                'mac_address': mac
            })
        return fake_pkt_classifiers, fake_binding_repr

    def test_create_logical_port(self):
        """Test creating a port.

        returns the correct response and 200 status
        """
        fake_port = test_constants.FAKE_PORT.copy()

        profile_dicts = self._get_profile_dicts(fake_port)

        pkt_classifiers, binding_repr = self._get_pktcls_bindings()

        fake_port['address_bindings'] = binding_repr

        mocked_resource = self._mocked_lport()

        switch_profile = resources.SwitchingProfile
        mocked_resource.create(
            fake_port['logical_switch_id'],
            fake_port['attachment']['id'],
            address_bindings=pkt_classifiers,
            switch_profile_ids=switch_profile.build_switch_profile_ids(
                mock.Mock(), *profile_dicts))

        resp_body = {
            'logical_switch_id': fake_port['logical_switch_id'],
            'switching_profile_ids': fake_port['switching_profile_ids'],
            'attachment': {
                'attachment_type': 'VIF',
                'id': fake_port['attachment']['id']
            },
            'admin_state': 'UP',
            'address_bindings': fake_port['address_bindings']
        }

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports',
            data=jsonutils.dumps(resp_body, sort_keys=True),
            headers=self.default_headers())

    def test_create_logical_port_with_attachtype_cif(self):
        """Test creating a port returns the correct response and 200 status

        """
        fake_port = test_constants.FAKE_CONTAINER_PORT.copy()

        profile_dicts = self._get_profile_dicts(fake_port)

        pkt_classifiers, binding_repr = self._get_pktcls_bindings()

        fake_port['address_bindings'] = binding_repr

        mocked_resource = self._mocked_lport()
        switch_profile = resources.SwitchingProfile
        fake_port_ctx = fake_port['attachment']['context']

        fake_container_host_vif_id = fake_port_ctx['container_host_vif_id']

        mocked_resource.create(
            fake_port['logical_switch_id'],
            fake_port['attachment']['id'],
            parent_vif_id=fake_container_host_vif_id,
            traffic_tag=fake_port_ctx['vlan_tag'],
            address_bindings=pkt_classifiers,
            switch_profile_ids=switch_profile.build_switch_profile_ids(
                mock.Mock(), *profile_dicts),
            vif_type=fake_port_ctx['vif_type'], app_id=fake_port_ctx['app_id'],
            allocate_addresses=fake_port_ctx['allocate_addresses'])

        resp_body = {
            'logical_switch_id': fake_port['logical_switch_id'],
            'switching_profile_ids': fake_port['switching_profile_ids'],
            'attachment': {
                'attachment_type': 'VIF',
                'id': fake_port['attachment']['id'],
                'context': {
                    'resource_type': 'VifAttachmentContext',
                    'allocate_addresses': 'Both',
                    'parent_vif_id': fake_container_host_vif_id,
                    'traffic_tag': fake_port_ctx['vlan_tag'],
                    'app_id': fake_port_ctx['app_id'],
                    'vif_type': 'CHILD',
                }
            },
            'admin_state': 'UP',
            'address_bindings': fake_port['address_bindings']
        }

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports',
            data=jsonutils.dumps(resp_body, sort_keys=True),
            headers=self.default_headers())

    def test_create_logical_port_admin_down(self):
        """Test creating port with admin_state down."""
        fake_port = test_constants.FAKE_PORT
        fake_port['admin_state'] = "DOWN"

        mocked_resource = self._mocked_lport(
            session_response=mocks.MockRequestsResponse(
                200, jsonutils.dumps(fake_port)))

        result = mocked_resource.create(
            test_constants.FAKE_PORT['logical_switch_id'],
            test_constants.FAKE_PORT['attachment']['id'],
            tags={}, admin_state=False)

        self.assertEqual(fake_port, result)

    def test_delete_logical_port(self):
        """Test deleting port."""
        mocked_resource = self._mocked_lport()

        uuid = test_constants.FAKE_PORT['id']
        mocked_resource.delete(uuid)
        test_client.assert_json_call(
            'delete', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports/%s?detach=true' % uuid,
            headers=self.default_headers())

    def test_get_logical_port_by_attachment(self):
        """Test deleting port."""
        mocked_resource = self._mocked_lport()
        attachment_type = nsx_constants.ATTACHMENT_DHCP
        attachment_id = '1234'
        mocked_resource.get_by_attachment(attachment_type, attachment_id)
        test_client.assert_json_call(
            'get', mocked_resource,
            "https://1.2.3.4/api/v1/logical-ports/?attachment_type=%s"
            "&attachment_id=%s" % (attachment_type, attachment_id),
            headers=self.default_headers())

    def test_clear_port_bindings(self):
        fake_port = copy.copy(test_constants.FAKE_PORT)
        fake_port['address_bindings'] = ['a', 'b']
        mocked_resource = self._mocked_lport()

        def get_fake_port(*args):
            return fake_port

        mocked_resource.get = get_fake_port
        mocked_resource.update(
            fake_port['id'], fake_port['id'], address_bindings=[])

        fake_port['address_bindings'] = []
        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/logical-ports/%s' % fake_port['id'],
            data=jsonutils.dumps(fake_port, sort_keys=True),
            headers=self.default_headers())

    def test_create_logical_port_fail(self):
        """Test the failure of port creation."""
        fake_port = test_constants.FAKE_PORT.copy()

        profile_dicts = self._get_profile_dicts(fake_port)

        pkt_classifiers, binding_repr = self._get_pktcls_bindings()

        fake_port['address_bindings'] = binding_repr

        mocked_resource = self._mocked_lport(mock_validate=False)

        switch_profile = resources.SwitchingProfile
        try:
            mocked_resource.create(
                fake_port['logical_switch_id'],
                fake_port['attachment']['id'],
                address_bindings=pkt_classifiers,
                switch_profile_ids=switch_profile.build_switch_profile_ids(
                    mock.Mock(), *profile_dicts))
        except exceptions.ManagerError as e:
            self.assertIn(nsxlib_testcase.NSX_MANAGER, e.msg)


class LogicalRouterTestCase(nsxlib_testcase.NsxClientTestCase):

    def _mocked_lrouter(self, session_response=None):
        return self.mocked_resource(
            core_resources.NsxLibLogicalRouter,
            session_response=session_response)

    def test_create_logical_router(self):
        """Test creating a router returns the correct response and 201 status.

        """
        fake_router = test_constants.FAKE_ROUTER.copy()

        router = self._mocked_lrouter()

        tier0_router = True
        description = 'dummy'
        router.create(fake_router['display_name'], None, None, tier0_router,
                      description=description)

        data = {
            'display_name': fake_router['display_name'],
            'router_type': 'TIER0' if tier0_router else 'TIER1',
            'tags': None,
            'description': description
        }

        test_client.assert_json_call(
            'post', router,
            'https://1.2.3.4/api/v1/logical-routers',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_delete_logical_router(self):
        """Test deleting router"""
        router = self._mocked_lrouter()
        uuid = test_constants.FAKE_ROUTER['id']
        router.delete(uuid)
        test_client.assert_json_call(
            'delete', router,
            'https://1.2.3.4/api/v1/logical-routers/%s' % uuid,
            headers=self.default_headers())

    def test_force_delete_logical_router(self):
        """Test force deleting router"""
        router = self._mocked_lrouter()
        uuid = test_constants.FAKE_ROUTER['id']
        router.delete(uuid, True)
        test_client.assert_json_call(
            'delete', router,
            'https://1.2.3.4/api/v1/logical-routers/%s?force=True' % uuid,
            headers=self.default_headers())

    def test_list_logical_router(self):
        router = self._mocked_lrouter()
        router.list()
        test_client.assert_json_call(
            'get', router,
            'https://1.2.3.4/api/v1/logical-routers')

    def test_list_logical_router_by_type(self):
        router = self._mocked_lrouter()
        router_type = 'TIER0'
        router.list(router_type=router_type)
        test_client.assert_json_call(
            'get', router,
            'https://1.2.3.4/api/v1/logical-routers?router_type=%s' %
            router_type)

    def test_get_logical_router_fw_section(self):
        fake_router = test_constants.FAKE_ROUTER.copy()

        router = self._mocked_lrouter()
        section_id = router.get_firewall_section_id(
            test_constants.FAKE_ROUTER_UUID, router_body=fake_router)
        self.assertEqual(test_constants.FAKE_ROUTER_FW_SEC_UUID, section_id)

    def _test_nat_rule_create(self, nsx_version, add_bypas_arg):
        router = self._mocked_lrouter()
        action = 'SNAT'
        translated_net = '1.1.1.1'
        priority = 10

        data = {
            'action': action,
            'enabled': True,
            'translated_network': translated_net,
            'rule_priority': priority
        }
        if add_bypas_arg:
            # Expect nat_pass to be sent to the backend
            data['nat_pass'] = False

        # Ignoring 'bypass_firewall' with version 1.1
        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value=nsx_version):
            router.add_nat_rule(test_constants.FAKE_ROUTER_UUID,
                                action=action,
                                translated_network=translated_net,
                                rule_priority=priority,
                                bypass_firewall=False)
            test_client.assert_json_call(
                'post', router,
                ('https://1.2.3.4/api/v1/logical-routers/%s/nat/rules' %
                    test_constants.FAKE_ROUTER_UUID),
                data=jsonutils.dumps(data, sort_keys=True),
                headers=self.default_headers())

    def test_nat_rule_create_v1(self):
        # Ignoring 'bypass_firewall' with version 1.1
        self._test_nat_rule_create('1.1.0', False)

    def test_nat_rule_create_v2(self):
        # Sending 'bypass_firewall' with version 1.1
        self._test_nat_rule_create('2.0.0', True)

    def test_nat_rule_list(self):
        router = self._mocked_lrouter()
        router.list_nat_rules(test_constants.FAKE_ROUTER_UUID)
        test_client.assert_json_call(
            'get', router,
            ('https://1.2.3.4/api/v1/logical-routers/%s/nat/rules' %
                test_constants.FAKE_ROUTER_UUID),
            headers=self.default_headers())

    def test_nat_rule_update(self):
        router = self._mocked_lrouter()
        rule_id = '123'
        with mock.patch.object(router.client, 'get',
                               return_value={'id': rule_id}):
            router.update_nat_rule(test_constants.FAKE_ROUTER_UUID,
                                   rule_id, nat_pass=False)
            data = {'id': rule_id, 'nat_pass': False}
            test_client.assert_json_call(
                'put', router,
                ('https://1.2.3.4/api/v1/logical-routers/%s/nat/rules/%s' %
                    (test_constants.FAKE_ROUTER_UUID, rule_id)),
                data=jsonutils.dumps(data, sort_keys=True),
                headers=self.default_headers())

    def test_delete_nat_rule_by_gw(self):
        router = self._mocked_lrouter()
        rule_id = '123'
        gw_ip = '3.3.3.3'
        existing_rules = [{
            'translated_network': gw_ip,
            'logical_router_id': test_constants.FAKE_ROUTER_UUID,
            'id': rule_id,
            'action': 'SNAT',
            'resource_type': 'NatRule'}]
        with mock.patch.object(router.client, 'list',
                               return_value={'results': existing_rules}):
            router.delete_nat_rule_by_values(test_constants.FAKE_ROUTER_UUID,
                                             translated_network=gw_ip)
            test_client.assert_json_call(
                'delete', router,
                ('https://1.2.3.4/api/v1/logical-routers/%s/nat/rules/%s' %
                    (test_constants.FAKE_ROUTER_UUID, rule_id)),
                headers=self.default_headers())

    def test_delete_nat_rule_by_gw_and_source(self):
        router = self._mocked_lrouter()
        rule_id = '123'
        gw_ip = '3.3.3.3'
        source_net = '4.4.4.4'
        existing_rules = [{
            'translated_network': gw_ip,
            'logical_router_id': test_constants.FAKE_ROUTER_UUID,
            'id': rule_id,
            'match_source_network': source_net,
            'action': 'SNAT',
            'resource_type': 'NatRule'}]
        with mock.patch.object(router.client, 'list',
                               return_value={'results': existing_rules}):
            router.delete_nat_rule_by_values(test_constants.FAKE_ROUTER_UUID,
                                             translated_network=gw_ip,
                                             match_source_network=source_net)
            test_client.assert_json_call(
                'delete', router,
                ('https://1.2.3.4/api/v1/logical-routers/%s/nat/rules/%s' %
                    (test_constants.FAKE_ROUTER_UUID, rule_id)),
                headers=self.default_headers())


class LogicalRouterPortTestCase(nsxlib_testcase.NsxClientTestCase):

    def _mocked_lrport(self, session_response=None):
        return self.mocked_resource(
            resources.LogicalRouterPort, session_response=session_response)

    def test_create_logical_router_port(self):
        """Test creating a router port.

        returns the correct response and 201 status
        """
        fake_router_port = test_constants.FAKE_ROUTER_PORT.copy()
        fake_relay_uuid = uuidutils.generate_uuid()
        lrport = self._mocked_lrport()

        data = {
            'display_name': fake_router_port['display_name'],
            'logical_router_id': fake_router_port['logical_router_id'],
            'resource_type': fake_router_port['resource_type'],
            'tags': [],
            'service_bindings': [{'service_id': {
                'target_type': 'LogicalService',
                'target_id': fake_relay_uuid}}]
        }

        with mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                        return_value='2.0.0'):
            lrport.create(fake_router_port['logical_router_id'],
                          fake_router_port['display_name'],
                          None,
                          fake_router_port['resource_type'],
                          None, None, None,
                          relay_service_uuid=fake_relay_uuid)

            test_client.assert_json_call(
                'post', lrport,
                'https://1.2.3.4/api/v1/logical-router-ports',
                data=jsonutils.dumps(data, sort_keys=True),
                headers=self.default_headers())

    def test_logical_router_port_max_attempts(self):
        """Test a router port api has the configured retries."""
        lrport = self._mocked_lrport()

        self.assertEqual(nsxlib_testcase.NSX_MAX_ATTEMPTS,
                         lrport.client.max_attempts)

    def test_delete_logical_router_port(self):
        """Test deleting router port."""
        lrport = self._mocked_lrport()

        uuid = test_constants.FAKE_ROUTER_PORT['id']
        lrport.delete(uuid)
        test_client.assert_json_call(
            'delete', lrport,
            'https://1.2.3.4/api/v1/logical-router-ports/%s' % uuid,
            headers=self.default_headers())

    def test_update_logical_router_port(self):
        fake_router_port = test_constants.FAKE_ROUTER_PORT.copy()
        uuid = fake_router_port['id']
        fake_relay_uuid = uuidutils.generate_uuid()
        lrport = self._mocked_lrport()
        with mock.patch.object(lrport, 'get', return_value=fake_router_port),\
            mock.patch("vmware_nsxlib.v3.NsxLib.get_version",
                       return_value='2.0.0'):
            lrport.update(uuid,
                          relay_service_uuid=fake_relay_uuid)
            data = {
                'id': uuid,
                'display_name': fake_router_port['display_name'],
                'logical_router_id': fake_router_port['logical_router_id'],
                'resource_type': fake_router_port['resource_type'],
                "revision": 0,
                'service_bindings': [{'service_id': {
                    'target_type': 'LogicalService',
                    'target_id': fake_relay_uuid}}]
            }

            test_client.assert_json_call(
                'put', lrport,
                'https://1.2.3.4/api/v1/logical-router-ports/%s' % uuid,
                data=jsonutils.dumps(data, sort_keys=True),
                headers=self.default_headers())

    def test_get_logical_router_port_by_router_id(self):
        """Test getting a router port by router id."""
        fake_router_port = test_constants.FAKE_ROUTER_PORT.copy()
        resp_resources = {'results': [fake_router_port]}

        lrport = self._mocked_lrport(
            session_response=mocks.MockRequestsResponse(
                200, jsonutils.dumps(resp_resources)))

        router_id = fake_router_port['logical_router_id']
        result = lrport.get_by_router_id(router_id)
        self.assertEqual(fake_router_port, result[0])
        test_client.assert_json_call(
            'get', lrport,
            'https://1.2.3.4/api/v1/logical-router-ports/?'
            'logical_router_id=%s' % router_id,
            headers=self.default_headers())

    def test_get_logical_router_port_by_switch_id(self):
        """Test getting a router port by switch id."""
        fake_router_port = test_constants.FAKE_ROUTER_PORT.copy()
        resp_resources = {
            'result_count': 1,
            'results': [fake_router_port]
        }

        lrport = self._mocked_lrport(
            session_response=mocks.MockRequestsResponse(
                200, jsonutils.dumps(resp_resources)))

        switch_id = test_constants.FAKE_SWITCH_UUID
        lrport.get_by_lswitch_id(switch_id)
        test_client.assert_json_call(
            'get', lrport,
            'https://1.2.3.4/api/v1/logical-router-ports/?'
            'logical_switch_id=%s' % switch_id,
            headers=self.default_headers())


class IpPoolTestCase(nsxlib_testcase.NsxClientTestCase):

    def _mocked_pool(self, session_response=None):
        return self.mocked_resource(
            resources.IpPool, session_response=session_response)

    def test_create_ip_pool_all_args(self):
        """Test creating an IP pool

        returns the correct response and 201 status
        """
        pool = self._mocked_pool()

        display_name = 'dummy'
        gateway_ip = '1.1.1.1'
        ranges = [{'start': '2.2.2.0', 'end': '2.2.2.255'},
                  {'start': '3.2.2.0', 'end': '3.2.2.255'}]
        cidr = '2.2.2.0/24'
        description = 'desc'
        dns_nameserver = '7.7.7.7'
        pool.create(cidr, allocation_ranges=ranges,
                    display_name=display_name,
                    gateway_ip=gateway_ip,
                    description=description,
                    dns_nameservers=[dns_nameserver])

        data = {
            'display_name': display_name,
            'description': description,
            'subnets': [{
                'gateway_ip': gateway_ip,
                'allocation_ranges': ranges,
                'cidr': cidr,
                'dns_nameservers': [dns_nameserver]
            }]
        }

        test_client.assert_json_call(
            'post', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_create_ip_pool_minimal_args(self):
        pool = self._mocked_pool()

        ranges = [{'start': '2.2.2.0', 'end': '2.2.2.255'},
                  {'start': '3.2.2.0', 'end': '3.2.2.255'}]
        cidr = '2.2.2.0/24'
        pool.create(cidr, allocation_ranges=ranges)

        data = {
            'subnets': [{
                'allocation_ranges': ranges,
                'cidr': cidr,
            }]
        }

        test_client.assert_json_call(
            'post', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_create_ip_pool_no_ranges_with_gateway(self):
        pool = self._mocked_pool()
        cidr = '2.2.2.0/30'
        gateway_ip = '2.2.2.1'
        pool.create(cidr, allocation_ranges=None, gateway_ip=gateway_ip)
        exp_ranges = [{'start': '2.2.2.0', 'end': '2.2.2.0'},
                      {'start': '2.2.2.2', 'end': '2.2.2.3'}]

        data = {
            'subnets': [{
                'gateway_ip': gateway_ip,
                'allocation_ranges': exp_ranges,
                'cidr': cidr,
            }]
        }

        test_client.assert_json_call(
            'post', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_create_ip_pool_no_ranges_no_gateway(self):
        pool = self._mocked_pool()
        cidr = '2.2.2.0/30'
        pool.create(cidr, allocation_ranges=None)
        exp_ranges = [{'start': '2.2.2.0', 'end': '2.2.2.3'}]

        data = {
            'subnets': [{
                'allocation_ranges': exp_ranges,
                'cidr': cidr,
            }]
        }

        test_client.assert_json_call(
            'post', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools',
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_create_ip_pool_no_cidr(self):
        pool = self._mocked_pool()
        gateway_ip = '1.1.1.1'
        ranges = [{'start': '2.2.2.0', 'end': '2.2.2.255'},
                  {'start': '3.2.2.0', 'end': '3.2.2.255'}]
        cidr = None

        try:
            pool.create(cidr, allocation_ranges=ranges,
                        gateway_ip=gateway_ip)
        except exceptions.InvalidInput:
            # This call should fail
            pass
        else:
            self.fail("shouldn't happen")

    def test_update_ip_pool_name(self):
        fake_ip_pool = test_constants.FAKE_IP_POOL.copy()
        resp_resources = fake_ip_pool
        pool = self._mocked_pool(
            session_response=mocks.MockRequestsResponse(
                200, jsonutils.dumps(resp_resources)))

        uuid = fake_ip_pool['id']
        new_name = 'new_name'
        pool.update(uuid, display_name=new_name)
        fake_ip_pool['display_name'] = new_name
        test_client.assert_json_call(
            'put', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s' % uuid,
            data=jsonutils.dumps(fake_ip_pool, sort_keys=True),
            headers=self.default_headers())

    def test_update_ip_pool_gateway(self):
        fake_ip_pool = test_constants.FAKE_IP_POOL.copy()
        resp_resources = fake_ip_pool
        pool = self._mocked_pool(
            session_response=mocks.MockRequestsResponse(
                200, jsonutils.dumps(resp_resources)))

        uuid = fake_ip_pool['id']
        new_gateway = '1.0.0.1'
        pool.update(uuid, gateway_ip=new_gateway)
        fake_ip_pool["subnets"][0]['gateway_ip'] = new_gateway
        test_client.assert_json_call(
            'put', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s' % uuid,
            data=jsonutils.dumps(fake_ip_pool, sort_keys=True),
            headers=self.default_headers())

    def test_update_ip_pool_delete_gateway(self):
        fake_ip_pool = test_constants.FAKE_IP_POOL.copy()
        resp_resources = fake_ip_pool
        pool = self._mocked_pool(
            session_response=mocks.MockRequestsResponse(
                200, jsonutils.dumps(resp_resources)))

        uuid = fake_ip_pool['id']
        pool.update(uuid, gateway_ip=None)
        del fake_ip_pool["subnets"][0]['gateway_ip']
        test_client.assert_json_call(
            'put', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s' % uuid,
            data=jsonutils.dumps(fake_ip_pool, sort_keys=True),
            headers=self.default_headers())

    def test_get_ip_pool(self):
        """Test getting a router port by router id"""
        fake_ip_pool = test_constants.FAKE_IP_POOL.copy()
        resp_resources = fake_ip_pool

        pool = self._mocked_pool(
            session_response=mocks.MockRequestsResponse(
                200, jsonutils.dumps(resp_resources)))

        uuid = fake_ip_pool['id']
        result = pool.get(uuid)
        self.assertEqual(fake_ip_pool, result)
        test_client.assert_json_call(
            'get', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s' % uuid,
            headers=self.default_headers())

    def test_delete_ip_pool(self):
        """Test deleting router port"""
        pool = self._mocked_pool()

        uuid = test_constants.FAKE_IP_POOL['id']
        pool.delete(uuid)
        test_client.assert_json_call(
            'delete', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s' % uuid,
            headers=self.default_headers())

    def test_allocate_ip_from_pool(self):
        pool = self._mocked_pool()

        uuid = test_constants.FAKE_IP_POOL['id']
        addr = '1.1.1.1'
        pool.allocate(uuid, ip_addr=addr)

        data = {'allocation_id': addr}
        test_client.assert_json_call(
            'post', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s?action=ALLOCATE' % uuid,
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_release_ip_to_pool(self):
        pool = self._mocked_pool()

        uuid = test_constants.FAKE_IP_POOL['id']
        addr = '1.1.1.1'
        pool.release(uuid, addr)

        data = {'allocation_id': addr}
        test_client.assert_json_call(
            'post', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s?action=RELEASE' % uuid,
            data=jsonutils.dumps(data, sort_keys=True),
            headers=self.default_headers())

    def test_get_ip_pool_allocations(self):
        """Test getting a router port by router id"""
        fake_ip_pool = test_constants.FAKE_IP_POOL.copy()
        resp_resources = fake_ip_pool

        pool = self._mocked_pool(
            session_response=mocks.MockRequestsResponse(
                200, jsonutils.dumps(resp_resources)))

        uuid = fake_ip_pool['id']
        result = pool.get_allocations(uuid)
        self.assertEqual(fake_ip_pool, result)
        test_client.assert_json_call(
            'get', pool,
            'https://1.2.3.4/api/v1/pools/ip-pools/%s/allocations' % uuid,
            headers=self.default_headers())


class TestNsxSearch(nsxlib_testcase.NsxClientTestCase):

    def test_nsx_search_tags(self):
        """Test search of resources with the specified tag."""
        with mock.patch.object(self.nsxlib.client, 'url_get') as search:
            user_tags = [{'scope': 'user', 'tag': 'k8s'}]
            query = self.nsxlib._build_query(tags=user_tags)
            self.nsxlib.search_by_tags(tags=user_tags)
            search.assert_called_with('search?query=%s' % query)

    def test_nsx_search_tags_and_resource_type(self):
        """Test search of specified resource with the specified tag."""
        with mock.patch.object(self.nsxlib.client, 'url_get') as search:
            user_tags = [{'scope': 'user', 'tag': 'k8s'}]
            res_type = 'LogicalPort'
            query = self.nsxlib._build_query(tags=user_tags)
            # Add resource_type to the query
            query = "resource_type:%s AND %s" % (res_type, query)
            self.nsxlib.search_by_tags(tags=user_tags, resource_type=res_type)
            search.assert_called_with('search?query=%s' % query)

    def test_nsx_search_tags_and_cursor(self):
        """Test search of resources with the specified tag and cursor."""
        with mock.patch.object(self.nsxlib.client, 'url_get') as search:
            user_tags = [{'scope': 'user', 'tag': 'k8s'}]
            query = self.nsxlib._build_query(tags=user_tags)
            self.nsxlib.search_by_tags(tags=user_tags, cursor=50)
            search.assert_called_with('search?query=%s&cursor=50' % query)

    def test_nsx_search_tags_and_page_size(self):
        """Test search of resources with the specified tag and page size."""
        with mock.patch.object(self.nsxlib.client, 'url_get') as search:
            user_tags = [{'scope': 'user', 'tag': 'k8s'}]
            query = self.nsxlib._build_query(tags=user_tags)
            self.nsxlib.search_by_tags(tags=user_tags, page_size=100)
            search.assert_called_with('search?query=%s&page_size=100' % query)

    def test_nsx_search_invalid_query_fail(self):
        """Test search query failure for missing tag argument."""
        self.assertRaises(exceptions.NsxSearchInvalidQuery,
                          self.nsxlib.search_by_tags,
                          tags=None, resource_type=None)

    def test_nsx_search_invalid_tags_fail(self):
        """Test search of resources with the invalid tag."""
        user_tags = [{'scope': 'user', 'invalid_tag_key': 'k8s'}]
        self.assertRaises(exceptions.NsxSearchInvalidQuery,
                          self.nsxlib._build_query,
                          tags=user_tags)

    def test_nsx_search_all_by_tags(self):
        """Test search all of resources with the specified tag."""
        with mock.patch.object(self.nsxlib.client, 'url_get') as search:
            search.side_effect = [
                {"cursor": "2",
                 "result_count": 3,
                 "results": [{"id": "s1"},
                             {"id": "s2"}]},
                {"cursor": "3",
                 "result_count": 3,
                 "results": [{"id": "s3"}]}]
            user_tags = [{'scope': 'user', 'tag': 'k8s'}]
            query = self.nsxlib._build_query(tags=user_tags)
            results = self.nsxlib.search_all_by_tags(tags=user_tags)
            search.assert_has_calls([
                mock.call('search?query=%s' % query),
                mock.call('search?query=%s&cursor=2' % query)])
            self.assertEqual(3, len(results))

    def test_get_id_by_resource_and_tag(self):
        id = 'test'
        scope = 'user'
        tag = 'k8s'
        res_type = 'LogicalPort'
        results = {'result_count': 1, 'results': [{'id': id}]}
        with mock.patch.object(self.nsxlib.client, 'url_get',
                               return_value=results):
            actual_id = self.nsxlib.get_id_by_resource_and_tag(
                res_type, scope, tag)
            self.assertEqual(id, actual_id)

    def test_get_id_by_resource_and_tag_not_found(self):
        scope = 'user'
        tag = 'k8s'
        res_type = 'LogicalPort'
        results = {'result_count': 0, 'results': []}
        with mock.patch.object(self.nsxlib.client, 'url_get',
                               return_value=results):
            self.assertRaises(exceptions.ResourceNotFound,
                              self.nsxlib.get_id_by_resource_and_tag,
                              res_type, scope, tag, alert_not_found=True)

    def test_get_id_by_resource_and_tag_multiple(self):
        scope = 'user'
        tag = 'k8s'
        res_type = 'LogicalPort'
        results = {'result_count': 2, 'results': [{'id': '1'}, {'id': '2'}]}
        with mock.patch.object(self.nsxlib.client, 'url_get',
                               return_value=results):
            self.assertRaises(exceptions.ManagerError,
                              self.nsxlib.get_id_by_resource_and_tag,
                              res_type, scope, tag, alert_multiple=True)
