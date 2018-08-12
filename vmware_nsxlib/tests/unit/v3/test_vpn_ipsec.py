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

from oslo_serialization import jsonutils

from vmware_nsxlib.tests.unit.v3 import test_client
from vmware_nsxlib.tests.unit.v3 import test_constants
from vmware_nsxlib.tests.unit.v3 import test_resources
from vmware_nsxlib.v3 import vpn_ipsec


class TestIkeProfile(test_resources.BaseTestResource):

    def setUp(self):
        super(TestIkeProfile, self).setUp(
            vpn_ipsec.IkeProfile)

    def test_ike_profile_create(self):
        mocked_resource = self.get_mocked_resource()
        name = 'ike_profile'
        description = 'desc'
        enc_alg = vpn_ipsec.EncryptionAlgorithmTypes.ENCRYPTION_ALGORITHM_128
        dig_alg = vpn_ipsec.DigestAlgorithmTypes.DIGEST_ALGORITHM_SHA1
        ike_ver = vpn_ipsec.IkeVersionTypes.IKE_VERSION_V1
        dh_group = vpn_ipsec.DHGroupTypes.DH_GROUP_14
        lifetime = 100
        mocked_resource.create(name, description=description,
                               encryption_algorithm=enc_alg,
                               digest_algorithm=dig_alg,
                               ike_version=ike_ver,
                               dh_group=dh_group,
                               sa_life_time=lifetime)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/%s' % mocked_resource.uri_segment,
            data=jsonutils.dumps({
                'display_name': name,
                'description': description,
                'encryption_algorithms': [enc_alg],
                'digest_algorithms': [dig_alg],
                'ike_version': ike_ver,
                'dh_groups': [dh_group],
                'sa_life_time': lifetime
            }, sort_keys=True),
            headers=self.default_headers())


class TestIPSecTunnelProfile(test_resources.BaseTestResource):

    def setUp(self):
        super(TestIPSecTunnelProfile, self).setUp(
            vpn_ipsec.IPSecTunnelProfile)

    def test_ipsec_profile_create(self):
        mocked_resource = self.get_mocked_resource()
        name = 'ipsec_profile'
        description = 'desc'
        enc_alg = vpn_ipsec.EncryptionAlgorithmTypes.ENCRYPTION_ALGORITHM_128
        dig_alg = vpn_ipsec.DigestAlgorithmTypes.DIGEST_ALGORITHM_SHA1
        dh_group = vpn_ipsec.DHGroupTypes.DH_GROUP_14
        lifetime = 100
        mocked_resource.create(name, description=description,
                               encryption_algorithm=enc_alg,
                               digest_algorithm=dig_alg,
                               pfs=True,
                               dh_group=dh_group,
                               sa_life_time=lifetime)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/%s' % mocked_resource.uri_segment,
            data=jsonutils.dumps({
                'display_name': name,
                'description': description,
                'encryption_algorithms': [enc_alg],
                'digest_algorithms': [dig_alg],
                'enable_perfect_forward_secrecy': True,
                'dh_groups': [dh_group],
                'sa_life_time': lifetime
            }, sort_keys=True),
            headers=self.default_headers())


class TestIPSecDpdProfile(test_resources.BaseTestResource):

    def setUp(self):
        super(TestIPSecDpdProfile, self).setUp(
            vpn_ipsec.IPSecDpdProfile)

    def test_dpd_profile_create(self):
        mocked_resource = self.get_mocked_resource()
        name = 'dpd_profile'
        description = 'desc'
        timeout = 100
        enabled = True
        mocked_resource.create(name, description=description,
                               timeout=timeout,
                               enabled=enabled)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/%s' % mocked_resource.uri_segment,
            data=jsonutils.dumps({
                'display_name': name,
                'description': description,
                'dpd_probe_interval': timeout,
                'enabled': enabled
            }, sort_keys=True),
            headers=self.default_headers())

    def test_dpd_profile_update(self):
        fake_dpd = test_constants.FAKE_DPD.copy()
        new_timeout = 1000
        new_name = 'dpd_profile_updated'
        new_desc = 'desc updated'
        uuid = test_constants.FAKE_DPD_ID
        mocked_resource = self.get_mocked_resource(response=fake_dpd)
        mocked_resource.update(uuid, timeout=new_timeout, name=new_name,
                               description=new_desc)
        fake_dpd['dpd_probe_interval'] = new_timeout
        fake_dpd['display_name'] = new_name
        fake_dpd['description'] = new_desc
        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/%s/%s' % (mocked_resource.uri_segment,
                                              uuid),
            data=jsonutils.dumps(fake_dpd, sort_keys=True),
            headers=self.default_headers())


class TestIPSecPeerEndpoint(test_resources.BaseTestResource):

    def setUp(self):
        super(TestIPSecPeerEndpoint, self).setUp(
            vpn_ipsec.IPSecPeerEndpoint)

    def test_peer_endpoint_create(self):
        mocked_resource = self.get_mocked_resource()
        name = 'peerep'
        description = 'desc'
        peer_address = peer_id = '1.1.1.1'
        authentication_mode = 'PSK'
        dpd_profile_id = 'uuid1'
        ike_profile_id = 'uuid2'
        ipsec_profile_id = 'uuid3'
        initiation_mode = 'INITIATOR'
        psk = 'secret'
        mocked_resource.create(name, peer_address, peer_id,
                               description=description,
                               authentication_mode=authentication_mode,
                               dpd_profile_id=dpd_profile_id,
                               ike_profile_id=ike_profile_id,
                               ipsec_tunnel_profile_id=ipsec_profile_id,
                               connection_initiation_mode=initiation_mode,
                               psk=psk)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/%s' % mocked_resource.uri_segment,
            data=jsonutils.dumps({
                'display_name': name,
                'peer_address': peer_address,
                'peer_id': peer_id,
                'description': description,
                'authentication_mode': authentication_mode,
                'dpd_profile_id': dpd_profile_id,
                'ike_profile_id': ike_profile_id,
                'ipsec_tunnel_profile_id': ipsec_profile_id,
                'connection_initiation_mode': initiation_mode,
                'psk': psk
            }, sort_keys=True),
            headers=self.default_headers())

    def test_peer_endpoint_update(self):
        fake_pep = test_constants.FAKE_PEP.copy()
        new_desc = 'updated'
        new_name = 'new'
        new_psk = 'psk12'
        uuid = test_constants.FAKE_PEP_ID
        mocked_resource = self.get_mocked_resource(response=fake_pep)
        mocked_resource.update(uuid, name=new_name, description=new_desc,
                               psk=new_psk)
        fake_pep['description'] = new_desc
        fake_pep['display_name'] = new_name
        fake_pep['psk'] = new_psk
        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/%s/%s' % (mocked_resource.uri_segment,
                                              uuid),
            data=jsonutils.dumps(fake_pep, sort_keys=True),
            headers=self.default_headers())


class TestLocalEndpoint(test_resources.BaseTestResource):

    def setUp(self):
        super(TestLocalEndpoint, self).setUp(
            vpn_ipsec.LocalEndpoint)

    def test_local_endpoint_create(self):
        mocked_resource = self.get_mocked_resource()
        name = 'localep'
        description = 'desc'
        local_address = local_id = '1.1.1.1'
        ipsec_vpn_service_id = 'uuid1'
        mocked_resource.create(name, local_address, ipsec_vpn_service_id,
                               description=description,
                               local_id=local_id)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/%s' % mocked_resource.uri_segment,
            data=jsonutils.dumps({
                'display_name': name,
                'local_address': local_address,
                'local_id': local_id,
                'description': description,
                'ipsec_vpn_service_id': {'target_id': ipsec_vpn_service_id}
            }, sort_keys=True),
            headers=self.default_headers())

    def test_local_endpoint_update(self):
        fake_pep = test_constants.FAKE_LEP.copy()
        new_desc = 'updated'
        new_name = 'new'
        new_addr = '2.2.2.2'
        uuid = test_constants.FAKE_LEP_ID
        mocked_resource = self.get_mocked_resource(response=fake_pep)
        mocked_resource.update(uuid, name=new_name, description=new_desc,
                               local_address=new_addr,
                               local_id=new_addr)
        fake_pep['description'] = new_desc
        fake_pep['display_name'] = new_name
        fake_pep['local_address'] = new_addr
        fake_pep['local_id'] = new_addr
        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/%s/%s' % (mocked_resource.uri_segment,
                                              uuid),
            data=jsonutils.dumps(fake_pep, sort_keys=True),
            headers=self.default_headers())


class TestSession(test_resources.BaseTestResource):

    def setUp(self):
        super(TestSession, self).setUp(
            vpn_ipsec.Session)

    def test_session_create(self):
        mocked_resource = self.get_mocked_resource()
        name = 'session'
        description = 'desc'
        local_ep_id = 'uuid1'
        peer_ep_id = 'uuid2'
        policy_rules = [mocked_resource.get_rule_obj(['1.1.1.0/24'],
                                                     ['2.2.2.0/24'])]
        mocked_resource.create(name, local_ep_id, peer_ep_id, policy_rules,
                               description=description)
        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/%s' % mocked_resource.uri_segment,
            data=jsonutils.dumps({
                'display_name': name,
                'description': description,
                'local_endpoint_id': local_ep_id,
                'peer_endpoint_id': peer_ep_id,
                'enabled': True,
                'resource_type': mocked_resource.resource_type,
                'policy_rules': policy_rules,
            }, sort_keys=True),
            headers=self.default_headers())

    def test_session_update_with_rules(self):
        fake_sess = test_constants.FAKE_VPN_SESS.copy()
        mocked_resource = self.get_mocked_resource(response=fake_sess)
        uuid = test_constants.FAKE_VPN_SESS_ID
        new_name = 'session'
        new_desc = 'desc'
        cidr1 = '1.1.1.0/24'
        cidr2 = '2.2.2.0/24'
        policy_rules = [mocked_resource.get_rule_obj([cidr1], [cidr2])]
        mocked_resource.update(uuid, name=new_name, description=new_desc,
                               policy_rules=policy_rules, enabled=False)
        fake_sess['description'] = new_desc
        fake_sess['display_name'] = new_name
        fake_sess['policy_rules'] = policy_rules
        fake_sess['enabled'] = False
        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/%s/%s' % (mocked_resource.uri_segment,
                                              uuid),
            data=jsonutils.dumps(fake_sess, sort_keys=True),
            headers=self.default_headers())

    def test_session_update_no_rules(self):
        fake_sess = test_constants.FAKE_VPN_SESS.copy()
        mocked_resource = self.get_mocked_resource(response=fake_sess)
        uuid = test_constants.FAKE_VPN_SESS_ID
        new_name = 'session'
        new_desc = 'desc'
        mocked_resource.update(uuid, name=new_name, description=new_desc,
                               enabled=False)
        fake_sess['description'] = new_desc
        fake_sess['display_name'] = new_name
        fake_sess['enabled'] = False
        test_client.assert_json_call(
            'put', mocked_resource,
            'https://1.2.3.4/api/v1/%s/%s' % (mocked_resource.uri_segment,
                                              uuid),
            data=jsonutils.dumps(fake_sess, sort_keys=True),
            headers=self.default_headers())

    def test_session_get_status(self):
        uuid = test_constants.FAKE_VPN_SESS_ID
        mocked_resource = self.get_mocked_resource()
        mocked_resource.get_status(uuid)
        test_client.assert_json_call(
            'get', mocked_resource,
            'https://1.2.3.4/api/v1/%s/%s/status?source=realtime' % (
                mocked_resource.uri_segment, uuid),
            headers=self.default_headers())


class TestService(test_resources.BaseTestResource):

    def setUp(self):
        super(TestService, self).setUp(
            vpn_ipsec.Service)

    def test_service_create(self):
        mocked_resource = self.get_mocked_resource()
        router_id = 'abcd'
        enabled = True
        log_level = "DEBUG"
        name = 'service'
        mocked_resource.create(name, router_id, ike_log_level=log_level,
                               enabled=enabled)

        test_client.assert_json_call(
            'post', mocked_resource,
            'https://1.2.3.4/api/v1/%s' % mocked_resource.uri_segment,
            data=jsonutils.dumps({
                'display_name': name,
                'logical_router_id': router_id,
                'ike_log_level': log_level,
                'enabled': enabled
            }, sort_keys=True),
            headers=self.default_headers())
