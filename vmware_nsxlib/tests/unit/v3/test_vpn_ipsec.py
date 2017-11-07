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

from vmware_nsxlib.tests.unit.v3 import test_resources
from vmware_nsxlib.v3 import vpn_ipsec


class TestIkeProfile(test_resources.BaseTestResource):

    def setUp(self):
        super(TestIkeProfile, self).setUp(
            vpn_ipsec.IkeProfile)

    # TODO(asarfaty): Add create/update tests


class TestTunnelProfile(test_resources.BaseTestResource):

    def setUp(self):
        super(TestTunnelProfile, self).setUp(
            vpn_ipsec.TunnelProfile)

    # TODO(asarfaty): Add create/update tests


class TestPeerEndpoint(test_resources.BaseTestResource):

    def setUp(self):
        super(TestPeerEndpoint, self).setUp(
            vpn_ipsec.PeerEndpoint)

    # TODO(asarfaty): Add create/update tests


class TestLocalEndpoint(test_resources.BaseTestResource):

    def setUp(self):
        super(TestLocalEndpoint, self).setUp(
            vpn_ipsec.LocalEndpoint)

    # TODO(asarfaty): Add create/update tests


class TestSession(test_resources.BaseTestResource):

    def setUp(self):
        super(TestSession, self).setUp(
            vpn_ipsec.Session)

    # TODO(asarfaty): Add create/update tests


class TestService(test_resources.BaseTestResource):

    def setUp(self):
        super(TestService, self).setUp(
            vpn_ipsec.Service)

    # TODO(asarfaty): Add create/update tests
