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

from oslo_log import log as logging

from vmware_nsxlib.v3 import utils

LOG = logging.getLogger(__name__)
VPN_IPSEC_PATH = 'vpn/ipsec/'


class IkeProfile(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        # TODO(asarfaty) wait for backend
        return 'IkeProfile'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'ike-profiles'

    def create(self, name, description=None,
               encription_algorithm="AESGCM",
               ike_version="V2"):
        # TODO(asarfaty): list allowed algorithms? constants
        # TODO(asarfaty): list allowed versions? constants
        body = {'display_name': name,
                'encription_algorithm': encription_algorithm,
                'ike_version': ike_version}
        if description:
            body['description'] = description

        return self.client.create(self.get_path(), body=body)


class TunnelProfile(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        # TODO(asarfaty) wait for backend
        return 'TunnelProfile'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'tunnel-profiles'


class PeerEndpoint(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        # TODO(asarfaty) wait for backend
        return 'PeerEndpoint'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'peer-endpoints'


class LocalEndpoint(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        # TODO(asarfaty) wait for backend
        return 'LocalEndpoint'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'local-endpoints'


class Session(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        # TODO(asarfaty) wait for backend
        return 'Session'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'sessions'


class Service(utils.NsxLibApiBase):

    @property
    def resource_type(self):
        # TODO(asarfaty) wait for backend
        return 'Service'

    @property
    def uri_segment(self):
        return VPN_IPSEC_PATH + 'services'


class VpnIpSec(object):
    """This is the class that have all vpn ipsec resource clients"""

    def __init__(self, client, nsxlib_config, nsxlib=None):
        self.ike_profile = IkeProfile(client, nsxlib_config, nsxlib=nsxlib)
        self.tunnel_profile = TunnelProfile(client, nsxlib_config,
                                            nsxlib=nsxlib)
        self.peer_profile = PeerEndpoint(client, nsxlib_config, nsxlib=nsxlib)
        self.local_profile = LocalEndpoint(client, nsxlib_config,
                                           nsxlib=nsxlib)
        self.session = Session(client, nsxlib_config, nsxlib=nsxlib)
        self.service = Service(client, nsxlib_config, nsxlib=nsxlib)
