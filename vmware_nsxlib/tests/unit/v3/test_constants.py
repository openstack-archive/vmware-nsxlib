# Copyright (c) 2016 VMware, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from oslo_utils import uuidutils

from vmware_nsxlib.v3 import nsx_constants

FAKE_NAME = "fake_name"
FAKE_SWITCH_UUID = uuidutils.generate_uuid()
FAKE_IP_SET_UUID = uuidutils.generate_uuid()

FAKE_PORT_UUID = uuidutils.generate_uuid()
FAKE_PORT = {
    "id": FAKE_PORT_UUID,
    "display_name": FAKE_NAME,
    "resource_type": "LogicalPort",
    "address_bindings": [],
    "logical_switch_id": FAKE_SWITCH_UUID,
    "admin_state": "UP",
    "attachment": {
        "id": "9ca8d413-f7bf-4276-b4c9-62f42516bdb2",
        "attachment_type": "VIF"
    },
    "switching_profile_ids": [
        {
            "value": "64814784-7896-3901-9741-badeff705639",
            "key": "IpDiscoverySwitchingProfile"
        },
        {
            "value": "fad98876-d7ff-11e4-b9d6-1681e6b88ec1",
            "key": "SpoofGuardSwitchingProfile"
        },
        {
            "value": "93b4b7e8-f116-415d-a50c-3364611b5d09",
            "key": "PortMirroringSwitchingProfile"
        },
        {
            "value": "fbc4fb17-83d9-4b53-a286-ccdf04301888",
            "key": "SwitchSecuritySwitchingProfile"
        },
        {
            "value": "f313290b-eba8-4262-bd93-fab5026e9495",
            "key": "QosSwitchingProfile"
        }
    ]
}

FAKE_CONTAINER_PORT = {
    "id": FAKE_PORT_UUID,
    "display_name": FAKE_NAME,
    "resource_type": "LogicalPort",
    "address_bindings": [
        {
            "ip_address": "192.168.1.110",
            "mac_address": "aa:bb:cc:dd:ee:ff"
        }
    ],
    "logical_switch_id": FAKE_SWITCH_UUID,
    "admin_state": "UP",
    "attachment": {
        "id": "9ca8d413-f7bf-4276-b4c9-62f42516bdb2",
        "attachment_type": "VIF",
        "context": {
            "vlan_tag": 122,
            "container_host_vif_id": "c6f817a0-4e36-421e-98a6-8a2faed880bc",
            "resource_type": "VifAttachmentContext",
            "app_id": "container-1",
            "vif_type": "CHILD",
            "allocate_addresses": "Both",
        }
    },
    "switching_profile_ids": [
        {
            "value": "64814784-7896-3901-9741-badeff705639",
            "key": "IpDiscoverySwitchingProfile"
        },
        {
            "value": "fad98876-d7ff-11e4-b9d6-1681e6b88ec1",
            "key": "SpoofGuardSwitchingProfile"
        },
        {
            "value": "93b4b7e8-f116-415d-a50c-3364611b5d09",
            "key": "PortMirroringSwitchingProfile"
        },
        {
            "value": "fbc4fb17-83d9-4b53-a286-ccdf04301888",
            "key": "SwitchSecuritySwitchingProfile"
        },
        {
            "value": "f313290b-eba8-4262-bd93-fab5026e9495",
            "key": "QosSwitchingProfile"
        }
    ]
}


FAKE_ROUTER_UUID = uuidutils.generate_uuid()
FAKE_ROUTER_FW_SEC_UUID = uuidutils.generate_uuid()
FAKE_ROUTER = {
    "resource_type": "LogicalRouter",
    "revision": 0,
    "id": FAKE_ROUTER_UUID,
    "display_name": FAKE_NAME,
    "firewall_sections": [{
        "is_valid": True,
        "target_type": "FirewallSection",
        "target_id": FAKE_ROUTER_FW_SEC_UUID
    }],
    "advanced_config": {
        "external_transit_networks": ["100.64.0.0/10"],
    },
}

FAKE_ROUTER_PORT_UUID = uuidutils.generate_uuid()
FAKE_ROUTER_PORT = {
    "resource_type": nsx_constants.LROUTERPORT_UPLINK,
    "revision": 0,
    "id": FAKE_ROUTER_PORT_UUID,
    "display_name": FAKE_NAME,
    "logical_router_id": FAKE_ROUTER_UUID,
    "subnets": [{'ip_addresses': ['172.20.1.60'], 'prefix_length': 24}]
}

FAKE_ROUTER_LINKT1_PORT_UUID = uuidutils.generate_uuid()
FAKE_ROUTER_LINKT1_PORT = {
    "resource_type": nsx_constants.LROUTERPORT_LINKONTIER1,
    "revision": 0,
    "id": FAKE_ROUTER_LINKT1_PORT_UUID,
    "display_name": FAKE_NAME,
    "logical_router_id": FAKE_ROUTER_UUID,
    "linked_logical_router_port_id": {'target_id': uuidutils.generate_uuid()}
}

FAKE_QOS_PROFILE = {
    "resource_type": "QosSwitchingProfile",
    "id": uuidutils.generate_uuid(),
    "display_name": FAKE_NAME,
    "system_defined": False,
    "dscp": {
        "priority": 25,
        "mode": "UNTRUSTED"
    },
    "tags": [],
    "description": FAKE_NAME,
    "class_of_service": 0,
    "shaper_configuration": [
        {
            "resource_type": "IngressRateShaper",
            "enabled": False,
            "peak_bandwidth_mbps": 0,
            "burst_size_bytes": 0,
            "average_bandwidth_mbps": 0
        },
        {
            "resource_type": "IngressBroadcastRateShaper",
            "enabled": False,
            "peak_bandwidth_kbps": 0,
            "average_bandwidth_kbps": 0,
            "burst_size_bytes": 0
        },
        {
            "resource_type": "EgressRateShaper",
            "enabled": False,
            "peak_bandwidth_mbps": 0,
            "burst_size_bytes": 0,
            "average_bandwidth_mbps": 0
        }
    ],
    "_last_modified_user": "admin",
    "_last_modified_time": 1438383180608,
    "_create_time": 1438383180608,
    "_create_user": "admin",
    "_revision": 0
}

FAKE_IP_POOL_UUID = uuidutils.generate_uuid()
FAKE_IP_POOL = {
    "_revision": 0,
    "id": FAKE_IP_POOL_UUID,
    "display_name": "IPPool-IPV6-1",
    "description": "IPPool-IPV6-1 Description",
    "subnets": [{
        "dns_nameservers": [
            "2002:a70:cbfa:1:1:1:1:1"
        ],
        "allocation_ranges": [{
            "start": "2002:a70:cbfa:0:0:0:0:1",
            "end": "2002:a70:cbfa:0:0:0:0:5"
        }],
        "gateway_ip": "2002:a80:cbfa:0:0:0:0:255",
        "cidr": "2002:a70:cbfa:0:0:0:0:0/24"
    }],
}

FAKE_IP_SET = {
    "id": FAKE_IP_SET_UUID,
    "display_name": FAKE_NAME,
    "resource_type": "IPSet",
    "ip_addresses": [
        "192.168.1.1-192.168.1.6",
        "192.168.1.8",
        "192.168.4.8/24"]
}

FAKE_APPLICATION_PROFILE_UUID = uuidutils.generate_uuid()
FAKE_APPLICATION_PROFILE = {
    "resource_type": "LbHttpProfile",
    "description": "my http profile",
    "id": FAKE_APPLICATION_PROFILE_UUID,
    "display_name": "httpprofile1",
    "ntlm": False,
    "request_header_size": 1024,
    "http_redirect_to_https": False,
    "idle_timeout": 1800,
    "x_forwarded_for": "INSERT",
    "_create_user": "admin",
    "_create_time": 1493834124218,
    "_last_modified_user": "admin",
    "_last_modified_time": 1493834124218,
    "_system_owned": False,
    "_revision": 0
}

FAKE_PERSISTENCE_PROFILE_UUID = uuidutils.generate_uuid()
FAKE_PERSISTENCE_PROFILE = {
    "resource_type": "LbCookiePersistenceProfile",
    "description": "cookie persistence",
    "id": FAKE_PERSISTENCE_PROFILE_UUID,
    "display_name": "cookiePersistence",
    "cookie_mode": "INSERT",
    "cookie_garble": True,
    "cookie_fallback": True,
    "cookie_name": "ABC",
    "_create_user": "admin",
    "_create_time": 1493837413804,
    "_last_modified_user": "admin",
    "_last_modified_time": 1493837413804,
    "_system_owned": False,
    "_revision": 0
}

FAKE_RULE_UUID = uuidutils.generate_uuid()
FAKE_RULE = {
    "resource_type": "LbRule",
    "description": "LbRule to route login requests to dedicated pool",
    "id": FAKE_RULE_UUID,
    "display_name": "LoginRouteRule",
    "phase": "HTTP_FORWARDING",
    "match_strategy": "ALL",
    "match_conditions": [
        {
            "type": "LbHttpRequestUriCondition",
            "uri": "/login"
        }
    ],
    "actions": [
        {
            "type": "LbSelectPoolAction",
            "pool_id": "54411c58-046c-4236-8ff1-e1e1aad3e873"
        }
    ]
}

FAKE_CLIENT_SSL_PROFILE_UUID = uuidutils.generate_uuid()
FAKE_CLIENT_SSL_PROFILE = {
    "display_name": "clientSslProfile1",
    "description": "client ssl profile",
    "id": FAKE_CLIENT_SSL_PROFILE_UUID,
    "prefer_server_ciphers": False,
    "session_cache_enabled": False,
    "session_cache_timeout": 300
}

FAKE_SERVER_SSL_PROFILE_UUID = uuidutils.generate_uuid()
FAKE_SERVER_SSL_PROFILE = {
    "display_name": "serverSslProfile1",
    "description": "server ssl profile",
    "id": FAKE_SERVER_SSL_PROFILE_UUID,
    "session_cache_enabled": False
}

FAKE_MONITOR_UUID = uuidutils.generate_uuid()
FAKE_MONITOR = {
    "display_name": "httpmonitor1",
    "description": "my http monitor",
    "id": FAKE_MONITOR_UUID,
    "resource_type": "LbHttpMonitor",
    "interval": 5,
    "rise_count": 3,
    "fall_count": 3,
    "timeout": 15,
    "request_url": "/",
    "request_method": "GET",
    "monitor_port": "80"
}

FAKE_POOL_UUID = uuidutils.generate_uuid()
FAKE_POOL = {
    "display_name": "httppool1",
    "description": "my http pool",
    "id": FAKE_POOL_UUID,
    "algorithm": "ROUND_ROBIN",
}

FAKE_VIRTUAL_SERVER_UUID = uuidutils.generate_uuid()
FAKE_VIRTUAL_SERVER = {
    "display_name": "httpvirtualserver1",
    "description": "my http virtual server",
    "id": FAKE_VIRTUAL_SERVER_UUID,
    "enabled": True,
    "port": "80",
    "ip_protocol": "TCP",
}

FAKE_SERVICE_UUID = uuidutils.generate_uuid()
FAKE_SERVICE = {
    "display_name": "my LB web service1",
    "description": "my LB web service",
    "id": FAKE_SERVICE_UUID,
    "enabled": True,
    "attachment": {
        "target_id": FAKE_ROUTER_UUID,
        "target_type": "LogicalRouter"
    }
}

FAKE_TZ_UUID = uuidutils.generate_uuid()
FAKE_TZ = {
    "resource_type": "TransportZone",
    "revision": 0,
    "id": FAKE_TZ_UUID,
    "display_name": FAKE_NAME,
    "transport_type": "OVERLAY",
    "host_switch_mode": "STANDARD"
}

FAKE_TN_UUID = uuidutils.generate_uuid()
FAKE_TN = {
    "resource_type": "TransportNode",
    "revision": 0,
    "id": FAKE_TZ_UUID,
    "display_name": FAKE_NAME,
    "transport_zone_endpoints": [{"transport_zone_id": FAKE_TZ_UUID}]
}

FAKE_MD_UUID = uuidutils.generate_uuid()
FAKE_URL = "http://7.7.7.70:3500/abc"
FAKE_MD = {
    "resource_type": "MetadataProxy",
    "revision": 0,
    "id": FAKE_MD_UUID,
    "metadata_server_url": FAKE_URL
}

FAKE_RELAY_UUID = uuidutils.generate_uuid()
FAKE_RELAY_SERVER = "6.6.6.6"
FAKE_RELAY_PROFILE = {
    "id": FAKE_RELAY_UUID,
    "display_name": "dummy",
    "server_addresses": [FAKE_RELAY_SERVER],
    "resource_type": "DhcpRelayProfile"
}

FAKE_RELAY_SERVICE_UUID = uuidutils.generate_uuid()
FAKE_RELAY_SERVICE = {
    "id": FAKE_RELAY_SERVICE_UUID,
    "display_name": "dummy",
    "dhcp_relay_profile_id": FAKE_RELAY_UUID,
    "resource_type": "DhcpRelayService"
}

FAKE_DEFAULT_CERTIFICATE_ID = uuidutils.generate_uuid()

FAKE_CERT_LIST = [
    {'pem_encoded': '-----BEGINCERTIFICATE-----\n'
                    'MIIDmzCCAoOgAwIBAgIGAV8Rg5RhMA0GCSqGSIb3DQEBCwUAMHoxJzA'
                    'lBgNVBAMM\nHlZNd2FyZSBOU1hBUEkgVHJ1c3QgTWFuYWdlbWVudDET'
                    'MBEGA1UECgwKVk13YXJl\nIEluYzEMMAoGA1UECwwDTlNYMQswCQYDV'
                    'QQGEwJVUzELMAkGA1UECAwCQ0ExEjAQ\nBgNVBAcMCVBhbG8gQWx0bz'
                    'AeFw0xNzEwMTIxNjU1NTZaFw0yNzEwMTAxNjU1NTZa\nMHoxJzAlBgN'
                    'VBAMMHlZNd2FyZSBOU1hBUEkgVHJ1c3QgTWFuYWdlbWVudDETMBEG\n'
                    'A1UECgwKVk13YXJlIEluYzEMMAoGA1UECwwDTlNYMQswCQYDVQQGEwJ'
                    'VUzELMAkG\nA1UECAwCQ0ExEjAQBgNVBAcMCVBhbG8gQWx0bzCCASIw'
                    'DQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAJuRUtmJLamkJyW3X'
                    'qpilC7o0dxp3l5vlWWCjnbz3cl+/5Fd\nnpd8dTco9UMeSv5bPBGvLm'
                    'qSPBZwTYCO3JAowF7aS3qPPWo8tNYWqlMfrZqo5Phc\nGRwtTkfK+GO'
                    '2VN6EG7kTewjrNMW7EAA/68fsNk0QeYIkDJw4ozaX6MhyNDjR+20M\n'
                    '0urN5DEt0ucNZfuQ0pfwYwZoAULHJJODRgUzQG7OT0u64m4ugjQ0uxD'
                    '268aV2IFU\ntSln5HAw2IHXsSn+TVCxInDb+3Uj5E0gjANk5xH7yumi'
                    'mFXC5DGVvdi1vHdQwZzi\nEklX2Gj2+qEiLul9Jr6BjMM+cor3ediuL'
                    'KfC05kCAwEAAaMnMCUwDgYDVR0PAQH/\nBAQDAgeAMBMGA1UdJQQMMA'
                    'oGCCsGAQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQBb\nk498dN3Wid9'
                    '0NIfEJOtTuPtMBSLbCuXgeAqmxGgAB1mYyXCSk50AzkzDZqdt7J9Z\n'
                    'm3LMe1mfyzfD5zboGiSbb6OrMac3RO9B3nFl2h2pkJtZQAqQDxrighQ'
                    'qodlbLCum\nw3juA9AIx+YveAOP8mwldo6XJX4ogIXiTol6m1EkOmJ/'
                    '6YnFiVN/BloBhSbbv2zJ\nhk9LKwCjZ23hkWj74zQY94iknhcS3VxEt'
                    'FlEyk1VrRGkmFfn618JCOCt+8Zuw1M3\nlkn4tA81IVjbj/uWaRIDY1'
                    'gSfltVX14vNy5fbtCHlQiJgI/A4I4z8UNaktkLO/ie\ntiAwSni6x7S'
                    'ZWsf3Sy/P\n-----END CERTIFICATE-----\n',
     'id': 'c863428e-bfce-4a93-9341-6c9b9ec07657',
     'resource_type': 'certificate_self_signed'},
    {'pem_encoded': '-----BEGIN CERTIFICATE-----\n'
                    'MIIEgzCCAmsCCQCmkvlHE5M1KTANBgkqhkiG9w0BAQsFADB0MQswCQY'
                    'DVQQGEwJV\nUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJ'
                    'UGFsbyBBbHRvMQ8wDQYD\nVQQKDAZWTXdhcmUxDTALBgNVBAsMBE5TQ'
                    'lUxHDAaBgNVBAMME1ZNd2FyZSBOU0JV\nIFJvb3QgQ0EwHhcNMTcxMD'
                    'EyMjI0NzU0WhcNMTgxMDA3MjI0NzU0WjCBkjELMAkG\nA1UEBhMCVVM'
                    'xEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCVBhbG8gQWx0\n'
                    'bzEPMA0GA1UECgwGVk13YXJlMQ0wCwYDVQQLDAROU0JVMRgwFgYDVQQ'
                    'DDA93d3cu\nZXhhbXBsZS5jb20xIDAeBgkqhkiG9w0BCQEWEWFkbWlu'
                    'QGV4YW1wbGUuY29tMIIB\nIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBC'
                    'gKCAQEA7F2TheIEy9g9CwVMlxlTuZqQ\n6QbJdymQw9RQwR0O09wsbS'
                    'jx4XJtzwDjCX7aZ1ON7eZBXXNkQx6nWlkYrS7zmR4T\npWmLiIYQWpV'
                    'H6oIzgEEaeabFOqfs5b0zbYZN868fcFsPVGGgizfKO6I+gJwp5sii\n'
                    'IQvBa9hCKlXRwbGYYeywThfMf4plxzj/YDIIBkM+4qck58sr7Nhjb5J'
                    'FD60LrOJK\nSdqzCSinsYlx5eZ4f5GjpMc7euAsS5UVdZFV13CysK83'
                    '6h/KHYyz/LXTjGpGbDd7\n2wPSUZRkjY58I5FU0hVeH3zMoaVJBfXmj'
                    'X8TVjR2Jk+NcNr5Azmgn3BC8pTqowID\nAQABMA0GCSqGSIb3DQEBCw'
                    'UAA4ICAQBtGBazJXwQVtIqBeyzmoQDWNctBc5VSTEq\nGT3dAyy0LYJ'
                    'Tm+4aaCVAY4uiS6HTzb4MQR+EtGxN/1fLyFgs/V3oQ+bRh+aWS85u\n'
                    'J4sZL87EtO7VlXLt8mAjqrAAJwwywMhbw+PlGVjhJgp8vAjpbDiccmb'
                    'QRN/noSSF\nTCqUDFtsP4yyf+b8xbipVGvmTLrqTX1Dt9iQKKKD8QYi'
                    'GG0Bt2t38YVc8hEQg3TC\n8xjs1OcyYN+oCRHj+Nunib9fH8OGMjn3j'
                    'OpVAJGADpwmTc0rbwkTFtTUweT5HSCD\nrzLZNI0DwjLeR8mDZRMpjN'
                    'tYaCSERbpzhEUFWEIXuVT3GdrgsPGcNZi520cyeUyz\nTC9ixXgkiy4'
                    'yS8zqca0v2mryrf9MxhYKu2nek+0GB4WodHO904Tlbcdz9wHnCi4f\n'
                    '6VdS7/lKncvj8yJrqE7yQtzLlNGjBUJNajp/jchzlHpsYLCiuIX7fyh'
                    '6Z+cQVwjJ\nSWkf7yuOO+jEw45A0Jxtyl3aLf5aoptmzLOKLFznscSg'
                    'tkFvtdh4O/APxORxgPKc\n1WiQCpUecsmxc4qMRulh31tVBFi6uIsKY'
                    'vrUkP5JaxIxV/nKGBDJyzKbAZWLqdnm\nNd3coEUMwd16vr57QJatJb'
                    'To/wVMMbvW3vqVy0AuXReHCPVTDF5+vnsMGXK/IV7w\nLzulLswFmA='
                    '=\n-----END CERTIFICATE-----\n',
     'id': 'e4b0ab75-ce14-456e-8f5f-071303dd6275',
     'resource_type': 'certificate_signed'}
]
FAKE_CERT_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIEgzCCAmsCCQCmkvlHE5M1KTANBgkqhkiG9w0BAQsFADB0MQswCQYDVQQGEwJV\n"
    "UzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJUGFsbyBBbHRvMQ8wDQYD\n"
    "VQQKDAZWTXdhcmUxDTALBgNVBAsMBE5TQlUxHDAaBgNVBAMME1ZNd2FyZSBOU0JV\n"
    "IFJvb3QgQ0EwHhcNMTcxMDEyMjI0NzU0WhcNMTgxMDA3MjI0NzU0WjCBkjELMAkG\n"
    "A1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEjAQBgNVBAcMCVBhbG8gQWx0\n"
    "bzEPMA0GA1UECgwGVk13YXJlMQ0wCwYDVQQLDAROU0JVMRgwFgYDVQQDDA93d3cu\n"
    "ZXhhbXBsZS5jb20xIDAeBgkqhkiG9w0BCQEWEWFkbWluQGV4YW1wbGUuY29tMIIB\n"
    "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7F2TheIEy9g9CwVMlxlTuZqQ\n"
    "6QbJdymQw9RQwR0O09wsbSjx4XJtzwDjCX7aZ1ON7eZBXXNkQx6nWlkYrS7zmR4T\n"
    "pWmLiIYQWpVH6oIzgEEaeabFOqfs5b0zbYZN868fcFsPVGGgizfKO6I+gJwp5sii\n"
    "IQvBa9hCKlXRwbGYYeywThfMf4plxzj/YDIIBkM+4qck58sr7Nhjb5JFD60LrOJK\n"
    "SdqzCSinsYlx5eZ4f5GjpMc7euAsS5UVdZFV13CysK836h/KHYyz/LXTjGpGbDd7\n"
    "2wPSUZRkjY58I5FU0hVeH3zMoaVJBfXmjX8TVjR2Jk+NcNr5Azmgn3BC8pTqowID\n"
    "AQABMA0GCSqGSIb3DQEBCwUAA4ICAQBtGBazJXwQVtIqBeyzmoQDWNctBc5VSTEq\n"
    "GT3dAyy0LYJTm+4aaCVAY4uiS6HTzb4MQR+EtGxN/1fLyFgs/V3oQ+bRh+aWS85u\n"
    "J4sZL87EtO7VlXLt8mAjqrAAJwwywMhbw+PlGVjhJgp8vAjpbDiccmbQRN/noSSF\n"
    "TCqUDFtsP4yyf+b8xbipVGvmTLrqTX1Dt9iQKKKD8QYiGG0Bt2t38YVc8hEQg3TC\n"
    "8xjs1OcyYN+oCRHj+Nunib9fH8OGMjn3jOpVAJGADpwmTc0rbwkTFtTUweT5HSCD\n"
    "rzLZNI0DwjLeR8mDZRMpjNtYaCSERbpzhEUFWEIXuVT3GdrgsPGcNZi520cyeUyz\n"
    "TC9ixXgkiy4yS8zqca0v2mryrf9MxhYKu2nek+0GB4WodHO904Tlbcdz9wHnCi4f\n"
    "6VdS7/lKncvj8yJrqE7yQtzLlNGjBUJNajp/jchzlHpsYLCiuIX7fyh6Z+cQVwjJ\n"
    "SWkf7yuOO+jEw45A0Jxtyl3aLf5aoptmzLOKLFznscSgtkFvtdh4O/APxORxgPKc\n"
    "1WiQCpUecsmxc4qMRulh31tVBFi6uIsKYvrUkP5JaxIxV/nKGBDJyzKbAZWLqdnm\n"
    "Nd3coEUMwd16vr57QJatJbTo/wVMMbvW3vqVy0AuXReHCPVTDF5+vnsMGXK/IV7w\n"
    "LzulLswFmA==\n"
    "-----END CERTIFICATE-----\n")

FAKE_DPD_ID = "c933402b-f111-4634-9d66-cc8fffde0f65"
FAKE_DPD = {
    "resource_type": "IPSecVPNDPDProfile",
    "description": "neutron dpd profile",
    "id": FAKE_DPD_ID,
    "display_name": "con1-dpd-profile",
    "enabled": True,
    "timeout": 120,
}

FAKE_PEP_ID = "a7b2915c-2041-4a33-9ea7-9d22b67bf38e"
FAKE_PEP = {
    "resource_type": "IPSecVPNPeerEndpoint",
    "id": FAKE_PEP_ID,
    "display_name": "con1",
    "connection_initiation_mode": "INITIATOR",
    "authentication_mode": "PSK",
    "ipsec_tunnel_profile_id": "76e3707d-22e5-4e36-a9ef-b568215e2481",
    "dpd_profile_id": "04191f5f-3bdd-4ec1-ae56-154b06778d4f",
    "ike_profile_id": "df386534-5cec-49b4-9c21-4c212cba3cbf",
    "peer_address": "172.24.4.233",
    "peer_id": "172.24.4.233"
}

FAKE_LEP_ID = "cb57de72-4adb-4dad-9abc-685f9f1d0265"
FAKE_LEP = {
    "resource_type": "IPSecVPNLocalEndpoint",
    "description": "XXX",
    "id": FAKE_LEP_ID,
    "display_name": "XXX",
    "local_id": "1.1.1.1",
    "ipsec_vpn_service_id": {"target_id":
                             "aca38a11-981b-46d8-9e2c-9bedc0d96794"},
    "local_address": "1.1.1.1",
    "trust_ca_ids": [],
    "trust_crl_ids": [],
}

FAKE_VPN_SESS_ID = "33b2f8ce-4357-4780-8c7c-270094847395"
FAKE_VPN_SESS = {
    "resource_type": "PolicyBasedIPSecVPNSession",
    "description": "con1",
    "id": FAKE_VPN_SESS_ID,
    "display_name": "con1",
    "ipsec_vpn_service_id": "f5bbbd92-0c57-412f-82e6-83c73298f2e9",
    "peer_endpoint_id": "7a821e15-93b6-46f9-9d2a-db5a164ee6e3",
    "local_endpoint_id": "e8a3c141-b866-4cb7-91a4-e556b7bd84d6",
    "enabled": True,
    "policy_rules": [{
        "id": "1211",
        "sources": [{"subnet": "10.0.6.0/24"}],
        "logged": False,
        "destinations": [{"subnet": "10.0.5.0/24"}],
        "action": "PROTECT",
        "enabled": True,
    }],
}

FAKE_EDGE_CLUSTER_ID = "69c6bc48-0590-4ff5-87b6-9b49e20b67e0"
FAKE_EDGE_CLUSTER = {
    "resource_type": "EdgeCluster",
    "description": "edgecluster1",
    "id": FAKE_EDGE_CLUSTER_ID,
    "display_name": "edgecluster1",
    "deployment_type": "VIRTUAL_MACHINE",
    "member_node_type": "EDGE_NODE",
    "members": [{
        "member_index": 0,
        "transport_node_id": "321d2746-898e-11e8-9723-000c29391f21"
    }],
    "cluster_profile_bindings": [{
        "profile_id": "15d3485e-0474-4511-bd79-1506ce777baa",
        "resource_type": "EdgeHighAvailabilityProfile"
    }],
}

FAKE_TIERO_ROUTER_ID = "67927d95-18d3-4763-9eb1-a45ff0e63bbe"
FAKE_TIERO_ROUTER = {
    "resource_type": "LogicalRouter",
    "description": "Provider Logical Router(Tier0)",
    "id": FAKE_TIERO_ROUTER_ID,
    "display_name": "PLR-1 LogicalRouterTier0",
    "edge_cluster_id": FAKE_EDGE_CLUSTER_ID,
    "firewall_sections": [{
        "is_valid": True,
        "target_type": "FirewallSection",
        "target_id": "c3d80576-e340-403d-a2d0-f4a72a1db6e3"
    }],
    "advanced_config": {
        "external_transit_networks": ["100.64.0.0/16"],
        "internal_transit_network": "169.254.0.0/28"
    },
    "router_type": "TIER0",
    "high_availability_mode": "ACTIVE_STANDBY",
    "failover_mode": "NON_PREEMPTIVE",
}


FAKE_TRANS_NODE_ID = "f5a2b5ca-8dba-11e8-9799-020039422cc8"
FAKE_TRANS_NODE = {
    "resource_type": "TransportNode",
    "id": FAKE_TRANS_NODE_ID,
    "display_name": FAKE_TRANS_NODE_ID,
    "maintenance_mode": "DISABLED",
    "transport_zone_endpoints": [{
        "transport_zone_id": FAKE_TZ_UUID,
        "transport_zone_profile_ids": [{
            "profile_id": "52035bb3-ab02-4a08-9884-18631312e50a",
            "resource_type": "BfdHealthMonitoringProfile"
        }]
    }],
    "node_id": "f5a2b5ca-8dba-11e8-9799-020039422cc8"
}

FAKE_MANAGER_IP1 = "10.192.210.181"
FAKE_MANAGER_IP2 = "10.192.210.182"
FAKE_CLUSTER_NODES_CONFIG = [{
    "resource_type": "ClusterNodeConfig",
    "manager_role": {
        "type": "ManagementClusterRoleConfig",
        "mgmt_cluster_listen_addr": {
            "port": 0,
            "ip_address": FAKE_MANAGER_IP1
        },
        "api_listen_addr": {
            "port": 443,
            "ip_address": FAKE_MANAGER_IP1
        },
        "mgmt_plane_listen_addr": {
            "port": 5671,
            "ip_address": FAKE_MANAGER_IP1
        }
    },
    "appliance_mgmt_listen_addr": FAKE_MANAGER_IP1
}, {
    "resource_type": "ClusterNodeConfig",
    "controller_role": {
        "type": "ControllerClusterRoleConfig",
        "control_cluster_listen_addr": {
            "port": 7777,
            "ip_address": "127.0.0.1"
        },
    },
}, {
    "resource_type": "ClusterNodeConfig",
    "manager_role": {
        "type": "ManagementClusterRoleConfig",
        "mgmt_cluster_listen_addr": {
            "port": 0,
            "ip_address": FAKE_MANAGER_IP2
        },
        "api_listen_addr": {
            "port": 443,
            "ip_address": FAKE_MANAGER_IP2
        },
        "mgmt_plane_listen_addr": {
            "port": 5671,
            "ip_address": FAKE_MANAGER_IP2
        }
    },
    "appliance_mgmt_listen_addr": FAKE_MANAGER_IP2
}]
