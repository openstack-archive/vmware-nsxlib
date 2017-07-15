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
}

FAKE_ROUTER_PORT_UUID = uuidutils.generate_uuid()
FAKE_ROUTER_PORT = {
    "resource_type": "LogicalRouterLinkPort",
    "revision": 0,
    "id": FAKE_ROUTER_PORT_UUID,
    "display_name": FAKE_NAME,
    "logical_router_id": FAKE_ROUTER_UUID
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
