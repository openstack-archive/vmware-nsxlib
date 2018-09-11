# Copyright 2016 VMware, Inc.
# All Rights Reserved
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
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

# Admin statuses
ADMIN_STATE_UP = "UP"
ADMIN_STATE_DOWN = "DOWN"

# Replication modes
MTEP = "MTEP"

# Port attachment types
ATTACHMENT_VIF = "VIF"
ATTACHMENT_LR = "LOGICALROUTER"
ATTACHMENT_DHCP = "DHCP_SERVICE"
ATTACHMENT_MDPROXY = "METADATA_PROXY"

VIF_RESOURCE_TYPE = "VifAttachmentContext"

VIF_TYPE_PARENT = "PARENT"
VIF_TYPE_CHILD = "CHILD"

ALLOCATE_ADDRESS_NONE = "None"

# NSXv3 L2 Gateway constants
BRIDGE_ENDPOINT = "BRIDGEENDPOINT"

# Router type
ROUTER_TYPE_TIER0 = "TIER0"
ROUTER_TYPE_TIER1 = "TIER1"
ROUTER_TYPE_TIER0_DR = "DISTRIBUTED_ROUTER_TIER0"

LROUTERPORT_UPLINK = "LogicalRouterUpLinkPort"
LROUTERPORT_DOWNLINK = "LogicalRouterDownLinkPort"
LROUTERPORT_CENTRALIZED = "LogicalRouterCentralizedServicePort"
LROUTERPORT_LINKONTIER0 = "LogicalRouterLinkPortOnTIER0"
LROUTERPORT_LINKONTIER1 = "LogicalRouterLinkPortOnTIER1"

# NSX service type
SERVICE_DHCP = "dhcp"

# NSX-V3 Distributed Firewall constants
IP_SET = 'IPSet'
NSGROUP = 'NSGroup'
NSGROUP_COMPLEX_EXP = 'NSGroupComplexExpression'
NSGROUP_SIMPLE_EXP = 'NSGroupSimpleExpression'
NSGROUP_TAG_EXP = 'NSGroupTagExpression'
EXCLUDE_PORT = 'Exclude-Port'

# Firewall rule position
FW_INSERT_BEFORE = 'insert_before'
FW_INSERT_AFTER = 'insert_after'
FW_INSERT_BOTTOM = 'insert_bottom'
FW_INSERT_TOP = 'insert_top'

# firewall rule actions
FW_ACTION_ALLOW = 'ALLOW'
FW_ACTION_DROP = 'DROP'
FW_ACTION_REJECT = 'REJECT'

# nsgroup members update actions
NSGROUP_ADD_MEMBERS = 'ADD_MEMBERS'
NSGROUP_REMOVE_MEMBERS = 'REMOVE_MEMBERS'

# NSServices resource types
L4_PORT_SET_NSSERVICE = 'L4PortSetNSService'
ICMP_TYPE_NSSERVICE = 'ICMPTypeNSService'
IP_PROTOCOL_NSSERVICE = 'IPProtocolNSService'

# firewall section types
FW_SECTION_LAYER3 = 'LAYER3'

TARGET_TYPE_LOGICAL_SWITCH = 'LogicalSwitch'
TARGET_TYPE_LOGICAL_PORT = 'LogicalPort'
TARGET_TYPE_IPV4ADDRESS = 'IPv4Address'
TARGET_TYPE_IPV6ADDRESS = 'IPv6Address'

# filtering operators and expressions
EQUALS = 'EQUALS'

IN = 'IN'
OUT = 'OUT'
IN_OUT = 'IN_OUT'

TCP = 'TCP'
UDP = 'UDP'
ICMPV4 = 'ICMPv4'
ICMPV6 = 'ICMPv6'
IPV4 = 'IPV4'
IPV6 = 'IPV6'
IPV4_IPV6 = 'IPV4_IPV6'

LOCAL_IP_PREFIX = 'local_ip_prefix'

LOGGING = 'logging'

# QoS directions egress/ingress
EGRESS = 'egress'
INGRESS = 'ingress'
EGRESS_SHAPING = 'EgressRateShaper'
INGRESS_SHAPING = 'IngressRateShaper'

# Error codes returned by the backend
ERR_CODE_OBJECT_NOT_FOUND = 202
ERR_CODE_IPAM_POOL_EXHAUSTED = 5109
ERR_CODE_IPAM_SPECIFIC_IP = 5123
ERR_CODE_IPAM_IP_ALLOCATED = 5141
ERR_CODE_IPAM_IP_NOT_IN_POOL = 5110
ERR_CODE_IPAM_RANGE_MODIFY = 5602
ERR_CODE_IPAM_RANGE_DELETE = 5015
ERR_CODE_IPAM_RANGE_SHRUNK = 5016

# backend versions
NSX_VERSION_1_1_0 = '1.1.0'
NSX_VERSION_2_0_0 = '2.0.0'
NSX_VERSION_2_1_0 = '2.1.0'
NSX_VERSION_2_2_0 = '2.2.0'
NSX_VERSION_2_3_0 = '2.3.0'
NSX_VERSION_2_4_0 = '2.4.0'
NSX_VERSION_3_0_0 = '3.0.0'

# Features available depending on the NSX Manager backend version
FEATURE_MAC_LEARNING = 'MAC Learning'
FEATURE_DYNAMIC_CRITERIA = 'Dynamic criteria'
FEATURE_EXCLUDE_PORT_BY_TAG = 'Exclude Port by Tag'
FEATURE_ROUTER_FIREWALL = 'Router Firewall'
FEATURE_LOAD_BALANCER = 'Load Balancer'
FEATURE_DHCP_RELAY = 'DHCP Relay'
FEATURE_VLAN_ROUTER_INTERFACE = 'VLAN Router Interface'
FEATURE_RATE_LIMIT = 'Requests Rate Limit'
FEATURE_IPSEC_VPN = 'IPSec VPN'
FEATURE_ON_BEHALF_OF = 'On Behalf Of'
FEATURE_TRUNK_VLAN = 'Trunk Vlan'
FEATURE_ROUTER_TRANSPORT_ZONE = 'Router Transport Zone'
FEATURE_NO_DNAT_NO_SNAT = 'No DNAT/No SNAT'
FEATURE_ENS_WITH_SEC = 'ENS with security'
FEATURE_ICMP_STRICT = 'Strict list of supported ICMP types and codes'
FEATURE_ROUTER_ALLOCATION_PROFILE = 'Router Allocation Profile'

# Features available depending on the Policy Manager backend version
FEATURE_NSX_POLICY = 'NSX Policy'
FEATURE_NSX_POLICY_NETWORKING = 'NSX Policy Networking'
