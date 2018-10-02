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

IPv4_ANY = '0.0.0.0/0'

# Protocol names and numbers for Security Groups/Firewalls
PROTO_NAME_AH = 'ah'
PROTO_NAME_DCCP = 'dccp'
PROTO_NAME_EGP = 'egp'
PROTO_NAME_ESP = 'esp'
PROTO_NAME_GRE = 'gre'
PROTO_NAME_ICMP = 'icmp'
PROTO_NAME_IGMP = 'igmp'
PROTO_NAME_IPIP = 'ipip'
PROTO_NAME_IPV6_ENCAP = 'ipv6-encap'
PROTO_NAME_IPV6_FRAG = 'ipv6-frag'
PROTO_NAME_IPV6_ICMP = 'ipv6-icmp'
# For backward-compatibility of security group rule API, we keep the old value
# for IPv6 ICMP. It should be clean up in the future.
PROTO_NAME_IPV6_ICMP_LEGACY = 'icmpv6'
PROTO_NAME_IPV6_NONXT = 'ipv6-nonxt'
PROTO_NAME_IPV6_OPTS = 'ipv6-opts'
PROTO_NAME_IPV6_ROUTE = 'ipv6-route'
PROTO_NAME_OSPF = 'ospf'
PROTO_NAME_PGM = 'pgm'
PROTO_NAME_RSVP = 'rsvp'
PROTO_NAME_SCTP = 'sctp'
PROTO_NAME_TCP = 'tcp'
PROTO_NAME_UDP = 'udp'
PROTO_NAME_UDPLITE = 'udplite'
PROTO_NAME_VRRP = 'vrrp'

PROTO_NUM_AH = 51
PROTO_NUM_DCCP = 33
PROTO_NUM_EGP = 8
PROTO_NUM_ESP = 50
PROTO_NUM_GRE = 47
PROTO_NUM_ICMP = 1
PROTO_NUM_IGMP = 2
PROTO_NUM_IPIP = 4
PROTO_NUM_IPV6_ENCAP = 41
PROTO_NUM_IPV6_FRAG = 44
PROTO_NUM_IPV6_ICMP = 58
PROTO_NUM_IPV6_NONXT = 59
PROTO_NUM_IPV6_OPTS = 60
PROTO_NUM_IPV6_ROUTE = 43
PROTO_NUM_OSPF = 89
PROTO_NUM_PGM = 113
PROTO_NUM_RSVP = 46
PROTO_NUM_SCTP = 132
PROTO_NUM_TCP = 6
PROTO_NUM_UDP = 17
PROTO_NUM_UDPLITE = 136
PROTO_NUM_VRRP = 112

IP_PROTOCOL_MAP = {PROTO_NAME_AH: PROTO_NUM_AH,
                   PROTO_NAME_DCCP: PROTO_NUM_DCCP,
                   PROTO_NAME_EGP: PROTO_NUM_EGP,
                   PROTO_NAME_ESP: PROTO_NUM_ESP,
                   PROTO_NAME_GRE: PROTO_NUM_GRE,
                   PROTO_NAME_ICMP: PROTO_NUM_ICMP,
                   PROTO_NAME_IGMP: PROTO_NUM_IGMP,
                   PROTO_NAME_IPIP: PROTO_NUM_IPIP,
                   PROTO_NAME_IPV6_ENCAP: PROTO_NUM_IPV6_ENCAP,
                   PROTO_NAME_IPV6_FRAG: PROTO_NUM_IPV6_FRAG,
                   PROTO_NAME_IPV6_ICMP: PROTO_NUM_IPV6_ICMP,
                   # For backward-compatibility of security group rule API
                   PROTO_NAME_IPV6_ICMP_LEGACY: PROTO_NUM_IPV6_ICMP,
                   PROTO_NAME_IPV6_NONXT: PROTO_NUM_IPV6_NONXT,
                   PROTO_NAME_IPV6_OPTS: PROTO_NUM_IPV6_OPTS,
                   PROTO_NAME_IPV6_ROUTE: PROTO_NUM_IPV6_ROUTE,
                   PROTO_NAME_OSPF: PROTO_NUM_OSPF,
                   PROTO_NAME_PGM: PROTO_NUM_PGM,
                   PROTO_NAME_RSVP: PROTO_NUM_RSVP,
                   PROTO_NAME_SCTP: PROTO_NUM_SCTP,
                   PROTO_NAME_TCP: PROTO_NUM_TCP,
                   PROTO_NAME_UDP: PROTO_NUM_UDP,
                   PROTO_NAME_UDPLITE: PROTO_NUM_UDPLITE,
                   PROTO_NAME_VRRP: PROTO_NUM_VRRP}

# Supported ICMP types and their codes
IPV4_ICMP_TYPES = {0: [0],  # Echo reply
                   3: range(0, 16),  # Destination unreachable
                   4: [0],  # Source quench
                   5: range(0, 4),  # Redirect
                   8: [0],  # Echo request
                   9: [0, 16],  # Router advertisement
                   10: [0],  # Router Selection
                   11: [0, 1],  # Time exceeded
                   12: [0, 1, 2],  # Parameter Problem
                   13: [0],  # Timestamp
                   14: [0],  # Timestamp reply
                   15: [0],  # Information request
                   16: [0],  # Information reply
                   17: [0],  # Address mask request
                   18: [0],  # Address mask reply
                   33: [0],  # Where-Are-You
                   34: [0],  # I-Am-Here
                   35: [0],  # Mobile registration request
                   36: [0],  # Mobile registration reply
                   }
# Supported strict ICMP types and codes. MP accepts everything except 9:16
IPV4_ICMP_STRICT_TYPES = IPV4_ICMP_TYPES.copy()
# Note: replace item 9 as we did a shallow copy
IPV4_ICMP_STRICT_TYPES[9] = [0]
