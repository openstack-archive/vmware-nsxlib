# Copyright 2017 VMware, Inc.
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

TCP = 'TCP'
UDP = 'UDP'

POLICY_INFRA_TENANT = 'infra'

ACTION_ALLOW = 'ALLOW'
ACTION_DENY = 'DROP'

ANY_GROUP = 'ANY'

CONDITION_KEY_TAG = 'Tag'
CONDITION_MEMBER_VM = 'VirtualMachine'
CONDITION_MEMBER_PORT = 'LogicalPort'
CONDITION_OP_EQUALS = 'EQUALS'
CONDITION_OP_CONTAINS = 'CONTAINS'
CONDITION_OP_STARTS_WITH = 'STARTSWITH'

DEFAULT_THUMBPRINT = 'abc'

STATE_REALIZED = 'REALIZED'
STATE_UNREALIZED = 'UNREALIZED'

CATEGORY_EMERGENCY = 'Emergency'
CATEGORY_INFRASTRUCTURE = 'Infrastructure'
CATEGORY_ENVIRONMENTAL = 'Environmental'
CATEGORY_APPLICATION = 'Application'
CATEGORY_DEFAULT = 'Default'
