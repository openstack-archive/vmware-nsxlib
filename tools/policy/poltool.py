# Copyright 2018 VMware, Inc.
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

import getopt
import json
import os
import sys
from sys import path

path.append(os.path.abspath("../../"))


OPERATIONS = ("create", "update", "delete", "get")
RESOURCES = ("domain", "service", "group", "network", "segment")


def get_resource_api(lib, resource_type):
    return getattr(lib, resource_type)


def get_resource(lib, resource_type, resource_id):

    api = get_resource_api(lib, resource_type)

    ids = resource_id.split(":")
    if ids[-1] == "all":
        result = api.list(*ids[:-1])
    else:
        result = api.get(*ids)

    return result


def create_resource(lib, resource_type, resource_id, args):
    api = get_resource_api(lib, resource_type)

    args["%s_id" % resource_type] = resource_id
    api.create_or_overwrite(**args)


def delete_resource(lib, resource_type, resource_id):
    api = get_resource_api(lib, resource_type)
    if resource_id == "all":
        resource_list = get_resource(lib, resource_type, "all")
        for resource in resource_list:
            delete_resource(lib, resource_type, resource["id"])
    else:
        print("Deleting %s" % resource_id)
        api.delete(resource_id)


def main(argv=sys.argv):

    from vmware_nsxlib import v3
    from vmware_nsxlib.v3 import config

    op = None
    resource_type = None
    resource_id = None
    resource_args = {}

    policy_ip = os.environ.get('NSX_POLICY_IP')
    policy_username = os.environ.get('NSX_POLICY_USERNAME')
    policy_password = os.environ.get('NSX_POLICY_PASSWORD')

    if not policy_ip or not policy_username or not policy_password:
        print("Please provide policy appliance details in environment")
        sys.exit(1)

    usage = "Usage: %s -o <operation> -r <resource type> " \
            "-i <resource id> -a <arg name=value>" % argv[0]
    try:
        opts, args = getopt.getopt(argv[1:], "o:r:i:a:")
    except getopt.GetoptError:
        print(usage)
        sys.exit(1)

    for opt, val in opts:
        if opt in ('-o'):
            op = val
            if op not in OPERATIONS:
                print("Choose operation from %s" % (OPERATIONS,))
                sys.exit(1)

        elif opt in ('-p'):
            policy_ip = val

        elif opt in ('-r'):
            resource_type = val
            if resource_type not in RESOURCES:
                print("Choose resource from %s" % (RESOURCES,))
                sys.exit(1)

        elif opt in ('-i'):
            resource_id = val

        elif opt in ('-a'):
            arg = val.split("=")
            if len(arg) != 2:
                print(usage)
                sys.exit(1)

            resource_args[arg[0]] = arg[1]

    print("Performing %s operation on %s %s" %
          (op, resource_type, resource_id))
    nsxlib_config = config.NsxLibConfig(
        nsx_api_managers=[policy_ip],
        username=policy_username,
        password=policy_password)
    nsxlib = v3.NsxPolicyLib(nsxlib_config)

    if op == 'get':
        result = get_resource(nsxlib, resource_type, resource_id)

        print(json.dumps(result, indent=4))
    elif op == 'create':
        create_resource(nsxlib, resource_type, resource_id, resource_args)
    elif op == 'delete':
        delete_resource(nsxlib, resource_type, resource_id)


if __name__ == "__main__":
    sys.exit(main())
