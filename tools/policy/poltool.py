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

#   This is a simple tool for wrapping NSX Policy APIs
#
#   Examples:
#
#   Create tier1 'test' on tier0 provider_test:
#      python poltool.py -o create -r tier1 -i test -a "name=test"
#                        -a "tier0=provider_test"
#   List all tier1s:
#       python poltool.py -o get -r tier1
#   Show tier1 'test':
#       python poltool.py -o get -r tier1 -i test
#   Create segment seg1 on tier1 test:
#       python poltool.py -o create -r tier1_segment -i "seg1" -a "name=seg1"
#                         -a "tier1_id=test"
#                         -a "subnet:gateway_address=1.1.1.1/32"
#   Delete segment seg1:
#       python poltool.py -o delete -r tier1_segment -i "test:seg1"
#   Delete all segments under tier1 test:
#       python poltool.py -o delete -r tier1_segment -i "test:all"


import sys

from sys import path

import copy
import getopt
import json
import os

import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
path.append(os.path.abspath("../../"))


OPERATIONS = ("create", "update", "delete", "get")
RESOURCES = ("domain", "service", "icmp_service", "group", "tier1",
             "segment", "tier1_segment", "segment_port")


def get_resource_api(lib, resource_type):
    return getattr(lib, resource_type)


def build_ids(resource_id):
    return resource_id.split(":")


def get_resource(lib, resource_type, resource_id):

    from vmware_nsxlib.v3 import exceptions as exc
    api = get_resource_api(lib, resource_type)

    ids = build_ids(resource_id)
    try:
        if ids[-1] == "all":
            result = api.list(*ids[:-1])
        else:
            result = api.get(*ids)
    except exc.ResourceNotFound:
        print("Resource of type %s %s not found" % (resource_type, ids))
        sys.exit(2)

    return result


def build_args(resource_type, resource_id, args, add_name=True):
    from vmware_nsxlib.v3 import policy_defs

    if "_" in resource_type:
        # handle cases like tier1_segment_id
        # type is tier1_segment, but id parameter is segment_id
        resource_type = "_".join(resource_type.split("_")[1:])

    args["%s_id" % resource_type] = resource_id
    if "name" not in args and add_name:
        args["name"] = resource_id

    subresources = {}
    for arg, value in args.items():
        if ":" in arg:
            tokens = arg.split(":")
            if len(tokens) < 2:
                print("Bad argument %s" % arg)
                return

            if tokens[0] not in subresources:
                subresources[tokens[0]] = {}
            subresources[tokens[0]][tokens[1]] = copy.copy(value)
            del args[arg]

    for sub, sub_args in subresources.items():
        if sub == "subnet":
            # TODO(annak) - generalize this
            subnet = policy_defs.Subnet(**sub_args)
            args["subnets"] = [subnet]

    return args


def create_resource(lib, resource_type, resource_id, args):

    args = build_args(resource_type, resource_id, args)
    api = get_resource_api(lib, resource_type)

    api.create_or_overwrite(**args)


def update_resource(lib, resource_type, resource_id, args):

    args = build_args(resource_type, resource_id, args, add_name=False)
    api = get_resource_api(lib, resource_type)

    api.update(**args)


def custom_operation(lib, op, resource_type, resource_id, args):

    args = build_args(resource_type, resource_id, args, add_name=False)
    api = get_resource_api(lib, resource_type)

    func = getattr(api, op)
    func(**args)


def delete_resource(lib, resource_type, resource_id):
    api = get_resource_api(lib, resource_type)
    if isinstance(resource_id, list):
        ids = resource_id
    else:
        ids = build_ids(resource_id)
    if ids[-1] == "all":
        resource_list = get_resource(lib, resource_type, resource_id)
        for resource in resource_list:
            resource_ids = copy.deepcopy(ids)
            resource_ids[-1] = resource["id"]
            delete_resource(lib, resource_type, resource_ids)
    else:
        print("Deleting %s" % ids[-1])
        api.delete(*ids)


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
                print("Running custom operation %s" % op)

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
        if not resource_id:
            resource_id = "all"
        result = get_resource(nsxlib, resource_type, resource_id)

        print(json.dumps(result, indent=4))
    elif op == 'create':
        create_resource(nsxlib, resource_type, resource_id, resource_args)
    elif op == 'delete':
        delete_resource(nsxlib, resource_type, resource_id)
    elif op == 'update':
        update_resource(nsxlib, resource_type, resource_id, resource_args)
    else:
        custom_operation(nsxlib, op, resource_type, resource_id, resource_args)

if __name__ == "__main__":
    sys.exit(main())
