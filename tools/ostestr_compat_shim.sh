#!/bin/sh

# Copied from neutron/tools. Otherwise no units tests are found.
# preserve old behavior of using an arg as a regex when '--' is not present
case $@ in
  (*--*) ostestr $@;;
  ('') ostestr;;
  (*) ostestr --regex "$@"
esac
