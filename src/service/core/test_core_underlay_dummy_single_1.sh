#!/bin/sh

#strace -f -e trace=network,close,shutdown .libs/test_core_underlay_dummy_single > test_core_underlay_dummy_single_0.log 2>&1
.libs/test_core_underlay_dummy_single > test_core_underlay_dummy_single_1.log 2>&1
