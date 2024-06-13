#!/bin/sh

#TEST_PREFIX='strace -f -e trace=network,close,shutdown'
TEST_PREFIX='valgrind --track-origins=yes'
GNUNET_FORCE_LOG='core-underlay-dummy;;;;DEBUG/core;;;;DEBUG/;;;;INFO'
$TEST_PREFIX .libs/test_core_underlay_dummy_single > test_core_underlay_dummy_single_1.log 2>&1
