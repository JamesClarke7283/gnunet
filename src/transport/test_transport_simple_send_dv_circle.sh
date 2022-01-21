#!/bin/bash
if ! [ -d "/run/netns" ]; then
    echo You have to create the directory /run/netns.
fi
if  [ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" == 1 ]; then
    # exec unshare -r -nmU bash -c "mount -t tmpfs --make-rshared tmpfs /run/netns; valgrind --leak-check=full --track-origins=yes --trace-children=yes --trace-children-skip=/usr/bin/awk,/usr/bin/cut,/usr/bin/seq,/sbin/ip/sed/bash  ./test_transport_start_with_config test_transport_distance_vector_topo.conf"
    exec unshare -r -nmU bash -c "mount -t tmpfs --make-rshared tmpfs /run/netns; ./test_transport_start_with_config test_transport_distance_vector_circle_topo.conf"
    #./test_transport_start_with_config test_transport_distance_vector_circle_topo.conf
else
    echo -e "Error during test setup: The kernel parameter kernel.unprivileged_userns_clone has to be set to 1! One has to execute\n\n sysctl kernel.unprivileged_userns_clone=1\n"
    exit 78
fi
