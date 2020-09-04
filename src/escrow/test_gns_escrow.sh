#!/bin/sh

LOCATION=$(which gnunet-config)
if [ -z $LOCATION ]
then
  LOCATION="gnunet-config"
fi
$LOCATION --version 1> /dev/null
if test $? != 0
then
	echo "GNUnet command line tools cannot be found, check environmental variables PATH and GNUNET_PREFIX"
	exit 77
fi

rm -rf `gnunet-config -c test_escrow.conf -s PATHS -o GNUNET_HOME -f`

which timeout > /dev/null 2>&1 && DO_TIMEOUT="timeout 30"

gnunet-arm -s -c test_escrow.conf
gnunet-identity -C testego -c test_escrow.conf
ANCHOR=$(gnunet-escrow -m gns -P testego -u secret -c test_escrow.conf)
if test $? != 0
then
	echo "GNS escrow failed!"
	gnunet-arm -e -c test_escrow.conf
	exit 1
else
	ANCHOR=$(echo $ANCHOR | awk 'NF>1{print $NF}')
	echo "using anchor $ANCHOR"
fi
gnunet-escrow -m gns -V testego -a $ANCHOR -c test_escrow.conf
if test $? != 0
then
	echo "GNS verification failed!"
	gnunet-arm -e -c test_escrow.conf
	exit 1
fi
gnunet-identity -D testego -c test_escrow.conf
gnunet-escrow -G -a $ANCHOR -c test_escrow.conf
if test $? != 0
then
	echo "GNS restore failed!"
	gnunet-arm -e -c test_escrow.conf
	exit 1
fi
gnunet-arm -e -c test_escrow.conf

exit 0
