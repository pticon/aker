#!/bin/sh

which autoreconf > /dev/null || {
	echo "You should install autoconf"
	exit -1
}

autoreconf --install
