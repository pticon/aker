# AKER
A port knocking daemon. It gives you the ability to execute a command triggered by a *magic* port combination.
Generally, we can use it to hide a management port like SSH and execute the given *iptables* rule to allow this client.

Aker was also an Ancient Egyptian earth and death deity and was described as one of the earth gods guarding the "gate to the yonder site". For more info, please check [wikipedia](https://en.wikipedia.org/wiki/Aker_(deity)).

## Prerequisites
You have to install the *libpcap*, *make*, and a working C compiler (clang, gcc, etc...).

## Build
Generate the configure script:
```
./bootstrap.sh
```

Generate the Makefile:
```
./configure
```

Compile the source:
```
make
```

Clean everything:
```
./clean.sh
```

## Running the tests
There is a python script called *regress.py*.

```
Usage: regress.py [options] <testname>

Options:
  -h, --help            show this help message and exit
  -a, --all             execute all of the tests
  -l, --list            list all of the tests
  -g GROUP, --group=GROUP
                        execute the group test
```

There is some issues for the live tests with FreeBSD because we cannot create socket with the **AF_PACKET** type. Any help would be appreciated !

## Install
Just run:
```
make install
```

Then you should edit the config file in */usr/local/etc/aker.conf* to suit to your needs.

## Config
Edit the *aker.conf*.

## Run
```
usage: aker [options]
options:
        -c <conffile> : default is /usr/local/etc/aker.conf
        -f            : run in foreground (do not fork)
        -h            : display this and exit
        -t            : test the generated pcap filter and exit
        -v            : display version number and exit
```

## License
**aker** is licensed under the BSD 3-clause "New" or "Revised" License.
