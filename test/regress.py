#!/usr/bin/env python

# Copyright 2017,2018 Pticon
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# # Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# # Redistributions in binary form must reproduce the above copyright notice,
#  this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# # Neither the name of the copyright holder nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# @desc Quick and dirty script to avoid regressions
#
#


import sys
import os
import subprocess
import shlex
import random
import difflib
import tempfile
from optparse import OptionParser
from scapy.all import *
import time
import os.path
import os
import signal
import platform


PROGNAME="../src/aker"
TEST_DIR="./"
CONF_DIR=TEST_DIR + "confs/"
RESULT_DIR=TEST_DIR + "results/"

# define the config tests list
config_tests = []

# commodity
NAME=0
OPTIONS=1
CONFIG=2
RESULT=3

# Fields description
# 			test name              options         config                          result file
config_tests.append(["usage",                  "-h",           "empty.conf",                   "usage.result"])
config_tests.append(["version",                "-v",           "empty.conf",                   "version.result"])
config_tests.append(["empty",                  "-t",           "empty.conf",                   "empty.result"])
config_tests.append(["simple_syn",             "-t",           "simple_syn.conf",              "simple_syn.result"])
config_tests.append(["simple_rst",             "-t",           "simple_rst.conf",              "simple_rst.result"])
config_tests.append(["simple_fin",             "-t",           "simple_fin.conf",              "simple_fin.result"])
config_tests.append(["simple_ack",             "-t",           "simple_ack.conf",              "simple_ack.result"])
config_tests.append(["simple_psh",             "-t",           "simple_psh.conf",              "simple_psh.result"])
config_tests.append(["simple_urg",             "-t",           "simple_urg.conf",              "simple_urg.result"])
config_tests.append(["multiple_targets",       "-t",           "multiple_targets.conf",        "multiple_targets.result"])
config_tests.append(["simple_udp",             "-t",           "simple_udp.conf",              "simple_udp.result"])
config_tests.append(["udp_syn_rst",            "-t",           "udp_syn_rst.conf",             "udp_syn_rst.result"])
config_tests.append(["udp_with_default_urg",   "-t",           "udp_with_default_urg.conf",    "udp_with_default_urg.result"])

# define the live tests list
live_tests = []

TARGET=4
SEQUENCE=5
FLAGS=6
TEST=7

live_tests.append(["live_syn",			"",		"live_syn.conf",		"live_syn.result",		"127.0.0.1",	"1,2,3,4,5",	        "S",	"/tmp/live_syn"])
live_tests.append(["live_ack",			"",		"live_ack.conf",		"live_ack.result",		"127.0.0.1",	"1,2,3,4,5",	        "A",	"/tmp/live_ack"])
live_tests.append(["live_fin",			"",		"live_fin.conf",		"live_fin.result",		"127.0.0.1",	"1,2,3,4,5",	        "F",	"/tmp/live_fin"])
live_tests.append(["live_rst",			"",		"live_rst.conf",		"live_rst.result",		"127.0.0.1",	"1,2,3,4,5",	        "R",	"/tmp/live_rst"])
live_tests.append(["live_udp",			"",		"live_udp.conf",		"live_udp.result",		"127.0.0.1",	"1,2,3,4,5",	        "UDP",	"/tmp/live_udp"])
live_tests.append(["live_udp_syn_rst",		"",		"live_udp_syn_rst.conf",	"live_udp_syn_rst.result",	"127.0.0.1",	"1,2,3:S,4:R,5",	"UDP",	"/tmp/live_udp_syn_rst"])

# define the signal tests list
signal_tests = []

SIGNAL=4
ACTION=5

signal_tests.append(["signal_term",             "",             "signal_term.conf",             "signal_term.result",   signal.SIGTERM, "dead"])


def exec_config_test(testname):
	"""Execute the given test name relative to the config subset"""
	t = [elt for elt in config_tests if elt[NAME] == testname]

	if not len(t):
		print "No test named %s found" % testname
		sys.exit(-1)

	t = t[0]

	args = ["sudo", PROGNAME, t[OPTIONS], "-c", CONF_DIR + t[CONFIG]]
	print "%26s\t%60s\t" % (t[NAME], " ".join(args)),
	p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	tmp = tempfile.NamedTemporaryFile(delete=False)
	tmp.write(p.communicate()[0])
	tmp.close()
	f1 = open(tmp.name, "r")
	try:
		f2 = open(RESULT_DIR + t[RESULT], 'r')
	except:
		f1.close()
		os.unlink(tmp.name)
		print
		print "%s does not exist !!!" % (RESULT_DIR + t[RESULT])
		sys.exit(-1)
	diff = difflib.ndiff(f1.readlines(), f2.readlines())
	delta = ''.join(x[2:] for x in diff if x.startswith('- '))
	f1.close()
	os.unlink(tmp.name)
	f2.close()
	if delta:
		print
		print delta
		print "[FAILED]"
		sys.exit(-1)
	print "[OK]"


def build_config_tests_list():
	"""Build config tests list"""
	names,_,_,_ = zip(*config_tests)

	return names


def build_live_tests_list():
	"""Build live tests list"""

	# XXX Because the socket AF_PACKET does not on FreeBSD
	if platform.system() == "FreeBSD":
	    return ()

	names,_,_,_,_,_,_,_ = zip(*live_tests)

	return names


def build_signal_tests_list():
	"""Build signal tests list"""
	names,_,_,_,_,_ = zip(*signal_tests)

	return names


def exec_all_config_tests():
	"""Execute all of the configuration checking tests"""

	[exec_config_test(n) for n in build_config_tests_list()]

	return


def exec_live_test(testname):
	"""Execute the given test name relative to the live subset"""
	t = [elt for elt in live_tests if elt[NAME] == testname]

	if not len(t):
		print "No test named %s found" % testname
		sys.exit(-1)

	t = t[0]

        if len(t[OPTIONS]):
	    args = ["sudo", PROGNAME, t[OPTIONS], "-c", CONF_DIR + t[CONFIG]]
        else:
	    args = ["sudo", PROGNAME, "-c", CONF_DIR + t[CONFIG]]
	print "%26s\t%60s\t" % (t[NAME], " ".join(args)),
	p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

	# Give time to start the process
	time.sleep(1)

	for port in t[SEQUENCE].split(","):
		srcport = RandShort()
		substr = port.split(":")
		if len(substr) != 1:
			port = substr[0]
			flags = substr[1]
		else:
			flags = str(t[FLAGS])

		if flags == "UDP":
			synpkt = sr1(IP(dst=t[TARGET])/UDP(sport=int(srcport), dport=int(port)), timeout=0.1, verbose=False)
		else:
			synpkt = sr1(IP(dst=t[TARGET])/TCP(sport=int(srcport), dport=int(port), flags=flags), timeout=0.1, verbose=False)

	# Clean
	pid = int(open("/tmp/aker.pid").read())
	os.kill(pid, signal.SIGKILL)

	os.remove("/tmp/aker.pid")
	os.remove("/tmp/aker.log")

	if os.path.isfile(t[TEST]):
		print "[OK]"
	else:
		print "[FAILED]"
		sys.exit(-1)

	os.remove(t[TEST])


def exec_all_live_tests():
	"""Execute all of the live checking tests"""

	[exec_live_test(n) for n in build_live_tests_list()]

	return


def exec_signal_test(testname):
	"""Execute the given test name relative to the signal subset"""
	t = [elt for elt in signal_tests if elt[NAME] == testname]

	if not len(t):
		print "No test named %s found" % testname
		sys.exit(-1)

	t = t[0]

        if len(t[OPTIONS]):
		args = ["sudo", PROGNAME, t[OPTIONS], "-c", CONF_DIR + t[CONFIG]]
	else:
		args = ["sudo", PROGNAME, "-c", CONF_DIR + t[CONFIG]]
	print "%26s\t%60s\t" % (t[NAME], " ".join(args)),
	p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

	# Give time to the process to start
	time.sleep(1)

	pid = int(open("/tmp/aker.pid").read())
	os.kill(pid, t[SIGNAL])
	time.sleep(1)

        if t[ACTION] == "dead":
                if os.path.isfile("/tmp/aker.pid"):
                        print "[FAILED]"
                else:
                        print "[OK]"

	os.remove("/tmp/aker.log")


def exec_all_signal_tests():
	"""Execute all of the live checking tests"""

	[exec_signal_test(n) for n in build_signal_tests_list()]

	return


def exec_all_tests():
	"""Execute all of the tests"""
	exec_all_config_tests()
	exec_all_live_tests()
        exec_all_signal_tests()


def build_tests_list():
	"""Build the test lists"""
	l = build_config_tests_list()
	l += build_live_tests_list()

	return l


def list_tests():
	"""List all of the tests name"""
	print "Tests list :"

	for t in build_tests_list():
		print "\t%s" % t


def exec_test(testname):
	"""Execute the given testname"""

	if testname in build_config_tests_list():
		return exec_config_test(testname)

	if testname in build_live_tests_list():
		return exec_live_test(testname)

	print "No test named \"%s\" found in any group" % testname


def main():
	"""Main entry point"""
	usage = "usage: %prog [options] <testname>"
	parser = OptionParser(usage)
	parser.add_option("-a", "--all", action="store_true", dest="all",
		help="execute all of the tests")
	parser.add_option("-l", "--list", action="store_true", dest="list",
		help="list all of the tests")
	parser.add_option("-g", "--group", action="store", type="string",
		dest="group", help="execute the group test")

	(options, args) = parser.parse_args()

	if options.list:
		list_tests()
		return
	if options.all:
		exec_all_tests()
		return
	if options.group == "config":
		exec_all_config_tests()
		return
	if options.group == "live":
		exec_all_live_tests()
		return
        if options.group == "signal":
                exec_all_signal_tests()
		return

	if not len(args):
		parser.error("No test name provided")

	for tname in args:
		exec_test(tname)


if __name__ == "__main__":
	main()
