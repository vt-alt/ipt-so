#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

PATH=$PATH:/sbin:/usr/sbin

RED=$'\e[0;31m'
BRED=$'\e[1;31m'
GREEN=$'\e[0;32m'
YELLOW=$'\e[0;33m'
NORM=$'\e[m'

show_dmesg() {
	if [ "$LDMESG" ]; then
		dmesg | sed '/'$LDMESG'/,$!d;//d'
	fi
	LDMESG=$(dmesg | tail -1 | awk '{print$1}')
	LDMESG=${LDMESG%]}
	LDMESG=${LDMESG#[}
}

unload_module() {
	unload_all_rules
	lsmod | grep -q xt_so && rmmod -v xt_so
}
load_module() {
	sysctl kernel.printk=8
	if ! lsmod | grep -q xt_so; then
		insmod ./xt_so.ko debug=2 || exit 1
	fi
	# check if correct module is loaded
	if ! modinfo ./xt_so.ko | grep -qw $(cat /sys/module/xt_so/srcversion); then
		echo "Incorect version of module is loaded."
		exit 1
	fi
}
unload_rules() {
	local t=$1

	iptables-save -t $t | grep -q '.-m so' || return
	iptables-save -t $t | grep '.-m so' \
	| sed "s/-A//" \
	| while read y; do
		iptables -t $t -D $y
	done
}
unload_all_rules() {
	for t in raw mangle nat filter security; do
		unload_rules $t
	done
}
load() {
	load_module
}
unload() {
	unload_module
}
reload() {
	unload_module
	load_module
}
RET=0
TABLE=security
CHAIN=INPUT
RUN() {
	MATCH="$*"
	CMD=("$@")
	echo -n Test: "$@" "-> "
	OUT=$(iptables -t $TABLE -I $CHAIN "$@" 2>&1)
	CODE=$?
}
OK() {
	[ "$*" ] && MATCH="$*"
	if [ $CODE = 0 ]; then
		echo -n "(0) $GREEN OK $NORM"
		set -- "${CMD[@]}"

		MOUT=$(iptables-save -t $TABLE | grep -e "^-A $CHAIN $MATCH\$" 2>&1)
		if [ $? != 0 ]; then
			echo -n " $RED(unmatched)$NORM "
			echo -n "{$(iptables-save -t $TABLE | grep -e '-m so')}"
			RET=1
		fi

		OUT=$(iptables -t $TABLE -D $CHAIN "$@" 2>&1)
		if [ $? = 0 ]; then
			echo " (unload) $GREEN OK $NORM"
		else
			echo " (unload) $RED FAIL: $NORM $OUT"
			RET=1
		fi
	else
		echo "($CODE) $RED FAIL: $NORM $OUT"
		RET=1
	fi
}
FAIL() {
	if [ $CODE != 0 ]; then
		echo "($CODE) $GREEN OK $NORM"
	else
		echo "(0) $RED FAIL $NORM"
		RET=1
	fi
}
run_lib_tests() {
	load
	unload_rules $TABLE
	source libxt_so.t

	if [ $RET != 0 ]; then
		echo "Tests ${BRED}FAIL$NORM!"
	else
		echo "Tests ${GREEN}PASSED$NORM!"
	fi
	exit $RET
}

for j; do
	case $j in
		load)    load ;;
	        unload)  unload ;;
		reload)  reload ;;
	        test)    run_lib_tests ;;
		*)       echo "argument error: $j"; exit 1 ;;
	esac
done
