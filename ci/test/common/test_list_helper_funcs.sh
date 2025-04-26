#!/bin/bash

# Copyright (c) 2025 Marvell.
# SPDX-License-Identifier: Apache-2.0
# https://spdx.org/licenses/Apache-2.0.html

# Functions required to manipulate the test.list file.

TEST_LIST=$BUILD_ROOT/ci/test/test.list

function get_test_name()
{
	local test_num=$1
	local num=1
	local info="LIST_END"
	while read -r testinfo; do
		if [[ $num == $test_num ]]; then
			info=$testinfo
			break
		fi
		num=$((num + 1))
	done <$TEST_LIST
	echo $info | awk -F'#' '{print $1}'
}

function get_test_info()
{
	local test_name=$1
	local name
	local info="LIST_END"
	while read -r testinfo; do
		name=$(echo $testinfo | awk -F'#' '{print $1}')
		if [[ $name == $test_name ]]; then
			info=$testinfo
			break
		fi
	done <$TEST_LIST
	echo $info
}

function get_test_timeout()
{
	local tmo=${DEFAULT_CMD_TIMEOUT:-5m}
	local tst=$1

	for t in ${CMD_TIMEOUTS:-}; do
		if [ "${t%=*}" == "$tst" ]; then
			tmo=${t#*=}
			break
		fi
	done
	echo $tmo
}

function test_enabled()
{
	local test_num=$1
	local tst=$(get_test_name $test_num)

	if [[ $tst == LIST_END ]]; then
		return 1
	fi

	echo -e "\n\n#################### Test $test_num: $tst ########################"

	# Check the SKIP_TESTS and RUN_TESTS and make sure that test need indeed be run
	if [[ -n $RUN_TESTS ]]; then
		if ! (echo "$RUN_TESTS" | grep -q "$tst"); then
			echo "Skipping $tst as not on RUN_TESTS list !!"
			echo "$test_num: $tst [RUN_TESTS]" >> $RUN_DIR/skip.list
			return 77
		fi
	elif $(echo "$SKIP_TESTS" | grep -q "$tst"); then
		echo "Skipping $tst on SKIP_TESTS list !!"
		echo "$test_num: $tst [SKIP_TESTS]" >> $RUN_DIR/skip.list
		return 77
	fi

	if [[ $test_num -lt ${START_TEST_NUM} ]] || [[ $test_num -gt ${END_TEST_NUM} ]]; then
		echo "Skipping $tst as test num not within given test num range ($START_TEST_NUM-$END_TEST_NUM) !!"
		echo "$test_num: $tst [TEST_NUM_OUT_OF_RANGE $START_TEST_NUM-$END_TEST_NUM]" >> $RUN_DIR/skip.list
		return 77
	fi

	echo "$test_num: $tst" >> $RUN_DIR/run.list
	return 0
}

function test_info_print()
{
	local name=$1
	local exec_bin
	local args=
	local defargs
	local envs
	local tmo
	local cmd
	local test_dir
	local extra_args=

	exec_bin=$(get_test_exec_bin $name)
	test_dir=$(get_test_dir $name)
	defargs=$(get_test_args $name)
	envs=$(get_test_env $name)
	tmo=$(get_test_timeout $name)
	cmd=$(get_test_command $name)
	extra_args=$(get_test_extra_args $name)
	echo "Test Binary/script -> $exec_bin"
	echo "Test Timeout -> $tmo"
	echo "Test Environment -> $envs"
	echo "Test Directory -> $test_dir"

	# Remove unnecessary arguments from command line
	echo "Default arguments -> '$defargs'"
	eval set -- "$defargs"
	while [[ $# -gt 0 ]]; do
		case $1 in
			-l) shift; shift;;
			--no-huge) shift;;
			-m) shift; shift;;
			*) args="$args $1"; shift;;
		esac
	done
	echo "Modified arguments -> '$args $extra_args'"
	echo "Test Command -> $cmd"
}

function get_test_command()
{
	local name=$1
	local cmd
	local test_dir

	test_dir=$(get_test_dir $name)

	cmd="cd $REMOTE_BUILD_DIR/ci/test/$name && $TARGET_SUDO bash ${REMOTE_BUILD_DIR}/ci/test/$name/$name.sh"
	echo "$cmd"
}
