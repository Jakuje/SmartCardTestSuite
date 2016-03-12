#!/bin/bash

usage() { 
	printf "\nUsage:\n\t $0 -m module_path -t [PKCS15, PIV]\n"
	printf "\t -m  module_path:\tpath to tested module (e.g. /usr/lib64/opensc-pkcs11.so)\n"
	printf "\t -t  card_type:\t\tcard type, supported are PKCS15 and PIV\n\n"
	exit 1; 
}

echo
echo "Current directory: $(pwd)"

MODULE=
TYPE=
TEST_APP="./SmartCardTestSuite"

cd ./build
while getopts "m:t:" o; do
    case "${o}" in
    m)
        MODULE=${OPTARG}
	    ;;
	t)
        if test $OPTARG == "PIV"; then
            TYPE=$OPTARG
        elif test $OPTARG == "PKCS15"; then
		    TYPE=$OPTARG
		else
		    echo "Wrong card type."
		    usage
		    exit 1
		fi
	    ;;
    *)
        usage
        ;;
    esac
done
shift $((OPTIND-1))

echo "Module: $MODULE"
echo "Card type: $TYPE"

if test "x$MODULE" == "x"; then
	echo "Module is required parameter"
	usage
	exit 1
fi

if test "x$TYPE" == "x"; then
	echo "Card type is required parameter"
	usage
	exit 1
fi

if test "$TYPE" == "PIV"; then
    if ! type "yubico-piv-tool" > /dev/null 2>&1; then
        echo "Command line tool 'yubico-piv-tool' doesn't exists and has to be installed."
        exit 1
    fi
elif test "$TYPE" == "PKCS15"; then
    if ! type "pkcs15-init" > /dev/null 2>&1; then
        echo "Command line tool 'pkcs15-init' doesn't exists and has to be installed."
        exit 1
    fi

    if ! type "pkcs11-tool" > /dev/null 2>&1; then
        echo "Command line tool 'pkcs11-tool' doesn't exists and has to be installed."
        exit 1
    fi
fi

if ! test -x $MODULE; then
	echo "Module '$MODULE' doesn't exists"
	exit 1
fi

echo "Module for testing is: $MODULE"
echo

if ! test -x $TEST_APP; then
	echo "Smartcard test suite has to be build first"
	echo "Run 'cmake . && make'"
	exit 1
fi

$TEST_APP -m $MODULE -t $TYPE
