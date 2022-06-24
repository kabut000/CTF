#!/bin/bash

cd $(dirname $0)

echo "Your input:"

TEMP=$(mktemp -d)

# input is up to 1MiB
dd bs=1024 count=1024 > ${TEMP}/input.txt 2> /dev/null

# Run competitor's solution
timeout 2s stdbuf -i0 ./mirror < ${TEMP}/input.txt > ${TEMP}/output.txt 2> /dev/null
if [ $? -ne 0 ]
then
    echo "Time limit exceeded or something went wrong"
else
    echo "Output:"
    cat ${TEMP}/output.txt
    echo

    ./check_constraints < ${TEMP}/input.txt
    if [ $? -ne 0 ]
    then
        echo "Your input violate constraints or is invalid format"
    else
        timeout 2s ./judge_solution < ${TEMP}/input.txt > ${TEMP}/judge_output.txt
        if [ $? -ne 0 ]
        then
            echo "!?"
        else
            diff ${TEMP}/output.txt ${TEMP}/judge_output.txt > /dev/null
            if [ $? -eq 0 ]
            then
                echo "Your hack was unsuccessful..."
                echo "mirror's output is correct."
            else
                echo "Your hack was successful!"
                echo "mirror's output is wrong."
                echo "Hint:"
                echo "** ***** ***** ****** ********* ******** *** ****** ** ****** ***** ****** ***** ** ******* ****** ********* * ****** ******"
                echo "***** ****** * *** ** *** *** ****** ** *******"
            fi
        fi
    fi
fi

rm -rf ${TEMP}
