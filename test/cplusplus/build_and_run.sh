#!/bin/bash

# 컴파일
export PATH=.:$PATH
export LD_LIBRARY_PATH=.:lib
outfile="program.out"

[ -f $outfile ] && rm $outfile
[ ! -d lib ] && mkdir lib
[ ! -d include ] && mkdir include

g++ -Iinclude -Llib -lpcapi -o $outfile main.cpp

# 컴파일 성공 여부 확인

rsult_file="result.dat"
if [ $? -eq 0 ]; then
    echo "Compilation successful. Running the program..."
    $outfile ../../result/testcase.csv $rsult_file
else
    echo "Compilation failed."
fi

diff $rsult_file ../answer_key/encryption_validation_report.csv
if [ $? -eq 0 ]; then
    echo "test passed!"
else
    echo "test failed!"
fi