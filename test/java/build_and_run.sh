#!/bin/bash

# 컴파일
javac -cp .:lib/PetraCipherAPI.jar CipherAlgorithmTest.java
#javac -cp ".;lib\PetraCipherAPI.jar" CipherAlgorithmTest.java

# 컴파일 성공 여부 확인
if [ $? -eq 0 ]; then
    echo "Compilation successful. Running the program..."
    # 프로그램 실행. 필요한 경우 인자를 추가합니다.
    java -cp .:lib/PetraCipherAPI.jar -Djava.library.path=lib CipherAlgorithmTest ../../result/testcase.csv ./answer.csv
    #java -cp ".;lib\PetraCipherAPI.jar" CipherAlgorithmTest ../../result/testcase.csv ./answer.win.java.csv
else
    echo "Compilation failed."
fi

diff ./answer.csv ../answer_key/encryption_validation_report.csv

if [ $? -eq 0 ]; then
    echo "test passed!"
else
    echo "test failed!"
fi