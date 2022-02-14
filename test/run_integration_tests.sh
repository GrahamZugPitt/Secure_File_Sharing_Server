#!/bin/bash
#see extra-credit.txt for usage

CLASSPATH="../lib/*:../build/"
IP="localhost"
GS_PORT="100"
FS_PORT="101"
ADMIN_USER="admin"
ADMIN_PASS="admin"

test_file="tests"
output_file="output.test"
input_file="input.test"

GS_keyfile="GS_Key.test"
GS_output="GS_output.test"
FS_keyfile="FS_Key.test"
FS_output="FS_output.test"


run_client="java -cp $CLASSPATH RunUserClient $input_file"
run_groupserver="java -cp $CLASSPATH RunGroupServer $GS_PORT"
run_fileserver="java -cp $CLASSPATH RunFileServer $FS_PORT"

rm *.bin
rm *.test


(echo "$ADMIN_USER $ADMIN_PASS " | $run_groupserver) > $GS_output &
sleep 5s
cat $GS_output | head -9 | tail -1 > $GS_keyfile

(echo "$GS_keyfile" | $run_fileserver) > $FS_output &
sleep 5s
cat $FS_output | head -3 | tail -1 > $FS_keyfile


GS_KEY=`cat $GS_keyfile`
FS_KEY=`cat $FS_keyfile`


client_login="$IP\n$GS_PORT\n$GS_KEY\n$IP\n$FS_PORT\n$FS_KEY\n$ADMIN_USER\n$ADMIN_PASS\n"
echo -e "$client_login$(cat $test_file)" > $input_file

$run_client >  $output_file && fg
echo "Tests Passed: $(grep -c "OK" $output_file)"
echo "Tests Failed: $(grep -c "FAIL" $output_file)"

kill $(lsof -t -i:100)
kill $(lsof -t -i:101)