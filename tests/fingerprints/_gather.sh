
  pwd

  set TEMP_FILE "10e0_temp.log"
  echo > $TEMP_FILE

  cat tests/*/*.log | grep -E ' (I|RP).* 10E0 ' | grep -v ' 10E0 001 ' | python client.py -rrr parse >> $TEMP_FILE.tmp
  cat .sec*/*/*.log | grep -E ' (I|RP).* 10E0 ' | grep -v ' 10E0 001 ' | python client.py -rrr parse >> $TEMP_FILE.tmp
  cat .secret/*.log | grep -E ' (I|RP).* 10E0 ' | grep -v ' 10E0 001 ' | python client.py -rrr parse >> $TEMP_FILE.tmp

  sed -i -e '/^x$/d' -e '/^client/d' -e "s,\x1B\[[0-9;]*[a-zA-Z],,g" $TEMP_FILE.tmp
  sort -uk 5,5 $TEMP_FILE.tmp > $TEMP_FILE

  rm $TEMP_FILE.tmp
