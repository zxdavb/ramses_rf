(cat .secrets/.acstraus/*.log           | grep -vE '3150 .* ..(CA|FE)'      | python client.py parse 2> err_acstraus.log) &  # 1006881
(cat .secrets/.bruce/evo*.log           | grep -vE '(\*|\#|CC\.|AA\.|None)' | python client.py parse 2> err_bruce.log)    &  #   67616
(cat .secrets/.secrets/captain*.log                                         | python client.py parse 2> err_captain.log) &
# (cat .secrets/dariusz*.raw                                         | python client.py parse 2> err_dariusz.log) &            # 5768
(cat .secrets/.hamba/*.log                                                  | python client.py parse 2> err_hamba.log) &
(cat .secrets/.nsenica/*.log            | grep -vE '(\*|\#)'                | python client.py parse 2> err_nsenica.log) &
(cat .secrets/.petep/*.log              | grep -vE 'RQ .* 3EF1'             | python client.py parse 2> err_petep.log) &
(cat .secrets/.service/packets_1.log    | grep -vE '(\*|\#)'                | python client.py parse 2> err_zxdavb.log) &


LINES=9910000
cat .secrets/.acstraus/*.log           | grep -vE '3150 .* ..(CA|FE)'      | head -${LINES}   > ztest.log
cat .secrets/.bruce/*.log .bruce/*.raw | grep -vE '(\*|\#|CC\.|AA\.|None)' | head -${LINES}  >> ztest.log
cat .secrets/.secrets/captain*.log                                         | head -${LINES}  >> ztest.log
# cat .secrets/.secrets/dariusz*.raw                                       | head -${LINES}  >> ztest.log
cat .secrets/.hamba/*.log                                                  | head -${LINES}  >> ztest.log
cat .secrets/.nsenica/*.log            | grep -vE '(\*|\#)'                | head -${LINES}  >> ztest.log
cat .secrets/.petep/*.log              | grep -vE 'RQ .* 3EF1'             | head -${LINES}  >> ztest.log
cat .secrets/.service/packets_1.log    | grep -vE '(\*|\#)'                | head -${LINES}  >> ztest.log
