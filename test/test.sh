(cat .acstraus/*.log           | grep -vE '3150 .* ..(CA|FE)'      | python client.py parse 2> err_acstraus.log) &
(cat .bruce/*.log .bruce/*.raw | grep -vE '(\*|\#|CC\.|AA\.|None)' | python client.py parse 2> err_bruce.log) &
(cat .secrets/captain*.log                                         | python client.py parse 2> err_captain.log) &
# (cat .secrets/dariusz*.raw                                         | python client.py parse 2> err_dariusz.log) &
(cat .hamba/*.log                                                  | python client.py parse 2> err_hamba.log) &
(cat .nsenica/*.log            | grep -vE '(\*|\#)'                | python client.py parse 2> err_nsenica.log) &
(cat .petep/*.log              | grep -vE 'RQ .* 3EF1'             | python client.py parse 2> err_petep.log) &
(cat .service/packets_1.log    | grep -vE '(\*|\#)'                | python client.py parse 2> err_zxdavb.log) &


LINES=9910000
cat .acstraus/*.log           | grep -vE '3150 .* ..(CA|FE)'      | head -${LINES}   > ztest.log
cat .bruce/*.log .bruce/*.raw | grep -vE '(\*|\#|CC\.|AA\.|None)' | head -${LINES}  >> ztest.log
cat .secrets/captain*.log                                         | head -${LINES}  >> ztest.log
# cat .secrets/dariusz*.raw                                       | head -${LINES}  >> ztest.log
cat .hamba/*.log                                                  | head -${LINES}  >> ztest.log
cat .nsenica/*.log            | grep -vE '(\*|\#)'                | head -${LINES}  >> ztest.log
cat .petep/*.log              | grep -vE 'RQ .* 3EF1'             | head -${LINES}  >> ztest.log
cat .service/packets_1.log    | grep -vE '(\*|\#)'                | head -${LINES}  >> ztest.log
