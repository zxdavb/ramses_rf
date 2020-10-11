(cat .secrets/acstraus/*.log           | grep -vE '3150 .* ..(CA|FE)'      | python client.py parse 2> err_acstraus.log)  &  # 1006881
(cat .secrets/bruce/evo*.log           | grep -vE '(\*|\#|CC\.|AA\.|None)' | python client.py parse 2> err_bruce.log)     &  #   67616
(cat .secrets/captain/*.log                                                | python client.py parse 2> err_captain.log)   &
(cat .secrets/dariusz/dariusz*.raw                                         | python client.py parse 2> err_dariusz.log)   &  #    5768
(cat .secrets/fysmd/*.log                                                  | python client.py parse 2> err_fysmd.log)     &
(cat .secrets/hamba/*.log                                                  | python client.py parse 2> err_hamba.log)     &
(cat .secrets/lustasag/*.log           | grep -vE '(\*|\#)'                | python client.py parse 2> err_lustasag.log)  &
(cat .secrets/maniac/*.log             | grep -vE '( 2349 |\*|\#)'         | python client.py parse 2> err_maniac.log)    &
(cat .secrets/nsenica/*.log            | grep -vE '(\*|\#)'                | python client.py parse 2> err_nsenica.log)   &
(cat .secrets/rbrommer/*.log                                               | python client.py parse 2> err_rbrommer.log)  &
(cat .secrets/petep/*.log              | python client.py parse 2> err_petep.log)     &



LINES=5000
cat .secrets/acstraus/*.log           | grep -vE '3150 .* ..(CA|FE)'      | head -${LINES}   > ztest.log
cat .secrets/bruce/evo*.log           | grep -vE '(\*|\#|CC\.|AA\.|None)' | head -${LINES}  >> ztest.log
cat .secrets/captain/captain*.log                                         | head -${LINES}  >> ztest.log
# cat .secrets/dariusz/dariusz*.raw                                       | head -${LINES}  >> ztest.log
cat .secrets/hamba/*.log                                                  | head -${LINES}  >> ztest.log
cat .secrets/lustasag/*.log                                               | head -${LINES}  >> ztest.log
cat .secrets/nsenica/*.log            | grep -vE '(\*|\#)'                | head -${LINES}  >> ztest.log
cat .secrets/petep/*.log              | grep -vE 'RQ .* 3EF1'             | head -${LINES}  >> ztest.log
cat .secrets/rbrommer/*.log                                               | head -${LINES}  >> ztest.log
cat .service/packets_1.log            | grep -vE '(\*|\#)'                | head -${LINES}  >> ztest.log
