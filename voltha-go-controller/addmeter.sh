#!/bin/bash
for ont in $(seq 1 1)
do
    curl --request POST http://172.17.0.1:8181/meter/ -d "{\"Id\":\"BandwidthProf1\",\"cir\":0,\"cbs\":20000,\"eir\":100000,\"ebs\":1000}"
    curl --request POST http://172.17.0.1:8181/meter/ -d "{\"Id\":\"BandwidthProf2\",\"cir\":0,\"cbs\":20000,\"eir\":100000,\"ebs\":2000}"
done
