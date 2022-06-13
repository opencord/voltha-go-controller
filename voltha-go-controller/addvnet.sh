#!/bin/bash
for ont in $(seq 1 1)
do
    curl --request POST http://172.17.0.1:8181/vnet/ -d "{\"Name\":\"vnet-name-1\",\"SVlan\":2,\"CVlan\":1015,\"UniVlan\":1015,\"DhcpRelay\":true,\"MacLearning\":false,\"UsDhcpPbits\":[4],\"DsDhcpPbits\":[2],\"UsIGMPPbit\":0,\"DsIGMPPbit\":0,\"VlanControl\":1}"
done
