#!/bin/bash
onts="0001 0002"
for ont in $(seq 1 2)
do
	servname=TWSH8080$(printf "%04d" $ont)
	# echo $servname
	curl --request POST http://127.0.0.1:8181/service/ -d "{\"Name\":\"${servname}\",\"Cvlan\":1015,\"Svlan\":2,\"Uvlan\":1015,\"Uni\":1,\"CircuitId\":\"\",\"RemoteId\":\"\",\"TechProfileId\":10,\"UsMeterId\":0,\"DsMeterId\":0,\"MulticastEnabled\":false,\"DhcpPbitMarking\":0,\"IgmpPbitMarking\":0,\"Pbits\":[0],\"MacAddr\":\"01:02:03:04:05:06\",\"IgmpEnabled\":true}"
	curl --request POST http://127.0.0.1:8181/service/ -d "{\"Name\":\"${servname}\",\"Cvlan\":1015,\"Svlan\":2,\"Uvlan\":1015,\"Uni\":1,\"CircuitId\":\"\",\"RemoteId\":\"\",\"TechProfileId\":20,\"UsMeterId\":0,\"DsMeterId\":0,\"MulticastEnabled\":false,\"DhcpPbitMarking\":0,\"IgmpPbitMarking\":0,\"Pbits\":[4],\"MacAddr\":\"01:02:03:04:05:06\",\"IgmpEnabled\":true}"
	curl --request POST http://127.0.0.1:8181/service/ -d "{\"Name\":\"${servname}\",\"Cvlan\":1015,\"Svlan\":2,\"Uvlan\":1015,\"Uni\":1,\"CircuitId\":\"\",\"RemoteId\":\"\",\"TechProfileId\":50,\"UsMeterId\":0,\"DsMeterId\":0,\"MulticastEnabled\":false,\"DhcpPbitMarking\":0,\"IgmpPbitMarking\":0,\"Pbits\":[5],\"MacAddr\":\"01:02:03:04:05:06\",\"IgmpEnabled\":true}"
	curl --request POST http://127.0.0.1:8181/service/ -d "{\"Name\":\"${servname}\",\"Cvlan\":1015,\"Svlan\":2,\"Uvlan\":1015,\"Uni\":1,\"CircuitId\":\"\",\"RemoteId\":\"\",\"TechProfileId\":60,\"UsMeterId\":0,\"DsMeterId\":0,\"MulticastEnabled\":false,\"DhcpPbitMarking\":0,\"IgmpPbitMarking\":0,\"Pbits\":[6],\"MacAddr\":\"01:02:03:04:05:06\",\"IgmpEnabled\":true}"
	curl --request POST http://127.0.0.1:8181/service/ -d "{\"Name\":\"${servname}\",\"Cvlan\":1015,\"Svlan\":2,\"Uvlan\":1015,\"Uni\":1,\"CircuitId\":\"\",\"RemoteId\":\"\",\"TechProfileId\":70,\"UsMeterId\":0,\"DsMeterId\":0,\"MulticastEnabled\":false,\"DhcpPbitMarking\":0,\"IgmpPbitMarking\":0,\"Pbits\":[7],\"MacAddr\":\"01:02:03:04:05:06\",\"IgmpEnabled\":true}"
done
