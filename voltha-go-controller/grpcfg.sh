#!/bin/bash
curl --request POST http://127.0.0.1:8181/configuration/ -d '{"apps":{"IgmpApp":{"Groups":{"grp3":["239.0.0.1","239.0.0.2","239.0.0.3"],"grp4":["240.0.0.1","240.0.0.2","240.0.0.3"]}}}}'
