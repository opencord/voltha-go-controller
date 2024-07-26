#!/bin/bash
#
# Copyright 2022-2024present Open Networking Foundation
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#/

echo '[ ! -z "$TERM" -a -r /etc/banner ] && cat /etc/issue && cat /etc/banner' \
    >> /etc/bash.bashrc \
    ; echo -e "
-----------------------------------------------------------
	__      _______  _____    _____ _      _____ 
	\ \    / / ____|/ ____|  / ____| |    |_   _|
	 \ \  / / |  __| |      | |    | |      | |  
	  \ \/ /| | |_ | |      | |    | |      | |  
	   \  / | |__| | |____  | |____| |____ _| |_ 
	    \/   \_____|\_____|  \_____|______|_____|

-----------------------------------------------------------
                   Welcome to VGC-CLI
-----------------------------------------------------------

"\
    > /etc/banner

# ENVIRONMENT VARIABLES
echo "export KAFKA_ADAPTER_HOST=${KAFKA_ADAPTER_HOST}" >> /home/voltha-go-controller/.bash_profile
echo "export KAFKA_ADAPTER_PORT=9092" >> /home/voltha-go-controller/.bash_profile
echo "export KAFKA_CLUSTER_HOST=${KAFKA_CLUSTER_HOST}" >> /home/voltha-go-controller/.bash_profile
echo "export KAFKA_CLUSTER_PORT=9092" >> /home/voltha-go-controller/.bash_profile
echo "export KV_STORE_HOST=${KV_STORE_HOST}" >> /home/voltha-go-controller/.bash_profile
echo "export KV_STORE_PORT=${KV_STORE_PORT}" >> /home/voltha-go-controller/.bash_profile
echo "export KV_STORE_TYPE=redis" >> /home/voltha-go-controller/.bash_profile
echo "export VOLTHA_HOST=${VOLTHA_HOST}" >> /home/voltha-go-controller/.bash_profile
echo "export VOLTHA_PORT=${VOLTHA_PORT}" >> /home/voltha-go-controller/.bash_profile
echo "export KV_STORE_TIMEOUT=10" >> /home/voltha-go-controller/.bash_profile
echo "export BANNER=false" >> /home/voltha-go-controller/.bash_profile

# ALIAS FOR VGC COMMANDS
echo "alias flows='./vgcctl flows'" >> /home/voltha-go-controller/.bash_profile
echo "alias igmp='./vgcctl igmp'" >> /home/voltha-go-controller/.bash_profile
echo "alias mvlan='./vgcctl mvlan'" >> /home/voltha-go-controller/.bash_profile
echo "alias port='./vgcctl port'" >> /home/voltha-go-controller/.bash_profile
echo "alias service='./vgcctl service'" >> /home/voltha-go-controller/.bash_profile
echo "alias vnet='./vgcctl vnet'" >> /home/voltha-go-controller/.bash_profile
echo "alias vpvs='./vgcctl vpvs'" >> /home/voltha-go-controller/.bash_profile
echo "alias meter='./vgcctl meter'" >> /home/voltha-go-controller/.bash_profile
echo "alias group='./vgcctl group'" >> /home/voltha-go-controller/.bash_profile
echo "alias igmpgroup='./vgcctl igmpgroup'">> /home/voltha-go-controller/.bash_profile
echo "alias igmpchannel='./vgcctl igmpchannel'">> /home/voltha-go-controller/.bash_profile
echo "alias igmpdevice='./vgcctl igmpdevice'">>/home/voltha-go-controller/.bash_profile
echo "alias igmpport='./vgcctl igmpport'">>/home/voltha-go-controller/.bash_profile
echo "alias cacheicmp='./vgcctl cacheicmp'">>/home/voltha-go-controller/.bash_profile
echo "alias cachemvlan='./vgcctl cachemvlan'">>/home/voltha-go-controller/.bash_profile
echo "alias cacheport='./vgcctl cacheport'">>/home/voltha-go-controller/.bash_profile
echo "alias tasklist='./vgcctl tasklist'">>/home/voltha-go-controller/.bash_profile
echo "alias device='./vgcctl device'">>/home/voltha-go-controller/.bash_profile
echo "alias help='./vgcctl --help'">>/home/voltha-go-controller/.bash_profile
echo "alias dhcpsession='./vgcctl dhcpsession'">>/home/voltha-go-controller/.bash_profile
echo "alias ponports='./vgcctl ponports'">>/home/voltha-go-controller/.bash_profile
echo "alias mcast='./vgcctl mcast'" >> /home/voltha-go-controller/.bash_profile

chown voltha-go-controller.voltha-go-controller /home/voltha-go-controller/.bash_profile
ssh-keygen -A
/usr/sbin/sshd -D &
/home/voltha-go-controller/voltha-go-controller
