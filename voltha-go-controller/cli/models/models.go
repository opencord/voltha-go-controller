/*
* Copyright 2022-present Open Networking Foundation
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
 */

package models

// TableTitle describe the title of table.
type TableTitle string

const (
	// IGMP constant
	IGMP TableTitle = "IGMP Configurations"
	// SingleMVLAN constant
	SingleMVLAN TableTitle = "MVLAN Profile with ID %s"
	// AllMVLAN constant
	AllMVLAN TableTitle = "All MVLAN Profiles"
	// SingleFlow constant
	SingleFlow TableTitle = "Flow with ID %s"
	// AllFlow constant
	AllFlow TableTitle = "All Flows"
	// AllVNET constant
	AllVNET TableTitle = "All VNET Profiles"
	// SingleVNET constant
	SingleVNET TableTitle = "VNET Profile with ID %s"
	// SinglePort constant
	SinglePort TableTitle = "Port with Device-ID %s Port-ID %s"
	// AllPorts constant
	AllPorts TableTitle = "All Ports Information"
	// SingleService constant
	SingleService TableTitle = "Service with Name %s"
	// AllServices constant
	AllServices TableTitle = "All Services"
	// SingleVpv constant
	SingleVpv TableTitle = "Vpv with Port %s SVlan %s CVlan %s"
	// AllVpvs constant
	AllVpvs TableTitle = "All Vpvs"
	// SingleGroup constant
	SingleGroup TableTitle = "Group with Group-ID %s"
	// AllGroups constant
	AllGroups TableTitle = "All Groups"
	// AllIGMPGroups constant
	AllIGMPGroups TableTitle = "All IGMP Groups"
	// SingleIGMPGroup constant
	SingleIGMPGroup TableTitle = "IGMP Group with ID %s"
	// AllIGMPChannels constant
	AllIGMPChannels TableTitle = "IGMP Channels with  Mvlan %s GroupName %s Device-ID %s"
	// SingleIGMPChannel constant
	SingleIGMPChannel TableTitle = "IGMP Channel with Mvlan %s GroupName %s Device-ID %s Channel-IP %s"
	// AllIGMPDevices constant
	AllIGMPDevices TableTitle = "IGMP Devices with Mvlan %s Group-ID %s Channel-IP %s"
	// SingleIGMPDevice constant
	SingleIGMPDevice TableTitle = "IGMP Device with Mvlan %s Group-ID %s Channel-IP %s Device-ID %s"
	// AllIGMPPorts constant
	AllIGMPPorts TableTitle = "IGMP Ports with Mvlan %s Channel-IP %s Device-ID %s"
	// SingleIGMPPort constant
	SingleIGMPPort TableTitle = "IGMP Port with Mvlan %s Channel-IP %s Device-ID %s Port %s"
	// AllCacheIcmps constant
	AllCacheIcmps TableTitle = "All Cache Icmps"
	// SingleCacheIcmp constant
	SingleCacheIcmp TableTitle = "Cache Icmp with Device-ID %s"
	// AllCacheMvlans constant
	AllCacheMvlans TableTitle = "All Cache Mvlans"
	// SingleCacheMvlan constant
	SingleCacheMvlan TableTitle = "Cache Mvlan with Device-ID %s"
	// AllCachePorts constant
	AllCachePorts TableTitle = "All Cache Ports"
	// SingleCachePort constant
	SingleCachePort TableTitle = "Cache Ports with Device-ID %s"
	// AllTaskLists constant
	AllTaskLists TableTitle = "All Task Lists"
	// SingleTaskList constant
	SingleTaskList TableTitle = "Single Task List with Device-ID %s"
	// AllDeviceInfo constant
	AllDeviceInfo TableTitle = "All Device Info"
	// SingleDeviceInfo constant
	SingleDeviceInfo TableTitle = "Device Info with Device-ID %s"
	// AllPonPorts constant
	AllPonPorts TableTitle = "All PON Ports"
	// SinglePONPorts constant
	SinglePONPorts TableTitle = "PON Ports with Device-ID %s"
	// AllDHCPSessions constant
	AllDHCPSessions TableTitle = "All DHCP Sessions with Device-ID %s"
	// DHCPSessionsWithMAC constant
	DHCPSessionsWithMAC TableTitle = "All DHCP Sessions with Device-ID %s and MAC Address %s"
	// DHCPSessionsWithVLAN constant
	DHCPSessionsWithVLAN TableTitle = "All DHCP Sessions with Device-ID %s SVLAN %s and CVLAN %s"
	// SingleDHCPSession constant
	SingleDHCPSession TableTitle = "All DHCP Sessions with Device-ID %s SVLAN %s CVLAN %s and MAC %s"
	// GetFlowHash constant
	GetFlowHash TableTitle = "Flow hash for device %s"
	// MCAST constant
	MCAST TableTitle = "MCAST Configurations"
)

// CommandUsage describe the type of command used.
type CommandUsage string

const (
	// MVLANUsage constant
	MVLANUsage CommandUsage = "mvlan [mvlan-id]"
	// FlowUsage constant
	FlowUsage CommandUsage = "flows [device-id] [flow-id]"
	// IGMPUsage constant
	IGMPUsage CommandUsage = "igmp"
	// VNETUsage constant
	VNETUsage CommandUsage = "vnet [vnet-id]"
	// PortUsage constant
	PortUsage CommandUsage = "port [device-id] [port-id]"
	// ServiceUsage constant
	ServiceUsage CommandUsage = "service [service-id]"
	// VpvsUsage constant
	VpvsUsage CommandUsage = "vpvs [port] [svlan] [cvlan]"
	// MeterUsage constant
	MeterUsage CommandUsage = "meter [meter-id]"
	// GroupUsage constant
	GroupUsage CommandUsage = "group [device-id] [group-id]"
	// IGMPGroupUsage constant
	IGMPGroupUsage CommandUsage = "igmpgroup [id]"
	// IGMPChannelUsage constant
	IGMPChannelUsage CommandUsage = "igmpchannel [mvlan] [group-name] [device-id] [channel-ip]"
	// IGMPDeviceUsage constant
	IGMPDeviceUsage CommandUsage = "igmpdevice [mvlan] [group-id] [channel-ip] [device-id]"
	// IGMPPortUsage constant
	IGMPPortUsage CommandUsage = "igmpport [mvlan] [channel-ip] [device-id] [port-list]"
	// CacheIcmpUsage constant
	CacheIcmpUsage CommandUsage = "cacheicmp [device-id]"
	// CacheMvlanUsage constant
	CacheMvlanUsage CommandUsage = "cachemvlan [device-id]"
	// CachePortUsage constant
	CachePortUsage CommandUsage = "cacheport [device-id]"
	// TaskListUsage constant
	TaskListUsage CommandUsage = "tasklist [device-id]"
	// DeviceInfoUsage constant
	DeviceInfoUsage CommandUsage = "device [device-id]"
	// PonPortsUsage constant
	PonPortsUsage CommandUsage = "ponports [device-id]"
	// DHCPSessionUsage constant
	DHCPSessionUsage CommandUsage = "dhcpsession [device-id] [mac] [svlan] [cvlan]"
	// SetflowhashUsage constant
	SetflowhashUsage CommandUsage = "setflowhash [device-id] [flowhash (flowhash should be a prime number)]"
	// GetflowhashUsage constant
	GetflowhashUsage CommandUsage = "getflowhash [device-id]"
	// MCASTUsage constant
	MCASTUsage CommandUsage = "mcast"
)

// Orientation describe the data orientation in the table.
type Orientation uint8

const (
	// Horizontal constant
	Horizontal Orientation = iota
	// Vertical constant
	Vertical
)
