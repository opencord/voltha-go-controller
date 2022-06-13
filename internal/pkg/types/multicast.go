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

package common

// IGMPConfig identifies the IGMP Configuration parameters.
type IGMPConfig struct {
	// ProfileID represents IGMP profile ID
	ProfileID string `json:"ProfileID"`
	// ProfileName represents IGMP profile Name
	ProfileName string `json:"ProfileName"`
	// UnsolicitedTimeOut represents unsolicited timeout.
	UnsolicitedTimeOut int `json:"UnsolicitedTimeOut"`
	// MaxResp represents IGMP max response time.
	MaxResp int `json:"MaxResp"`
	// KeepAliveInterval represents IGMP keep alive interval.
	KeepAliveInterval int `json:"KeepAliveInterval"`
	// KeepAliveCount represents IGMP keep alive count.
	KeepAliveCount int `json:"KeepAliveCount"`
	// LastQueryInterval represents IGMP last query interval.
	LastQueryInterval int `json:"LastQueryInterval"`
	// LastQueryCount represents IGMP last query count.
	LastQueryCount int `json:"LastQueryCount"`
	// FastLeave represents IGMP fast leave enabled or not.
	FastLeave *bool `json:"FastLeave"`
	// PeriodicQuery represents IGMP period query interval.
	PeriodicQuery *bool `json:"PeriodicQuery"`
	// IgmpCos represents IGMP COS value(0-7).
	IgmpCos int `json:"IgmpCos"`
	// WithRAUpLink represents IGMP RA uplink.
	WithRAUpLink *bool `json:"withRAUpLink"`
	// WithRADownLink represents IGMP RA downlink.
	WithRADownLink *bool `json:"withRADownLink"`
	// IgmpVerToServer represents IGMP version.
	IgmpVerToServer string `json:"igmpVerToServer"`
	// IgmpSourceIP represents IGMP src ip.
	IgmpSourceIP string `json:"igmpSourceIp"`
}

//MulticastSrcListMode represents mode of source list
type MulticastSrcListMode string

const (
	//Include refers to MulticastSrcListMode as include
	Include MulticastSrcListMode = "include"
	//Exclude refers to MulticastSrcListMode as exclude
	Exclude MulticastSrcListMode = "exclude"
	// StaticGroup refes to the static group name
	StaticGroup string = "static"
	// IsStaticYes refes to the static flag value yes
	IsStaticYes string = "yes"
	// IsStaticNo refes to the static flag value no
	IsStaticNo string = "no"
)

// MulticastGroupProxy identifies source specific multicast(SSM) config.
type MulticastGroupProxy struct {
	// Mode represents source list include/exclude
	Mode MulticastSrcListMode `json:"Mode"`
	// SourceList represents list of multicast server IP addresses.
	SourceList []string `json:"SourceList"`
	// IsStatic flag indicating if the group is a "static" group
	IsStatic string `json:"IsStatic,omitempty"`
}

// MVLANProfile identifies the MVLAN profile.
type MVLANProfile struct {
	// VLANID represents the Multicast VLAN ID.
	VLANID int `json:"VLANID"`
	// ProfileID represents Multicast profile ID
	ProfileID string `json:"ProfileID"`
	// ProfileName represents Multicast profile Name
	ProfileName string `json:"ProfileName"`
	// PonVLAN represents the vlan, where mcast traffic will be translated at OLT
	PonVLAN int `json:"PonVLAN"`
	// Groups represents the MVLAN group information. Key will be group name and value as array of multicast channel IPs.
	Groups map[string][]string `json:"Groups"`
	// Proxy represents multicast group proxy info. Key will be group name and value as proxy info
	Proxy map[string]MulticastGroupProxy `json:"Proxy"`
	//IsChannelBasedGroup represents if the group is channel based
	IsChannelBasedGroup bool `json:"IsChannelBasedGroup"`
	// ActiveIgmpChannelsPerSubscriber represents maximum igmp channels per subscriber can use
	// Default : 3
	ActiveIgmpChannelsPerSubscriber int `json:"ActiveIgmpChannelsPerSubscriber"`
}

// McastConfig the structure for multicast config
type McastConfig struct {
	MVLANProfileID string
	IGMPProfileID  string
	IGMPSrcIP      string
}
