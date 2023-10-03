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

package application

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
	"voltha-go-controller/internal/pkg/of"
	common "voltha-go-controller/internal/pkg/types"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func TestVoltApplication_InitIgmpSrcMac(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			va.InitIgmpSrcMac()
		})
	}
}

func TestVoltApplication_UpdateIgmpProfile(t *testing.T) {
	type args struct {
		cntx              context.Context
		igmpProfileConfig *common.IGMPConfig
	}
	igmpConfig := &common.IGMPConfig{
		ProfileID:      "test_profile_id",
		FastLeave:      &vgcRebooted,
		PeriodicQuery:  &isUpgradeComplete,
		WithRAUpLink:   &isUpgradeComplete,
		WithRADownLink: &isUpgradeComplete,
	}
	igmpProfile_data := &IgmpProfile{
		ProfileID: "test_profile_id",
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "UpdateIgmpProfile",
			args: args{
				cntx:              context.Background(),
				igmpProfileConfig: igmpConfig,
			},
		},
		{
			name: "UpdateIgmpProfile_Profile_not_found",
			args: args{
				cntx:              context.Background(),
				igmpProfileConfig: igmpConfig,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			switch tt.name {
			case "UpdateIgmpProfile":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutIgmpProfile(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				va.IgmpProfilesByName.Store("test_profile_id", igmpProfile_data)
				if err := va.UpdateIgmpProfile(tt.args.cntx, tt.args.igmpProfileConfig); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.UpdateIgmpProfile() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "UpdateIgmpProfile_Profile_not_found":
				igmpConfig.ProfileID = ""
				if err := va.UpdateIgmpProfile(tt.args.cntx, tt.args.igmpProfileConfig); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.UpdateIgmpProfile() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVoltApplication_resetIgmpProfileToDefault(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	igmpProfile_data := &IgmpProfile{
		ProfileID: "test_profile_id",
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "resetIgmpProfileToDefault",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			va.IgmpProfilesByName.Store("", igmpProfile_data)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutIgmpProfile(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			va.resetIgmpProfileToDefault(tt.args.cntx)
		})
	}
}

func Test_ipv4ToUint(t *testing.T) {
	type args struct {
		ip net.IP
	}
	tests := []struct {
		name string
		args args
		want uint32
	}{
		{
			name: "ipv4ToUint",
			args: args{
				ip: AllSystemsMulticastGroupIP,
			},
			want: 3758096385,
		},
		{
			name: "ipv4ToUint",
			args: args{
				ip: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipv4ToUint(tt.args.ip); got != tt.want {
				t.Errorf("ipv4ToUint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIgmpUsEthLayer(t *testing.T) {
	type args struct {
		mcip net.IP
	}
	tests := []struct {
		name string
		args args
		want *layers.Ethernet
	}{
		{
			name: "IgmpUsEthLayer",
			args: args{
				mcip: AllSystemsMulticastGroupIP,
			},
			want: &layers.Ethernet{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IgmpUsEthLayer(tt.args.mcip)
			assert.NotNil(t, got)
		})
	}
}

func TestIgmpUsDot1qLayer(t *testing.T) {
	type args struct {
		vlan     of.VlanType
		priority uint8
	}
	tests := []struct {
		name string
		args args
		want *layers.Dot1Q
	}{
		{
			name: "IgmpUsDot1qLayer",
			args: args{
				vlan:     of.VlanAny,
				priority: 0,
			},
			want: &layers.Dot1Q{},
		},
		{
			name: "IgmpDsDot1qLayer",
			args: args{
				vlan:     of.VlanAny,
				priority: 0,
			},
			want: &layers.Dot1Q{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "IgmpUsDot1qLayer":
				got := IgmpUsDot1qLayer(tt.args.vlan, tt.args.priority)
				assert.NotNil(t, got)
			case "IgmpDsDot1qLayer":
				got := IgmpDsDot1qLayer(tt.args.vlan, tt.args.priority)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestIgmpv2UsIpv4Layer(t *testing.T) {
	type args struct {
		src  net.IP
		mcip net.IP
	}
	tests := []struct {
		name string
		args args
		want *layers.IPv4
	}{
		{
			name: "Igmpv2UsIpv4Layer",
			args: args{
				src:  AllSystemsMulticastGroupIP,
				mcip: AllSystemsMulticastGroupIP,
			},
			want: &layers.IPv4{},
		},
		{
			name: "IgmpDsIpv4Layer",
			args: args{
				src:  AllSystemsMulticastGroupIP,
				mcip: net.ParseIP("0.0.0.0"),
			},
			want: &layers.IPv4{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "Igmpv2UsIpv4Layer":
				got := Igmpv2UsIpv4Layer(tt.args.src, tt.args.mcip)
				assert.NotNil(t, got)
			case "IgmpDsIpv4Layer":
				got := IgmpDsIpv4Layer(tt.args.src, tt.args.mcip)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestIgmpv3UsIpv4Layer(t *testing.T) {
	type args struct {
		src net.IP
	}
	tests := []struct {
		name string
		args args
		want *layers.IPv4
	}{
		{
			name: "Igmpv3UsIpv4Layer",
			args: args{
				src: AllSystemsMulticastGroupIP,
			},
			want: &layers.IPv4{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Igmpv3UsIpv4Layer(tt.args.src)
			assert.NotNil(t, got)
		})
	}
}

func TestIgmpDsEthLayer(t *testing.T) {
	type args struct {
		mcip net.IP
	}
	tests := []struct {
		name string
		args args
		want *layers.Ethernet
	}{
		{
			name: "IgmpDsEthLayer",
			args: args{
				mcip: AllSystemsMulticastGroupIP,
			},
			want: &layers.Ethernet{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IgmpDsEthLayer(tt.args.mcip)
			assert.NotNil(t, got)
		})
	}
}

func TestIgmpQueryv2Layer(t *testing.T) {
	type args struct {
		mcip     net.IP
		resptime time.Duration
	}
	tests := []struct {
		name string
		args args
		want *layers.IGMPv1or2
	}{
		{
			name: "IgmpQueryv2Laye",
			args: args{
				mcip:     AllSystemsMulticastGroupIP,
				resptime: time.Microsecond,
			},
			want: &layers.IGMPv1or2{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IgmpQueryv2Layer(tt.args.mcip, tt.args.resptime)
			assert.NotNil(t, got)
		})
	}
}

func TestIgmpQueryv3Layer(t *testing.T) {
	type args struct {
		mcip     net.IP
		resptime time.Duration
	}
	tests := []struct {
		name string
		args args
		want *layers.IGMP
	}{
		{
			name: "IgmpQueryv3Layer",
			args: args{
				mcip:     AllSystemsMulticastGroupIP,
				resptime: time.Microsecond,
			},
			want: &layers.IGMP{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IgmpQueryv3Layer(tt.args.mcip, tt.args.resptime)
			assert.NotNil(t, got)
		})
	}
}

func TestIgmpReportv2Layer(t *testing.T) {
	type args struct {
		mcip net.IP
	}
	tests := []struct {
		name string
		args args
		want *layers.IGMPv1or2
	}{
		{
			name: "IgmpReportv2Layer",
			args: args{
				mcip: AllSystemsMulticastGroupIP,
			},
			want: &layers.IGMPv1or2{},
		},
		{
			name: "IgmpLeavev2Layer",
			args: args{
				mcip: AllSystemsMulticastGroupIP,
			},
			want: &layers.IGMPv1or2{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "IgmpReportv2Layer":
				got := IgmpReportv2Layer(tt.args.mcip)
				assert.NotNil(t, got)
			case "IgmpLeavev2Layer":
				got := IgmpLeavev2Layer(tt.args.mcip)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestIgmpReportv3Layer(t *testing.T) {
	type args struct {
		mcip    net.IP
		incl    bool
		srclist []net.IP
	}
	tests := []struct {
		name string
		args args
		want *layers.IGMP
	}{
		{
			name: "IgmpReportv3Layer",
			args: args{
				mcip: AllSystemsMulticastGroupIP,
				incl: true,
			},
			want: &layers.IGMP{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IgmpReportv3Layer(tt.args.mcip, tt.args.incl, tt.args.srclist)
			assert.NotNil(t, got)
		})
	}
}

func Test_getVersion(t *testing.T) {
	type args struct {
		ver string
	}
	tests := []struct {
		name string
		args args
		want uint8
	}{
		{
			name: "getVersion_IgmpVersion2",
			args: args{
				ver: "2",
			},
			want: IgmpVersion2,
		},
		{
			name: "getVersion_IgmpVersion2",
			args: args{
				ver: "0",
			},
			want: IgmpVersion3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getVersion(tt.args.ver); got != tt.want {
				t.Errorf("getVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsIPPresent(t *testing.T) {
	type args struct {
		i   net.IP
		ips []net.IP
	}
	ips := []net.IP{}
	ips = append(ips, AllSystemsMulticastGroupIP)
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "TestIsIPPresent_True",
			args: args{
				i:   AllSystemsMulticastGroupIP,
				ips: ips,
			},
			want: true,
		},
		{
			name: "TestIsIPPresent_False",
			args: args{
				ips: ips,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsIPPresent(tt.args.i, tt.args.ips); got != tt.want {
				t.Errorf("IsIPPresent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddToPendingPool(t *testing.T) {
	type args struct {
		cntx     context.Context
		device   string
		groupKey string
	}

	group := &IgmpGroup{
		GroupName:             "test_key",
		GroupID:               uint32(256),
		PendingGroupForDevice: make(map[string]time.Time),
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "AddToPendingPool_true",
			args: args{
				device:   "SDX6320031",
				cntx:     context.Background(),
				groupKey: "test_key",
			},
			want: true,
		},
		{
			name: "AddToPendingPool_false",
			args: args{
				device:   "SDX6320031",
				cntx:     context.Background(),
				groupKey: "test_key",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "AddToPendingPool_true":
				va := GetApplication()
				va.IgmpGroups.Store("test_key", group)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutIgmpGroup(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				if got := AddToPendingPool(tt.args.cntx, tt.args.device, tt.args.groupKey); got != tt.want {
					t.Errorf("AddToPendingPool() = %v, want %v", got, tt.want)
				}
			case "AddToPendingPool_false":
				va := GetApplication()
				va.IgmpGroups.Store("test_key", group)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutIgmpGroup(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("failed")).Times(1)
				if got := AddToPendingPool(tt.args.cntx, tt.args.device, tt.args.groupKey); got != tt.want {
					t.Errorf("AddToPendingPool() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestGetMcastServiceForSubAlarm(t *testing.T) {
	type args struct {
		uniPort *VoltPort
		mvp     *MvlanProfile
	}
	mvp := &MvlanProfile{
		Name: "mvlan_test",
	}
	voltPort := &VoltPort{
		Name:   "16777472",
		Device: "SDX6320031",
		ID:     16777472,
		State:  PortStateUp,
	}
	voltServ := &VoltService{
		VoltServiceOper: VoltServiceOper{
			Device: "SDX6320031",
		},
		VoltServiceCfg: VoltServiceCfg{
			IgmpEnabled:      true,
			MvlanProfileName: "mvlan_test",
			Name:             "SDX6320031-1_SDX6320031-1-4096-2310-4096-65",
		},
	}
	voltPortVnets := make([]*VoltPortVnet, 0)
	voltPortVnet := &VoltPortVnet{
		Device:      "SDX6320031",
		Port:        "16777472",
		IgmpEnabled: true,
		services:    sync.Map{},
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "GetMcastServiceForSubAlarm",
			args: args{
				uniPort: voltPort,
				mvp:     mvp,
			},
			want: "SDX6320031-1_SDX6320031-1-4096-2310-4096-65",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "GetMcastServiceForSubAlarm":
				va := GetApplication()
				voltPortVnets = append(voltPortVnets, voltPortVnet)
				voltPortVnet.services.Store("SDX6320031-1_SDX6320031-1-4096-2310-4096-65", voltServ)
				va.VnetsByPort.Store("16777472", voltPortVnets)
				if got := GetMcastServiceForSubAlarm(tt.args.uniPort, tt.args.mvp); got != tt.want {
					t.Errorf("GetMcastServiceForSubAlarm() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestSendQueryExpiredEventGroupSpecific(t *testing.T) {
	type args struct {
		portKey string
		igd     *IgmpGroupDevice
		igc     *IgmpGroupChannel
	}
	mvp := &MvlanProfile{
		Name: "mvlan_test",
	}
	voltServ := &VoltService{
		VoltServiceOper: VoltServiceOper{
			Device: "SDX6320031",
		},
		VoltServiceCfg: VoltServiceCfg{
			IgmpEnabled:      true,
			MvlanProfileName: "mvlan_test",
			Name:             "SDX6320031-1_SDX6320031-1-4096-2310-4096-65",
		},
	}
	voltPortVnets := make([]*VoltPortVnet, 0)
	voltPortVnet := &VoltPortVnet{
		Device:      "SDX6320031",
		Port:        "16777472",
		IgmpEnabled: true,
		services:    sync.Map{},
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "SendQueryExpiredEventGroupSpecific",
			args: args{
				portKey: "16777472",
				igd: &IgmpGroupDevice{
					Mvlan: of.VlanAny,
				},
				igc: &IgmpGroupChannel{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := GetApplication()
			voltPortVnets = append(voltPortVnets, voltPortVnet)
			voltPortVnet.services.Store("SDX6320031-1_SDX6320031-1-4096-2310-4096-65", voltServ)
			va.VnetsByPort.Store("16777472", voltPortVnets)
			va.MvlanProfilesByTag.Store(of.VlanAny, mvp)
			SendQueryExpiredEventGroupSpecific(tt.args.portKey, tt.args.igd, tt.args.igc)
		})
	}
}

func TestVoltApplication_GetPonPortID(t *testing.T) {
	type args struct {
		device    string
		uniPortID string
	}
	tests := []struct {
		name string
		args args
		want uint32
	}{
		{
			name: "RestoreIgmpGroupsFromDb",
			args: args{},
			want: uint32(255),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			if got := va.GetPonPortID(tt.args.device, tt.args.uniPortID); got != tt.want {
				t.Errorf("VoltApplication.GetPonPortID() = %v, want %v", got, tt.want)
			}
		})
	}
}
