/*
* Copyright 2022-2024present Open Networking Foundation
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
	"net"
	"reflect"
	"sync"
	"testing"
	"voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/pkg/of"
	common "voltha-go-controller/internal/pkg/types"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func Test_newIgmpProfile(t *testing.T) {
	type args struct {
		igmpProfileConfig *common.IGMPConfig
	}
	b := true
	tests := []struct {
		name string
		args args
		want *IgmpProfile
	}{
		{
			name: "DelExclSource",
			args: args{
				igmpProfileConfig: &common.IGMPConfig{
					FastLeave:      &b,
					PeriodicQuery:  &b,
					WithRAUpLink:   &b,
					WithRADownLink: &b,
				},
			},
			want: &IgmpProfile{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newIgmpProfile(tt.args.igmpProfileConfig)
			assert.NotNil(t, got)
		})
	}
}

func TestNewMvlanProfile(t *testing.T) {
	type args struct {
		name                string
		mvlan               of.VlanType
		ponVlan             of.VlanType
		isChannelBasedGroup bool
		OLTSerialNums       []string
		actChannelPerPon    uint32
	}
	tests := []struct {
		name string
		args args
		want *MvlanProfile
	}{
		{
			name: "DelExclSource",
			args: args{
				name: "test_mvlan",
			},
			want: &MvlanProfile{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewMvlanProfile(tt.args.name, tt.args.mvlan, tt.args.ponVlan, tt.args.isChannelBasedGroup, tt.args.OLTSerialNums, tt.args.actChannelPerPon)
			assert.NotNil(t, got)
		})
	}
}

func TestMvlanProfile_AddMvlanProxy(t *testing.T) {
	proxy := map[string]*MCGroupProxy{}
	proxy["test_key"] = &MCGroupProxy{
		Mode: common.Exclude,
	}
	grp := make(map[string]*MvlanGroup)
	grp["test_key"] = &MvlanGroup{
		Name:     "test_key",
		IsStatic: true,
	}
	type args struct {
		name      string
		proxyInfo common.MulticastGroupProxy
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "AddMvlanProxy",
			args: args{
				name: "test_key",
				proxyInfo: common.MulticastGroupProxy{
					IsStatic: common.IsStaticYes,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mvp := &MvlanProfile{
				Proxy:  proxy,
				Groups: grp,
			}
			mvp.AddMvlanProxy(tt.args.name, tt.args.proxyInfo)
		})
	}
}

func TestMvlanProfile_AddMvlanGroup(t *testing.T) {
	type args struct {
		name string
		ips  []string
	}
	grp := make(map[string]*MvlanGroup)
	grp["test_key"] = &MvlanGroup{
		Name:     "test_key",
		IsStatic: true,
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "AddMvlanProxy",
			args: args{
				name: "test_key",
				ips: []string{
					"0.0.0.0",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mvp := &MvlanProfile{
				Groups: grp,
			}
			mvp.AddMvlanGroup(tt.args.name, tt.args.ips)
		})
	}
}

func TestMvlanProfile_GetUsMatchVlan(t *testing.T) {
	tests := []struct {
		name string
		want of.VlanType
	}{
		{
			name: "GetUsMatchVlan",
			want: of.VlanAny,
		},
		{
			name: "GetUsMatchVlan_IsPonVlanPresent",
			want: of.VlanAny,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mvp := &MvlanProfile{
				PonVlan: of.VlanAny,
				Mvlan:   of.VlanAny,
			}
			switch tt.name {
			case "GetUsMatchVlan":
				mvp.IsPonVlanPresent = true
				if got := mvp.GetUsMatchVlan(); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("MvlanProfile.GetUsMatchVlan() = %v, want %v", got, tt.want)
				}
			case "GetUsMatchVlan_IsPonVlanPresent":
				if got := mvp.GetUsMatchVlan(); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("MvlanProfile.GetUsMatchVlan() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestMvlanProfile_isChannelStatic(t *testing.T) {
	type args struct {
		channel net.IP
	}
	grp := make(map[string]*MvlanGroup)
	grp["test_key"] = &MvlanGroup{
		Name:     "test_key",
		IsStatic: true,
		McIPs: []string{
			"224.0.0.1",
		},
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "isChannelStatic",
			args: args{
				channel: AllSystemsMulticastGroupIP,
			},
			want: true,
		},
		{
			name: "isChannelStatic_false",
			want: false,
		},
		{
			name: "containsStaticChannels",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mvp := &MvlanProfile{
				Groups: grp,
			}
			switch tt.name {
			case "isChannelStatic", "isChannelStatic_false":
				if got := mvp.isChannelStatic(tt.args.channel); got != tt.want {
					t.Errorf("MvlanProfile.isChannelStatic() = %v, want %v", got, tt.want)
				}

			case "containsStaticChannels":
				if got := mvp.containsStaticChannels(); got != tt.want {
					t.Errorf("MvlanProfile.isChannelStatic() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestMvlanProfile_getAllStaticChannels(t *testing.T) {
	grp := make(map[string]*MvlanGroup)
	grp["test_key"] = &MvlanGroup{
		Name:     "test_key",
		IsStatic: true,
		McIPs: []string{
			"224.0.0.1",
		},
	}
	tests := []struct {
		name  string
		want  []net.IP
		want1 bool
	}{
		{
			name: "getAllStaticChannels",
			want: []net.IP{
				AllSystemsMulticastGroupIP,
			},
			want1: true,
		},
		{
			name: "getAllOldGroupStaticChannels",
			want: []net.IP{
				AllSystemsMulticastGroupIP,
			},
			want1: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mvp := &MvlanProfile{
				Groups:    grp,
				oldGroups: grp,
			}
			switch tt.name {
			case "getAllStaticChannels":
				got, got1 := mvp.getAllStaticChannels()
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("MvlanProfile.getAllStaticChannels() got = %v, want %v", got, tt.want)
				}
				if got1 != tt.want1 {
					t.Errorf("MvlanProfile.getAllStaticChannels() got1 = %v, want %v", got1, tt.want1)
				}
			case "getAllOldGroupStaticChannels":
				got, got1 := mvp.getAllOldGroupStaticChannels()
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("MvlanProfile.getAllStaticChannels() got = %v, want %v", got, tt.want)
				}
				if got1 != tt.want1 {
					t.Errorf("MvlanProfile.getAllStaticChannels() got1 = %v, want %v", got1, tt.want1)
				}
			}
		})
	}
}

func TestMvlanProfile_DelFlows(t *testing.T) {
	type args struct {
		cntx   context.Context
		device *VoltDevice
		flow   *of.VoltFlow
	}
	appMock := mocks.NewMockApp(gomock.NewController(t))
	controller.NewController(ctx, appMock)
	pendingDeleteFlow := map[string]map[string]bool{}
	delFlow := map[string]bool{}
	delFlow["SDX6320031"] = true
	pendingDeleteFlow["SDX6320031"] = delFlow
	voltDev := &VoltDevice{
		Name:            "SDX6320031",
		SerialNum:       "SDX6320031",
		FlowDelEventMap: util.NewConcurrentMap(),
	}
	subFlows := map[uint64]*of.VoltSubFlow{}
	vltSubFlow := &of.VoltSubFlow{
		Cookie: 103112802816,
		State:  of.FlowAddSuccess,
	}
	subFlows[0] = vltSubFlow
	flow := &of.VoltFlow{
		PortName: "SDX6320031-1",
		SubFlows: subFlows,
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "getAllStaticChannels",
			args: args{
				cntx:   context.Background(),
				device: voltDev,
				flow:   flow,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mvp := &MvlanProfile{
				PendingDeleteFlow: pendingDeleteFlow,
			}
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutMvlan(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			if err := mvp.DelFlows(tt.args.cntx, tt.args.device, tt.args.flow); (err != nil) != tt.wantErr {
				t.Errorf("MvlanProfile.DelFlows() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMvlanProfile_generateGroupKey(t *testing.T) {
	type args struct {
		name   string
		ipAddr string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "generateGroupKey",
			args: args{
				name:   "test-key",
				ipAddr: "0.0.0.0",
			},
			want: "0_test-key",
		},
		{
			name: "generateGroupKey_IsChannelBasedGroup",
			args: args{
				name:   "test-key",
				ipAddr: "0.0.0.0",
			},
			want: "0_0.0.0.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mvp := &MvlanProfile{}
			switch tt.name {
			case "generateGroupKey":
				if got := mvp.generateGroupKey(tt.args.name, tt.args.ipAddr); got != tt.want {
					t.Errorf("MvlanProfile.generateGroupKey() = %v, want %v", got, tt.want)
				}
			case "generateGroupKey_IsChannelBasedGroup":
				mvp.IsChannelBasedGroup = true
				if got := mvp.generateGroupKey(tt.args.name, tt.args.ipAddr); got != tt.want {
					t.Errorf("MvlanProfile.generateGroupKey() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestMvlanProfile_GetStaticGroupName(t *testing.T) {
	type args struct {
		gip net.IP
	}
	grp := make(map[string]*MvlanGroup)
	grp["test_key"] = &MvlanGroup{
		Name:     "test_key",
		IsStatic: true,
		McIPs: []string{
			"224.0.0.1",
		},
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "GetStaticGroupName",
			args: args{
				gip: AllSystemsMulticastGroupIP,
			},
			want: "test_key",
		},
		{
			name: "GetStaticGroupName",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mvp := &MvlanProfile{
				Groups: grp,
			}
			if got := mvp.GetStaticGroupName(tt.args.gip); got != tt.want {
				t.Errorf("MvlanProfile.GetStaticGroupName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMvlanProfile_pushIgmpMcastFlows(t *testing.T) {
	type args struct {
		cntx         context.Context
		OLTSerialNum string
	}
	grp := make(map[string]*MvlanGroup)
	grp["test_key"] = &MvlanGroup{
		Name:     "test_key",
		IsStatic: true,
		McIPs: []string{
			"224.0.0.1",
		},
	}
	devicesList := make(map[string]OperInProgress)
	devicesList["SDX6320031"] = opt82
	va := GetApplication()
	d := &VoltDevice{
		Name:      "SDX6320031",
		SerialNum: "SDX6320031",
		Ports:     sync.Map{},
		NniPort:   "16777472",
	}
	voltPort := &VoltPort{
		Name:                     "16777472",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateUp,
		ChannelPerSubAlarmRaised: false,
		Type:                     VoltPortTypeNni,
	}
	d.Ports.Store("16777472", voltPort)
	va.DevicesDisc.Store("SDX6320031", d)
	mvp := &MvlanProfile{
		Name: "mvlan_test",
	}
	va.MvlanProfilesByTag.Store(of.VlanAny, mvp)
	tests := []struct {
		name string
		args args
	}{
		{
			name: "GetStaticGroupName",
			args: args{
				cntx:         context.Background(),
				OLTSerialNum: "SDX6320031",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mvp := &MvlanProfile{
				DevicesList: devicesList,
				Groups:      grp,
				Mvlan:       of.VlanAny,
			}
			mvp.pushIgmpMcastFlows(tt.args.cntx, tt.args.OLTSerialNum)
		})
	}
}

func TestMvlanProfile_updateStaticGroups(t *testing.T) {
	type args struct {
		cntx     context.Context
		deviceID string
		added    []net.IP
		removed  []net.IP
	}
	devicesList := make(map[string]OperInProgress)
	devicesList["SDX6320031"] = opt82
	va := GetApplication()
	d := &VoltDevice{
		Name:            "SDX6320031",
		SerialNum:       "SDX6320031",
		Ports:           sync.Map{},
		NniPort:         "16777472",
		FlowDelEventMap: util.NewConcurrentMap(),
	}
	va.DevicesDisc.Store("SDX6320031", d)
	tests := []struct {
		name string
		args args
	}{
		{
			name: "updateStaticGroups",
			args: args{
				cntx:     context.Background(),
				deviceID: "SDX6320031",
				added:    []net.IP{AllSystemsMulticastGroupIP},
				removed:  []net.IP{AllSystemsMulticastGroupIP},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mvp := &MvlanProfile{
				Name:        "mvlan_test",
				DevicesList: devicesList,
				Mvlan:       of.VlanAny,
			}
			va.MvlanProfilesByTag.Store(of.VlanAny, mvp)
			va.MvlanProfilesByName.Store("mvlan_test", mvp)
			mvp.updateStaticGroups(tt.args.cntx, tt.args.deviceID, tt.args.added, tt.args.removed)
		})
	}
}
func TestMvlanProfile_updateDynamicGroups(t *testing.T) {
	type args struct {
		cntx     context.Context
		deviceID string
		added    []net.IP
		removed  []net.IP
	}
	grp := make(map[string]*MvlanGroup)
	grp["test_key"] = &MvlanGroup{
		Name:     "test_key",
		IsStatic: true,
		McIPs: []string{
			"224.0.0.1",
		},
	}
	devicesList := make(map[string]OperInProgress)
	devicesList["SDX6320031"] = opt82
	va := GetApplication()
	d := &VoltDevice{
		Name:            "SDX6320031",
		SerialNum:       "SDX6320031",
		Ports:           sync.Map{},
		NniPort:         "16777472",
		FlowDelEventMap: util.NewConcurrentMap(),
	}
	va.DevicesDisc.Store("SDX6320031", d)
	devices := map[string]*IgmpGroupDevice{}
	igmpDevice := &IgmpGroupDevice{
		Device:        "SDX6320031",
		SerialNo:      "SDX6320031",
		GroupName:     "4096_test_key",
		Mvlan:         of.VlanAny,
		GroupChannels: sync.Map{},
		GroupAddr:     AllSystemsMulticastGroupIP,
	}
	devices["SDX6320031"] = igmpDevice
	group := &IgmpGroup{
		GroupName: "4096_test_key",
		GroupID:   uint32(256),
		Mvlan:     of.VlanAny,
		Devices:   devices,
	}
	va.IgmpGroups.Store("4096_test_key", group)
	newReceivers := map[string]*IgmpGroupPort{}
	igp := &IgmpGroupPort{
		Port: "16777470",
	}
	newReceivers["16777472"] = igp
	b := IgmpVersion2
	igmpChanel := &IgmpGroupChannel{
		GroupAddr:    AllSystemsMulticastGroupIP,
		GroupName:    "test_key",
		NewReceivers: newReceivers,
		Version:      IgmpVersion2,
		ServVersion:  &b,
	}
	igmpDevice.GroupChannels.Store(AllSystemsMulticastGroupIP.String(), igmpChanel)
	proxy := map[string]*MCGroupProxy{}
	mgGroupProxy := &MCGroupProxy{
		Mode: common.Include,
		SourceList: []net.IP{
			AllSystemsMulticastGroupIP,
		},
	}
	proxy[igmpChanel.GroupName] = mgGroupProxy
	tests := []struct {
		name string
		args args
	}{
		{
			name: "updateDynamicGroups",
			args: args{
				cntx:     context.Background(),
				deviceID: "SDX6320031",
				added:    []net.IP{AllSystemsMulticastGroupIP},
				removed:  []net.IP{AllSystemsMulticastGroupIP},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mvp := &MvlanProfile{
				Name:        "test_key",
				DevicesList: devicesList,
				Mvlan:       of.VlanAny,
				Groups:      grp,
				Proxy:       proxy,
			}
			va.MvlanProfilesByTag.Store(of.VlanAny, mvp)
			va.MvlanProfilesByName.Store("test_key", mvp)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutIgmpRcvr(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			dbintf.EXPECT().PutIgmpChannel(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			mvp.updateDynamicGroups(tt.args.cntx, tt.args.deviceID, tt.args.added, tt.args.removed)
		})
	}
}

func TestMvlanProfile_checkStaticGrpSSMProxyDiff(t *testing.T) {
	type args struct {
		oldProxy *MCGroupProxy
		newProxy *MCGroupProxy
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "updateDynamicGroups",
			args: args{
				oldProxy: &MCGroupProxy{
					Mode: common.Exclude,
					SourceList: []net.IP{
						AllSystemsMulticastGroupIP,
					},
				},
				newProxy: &MCGroupProxy{
					Mode: common.Exclude,
					SourceList: []net.IP{
						AllSystemsMulticastGroupIP,
					},
				},
			},
		},
		{
			name: "updateDynamicGroups_true",
			args: args{
				newProxy: &MCGroupProxy{},
			},
			want: true,
		},
		{
			name: "updateDynamicGroups_nil",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mvp := &MvlanProfile{}
			if got := mvp.checkStaticGrpSSMProxyDiff(tt.args.oldProxy, tt.args.newProxy); got != tt.want {
				t.Errorf("MvlanProfile.checkStaticGrpSSMProxyDiff() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMvlanProfile_UpdateActiveChannelSubscriberAlarm(t *testing.T) {
	devicesList := make(map[string]OperInProgress)
	devicesList["SDX6320031"] = opt82
	voltDev := &VoltDevice{
		Name:            "SDX6320031",
		SerialNum:       "SDX6320031",
		FlowDelEventMap: util.NewConcurrentMap(),
		Ports:           sync.Map{},
	}
	va := GetApplication()
	va.DevicesDisc.Store("SDX6320031", voltDev)
	voltPort := &VoltPort{
		Name:                     "16777472",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateUp,
		ChannelPerSubAlarmRaised: true,
		Type:                     VoltPortTypeAccess,
		ActiveChannels:           uint32(2),
	}
	voltDev.Ports.Store("16777472", voltPort)
	tests := []struct {
		name string
	}{
		{
			name: "UpdateActiveChannelSubscriberAlarm",
		},
		{
			name: "UpdateActiveChannelSubscriberAlarm_else",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mvp := &MvlanProfile{
				DevicesList:       devicesList,
				MaxActiveChannels: uint32(5),
			}
			switch tt.name {
			case "UpdateActiveChannelSubscriberAlarm":
				mvp.UpdateActiveChannelSubscriberAlarm()
			case "UpdateActiveChannelSubscriberAlarm_else":
				voltPort.ActiveChannels = uint32(6)
				voltPort.ChannelPerSubAlarmRaised = false
				mvp.UpdateActiveChannelSubscriberAlarm()
			}
		})
	}
}
