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
	"encoding/json"
	"net"
	"reflect"
	"sync"
	"testing"
	"voltha-go-controller/internal/pkg/controller"
	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/internal/test/mocks"

	"go.uber.org/mock/gomock"
	"github.com/google/gopacket/layers"
	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
	"github.com/stretchr/testify/assert"
	"go.uber.org/atomic"
)

const deviceName = "SDX6320031"

func TestVoltPortVnet_JSONMarshal(t *testing.T) {
	tests := []struct {
		name    string
		want    []byte
		wantErr bool
	}{
		{
			name: "VoltPortVnet_JSONMarshal",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{}
			_, err := vpv.JSONMarshal()
			if (err != nil) != tt.wantErr {
				t.Errorf("VoltPortVnet.JSONMarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestVoltPortVnet_IsServiceActivated(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "VoltPortVnet_IsServiceActivated",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{}
			voltServ := &VoltService{
				VoltServiceOper: VoltServiceOper{
					Device:      test_device,
					ForceDelete: true,
				},
			}
			vpv.services.Store(test_device, voltServ)
			if got, _ := vpv.IsServiceActivated(tt.args.cntx); got != tt.want {
				t.Errorf("VoltPortVnet.IsServiceActivated() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltVnet_JSONMarshal(t *testing.T) {
	tests := []struct {
		name    string
		want    []byte
		wantErr bool
	}{
		{
			name: "VoltVnet_JSONMarshal",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vv := &VoltVnet{}
			_, err := vv.JSONMarshal()
			if (err != nil) != tt.wantErr {
				t.Errorf("VoltVnet.JSONMarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestVoltVnet_TriggerAssociatedFlowDelete(t *testing.T) {
	type args struct {
		cntx   context.Context
		device string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "VoltVnet_TriggerAssociatedFlowDelete",
			args: args{
				cntx:   context.Background(),
				device: test_device,
			},
			want: true,
		},
		{
			name: "cookieList_empty",
			args: args{
				cntx:   context.Background(),
				device: test_device,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vv := &VoltVnet{}
			switch tt.name {
			case "VoltVnet_TriggerAssociatedFlowDelete":
				cookie := map[string]bool{}
				cookie["1234"] = true
				pendingDeleteFlow := map[string]map[string]bool{}
				pendingDeleteFlow[test_device] = cookie
				vv.PendingDeleteFlow = pendingDeleteFlow
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutVnet(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				if got := vv.TriggerAssociatedFlowDelete(tt.args.cntx, tt.args.device); got != tt.want {
					t.Errorf("VoltVnet.TriggerAssociatedFlowDelete() = %v, want %v", got, tt.want)
				}
			case "cookieList_empty":
				if got := vv.TriggerAssociatedFlowDelete(tt.args.cntx, tt.args.device); got != tt.want {
					t.Errorf("VoltVnet.TriggerAssociatedFlowDelete() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVoltApplication_GetMatchingMcastService(t *testing.T) {
	type args struct {
		port   string
		device string
		cvlan  of.VlanType
	}
	tests := []struct {
		name string
		args args
		want *VoltService
	}{
		{
			name: "VoltApplication_GetMatchingMcastService",
			args: args{
				port:   "test_port",
				device: test_device,
				cvlan:  of.VlanAny,
			},
		},
		{
			name: "dIntf_error",
			args: args{
				port:   "test_port",
				device: test_device,
				cvlan:  of.VlanAny,
			},
		},
		{
			name: "port == d.NniPort",
			args: args{
				port:   "test_port",
				device: test_device,
				cvlan:  of.VlanAny,
			},
		},
		{
			name: "vnets_error",
			args: args{
				port:   "",
				device: test_device,
				cvlan:  of.VlanAny,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			switch tt.name {
			case "VoltApplication_GetMatchingMcastService":
				va.DevicesDisc.Store(test_device, voltDevice)
				va.VnetsByPort.Store("test_port", voltPortVnet1)
				if got := va.GetMatchingMcastService(tt.args.port, tt.args.device, tt.args.cvlan); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltApplication.GetMatchingMcastService() = %v, want %v", got, tt.want)
				}
			case "dIntf_error":
				if got := va.GetMatchingMcastService(tt.args.port, tt.args.device, tt.args.cvlan); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltApplication.GetMatchingMcastService() = %v, want %v", got, tt.want)
				}
			case "port == d.NniPort":
				va.DevicesDisc.Store(test_device, voltDevice)
				voltDevice.NniPort = []string{"test_port"}
				if got := va.GetMatchingMcastService(tt.args.port, tt.args.device, tt.args.cvlan); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltApplication.GetMatchingMcastService() = %v, want %v", got, tt.want)
				}
			case "vnets_error":
				va.DevicesDisc.Store(test_device, voltDevice)
				va.VnetsByPort.Store("test_port1", voltPortVnet1)
				if got := va.GetMatchingMcastService(tt.args.port, tt.args.device, tt.args.cvlan); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltApplication.GetMatchingMcastService() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVoltPortVnet_IgmpFlowInstallFailure(t *testing.T) {
	type args struct {
		cookie    string
		errorCode uint32
		errReason string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltPortVnet_IgmpFlowInstallFailure",
			args: args{
				cookie:    "test_cookie",
				errorCode: uint32(1),
				errReason: "errReason",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{}
			switch tt.name {
			case "VoltPortVnet_IgmpFlowInstallFailure":
				voltService.IgmpEnabled = true
				vpv.services.Store("test_cookie", voltService)
				vpv.IgmpFlowInstallFailure(tt.args.cookie, tt.args.errorCode, tt.args.errReason)
			}
		})
	}
}

func TestVoltVnet_FlowRemoveFailure(t *testing.T) {
	type args struct {
		cntx      context.Context
		cookie    string
		device    string
		errorCode uint32
		errReason string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltVnet_FlowRemoveFailure",
			args: args{
				cntx:   context.Background(),
				cookie: "1234",
				device: test_device,
			},
		},
		{
			name: "mismatch_cookie",
			args: args{
				cntx:   context.Background(),
				cookie: "1234",
				device: test_device,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vv := &VoltVnet{}
			switch tt.name {
			case "VoltVnet_FlowRemoveFailure":
				cookie := map[string]bool{}
				cookie["1234"] = true
				pendingDeleteFlow := map[string]map[string]bool{}
				pendingDeleteFlow[test_device] = cookie
				vv.PendingDeleteFlow = pendingDeleteFlow
				vv.DeleteInProgress = true
				vv.Name = "test_name"
				vv.VnetPortLock = sync.RWMutex{}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().DelVnet(tt.args.cntx, "test_name").Return(nil).AnyTimes()
				vv.FlowRemoveFailure(tt.args.cntx, tt.args.cookie, tt.args.device, tt.args.errorCode, tt.args.errReason)
			case "mismatch_cookie":
				cookie := map[string]bool{}
				cookie["12345"] = true
				pendingDeleteFlow := map[string]map[string]bool{}
				pendingDeleteFlow[test_device] = cookie
				vv.PendingDeleteFlow = pendingDeleteFlow
				vv.DeleteInProgress = true
				vv.Name = "test_name"
				vv.VnetPortLock = sync.RWMutex{}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().DelVnet(tt.args.cntx, "test_name").Return(nil).AnyTimes()
				vv.FlowRemoveFailure(tt.args.cntx, tt.args.cookie, tt.args.device, tt.args.errorCode, tt.args.errReason)
			}
		})
	}
}

func TestVoltVnet_FlowRemoveSuccess(t *testing.T) {
	type args struct {
		cntx   context.Context
		cookie string
		device string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltVnet_FlowRemoveSuccess",
			args: args{
				cntx:   context.Background(),
				cookie: "1234",
				device: test_device,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vv := &VoltVnet{}
			cookie := map[string]bool{}
			cookie["1234"] = true
			pendingDeleteFlow := map[string]map[string]bool{}
			pendingDeleteFlow[test_device] = cookie
			vv.PendingDeleteFlow = pendingDeleteFlow
			ga := GetApplication()
			voltDevice.ConfiguredVlanForDeviceFlows = util.NewConcurrentMap()
			ga.DevicesDisc.Store(test_device, voltDevice)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutVnet(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			vv.FlowRemoveSuccess(tt.args.cntx, tt.args.cookie, tt.args.device)
		})
	}
}

func TestVoltPortVnet_FlowRemoveFailure(t *testing.T) {
	type args struct {
		cntx      context.Context
		cookie    string
		device    string
		errorCode uint32
		errReason string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltPortVnet_FlowRemoveFailure",
			args: args{
				cntx:   context.Background(),
				cookie: "1234",
				device: test_device,
			},
		},
		{
			name: "DeleteInProgress_false",
			args: args{
				cntx:   context.Background(),
				cookie: "1234",
				device: test_device,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{}
			switch tt.name {
			case "VoltPortVnet_FlowRemoveFailure":
				vpv.services.Store("1234", voltService)
				vpv.DeleteInProgress = true
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().DelVpv(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				vpv.FlowRemoveFailure(tt.args.cntx, tt.args.cookie, tt.args.device, tt.args.errorCode, tt.args.errReason)
			case "DeleteInProgress_false":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutVpv(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				vpv.FlowRemoveFailure(tt.args.cntx, tt.args.cookie, tt.args.device, tt.args.errorCode, tt.args.errReason)
			}
		})
	}
}

func TestVoltPortVnet_PushFlows(t *testing.T) {
	type args struct {
		cntx   context.Context
		device *VoltDevice
		flow   *of.VoltFlow
	}
	vsf := make(map[uint64]*of.VoltSubFlow)
	vsf[uint64(1)] = &of.VoltSubFlow{
		Cookie: uint64(1234),
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "VoltPortVnet_PushFlows",
			args: args{
				cntx:   context.Background(),
				device: voltDevice,
				flow: &of.VoltFlow{
					PortName: "test_port",
					SubFlows: vsf,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{}
			_ = cntlr.NewController(context.Background(), mocks.NewMockApp(gomock.NewController(t)))
			err := vpv.PushFlows(tt.args.cntx, tt.args.device, tt.args.flow)
			assert.NotNil(t, err)
		})
	}
}

func TestVoltPortVnet_isVlanMatching(t *testing.T) {
	type args struct {
		cvlan of.VlanType
		svlan of.VlanType
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "VoltPortVnet_isVlanMatching",
			args: args{
				cvlan: of.VlanAny,
				svlan: of.VlanAny,
			},
			want: true,
		},
		{
			name: "vpv.VlanControl_nil",
			args: args{
				cvlan: of.VlanAny,
				svlan: of.VlanAny,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{}
			switch tt.name {
			case "VoltPortVnet_isVlanMatching":
				vpv.VlanControl = ONUCVlanOLTSVlan
				vpv.SVlan = of.VlanAny
				vpv.CVlan = of.VlanAny
				if got := vpv.isVlanMatching(tt.args.cvlan, tt.args.svlan); got != tt.want {
					t.Errorf("VoltPortVnet.isVlanMatching() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestProcessIcmpv6McGroup(t *testing.T) {
	type args struct {
		device string
		delete bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "TestProcessIcmpv6McGroup",
			args: args{
				device: test_device,
				delete: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ProcessIcmpv6McGroup(tt.args.device, tt.args.delete)
			assert.NotNil(t, err)
		})
	}
}

func TestVoltVnet_setPbitRemarking(t *testing.T) {
	tests := []struct {
		name string
		want uint32
	}{
		{
			name: "VoltVnet_setPbitRemarking",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vv := &VoltVnet{}
			a := make(map[of.PbitType]of.PbitType)
			a[of.PbitMatchAll] = of.PbitMatchAll
			vv.CtrlPktPbitRemark = a
			if got := vv.setPbitRemarking(); got != tt.want {
				t.Errorf("VoltVnet.setPbitRemarking() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildDSArpFlow(t *testing.T) {
	type args struct {
		inport uint32
		vnet   *VoltVnet
	}
	tests := []struct {
		name string
		args args
		want *of.VoltFlow
	}{
		{
			name: "BuildDSArpFlow",
			args: args{
				inport: uint32(1),
				vnet: &VoltVnet{
					Version: "test_version",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "BuildDSArpFlow":
				got := BuildDSArpFlow(tt.args.inport, tt.args.vnet)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestBuildICMPv6Flow(t *testing.T) {
	type args struct {
		inport uint32
		vnet   *VoltVnet
	}
	tests := []struct {
		name string
		args args
		want *of.VoltFlow
	}{
		{
			name: "BuildICMPv6Flow",
			args: args{
				inport: uint32(1),
				vnet: &VoltVnet{
					Version: "test_version",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildICMPv6Flow(tt.args.inport, tt.args.vnet)
			assert.NotNil(t, got)
		})
	}
}

func TestVoltApplication_DeleteDevFlowForVlanFromDevice(t *testing.T) {
	type args struct {
		cntx            context.Context
		vnet            *VoltVnet
		deviceSerialNum string
	}
	voltDev := &VoltDevice{
		Name:                         "SDX6320031",
		SerialNum:                    "SDX6320031",
		NniDhcpTrapVid:               123,
		State:                        cntlr.DeviceStateUP,
		NniPort:                      []string{"16777472"},
		Ports:                        sync.Map{},
		FlowDelEventMap:              util.NewConcurrentMap(),
		ConfiguredVlanForDeviceFlows: util.NewConcurrentMap(),
	}
	voltVnet = &VoltVnet{
		Version: "v3",
		VnetConfig: VnetConfig{
			Name:     "2310-4096-4096",
			VnetType: "Encapsulation",
		},
		VnetOper: VnetOper{
			PendingDeviceToDelete: "SDX6320031",
			DeleteInProgress:      true,
			PendingDeleteFlow:     make(map[string]map[string]bool),
		},
	}
	voltPort := &VoltPort{
		Name:                     "16777472",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateUp,
		ChannelPerSubAlarmRaised: false,
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "device.SerialNum != deviceSerialNum",
			args: args{
				cntx: context.Background(),
				vnet: voltVnet,
			},
		},
		{
			name: "DeleteDevFlowForVlanFromDevice",
			args: args{
				cntx:            context.Background(),
				deviceSerialNum: "SDX6320031",
				vnet:            voltVnet,
			},
		},
		{
			name: "DeleteDevFlowForVlanFromDevice_PortStateDown",
			args: args{
				cntx:            context.Background(),
				deviceSerialNum: "SDX6320031",
				vnet:            voltVnet,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
			}
			switch tt.name {
			case "device.SerialNum != deviceSerialNum":
				va.DevicesDisc.Store(test_device, voltDevice)
				va.DeleteDevFlowForVlanFromDevice(tt.args.cntx, tt.args.vnet, tt.args.deviceSerialNum)
			case "DeleteDevFlowForVlanFromDevice":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				va.VnetsByName.Store("2310-4096-4096", voltVnet)
				voltDev.ConfiguredVlanForDeviceFlows.Set("0-0-0", util.NewConcurrentMap())
				va.PortsDisc.Store("16777472", voltPort)
				appMock := mocks.NewMockApp(gomock.NewController(t))
				cntlr.NewController(ctx, appMock)
				vc := cntlr.GetController()
				portsByName := map[string]*cntlr.DevicePort{}
				portsByName["16777472"] = &cntlr.DevicePort{
					Name:  "16777472",
					ID:    256,
					State: cntlr.PortStateUp,
				}
				device := &cntlr.Device{
					ID:          "SDX6320031",
					PortsByName: portsByName,
				}
				vc.Devices.Store("SDX6320031", device)
				va.DeleteDevFlowForVlanFromDevice(tt.args.cntx, tt.args.vnet, tt.args.deviceSerialNum)
			case "DeleteDevFlowForVlanFromDevice_PortStateDown":
				voltDev.Name = ""
				va.DevicesDisc.Store("SDX6320031", voltDev)
				va.VnetsByName.Store("2310-4096-4096", voltVnet)
				voltDev.ConfiguredVlanForDeviceFlows.Set("0-0-0", util.NewConcurrentMap())
				va.PortsDisc.Store("16777472", voltPort)
				appMock := mocks.NewMockApp(gomock.NewController(t))
				cntlr.NewController(ctx, appMock)
				vc := cntlr.GetController()
				portsByName := map[string]*cntlr.DevicePort{}
				portsByName["16777472"] = &cntlr.DevicePort{
					Name:  "16777472",
					ID:    256,
					State: cntlr.PortStateUp,
				}
				device := &cntlr.Device{
					ID:          "SDX6320031",
					PortsByName: portsByName,
				}
				vc.Devices.Store("SDX6320031", device)
				va.DeleteDevFlowForVlanFromDevice(tt.args.cntx, tt.args.vnet, tt.args.deviceSerialNum)
			}
		})
	}
}

func TestVoltApplication_RestoreVnetsFromDb(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_RestoreVnetsFromDb",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vnetsToDelete := map[string]bool{}
			vnetsToDelete["test_name"] = true
			va := &VoltApplication{
				VnetsBySvlan:  util.NewConcurrentMap(),
				VnetsToDelete: vnetsToDelete,
			}
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			vnets := map[string]*kvstore.KVPair{}
			voltVnet.SVlan = of.VlanAny
			b, err := json.Marshal(voltVnet)
			if err != nil {
				panic(err)
			}
			vnets["test_device_id"] = &kvstore.KVPair{
				Key:   "test_device_id",
				Value: b,
			}
			dbintf.EXPECT().PutVnet(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			dbintf.EXPECT().GetVnets(tt.args.cntx).Return(vnets, nil)
			va.RestoreVnetsFromDb(tt.args.cntx)
		})
	}
}

func TestVoltApplication_DeleteDevFlowForDevice(t *testing.T) {
	type args struct {
		cntx   context.Context
		device *VoltDevice
	}
	voltDev := &VoltDevice{
		Name:                         "SDX6320031",
		SerialNum:                    "SDX6320031",
		NniDhcpTrapVid:               123,
		State:                        cntlr.DeviceStateUP,
		NniPort:                      []string{"16777472"},
		FlowDelEventMap:              util.NewConcurrentMap(),
		ConfiguredVlanForDeviceFlows: util.NewConcurrentMap(),
		icmpv6GroupAdded:             true,
	}
	voltVnet = &VoltVnet{
		Version: "v3",
		VnetConfig: VnetConfig{
			Name:     "2310-4096-4096",
			VnetType: "Encapsulation",
		},
		VnetOper: VnetOper{
			PendingDeviceToDelete: "SDX6320031",
			DeleteInProgress:      true,
			PendingDeleteFlow:     make(map[string]map[string]bool),
		},
	}
	voltPort := &VoltPort{
		Name:                     "16777472",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateUp,
		ChannelPerSubAlarmRaised: false,
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "DeleteDevFlowForDevice",
			args: args{
				cntx:   context.Background(),
				device: voltDev,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			switch tt.name {
			case "DeleteDevFlowForDevice":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				va.VnetsByName.Store("2310-4096-4096", voltVnet)
				voltDev.ConfiguredVlanForDeviceFlows.Set("0-0-0", util.NewConcurrentMap())
				va.PortsDisc.Store("16777472", voltPort)
				voltApp := GetApplication()
				voltApp.DevicesDisc.Store("SDX6320031", voltDev)
				appMock := mocks.NewMockApp(gomock.NewController(t))
				cntlr.NewController(ctx, appMock)
				vc := cntlr.GetController()
				portsByName := map[string]*cntlr.DevicePort{}
				portsByName["16777472"] = &cntlr.DevicePort{
					Name:  "16777472",
					ID:    256,
					State: cntlr.PortStateUp,
				}
				device := &cntlr.Device{
					ID:          "SDX6320031",
					PortsByName: portsByName,
				}
				vc.Devices.Store("SDX6320031", device)
				va.DeleteDevFlowForDevice(tt.args.cntx, tt.args.device)
			}
		})
	}
}

func TestVoltApplication_DelVnetFromPort(t *testing.T) {
	macAdd, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	vpv_test := []*VoltPortVnet{
		{
			Device:   test_device,
			Port:     "test_port",
			MacAddr:  macAdd,
			VnetName: "test_vnet_name",
		},
	}
	type args struct {
		cntx context.Context
		port string
		vpv  *VoltPortVnet
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_DelVnetFromPort",
			args: args{
				cntx: context.Background(),
				port: "test_port",
				vpv: &VoltPortVnet{
					Device:   test_device,
					Port:     "test_port",
					MacAddr:  macAdd,
					VnetName: "test_vnet_name",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			va.VnetsByPort.Store("test_port", vpv_test)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutVpv(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			dbintf.EXPECT().DelVpv(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			va.VnetsByName.Store("test_vnet_name", &VoltVnet{
				Version: "test_version",
			})
			va.DelVnetFromPort(tt.args.cntx, tt.args.port, tt.args.vpv)
		})
	}
}

func TestVoltApplication_PushDevFlowForVlan(t *testing.T) {
	type args struct {
		cntx context.Context
		vnet *VoltVnet
	}
	voltDev := &VoltDevice{
		Name:                         "SDX6320031",
		SerialNum:                    "SDX6320031",
		NniDhcpTrapVid:               123,
		State:                        cntlr.DeviceStateUP,
		NniPort:                      []string{"16777472"},
		FlowDelEventMap:              util.NewConcurrentMap(),
		ConfiguredVlanForDeviceFlows: util.NewConcurrentMap(),
		icmpv6GroupAdded:             true,
		VlanPortStatus:               sync.Map{},
	}
	voltVnet := &VoltVnet{
		Version: "v3",
		VnetConfig: VnetConfig{
			Name:        "2310-4096-4096",
			VnetType:    "Encapsulation",
			DevicesList: []string{"SDX6320031"},
			SVlan:       0,
		},
		VnetOper: VnetOper{
			PendingDeviceToDelete: "SDX6320031",
			DeleteInProgress:      true,
			PendingDeleteFlow:     make(map[string]map[string]bool),
		},
	}
	voltPort := &VoltPort{
		Name:                     "16777216",
		Device:                   "SDX6320031",
		ID:                       16777216,
		State:                    PortStateUp,
		ChannelPerSubAlarmRaised: false,
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_PushDevFlowForVlan",
			args: args{
				cntx: context.Background(),
				vnet: &VoltVnet{
					Version: "test_version",
					VnetConfig: VnetConfig{
						DevicesList: []string{"test_serialNum"},
						SVlan:       of.VlanAny,
					},
				},
			},
		},
		// {
		// 	name: "PushDevFlowForVlan",
		// 	args: args{
		// 		cntx: context.Background(),
		// 		vnet: voltVnet,
		// 	},
		// },
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			switch tt.name {
			case "VoltApplication_PushDevFlowForVlan":
				voltDevice.SerialNum = "test_serialNum"
				voltDevice.VlanPortStatus.Store(uint16(of.VlanAny), true)
				voltDevice.Name = test_device
				va.DevicesDisc.Store(test_device, voltDevice)
				va.PortsDisc.Store("16777216", voltPort)
				ga := GetApplication()
				ga.DevicesDisc.Store(test_device, voltDevice)
				_ = cntlr.NewController(context.Background(), mocks.NewMockApp(gomock.NewController(t)))
				va.PushDevFlowForVlan(tt.args.cntx, tt.args.vnet)
			case "PushDevFlowForVlan":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				voltDevice.VlanPortStatus.Store(uint16(0), true)
				va.VnetsByName.Store("2310-4096-4096", voltVnet)
				voltDev.ConfiguredVlanForDeviceFlows.Set("0-0-0", util.NewConcurrentMap())
				va.PortsDisc.Store("16777472", voltPort)
				voltApp := GetApplication()
				voltApp.DevicesDisc.Store("SDX6320031", voltDev)
				_ = cntlr.NewController(context.Background(), mocks.NewMockApp(gomock.NewController(t)))
				va.PushDevFlowForVlan(tt.args.cntx, tt.args.vnet)
			}
		})
	}
}

func TestVoltApplication_PushDevFlowForDevice(t *testing.T) {
	type args struct {
		cntx   context.Context
		device *VoltDevice
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "device.ConfiguredVlanForDeviceFlows is ok",
			args: args{
				cntx: context.Background(),
				device: &VoltDevice{
					Name:                         test_device,
					ConfiguredVlanForDeviceFlows: util.NewConcurrentMap(),
				},
			},
		},
		{
			name: "device.VlanPortStatus is false",
			args: args{
				cntx: context.Background(),
				device: &VoltDevice{
					Name:                         test_device,
					ConfiguredVlanForDeviceFlows: util.NewConcurrentMap(),
					NniPort:                      []string{"test_nni_port"},
				},
			},
		},
		{
			name: "device.VlanPortStatus is true",
			args: args{
				cntx: context.Background(),
				device: &VoltDevice{
					Name:                         test_device,
					ConfiguredVlanForDeviceFlows: util.NewConcurrentMap(),
					NniPort:                      []string{"test_nni_port"},
					VlanPortStatus:               sync.Map{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			switch tt.name {
			case "device.ConfiguredVlanForDeviceFlows is ok":
				va.VnetsByName.Store("test_vnet_name", &VoltVnet{
					Version: "test_version",
				})
				tt.args.device.ConfiguredVlanForDeviceFlows.Set("0-0-0", util.NewConcurrentMap())
				va.PushDevFlowForDevice(tt.args.cntx, tt.args.device)
			case "device.VlanPortStatus is false":
				va.VnetsByName.Store("test_vnet_name", &VoltVnet{
					Version: "test_version",
				})
				va.PortsDisc.Store("test_nni_port", &VoltPort{
					Name: "test_name",
				})
				va.PushDevFlowForDevice(tt.args.cntx, tt.args.device)
			case "device.VlanPortStatus is true":
				va.VnetsByName.Store("test_vnet_name", &VoltVnet{
					Version: "test_version",
					VnetConfig: VnetConfig{
						SVlan: of.VlanAny,
					},
				})
				va.PortsDisc.Store("test_nni_port", &VoltPort{
					Name: "test_name",
				})
				tt.args.device.VlanPortStatus.Store(uint16(of.VlanAny), true)
				va.PushDevFlowForDevice(tt.args.cntx, tt.args.device)
			}
		})
	}
}

func TestNewVoltPortVnet(t *testing.T) {
	type args struct {
		vnet *VoltVnet
	}
	usDhcpPbit := []of.PbitType{}
	usDhcpPbit = append(usDhcpPbit, PbitMatchNone)
	tests := []struct {
		name string
		args args
		want *VoltPortVnet
	}{
		{
			name: "NewVoltPortVnet",
			args: args{
				vnet: &VoltVnet{
					VnetConfig: VnetConfig{
						UsDhcpPbit: usDhcpPbit,
					},
				},
			},
			want: &VoltPortVnet{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewVoltPortVnet(tt.args.vnet)
			assert.NotNil(t, got)
		})
	}
}

func TestVoltPortVnet_GetCircuitID(t *testing.T) {
	vpv := &VoltPortVnet{}
	got := vpv.GetCircuitID()
	assert.Nil(t, got)
	got1 := vpv.GetRemoteID()
	assert.Nil(t, got1)
	got3 := vpv.GetDhcpState()
	assert.NotNil(t, got3)
	got4 := vpv.GetPppoeIaState()
	assert.NotNil(t, got4)
	got5 := vpv.GetDhcpv6State()
	assert.NotNil(t, got5)
}

func TestVoltPortVnet_GetNniVlans(t *testing.T) {
	tests := []struct {
		name  string
		want  uint16
		want1 uint16
	}{
		{
			name:  "GetNniVlans",
			want:  uint16(of.VlanAny),
			want1: uint16(of.VlanAny),
		},
		{
			name:  "GetNniVlans_OLTSVlan",
			want:  uint16(of.VlanAny),
			want1: uint16(of.VlanNone),
		},
		{
			name:  "GetNniVlans_Default",
			want:  uint16(of.VlanNone),
			want1: uint16(of.VlanNone),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				VlanControl: ONUCVlanOLTSVlan,
				SVlan:       of.VlanAny,
				CVlan:       of.VlanAny,
			}
			switch tt.name {
			case "GetNniVlans":
				got, got1 := vpv.GetNniVlans()
				if got != tt.want {
					t.Errorf("VoltPortVnet.GetNniVlans() got = %v, want %v", got, tt.want)
				}
				if got1 != tt.want1 {
					t.Errorf("VoltPortVnet.GetNniVlans() got1 = %v, want %v", got1, tt.want1)
				}
			case "GetNniVlans_OLTSVlan":
				vpv.VlanControl = OLTSVlan
				got, got1 := vpv.GetNniVlans()
				if got != tt.want {
					t.Errorf("VoltPortVnet.GetNniVlans() got = %v, want %v", got, tt.want)
				}
				if got1 != tt.want1 {
					t.Errorf("VoltPortVnet.GetNniVlans() got1 = %v, want %v", got1, tt.want1)
				}
			case "GetNniVlans_Default":
				vpv.VlanControl = opt82
				got, got1 := vpv.GetNniVlans()
				if got != tt.want {
					t.Errorf("VoltPortVnet.GetNniVlans() got = %v, want %v", got, tt.want)
				}
				if got1 != tt.want1 {
					t.Errorf("VoltPortVnet.GetNniVlans() got1 = %v, want %v", got1, tt.want1)
				}
			}
		})
	}
}

func TestVoltPortVnet_GetService(t *testing.T) {
	type args struct {
		name string
	}
	voltServ := &VoltService{
		VoltServiceOper: VoltServiceOper{
			Device: "SDX6320031",
		},
		VoltServiceCfg: VoltServiceCfg{
			IsActivated: true,
		},
	}
	tests := []struct {
		name  string
		args  args
		want  *VoltService
		want1 bool
	}{
		{
			name: "GetService",
			args: args{
				name: "SDX6320031-1_SDX6320031-1-4096-2310-4096-65",
			},
			want:  voltServ,
			want1: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{}
			vpv.services.Store("SDX6320031-1_SDX6320031-1-4096-2310-4096-65", voltServ)
			got, got1 := vpv.GetService(tt.args.name)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VoltPortVnet.GetService() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("VoltPortVnet.GetService() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestVoltPortVnet_ProcessDhcpSuccess(t *testing.T) {
	type args struct {
		cntx context.Context
		res  *layers.DHCPv4
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "ProcessDhcpSuccess",
			args: args{
				cntx: context.Background(),
				res:  &layers.DHCPv4{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				servicesCount: atomic.NewUint64(0),
			}
			vpv.ProcessDhcpSuccess(tt.args.cntx, tt.args.res)
		})
	}
}

func TestVoltPortVnet_ProcessDhcpResult(t *testing.T) {
	type args struct {
		cntx context.Context
		res  *layers.DHCPv4
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "ProcessDhcpResult",
			args: args{
				cntx: context.Background(),
				res:  &layers.DHCPv4{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{}
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutVpv(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			vpv.ProcessDhcpResult(tt.args.cntx, tt.args.res)
		})
	}
}

func TestVoltVnet_associatePortToVnet(t *testing.T) {
	type args struct {
		port string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "ProcessDhcpResult",
			args: args{
				port: "SDX6320031-1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vv := &VoltVnet{}
			vv.associatePortToVnet(tt.args.port)
		})
	}
}

func TestVoltPortVnet_ProcessDhcpv6Result(t *testing.T) {
	type args struct {
		cntx      context.Context
		ipv6Addr  net.IP
		leaseTime uint32
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "ProcessDhcpResult",
			args: args{
				cntx:      context.Background(),
				ipv6Addr:  AllSystemsMulticastGroupIP,
				leaseTime: uint32(128),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{}
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutVpv(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			vpv.ProcessDhcpv6Result(tt.args.cntx, tt.args.ipv6Addr, tt.args.leaseTime)
		})
	}
}

func TestAddSvcUsMeterToDevice(t *testing.T) {
	type args struct {
		cntx  context.Context
		key   interface{}
		value interface{}
		flag  bool
	}
	vpv := &VoltApplication{}
	voltServ := &VoltService{
		VoltServiceOper: VoltServiceOper{
			Device:      test_device,
			ForceDelete: true,
		},
	}
	vpv.ServiceByName.Store(test_device, voltServ)
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "ProcessDhcpResult",
			args: args{
				cntx:  context.Background(),
				key:   test_device,
				value: voltServ,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AddSvcUsMeterToDevice(tt.args.cntx, tt.args.key, tt.args.value, tt.args.flag); got != tt.want {
				t.Errorf("AddSvcUsMeterToDevice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClearFlagsInService(t *testing.T) {
	type args struct {
		cntx  context.Context
		key   interface{}
		value interface{}
		flag  bool
	}
	vpv := &VoltPortVnet{}
	voltServ := &VoltService{
		VoltServiceOper: VoltServiceOper{
			Device: "SDX6320031",
		},
		VoltServiceCfg: VoltServiceCfg{
			IsActivated: true,
		},
	}
	vpv.services.Store("SDX6320031-1_SDX6320031-1-4096-2310-4096-65", voltServ)
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "ClearFlagsInService",
			args: args{
				cntx:  context.Background(),
				key:   test_device,
				value: voltServ,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			got := ClearFlagsInService(tt.args.cntx, tt.args.key, tt.args.value, tt.args.flag)
			assert.NotNil(t, got)
		})
	}
}

func TestVoltPortVnet_DelDhcpFlows(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "DelDhcpFlows",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{}
			vpv.DelDhcpFlows(tt.args.cntx)
		})
	}
}

func TestVoltPortVnet_PushFlowsForPortVnet(t *testing.T) {
	type args struct {
		cntx context.Context
		d    *VoltDevice
	}
	va := GetApplication()
	voltDev := &VoltDevice{
		Name:            "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:       "SDX6320031",
		NniDhcpTrapVid:  123,
		State:           cntlr.DeviceStateUP,
		FlowAddEventMap: util.NewConcurrentMap(),
		Ports:           sync.Map{},
	}
	va.DevicesDisc.Store("SDX6320031", voltDev)
	voltPort := &VoltPort{
		Name:   "49686e2d-618f-4e8e-bca0-442ab850a63a",
		Device: "SDX6320031",
		ID:     16777472,
		State:  PortStateUp,
		Type:   VoltPortTypeNni,
	}
	voltDev.Ports.Store("16777472", voltPort)
	tests := []struct {
		name string
		args args
	}{
		{
			name: "PushFlowsForPortVnet",
			args: args{
				cntx: context.Background(),
				d:    voltDev,
			},
		},
		{
			name: "PushFlowsForPortVnet_PortDown",
			args: args{
				cntx: context.Background(),
				d:    voltDev,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{}
			switch tt.name {
			case "PushFlowsForPortVnet_PortDown":
				vpv.PushFlowsForPortVnet(tt.args.cntx, tt.args.d)
			case "PushFlowsForPortVnet":
				vpv.Port = "16777472"
				vpv.PushFlowsForPortVnet(tt.args.cntx, tt.args.d)
			}
		})
	}
}

func TestVoltPortVnet_setLearntMAC(t *testing.T) {
	type args struct {
		cntx  context.Context
		key   interface{}
		value interface{}
		flag  bool
	}
	voltServ := &VoltService{
		VoltServiceOper: VoltServiceOper{
			Device:      test_device,
			ForceDelete: true,
		},
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "setLearntMAC",
			args: args{
				cntx:  context.Background(),
				key:   test_device,
				value: voltServ,
			},
			want: true,
		},
		{
			name: "updateIPv4AndProvisionFlows",
			args: args{
				cntx:  context.Background(),
				key:   test_device,
				value: voltServ,
			},
			want: true,
		},
		{
			name: "updateIPv6AndProvisionFlows",
			args: args{
				cntx:  context.Background(),
				key:   test_device,
				value: voltServ,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				MacAddr:  net.HardwareAddr(pendingPoolTimer),
				Ipv4Addr: AllSystemsMulticastGroupIP,
				Ipv6Addr: AllSystemsMulticastGroupIP,
			}
			vpv.services.Store(test_device, voltServ)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			switch tt.name {
			case "setLearntMAC":
				if got := vpv.setLearntMAC(tt.args.cntx, tt.args.key, tt.args.value, tt.args.flag); got != tt.want {
					t.Errorf("VoltPortVnet.setLearntMAC() = %v, want %v", got, tt.want)
				}
			case "updateIPv4AndProvisionFlows":
				if got := vpv.updateIPv4AndProvisionFlows(tt.args.cntx, tt.args.key, tt.args.value, tt.args.flag); got != tt.want {
					t.Errorf("VoltPortVnet.updateIPv4AndProvisionFlows() = %v, want %v", got, tt.want)
				}
			case "updateIPv6AndProvisionFlows":
				if got := vpv.updateIPv6AndProvisionFlows(tt.args.cntx, tt.args.key, tt.args.value, tt.args.flag); got != tt.want {
					t.Errorf("VoltPortVnet.updateIPv6AndProvisionFlows() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestAddMeterToDevice(t *testing.T) {
	type args struct {
		cntx  context.Context
		key   interface{}
		value interface{}
		flag  bool
	}
	voltServ := &VoltService{
		VoltServiceOper: VoltServiceOper{
			Device:      test_device,
			ForceDelete: true,
		},
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "TestAddMeterToDevice",
			args: args{
				cntx:  context.Background(),
				key:   test_device,
				value: voltServ,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AddMeterToDevice(tt.args.cntx, tt.args.key, tt.args.value, tt.args.flag); got != tt.want {
				t.Errorf("AddMeterToDevice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltPortVnet_AddUsArpFlows(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	va := GetApplication()
	voltDev := &VoltDevice{
		Name:            "SDX6320031",
		SerialNum:       "SDX6320031",
		NniDhcpTrapVid:  123,
		State:           cntlr.DeviceStateUP,
		FlowAddEventMap: util.NewConcurrentMap(),
		Ports:           sync.Map{},
	}
	voltPort := &VoltPort{
		Name:                     "16777472",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateUp,
		ChannelPerSubAlarmRaised: false,
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "AddUsArpFlows",
			args: args{
				cntx: context.Background(),
			},
			wantErr: true,
		},
		{
			name: "AddUsArpFlows_DeviceNotFound",
			args: args{
				cntx: context.Background(),
			},
			wantErr: true,
		},
		{
			name: "AddUsArpFlows_DeviceStateDOWN",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				Device:      deviceName,
				MacLearning: MacLearningNone,
				MacAddr:     BroadcastMAC,
				Port:        "16777472",
			}
			va.DevicesDisc.Store(deviceName, voltDev)
			va.PortsDisc.Store("16777472", voltPort)
			appMock := mocks.NewMockApp(gomock.NewController(t))
			cntlr.NewController(ctx, appMock)
			vc := cntlr.GetController()
			portsByName := map[string]*cntlr.DevicePort{}
			portsByName["16777472"] = &cntlr.DevicePort{
				Name: "16777472",
				ID:   256,
			}
			device := &cntlr.Device{
				ID:          deviceName,
				PortsByName: portsByName,
			}
			vc.Devices.Store("SDX6320031", device)
			switch tt.name {
			case "AddUsArpFlows":
				if err := vpv.AddUsArpFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddUsArpFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddUsArpFlows_DeviceNotFound":
				vpv.Device = ""
				if err := vpv.AddUsArpFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddUsArpFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddUsArpFlows_DeviceStateDOWN":
				vpv.Device = deviceName
				voltDev.State = cntlr.DeviceStateDOWN
				if err := vpv.AddUsArpFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddUsArpFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVoltPortVnet_AddDsDhcpFlows(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	va := GetApplication()
	voltDev := &VoltDevice{
		Name:            "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:       "SDX6320031",
		NniDhcpTrapVid:  123,
		State:           cntlr.DeviceStateUP,
		FlowAddEventMap: util.NewConcurrentMap(),
	}
	va.DevicesDisc.Store("SDX6320031", voltDev)
	voltPort := &VoltPort{
		Name:                     "49686e2d-618f-4e8e-bca0-442ab850a63a",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateDown,
		ChannelPerSubAlarmRaised: false,
		Type:                     VoltPortTypeNni,
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "AddDsDhcpFlows",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "AddDsDhcpFlows_DeviceNotFound",
			args: args{
				cntx: context.Background(),
			},
			wantErr: true,
		},
		{
			name: "AddDsDhcpFlows_StateDown",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "AddDsDhcpFlows_GlobalDhcpFlowAdded",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "AddDsDhcpFlows_PositiveSenario",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				Device: "SDX6320031",
			}
			switch tt.name {
			case "AddDsDhcpFlows":
				if err := vpv.AddDsDhcpFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddDsDhcpFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddDsDhcpFlows_DeviceNotFound":
				vpv.Device = ""
				if err := vpv.AddDsDhcpFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddDsDhcpFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddDsDhcpFlows_StateDown":
				voltDev.State = cntlr.DeviceStateDOWN
				if err := vpv.AddDsDhcpFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddDsDhcpFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddDsDhcpFlows_GlobalDhcpFlowAdded":
				vpv.Device = deviceName
				voltDev.State = cntlr.DeviceStateUP
				voltDev.GlobalDhcpFlowAdded = true
				if err := vpv.AddDsDhcpFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddDsDhcpFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddDsDhcpFlows_PositiveSenario":
				vpv.Device = deviceName
				voltDev.State = cntlr.DeviceStateUP
				voltDev.GlobalDhcpFlowAdded = false
				voltDev.NniPort = []string{"16777472"}
				va.PortsDisc.Store("16777472", voltPort)
				appMock := mocks.NewMockApp(gomock.NewController(t))
				cntlr.NewController(ctx, appMock)
				vc := cntlr.GetController()
				device := &cntlr.Device{
					ID: "SDX6320031",
				}
				vc.Devices.Store("SDX6320031", device)
				if err := vpv.AddDsDhcpFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddDsDhcpFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVoltPortVnet_AddUsDhcpFlows(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	va := GetApplication()
	voltDev := &VoltDevice{
		Name:            "SDX6320031",
		SerialNum:       "SDX6320031",
		NniDhcpTrapVid:  123,
		State:           cntlr.DeviceStateUP,
		NniPort:         []string{"16777472"},
		FlowAddEventMap: util.NewConcurrentMap(),
	}
	va.DevicesDisc.Store("SDX6320031", voltDev)
	voltPort := &VoltPort{
		Name:                     "16777472",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateDown,
		ChannelPerSubAlarmRaised: false,
		Type:                     VoltPortTypeNni,
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "AddUsDhcpFlows_PositiveSenario",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "AddUsDhcpFlows_StateDown",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "AddUsDhcpFlows_DeviceNotFound",
			args: args{
				cntx: context.Background(),
			},
			wantErr: true,
		},
		{
			name: "AddUsDhcpFlows_GlobalDhcpFlowAdded",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				Device:   "SDX6320031",
				VnetType: DpuMgmtTraffic,
				Port:     "16777472",
			}
			switch tt.name {
			case "AddUsDhcpFlows_PositiveSenario":
				va.PortsDisc.Store("16777472", voltPort)
				appMock := mocks.NewMockApp(gomock.NewController(t))
				cntlr.NewController(ctx, appMock)
				vc := cntlr.GetController()
				device := &cntlr.Device{
					ID: "SDX6320031",
				}
				vc.Devices.Store("SDX6320031", device)
				if err := vpv.AddUsDhcpFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddDsDhcpFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddUsDhcpFlows_DeviceNotFound":
				vpv.Device = ""
				if err := vpv.AddUsDhcpFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddDsDhcpFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddUsDhcpFlows_StateDown":
				voltDev.State = cntlr.DeviceStateDOWN
				if err := vpv.AddUsDhcpFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddDsDhcpFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddUsDhcpFlows_GlobalDhcpFlowAdded":
				vpv.Device = "SDX6320031"
				voltDev.State = cntlr.DeviceStateUP
				vpv.Port = ""
				if err := vpv.AddUsDhcpFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddDsDhcpFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVoltPortVnet_AddUsPppoeFlows(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	va := GetApplication()
	voltDev := &VoltDevice{
		Name:            "SDX6320031",
		SerialNum:       "SDX6320031",
		NniDhcpTrapVid:  123,
		State:           cntlr.DeviceStateUP,
		NniPort:         []string{"16777472"},
		FlowAddEventMap: util.NewConcurrentMap(),
	}
	voltPort := &VoltPort{
		Name:                     "16777472",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateUp,
		ChannelPerSubAlarmRaised: false,
	}
	va.DevicesDisc.Store("SDX6320031", voltDev)
	va.PortsDisc.Store("16777472", voltPort)
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "AddUsPppoeFlows",
			args: args{
				cntx: context.Background(),
			},
			wantErr: true,
		},
		{
			name: "AddDsPppoeFlows",
			args: args{
				cntx: context.Background(),
			},
			wantErr: true,
		},
		{
			name: "AddUsPppoeFlows_StateDown",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "AddDsPppoeFlows_StateDown",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "AddUsPppoeFlows_DeviceNotFound",
			args: args{
				cntx: context.Background(),
			},
			wantErr: true,
		},
		{
			name: "AddDsPppoeFlows_DeviceNotFound",
			args: args{
				cntx: context.Background(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				Device:      "SDX6320031",
				MacLearning: MacLearningNone,
				MacAddr:     net.HardwareAddr(pendingPoolTimer),
			}
			switch tt.name {
			case "AddUsPppoeFlows":
				if err := vpv.AddUsPppoeFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddUsPppoeFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddDsPppoeFlows":
				appMock := mocks.NewMockApp(gomock.NewController(t))
				cntlr.NewController(ctx, appMock)
				vc := cntlr.GetController()
				portsByName := map[string]*cntlr.DevicePort{}
				portsByName["16777472"] = &cntlr.DevicePort{
					Name: "16777472",
					ID:   256,
				}
				device := &cntlr.Device{
					ID:          "SDX6320031",
					PortsByName: portsByName,
				}
				vc.Devices.Store("SDX6320031", device)
				if err := vpv.AddDsPppoeFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddUsPppoeFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddUsPppoeFlows_StateDown":
				voltDev.State = cntlr.DeviceStateDOWN
				if err := vpv.AddUsPppoeFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddUsPppoeFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddDsPppoeFlows_StateDown":
				voltDev.State = cntlr.DeviceStateDOWN
				if err := vpv.AddDsPppoeFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddUsPppoeFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddUsPppoeFlows_DeviceNotFound":
				vpv.Device = ""
				if err := vpv.AddUsPppoeFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddUsPppoeFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "AddDsPppoeFlows_DeviceNotFound":
				vpv.Device = ""
				if err := vpv.AddDsPppoeFlows(tt.args.cntx); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.AddUsPppoeFlows() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVoltPortVnet_AddIgmpFlows(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	var voltPortTest = &VoltPort{
		Name:  "test_name",
		State: PortStateUp,
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "AddIgmpFlows",
			args: args{
				cntx: context.Background(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				MvlanProfileName: "mvlan_profile",
			}
			va := GetApplication()
			va.PortsDisc.Store("test_port", voltPortTest)
			if err := vpv.AddIgmpFlows(tt.args.cntx); (err != nil) != tt.wantErr {
				t.Errorf("VoltPortVnet.AddIgmpFlows() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVoltPortVnet_BuildUsDhcp6Flows(t *testing.T) {
	voltPort := &VoltPort{
		Name:                     "16777216",
		Device:                   "SDX6320031",
		ID:                       16777216,
		State:                    PortStateDown,
		ChannelPerSubAlarmRaised: false,
		Type:                     VoltPortTypeNni,
	}
	voltService := &VoltService{
		Version: "test_version",
		VoltServiceCfg: VoltServiceCfg{
			VnetID:  "test_vnet_id",
			Port:    "16777216",
			SVlan:   of.VlanAny,
			CVlan:   of.VlanAny,
			UniVlan: of.VlanAny,
		},
	}
	deviceConfig := &DeviceConfig{
		SerialNumber:       "SDX6320031",
		HardwareIdentifier: "dummy_hardware_identifier",
		IPAddress:          "10.9.8.7",
		UplinkPort:         "16777216",
		NasID:              "nas_id",
		NniDhcpTrapVid:     123,
	}
	voltDev := &VoltDevice{
		Name:           "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
		State:          cntlr.DeviceStateUP,
		NniPort:        []string{"16777472"},
		Ports:          sync.Map{},
	}
	tests := []struct {
		name    string
		want    *of.VoltFlow
		wantErr bool
	}{
		{
			name: "BuildUsDhcp6Flows",
			want: &of.VoltFlow{},
		},
		{
			name: "BuildDsDhcp6Flows",
			want: &of.VoltFlow{},
		},
		{
			name:    "BuildDsDhcp6Flows_DeviceNotFound",
			want:    &of.VoltFlow{},
			wantErr: true,
		},
		{
			name:    "BuildUsDhcp6Flows_portnotfound",
			want:    &of.VoltFlow{},
			wantErr: true,
		},
		{
			name:    "BuildDsDhcp6Flows_portnotfound",
			want:    &of.VoltFlow{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				Port:             "16777216",
				services:         sync.Map{},
				AllowTransparent: true,
				Device:           "SDX6320031",
			}
			va := GetApplication()
			va.PortsDisc.Store("16777216", voltPort)
			vpv.services.Store("SDX6320031-1_SDX6320031-1-4096-2310-4096-65", voltService)
			switch tt.name {
			case "BuildUsDhcp6Flows":
				got, err := vpv.BuildUsDhcp6Flows()
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.BuildUsDhcp6Flows() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.NotNil(t, got)
			case "BuildDsDhcp6Flows":
				voltDev.NniPort = []string{"16777216"}
				voltDev.Ports.Store("16777216", voltPort)
				va.DevicesDisc.Store("SDX6320031", voltDev)
				va.DevicesConfig.Store("SDX6320031", deviceConfig)
				got, err := vpv.BuildDsDhcp6Flows()
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.BuildDsDhcp6Flows() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.NotNil(t, got)
			case "BuildDsDhcp6Flows_DeviceNotFound":
				vpv.Device = ""
				got, err := vpv.BuildDsDhcp6Flows()
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.BuildDsDhcp6Flows() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.Nil(t, got)
			case "BuildUsDhcp6Flows_portnotfound":
				vpv.Port = ""
				got, err := vpv.BuildUsDhcp6Flows()
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.BuildUsDhcp6Flows_portnotfound() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.Nil(t, got)
			case "BuildDsDhcp6Flows_portnotfound":
				voltDev.NniPort = []string{"abc"}
				got, err := vpv.BuildDsDhcp6Flows()
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.BuildDsDhcp6Flows_portnotfound() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.Nil(t, got)
			}
		})
	}
}

func TestVoltPortVnet_setUsMatchVlan(t *testing.T) {
	type args struct {
		flow *of.VoltSubFlow
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "setUsMatchVlan",
			args: args{
				flow: &of.VoltSubFlow{},
			},
		},
		{
			name: "OLTCVlanOLTSVlan",
			args: args{
				flow: &of.VoltSubFlow{},
			},
		},
		{
			name: "ONUCVlan",
			args: args{
				flow: &of.VoltSubFlow{},
			},
		},
		{
			name: "OLTSVlan",
			args: args{
				flow: &of.VoltSubFlow{},
			},
		},
		{
			name: "Default",
			args: args{
				flow: &of.VoltSubFlow{},
			},
			wantErr: true,
		},
		{
			name: "setDsMatchVlan_OLTCVlanOLTSVlan",
			args: args{
				flow: &of.VoltSubFlow{},
			},
		},
		{
			name: "setDsMatchVlan_Default",
			args: args{
				flow: &of.VoltSubFlow{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				VlanControl: ONUCVlanOLTSVlan,
			}
			switch tt.name {
			case "setUsMatchVlan":
				if err := vpv.setUsMatchVlan(tt.args.flow); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.setUsMatchVlan() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "OLTCVlanOLTSVlan":
				vpv.VlanControl = OLTCVlanOLTSVlan
				if err := vpv.setUsMatchVlan(tt.args.flow); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.setUsMatchVlan() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "ONUCVlan":
				vpv.VlanControl = ONUCVlan
				if err := vpv.setUsMatchVlan(tt.args.flow); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.setUsMatchVlan() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "OLTSVlan":
				vpv.VlanControl = OLTSVlan
				if err := vpv.setUsMatchVlan(tt.args.flow); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.setUsMatchVlan() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "Default":
				vpv.VlanControl = opt82
				if err := vpv.setUsMatchVlan(tt.args.flow); (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.setUsMatchVlan() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "setDsMatchVlan_OLTCVlanOLTSVlan":
				vpv.VlanControl = OLTCVlanOLTSVlan
				vpv.setDsMatchVlan(tt.args.flow)
			case "setDsMatchVlan_Default":
				vpv.VlanControl = opt82
				vpv.setDsMatchVlan(tt.args.flow)
			}
		})
	}
}

func TestVoltPortVnet_BuildIgmpFlows(t *testing.T) {
	va := GetApplication()
	devicesList := make(map[string]OperInProgress)
	devicesList["SDX6320030"] = opt82
	mvp := &MvlanProfile{
		Name:        "mvlan_test",
		DevicesList: devicesList,
	}
	va.MvlanProfilesByName.Store("mvlan_test", mvp)
	voltPort := &VoltPort{
		Name:                     "16777472",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateUp,
		ChannelPerSubAlarmRaised: false,
	}
	va.PortsDisc.Store("16777472", voltPort)
	tests := []struct {
		name    string
		want    *of.VoltFlow
		wantErr bool
	}{
		{
			name: "BuildIgmpFlows",
			want: &of.VoltFlow{},
		},
		{
			name: "BuildIgmpFlows_McastService_False",
			want: &of.VoltFlow{},
		},
		{
			name:    "BuildIgmpFlows_PortNotFound",
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				Port:             "16777472",
				MvlanProfileName: "mvlan_test",
				MacLearning:      MacLearningNone,
				MacAddr:          util.Uint32ToByte(uint32(23)),
				McastService:     true,
				AllowTransparent: true,
			}

			switch tt.name {
			case "BuildIgmpFlows":
				got, err := vpv.BuildIgmpFlows()
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.BuildIgmpFlows() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.NotNil(t, got)
			case "BuildIgmpFlows_McastService_False":
				vpv.McastService = false
				vpv.services.Store("16777472", &VoltService{})
				got, err := vpv.BuildIgmpFlows()
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.BuildIgmpFlows() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.NotNil(t, got)
			case "BuildIgmpFlows_PortNotFound":
				vpv.Port = ""
				got, err := vpv.BuildIgmpFlows()
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltPortVnet.BuildIgmpFlows() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.Nil(t, got)
			}
		})
	}
}

func TestVoltPortVnet_SetMacAddr(t *testing.T) {
	type args struct {
		cntx context.Context
		addr net.HardwareAddr
	}
	addr, _ := net.ParseMAC("00:00:11:00:00:00")
	macAddr, _ := net.ParseMAC("00:00:00:00:00:11")
	tests := []struct {
		name string
		args args
	}{
		{
			name: "SetMacAddr",
			args: args{
				cntx: context.Background(),
				addr: addr,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				MacAddr:      macAddr,
				MacLearning:  MaxLenDhcpv6DUID,
				FlowsApplied: true,
			}
			switch tt.name {
			case "SetMacAddr":
				vpv.SetMacAddr(tt.args.cntx, tt.args.addr)
			}
		})
	}
}

func TestVoltPortVnet_AddTrapFlows(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "AddTrapFlows",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "AddTrapFlows_ArpRelay",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "AddTrapFlows_PppoeIa",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				DhcpRelay:        true,
				DeleteInProgress: true,
			}
			switch tt.name {
			case "AddTrapFlows":
				vpv.AddTrapFlows(tt.args.cntx)
			case "AddTrapFlows_ArpRelay":
				vpv.DhcpRelay = false
				vpv.ArpRelay = true
				vpv.AddTrapFlows(tt.args.cntx)
			case "AddTrapFlows_PppoeIa":
				vpv.DhcpRelay = false
				vpv.ArpRelay = false
				vpv.PppoeIa = true
				vpv.AddTrapFlows(tt.args.cntx)
			}
		})
	}
}

func TestVoltPortVnet_DelTrapFlows(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "DelTrapFlows",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				FlowsApplied:     true,
				DhcpRelay:        true,
				DeleteInProgress: true,
			}
			switch tt.name {
			case "DelTrapFlows":
				vpv.DelTrapFlows(tt.args.cntx)
			}
		})
	}
}

func TestVoltPortVnet_delDsDhcp4Flows(t *testing.T) {
	type args struct {
		cntx   context.Context
		device *VoltDevice
	}
	voltDev := &VoltDevice{
		Name:            "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:       "SDX6320031",
		NniDhcpTrapVid:  123,
		State:           cntlr.DeviceStateUP,
		NniPort:         []string{"16777472"},
		Ports:           sync.Map{},
		FlowDelEventMap: util.NewConcurrentMap(),
	}
	va := GetApplication()
	devicesList := make(map[string]OperInProgress)
	devicesList["SDX6320031"] = opt82
	mvp := &MvlanProfile{
		Name:        "mvlan_test",
		DevicesList: devicesList,
	}
	va.MvlanProfilesByName.Store("mvlan_test", mvp)
	voltPort := &VoltPort{
		Name:                     "16777472",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateUp,
		ChannelPerSubAlarmRaised: false,
	}
	va.DevicesDisc.Store("SDX6320031", voltDev)
	va.PortsDisc.Store("16777472", voltPort)
	appMock := mocks.NewMockApp(gomock.NewController(t))
	controller.NewController(ctx, appMock)
	vc := cntlr.GetController()
	portsByName := map[string]*cntlr.DevicePort{}
	portsByName["16777472"] = &cntlr.DevicePort{
		Name: "16777472",
		ID:   256,
	}
	device := &cntlr.Device{
		ID:          deviceName,
		PortsByName: portsByName,
	}
	vc.Devices.Store("SDX6320031", device)
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "delDsDhcp4Flows",
			args: args{
				cntx:   context.Background(),
				device: voltDev,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vpv := &VoltPortVnet{
				Device:            "SDX6320031",
				Port:              "16777472",
				MvlanProfileName:  "mvlan_test",
				MacLearning:       MacLearningNone,
				MacAddr:           util.Uint32ToByte(uint32(23)),
				McastService:      true,
				AllowTransparent:  true,
				PendingDeleteFlow: make(map[string]bool),
			}
			if err := vpv.delDsDhcp4Flows(tt.args.cntx, tt.args.device); (err != nil) != tt.wantErr {
				t.Errorf("VoltPortVnet.delDsDhcp4Flows() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVoltApplication_DeleteDevFlowForVlan(t *testing.T) {
	type args struct {
		cntx context.Context
		vnet *VoltVnet
	}
	voltDev := &VoltDevice{
		Name:                         "SDX6320031",
		SerialNum:                    "SDX6320031",
		NniDhcpTrapVid:               123,
		State:                        cntlr.DeviceStateUP,
		NniPort:                      []string{"16777472"},
		Ports:                        sync.Map{},
		FlowDelEventMap:              util.NewConcurrentMap(),
		ConfiguredVlanForDeviceFlows: util.NewConcurrentMap(),
	}
	voltVnet := &VoltVnet{
		Version: "v3",
		VnetConfig: VnetConfig{
			Name:     "2310-4096-4096",
			VnetType: "Encapsulation",
		},
		VnetOper: VnetOper{
			PendingDeviceToDelete: "SDX6320031",
			DeleteInProgress:      true,
			PendingDeleteFlow:     make(map[string]map[string]bool),
		},
	}
	voltPort := &VoltPort{
		Name:                     "16777472",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateUp,
		ChannelPerSubAlarmRaised: false,
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "DeleteDevFlowForVlan",
			args: args{
				cntx: context.Background(),
				vnet: voltVnet,
			},
		},
		{
			name: "DeleteDevFlowForVlan_PortStateDown",
			args: args{
				cntx: context.Background(),
				vnet: voltVnet,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			switch tt.name {
			case "DeleteDevFlowForVlan":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				va.VnetsByName.Store("2310-4096-4096", voltVnet)
				voltDev.ConfiguredVlanForDeviceFlows.Set("0-0-0", util.NewConcurrentMap())
				va.PortsDisc.Store("16777472", voltPort)
				appMock := mocks.NewMockApp(gomock.NewController(t))
				cntlr.NewController(ctx, appMock)
				vc := cntlr.GetController()
				portsByName := map[string]*cntlr.DevicePort{}
				portsByName["16777472"] = &cntlr.DevicePort{
					Name:  "16777472",
					ID:    256,
					State: cntlr.PortStateUp,
				}
				device := &cntlr.Device{
					ID:          "SDX6320031",
					PortsByName: portsByName,
				}
				vc.Devices.Store("SDX6320031", device)
				va.DeleteDevFlowForVlan(tt.args.cntx, tt.args.vnet)
			case "DeleteDevFlowForVlan_PortStateDown":
				voltDev.Name = ""
				va.DevicesDisc.Store("SDX6320031", voltDev)
				va.VnetsByName.Store("2310-4096-4096", voltVnet)
				voltDev.ConfiguredVlanForDeviceFlows.Set("0-0-0", util.NewConcurrentMap())
				va.PortsDisc.Store("16777472", voltPort)
				appMock := mocks.NewMockApp(gomock.NewController(t))
				cntlr.NewController(ctx, appMock)
				vc := cntlr.GetController()
				portsByName := map[string]*cntlr.DevicePort{}
				portsByName["16777472"] = &cntlr.DevicePort{
					Name:  "16777472",
					ID:    256,
					State: cntlr.PortStateUp,
				}
				device := &cntlr.Device{
					ID:          "SDX6320031",
					PortsByName: portsByName,
				}
				vc.Devices.Store("SDX6320031", device)
				va.DeleteDevFlowForVlan(tt.args.cntx, tt.args.vnet)
			}
		})
	}
}
