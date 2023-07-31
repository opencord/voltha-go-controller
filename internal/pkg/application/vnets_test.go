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
	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
	"github.com/stretchr/testify/assert"
)

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
			if got := vpv.IsServiceActivated(tt.args.cntx); got != tt.want {
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
				voltDevice.NniPort = "test_port"
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
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().DelVnet(tt.args.cntx, "test_name").Return(nil).Times(1)
				vv.FlowRemoveFailure(tt.args.cntx, tt.args.cookie, tt.args.device, tt.args.errorCode, tt.args.errReason)
			case "mismatch_cookie":
				cookie := map[string]bool{}
				cookie["12345"] = true
				pendingDeleteFlow := map[string]map[string]bool{}
				pendingDeleteFlow[test_device] = cookie
				vv.PendingDeleteFlow = pendingDeleteFlow
				vv.DeleteInProgress = true
				vv.Name = "test_name"
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().DelVnet(tt.args.cntx, "test_name").Return(nil).Times(1)
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
	tests := []struct {
		name string
		args args
	}{
		{
			name: "device.SerialNum != deviceSerialNum",
			args: args{
				cntx: context.Background(),
				vnet: &VoltVnet{
					Version: "test_version",
				},
			},
		},
		{
			name: "VoltApplication_DeleteDevFlowForVlanFromDevice",
			args: args{
				cntx: context.Background(),
				vnet: &VoltVnet{
					Version: "test_version",
				},
				deviceSerialNum: "test_serial_number",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			switch tt.name {
			case "device.SerialNum != deviceSerialNum":
				va.DevicesDisc.Store(test_device, voltDevice)
				va.DeleteDevFlowForVlanFromDevice(tt.args.cntx, tt.args.vnet, tt.args.deviceSerialNum)
			case "VoltApplication_DeleteDevFlowForVlanFromDevice":
				va.DevicesDisc.Store(test_device, voltDevice)
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
			dbintf.EXPECT().PutVnet(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
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
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_DeleteDevFlowForDevice",
			args: args{
				cntx: context.Background(),
				device: &VoltDevice{
					Name:                         test_device,
					ConfiguredVlanForDeviceFlows: util.NewConcurrentMap(),
				},
			},
		},
	}
	var voltVnet_DeleteDevFlowForDevice = &VoltVnet{
		Version: "test_version",
		VnetConfig: VnetConfig{
			Name:  "test_name",
			SVlan: of.VlanAny,
			CVlan: of.VlanAny,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			va.VnetsByName.Store("4096-4096-0", voltVnet_DeleteDevFlowForDevice)
			//tt.args.device.ConfiguredVlanForDeviceFlows.SyncMap.Store("4096-4069-0", util.NewConcurrentMap())
			va.DeleteDevFlowForDevice(tt.args.cntx, tt.args.device)
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			voltDevice.SerialNum = "test_serialNum"
			voltDevice.VlanPortStatus.Store(uint16(of.VlanAny), true)
			voltDevice.Name = test_device
			va.DevicesDisc.Store(test_device, voltDevice)
			ga := GetApplication()
			ga.DevicesDisc.Store(test_device, voltDevice)
			_ = cntlr.NewController(context.Background(), mocks.NewMockApp(gomock.NewController(t)))
			va.PushDevFlowForVlan(tt.args.cntx, tt.args.vnet)
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
					NniPort:                      "test_nni_port",
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
					NniPort:                      "test_nni_port",
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
