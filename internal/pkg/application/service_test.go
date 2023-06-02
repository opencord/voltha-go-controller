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
	"errors"
	"sync"
	"testing"
	"voltha-go-controller/internal/pkg/controller"
	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket/layers"
	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
	"github.com/stretchr/testify/assert"
	"go.uber.org/atomic"
)

var test_device = "test_device"
var voltPort = &VoltPort{
	Name:   "test_name",
	Device: test_device,
}
var voltDevice = &VoltDevice{
	Name:            "test_name",
	State:           controller.DeviceStateUP,
	FlowAddEventMap: util.NewConcurrentMap(),
	FlowDelEventMap: util.NewConcurrentMap(),
	SerialNum:       "test_serial_number",
}

var voltMeter = &VoltMeter{
	Name:    "test_volt_meter",
	Version: "test_version",
}

var voltVnet = &VoltVnet{
	Version: "test_version",
	VnetConfig: VnetConfig{
		Name: "test_name",
	},
}

var voltPortVnet1 = []*VoltPortVnet{
	{
		Device:        "4096-4096-4096",
		SVlan:         of.VlanAny,
		CVlan:         of.VlanAny,
		UniVlan:       of.VlanAny,
		IgmpEnabled:   true,
		servicesCount: &atomic.Uint64{},
	},
}

var voltDevice1 = &VoltDevice{
	State: cntlr.DeviceStateDOWN,
}

var GetDeviceFromPort_error = "GetDeviceFromPort_error"

func TestVoltApplication_RestoreSvcsFromDb(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_RestoreSvcsFromDb",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "invalid_value_type",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "unmarshal_error",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			voltService := &VoltService{
				VoltServiceOper: VoltServiceOper{
					Device:           "SDX6320031",
					ForceDelete:      true,
					DeleteInProgress: true,
				},
				VoltServiceCfg: VoltServiceCfg{
					Name: "test_service_name",
				},
			}
			serviceToDelete := map[string]bool{}
			serviceToDelete[voltService.VoltServiceCfg.Name] = true
			va := &VoltApplication{
				ServicesToDelete: serviceToDelete,
			}
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			switch tt.name {
			case "VoltApplication_RestoreSvcsFromDb":

				b, err := json.Marshal(voltService)
				if err != nil {
					panic(err)
				}
				kvPair := map[string]*kvstore.KVPair{}
				kvPair["key"] = &kvstore.KVPair{
					Key:     "test_key",
					Value:   b,
					Version: 1,
				}
				dbintf.EXPECT().GetServices(tt.args.cntx).Return(kvPair, nil).Times(1)
				va.RestoreSvcsFromDb(tt.args.cntx)
			case "invalid_value_type":
				kvPair := map[string]*kvstore.KVPair{}
				kvPair["key"] = &kvstore.KVPair{
					Key:     "test_key",
					Value:   "invalid_value",
					Version: 1,
				}
				dbintf.EXPECT().GetServices(tt.args.cntx).Return(kvPair, nil).Times(1)
				va.RestoreSvcsFromDb(tt.args.cntx)
			case "unmarshal_error":
				b, err := json.Marshal("test")
				if err != nil {
					panic(err)
				}
				kvPair := map[string]*kvstore.KVPair{}
				kvPair["key"] = &kvstore.KVPair{
					Key:     "test_key",
					Value:   b,
					Version: 1,
				}
				dbintf.EXPECT().GetServices(tt.args.cntx).Return(kvPair, nil).Times(1)
				va.RestoreSvcsFromDb(tt.args.cntx)
			}
		})
	}
}

func TestVoltService_FlowRemoveFailure(t *testing.T) {
	type args struct {
		cntx      context.Context
		cookie    string
		errorCode uint32
		errReason string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltService_FlowRemoveFailure",
			args: args{
				cntx:      context.Background(),
				cookie:    "test_cookie",
				errorCode: 200,
				errReason: "test_reason",
			},
		},
		{
			name: "cookie_not_found",
			args: args{
				cntx:      context.Background(),
				cookie:    "test_cookie",
				errorCode: 200,
				errReason: "test_reason",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "VoltService_FlowRemoveFailure":
				associatedFlows := map[string]bool{}
				associatedFlows["test_cookie"] = true
				vs := &VoltService{
					VoltServiceOper: VoltServiceOper{
						AssociatedFlows: associatedFlows,
					},
				}
				vs.FlowRemoveFailure(tt.args.cntx, tt.args.cookie, tt.args.errorCode, tt.args.errReason)
			case "cookie_not_found":
				associatedFlows := map[string]bool{}
				associatedFlows["cookie"] = true
				vs := &VoltService{
					VoltServiceOper: VoltServiceOper{
						AssociatedFlows: associatedFlows,
					},
				}
				vs.FlowRemoveFailure(tt.args.cntx, tt.args.cookie, tt.args.errorCode, tt.args.errReason)
			}
		})
	}
}

func TestVoltApplication_GetServiceNameFromCookie(t *testing.T) {
	type args struct {
		cookie        uint64
		portName      string
		pbit          uint8
		device        string
		tableMetadata uint64
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_GetServiceNameFromCookie",
			args: args{
				cookie:        uint64(1),
				portName:      "test_port_name",
				device:        "SDX6320031",
				pbit:          2,
				tableMetadata: uint64(2),
			},
		},
	}
	voltDev := &VoltDevice{
		Name:           "SDX6320031",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ga := GetApplication()
			ga.DevicesDisc.Store("SDX6320031", voltDev)
			voltPortVnets := make([]*VoltPortVnet, 0)
			voltPortVnet := &VoltPortVnet{
				Device:      test_device,
				VlanControl: ONUCVlanOLTSVlan,
			}
			voltPortVnets = append(voltPortVnets, voltPortVnet)
			ga.VnetsByPort.Store("test_port_name", voltPortVnets)
			got := ga.GetServiceNameFromCookie(tt.args.cookie, tt.args.portName, tt.args.pbit, tt.args.device, tt.args.tableMetadata)
			assert.Nil(t, got)
		})
	}
}

func TestVoltService_SvcUpInd(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltService_SvcUpInd",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := &VoltService{
				VoltServiceOper: VoltServiceOper{
					PendingFlows: make(map[string]bool),
				},
				VoltServiceCfg: VoltServiceCfg{
					SVlanTpid: layers.EthernetTypeDot1Q,
					MacAddr:   layers.EthernetBroadcast,
				},
			}
			vs.Port = test_device
			vs.Device = "device"
			ga := GetApplication()
			_ = cntlr.NewController(context.Background(), mocks.NewMockApp(gomock.NewController(t)))
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			ga.PortsDisc.Store(test_device, voltPort)
			ga.DevicesDisc.Store(test_device, voltDevice)
			vs.SvcUpInd(tt.args.cntx)
		})
	}
}

func TestVoltService_SvcDownInd(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltService_SvcDownInd",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := &VoltService{
				VoltServiceOper: VoltServiceOper{
					UsHSIAFlowsApplied: true,
					DsHSIAFlowsApplied: true,
				},
				VoltServiceCfg: VoltServiceCfg{
					SVlanTpid: layers.EthernetTypeQinQ,
					MacAddr:   layers.EthernetBroadcast,
				},
			}
			vs.Port = test_device
			vs.Device = "device"
			ga := GetApplication()
			_ = cntlr.NewController(context.Background(), mocks.NewMockApp(gomock.NewController(t)))
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			ga.PortsDisc.Store(test_device, voltPort)
			ga.DevicesDisc.Store(test_device, voltDevice)
			vs.SvcDownInd(tt.args.cntx)
		})
	}
}

func TestVoltApplication_AddService(t *testing.T) {
	type args struct {
		cntx context.Context
		cfg  VoltServiceCfg
		oper *VoltServiceOper
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_AddService",
			args: args{
				cntx: context.Background(),
				cfg: VoltServiceCfg{
					Name:           "test_name",
					Port:           "test_port",
					DsMeterProfile: "4096-4096-4096",
					UsMeterProfile: "4096-4096-4096",
					SVlan:          of.VlanAny,
					CVlan:          of.VlanAny,
					UniVlan:        of.VlanAny,
					MacLearning:    Learn,
					IsActivated:    true,
				},
				oper: &VoltServiceOper{
					Device: "4096-4096-4096",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				MeterMgr: MeterMgr{
					Meters: sync.Map{},
				},
				VnetsByPort: sync.Map{},
				VnetsByTag:  sync.Map{},
			}
			va.MeterMgr.Meters.Store("4096-4096-4096", voltMeter)
			va.VnetsByTag.Store("4096-4096-4096", voltVnet)
			voltPortVnet1[0].SVlan = of.VlanAny
			voltPortVnet1[0].CVlan = of.VlanAny
			voltPortVnet1[0].UniVlan = of.VlanAny
			voltPortVnet1[0].servicesCount = atomic.NewUint64(uint64(56))
			voltPortVnet1[0].MacAddr = layers.EthernetBroadcast
			voltPortVnet1[0].Port = "test_port"
			va.VnetsByPort.Store("test_port", voltPortVnet1)
			ga := GetApplication()
			voltPort1 := &VoltPort{
				Name:   "test_name",
				Device: test_device,
			}
			deviceConfig := &DeviceConfig{
				SerialNumber: "test_serial_number",
			}
			ga.PortsDisc.Store("test_port", voltPort1)
			ga.DevicesDisc.Store(test_device, voltDevice)
			ga.DevicesConfig.Store("test_serial_number", deviceConfig)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			dbintf.EXPECT().PutVpv(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			err := va.AddService(tt.args.cntx, tt.args.cfg, tt.args.oper)
			assert.Nil(t, err)
		})
	}
}

func TestVoltApplication_DelService(t *testing.T) {
	type args struct {
		cntx             context.Context
		name             string
		forceDelete      bool
		newSvc           *VoltServiceCfg
		serviceMigration bool
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_DelService",
			args: args{
				cntx:        context.Background(),
				name:        "test_name",
				forceDelete: true,
				newSvc: &VoltServiceCfg{
					Name: "vs_cfg_name",
					Port: "test_port",
				},
				serviceMigration: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				ServiceByName: sync.Map{},
				VnetsByPort:   sync.Map{},
			}
			voltService := &VoltService{
				Version: "test_version",
				VoltServiceCfg: VoltServiceCfg{
					Port:    "4096-4096-4096",
					SVlan:   of.VlanAny,
					CVlan:   of.VlanAny,
					UniVlan: of.VlanAny,
				},
			}
			va.ServiceByName.Store(tt.args.name, voltService)
			va.VnetsByPort.Store("4096-4096-4096", voltPortVnet1)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().DelService(gomock.Any(), gomock.Any()).AnyTimes()
			dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			va.DelService(tt.args.cntx, tt.args.name, tt.args.forceDelete, tt.args.newSvc, tt.args.serviceMigration)
		})
	}
}

func TestVoltService_FlowInstallSuccess(t *testing.T) {
	type args struct {
		cntx        context.Context
		cookie      string
		bwAvailInfo of.BwAvailDetails
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltService_FlowInstallSuccess",
			args: args{
				cntx:   context.Background(),
				cookie: "test_cookie",
				bwAvailInfo: of.BwAvailDetails{
					PrevBw:    "test_prev_BW",
					PresentBw: "test_present_BW",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pendingFlows := map[string]bool{}
			pendingFlows["test_cookie"] = true
			associatedFlows := map[string]bool{}
			associatedFlows["test_cookie"] = true
			vs := &VoltService{
				VoltServiceOper: VoltServiceOper{
					PendingFlows:       pendingFlows,
					AssociatedFlows:    associatedFlows,
					DsHSIAFlowsApplied: true,
				},
				VoltServiceCfg: VoltServiceCfg{
					Port: "test_port",
				},
			}
			ga := GetApplication()
			ga.PortsDisc.Store("test_port", voltPort)
			ga.DevicesDisc.Store(test_device, voltDevice)
			vs.FlowInstallSuccess(tt.args.cntx, tt.args.cookie, tt.args.bwAvailInfo)
		})
	}
}

func TestVoltService_AddMeterToDevice(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "VoltService_AddMeterToDevice",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: GetDeviceFromPort_error,
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "DeviceState_down",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "VoltService_AddMeterToDevice":
				vs := &VoltService{
					VoltServiceOper: VoltServiceOper{
						DeleteInProgress: true,
					},
					VoltServiceCfg: VoltServiceCfg{
						Port: "test_port",
					},
				}
				ga := GetApplication()
				ga.PortsDisc.Store("test_port", voltPort)
				ga.DevicesDisc.Store(test_device, voltDevice)
				err := vs.AddMeterToDevice(tt.args.cntx)
				assert.Nil(t, err)
			case GetDeviceFromPort_error:
				vs := &VoltService{
					VoltServiceOper: VoltServiceOper{
						DeleteInProgress: true,
					},
					VoltServiceCfg: VoltServiceCfg{
						Port: "",
					},
				}
				err := vs.AddMeterToDevice(tt.args.cntx)
				assert.NotNil(t, err)
			case "DeviceState_down":
				vs := &VoltService{
					VoltServiceOper: VoltServiceOper{
						DeleteInProgress: true,
					},
					VoltServiceCfg: VoltServiceCfg{
						Port: "test_port",
					},
				}
				ga := GetApplication()
				ga.PortsDisc.Store("test_port", voltPort)
				ga.DevicesDisc.Store(test_device, voltDevice1)
				err := vs.AddMeterToDevice(tt.args.cntx)
				assert.Nil(t, err)
			}
		})
	}
}

func TestVoltService_AddUsHsiaFlows(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "DeleteInProgress_true",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "GetDeviceFromPort_error",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "DeviceState_down",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "DeleteInProgress_true":
				vs := &VoltService{
					VoltServiceOper: VoltServiceOper{
						DeleteInProgress: true,
					},
				}
				err := vs.AddUsHsiaFlows(tt.args.cntx)
				assert.Nil(t, err)
			case "GetDeviceFromPort_error":
				vs := &VoltService{
					VoltServiceOper: VoltServiceOper{
						DeleteInProgress: false,
					},
				}
				err := vs.AddUsHsiaFlows(tt.args.cntx)
				assert.NotNil(t, err)
			case "DeviceState_down":
				vs := &VoltService{
					VoltServiceOper: VoltServiceOper{
						DeleteInProgress: false,
					},
					VoltServiceCfg: VoltServiceCfg{
						Port: "test_port",
					},
				}
				ga := GetApplication()
				ga.PortsDisc.Store("test_port", voltPort)
				ga.DevicesDisc.Store(test_device, voltDevice1)
				err := vs.AddUsHsiaFlows(tt.args.cntx)
				assert.Nil(t, err)
			}
		})
	}
}

func TestVoltService_AddHsiaFlows(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "AddUsHsiaFlows_error",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := &VoltService{
				VoltServiceCfg: VoltServiceCfg{
					Port:        "test_port",
					VlanControl: 5,
				},
			}
			ga := GetApplication()
			ga.PortsDisc.Store("test_port", voltPort)
			ga.DevicesDisc.Store(test_device, voltDevice)
			vs.AddHsiaFlows(tt.args.cntx)
		})
	}
}

func TestVoltService_ForceWriteToDb(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "PutService_error",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "PutService_error":
				vs := &VoltService{}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("error")).AnyTimes()
				vs.ForceWriteToDb(tt.args.cntx)
			}
		})
	}
}

func TestVoltService_isDataRateAttrPresent(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{
			name: "VoltService_isDataRateAttrPresent",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := &VoltService{}
			if got := vs.isDataRateAttrPresent(); got != tt.want {
				t.Errorf("VoltService.isDataRateAttrPresent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltService_GetServicePbit(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{
			name: "VoltService_GetServicePbit",
			want: -1,
		},
		{
			name: "!IsPbitExist",
			want: 8,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "VoltService_GetServicePbit":
				vs := &VoltService{
					VoltServiceCfg: VoltServiceCfg{
						Pbits: []of.PbitType{of.PbitMatchAll},
					},
				}
				if got := vs.GetServicePbit(); got != tt.want {
					t.Errorf("VoltService.GetServicePbit() = %v, want %v", got, tt.want)
				}
			case "!IsPbitExist":
				vs := &VoltService{}
				if got := vs.GetServicePbit(); got != tt.want {
					t.Errorf("VoltService.GetServicePbit() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVoltApplication_DeactivateService(t *testing.T) {
	type args struct {
		cntx     context.Context
		deviceID string
		portNo   string
		sVlan    of.VlanType
		cVlan    of.VlanType
		tpID     uint16
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "VoltApplication_DeactivateService",
			args: args{
				cntx:     context.Background(),
				deviceID: "test_device_id",
				portNo:   "test_port",
				sVlan:    of.VlanNone,
				cVlan:    of.VlanAny,
				tpID:     AnyVlan,
			},
		},
		{
			name: "VoltPortVnet_nil",
			args: args{
				cntx:     context.Background(),
				deviceID: "test_device_id",
				portNo:   "test_port",
				sVlan:    of.VlanNone,
				cVlan:    of.VlanAny,
				tpID:     AnyVlan,
			},
		},
		{
			name: "sVlan != of.VlanNone",
			args: args{
				cntx:     context.Background(),
				deviceID: "test_device_id",
				portNo:   "test_port",
				sVlan:    of.VlanAny,
				cVlan:    of.VlanAny,
				tpID:     AnyVlan,
			},
		},
		{
			name: GetDeviceFromPort_error,
			args: args{
				cntx:     context.Background(),
				deviceID: "test_device_id",
				portNo:   "test_port",
				sVlan:    of.VlanNone,
				cVlan:    of.VlanAny,
				tpID:     AnyVlan,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				ServiceByName: sync.Map{},
				VnetsByPort:   sync.Map{},
				DevicesDisc:   sync.Map{},
				PortsDisc:     sync.Map{},
			}
			voltServiceTest := &VoltService{
				VoltServiceOper: VoltServiceOper{
					Device: test_device,
				},
				Version: "test_version",
				VoltServiceCfg: VoltServiceCfg{
					Port:        "test_port",
					Name:        "test_name",
					IsActivated: true,
					CVlan:       of.VlanAny,
					SVlan:       of.VlanAny,
					UniVlan:     of.VlanAny,
				},
			}
			switch tt.name {
			case "VoltApplication_DeactivateService":
				va.ServiceByName.Store("test_name", voltServiceTest)
				va.PortsDisc.Store("test_port", voltPort)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				va.DevicesDisc.Store(test_device, voltDevice)
				voltDevice.Ports.Store("test_port", voltPort)
				va.VnetsByPort.Store("test_port", voltPortVnet1)
				voltPortVnet1[0].servicesCount.Store(uint64(1))
				dbintf.EXPECT().PutVpv(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				if err := va.DeactivateService(tt.args.cntx, tt.args.deviceID, tt.args.portNo, tt.args.sVlan, tt.args.cVlan, tt.args.tpID); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.DeactivateService() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "VoltPortVnet_nil":
				va.ServiceByName.Store("test_name", voltServiceTest)
				va.PortsDisc.Store("test_port", voltPort)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				va.DevicesDisc.Store(test_device, voltDevice)
				voltDevice.Ports.Store("test_port", voltPort)
				if err := va.DeactivateService(tt.args.cntx, tt.args.deviceID, tt.args.portNo, tt.args.sVlan, tt.args.cVlan, tt.args.tpID); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.DeactivateService() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "sVlan != of.VlanNone":
				va.ServiceByName.Store("test_name", voltServiceTest)
				if err := va.DeactivateService(tt.args.cntx, tt.args.deviceID, tt.args.portNo, tt.args.sVlan, tt.args.cVlan, tt.args.tpID); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.DeactivateService() error = %v, wantErr %v", err, tt.wantErr)
				}
			case GetDeviceFromPort_error:
				va.ServiceByName.Store("test_name", voltServiceTest)
				if err := va.DeactivateService(tt.args.cntx, tt.args.deviceID, tt.args.portNo, tt.args.sVlan, tt.args.cVlan, tt.args.tpID); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.DeactivateService() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVoltApplication_ActivateService(t *testing.T) {
	type args struct {
		cntx     context.Context
		deviceID string
		portNo   string
		sVlan    of.VlanType
		cVlan    of.VlanType
		tpID     uint16
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "VoltApplication_ActivateService",
			args: args{
				cntx:     context.Background(),
				deviceID: "test_name",
				portNo:   "test_port",
				sVlan:    of.VlanNone,
				cVlan:    of.VlanAny,
				tpID:     AnyVlan,
			},
		},
		{
			name: "VoltPortVnet_nil",
			args: args{
				cntx:     context.Background(),
				deviceID: "test_name",
				portNo:   "test_port",
				sVlan:    of.VlanNone,
				cVlan:    of.VlanAny,
				tpID:     AnyVlan,
			},
		},
		{
			name: GetDeviceFromPort_error,
			args: args{
				cntx:     context.Background(),
				deviceID: "test_name",
				portNo:   "test_port",
				sVlan:    of.VlanNone,
				cVlan:    of.VlanAny,
				tpID:     AnyVlan,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
			}
			var voltPortTest = &VoltPort{
				Name:  "test_name",
				State: PortStateUp,
			}
			voltServiceTest := &VoltService{
				VoltServiceOper: VoltServiceOper{
					Device: test_device,
				},
				Version: "test_version",
				VoltServiceCfg: VoltServiceCfg{
					Port:        "test_port",
					Name:        "test_name",
					IsActivated: false,
					CVlan:       of.VlanAny,
					SVlan:       of.VlanAny,
					UniVlan:     of.VlanAny,
				},
			}
			switch tt.name {
			case "VoltApplication_ActivateService":
				voltPortTest.Device = test_device
				va.PortsDisc.Store("test_port", voltPortTest)
				va.DevicesDisc.Store(test_device, voltDevice)
				va.ServiceByName.Store("test_name", voltServiceTest)
				va.VnetsByPort.Store("test_port", voltPortVnet1)
				voltDevice.Ports.Store("test_port", voltPortTest)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				if err := va.ActivateService(tt.args.cntx, tt.args.deviceID, tt.args.portNo, tt.args.sVlan, tt.args.cVlan, tt.args.tpID); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.ActivateService() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "VoltPortVnet_nil":
				voltPortTest.Device = test_device
				va.ServiceByName.Store("test_name", voltServiceTest)
				va.PortsDisc.Store("test_port", voltPortTest)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				va.DevicesDisc.Store(test_device, voltDevice)
				voltDevice.Ports.Store("test_port", voltPortTest)
				if err := va.ActivateService(tt.args.cntx, tt.args.deviceID, tt.args.portNo, tt.args.sVlan, tt.args.cVlan, tt.args.tpID); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.ActivateService() error = %v, wantErr %v", err, tt.wantErr)
				}
			case GetDeviceFromPort_error:
				err := va.ActivateService(tt.args.cntx, tt.args.deviceID, tt.args.portNo, tt.args.sVlan, tt.args.cVlan, tt.args.tpID)
				assert.NotNil(t, err)
			}
		})
	}
}

func TestVoltApplication_GetProgrammedSubscribers(t *testing.T) {
	type args struct {
		cntx     context.Context
		deviceID string
		portNo   string
	}
	tests := []struct {
		name    string
		args    args
		want    []*VoltService
		wantErr bool
	}{
		{
			name: "VoltApplication_GetProgrammedSubscribers",
			args: args{
				cntx:     context.Background(),
				deviceID: test_device,
				portNo:   "test_port",
			},
		},
		{
			name: "portNo_nil",
			args: args{
				cntx:     context.Background(),
				deviceID: test_device,
			},
		},
		{
			name: "deviceID_nil",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				vendorID: "test_vendor",
			}
			voltServiceTest := &VoltService{
				VoltServiceOper: VoltServiceOper{
					Device: test_device,
				},
				Version: "test_version",
				VoltServiceCfg: VoltServiceCfg{
					Port:        "test_port",
					Name:        "test_name",
					IsActivated: false,
					CVlan:       of.VlanAny,
					SVlan:       of.VlanAny,
					UniVlan:     of.VlanAny,
				},
			}
			switch tt.name {
			case "VoltApplication_GetProgrammedSubscribers":
				va.ServiceByName.Store("test_name", voltServiceTest)
				got, err := va.GetProgrammedSubscribers(tt.args.cntx, tt.args.deviceID, tt.args.portNo)
				assert.NotNil(t, got)
				assert.Nil(t, err)
			case "portNo_nil":
				va.ServiceByName.Store("test_name", voltServiceTest)
				got, err := va.GetProgrammedSubscribers(tt.args.cntx, tt.args.deviceID, tt.args.portNo)
				assert.NotNil(t, got)
				assert.Nil(t, err)
			case "deviceID_nil":
				va.ServiceByName.Store("test_name", voltServiceTest)
				got, err := va.GetProgrammedSubscribers(tt.args.cntx, tt.args.deviceID, tt.args.portNo)
				assert.NotNil(t, got)
				assert.Nil(t, err)
			}
		})
	}
}

func TestVoltService_JSONMarshal(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "VoltService_JSONMarshal",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := &VoltService{
				VoltServiceOper: VoltServiceOper{
					Device: test_device,
				},
				Version: "test_version",
				VoltServiceCfg: VoltServiceCfg{
					Name: "test_name",
				},
			}
			got, err := vs.JSONMarshal()
			assert.NotNil(t, got)
			assert.Nil(t, err)
		})
	}
}

func TestVoltService_triggerServiceInProgressInd(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "VoltService_triggerServiceInProgressInd",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := &VoltService{
				Version: "test_version",
			}
			vs.triggerServiceInProgressInd()
		})
	}
}

func TestVoltService_TriggerAssociatedFlowDelete(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "VoltService_TriggerAssociatedFlowDelete",
			args: args{
				cntx: context.Background(),
			},
			want: true,
		},
		{
			name: "cookieList_nil",
			args: args{
				cntx: context.Background(),
			},
			want: false,
		},
	}
	associatedFlows := map[string]bool{}
	associatedFlows["5765317"] = true
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "VoltService_TriggerAssociatedFlowDelete":
				vs := &VoltService{
					VoltServiceOper: VoltServiceOper{
						UsHSIAFlowsApplied: true,
						DsHSIAFlowsApplied: true,
						AssociatedFlows:    associatedFlows,
						Device:             test_device,
					},
				}
				ga := GetApplication()
				ga.DevicesDisc.Store(test_device, voltDevice)
				if got := vs.TriggerAssociatedFlowDelete(tt.args.cntx); got != tt.want {
					t.Errorf("VoltService.TriggerAssociatedFlowDelete() = %v, want %v", got, tt.want)
				}
			case "cookieList_nil":
				vs := &VoltService{
					VoltServiceOper: VoltServiceOper{
						UsHSIAFlowsApplied: true,
						DsHSIAFlowsApplied: true,
						Device:             test_device,
					},
				}
				ga := GetApplication()
				ga.DevicesDisc.Store(test_device, voltDevice)
				if got := vs.TriggerAssociatedFlowDelete(tt.args.cntx); got != tt.want {
					t.Errorf("VoltService.TriggerAssociatedFlowDelete() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVoltApplication_DeepEqualServicecfg(t *testing.T) {
	type args struct {
		evs *VoltServiceCfg
		nvs *VoltServiceCfg
	}
	a := map[int]int{}
	a[0] = 0
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "VoltApplication_DeepEqualServicecfg",
			args: args{
				evs: &VoltServiceCfg{
					Port: "test_port",
				},
				nvs: &VoltServiceCfg{
					Port: "test_port",
				},
			},
			want: true,
		},
		{
			name: "nvs.Name != evs.Name",
			args: args{
				evs: &VoltServiceCfg{
					Name: "test_name",
				},
				nvs: &VoltServiceCfg{
					Port: "test_port",
				},
			},
			want: false,
		},
		{
			name: "nvs.UniVlan != evs.UniVlan",
			args: args{
				evs: &VoltServiceCfg{
					UniVlan: of.VlanAny,
				},
				nvs: &VoltServiceCfg{
					Port: "test_port",
				},
			},
			want: false,
		},
		{
			name: "nvs.CVlan != evs.CVlan",
			args: args{
				evs: &VoltServiceCfg{
					CVlan: of.VlanAny,
				},
				nvs: &VoltServiceCfg{
					Port: "test_port",
				},
			},
			want: false,
		},
		{
			name: "nvs.SVlan != evs.SVlan",
			args: args{
				evs: &VoltServiceCfg{
					SVlan: of.VlanAny,
				},
				nvs: &VoltServiceCfg{
					Port: "test_port",
				},
			},
			want: false,
		},
		{
			name: "nvs.SVlanTpid != 0",
			args: args{
				evs: &VoltServiceCfg{
					SVlanTpid: layers.EthernetTypeARP,
				},
				nvs: &VoltServiceCfg{
					SVlanTpid: layers.EthernetTypeCiscoDiscovery,
				},
			},
			want: false,
		},
		{
			name: "nvs.Pbits != evs.Pbits",
			args: args{
				evs: &VoltServiceCfg{
					Pbits: []of.PbitType{
						PbitMatchAll,
					},
				},
				nvs: &VoltServiceCfg{
					Port: "test_port",
				},
			},
			want: false,
		},
		{
			name: "nvs.DsRemarkPbitsMap != evs.DsRemarkPbitsMap",
			args: args{
				evs: &VoltServiceCfg{
					DsRemarkPbitsMap: a,
				},
				nvs: &VoltServiceCfg{
					Port: "test_port",
				},
			},
			want: false,
		},
		{
			name: "nvs.TechProfileID != evs.TechProfileID",
			args: args{
				evs: &VoltServiceCfg{
					TechProfileID: uint16(1),
				},
				nvs: &VoltServiceCfg{
					Port: "test_port",
				},
			},
			want: false,
		},
		{
			name: "nvs.CircuitID != evs.CircuitID",
			args: args{
				evs: &VoltServiceCfg{
					CircuitID: "test_circuit_id",
				},
				nvs: &VoltServiceCfg{
					Port: "test_port",
				},
			},
			want: false,
		},
		{
			name: "nvs.RemoteID != evs.RemoteID",
			args: args{
				evs: &VoltServiceCfg{
					RemoteID: []byte{1},
				},
				nvs: &VoltServiceCfg{
					Port: "test_port",
				},
			},
			want: false,
		},
		{
			name: "nvs.Port != evs.Port",
			args: args{
				evs: &VoltServiceCfg{},
				nvs: &VoltServiceCfg{
					Port: "test_port",
				},
			},
			want: false,
		},
		{
			name: "nvs.PonPort != evs.PonPort",
			args: args{
				evs: &VoltServiceCfg{},
				nvs: &VoltServiceCfg{
					PonPort: uint32(1),
				},
			},
			want: false,
		},
		{
			name: "evs.MacLearning == MacLearningNone",
			args: args{
				evs: &VoltServiceCfg{
					MacAddr: layers.EthernetBroadcast,
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.IgmpEnabled != evs.IgmpEnabled",
			args: args{
				evs: &VoltServiceCfg{
					IgmpEnabled: true,
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.McastService != evs.McastService",
			args: args{
				evs: &VoltServiceCfg{
					McastService: true,
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.ONTEtherTypeClassification != evs.ONTEtherTypeClassification",
			args: args{
				evs: &VoltServiceCfg{
					ONTEtherTypeClassification: 1,
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.UsMeterProfile != evs.UsMeterProfile",
			args: args{
				evs: &VoltServiceCfg{
					UsMeterProfile: "UsMeterProfile",
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.DsMeterProfile != evs.DsMeterProfile",
			args: args{
				evs: &VoltServiceCfg{
					DsMeterProfile: "DsMeterProfile",
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.AggDsMeterProfile != evs.AggDsMeterProfile",
			args: args{
				evs: &VoltServiceCfg{
					AggDsMeterProfile: "AggDsMeterProfile",
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.VnetID != evs.VnetID",
			args: args{
				evs: &VoltServiceCfg{
					VnetID: "VnetID",
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.MvlanProfileName != evs.MvlanProfileName",
			args: args{
				evs: &VoltServiceCfg{
					MvlanProfileName: "MvlanProfileName",
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.RemoteIDType != evs.RemoteIDType",
			args: args{
				evs: &VoltServiceCfg{
					RemoteIDType: "RemoteIDType",
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.SchedID != evs.SchedID",
			args: args{
				evs: &VoltServiceCfg{
					SchedID: 1,
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.AllowTransparent != evs.AllowTransparent",
			args: args{
				evs: &VoltServiceCfg{
					AllowTransparent: true,
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.EnableMulticastKPI != evs.EnableMulticastKPI",
			args: args{
				evs: &VoltServiceCfg{
					EnableMulticastKPI: true,
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.DataRateAttr != evs.DataRateAttr",
			args: args{
				evs: &VoltServiceCfg{
					DataRateAttr: "DataRateAttr",
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.MinDataRateUs != evs.MinDataRateUs",
			args: args{
				evs: &VoltServiceCfg{
					MinDataRateUs: uint32(1),
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.MinDataRateDs != evs.MinDataRateDs",
			args: args{
				evs: &VoltServiceCfg{
					MinDataRateDs: uint32(1),
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.MaxDataRateUs != evs.MaxDataRateUs",
			args: args{
				evs: &VoltServiceCfg{
					MaxDataRateUs: uint32(1),
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
		{
			name: "nvs.MaxDataRateDs != evs.MaxDataRateDs",
			args: args{
				evs: &VoltServiceCfg{
					MaxDataRateDs: uint32(1),
				},
				nvs: &VoltServiceCfg{},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				vendorID: "test_vendor_id",
			}
			switch tt.name {
			case "VoltApplication_DeepEqualServicecfg", "nvs.Name != evs.Name", "nvs.UniVlan != evs.UniVlan",
				"nvs.CVlan != evs.CVlan", "nvs.SVlan != evs.SVlan", "nvs.SVlanTpid != 0", "nvs.Pbits != evs.Pbits",
				"nvs.DsRemarkPbitsMap != evs.DsRemarkPbitsMap", "nvs.TechProfileID != evs.TechProfileID",
				"nvs.CircuitID != evs.CircuitID", "nvs.RemoteID != evs.RemoteID", "nvs.Port != evs.Port",
				"evs.MacLearning == MacLearningNone", "nvs.PonPort != evs.PonPort", "nvs.IgmpEnabled != evs.IgmpEnabled",
				"nvs.McastService != evs.McastService", "nvs.ONTEtherTypeClassification != evs.ONTEtherTypeClassification",
				"nvs.UsMeterProfile != evs.UsMeterProfile",
				"nvs.DsMeterProfile != evs.DsMeterProfile", "nvs.AggDsMeterProfile != evs.AggDsMeterProfile",
				"nvs.VnetID != evs.VnetID", "nvs.MvlanProfileName != evs.MvlanProfileName",
				"nvs.RemoteIDType != evs.RemoteIDType", "nvs.SchedID != evs.SchedID",
				"nvs.AllowTransparent != evs.AllowTransparent",
				"nvs.EnableMulticastKPI != evs.EnableMulticastKPI", "nvs.DataRateAttr != evs.DataRateAttr",
				"nvs.MinDataRateUs != evs.MinDataRateUs", "nvs.MinDataRateDs != evs.MinDataRateDs",
				"nvs.MaxDataRateUs != evs.MaxDataRateUs", "nvs.MaxDataRateDs != evs.MaxDataRateDs":
				if got := va.DeepEqualServicecfg(tt.args.evs, tt.args.nvs); got != tt.want {
					t.Errorf("VoltApplication.DeepEqualServicecfg() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
