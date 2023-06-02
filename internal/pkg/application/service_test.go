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

var voltPort = &VoltPort{
	Name:   "test_name",
	Device: "test_device",
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
		Device: "4096-4096-4096",
	},
}

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
			ga.DevicesDisc = sync.Map{}
			ga.DevicesDisc.Store("SDX6320031", voltDev)
			voltPortVnets := make([]*VoltPortVnet, 0)
			voltPortVnet := &VoltPortVnet{
				Device:      "test_device",
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
			vs.Port = "test_device"
			vs.Device = "device"
			ga := GetApplication()
			ga.PortsDisc = sync.Map{}
			ga.DevicesDisc = sync.Map{}
			_ = cntlr.NewController(context.Background(), mocks.NewMockApp(gomock.NewController(t)))
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			ga.PortsDisc.Store("test_device", voltPort)
			ga.DevicesDisc.Store("test_device", voltDevice)
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
			vs.Port = "test_device"
			vs.Device = "device"
			ga := GetApplication()
			ga.PortsDisc = sync.Map{}
			ga.DevicesDisc = sync.Map{}
			_ = cntlr.NewController(context.Background(), mocks.NewMockApp(gomock.NewController(t)))
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			ga.PortsDisc.Store("test_device", voltPort)
			ga.DevicesDisc.Store("test_device", voltDevice)
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
			ga.PortsDisc = sync.Map{}
			ga.DevicesDisc = sync.Map{}
			ga.DevicesConfig = sync.Map{}
			voltPort1 := &VoltPort{
				Name:   "test_name",
				Device: "test_device",
			}
			deviceConfig := &DeviceConfig{
				SerialNumber: "test_serial_number",
			}
			ga.PortsDisc.Store("test_port", voltPort1)
			ga.DevicesDisc.Store("test_device", voltDevice)
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
			ga.DevicesDisc = sync.Map{}
			ga.PortsDisc = sync.Map{}
			ga.PortsDisc.Store("test_port", voltPort)
			ga.DevicesDisc.Store("test_device", voltDevice)
			vs.FlowInstallSuccess(tt.args.cntx, tt.args.cookie, tt.args.bwAvailInfo)
		})
	}
}
