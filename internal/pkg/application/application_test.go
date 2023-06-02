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
	"sync"
	"testing"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
	"github.com/stretchr/testify/assert"
)

func TestVoltApplication_RestoreNbDeviceFromDb(t *testing.T) {
	type args struct {
		cntx     context.Context
		deviceID string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_RestoreNbDeviceFromDb",
			args: args{
				cntx:     context.Background(),
				deviceID: "test_device_id",
			},
		},
		{
			name: "VoltApplication_RestoreNbDeviceFromDb_invalid_Value_type",
			args: args{
				cntx:     context.Background(),
				deviceID: "test_device_id1",
			},
		},
		{
			name: "VoltApplication_RestoreNbDeviceFromDb_unmarshal_error",
			args: args{
				cntx:     context.Background(),
				deviceID: "test_device_id1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				NbDevice: sync.Map{},
			}
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			switch tt.name {
			case "VoltApplication_RestoreNbDeviceFromDb":
				var port PonPortCfg
				port = PonPortCfg{
					PortAlarmProfileID: "test",
					PortID:             256,
					MaxActiveChannels:  256,
					ActiveIGMPChannels: 7679,
					EnableMulticastKPI: false,
				}
				b, err := json.Marshal(port)
				if err != nil {
					panic(err)
				}
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: b,
				}
				dbintf.EXPECT().GetAllNbPorts(gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				got := va.RestoreNbDeviceFromDb(tt.args.cntx, tt.args.deviceID)
				assert.NotNil(t, got)
			case "VoltApplication_RestoreNbDeviceFromDb_invalid_Value_type":
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: "invalid_value",
				}
				dbintf.EXPECT().GetAllNbPorts(gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				got := va.RestoreNbDeviceFromDb(tt.args.cntx, tt.args.deviceID)
				assert.NotNil(t, got)
			case "VoltApplication_RestoreNbDeviceFromDb_unmarshal_error":
				b, err := json.Marshal("error")
				if err != nil {
					panic(err)
				}
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: b,
				}
				dbintf.EXPECT().GetAllNbPorts(gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				got := va.RestoreNbDeviceFromDb(tt.args.cntx, tt.args.deviceID)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestVoltApplication_AddNbPonPort(t *testing.T) {
	type args struct {
		cntx               context.Context
		oltSbID            string
		portID             uint32
		maxAllowedChannels uint32
		enableMulticastKPI bool
		portAlarmProfileID string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "VoltApplication_AddNbPonPort",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				NbDevice: sync.Map{},
			}
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutNbDevicePort(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			if err := va.AddNbPonPort(tt.args.cntx, tt.args.oltSbID, tt.args.portID, tt.args.maxAllowedChannels, tt.args.enableMulticastKPI, tt.args.portAlarmProfileID); (err != nil) != tt.wantErr {
				t.Errorf("VoltApplication.AddNbPonPort() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVoltApplication_PortUpdateInd(t *testing.T) {
	type args struct {
		device   string
		portName string
		id       uint32
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_PortUpdateInd",
			args: args{
				device:   "test_device",
				portName: "test_port_name",
				id:       1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				portLock: sync.Mutex{},
			}
			va.PortUpdateInd(tt.args.device, tt.args.portName, tt.args.id)
		})
	}
}

func TestVoltApplication_DelDevice(t *testing.T) {
	type args struct {
		cntx   context.Context
		device string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "DelDevice_device_not_found",
			args: args{
				cntx:   context.Background(),
				device: "test_device",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
			}
			va.DelDevice(tt.args.cntx, tt.args.device)
		})
	}
}

func TestVoltApplication_UpdateDeviceConfig(t *testing.T) {
	type args struct {
		cntx         context.Context
		deviceConfig *DeviceConfig
	}

	dvcConfg := &DeviceConfig{
		SerialNumber:       "SDX6320031",
		HardwareIdentifier: "0.0.0.0",
		IPAddress:          "127.26.1.74",
		UplinkPort:         "43322",
		NasID:              "12345",
		NniDhcpTrapVid:     123,
	}

	voltDev := &VoltDevice{
		Name:           "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "SDX6320031",
			args: args{
				cntx:         context.Background(),
				deviceConfig: dvcConfg,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc:   sync.Map{},
				DevicesConfig: sync.Map{},
			}
			va.DevicesDisc.Store("SDX6320031", voltDev)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutDeviceConfig(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

			va.UpdateDeviceConfig(tt.args.cntx, tt.args.deviceConfig)
		})
	}
}

func TestVoltApplication_RestoreOltFlowService(t *testing.T) {
	type fields struct {
		OltFlowServiceConfig OltFlowService
	}
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "OltFlowService",
			args: args{
				cntx: context.Background(),
			},
			fields: fields{
				OltFlowServiceConfig: OltFlowService{
					DefaultTechProfileID: 1233,
					EnableDhcpOnNni:      true,
					EnableIgmpOnNni:      false,
					RemoveFlowsOnDisable: false,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				OltFlowServiceConfig: tt.fields.OltFlowServiceConfig,
			}

			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().GetOltFlowService(gomock.Any()).AnyTimes()

			va.RestoreOltFlowService(tt.args.cntx)
		})
	}
}

func TestVoltApplication_UpdateOltFlowService(t *testing.T) {
	type fields struct {
		OltFlowServiceConfig OltFlowService
	}
	type args struct {
		cntx           context.Context
		oltFlowService OltFlowService
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "OltFlowService",
			args: args{
				cntx: context.Background(),
				oltFlowService: OltFlowService{
					DefaultTechProfileID: 1233,
					EnableDhcpOnNni:      true,
					EnableIgmpOnNni:      false,
					RemoveFlowsOnDisable: false,
				},
			},
			fields: fields{
				OltFlowServiceConfig: OltFlowService{
					DefaultTechProfileID: 1233,
					EnableDhcpOnNni:      true,
					EnableIgmpOnNni:      false,
					RemoveFlowsOnDisable: false,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				OltFlowServiceConfig: tt.fields.OltFlowServiceConfig,
			}

			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutOltFlowService(gomock.Any(), gomock.Any()).AnyTimes()
			va.UpdateOltFlowService(tt.args.cntx, tt.args.oltFlowService)
		})
	}
}

func TestVoltApplication_TriggerPendingVpvDeleteReq(t *testing.T) {
	type args struct {
		cntx   context.Context
		device string
	}
	macAdd, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	test := map[*VoltPortVnet]bool{}
	test[&VoltPortVnet{Device: "SDX6320031", Port: "16777472", MacAddr: macAdd}] = true
	tests := []struct {
		name string
		args args
	}{
		{
			name: "SDX6320031",
			args: args{
				cntx:   context.Background(),
				device: "SDX6320031",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				VoltPortVnetsToDelete: test,
			}
			va.TriggerPendingVpvDeleteReq(tt.args.cntx, tt.args.device)
		})
	}
}

func TestVoltApplication_TriggerPendingProfileDeleteReq(t *testing.T) {
	type args struct {
		cntx   context.Context
		device string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "SDX6320031",
			args: args{
				cntx:   context.Background(),
				device: "SDX6320031",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
			}
			va.TriggerPendingProfileDeleteReq(tt.args.cntx, tt.args.device)
		})
	}
}

func TestVoltApplication_TriggerPendingServiceDeleteReq(t *testing.T) {
	type args struct {
		cntx   context.Context
		device string
	}
	voltServ := &VoltService{
		VoltServiceOper: VoltServiceOper{
			Device:      "SDX6320031",
			ForceDelete: true,
		},
	}

	servicesToDel := map[string]bool{}
	servicesToDel["SCOM00001c75-1_SCOM00001c75-1-4096-2310-4096-65"] = true

	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_TriggerPendingServiceDeleteReq",
			args: args{
				cntx:   context.Background(),
				device: "SDX6320031",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				ServicesToDelete: servicesToDel,
				ServiceByName:    sync.Map{},
				DevicesDisc:      sync.Map{},
			}

			va.ServiceByName.Store("SCOM00001c75-1_SCOM00001c75-1-4096-2310-4096-65", voltServ)

			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			dbintf.EXPECT().DelService(gomock.Any(), gomock.Any()).AnyTimes()
			va.TriggerPendingServiceDeleteReq(tt.args.cntx, tt.args.device)
		})
	}
}

func TestVoltApplication_TriggerPendingVnetDeleteReq(t *testing.T) {
	type args struct {
		cntx   context.Context
		device string
	}

	vnetToDel := map[string]bool{}
	vnetToDel["2310-4096-4096"] = true

	voltVnet := &VoltVnet{
		Version: "v3",
		VnetConfig: VnetConfig{
			Name:      "2310-4096-4096",
			VnetType:  "Encapsulation",
			SVlan:     2310,
			CVlan:     4096,
			UniVlan:   4096,
			SVlanTpid: 33024,
		},
		VnetOper: VnetOper{
			PendingDeviceToDelete: "SDX63200313",
		},
	}
	voltDev := &VoltDevice{
		Name:           "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "Negative_Case_TriggerPendingVnetDeleteReq",
			args: args{
				cntx:   context.Background(),
				device: "SDX6320031",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				VnetsToDelete: vnetToDel,
				DevicesDisc:   sync.Map{},
			}
			va.DevicesDisc.Store("SDX6320031", voltDev)
			va.VnetsByName.Store("2310-4096-4096", voltVnet)
			va.TriggerPendingVnetDeleteReq(tt.args.cntx, tt.args.device)
		})
	}
}
