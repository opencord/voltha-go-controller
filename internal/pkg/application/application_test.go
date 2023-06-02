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
	"voltha-go-controller/internal/pkg/intf"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
	"github.com/stretchr/testify/assert"
	"go.uber.org/atomic"
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

func TestVoltApplication_UpdateMacInPortMap(t *testing.T) {
	type args struct {
		macAddr net.HardwareAddr
		port    string
	}
	macAdd, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	macPort := map[string]string{}
	macPort[macAdd.String()] = "1234"
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_UpdateMacInPortMap",
			args: args{
				macAddr: macAdd,
				port:    "1234",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				macPortMap: macPort,
			}
			va.UpdateMacInPortMap(tt.args.macAddr, tt.args.port)
		})
	}
}

func TestVoltApplication_GetMacInPortMap(t *testing.T) {
	type args struct {
		macAddr net.HardwareAddr
	}
	macAdd, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	macPort := map[string]string{}
	macPort[macAdd.String()] = "1234"
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_GetMacInPortMap",
			args: args{
				macAddr: macAdd,
			},
			want: "1234",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				macPortMap: macPort,
			}
			if got := va.GetMacInPortMap(tt.args.macAddr); got != tt.want {
				t.Errorf("VoltApplication.GetMacInPortMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_pushFlowFailureNotif(t *testing.T) {
	type args struct {
		flowStatus intf.FlowStatus
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_pushFlowFailureNotif",
			args: args{
				flowStatus: intf.FlowStatus{
					Device: "SDX6320031",
					Cookie: "68786618880",
					Status: 0,
					Flow: &of.VoltSubFlow{
						Cookie:      68786618880,
						TableID:     0,
						Priority:    100,
						ErrorReason: "",
						OldCookie:   0,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pushFlowFailureNotif(tt.args.flowStatus)
		})
	}
}

func TestGetPonPortIDFromUNIPort(t *testing.T) {
	type args struct {
		uniPortID uint32
	}
	tests := []struct {
		name string
		args args
		want uint32
	}{
		{
			name: "Positive_Case_pushFlowFailureNotif",
			args: args{
				uniPortID: 1049600,
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetPonPortIDFromUNIPort(tt.args.uniPortID); got != tt.want {
				t.Errorf("GetPonPortIDFromUNIPort() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltApplication_ProcessFlowModResultIndication(t *testing.T) {
	type args struct {
		cntx       context.Context
		flowStatus intf.FlowStatus
	}
	voltDev := &VoltDevice{
		Name:            "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:       "SDX6320031",
		NniDhcpTrapVid:  123,
		FlowAddEventMap: util.NewConcurrentMap(),
	}
	flowState := intf.FlowStatus{
		Device:      "SDX6320031",
		Cookie:      "68786618880",
		Status:      1005,
		FlowModType: 0,
		Flow: &of.VoltSubFlow{
			Cookie:    68786618880,
			OldCookie: 0,
			TableID:   0,
			State:     0,
			Priority:  100,
		},
	}
	flowAddEvent := map[string]*FlowEvent{}
	flowEvent := &FlowEvent{
		device: "SDX6320031",
		cookie: "68786618880",
		eType:  EventTypeControlFlowAdded,
	}
	flowAddEvent["68786618880"] = flowEvent
	voltDev.FlowAddEventMap.Set("6878661888", flowEvent)
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_ProcessFlowModResultIndication",
			args: args{
				cntx:       context.Background(),
				flowStatus: flowState,
			},
		},
		{
			name: "Negetive_Case_ProcessFlowModResultIndication",
			args: args{
				cntx:       context.Background(),
				flowStatus: flowState,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_ProcessFlowModResultIndication":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				va.ProcessFlowModResultIndication(tt.args.cntx, tt.args.flowStatus)
			case "Negetive_Case_ProcessFlowModResultIndication":
				va.ProcessFlowModResultIndication(tt.args.cntx, tt.args.flowStatus)
			}
		})
	}
}
func Test_getPendingPoolKey(t *testing.T) {
	type args struct {
		mvlan  of.VlanType
		device string
	}

	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_getPendingPoolKey",
			args: args{
				mvlan:  of.VlanAny,
				device: "SDX6320031",
			},
			want: "4096_SDX6320031",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getPendingPoolKey(tt.args.mvlan, tt.args.device); got != tt.want {
				t.Errorf("getPendingPoolKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewVoltPort(t *testing.T) {
	type args struct {
		device string
		name   string
		id     uint32
	}

	voltPort := &VoltPort{
		Name:                     "49686e2d-618f-4e8e-bca0-442ab850a63a",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateDown,
		ChannelPerSubAlarmRaised: false,
		Type:                     VoltPortTypeNni,
	}

	voltPort1 := &VoltPort{
		Name:                     "49686e2d-618f-4e8e-bca0-442ab850a63a",
		Device:                   "SDX6320031",
		ID:                       1049600,
		State:                    PortStateDown,
		ChannelPerSubAlarmRaised: false,
		PonPort:                  GetPonPortIDFromUNIPort(1049600),
	}
	tests := []struct {
		name string
		args args
		want *VoltPort
	}{
		{
			name: "Positive_Case_TestNewVoltPort",
			args: args{
				id:     16777472,
				device: "SDX6320031",
				name:   "49686e2d-618f-4e8e-bca0-442ab850a63a",
			},
			want: voltPort,
		},
		{
			name: "Positive_Case2_TestNewVoltPort",
			args: args{
				id:     1049600,
				device: "SDX6320031",
				name:   "49686e2d-618f-4e8e-bca0-442ab850a63a",
			},
			want: voltPort1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "Positive_Case_TestNewVoltPort":
				if got := NewVoltPort(tt.args.device, tt.args.name, tt.args.id); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("NewVoltPort() = %v, want %v", got, tt.want)
				}
			case "Positive_Case2_TestNewVoltPort":
				if got := NewVoltPort(tt.args.device, tt.args.name, tt.args.id); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("NewVoltPort() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVoltPort_SetPortID(t *testing.T) {
	type args struct {
		id uint32
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_TestNewVoltPort",
			args: args{
				id: 16777472,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp := &VoltPort{
				ID:   16777472,
				Type: VoltPortTypeNni,
			}
			vp.SetPortID(tt.args.id)
		})
	}
}

func TestNewVoltDevice(t *testing.T) {
	type args struct {
		name         string
		slno         string
		southBoundID string
	}

	devConfig := &DeviceConfig{
		SerialNumber:   "SDX6320033",
		NniDhcpTrapVid: 4,
	}
	voltDevice := &VoltDevice{
		Name:                         "11c3175b-50f3-4220-9555-93df733ded1d",
		SerialNum:                    "SDX6320033",
		SouthBoundID:                 "68580342-6b3e-57cb-9ea4-06125594e330",
		State:                        controller.DeviceStateDOWN,
		NniPort:                      "",
		icmpv6GroupAdded:             false,
		IgmpDsFlowAppliedForMvlan:    make(map[uint16]bool),
		ConfiguredVlanForDeviceFlows: util.NewConcurrentMap(),
		MigratingServices:            util.NewConcurrentMap(),
		VpvsBySvlan:                  util.NewConcurrentMap(),
		FlowAddEventMap:              util.NewConcurrentMap(),
		FlowDelEventMap:              util.NewConcurrentMap(),
		GlobalDhcpFlowAdded:          false,
		NniDhcpTrapVid:               4,
	}

	GetApplication().DevicesConfig.Store("SDX6320033", devConfig)
	tests := []struct {
		name string
		args args
		want *VoltDevice
	}{
		{
			name: "Positive_Case_TestNewVoltDevice",
			args: args{
				name:         "11c3175b-50f3-4220-9555-93df733ded1d",
				slno:         "SDX6320033",
				southBoundID: "68580342-6b3e-57cb-9ea4-06125594e330",
			},
			want: voltDevice,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewVoltDevice(tt.args.name, tt.args.slno, tt.args.southBoundID); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewVoltDevice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltApplication_GetAssociatedVpvsForDevice(t *testing.T) {
	type args struct {
		device string
		svlan  of.VlanType
	}

	voltDev := &VoltDevice{
		Name:           "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:      "SDX6320033",
		NniDhcpTrapVid: 123,
		VpvsBySvlan:    util.NewConcurrentMap(),
	}

	cuncurrentMap := &util.ConcurrentMap{
		Count: atomic.NewUint64(0),
	}

	voltDev1 := &VoltDevice{
		Name:           "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:      "SDX6320033",
		NniDhcpTrapVid: 123,
		VpvsBySvlan:    cuncurrentMap,
	}
	tests := []struct {
		name string
		args args
		want *util.ConcurrentMap
	}{
		{
			name: "Positive_Case_GetAssociatedVpvsForDevice",
			args: args{
				device: "SDX6320033",
				svlan:  of.VlanAny,
			},
			want: util.NewConcurrentMap(),
		},
		{
			name: "Positive_Case2_GetAssociatedVpvsForDevice",
			args: args{
				device: "SDX6320033",
				svlan:  of.VlanAny,
			},
			want: cuncurrentMap,
		},
		{
			name: "Negetive_Case2_GetAssociatedVpvsForDevice",
			args: args{
				device: "SDX6320031",
				svlan:  of.VlanAny,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "Positive_Case_GetAssociatedVpvsForDevice":
				va := &VoltApplication{
					DevicesDisc:  sync.Map{},
					VnetsBySvlan: util.NewConcurrentMap(),
				}
				va.DevicesDisc.Store("SDX6320033", voltDev)
				if got := va.GetAssociatedVpvsForDevice(tt.args.device, tt.args.svlan); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltApplication.GetAssociatedVpvsForDevice() = %v, want %v", got, tt.want)
				}
			case "Positive_Case2_GetAssociatedVpvsForDevice":
				va1 := &VoltApplication{
					DevicesDisc:  sync.Map{},
					VnetsBySvlan: cuncurrentMap,
				}
				va1.DevicesDisc.Store("SDX6320033", voltDev1)
				va1.VnetsBySvlan.Set(of.VlanAny, cuncurrentMap)
				if got := va1.GetAssociatedVpvsForDevice(tt.args.device, tt.args.svlan); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltApplication.GetAssociatedVpvsForDevice() = %v, want %v", got, tt.want)
				}
			case "Negetive_Case2_GetAssociatedVpvsForDevice":
				va1 := &VoltApplication{
					DevicesDisc: sync.Map{},
				}
				if got := va1.GetAssociatedVpvsForDevice(tt.args.device, tt.args.svlan); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltApplication.GetAssociatedVpvsForDevice() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
