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

func TestVoltApplication_AssociateVpvsToDevice(t *testing.T) {
	type args struct {
		device string
		vpv    *VoltPortVnet
	}

	vpv := &VoltPortVnet{
		Device: "SDX6320033",
		SVlan:  of.VlanAny,
	}
	voltDev := &VoltDevice{
		Name:           "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:      "SDX6320033",
		NniDhcpTrapVid: 123,
		VpvsBySvlan:    util.NewConcurrentMap(),
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_AssociateVpvsToDevice",
			args: args{
				device: "SDX6320033",
				vpv:    vpv,
			},
		},
		{
			name: "Negetive_Case_AssociateVpvsToDevice",
			args: args{
				device: "SDX6320033",
				vpv:    vpv,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "Positive_Case_AssociateVpvsToDevice":
				va := &VoltApplication{
					DevicesDisc:  sync.Map{},
					VnetsBySvlan: util.NewConcurrentMap(),
				}
				va.DevicesDisc.Store("SDX6320033", voltDev)
				va.AssociateVpvsToDevice(tt.args.device, tt.args.vpv)
			case "Negetive_Case_AssociateVpvsToDevice":
				va := &VoltApplication{
					DevicesDisc:  sync.Map{},
					VnetsBySvlan: util.NewConcurrentMap(),
				}
				va.AssociateVpvsToDevice(tt.args.device, tt.args.vpv)
			}
		})
	}
}

func TestVoltApplication_DisassociateVpvsFromDevice(t *testing.T) {
	type args struct {
		device string
		vpv    *VoltPortVnet
	}
	vpv := &VoltPortVnet{
		Device: "SDX6320033",
		SVlan:  of.VlanAny,
	}

	voltDev := &VoltDevice{
		Name:           "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:      "SDX6320033",
		NniDhcpTrapVid: 123,
		VpvsBySvlan:    util.NewConcurrentMap(),
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_DisassociateVpvsFromDevice",
			args: args{
				device: "SDX6320033",
				vpv:    vpv,
			},
		},
		{
			name: "Negetive_Case_DisassociateVpvsFromDevice",
			args: args{
				device: "SDX6320033",
				vpv:    vpv,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "Positive_Case_DisassociateVpvsFromDevice":
				va := &VoltApplication{
					DevicesDisc:  sync.Map{},
					VnetsBySvlan: util.NewConcurrentMap(),
				}
				va.DevicesDisc.Store("SDX6320033", voltDev)
				va.DisassociateVpvsFromDevice(tt.args.device, tt.args.vpv)
			case "Negetive_Case_DisassociateVpvsFromDevice":
				va := &VoltApplication{
					DevicesDisc:  sync.Map{},
					VnetsBySvlan: util.NewConcurrentMap(),
				}
				va.DisassociateVpvsFromDevice(tt.args.device, tt.args.vpv)
			}
		})
	}
}

func TestVoltDevice_GetPort(t *testing.T) {
	type args struct {
		port string
	}
	voltPort := &VoltPort{
		Name:                     "49686e2d-618f-4e8e-bca0-442ab850a63a",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateDown,
		ChannelPerSubAlarmRaised: false,
		Type:                     VoltPortTypeNni,
	}
	tests := []struct {
		name string
		args args
		want *VoltPort
	}{
		{
			name: "Positive_Case_GetPort",
			args: args{
				port: "16777472",
			},
			want: voltPort,
		},
		{
			name: "Negetive_Case_GetPort",
			args: args{
				port: "16777472",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &VoltDevice{
				Ports: sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_GetPort":
				d.Ports.Store("16777472", voltPort)
				if got := d.GetPort(tt.args.port); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltDevice.GetPort() = %v, want %v", got, tt.want)
				}
			case "Negetive_Case_GetPort":
				if got := d.GetPort(tt.args.port); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltDevice.GetPort() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVoltDevice_GetPortNameFromPortID(t *testing.T) {
	type args struct {
		portID uint32
	}
	voltPort := &VoltPort{
		Name:                     "49686e2d-618f-4e8e-bca0-442ab850a63a",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateDown,
		ChannelPerSubAlarmRaised: false,
		Type:                     VoltPortTypeNni,
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_GetPort",
			args: args{
				portID: 16777472,
			},
			want: "49686e2d-618f-4e8e-bca0-442ab850a63a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &VoltDevice{
				Ports: sync.Map{},
			}
			d.Ports.Store(16777472, voltPort)
			if got := d.GetPortNameFromPortID(tt.args.portID); got != tt.want {
				t.Errorf("VoltDevice.GetPortNameFromPortID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltDevice_DelPort(t *testing.T) {
	type args struct {
		port string
	}
	voltPort := &VoltPort{
		Name:                     "49686e2d-618f-4e8e-bca0-442ab850a63a",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateDown,
		ChannelPerSubAlarmRaised: false,
		Type:                     VoltPortTypeNni,
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_DelPort",
			args: args{
				port: "16777472",
			},
		},
		{
			name: "Negetive_Case_DelPort",
			args: args{
				port: "16777472",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &VoltDevice{
				Ports: sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_DelPort":
				d.Ports.Store("16777472", voltPort)
				d.DelPort(tt.args.port)
			case "Negetive_Case_DelPort":
				d.DelPort(tt.args.port)
			}
		})
	}
}

func TestVoltDevice_pushFlowsForUnis(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_pushFlowsForUnis",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "Negetive_Case_pushFlowsForUnis",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "Negetive_Case1_pushFlowsForUnis",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &VoltDevice{
				Name:      "SDX6320031",
				SerialNum: "SDX6320031",
				Ports:     sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_pushFlowsForUnis":
				voltPort := &VoltPort{
					Name:                     "16777472",
					Device:                   "SDX6320031",
					ID:                       16777472,
					State:                    PortStateUp,
					ChannelPerSubAlarmRaised: false,
					Type:                     VoltPortTypeNni,
				}
				d.Ports.Store("16777472", voltPort)
				ga := GetApplication()
				voltPortVnets := make([]*VoltPortVnet, 0)
				voltPortVnet := &VoltPortVnet{
					Device:           "SDX6320031",
					Port:             "16777472",
					DeleteInProgress: true,
				}
				voltPortVnets = append(voltPortVnets, voltPortVnet)
				ga.VnetsByPort.Store("16777472", voltPortVnets)

				d.pushFlowsForUnis(tt.args.cntx)
			case "Negetive_Case_pushFlowsForUnis":
				voltPort1 := &VoltPort{
					Name:                     "16777472",
					Device:                   "SDX6320031",
					ID:                       16777472,
					State:                    PortStateDown,
					ChannelPerSubAlarmRaised: false,
					Type:                     VoltPortTypeNni,
				}
				d.Ports.Store("16777472", voltPort1)
				d.pushFlowsForUnis(tt.args.cntx)
			case "Negetive_Case1_pushFlowsForUnis":
				voltPort2 := &VoltPort{
					Name:                     "16777472",
					Device:                   "SDX6320031",
					ID:                       16777472,
					State:                    PortStateUp,
					ChannelPerSubAlarmRaised: false,
					Type:                     VoltPortTypeNni,
				}
				d.Ports.Store("1677747", voltPort2)
				d.pushFlowsForUnis(tt.args.cntx)
			}
		})
	}
}

func TestNewNbDevice(t *testing.T) {
	tests := []struct {
		name string
		want *NbDevice
	}{
		{
			name: "Positive_Case_pushFlowsForUnis",
			want: &NbDevice{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewNbDevice(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewNbDevice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNbDevice_WriteToDb(t *testing.T) {
	type args struct {
		cntx    context.Context
		portID  uint32
		ponPort *PonPortCfg
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_pushFlowsForUnis",
			args: args{
				cntx:   context.Background(),
				portID: controller.NNIPortID,
				ponPort: &PonPortCfg{
					PortID:             controller.NNIPortID,
					EnableMulticastKPI: false,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nbd := &NbDevice{
				SouthBoundID: "49686e2d-618f-4e8e-bca0-442ab850a63a",
			}
			switch tt.name {
			case "Positive_Case_pushFlowsForUnis":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutNbDevicePort(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
				nbd.WriteToDb(tt.args.cntx, tt.args.portID, tt.args.ponPort)
			}
		})
	}
}

func TestNbDevice_AddPortToNbDevice(t *testing.T) {
	type args struct {
		cntx               context.Context
		portID             uint32
		allowedChannels    uint32
		enableMulticastKPI bool
		portAlarmProfileID string
	}
	ponPort := &PonPortCfg{
		PortID:             controller.NNIPortID,
		MaxActiveChannels:  123,
		EnableMulticastKPI: false,
		PortAlarmProfileID: "16777",
	}
	tests := []struct {
		name string
		args args
		want *PonPortCfg
	}{
		{
			name: "Positive_Case_AddPortToNbDevice",
			args: args{
				cntx:               context.Background(),
				portID:             controller.NNIPortID,
				allowedChannels:    123,
				enableMulticastKPI: false,
				portAlarmProfileID: "16777",
			},
			want: ponPort,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nbd := &NbDevice{
				SouthBoundID: "49686e2d-618f-4e8e-bca0-442ab850a63a",
				PonPorts:     sync.Map{},
			}
			nbd.PonPorts.Store(controller.NNIPortID, ponPort)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutNbDevicePort(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			if got := nbd.AddPortToNbDevice(tt.args.cntx, tt.args.portID, tt.args.allowedChannels, tt.args.enableMulticastKPI, tt.args.portAlarmProfileID); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NbDevice.AddPortToNbDevice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltApplication_AddDeviceConfig(t *testing.T) {
	type args struct {
		cntx               context.Context
		serialNum          string
		hardwareIdentifier string
		nasID              string
		ipAddress          string
		uplinkPort         string
		nniDhcpTrapID      int
	}
	dvcConfg := &DeviceConfig{
		SerialNumber:       "SDX6320031",
		HardwareIdentifier: "0.0.0.0",
		IPAddress:          "127.26.1.74",
		UplinkPort:         "16777216",
		NasID:              "12345",
		NniDhcpTrapVid:     123,
	}
	voltDev := &VoltDevice{
		Name:           "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Positive_Case_AddDeviceConfig",
			args: args{
				cntx:               context.Background(),
				serialNum:          "SDX6320031",
				hardwareIdentifier: "0.0.0.0.",
				nasID:              "12345",
				ipAddress:          "127.26.1.74",
				uplinkPort:         "16777216",
				nniDhcpTrapID:      123,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesConfig: sync.Map{},
			}
			va.DevicesConfig.Store("SDX6320031", dvcConfg)
			va.DevicesDisc.Store("SDX6320031", voltDev)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutDeviceConfig(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			if err := va.AddDeviceConfig(tt.args.cntx, tt.args.serialNum, tt.args.hardwareIdentifier, tt.args.nasID, tt.args.ipAddress, tt.args.uplinkPort, tt.args.nniDhcpTrapID); (err != nil) != tt.wantErr {
				t.Errorf("VoltApplication.AddDeviceConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVoltApplication_GetDeviceConfig(t *testing.T) {
	type args struct {
		serNum string
	}
	dvcConfg := &DeviceConfig{
		SerialNumber:       "SDX6320031",
		HardwareIdentifier: "0.0.0.0",
		IPAddress:          "127.26.1.74",
		UplinkPort:         "16777216",
		NasID:              "12345",
		NniDhcpTrapVid:     123,
	}
	tests := []struct {
		name string
		args args
		want *DeviceConfig
	}{
		{
			name: "Positive_Case_GetDeviceConfig",
			args: args{
				serNum: "SDX6320031",
			},
			want: dvcConfg,
		},
		{
			name: "Negetive_Case_GetDeviceConfig",
			args: args{
				serNum: "SDX6320031",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesConfig: sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_GetDeviceConfig":
				va.DevicesConfig.Store("SDX6320031", dvcConfg)
				if got := va.GetDeviceConfig(tt.args.serNum); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltApplication.GetDeviceConfig() = %v, want %v", got, tt.want)
				}
			case "Negetive_Case_GetDeviceConfig":
				if got := va.GetDeviceConfig(tt.args.serNum); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltApplication.GetDeviceConfig() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestNbDevice_UpdatePortToNbDevice(t *testing.T) {
	type args struct {
		cntx               context.Context
		portID             uint32
		allowedChannels    uint32
		enableMulticastKPI bool
		portAlarmProfileID string
	}
	ponPort := &PonPortCfg{
		PortID:             controller.NNIPortID,
		MaxActiveChannels:  123,
		EnableMulticastKPI: false,
		PortAlarmProfileID: "16777",
	}
	tests := []struct {
		name string
		args args
		want *PonPortCfg
	}{
		{
			name: "Positive_Case_UpdatePortToNbDevice",
			args: args{
				cntx:               context.Background(),
				portID:             controller.NNIPortID,
				allowedChannels:    123,
				enableMulticastKPI: false,
				portAlarmProfileID: "16777",
			},
			want: ponPort,
		},
		{
			name: "Negetive_Case_UpdatePortToNbDevice",
			args: args{
				cntx:               context.Background(),
				portID:             0,
				allowedChannels:    123,
				enableMulticastKPI: false,
				portAlarmProfileID: "16777",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nbd := &NbDevice{
				SouthBoundID: "49686e2d-618f-4e8e-bca0-442ab850a63a",
				PonPorts:     sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_UpdatePortToNbDevice":
				nbd.PonPorts.Store(controller.NNIPortID, ponPort)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutNbDevicePort(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
				if got := nbd.UpdatePortToNbDevice(tt.args.cntx, tt.args.portID, tt.args.allowedChannels, tt.args.enableMulticastKPI, tt.args.portAlarmProfileID); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("NbDevice.UpdatePortToNbDevice() = %v, want %v", got, tt.want)
				}
			case "Negetive_Case_UpdatePortToNbDevice":
				if got := nbd.UpdatePortToNbDevice(tt.args.cntx, tt.args.portID, tt.args.allowedChannels, tt.args.enableMulticastKPI, tt.args.portAlarmProfileID); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("NbDevice.UpdatePortToNbDevice() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestNbDevice_DeletePortFromNbDevice(t *testing.T) {
	type args struct {
		cntx   context.Context
		portID uint32
	}
	ponPort := &PonPortCfg{
		PortID:             controller.NNIPortID,
		MaxActiveChannels:  123,
		EnableMulticastKPI: false,
		PortAlarmProfileID: "16777",
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_DeletePortFromNbDevice",
			args: args{
				portID: controller.NNIPortID,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nbd := &NbDevice{
				SouthBoundID: "49686e2d-618f-4e8e-bca0-442ab850a63a",
				PonPorts:     sync.Map{},
			}
			nbd.PonPorts.Store(controller.NNIPortID, ponPort)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().DelNbDevicePort(nil, "49686e2d-618f-4e8e-bca0-442ab850a63a", controller.NNIPortID).AnyTimes()
			nbd.DeletePortFromNbDevice(tt.args.cntx, tt.args.portID)
		})
	}
}

func TestVoltDevice_RegisterFlowAddEvent(t *testing.T) {
	type args struct {
		cookie string
		event  *FlowEvent
	}
	flowEvent := &FlowEvent{
		device: "SDX6320031",
		cookie: "68786618880",
		eType:  EventTypeControlFlowAdded,
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_RegisterFlowAddEvent",
			args: args{
				cookie: "68786618880",
				event:  flowEvent,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &VoltDevice{
				FlowAddEventMap: util.NewConcurrentMap(),
			}
			d.RegisterFlowAddEvent(tt.args.cookie, tt.args.event)
		})
	}
}

func TestVoltDevice_RegisterFlowDelEvent(t *testing.T) {
	type args struct {
		cookie string
		event  *FlowEvent
	}
	flowEvent := &FlowEvent{
		device: "SDX6320031",
		cookie: "68786618880",
		eType:  EventTypeControlFlowRemoved,
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_RegisterFlowDelEvent",
			args: args{
				cookie: "68786618880",
				event:  flowEvent,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &VoltDevice{
				FlowDelEventMap: util.NewConcurrentMap(),
			}
			d.RegisterFlowDelEvent(tt.args.cookie, tt.args.event)
		})
	}
}

func TestVoltDevice_UnRegisterFlowEvent(t *testing.T) {
	type args struct {
		cookie      string
		flowModType of.Command
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_RegisterFlowDelEvent",
			args: args{
				cookie:      "68786618880",
				flowModType: of.CommandDel,
			},
		},
		{
			name: "Negetive_Case_RegisterFlowDelEvent",
			args: args{
				cookie:      "68786618880",
				flowModType: opt82,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "Positive_Case_RegisterFlowDelEvent":
				d := &VoltDevice{
					FlowDelEventMap: util.NewConcurrentMap(),
				}
				d.UnRegisterFlowEvent(tt.args.cookie, tt.args.flowModType)
			case "Negetive_Case_RegisterFlowDelEvent":
				d := &VoltDevice{
					FlowDelEventMap: util.NewConcurrentMap(),
				}
				d.UnRegisterFlowEvent(tt.args.cookie, tt.args.flowModType)
			}
		})
	}
}

func TestVoltApplication_InitStaticConfig(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "Positive_Case_InitStaticConfig",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			va.InitStaticConfig()
		})
	}
}

func TestVoltApplication_SetVendorID(t *testing.T) {
	type args struct {
		vendorID string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_SetVendorID",
			args: args{
				vendorID: "DT",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			va.SetVendorID(tt.args.vendorID)
		})
	}
}

func TestVoltApplication_GetVendorID(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "Positive_Case_GetVendorID",
			want: "DT",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				vendorID: "DT",
			}
			if got := va.GetVendorID(); got != tt.want {
				t.Errorf("VoltApplication.GetVendorID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltApplication_SetRebootFlag(t *testing.T) {
	type args struct {
		flag bool
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_SetRebootFlag",
			args: args{
				flag: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			va.SetRebootFlag(tt.args.flag)
		})
	}
}

func TestVoltApplication_GetUpgradeFlag(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{
			name: "Positive_Case_GetUpgradeFlag",
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			isUpgradeComplete = true
			if got := va.GetUpgradeFlag(); got != tt.want {
				t.Errorf("VoltApplication.GetUpgradeFlag() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltApplication_SetUpgradeFlag(t *testing.T) {
	type args struct {
		flag bool
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_GetUpgradeFlag",
			args: args{
				flag: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			va.SetUpgradeFlag(tt.args.flag)
		})
	}
}

func TestVoltApplication_AddDevice(t *testing.T) {
	type args struct {
		cntx         context.Context
		device       string
		slno         string
		southBoundID string
	}
	voltDev := &VoltDevice{
		Name:           "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
		NniPort:        "16777216",
		SouthBoundID:   "49686e2d-618f-4e8e-bca0-442ab850a63a123",
	}
	nbd := &NbDevice{
		SouthBoundID: "49686e2d-618f-4e8e-bca0-442ab850a63a123",
		PonPorts:     sync.Map{},
	}
	ponPortCnf := &PonPortCfg{
		PortID:             controller.NNIPortID,
		MaxActiveChannels:  123,
		EnableMulticastKPI: false,
		PortAlarmProfileID: "16777",
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_AddDevice",
			args: args{
				cntx:         context.Background(),
				device:       "49686e2d-618f-4e8e-bca0-442ab850a63a",
				slno:         "SDX6320031",
				southBoundID: "49686e2d-618f-4e8e-bca0-442ab850a63a123",
			},
		},
		{
			name: "Negetive_Case_AddDevice",
			args: args{
				cntx:         context.Background(),
				device:       "49686e2d-618f-4e8e-bca0-442ab850a63a",
				slno:         "SDX6320031",
				southBoundID: "49686e2d-618f-4e8e-bca0-442ab850a63a123",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
				NbDevice:    sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_AddDevice":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				va.NbDevice.Store("49686e2d-618f-4e8e-bca0-442ab850a63a123", nbd)
				nbd.PonPorts.Store(controller.NNIPortID, ponPortCnf)
				va.AddDevice(tt.args.cntx, tt.args.device, tt.args.slno, tt.args.southBoundID)
			case "Negetive_Case_AddDevice":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				nbd.PonPorts.Store(controller.NNIPortID, ponPortCnf)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetAllNbPorts(context.Background(), "49686e2d-618f-4e8e-bca0-442ab850a63a123").AnyTimes()
				va.AddDevice(tt.args.cntx, tt.args.device, tt.args.slno, tt.args.southBoundID)
			}
		})
	}
}

func TestVoltApplication_DelDevice(t *testing.T) {
	type args struct {
		cntx   context.Context
		device string
	}
	voltDev := &VoltDevice{
		Name:           "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
		NniPort:        "16777216",
		SouthBoundID:   "49686e2d-618f-4e8e-bca0-442ab850a63a123",
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_AddDevice",
			args: args{
				cntx:   context.Background(),
				device: "SDX6320031",
			},
		},
		{
			name: "Delete_Case_AddDevice",
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
			switch tt.name {
			case "Positive_Case_AddDevice":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().DelAllRoutesForDevice(context.Background(), "SDX6320031").AnyTimes()
				dbintf.EXPECT().GetAllMigrateServicesReq(context.Background(), "SDX6320031").AnyTimes()
				dbintf.EXPECT().DelAllGroup(context.Background(), "SDX6320031").AnyTimes()
				dbintf.EXPECT().DelAllMeter(context.Background(), "SDX6320031").AnyTimes()
				dbintf.EXPECT().DelAllPorts(context.Background(), "SDX6320031").AnyTimes()
				va.DelDevice(tt.args.cntx, tt.args.device)
			case "Delete_Case_AddDevice":
				va.DelDevice(tt.args.cntx, tt.args.device)
			}
		})
	}
}

func TestVoltApplication_PortAddInd(t *testing.T) {
	type args struct {
		cntx     context.Context
		device   string
		id       uint32
		portName string
	}
	voltDev := &VoltDevice{
		Name:           "49686e2d-618f-4e8e-bca0-442ab850a63a",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
		NniPort:        "16777216",
		SouthBoundID:   "49686e2d-618f-4e8e-bca0-442ab850a63a123",
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_PortAddInd",
			args: args{
				cntx:     context.Background(),
				device:   "SDX6320031",
				id:       controller.NNIPortID,
				portName: "16777216",
			},
		},
		{
			name: "Negetive_Case_PortAddInd",
			args: args{
				cntx:     context.Background(),
				device:   "SDX6320031",
				id:       controller.NNIPortID,
				portName: "16777216",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_PortAddInd":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				va.PortAddInd(tt.args.cntx, tt.args.device, tt.args.id, tt.args.portName)
			case "Negetive_Case_PortAddInd":
				va.PortAddInd(tt.args.cntx, tt.args.device, tt.args.id, tt.args.portName)
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
	voltDev := &VoltDevice{
		Name:           "SDX6320031",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
		NniPort:        "16777216",
		SouthBoundID:   "49686e2d-618f-4e8e-bca0-442ab850a63a123",
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_PortUpdateInd",
			args: args{
				device:   "SDX6320031",
				id:       controller.NNIPortID,
				portName: "16777216",
			},
		},
		{
			name: "Negetive_Case_PortUpdateInd",
			args: args{
				device:   "SDX6320031",
				id:       controller.NNIPortID,
				portName: "16777216",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_PortAddInd":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				d := &VoltDevice{
					Ports: sync.Map{},
				}
				voltPort := &VoltPort{
					Name:                     "49686e2d-618f-4e8e-bca0-442ab850a63a",
					Device:                   "SDX6320031",
					ID:                       16777472,
					State:                    PortStateDown,
					ChannelPerSubAlarmRaised: false,
					Type:                     VoltPortTypeNni,
				}
				d.Ports.Store(16777472, voltPort)
				va.PortUpdateInd(tt.args.device, tt.args.portName, tt.args.id)
			case "Negetive_Case_PortUpdateInd":
				va.PortUpdateInd(tt.args.device, tt.args.portName, tt.args.id)
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
	voltDev := &VoltDevice{
		Name:           "SDX6320031",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
		NniPort:        "16777216",
		SouthBoundID:   "49686e2d-618f-4e8e-bca0-442ab850a63a",
	}
	nbd := &NbDevice{
		SouthBoundID: "49686e2d-618f-4e8e-bca0-442ab850a63a",
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Positive_Case_AddNbPonPort",
			args: args{
				cntx:               context.Background(),
				oltSbID:            "49686e2d-618f-4e8e-bca0-442ab850a63a",
				portID:             16777472,
				maxAllowedChannels: 0,
				enableMulticastKPI: false,
				portAlarmProfileID: "16777",
			},
		},
		{
			name: "Negetive_Case_AddNbPonPort",
			args: args{
				cntx:               context.Background(),
				oltSbID:            "0",
				portID:             16777472,
				maxAllowedChannels: 0,
				enableMulticastKPI: false,
				portAlarmProfileID: "16777",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
				NbDevice:    sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_AddNbPonPort":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				va.NbDevice.Store("49686e2d-618f-4e8e-bca0-442ab850a63a", nbd)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutNbDevicePort(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
				if err := va.AddNbPonPort(tt.args.cntx, tt.args.oltSbID, tt.args.portID, tt.args.maxAllowedChannels, tt.args.enableMulticastKPI, tt.args.portAlarmProfileID); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.AddNbPonPort() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "Negetive_Case_AddNbPonPort":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutNbDevicePort(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
				if err := va.AddNbPonPort(tt.args.cntx, tt.args.oltSbID, tt.args.portID, tt.args.maxAllowedChannels, tt.args.enableMulticastKPI, tt.args.portAlarmProfileID); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.AddNbPonPort() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVoltApplication_UpdateNbPonPort(t *testing.T) {
	type args struct {
		cntx               context.Context
		oltSbID            string
		portID             uint32
		maxAllowedChannels uint32
		enableMulticastKPI bool
		portAlarmProfileID string
	}
	voltDev := &VoltDevice{
		Name:                 "SDX6320031",
		SerialNum:            "SDX6320031",
		NniDhcpTrapVid:       123,
		NniPort:              "16777216",
		SouthBoundID:         "49686e2d-618f-4e8e-bca0-442ab850a63a",
		ActiveChannelsPerPon: sync.Map{},
	}
	nbd := &NbDevice{
		SouthBoundID: "49686e2d-618f-4e8e-bca0-442ab850a63a",
		PonPorts:     sync.Map{},
	}
	ponPortCnf := &PonPortCfg{
		PortID:             controller.NNIPortID,
		MaxActiveChannels:  123,
		EnableMulticastKPI: false,
		PortAlarmProfileID: "16777",
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Positive_Case_UpdateNbPonPort",
			args: args{
				cntx:               context.Background(),
				oltSbID:            "49686e2d-618f-4e8e-bca0-442ab850a63a",
				portID:             controller.NNIPortID,
				maxAllowedChannels: 0,
				enableMulticastKPI: false,
				portAlarmProfileID: "16777",
			},
			wantErr: false,
		},
		{
			name: "Negetive_Case_Port_doesn't_exists",
			args: args{
				cntx:               context.Background(),
				oltSbID:            "49686e2d-618f-4e8e-bca0-442ab850a63a",
				portID:             16777472,
				maxAllowedChannels: 0,
				enableMulticastKPI: false,
				portAlarmProfileID: "16777",
			},
			wantErr: true,
		},
		{
			name: "Negetive_Case_Device-doesn't-exists",
			args: args{
				cntx:               context.Background(),
				oltSbID:            "0",
				portID:             16777472,
				maxAllowedChannels: 0,
				enableMulticastKPI: false,
				portAlarmProfileID: "16777",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
				NbDevice:    sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_UpdateNbPonPort":
				va.NbDevice.Store("49686e2d-618f-4e8e-bca0-442ab850a63a", nbd)
				nbd.PonPorts.Store(controller.NNIPortID, ponPortCnf)
				va.DevicesDisc.Store("SDX6320031", voltDev)
				voltDev.ActiveChannelsPerPon.Store(controller.NNIPortID, ponPortCnf)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutNbDevicePort(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
				if err := va.UpdateNbPonPort(tt.args.cntx, tt.args.oltSbID, tt.args.portID, tt.args.maxAllowedChannels, tt.args.enableMulticastKPI, tt.args.portAlarmProfileID); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.UpdateNbPonPort() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "Negetive_Case_Port_doesn't_exists":
				va.NbDevice.Store("49686e2d-618f-4e8e-bca0-442ab850a63a", nbd)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutNbDevicePort(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
				if err := va.UpdateNbPonPort(tt.args.cntx, tt.args.oltSbID, tt.args.portID, tt.args.maxAllowedChannels, tt.args.enableMulticastKPI, tt.args.portAlarmProfileID); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.UpdateNbPonPort() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "Negetive_Case_Device-doesn't-exists":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutNbDevicePort(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
				if err := va.UpdateNbPonPort(tt.args.cntx, tt.args.oltSbID, tt.args.portID, tt.args.maxAllowedChannels, tt.args.enableMulticastKPI, tt.args.portAlarmProfileID); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.UpdateNbPonPort() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVoltApplication_DeleteNbPonPort(t *testing.T) {
	type args struct {
		cntx    context.Context
		oltSbID string
		portID  uint32
	}
	voltDev := &VoltDevice{
		Name:                 "SDX6320031",
		SerialNum:            "SDX6320031",
		NniDhcpTrapVid:       123,
		NniPort:              "16777216",
		SouthBoundID:         "49686e2d-618f-4e8e-bca0-442ab850a63a",
		ActiveChannelsPerPon: sync.Map{},
	}
	nbd := &NbDevice{
		SouthBoundID: "49686e2d-618f-4e8e-bca0-442ab850a63a",
	}
	ponPortCnf := &PonPortCfg{
		PortID:             controller.NNIPortID,
		MaxActiveChannels:  123,
		EnableMulticastKPI: false,
		PortAlarmProfileID: "16777",
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Positive_Case_DeleteNbPonPort",
			args: args{
				cntx:    context.Background(),
				oltSbID: "49686e2d-618f-4e8e-bca0-442ab850a63a",
				portID:  controller.NNIPortID,
			},
			wantErr: false,
		},
		{
			name: "Negetive_Case_DeleteNbPonPort",
			args: args{
				cntx:    context.Background(),
				oltSbID: "0",
				portID:  controller.NNIPortID,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
				NbDevice:    sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_DeleteNbPonPort":
				va.NbDevice.Store("49686e2d-618f-4e8e-bca0-442ab850a63a", nbd)
				nbd.PonPorts.Store(controller.NNIPortID, ponPortCnf)
				va.DevicesDisc.Store("SDX6320031", voltDev)
				voltDev.ActiveChannelsPerPon.Store(controller.NNIPortID, ponPortCnf)
				va.DevicesDisc.Store("SDX6320031", voltDev)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().DelNbDevicePort(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
				if err := va.DeleteNbPonPort(tt.args.cntx, tt.args.oltSbID, tt.args.portID); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.DeleteNbPonPort() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "Negetive_Case_DeleteNbPonPort":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().DelNbDevicePort(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
				if err := va.DeleteNbPonPort(tt.args.cntx, tt.args.oltSbID, tt.args.portID); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.DeleteNbPonPort() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVoltApplication_DeviceUpInd(t *testing.T) {
	type args struct {
		device string
	}
	voltDev := &VoltDevice{
		Name:           "SDX6320031",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
		NniPort:        "16777216",
		SouthBoundID:   "49686e2d-618f-4e8e-bca0-442ab850a63a",
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_DeviceUpInd",
			args: args{
				device: "SDX6320031",
			},
		},
		{
			name: "Negetive_Case_DeviceUpInd",
			args: args{
				device: "o",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_DeviceUpInd":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				va.DeviceUpInd(tt.args.device)
			case "Negetive_Case_DeviceUpInd":
				va.DeviceUpInd(tt.args.device)
			}
		})
	}
}

func TestVoltApplication_DeviceDownInd(t *testing.T) {
	type args struct {
		device string
	}
	voltDev := &VoltDevice{
		Name:           "SDX6320031",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
		NniPort:        "16777216",
		SouthBoundID:   "49686e2d-618f-4e8e-bca0-442ab850a63a",
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_DeviceDownInd",
			args: args{
				device: "SDX6320031",
			},
		},
		{
			name: "Negetive_Case_DeviceDownInd",
			args: args{
				device: "o",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
			}
			switch tt.name {
			case "Positive_Case_DeviceDownInd":
				va.DevicesDisc.Store("SDX6320031", voltDev)
				va.DeviceDownInd(tt.args.device)
			case "Negetive_Case_DeviceDownInd":
				va.DeviceDownInd(tt.args.device)
			}
		})
	}
}

func TestVoltApplication_DeviceRebootInd(t *testing.T) {
	type args struct {
		cntx         context.Context
		device       string
		serialNum    string
		southBoundID string
	}
	voltDev := &VoltDevice{
		Name:           "SDX6320031",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
		NniPort:        "16777216",
		SouthBoundID:   "49686e2d-618f-4e8e-bca0-442ab850a63a",
		State:          controller.DeviceStateREBOOTED,
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_DeviceRebootInd",
			args: args{
				device:       "SDX6320031",
				serialNum:    "SDX6320031",
				southBoundID: "49686e2d-618f-4e8e-bca0-442ab850a63a",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
			}
			va.DevicesDisc.Store("SDX6320031", voltDev)
			va.DeviceRebootInd(tt.args.cntx, tt.args.device, tt.args.serialNum, tt.args.southBoundID)
		})
	}
}
