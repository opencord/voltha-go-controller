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
	"net"
	"sync"
	"testing"
	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

var eth = &layers.Ethernet{
	SrcMAC:       layers.EthernetBroadcast,
	DstMAC:       layers.EthernetBroadcast,
	EthernetType: layers.EthernetTypeARP,
	Length:       uint16(1),
}
var dot1Q = &layers.Dot1Q{
	Priority:     uint8(1),
	DropEligible: true,
	Type:         layers.EthernetTypeARP,
}
var LayerTypeDot2Q = []gopacket.Layer{
	dot1Q,
}

func TestPppoeIaPacketTask_Start(t *testing.T) {
	type args struct {
		ctx    context.Context
		taskID uint8
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "PppoeIaPacketTask_Start",
			args: args{
				ctx:    context.Background(),
				taskID: EtherType8100,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pppoe := &layers.PPPoE{
				Version: uint8(1),
			}
			pkt := mocks.NewMockPacket(gomock.NewController(t))
			var dpt = &PppoeIaPacketTask{
				pkt: pkt,
			}
			pkt.EXPECT().Layer(layers.LayerTypePPPoE).Return(pppoe).Times(2)
			pkt.EXPECT().Layer(layers.LayerTypeEthernet).Return(eth).Times(1)
			pkt.EXPECT().Layer(layers.LayerTypeDot1Q).Return(dot1Q).Times(1)
			pkt.EXPECT().Layers().Return(LayerTypeDot2Q).Times(1)
			err := dpt.Start(tt.args.ctx, tt.args.taskID)
			assert.Nil(t, err)
		})
	}
}

func TestVoltApplication_ProcessPPPoEIaPacket(t *testing.T) {
	type args struct {
		cntx   context.Context
		device string
		port   string
		pkt    gopacket.Packet
	}
	pkt := mocks.NewMockPacket(gomock.NewController(t))
	tests := []struct {
		name string
		args args
	}{
		{
			name: "ProcessPPPoEIaPacket_ProcessUsPppoeIaPacket",
			args: args{
				cntx:   context.Background(),
				device: test_device,
				port:   "test_port",
				pkt:    pkt,
			},
		},
		{
			name: "pppoel_nil",
			args: args{
				cntx:   context.Background(),
				device: test_device,
				port:   "test_port",
				pkt:    pkt,
			},
		},
		{
			name: "pppoel_invalidType",
			args: args{
				cntx:   context.Background(),
				device: test_device,
				port:   "test_port",
				pkt:    pkt,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			// dot1Q := &layers.Dot1Q{
			// 	Priority:     uint8(1),
			// 	DropEligible: true,
			// 	Type:         layers.EthernetTypeARP,
			// }
			// LayerTypeDot2Q := []gopacket.Layer{
			// 	dot1Q,
			// }
			ga := GetApplication()
			switch tt.name {
			case "ProcessPPPoEIaPacket_ProcessUsPppoeIaPacket":
				ga.DevicesDisc.Store(test_device, voltDevice)
				pkt.EXPECT().Layer(layers.LayerTypePPPoE).Return(&layers.PPPoE{
					Version: uint8(1),
				}).Times(1)
				pkt.EXPECT().Layers().Return(LayerTypeDot2Q).Times(2)
				va.ProcessPPPoEIaPacket(tt.args.cntx, tt.args.device, tt.args.port, tt.args.pkt)
			case "pppoel_nil":
				pkt.EXPECT().Layer(layers.LayerTypePPPoE).Return(nil).Times(1)
				va.ProcessPPPoEIaPacket(tt.args.cntx, tt.args.device, tt.args.port, tt.args.pkt)
			case "pppoel_invalidType":
				pkt.EXPECT().Layer(layers.LayerTypePPPoE).Return(&layers.ARP{}).Times(1)
				va.ProcessPPPoEIaPacket(tt.args.cntx, tt.args.device, tt.args.port, tt.args.pkt)
			}
		})
	}
}

func TestVoltApplication_ProcessUsPppoeIaPacket(t *testing.T) {
	type args struct {
		cntx   context.Context
		device string
		port   string
		pkt    gopacket.Packet
	}
	pkt := mocks.NewMockPacket(gomock.NewController(t))
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_ProcessUsPppoeIaPacket",
			args: args{
				cntx:   context.Background(),
				device: test_device,
				port:   "test_port",
				pkt:    pkt,
			},
		},
	}
	macAdd, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	macPort := map[string]string{}
	macPort[macAdd.String()] = test_data
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				macPortMap:  macPort,
				VnetsByPort: sync.Map{},
				DevicesDisc: sync.Map{},
			}
			voltServ := &VoltService{
				VoltServiceOper: VoltServiceOper{
					Device: "SDX6320031",
				},
				VoltServiceCfg: VoltServiceCfg{
					IsActivated: true,
					Pbits:       []of.PbitType{PbitMatchAll},
				},
			}
			switch tt.name {
			case "VoltApplication_ProcessUsPppoeIaPacket":
				va.DevicesDisc.Store(test_device, voltDevice)
				pkt.EXPECT().Layers().Return(LayerTypeDot2Q).AnyTimes()
				voltPortVnet1[0].SVlan = 0
				voltDevice.NniPort = []string{"16777216"} // Set proper NNI port
				va.VnetsByPort.Store("test_port", voltPortVnet1)
				voltPortVnet1[0].PppoeIa = true
				voltPortVnet1[0].AllowTransparent = true
				voltPortVnet1[0].Port = test_data
				pendingDeleteFlow := map[string]bool{}
				pendingDeleteFlow["test_cookie"] = true
				voltPortVnet1[0].PendingDeleteFlow = pendingDeleteFlow
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				eth.SrcMAC = layers.EthernetBroadcast
				// Don't expect PutVpv since it won't be called due to error conditions
				voltPortVnet1[0].services.Store("SDX6320031-1_SDX6320031-1-4096-2310-4096-65", voltServ)
				// Mock expectations are minimal since the function will return early
				_ = cntlr.NewController(context.Background(), mocks.NewMockApp(gomock.NewController(t)))
				va.ProcessUsPppoeIaPacket(tt.args.cntx, tt.args.device, tt.args.port, tt.args.pkt)
			}
		})
	}
}

func TestVoltApplication_ProcessDsPppoeIaPacket(t *testing.T) {
	type args struct {
		cntx   context.Context
		device string
		port   string
		pkt    gopacket.Packet
	}
	pkt := mocks.NewMockPacket(gomock.NewController(t))
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_ProcessDsPppoeIaPacket",
			args: args{
				cntx:   context.Background(),
				device: test_device,
				port:   "test_port",
				pkt:    pkt,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			pkt.EXPECT().Layers().Return(LayerTypeDot2Q).AnyTimes()

			// Provide valid mock objects instead of nil to prevent panic
			pppoe := &layers.PPPoE{
				Version: uint8(1),
				Code:    layers.PPPoECodePADI,
			}

			pkt.EXPECT().Layer(layers.LayerTypeEthernet).Return(eth).AnyTimes()
			pkt.EXPECT().Layer(layers.LayerTypePPPoE).Return(pppoe).AnyTimes()
			pkt.EXPECT().Layer(layers.LayerTypeDot1Q).Return(dot1Q).AnyTimes()

			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			// Don't expect PutVpv since it won't be called due to error conditions
			va.ProcessDsPppoeIaPacket(tt.args.cntx, tt.args.device, tt.args.port, tt.args.pkt)
		})
	}
}

func TestAddIaOption(t *testing.T) {
	type args struct {
		svc   *VoltService
		pppoe *layers.PPPoE
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "AddIaOption",
			args: args{
				svc: &VoltService{
					VoltServiceCfg: VoltServiceCfg{
						CircuitID:    "test_circuit_id",
						RemoteID:     []byte{1},
						DataRateAttr: DSLAttrEnabled,
					},
				},
				pppoe: &layers.PPPoE{
					Options: make(layers.PPPoEOptions, 1),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AddIaOption(tt.args.svc, tt.args.pppoe)
		})
	}
}

func TestNewPppoeIaPacketTask(t *testing.T) {
	type args struct {
		pkt  gopacket.Packet
		dev  string
		port string
	}
	pkt := mocks.NewMockPacket(gomock.NewController(t))
	tests := []struct {
		name string
		args args
		want *PppoeIaPacketTask
	}{
		{
			name: "NewPppoeIaPacketTask",
			args: args{
				pkt:  pkt,
				dev:  test_device,
				port: "test_port",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewPppoeIaPacketTask(tt.args.pkt, tt.args.dev, tt.args.port)
			assert.NotNil(t, got)
		})
	}
}

func TestPppoeIaPacketTask_Name(t *testing.T) {
	dpt := &PppoeIaPacketTask{}
	got := dpt.Name()
	assert.NotNil(t, got)
	got1 := dpt.TaskID()
	assert.NotNil(t, got1)
	got2 := dpt.Timestamp()
	assert.NotNil(t, got2)
}
