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
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"go.uber.org/atomic"
)

func TestVoltApplication_GetIgnoredPorts(t *testing.T) {
	voltDevice := &VoltDevice{
		Name:         "11c3175b-50f3-4220-9555-93df733ded1d",
		SerialNum:    "SDX6320031",
		SouthBoundID: "68580342-6b3e-57cb-9ea4-06125594e330",
		NniPort:      "16777472",
		Ports:        sync.Map{},
		PonPortList:  sync.Map{},
	}
	voltPort := &VoltPort{
		Name:                     "16777472",
		Device:                   "SDX6320031",
		ID:                       16777472,
		State:                    PortStateDown,
		ChannelPerSubAlarmRaised: false,
		Type:                     VoltPortTypeNni,
	}
	voltPortVnets := make([]*VoltPortVnet, 0)
	voltPortVnet := &VoltPortVnet{
		Device:      "SDX6320031",
		Port:        "16777472",
		MacLearning: MacLearningNone,
	}
	voltPortVnets = append(voltPortVnets, voltPortVnet)
	IgnoredPorts := make(map[string][]string)
	IgnoredPorts["SDX6320031"] = append(IgnoredPorts["SDX6320031"], "16777472")
	tests := []struct {
		name    string
		want    map[string][]string
		wantErr bool
	}{
		{
			name:    "Positive_Case_GetIgnoredPorts",
			want:    IgnoredPorts,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
			}
			va.DevicesDisc.Store("SDX6320031", voltDevice)
			voltDevice.Ports.Store("16777472", voltPort)
			voltApp := GetApplication()
			voltApp.VnetsByPort.Store("16777472", voltPortVnets)
			got, err := va.GetIgnoredPorts()
			if (err != nil) != tt.wantErr {
				t.Errorf("VoltApplication.GetIgnoredPorts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VoltApplication.GetIgnoredPorts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDhcpNetworks_AddDhcpSession(t *testing.T) {
	pkt := mocks.NewMockPacket(gomock.NewController(t))
	type args struct {
		pkt     gopacket.Packet
		session IDhcpRelaySession
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "DhcpNetworks_AddDhcpSession",
			args: args{
				pkt:     pkt,
				session: &VoltPortVnet{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network := make(map[uint32]*DhcpRelayVnet)
			dn := &DhcpNetworks{
				Networks: network,
			}
			pkt.EXPECT().Layer(layers.LayerTypeEthernet).Return(eth).Times(1)
			if err := dn.AddDhcpSession(tt.args.pkt, tt.args.session); (err != nil) != tt.wantErr {
				t.Errorf("DhcpNetworks.AddDhcpSession() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDhcpNetworks_DelDhcpSession(t *testing.T) {
	pkt := mocks.NewMockPacket(gomock.NewController(t))
	type args struct {
		pkt     gopacket.Packet
		session IDhcpRelaySession
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "DhcpNetworks_DelDhcpSession",
			args: args{
				pkt:     pkt,
				session: &VoltPortVnet{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network := make(map[uint32]*DhcpRelayVnet)
			dn := &DhcpNetworks{
				Networks: network,
			}
			pkt.EXPECT().Layer(layers.LayerTypeEthernet).Return(eth).Times(1)
			dn.DelDhcpSession(tt.args.pkt, tt.args.session)
		})
	}
}

func TestDhcpNetworks_AddDhcp6Session(t *testing.T) {
	type args struct {
		key     [MaxLenDhcpv6DUID]byte
		session IDhcpRelaySession
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "DhcpNetworks_AddDhcp6Session",
			args: args{
				session: &VoltPortVnet{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network := make(map[uint32]*DhcpRelayVnet)
			dn := &DhcpNetworks{
				Networks: network,
			}
			if err := dn.AddDhcp6Session(tt.args.key, tt.args.session); (err != nil) != tt.wantErr {
				t.Errorf("DhcpNetworks.AddDhcp6Session() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDhcpNetworks_DelDhcp6Session(t *testing.T) {
	type args struct {
		key     [MaxLenDhcpv6DUID]byte
		session IDhcpRelaySession
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "DhcpNetworks_DelDhcp6Session",
			args: args{
				session: &VoltPortVnet{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network := make(map[uint32]*DhcpRelayVnet)
			network[uint32(4097)] = &DhcpRelayVnet{
				InnerVlan: uint16(4097),
			}
			dn := &DhcpNetworks{
				Networks: network,
			}
			dn.DelDhcp6Session(tt.args.key, tt.args.session)
		})
	}
}

func TestDhcpNetworks_GetDhcpSession(t *testing.T) {
	type fields struct {
		Networks map[uint32]*DhcpRelayVnet
	}
	type args struct {
		outerVlan uint16
		innerVlan uint16
		addr      net.HardwareAddr
	}
	macAdd, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	tests := []struct {
		name   string
		fields fields
		args   args
		want   IDhcpRelaySession
	}{
		{
			name: "DhcpNetworks_GetDhcpSession",
			args: args{
				outerVlan: uint16(0),
				innerVlan: uint16(4097),
				addr:      macAdd,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network := make(map[uint32]*DhcpRelayVnet)
			network[uint32(4097)] = &DhcpRelayVnet{
				InnerVlan: uint16(4097),
			}
			dn := &DhcpNetworks{
				Networks: network,
			}
			got, err := dn.GetDhcpSession(tt.args.outerVlan, tt.args.innerVlan, tt.args.addr)
			assert.NotNil(t, err)
			assert.Nil(t, got)
		})
	}
}

func TestDhcpNetworks_GetDhcp6Session(t *testing.T) {
	type fields struct {
		Networks map[uint32]*DhcpRelayVnet
	}
	type args struct {
		outerVlan uint16
		innerVlan uint16
		key       [MaxLenDhcpv6DUID]byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    IDhcpRelaySession
		wantErr bool
	}{
		{
			name: "DhcpNetworks_GetDhcp6Session",
			args: args{
				outerVlan: uint16(0),
				innerVlan: uint16(4097),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network := make(map[uint32]*DhcpRelayVnet)
			network[uint32(4097)] = &DhcpRelayVnet{
				InnerVlan: uint16(4097),
			}
			dn := &DhcpNetworks{
				Networks: network,
			}
			got, err := dn.GetDhcp6Session(tt.args.outerVlan, tt.args.innerVlan, tt.args.key)
			assert.NotNil(t, err)
			assert.Nil(t, got)
		})
	}
}

func TestGetVnetForV4Nni(t *testing.T) {
	type args struct {
		dhcp  *layers.DHCPv4
		cvlan of.VlanType
		svlan of.VlanType
		pbit  uint8
	}
	macAdd, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	tests := []struct {
		name    string
		args    args
		want    []*VoltPortVnet
		wantErr bool
	}{
		{
			name: "GetVnetForV4Nni",
			args: args{
				cvlan: of.VlanAny,
				svlan: of.VlanAny,
				dhcp: &layers.DHCPv4{
					BaseLayer:    dot1Q.BaseLayer,
					ClientHWAddr: macAdd,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetVnetForV4Nni(tt.args.dhcp, tt.args.cvlan, tt.args.svlan, tt.args.pbit)
			assert.NotNil(t, err)
			assert.Nil(t, got)
		})
	}
}

func TestGetVnetForV6Nni(t *testing.T) {
	type args struct {
		dhcp      *layers.DHCPv6
		cvlan     of.VlanType
		svlan     of.VlanType
		pbit      uint8
		clientMAC net.HardwareAddr
	}
	macAdd, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	tests := []struct {
		name    string
		args    args
		want    []*VoltPortVnet
		want1   net.HardwareAddr
		wantErr bool
	}{
		{
			name: "GetVnetForV6Nni",
			args: args{
				dhcp: &layers.DHCPv6{
					BaseLayer: dot1Q.BaseLayer,
					Options: layers.DHCPv6Options{
						{
							Code: layers.DHCPv6OptClientID,
							Data: []byte{2, 3, 4, 2, 3, 4, 2, 3, 4},
						},
					},
				},
				cvlan:     of.VlanAny,
				svlan:     of.VlanAny,
				clientMAC: macAdd,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := GetVnetForV6Nni(tt.args.dhcp, tt.args.cvlan, tt.args.svlan, tt.args.pbit, tt.args.clientMAC)
			assert.NotNil(t, err)
			assert.Nil(t, got)
			assert.NotNil(t, got1)
		})
	}
}

func TestAddDhcpv4Option82(t *testing.T) {
	type args struct {
		svc    *VoltService
		rID    []byte
		dhcpv4 *layers.DHCPv4
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "AddDhcpv4Option82",
			args: args{
				svc: &VoltService{
					VoltServiceCfg: VoltServiceCfg{
						CircuitID:    "test_circuit_id",
						DataRateAttr: DSLAttrEnabled,
					},
				},
				rID: []byte{1},
				dhcpv4: &layers.DHCPv4{
					Options: layers.DHCPOptions{
						{
							Type: layers.DHCPOptARPTimeout,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AddDhcpv4Option82(tt.args.svc, tt.args.rID, tt.args.dhcpv4)
		})
	}
}

func TestVoltApplication_ProcessDsDhcpv4Packet(t *testing.T) {
	pkt := mocks.NewMockPacket(gomock.NewController(t))
	type args struct {
		cntx   context.Context
		device string
		port   string
		pkt    gopacket.Packet
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_ProcessDsDhcpv4Packet",
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
			iPv4 := &layers.IPv4{
				Version: uint8(1),
			}
			uDP := &layers.UDP{
				Length: uint16(1),
			}
			dHCPv4 := &layers.DHCPv4{
				HardwareLen: uint8(1),
			}
			dot1Q_test := &layers.Dot1Q{
				Priority: uint8(1),
			}
			pkt.EXPECT().Layer(layers.LayerTypeEthernet).Return(eth).Times(1)
			pkt.EXPECT().Layer(layers.LayerTypeIPv4).Return(iPv4).Times(1)
			pkt.EXPECT().Layer(layers.LayerTypeUDP).Return(uDP).Times(1)
			pkt.EXPECT().Layer(layers.LayerTypeDHCPv4).Return(dHCPv4).Times(1)
			pkt.EXPECT().Layer(layers.LayerTypeDot1Q).Return(dot1Q_test).Times(1)
			pkt.EXPECT().Layers().Return(LayerTypeDot2Q).Times(1)
			va.ProcessDsDhcpv4Packet(tt.args.cntx, tt.args.device, tt.args.port, tt.args.pkt)
		})
	}
}

func TestDelOption82(t *testing.T) {
	type args struct {
		dhcpv4 *layers.DHCPv4
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "DelOption82",
			args: args{
				dhcpv4: &layers.DHCPv4{
					Options: layers.DHCPOptions{
						{
							Type: opt82,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			DelOption82(tt.args.dhcpv4)
		})
	}
}

func TestDhcpMsgType(t *testing.T) {
	type args struct {
		dhcp *layers.DHCPv4
	}
	tests := []struct {
		name string
		args args
		want layers.DHCPMsgType
	}{
		{
			name: "DhcpMsgType",
			args: args{
				dhcp: &layers.DHCPv4{
					Options: layers.DHCPOptions{
						{
							Type: layers.DHCPOptMessageType,
							Data: []byte{1},
						},
					},
				},
			},
			want: layers.DHCPMsgTypeDiscover,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DhcpMsgType(tt.args.dhcp); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DhcpMsgType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetIpv4Addr(t *testing.T) {
	type args struct {
		dhcp *layers.DHCPv4
	}
	tests := []struct {
		name  string
		args  args
		want  net.IP
		want1 int64
	}{
		{
			name: "GetIpv4Addr",
			args: args{
				dhcp: &layers.DHCPv4{
					Options: layers.DHCPOptions{
						{
							Type: layers.DHCPOptLeaseTime,
							Data: []byte{1, 2, 3, 4, 5},
						},
					},
				},
			},
			want1: int64(16909060),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := GetIpv4Addr(tt.args.dhcp)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetIpv4Addr() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("GetIpv4Addr() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestGetIpv6Addr(t *testing.T) {
	type args struct {
		dhcp6 *layers.DHCPv6
	}
	b, err := json.Marshal(layers.DHCPv6OptIAAddr)
	if err != nil {
		panic(err)
	}
	tests := []struct {
		name  string
		args  args
		want  net.IP
		want1 uint32
	}{
		{
			name: "GetIpv6Addr_error",
			args: args{
				dhcp6: &layers.DHCPv6{
					MsgType: layers.DHCPv6MsgTypeReply,
					Options: layers.DHCPv6Options{
						{
							Code: layers.DHCPv6OptIANA,
							Data: b,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := GetIpv6Addr(tt.args.dhcp6)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetIpv6Addr() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("GetIpv6Addr() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestVoltApplication_GetMacLearnerInfo(t *testing.T) {
	type args struct {
		cntx       context.Context
		deviceID   string
		portNumber string
		vlanID     string
	}
	vpv := &VoltPortVnet{
		Device:  "SDX6320031",
		Port:    "SDX6320031-1",
		SVlan:   of.VlanAny,
		MacAddr: BroadcastMAC,
	}
	sessions := map[[6]byte]IDhcpRelaySession{}
	key := [6]byte{1, 2, 3, 4, 5, 6}
	sessions[key] = vpv
	network := make(map[uint32]*DhcpRelayVnet)
	network[uint32(256)] = &DhcpRelayVnet{
		sessions: sessions,
	}
	dhcpNws.Networks = network
	svlan := of.VlanAny
	macLearning := MacLearnerInfo{
		DeviceID:   "SDX6320031",
		PortNumber: "SDX6320031-1",
		VlanID:     svlan.String(),
		MacAddress: BroadcastMAC.String(),
	}
	tests := []struct {
		name    string
		args    args
		want    MacLearnerInfo
		wantErr bool
	}{
		{
			name: "VoltApplication_GetMacLearnerInfo",
			args: args{
				cntx:       context.Background(),
				deviceID:   "SDX6320031",
				portNumber: "SDX6320031-1",
				vlanID:     svlan.String(),
			},
			want: macLearning,
		},
		{
			name: "VoltApplication_GetMacLearnerInfo_svlan_empty",
			args: args{
				cntx:       context.Background(),
				deviceID:   "SDX6320031",
				portNumber: "SDX6320031-1",
				vlanID:     "",
			},
			want: macLearning,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			got, err := va.GetMacLearnerInfo(tt.args.cntx, tt.args.deviceID, tt.args.portNumber, tt.args.vlanID)
			if (err != nil) != tt.wantErr {
				t.Errorf("VoltApplication.GetMacLearnerInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VoltApplication.GetMacLearnerInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltApplication_GetAllocations(t *testing.T) {
	type args struct {
		cntx     context.Context
		deviceID string
	}
	allocation := []DhcpAllocation{}
	vpv := &VoltPortVnet{
		Device:   "SDX6320031",
		services: sync.Map{},
	}
	voltServ := &VoltService{
		VoltServiceOper: VoltServiceOper{
			Device: "SDX6320031",
		},
		VoltServiceCfg: VoltServiceCfg{
			Name: "SDX6320031-1_SDX6320031-1-4096-2310-4096-65",
		},
	}
	sessions := map[[6]byte]IDhcpRelaySession{}
	key := [6]byte{1, 2, 3, 4, 5, 6}
	sessions[key] = vpv
	network := make(map[uint32]*DhcpRelayVnet)
	network[uint32(256)] = &DhcpRelayVnet{
		sessions: sessions,
	}
	dhcpNws.Networks = network
	tests := []struct {
		name    string
		args    args
		want    []DhcpAllocation
		wantErr bool
	}{
		{
			name: "VoltApplication_GetAllocations",
			args: args{
				cntx:     context.Background(),
				deviceID: "SDX6320031",
			},
			want: allocation,
		},
		{
			name: "GetAllocations_with_Services",
			args: args{
				cntx:     context.Background(),
				deviceID: "SDX6320031",
			},
			want: allocation,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			switch tt.name {
			case "VoltApplication_GetAllocations":
				got, err := va.GetAllocations(tt.args.cntx, tt.args.deviceID)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.GetAllocations() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.NotNil(t, got)
			case "GetAllocations_with_Services":
				vpv.services.Store("SDX6320031-1_SDX6320031-1-4096-2310-4096-65", voltServ)
				got, err := va.GetAllocations(tt.args.cntx, tt.args.deviceID)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.GetAllocations() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.NotNil(t, got)
			}
		})
	}
}

func TestVoltApplication_GetAllMacLearnerInfo(t *testing.T) {
	vpv := &VoltPortVnet{
		Device:  "SDX6320031",
		Port:    "SDX6320031-1",
		SVlan:   of.VlanAny,
		MacAddr: BroadcastMAC,
	}
	sessions := map[[6]byte]IDhcpRelaySession{}
	key := [6]byte{1, 2, 3, 4, 5, 6}
	sessions[key] = vpv
	network := make(map[uint32]*DhcpRelayVnet)
	network[uint32(256)] = &DhcpRelayVnet{
		sessions: sessions,
	}
	dhcpNws.Networks = network
	svlan := of.VlanAny
	macLearningList := []MacLearnerInfo{}
	macLearning := MacLearnerInfo{
		DeviceID:   "SDX6320031",
		PortNumber: "SDX6320031-1",
		VlanID:     svlan.String(),
		MacAddress: BroadcastMAC.String(),
	}
	macLearningList = append(macLearningList, macLearning)
	tests := []struct {
		name    string
		want    []MacLearnerInfo
		wantErr bool
	}{
		{
			name: "VoltApplication_GetAllMacLearnerInfo",
			want: macLearningList,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			got, err := va.GetAllMacLearnerInfo()
			if (err != nil) != tt.wantErr {
				t.Errorf("VoltApplication.GetAllMacLearnerInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VoltApplication.GetAllMacLearnerInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_raiseDHCPv4Indication(t *testing.T) {
	voltServ := &VoltService{
		VoltServiceOper: VoltServiceOper{
			Device: "SDX6320031",
		},
		VoltServiceCfg: VoltServiceCfg{
			IsActivated: true,
			Pbits: []of.PbitType{
				of.PbitNone,
			},
		},
	}
	voltPortVnet := &VoltPortVnet{
		Device:           "SDX6320031",
		Port:             "16777472",
		DeleteInProgress: false,
		services:         sync.Map{},
		SVlan:            4096,
		CVlan:            2310,
		UniVlan:          4096,
		SVlanTpid:        65,
		servicesCount:    atomic.NewUint64(1),
	}
	voltPortVnet.services.Store("SDX6320031-1_SDX6320031-1-4096-2310-4096-65", voltServ)
	type args struct {
		msgType   layers.DHCPMsgType
		vpv       *VoltPortVnet
		smac      net.HardwareAddr
		ip        net.IP
		pktPbit   uint8
		device    string
		leaseTime int64
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "raiseDHCPv4Indication_DHCPMsgTypeDiscover",
			args: args{
				msgType: layers.DHCPMsgTypeDiscover,
				vpv:     voltPortVnet,
				device:  "SDX6320031",
			},
		},
		{
			name: "raiseDHCPv4Indication_DHCPMsgTypeRequest",
			args: args{
				msgType: layers.DHCPMsgTypeRequest,
				vpv:     voltPortVnet,
			},
		},
		{
			name: "raiseDHCPv4Indication_DHCPMsgTypeRelease",
			args: args{
				msgType: layers.DHCPMsgTypeRelease,
				vpv:     voltPortVnet,
			},
		},
		{
			name: "raiseDHCPv4Indication_DHCPMsgTypeAck",
			args: args{
				msgType: layers.DHCPMsgTypeAck,
				vpv:     voltPortVnet,
			},
		},
		{
			name: "raiseDHCPv4Indication_DHCPMsgTypeNak",
			args: args{
				msgType: layers.DHCPMsgTypeNak,
				vpv:     voltPortVnet,
			},
		},
		{
			name: "raiseDHCPv4Indication_DHCPMsgTypeOffer",
			args: args{
				msgType: layers.DHCPMsgTypeOffer,
				vpv:     voltPortVnet,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raiseDHCPv4Indication(tt.args.msgType, tt.args.vpv, tt.args.smac, tt.args.ip, tt.args.pktPbit, tt.args.device, tt.args.leaseTime)
		})
	}
}

func Test_raiseDHCPv6Indication(t *testing.T) {
	voltServ := &VoltService{
		VoltServiceOper: VoltServiceOper{
			Device: "SDX6320031",
		},
		VoltServiceCfg: VoltServiceCfg{
			IsActivated: true,
			Pbits: []of.PbitType{
				of.PbitNone,
			},
		},
	}
	voltPortVnet := &VoltPortVnet{
		Device:           "SDX6320031",
		Port:             "16777472",
		DeleteInProgress: false,
		services:         sync.Map{},
		SVlan:            4096,
		CVlan:            2310,
		UniVlan:          4096,
		SVlanTpid:        65,
		servicesCount:    atomic.NewUint64(1),
	}
	voltPortVnet.services.Store("SDX6320031-1_SDX6320031-1-4096-2310-4096-65", voltServ)
	type args struct {
		msgType   layers.DHCPv6MsgType
		vpv       *VoltPortVnet
		smac      net.HardwareAddr
		ip        net.IP
		pktPbit   uint8
		device    string
		leaseTime uint32
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "raiseDHCPv6Indication_DHCPv6MsgTypeSolicit",
			args: args{
				msgType: layers.DHCPv6MsgTypeSolicit,
				vpv:     voltPortVnet,
				device:  "SDX6320031",
			},
		},
		{
			name: "raiseDHCPv4Indication_DHCPv6MsgTypeRelease",
			args: args{
				msgType: layers.DHCPv6MsgTypeRelease,
				vpv:     voltPortVnet,
			},
		},
		{
			name: "raiseDHCPv4Indication_DHCPv6MsgTypeReply",
			args: args{
				msgType: layers.DHCPv6MsgTypeReply,
				vpv:     voltPortVnet,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raiseDHCPv6Indication(tt.args.msgType, tt.args.vpv, tt.args.smac, tt.args.ip, tt.args.pktPbit, tt.args.device, tt.args.leaseTime)
		})
	}
}

func TestVoltApplication_ProcessUDP6Packet(t *testing.T) {
	type args struct {
		cntx   context.Context
		device string
		port   string
		pkt    gopacket.Packet
	}
	pkt := mocks.NewMockPacket(gomock.NewController(t))
	dhcpv6 := &layers.DHCPv6{
		MsgType: layers.DHCPv6MsgTypeSolicit,
	}
	ipv6 := &layers.IPv6{
		Version: EtherType8100,
	}
	uup := &layers.UDP{
		SrcPort: opt82,
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "ProcessUDP6Packet_DHCPv6MsgTypeSolicit",
			args: args{
				cntx:   context.Background(),
				device: "SDX6320031",
				port:   "16777472",
				pkt:    pkt,
			},
		},
		{
			name: "ProcessUDP6Packet_DHCPv6MsgTypeAdvertise",
			args: args{
				cntx:   context.Background(),
				device: "SDX6320031",
				port:   "16777472",
				pkt:    pkt,
			},
		},
		{
			name: "ProcessUDP6Packet_DHCPv6MsgTypeRelayForward",
			args: args{
				cntx:   context.Background(),
				device: "SDX6320031",
				port:   "16777472",
				pkt:    pkt,
			},
		},
		{
			name: "ProcessUDP6Packet_DHCPv6MsgTypeRelayReply",
			args: args{
				cntx:   context.Background(),
				device: "SDX6320031",
				port:   "16777472",
				pkt:    pkt,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			switch tt.name {
			case "ProcessUDP6Packet_DHCPv6MsgTypeSolicit":
				pkt.EXPECT().Layer(layers.LayerTypeDHCPv6).Return(dhcpv6).Times(2)
				pkt.EXPECT().Data().Times(1)
				pkt.EXPECT().Layers().Return(LayerTypeDot2Q).Times(2)
				if got := va.ProcessUDP6Packet(tt.args.cntx, tt.args.device, tt.args.port, tt.args.pkt); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltApplication.ProcessUDP6Packet() = %v, want %v", got, tt.want)
				}
			case "ProcessUDP6Packet_DHCPv6MsgTypeAdvertise":
				dhcpv6.MsgType = layers.DHCPv6MsgTypeAdvertise
				pkt.EXPECT().Layer(layers.LayerTypeDHCPv6).Return(dhcpv6).Times(2)
				if got := va.ProcessUDP6Packet(tt.args.cntx, tt.args.device, tt.args.port, tt.args.pkt); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltApplication.ProcessUDP6Packet() = %v, want %v", got, tt.want)
				}
			case "ProcessUDP6Packet_DHCPv6MsgTypeRelayForward":
				dhcpv6.MsgType = layers.DHCPv6MsgTypeRelayForward
				pkt.EXPECT().Layer(layers.LayerTypeDHCPv6).Return(dhcpv6).Times(2)
				if got := va.ProcessUDP6Packet(tt.args.cntx, tt.args.device, tt.args.port, tt.args.pkt); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltApplication.ProcessUDP6Packet() = %v, want %v", got, tt.want)
				}
			case "ProcessUDP6Packet_DHCPv6MsgTypeRelayReply":
				dhcpv6.MsgType = layers.DHCPv6MsgTypeRelayReply
				pkt.EXPECT().Data().Times(1)
				pkt.EXPECT().Layer(layers.LayerTypeEthernet).Return(eth).Times(1)
				pkt.EXPECT().Layer(layers.LayerTypeIPv6).Return(ipv6).Times(1)
				pkt.EXPECT().Layer(layers.LayerTypeUDP).Return(uup).Times(1)
				if got := va.ProcessUDP6Packet(tt.args.cntx, tt.args.device, tt.args.port, tt.args.pkt); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltApplication.ProcessUDP6Packet() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestBuildRelayFwd(t *testing.T) {
	type args struct {
		paddr             net.IP
		intfID            []byte
		remoteID          []byte
		payload           []byte
		isOption82Enabled bool
		dhcpRelay         bool
	}
	tests := []struct {
		name string
		args args
		want *layers.DHCPv6
	}{
		{
			name: "BuildRelayFwd",
			args: args{
				paddr:             AllSystemsMulticastGroupIP,
				intfID:            AllSystemsMulticastGroupIP,
				remoteID:          AllSystemsMulticastGroupIP,
				payload:           AllSystemsMulticastGroupIP,
				isOption82Enabled: true,
				dhcpRelay:         true,
			},
			want: &layers.DHCPv6{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildRelayFwd(tt.args.paddr, tt.args.intfID, tt.args.remoteID, tt.args.payload, tt.args.isOption82Enabled, tt.args.dhcpRelay)
			assert.NotNil(t, got)
		})
	}
}

func TestGetRelayReplyBytes(t *testing.T) {
	type args struct {
		dhcp6 *layers.DHCPv6
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "BuildRelayFwd",
			args: args{
				dhcp6: &layers.DHCPv6{
					Options: make(layers.DHCPv6Options, 1),
				},
			},
			want: AllSystemsMulticastGroupIP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetRelayReplyBytes(tt.args.dhcp6)
			assert.Nil(t, got)
		})
	}
}

func TestVoltApplication_ProcessUsDhcpv6Packet(t *testing.T) {
	type args struct {
		cntx   context.Context
		device string
		port   string
		pkt    gopacket.Packet
	}
	voltDevice := &VoltDevice{
		Name:         "11c3175b-50f3-4220-9555-93df733ded1d",
		SerialNum:    "SDX6320031",
		SouthBoundID: "68580342-6b3e-57cb-9ea4-06125594e330",
		NniPort:      "16777472",
		Ports:        sync.Map{},
		PonPortList:  sync.Map{},
	}
	pkt := mocks.NewMockPacket(gomock.NewController(t))
	tests := []struct {
		name string
		args args
	}{
		{
			name: "ProcessUsDhcpv6Packet",
			args: args{
				cntx:   context.Background(),
				device: "SDX6320031",
				port:   "16777472",
				pkt:    pkt,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{
				DevicesDisc: sync.Map{},
			}
			va.DevicesDisc.Store("SDX6320031", voltDevice)
			pkt.EXPECT().Data().Times(1)
			pkt.EXPECT().Layers().Return(LayerTypeDot2Q).Times(2)
			va.ProcessUsDhcpv6Packet(tt.args.cntx, tt.args.device, tt.args.port, tt.args.pkt)
		})
	}
}
# [EOF] - delta:force
