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
