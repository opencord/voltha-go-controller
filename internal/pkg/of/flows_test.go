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

package of

import (
	"net"
	"testing"
)

func TestMatch_SetTableMetadata(t *testing.T) {
	type fields struct {
		SrcMacAddr    net.HardwareAddr
		SrcMacMask    net.HardwareAddr
		DstMacAddr    net.HardwareAddr
		DstMacMask    net.HardwareAddr
		SrcIpv4Addr   net.IP
		DstIpv4Addr   net.IP
		TableMetadata uint64
		InPort        uint32
		MatchVlan     VlanType
		Pbits         PbitType
		L3Protocol    EtherType
		SrcPort       uint16
		DstPort       uint16
		L4Protocol    IPProtocol
		DstIpv4Match  bool
		SrcIpv4Match  bool
		SrcMacMatch   bool
		DstMacMatch   bool
		MatchPbits    bool
	}
	type args struct {
		metadata uint64
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "test",
			args: args{
				metadata: uint64(537416),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Match{
				SrcMacAddr:    tt.fields.SrcMacAddr,
				SrcMacMask:    tt.fields.SrcMacMask,
				DstMacAddr:    tt.fields.DstMacAddr,
				DstMacMask:    tt.fields.DstMacMask,
				SrcIpv4Addr:   tt.fields.SrcIpv4Addr,
				DstIpv4Addr:   tt.fields.DstIpv4Addr,
				TableMetadata: tt.fields.TableMetadata,
				InPort:        tt.fields.InPort,
				MatchVlan:     tt.fields.MatchVlan,
				Pbits:         tt.fields.Pbits,
				L3Protocol:    tt.fields.L3Protocol,
				SrcPort:       tt.fields.SrcPort,
				DstPort:       tt.fields.DstPort,
				L4Protocol:    tt.fields.L4Protocol,
				DstIpv4Match:  tt.fields.DstIpv4Match,
				SrcIpv4Match:  tt.fields.SrcIpv4Match,
				SrcMacMatch:   tt.fields.SrcMacMatch,
				DstMacMatch:   tt.fields.DstMacMatch,
				MatchPbits:    tt.fields.MatchPbits,
			}
			m.SetTableMetadata(tt.args.metadata)
		})
	}
}
# [EOF] - delta:force
