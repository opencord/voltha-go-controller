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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewIgmpGroupPort(t *testing.T) {
	type args struct {
		port      string
		cvlan     uint16
		pbit      uint8
		version   uint8
		incl      bool
		ponPortID uint32
	}
	tests := []struct {
		name string
		args args
		want *IgmpGroupPort
	}{
		{
			name: "NewIgmpGroupPort",
			args: args{
				port:      "256",
				cvlan:     AnyVlan,
				pbit:      0,
				version:   uint8(12),
				incl:      true,
				ponPortID: uint32(256),
			},
			want: &IgmpGroupPort{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewIgmpGroupPort(tt.args.port, tt.args.cvlan, tt.args.pbit, tt.args.version, tt.args.incl, tt.args.ponPortID)
			assert.NotNil(t, got)
		})
	}
}

func TestIgmpGroupPort_DelExclSource(t *testing.T) {
	type args struct {
		src net.IP
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "DelExclSource",
			args: args{
				src: AllSystemsMulticastGroupIP,
			},
		},
		{
			name: "AddExclSource",
			args: args{
				src: AllSystemsMulticastGroupIP,
			},
		},
		{
			name: "DelInclSource",
			args: args{
				src: AllSystemsMulticastGroupIP,
			},
		},
		{
			name: "AddInclSource",
			args: args{
				src: AllSystemsMulticastGroupIP,
			},
		},
		{
			name: "InclSourceIsIn",
			args: args{
				src: AllSystemsMulticastGroupIP,
			},
		},
		{
			name: "ExclSourceIsIn",
			args: args{
				src: AllSystemsMulticastGroupIP,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			igp := &IgmpGroupPort{
				ExcludeList: []net.IP{
					AllSystemsMulticastGroupIP,
				},
				IncludeList: []net.IP{
					AllSystemsMulticastGroupIP,
				},
			}
			switch tt.name {
			case "DelExclSource":
				igp.DelExclSource(tt.args.src)
			case "AddExclSource":
				igp.AddExclSource(tt.args.src)
			case "DelInclSource":
				igp.DelInclSource(tt.args.src)
			case "AddInclSource":
				igp.AddInclSource(tt.args.src)
			case "InclSourceIsIn":
				igp.InclSourceIsIn(tt.args.src)
			case "ExclSourceIsIn":
				igp.ExclSourceIsIn(tt.args.src)
			}
		})
	}
}
