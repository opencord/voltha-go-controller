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
	"reflect"
	"testing"
	"time"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestNewIgmpGroup(t *testing.T) {
	type args struct {
		name string
		vlan of.VlanType
	}
	group := &IgmpGroup{
		GroupName: "test_key",
	}
	tests := []struct {
		name string
		args args
		want *IgmpGroup
	}{
		{
			name: "NewIgmpGroup",
			args: args{
				name: "test_key",
			},
			want: group,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewIgmpGroup(tt.args.name, tt.args.vlan)
			assert.NotNil(t, got)
		})
	}
}

func TestIgmpGroup_IgmpGroupInit(t *testing.T) {
	type args struct {
		name string
		gip  net.IP
		mvp  *MvlanProfile
	}
	grp := make(map[string]*MvlanGroup)
	grp["test_key"] = &MvlanGroup{
		Name:     "test_key",
		IsStatic: true,
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "IgmpGroupInit",
			args: args{
				name: "test_key",
				gip:  AllSystemsMulticastGroupIP,
				mvp: &MvlanProfile{
					Version: "test_version",
					Name:    "test_key",
					Groups:  grp,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ig := &IgmpGroup{}
			ig.IgmpGroupInit(tt.args.name, tt.args.gip, tt.args.mvp)
		})
	}
}

func TestIgmpGroup_IgmpGroupReInit(t *testing.T) {
	type args struct {
		cntx context.Context
		name string
		gip  net.IP
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "IgmpGroupInit",
			args: args{
				cntx: context.Background(),
				name: "test_key",
				gip:  AllSystemsMulticastGroupIP,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ig := &IgmpGroup{}
			ig.IgmpGroupReInit(tt.args.cntx, tt.args.name, tt.args.gip)
		})
	}
}

func TestIgmpGroup_DeleteIgmpGroupDevice(t *testing.T) {
	type args struct {
		cntx   context.Context
		device string
	}
	devices := map[string]*IgmpGroupDevice{}
	igmpDevice := &IgmpGroupDevice{
		Device:    "SDX6320031",
		SerialNo:  "SDX6320031",
		GroupName: "group1",
		Mvlan:     of.VlanAny,
	}
	devices["SDX6320031"] = igmpDevice
	tests := []struct {
		name string
		args args
	}{
		{
			name: "DeleteIgmpGroupDevice",
			args: args{
				cntx:   context.Background(),
				device: "SDX6320031",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ig := &IgmpGroup{
				Devices: devices,
			}
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().DelIgmpDevice(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			ig.DeleteIgmpGroupDevice(tt.args.cntx, tt.args.device)
		})
	}
}

func TestIgmpGroup_removeExpiredGroupFromDevice(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	PendingGroupForDevice := make(map[string]time.Time)
	PendingGroupForDevice["SDX6320031"] = time.Now().Add(time.Duration(GroupExpiryTime) * time.Minute)
	tests := []struct {
		name string
		args args
	}{
		{
			name: "DeleteIgmpGroupDevice",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ig := &IgmpGroup{
				PendingGroupForDevice: PendingGroupForDevice,
			}
			ig.removeExpiredGroupFromDevice(tt.args.cntx)
		})
	}
}

func TestIgmpGroup_GetAllIgmpChannel(t *testing.T) {
	devices := map[string]*IgmpGroupDevice{}
	igmpDevice := &IgmpGroupDevice{
		Device:    "SDX6320031",
		SerialNo:  "SDX6320031",
		GroupName: "group1",
		Mvlan:     of.VlanAny,
	}
	devices["SDX6320031"] = igmpDevice
	tests := []struct {
		name string
		want map[string]string
	}{
		{
			name: "GetAllIgmpChannel",
			want: make(map[string]string),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ig := &IgmpGroup{
				Devices: devices,
			}
			if got := ig.GetAllIgmpChannel(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IgmpGroup.GetAllIgmpChannel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIgmpGroup_GetAllIgmpChannelForDevice(t *testing.T) {
	type args struct {
		deviceID string
	}
	devices := map[string]*IgmpGroupDevice{}
	igmpDevice := &IgmpGroupDevice{
		Device:    "SDX6320031",
		SerialNo:  "SDX6320031",
		GroupName: "group1",
		Mvlan:     of.VlanAny,
	}
	devices["SDX6320031"] = igmpDevice
	tests := []struct {
		name string
		args args
		want map[string]string
	}{
		{
			name: "GetAllIgmpChannelForDevice",
			args: args{
				deviceID: "SDX6320031",
			},
			want: make(map[string]string),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ig := &IgmpGroup{
				Devices: devices,
			}
			if got := ig.GetAllIgmpChannelForDevice(tt.args.deviceID); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IgmpGroup.GetAllIgmpChannelForDevice() = %v, want %v", got, tt.want)
			}
		})
	}
}
