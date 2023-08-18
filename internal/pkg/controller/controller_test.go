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

package controller

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"voltha-go-controller/internal/pkg/intf"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestNewController(t *testing.T) {
	type args struct {
		ctx context.Context
		app intf.App
	}
	appMock := mocks.NewMockApp(gomock.NewController(t))
	app := NewController(ctx, appMock)
	tests := []struct {
		name string
		args args
		want intf.IVPClientAgent
	}{
		{
			name: "TestNewController",
			args: args{
				ctx: context.Background(),
				app: GetController().app,
			},
			want: app,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewController(tt.args.ctx, tt.args.app); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewController() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Cancel() {}
func TestVoltController_DelDevice(t *testing.T) {
	type args struct {
		cntx context.Context
		id   string
	}

	device := &Device{
		ID:     "SDX6320031",
		cancel: Cancel,
	}
	dev := map[string]*Device{}
	dev["SDX6320031"] = device
	appMock := mocks.NewMockApp(gomock.NewController(t))
	NewController(ctx, appMock)
	appMock.EXPECT().DelDevice(gomock.Any(), gomock.Any()).AnyTimes()
	tests := []struct {
		name string
		args args
	}{
		{
			name: "DelDevice",
			args: args{
				cntx: context.Background(),
				id:   "SDX6320031",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				devices: dev,
				app:     GetController().app,
			}
			v.DelDevice(tt.args.cntx, tt.args.id)
		})
	}
}

func TestVoltController_AddFlows(t *testing.T) {
	type args struct {
		cntx   context.Context
		port   string
		device string
		flow   *of.VoltFlow
	}
	subFlows := map[uint64]*of.VoltSubFlow{}
	vltSubFlow := &of.VoltSubFlow{
		Priority: 100,
		Cookie:   103112802816,
		State:    of.FlowAddSuccess,
		Match: of.Match{
			InPort:     1573376,
			MatchVlan:  4096,
			L4Protocol: 255,
		},
		Action: of.Action{
			Metadata:    279189651712,
			GoToTableID: 1,
			MeterID:     1,
			SetVlan:     4097,
			Pcp:         8,
			Output:      4,
		},
	}
	subFlows[0] = vltSubFlow
	portsByName := map[string]*DevicePort{}
	portsByName["SDX6320031-1"] = &DevicePort{
		Name: "SDX6320031-1",
		ID:   256,
	}
	device := &Device{
		ctx:         context.Background(),
		ID:          "SDX6320031",
		flows:       subFlows,
		PortsByName: portsByName,
	}
	dev := map[string]*Device{}
	dev["SDX6320031"] = device
	flow := &of.VoltFlow{
		PortName:      "SDX6320031-1",
		PortID:        256,
		Command:       0,
		MigrateCookie: true,
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "AddFlows",
			args: args{
				cntx:   context.Background(),
				port:   "SDX6320031-1",
				device: "SDX6320031",
				flow:   flow,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				devices: dev,
			}
			if err := v.AddFlows(tt.args.cntx, tt.args.port, tt.args.device, tt.args.flow); (err != nil) != tt.wantErr {
				t.Errorf("VoltController.AddFlows() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVoltController_DelFlows(t *testing.T) {
	type args struct {
		cntx   context.Context
		port   string
		device string
		flow   *of.VoltFlow
	}
	subFlows := map[uint64]*of.VoltSubFlow{}
	vltSubFlow := &of.VoltSubFlow{
		Priority: 100,
		Cookie:   103112802816,
		State:    of.FlowAddSuccess,
		Match: of.Match{
			InPort:     1573376,
			MatchVlan:  4096,
			L4Protocol: 255,
		},
		Action: of.Action{
			Metadata:    279189651712,
			GoToTableID: 1,
			MeterID:     1,
			SetVlan:     4097,
			Pcp:         8,
			Output:      4,
		},
	}
	subFlows[0] = vltSubFlow
	portsByName := map[string]*DevicePort{}
	portsByName["SDX6320031-1"] = &DevicePort{
		Name: "SDX6320031-1",
		ID:   256,
	}
	device := &Device{
		ctx:         context.Background(),
		ID:          "SDX6320031",
		flows:       subFlows,
		PortsByName: portsByName,
	}
	dev := map[string]*Device{}
	dev["SDX6320031"] = device
	flow := &of.VoltFlow{
		PortName:      "SDX6320031-1",
		PortID:        256,
		Command:       0,
		MigrateCookie: true,
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "DelFlows",
			args: args{
				cntx:   context.Background(),
				port:   "SDX6320031-1",
				device: "SDX6320031",
				flow:   flow,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				devices: dev,
			}
			if err := v.DelFlows(tt.args.cntx, tt.args.port, tt.args.device, tt.args.flow); (err != nil) != tt.wantErr {
				t.Errorf("VoltController.DelFlows() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVoltController_GetGroups(t *testing.T) {
	type args struct {
		cntx context.Context
		id   uint32
	}
	device := &Device{
		ctx:    context.Background(),
		ID:     "SDX6320031",
		groups: sync.Map{},
	}
	grp := &of.Group{
		Device:  "SDX6320031",
		GroupID: uint32(256),
		State:   1,
		SetVlan: of.VlanAny,
	}
	dev := map[string]*Device{}
	dev["SDX6320031"] = device
	tests := []struct {
		name    string
		args    args
		want    *of.Group
		wantErr bool
	}{
		{
			name: "VoltController_GetGroups",
			args: args{
				cntx: context.Background(),
				id:   uint32(256),
			},
			want:    grp,
			wantErr: false,
		},
		{
			name: "GetGroups_Not-Found",
			args: args{
				cntx: context.Background(),
				id:   1,
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				devices: dev,
			}
			switch tt.name {
			case "VoltController_GetGroups":
				device.groups.Store(uint32(256), grp)
				got, err := v.GetGroups(tt.args.cntx, tt.args.id)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltController.GetGroups() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltController.GetGroups() = %v, want %v", got, tt.want)
				}
			case "GetGroups_Not-Found":
				got, err := v.GetGroups(tt.args.cntx, tt.args.id)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltController.GetGroups() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltController.GetGroups() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVoltController_GetGroupList(t *testing.T) {
	device := &Device{
		ctx:    context.Background(),
		ID:     "SDX6320031",
		groups: sync.Map{},
	}
	grpList := []*of.Group{}
	grp := &of.Group{
		Device:  "SDX6320031",
		GroupID: uint32(256),
		State:   1,
		SetVlan: of.VlanAny,
	}
	grpList = append(grpList, grp)
	dev := map[string]*Device{}
	dev["SDX6320031"] = device
	tests := []struct {
		name    string
		want    []*of.Group
		wantErr bool
	}{
		{
			name:    "VoltController_GetGroups",
			want:    grpList,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				devices: dev,
			}
			device.groups.Store(uint32(256), grp)
			got, err := v.GetGroupList()
			if (err != nil) != tt.wantErr {
				t.Errorf("VoltController.GetGroupList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VoltController.GetGroupList() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltController_GetMeterInfo(t *testing.T) {
	type args struct {
		cntx context.Context
		id   uint32
	}
	mtrs := &of.Meter{
		ID:    uint32(256),
		State: 1,
	}
	mtr := map[string]*of.Meter{}
	mtr["SDX6320031"] = mtrs
	devMtr := map[uint32]*of.Meter{}
	devMtr[uint32(256)] = mtrs
	device := &Device{
		ctx:    context.Background(),
		ID:     "SDX6320031",
		meters: devMtr,
	}
	dev := map[string]*Device{}
	dev["SDX6320031"] = device
	tests := []struct {
		name    string
		args    args
		want    map[string]*of.Meter
		wantErr bool
	}{
		{
			name: "VoltController_GetMeterInfo",
			args: args{
				cntx: context.Background(),
				id:   uint32(256),
			},
			want:    mtr,
			wantErr: false,
		},
		{
			name: "Not_Found_Error",
			args: args{
				cntx: context.Background(),
				id:   1,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				devices: dev,
			}
			switch tt.name {
			case "VoltController_GetMeterInfo":
				got, err := v.GetMeterInfo(tt.args.cntx, tt.args.id)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltController.GetMeterInfo() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltController.GetMeterInfo() = %v, want %v", got, tt.want)
				}
			case "Not_Found_Error":
				got, err := v.GetMeterInfo(tt.args.cntx, tt.args.id)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltController.GetMeterInfo() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltController.GetMeterInfo() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVoltController_GetAllMeterInfo(t *testing.T) {
	vltMtr := map[string][]*of.Meter{}
	mtr := &of.Meter{
		ID:    uint32(256),
		State: 1,
	}
	mtrs := []*of.Meter{}
	mtrs = append(mtrs, mtr)
	vltMtr["SDX6320031"] = mtrs
	devMtr := map[uint32]*of.Meter{}
	devMtr[uint32(256)] = mtr
	device := &Device{
		ctx:    context.Background(),
		ID:     "SDX6320031",
		meters: devMtr,
	}
	dev := map[string]*Device{}
	dev["SDX6320031"] = device
	tests := []struct {
		name    string
		want    map[string][]*of.Meter
		wantErr bool
	}{
		{
			name:    "VoltController_GetMeterInfo",
			want:    vltMtr,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				devices: dev,
			}
			got, err := v.GetAllMeterInfo()
			if (err != nil) != tt.wantErr {
				t.Errorf("VoltController.GetAllMeterInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VoltController.GetAllMeterInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltController_GetAllPendingFlows(t *testing.T) {
	subFlowList := []*of.VoltSubFlow{}
	vltSubFlow := &of.VoltSubFlow{
		Priority: 100,
		Cookie:   103112802816,
		State:    of.FlowAddSuccess,
		Match: of.Match{
			InPort:     1573376,
			MatchVlan:  4096,
			L4Protocol: 255,
		},
		Action: of.Action{
			Metadata:    279189651712,
			GoToTableID: 1,
			MeterID:     1,
			SetVlan:     4097,
			Pcp:         8,
			Output:      4,
		},
	}
	subFlowList = append(subFlowList, vltSubFlow)
	subFlows := map[uint64]*of.VoltSubFlow{}
	subFlows[0] = vltSubFlow
	device := &Device{
		ctx:   context.Background(),
		ID:    "SDX6320031",
		flows: subFlows,
	}
	dev := map[string]*Device{}
	dev["SDX6320031"] = device
	tests := []struct {
		name    string
		want    []*of.VoltSubFlow
		wantErr bool
	}{
		{
			name:    "GetAllPendingFlows",
			want:    subFlowList,
			wantErr: false,
		},
	}
	type args1 struct {
		deviceId string
	}
	tests1 := []struct {
		name    string
		args    args1
		want    []*of.VoltSubFlow
		wantErr bool
	}{
		{
			name: "GetFlows_with_DeviceID",
			args: args1{
				deviceId: "SDX6320031",
			},
			want:    subFlowList,
			wantErr: false,
		},
		{
			name: "GetFlows_with_DeviceID_NOT_FOUND",
			args: args1{
				deviceId: "",
			},
			want:    subFlowList,
			wantErr: false,
		},
	}
	type args2 struct {
		deviceId string
		cookie   uint64
	}
	tests2 := []struct {
		name    string
		args    args2
		want    []*of.VoltSubFlow
		wantErr bool
	}{
		{
			name: "GetFlow_with_DeviceID_and_cookie",
			args: args2{
				deviceId: "SDX6320031",
				cookie:   103112802816,
			},
			want:    subFlowList,
			wantErr: false,
		},
		{
			name: "GetFlow_with_DeviceID_and_cookie_NOT_FOUND",
			args: args2{
				deviceId: "",
			},
			want:    subFlowList,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				devices: dev,
			}
			got, err := v.GetAllPendingFlows()
			if (err != nil) != tt.wantErr {
				t.Errorf("VoltController.GetAllPendingFlows() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Nil(t, got)
			got1, err1 := v.GetAllFlows()
			if (err1 != nil) != tt.wantErr {
				t.Errorf("VoltController.GetAllPendingFlows() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.NotNil(t, got1)
		})
	}
	for _, tt := range tests1 {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				devices: dev,
			}
			switch tt.name {
			case "GetFlows_with_DeviceID":
				got, err := v.GetFlows(tt.args.deviceId)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltController.GetAllPendingFlows() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.NotNil(t, got)
			case "GetFlows_with_DeviceID_NOT_FOUND":
				got, err := v.GetFlows(tt.args.deviceId)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltController.GetAllPendingFlows() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.Nil(t, got)
			}
		})
	}
	for _, tt := range tests2 {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				devices: dev,
			}
			switch tt.name {
			case "GetFlow_with_DeviceID_and_cookie":
				got, err := v.GetFlow(tt.args.deviceId, tt.args.cookie)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltController.GetAllPendingFlows() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.Nil(t, got)
			case "GetFlow_with_DeviceID_and_cookie_NOT_FOUND":
				got, err := v.GetFlow(tt.args.deviceId, tt.args.cookie)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltController.GetAllPendingFlows() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.Nil(t, got)
			}
		})
	}
}
