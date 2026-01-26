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
	"voltha-go-controller/internal/pkg/tasks"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/internal/pkg/vpagent"
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
			got := NewController(tt.args.ctx, tt.args.app)
			assert.NotNil(t, got)
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
	var dev sync.Map
	dev.Store("SDX6320031", device)
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
				Devices: sync.Map{},
				app:     GetController().app,
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
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
	var dev sync.Map
	dev.Store("SDX6320031", device)
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
				Devices: sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
			if err := v.AddFlows(tt.args.cntx, tt.args.port, tt.args.device, tt.args.flow, false); (err != nil) != tt.wantErr {
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
	var dev sync.Map
	dev.Store("SDX6320031", device)
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
				Devices: sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
			if err := v.DelFlows(tt.args.cntx, tt.args.port, tt.args.device, tt.args.flow, false); (err != nil) != tt.wantErr {
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
	var dev sync.Map
	dev.Store("SDX6320031", device)
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
				Devices: sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
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
	var dev sync.Map
	dev.Store("SDX6320031", device)
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
				Devices: sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
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
	var dev sync.Map
	dev.Store("SDX6320031", device)
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
				Devices: sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
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
	var dev sync.Map
	dev.Store("SDX6320031", device)
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
				Devices: sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
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
	var dev sync.Map
	dev.Store("SDX6320031", device)
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
				Devices: sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
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
				Devices: sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
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
				Devices: sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
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

func TestVoltController_GetTaskList(t *testing.T) {
	type args struct {
		device string
	}
	device := &Device{
		ctx: context.Background(),
		ID:  "SDX6320031",
	}
	var dev sync.Map
	dev.Store("SDX6320031", device)
	tests := []struct {
		name string
		args args
		want []tasks.Task
	}{
		{
			name: "GetTaskList",
			args: args{
				device: "SDX6320031",
			},
			want: []tasks.Task{},
		},
		{
			name: "GetTaskList_Device_Not_found",
			args: args{
				device: "SDX632003",
			},
			want: []tasks.Task{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				Devices: sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
			switch tt.name {
			case "GetTaskList":
				if got := v.GetTaskList(tt.args.device); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltController.GetTaskList() = %v, want %v", got, tt.want)
				}
			case "GetTaskList_Device_Not_found":
				if got := v.GetTaskList(tt.args.device); !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltController.GetTaskList() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVoltController_GetPortState(t *testing.T) {
	type args struct {
		device string
		name   string
	}
	portsByName := map[string]*DevicePort{}
	portsByName["SDX6320031-1"] = &DevicePort{
		Name: "SDX6320031-1",
		ID:   256,
	}
	device := &Device{
		ctx:         context.Background(),
		ID:          "SDX6320031",
		PortsByName: portsByName,
	}
	var dev sync.Map
	dev.Store("SDX6320031", device)
	tests := []struct {
		name    string
		args    args
		want    PortState
		wantErr bool
	}{
		{
			name: "GetPortState",
			args: args{
				device: "SDX6320031",
				name:   "SDX6320031-1",
			},
			want: PortStateUp,
		},
		{
			name: "GetPortState_Device_Not_found",
			args: args{
				device: "SDX6320031-1",
				name:   "SDX6320031",
			},
			want:    PortStateDown,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				Devices: sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
			switch tt.name {
			case "GetPortState":
				got, err := v.GetPortState(tt.args.device, tt.args.name)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltController.GetPortState() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				assert.NotNil(t, got)
			case "GetPortState_Device_Not_found":
				got, err := v.GetPortState(tt.args.device, tt.args.name)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltController.GetPortState() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if got != tt.want {
					t.Errorf("VoltController.GetPortState() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVoltController_ModMeter(t *testing.T) {
	type args struct {
		port    string
		device  string
		command of.MeterCommand
		meter   *of.Meter
	}
	portsByName := map[string]*DevicePort{}
	portsByName["SDX6320031-1"] = &DevicePort{
		Name: "SDX6320031-1",
		ID:   256,
	}
	mtrs := &of.Meter{
		ID:    uint32(256),
		State: 1,
	}
	devMtr := map[uint32]*of.Meter{}
	devMtr[uint32(256)] = mtrs
	device := &Device{
		ctx:         context.Background(),
		ID:          "SDX6320031",
		PortsByName: portsByName,
		meters:      devMtr,
	}
	var dev sync.Map
	dev.Store("SDX6320031", device)
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ModMeter",
			args: args{
				device:  "SDX6320031",
				port:    "SDX6320031-1",
				command: of.MeterCommandAdd,
				meter:   mtrs,
			},
			wantErr: false,
		},
		{
			name: "ModMeter_device_not_found",
			args: args{
				command: of.MeterCommandAdd,
				meter:   mtrs,
			},
			wantErr: true,
		},
		{
			name: "ModMeter_port_not_found",
			args: args{
				device:  "SDX6320031",
				command: of.MeterCommandAdd,
				meter:   mtrs,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				Devices: sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
			switch tt.name {
			case "ModMeter":
				if err := v.ModMeter(tt.args.port, tt.args.device, tt.args.command, tt.args.meter); (err != nil) != tt.wantErr {
					t.Errorf("VoltController.ModMeter() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "ModMeter_device_not_found":
				if err := v.ModMeter(tt.args.port, tt.args.device, tt.args.command, tt.args.meter); (err != nil) != tt.wantErr {
					t.Errorf("VoltController.ModMeter() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "ModMeter_port_not_found":
				if err := v.ModMeter(tt.args.port, tt.args.device, tt.args.command, tt.args.meter); (err != nil) != tt.wantErr {
					t.Errorf("VoltController.ModMeter() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVoltController_VPAgent(t *testing.T) {
	type args struct {
		vep string
	}
	vagent := map[string]*vpagent.VPAgent{}
	vpa := &vpagent.VPAgent{}
	vagent[""] = vpa
	tests := []struct {
		name    string
		args    args
		want    *vpagent.VPAgent
		wantErr bool
	}{
		{
			name:    "VPAgent",
			args:    args{},
			want:    vpa,
			wantErr: false,
		},
		{
			name: "VPAgent_Error",
			args: args{
				vep: "ab",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				vagent: vagent,
			}
			switch tt.name {
			case "VPAgent":
				got, err := v.VPAgent(tt.args.vep)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltController.VPAgent() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltController.VPAgent() = %v, want %v", got, tt.want)
				}
			case "VPAgent_Error":
				got, err := v.VPAgent(tt.args.vep)
				if (err != nil) != tt.wantErr {
					t.Errorf("VoltController.VPAgent() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if !reflect.DeepEqual(got, tt.want) {
					t.Errorf("VoltController.VPAgent() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVoltController_DeviceRebootInd(t *testing.T) {
	type args struct {
		cntx context.Context
		dID  string
		srNo string
		sbID string
	}
	appMock := mocks.NewMockApp(gomock.NewController(t))
	NewController(ctx, appMock)
	appMock.EXPECT().DeviceRebootInd(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
	db = dbintf
	dbintf.EXPECT().DelAllRoutesForDevice(gomock.Any(), gomock.Any()).AnyTimes()
	dbintf.EXPECT().DelAllGroup(gomock.Any(), gomock.Any()).AnyTimes()
	dbintf.EXPECT().DelAllMeter(gomock.Any(), gomock.Any()).AnyTimes()
	dbintf.EXPECT().DelAllPONCounters(gomock.Any(), gomock.Any()).AnyTimes()
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VPAgent",
			args: args{
				dID:  "1234",
				srNo: "SDX6320031",
				cntx: context.Background(),
				sbID: "4321",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				app: GetController().app,
			}
			v.DeviceRebootInd(tt.args.cntx, tt.args.dID, tt.args.srNo, tt.args.sbID)
		})
	}
}

func TestVoltController_SetRebootInProgressForDevice(t *testing.T) {
	type args struct {
		device string
	}
	rebootInProgressDevices := map[string]string{}
	device := &Device{
		ctx: context.Background(),
		ID:  "SDX6320031",
	}
	var dev sync.Map
	dev.Store("SDX6320031", device)
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "SetRebootInProgressForDevice",
			args: args{
				device: "SDX6320031",
			},
			want: true,
		},
		{
			name: "SetRebootInProgressForDevice_Error",
			args: args{
				device: "SDX6320031-1",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				rebootInProgressDevices: rebootInProgressDevices,
				Devices:                 sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
			switch tt.name {
			case "SetRebootInProgressForDevice":
				if got := v.SetRebootInProgressForDevice(tt.args.device); got != tt.want {
					t.Errorf("VoltController.SetRebootInProgressForDevice() = %v, want %v", got, tt.want)
				}
			case "SetRebootInProgressForDevice_Error":
				if got := v.SetRebootInProgressForDevice(tt.args.device); got != tt.want {
					t.Errorf("VoltController.SetRebootInProgressForDevice() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVoltController_ReSetRebootInProgressForDevice(t *testing.T) {
	type args struct {
		device string
	}
	rebootInProgressDevices := map[string]string{}
	device := &Device{
		ctx: context.Background(),
		ID:  "SDX6320031",
	}
	rebootInProgressDevices["SDX6320031"] = "done"
	var dev sync.Map
	dev.Store("SDX6320031", device)
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "ReSetRebootInProgressForDevice",
			args: args{
				device: "SDX6320031",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				rebootInProgressDevices: rebootInProgressDevices,
				Devices:                 sync.Map{},
			}
			dev.Range(func(key, value interface{}) bool {
				v.Devices.Store(key, value)
				return true
			})
			if got := v.ReSetRebootInProgressForDevice(tt.args.device); got != tt.want {
				t.Errorf("VoltController.ReSetRebootInProgressForDevice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltController_IsBlockedDevice(t *testing.T) {
	type args struct {
		DeviceserialNumber string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "IsBlockedDevice",
			args: args{
				DeviceserialNumber: "SDX6320031",
			},
			want: false,
		},
		{
			name: "DeviceserialNumber",
			args: args{
				DeviceserialNumber: "SDX6320031",
			},
			want: false,
		},
		{
			name: "AddBlockedDevices",
			args: args{
				DeviceserialNumber: "SDX6320031",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{
				BlockedDeviceList: util.NewConcurrentMap(),
			}
			switch tt.name {
			case "IsBlockedDevice":
				if got := v.IsBlockedDevice(tt.args.DeviceserialNumber); got != tt.want {
					t.Errorf("VoltController.IsBlockedDevice() = %v, want %v", got, tt.want)
				}
			case "DeviceserialNumber":
				v.DelBlockedDevices(tt.args.DeviceserialNumber)
			case "AddBlockedDevices":
				v.AddBlockedDevices(tt.args.DeviceserialNumber)
			}
		})
	}
}

func TestVoltController_SetDeviceTableSyncDuration(t *testing.T) {
	type args struct {
		duration int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "SetDeviceTableSyncDuration",
			args: args{
				duration: 1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{}
			switch tt.name {
			case "SetDeviceTableSyncDuration":
				v.SetDeviceTableSyncDuration(tt.args.duration)
				v.GetDeviceTableSyncDuration()
			}
		})
	}
}

func TestVoltController_IsRebootInProgressForDevice(t *testing.T) {
	type args struct {
		device string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "SetDeviceTableSyncDuration",
			args: args{
				device: "SDX6320031",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &VoltController{}
			if got := v.IsRebootInProgressForDevice(tt.args.device); got != tt.want {
				t.Errorf("VoltController.IsRebootInProgressForDevice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVoltController_GroupUpdate(t *testing.T) {
	type args struct {
		port   string
		device string
		group  *of.Group
	}
	portsByName := map[string]*DevicePort{}
	portsByName["SDX6320031-1"] = &DevicePort{
		Name: "SDX6320031-1",
		ID:   256,
	}
	device := &Device{
		ctx:         context.Background(),
		ID:          "SDX6320031",
		groups:      sync.Map{},
		PortsByName: portsByName,
	}
	var dev sync.Map
	dev.Store("SDX6320031", device)
	grp := &of.Group{
		Device:  "SDX6320031",
		GroupID: uint32(256),
		State:   1,
		SetVlan: of.VlanAny,
	}

	// Setup database mock for async operations
	dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
	db = dbintf
	dbintf.EXPECT().PutGroup(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "GroupUpdate",
			args: args{
				port:   "SDX6320031-1",
				device: "SDX6320031",
				group:  grp,
			},
			wantErr: false,
		},
		{
			name: "DeviceNOtFound_Error",
			args: args{
				device: "SDX632003134",
			},
			wantErr: true,
		},
		{
			name: "PortNOtFound_Error",
			args: args{
				device: "SDX6320031",
				port:   "SDX632003134",
			},
			wantErr: true,
		},
		{
			name: "ContextNill_Error",
			args: args{
				device: "SDX6320031",
				port:   "SDX6320031-1",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "GroupUpdate":
				v := &VoltController{
					Devices: sync.Map{},
				}
				dev.Range(func(key, value interface{}) bool {
					v.Devices.Store(key, value)
					return true
				})
				if err := v.GroupUpdate(tt.args.port, tt.args.device, tt.args.group); (err != nil) != tt.wantErr {
					t.Errorf("VoltController.GroupUpdate() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "DeviceNOtFound_Error", "PortNOtFound_Error":
				v := &VoltController{
					Devices: sync.Map{},
				}
				dev.Range(func(key, value interface{}) bool {
					v.Devices.Store(key, value)
					return true
				})
				if err := v.GroupUpdate(tt.args.port, tt.args.device, tt.args.group); (err != nil) != tt.wantErr {
					t.Errorf("VoltController.GroupUpdate() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "ContextNill_Error":
				device := &Device{
					ID:          "SDX6320031",
					groups:      sync.Map{},
					PortsByName: portsByName,
				}
				var dev sync.Map
				dev.Store("SDX6320031", device)
				v := &VoltController{
					Devices: sync.Map{},
				}
				dev.Range(func(key, value interface{}) bool {
					v.Devices.Store(key, value)
					return true
				})
				if err := v.GroupUpdate(tt.args.port, tt.args.device, tt.args.group); (err != nil) != tt.wantErr {
					t.Errorf("VoltController.GroupUpdate() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}
