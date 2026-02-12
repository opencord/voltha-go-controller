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
	"testing"
	"voltha-go-controller/internal/pkg/intf"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/internal/test/mocks"

	"go.uber.org/mock/gomock"
)

var voltPortVnet = &VoltPortVnet{
	Device: "test_device",
}
var voltService = &VoltService{
	Version: "test_version",
}

func TestExecuteFlowEvent(t *testing.T) {
	type args struct {
		cntx       context.Context
		vd         *VoltDevice
		cookie     string
		flowStatus intf.FlowStatus
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "ExecuteFlowEvent_add",
			args: args{
				cntx: context.Background(),
				vd: &VoltDevice{
					SouthBoundID:    "test_device_id",
					FlowAddEventMap: util.NewConcurrentMap(),
				},
				cookie: "test_cookie",
				flowStatus: intf.FlowStatus{
					Device:      "test_device",
					FlowModType: of.CommandAdd,
				},
			},
		},
		{
			name: "ExecuteFlowEvent_del",
			args: args{
				cntx: context.Background(),
				vd: &VoltDevice{
					SouthBoundID:    "test_device_id",
					FlowDelEventMap: util.NewConcurrentMap(),
				},
				cookie: "test_cookie",
				flowStatus: intf.FlowStatus{
					Device:      "test_device",
					FlowModType: of.CommandDel,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "ExecuteFlowEvent_add":
				if got := ExecuteFlowEvent(tt.args.cntx, tt.args.vd, tt.args.cookie, tt.args.flowStatus); got != tt.want {
					t.Errorf("ExecuteFlowEvent() = %v, want %v", got, tt.want)
				}
			case "ExecuteFlowEvent_del":
				if got := ExecuteFlowEvent(tt.args.cntx, tt.args.vd, tt.args.cookie, tt.args.flowStatus); got != tt.want {
					t.Errorf("ExecuteFlowEvent() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestInitEventFuncMapper(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "InitEventFuncMapper",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			InitEventFuncMapper()
		})
	}
}

func TestProcessUsIgmpFlowAddEvent(t *testing.T) {
	type args struct {
		cntx       context.Context
		event      *FlowEvent
		flowStatus intf.FlowStatus
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "ProcessUsIgmpFlowAddEvent",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					device:    "test_device",
					eType:     EventTypeControlFlowAdded,
					eventData: voltPortVnet,
				},
				flowStatus: intf.FlowStatus{
					Device: "test_device",
					Status: uint32(0),
				},
			},
		},
		{
			name: "ProcessUsIgmpFlowAddEvent_else_condition",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					device:    "test_device",
					eType:     EventTypeControlFlowAdded,
					eventData: voltPortVnet,
				},
				flowStatus: intf.FlowStatus{
					Device: "test_device",
					Status: uint32(1001),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ProcessUsIgmpFlowAddEvent(tt.args.cntx, tt.args.event, tt.args.flowStatus)
		})
	}
}

func TestProcessServiceFlowAddEvent(t *testing.T) {
	type args struct {
		cntx         context.Context
		event        *FlowEvent
		flowStatus   intf.FlowStatus
		flowEventMap *util.ConcurrentMap
	}

	vs := &VoltService{
		VoltServiceCfg: VoltServiceCfg{},
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "ProcessServiceFlowAddEvent",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					device:    "test_device",
					eventData: vs,
				},
				flowEventMap: util.NewConcurrentMap(),
			},
		},
		{
			name: "ProcessServiceFlowAddEvent_else_condition",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					device:    "test_device",
					eventData: vs,
				},
				flowStatus: intf.FlowStatus{
					Status: uint32(1001),
				},
				flowEventMap: util.NewConcurrentMap(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ProcessServiceFlowAddEvent(tt.args.cntx, tt.args.event, tt.args.flowStatus)
		})
	}
}

func TestProcessControlFlowAddEvent(t *testing.T) {
	type args struct {
		cntx       context.Context
		event      *FlowEvent
		flowStatus intf.FlowStatus
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "ProcessControlFlowAddEvent",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					eventData: voltPortVnet,
				},
			},
		},
		{
			name: "ProcessControlFlowAddEvent_else_condition",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					eventData: voltPortVnet,
				},
				flowStatus: intf.FlowStatus{
					Status: uint32(1001),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ProcessControlFlowAddEvent(tt.args.cntx, tt.args.event, tt.args.flowStatus)
		})
	}
}

func TestProcessServiceFlowDelEvent(t *testing.T) {
	type args struct {
		cntx         context.Context
		event        *FlowEvent
		flowStatus   intf.FlowStatus
		flowEventMap *util.ConcurrentMap
	}

	vs := &VoltService{
		VoltServiceCfg: VoltServiceCfg{},
	}

	tests := []struct {
		name string
		args args
	}{
		{
			name: "ProcessServiceFlowDelEvent",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					eventData: vs,
				},
				flowEventMap: util.NewConcurrentMap(),
			},
		},
		{
			name: "ProcessServiceFlowDelEvent_else_condition",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					eventData: vs,
				},
				flowStatus: intf.FlowStatus{
					Status: uint32(1001),
				},
				flowEventMap: util.NewConcurrentMap(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			switch tt.name {
			case "ProcessServiceFlowDelEvent":
				dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			case "ProcessServiceFlowDelEvent_else_condition":
				dbintf.EXPECT().PutService(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			}
			ProcessServiceFlowDelEvent(tt.args.cntx, tt.args.event, tt.args.flowStatus)
		})
	}
}

func TestProcessControlFlowDelEvent(t *testing.T) {
	type args struct {
		cntx       context.Context
		event      *FlowEvent
		flowStatus intf.FlowStatus
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "ProcessControlFlowDelEvent",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					eventData: voltPortVnet,
				},
			},
		},
		{
			name: "ProcessControlFlowDelEvent_else_condition",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					eventData: voltPortVnet,
				},
				flowStatus: intf.FlowStatus{
					Status: uint32(1001),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutVpv(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			ProcessControlFlowDelEvent(tt.args.cntx, tt.args.event, tt.args.flowStatus)
		})
	}
}

func TestProcessMcastFlowDelEvent(t *testing.T) {
	type args struct {
		cntx       context.Context
		event      *FlowEvent
		flowStatus intf.FlowStatus
	}
	mvlanProfile := &MvlanProfile{
		Version: "test_version",
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "ProcessMcastFlowDelEvent",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					eventData: mvlanProfile,
				},
			},
		},
		{
			name: "ProcessMcastFlowDelEvent_else_condition",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					eventData: mvlanProfile,
				},
				flowStatus: intf.FlowStatus{
					Status: uint32(1001),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			switch tt.name {
			case "ProcessMcastFlowDelEvent":
				dbintf.EXPECT().PutMvlan(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			case "ProcessMcastFlowDelEvent_else_condition":
				dbintf.EXPECT().PutMvlan(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			}
			ProcessMcastFlowDelEvent(tt.args.cntx, tt.args.event, tt.args.flowStatus)
		})
	}
}

func TestProcessDeviceFlowDelEvent(t *testing.T) {
	type args struct {
		cntx       context.Context
		event      *FlowEvent
		flowStatus intf.FlowStatus
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "ProcessDeviceFlowDelEvent",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					device:    test_device,
					eventData: voltVnet,
				},
				flowStatus: intf.FlowStatus{
					Device: test_device,
				},
			},
		},
		{
			name: "ProcessDeviceFlowDelEvent_else_condition",
			args: args{
				cntx: context.Background(),
				event: &FlowEvent{
					device:    test_device,
					eventData: voltVnet,
				},
				flowStatus: intf.FlowStatus{
					Device: test_device,
					Status: uint32(1001),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "ProcessDeviceFlowDelEvent":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutVnet(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil).AnyTimes()
				ProcessDeviceFlowDelEvent(tt.args.cntx, tt.args.event, tt.args.flowStatus)
			case "ProcessDeviceFlowDelEvent_else_condition":
				ProcessDeviceFlowDelEvent(tt.args.cntx, tt.args.event, tt.args.flowStatus)
			}
		})
	}
}
