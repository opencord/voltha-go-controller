/*
* Copyright 2022-2024present Open Networking Foundation
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
	"testing"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
)

func Test_isFlowOperSuccess(t *testing.T) {
	type args struct {
		statusCode uint32
		oper       of.Command
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "test",
			args: args{
				statusCode: uint32(1004),
				oper:       of.CommandAdd,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFlowOperSuccess(tt.args.statusCode, tt.args.oper); got != tt.want {
				t.Errorf("isFlowOperSuccess() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddFlowsTask_Start(t *testing.T) {
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
			name: "AddFlowsTask_Start",
			args: args{
				ctx:    context.Background(),
				taskID: 0,
			},
			wantErr: false,
		},
		{
			name: "DeleteFlowsTask_Start",
			args: args{
				ctx:    context.Background(),
				taskID: 0,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "AddFlowsTask_Start":
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
				portsByID := map[uint32]*DevicePort{}
				portsByID[256] = &DevicePort{
					Name: "SDX6320031",
					ID:   256,
				}
				device := &Device{
					flows:     subFlows,
					PortsByID: portsByID,
				}
				flow := &of.VoltFlow{
					SubFlows: subFlows,
					PortName: "SDX6320031-1",
					PortID:   256,
					Command:  0,
				}
				aft := &AddFlowsTask{
					flow:   flow,
					device: device,
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutFlow(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				if err := aft.Start(tt.args.ctx, tt.args.taskID); (err != nil) != tt.wantErr {
					t.Errorf("AddFlowsTask.Start() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "DeleteFlowsTask_Start":
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
				portsByID := map[uint32]*DevicePort{}
				portsByID[256] = &DevicePort{
					Name: "SDX6320031",
					ID:   256,
				}
				device := &Device{
					flows:     subFlows,
					PortsByID: portsByID,
				}
				flow := &of.VoltFlow{
					SubFlows: subFlows,
					PortName: "SDX6320031-1",
					PortID:   256,
					Command:  1,
				}
				aft := &AddFlowsTask{
					flow:   flow,
					device: device,
				}
				appMock := mocks.NewMockApp(gomock.NewController(t))
				NewController(ctx, appMock)
				appMock.EXPECT().ProcessFlowModResultIndication(gomock.Any(), gomock.Any()).AnyTimes()
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().DelFlow(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				if err := aft.Start(tt.args.ctx, tt.args.taskID); (err != nil) != tt.wantErr {
					t.Errorf("AddFlowsTask.Start() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestNewAddFlowsTask(t *testing.T) {
	type args struct {
		ctx    context.Context
		flow   *of.VoltFlow
		device *Device
	}
	flow := &of.VoltFlow{
		PortName: "SDX6320031-1",
		PortID:   256,
		Command:  0,
	}
	portsByID := map[uint32]*DevicePort{}
	portsByID[256] = &DevicePort{
		Name: "SDX6320031",
		ID:   256,
	}
	device := &Device{
		PortsByID: portsByID,
	}

	tests := []struct {
		name string
		args args
		want *AddFlowsTask
	}{
		{
			name: "NewAddFlowsTask",
			args: args{
				ctx:    context.Background(),
				flow:   flow,
				device: device,
			},
			want: &AddFlowsTask{
				ctx:    context.Background(),
				flow:   flow,
				device: device,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewAddFlowsTask(tt.args.ctx, tt.args.flow, tt.args.device); reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewAddFlowsTask() = %v, want %v", got, tt.want)
			}
		})
	}
}
