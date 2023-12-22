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
	"testing"
	"voltha-go-controller/internal/pkg/holder"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/opencord/voltha-protos/v5/go/openflow_13"
	"github.com/opencord/voltha-protos/v5/go/voltha"
)

func TestAuditDevice_DelExcessPorts(t *testing.T) {
	type args struct {
		cntx context.Context
		eps  map[uint32]*DevicePort
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
	portsByID := map[uint32]*DevicePort{}
	portsByID[256] = &DevicePort{
		Name:  "SDX6320031",
		ID:    256,
		State: PortStateUp,
	}
	eps := make(map[uint32]*DevicePort)
	device := &Device{
		flows:     subFlows,
		PortsByID: portsByID,
		ID:        "SDX6320031",
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "AddFlowsTask_Start",
			args: args{
				cntx: context.Background(),
				eps:  eps,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad := &AuditDevice{
				device: device,
			}
			appMock := mocks.NewMockApp(gomock.NewController(t))
			NewController(ctx, appMock)
			appMock.EXPECT().PortDownInd(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			appMock.EXPECT().PortDelInd(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().DelPort(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			ad.DelExcessPorts(tt.args.cntx, tt.args.eps)
		})
	}
}

func TestAuditDevice_Start(t *testing.T) {
	type args struct {
		ctx    context.Context
		taskID uint8
	}
	volthaClientMock := mocks.NewMockVolthaServiceClient(gomock.NewController(t))
	volthaServiceClientHolder := &holder.VolthaServiceClientHolder{
		VolthaSvcClient: volthaClientMock,
	}
	portsByID := map[uint32]*DevicePort{}
	portsByID[16777216] = &DevicePort{
		Name:  "SDX6320031",
		ID:    16777216,
		State: PortStateUp,
	}
	device := &Device{
		ID:            "SDX6320031",
		vclientHolder: volthaServiceClientHolder,
		PortsByID:     portsByID,
	}
	items := []*voltha.LogicalPort{}
	item := &voltha.LogicalPort{
		Id:           "SDX6320031-1",
		DeviceId:     "SDX6320031",
		DevicePortNo: 16777216,
		OfpPort: &openflow_13.OfpPort{
			PortNo: 16777216,
			Name:   "SDX6320031-1",
		},
	}
	items = append(items, item)

	ofpps := &voltha.LogicalPorts{
		Items: items,
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad := &AuditDevice{
				device: device,
			}
			volthaClientMock.EXPECT().ListLogicalDevicePorts(gomock.Any(), gomock.Any(), gomock.Any()).Return(ofpps, nil).AnyTimes()
			appMock := mocks.NewMockApp(gomock.NewController(t))
			NewController(ctx, appMock)
			appMock.EXPECT().SetRebootFlag(gomock.Any()).AnyTimes()
			appMock.EXPECT().PortDownInd(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutPort(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			if err := ad.Start(tt.args.ctx, tt.args.taskID); (err != nil) != tt.wantErr {
				t.Errorf("AuditDevice.Start() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
# [EOF] - delta:force
