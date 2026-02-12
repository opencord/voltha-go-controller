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
	"sync"
	"testing"
	"voltha-go-controller/internal/pkg/holder"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/test/mocks"

	"go.uber.org/mock/gomock"

	"github.com/stretchr/testify/assert"
)

func TestModMeterTask_Start(t *testing.T) {
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
			name: "mmt.command == of.MeterCommandAdd",
			args: args{
				ctx:    context.Background(),
				taskID: uint8(1),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meters := make(map[uint32]*of.Meter)
			meters[uint32(1)] = &of.Meter{
				ID: uint32(1),
			}
			volthaClientMock := mocks.NewMockVolthaServiceClient(gomock.NewController(t))
			mmt := &ModMeterTask{
				meter: &of.Meter{
					ID: uint32(1),
				},
				device: &Device{
					meterLock: sync.RWMutex{},
					meters:    meters,
					State:     DeviceStateUP,
					vclientHolder: &holder.VolthaServiceClientHolder{
						VolthaSvcClient: volthaClientMock,
					},
				},
			}
			mmt.meter.ID = uint32(2)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().DelDeviceMeter(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			volthaClientMock.EXPECT().UpdateLogicalDeviceMeterTable(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
			err := mmt.Start(tt.args.ctx, tt.args.taskID)
			assert.Nil(t, err)
		})
	}
}

func TestNewModMeterTask(t *testing.T) {
	type args struct {
		ctx     context.Context
		command of.MeterCommand
		meter   *of.Meter
		device  *Device
	}
	tests := []struct {
		name string
		args args
		want *ModMeterTask
	}{
		{
			name: "NewModMeterTask",
			args: args{
				ctx:     context.Background(),
				command: of.MeterCommandAdd,
				meter: &of.Meter{
					ID: uint32(1),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewModMeterTask(tt.args.ctx, tt.args.command, tt.args.meter, tt.args.device)
			assert.NotNil(t, got)
		})
	}
}

func TestModMeterTask_Name(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "ModMeterTask_Name",
			want: "Add Flows Task",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mmt := &ModMeterTask{}
			if got := mmt.Name(); got != tt.want {
				t.Errorf("ModMeterTask.Name() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModMeterTask_TaskID(t *testing.T) {
	tests := []struct {
		name string
		want uint8
	}{
		{
			name: "ModMeterTask_TaskID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mmt := &ModMeterTask{}
			if got := mmt.TaskID(); got != tt.want {
				t.Errorf("ModMeterTask.TaskID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModMeterTask_Timestamp(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "ModMeterTask_Timestamp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mmt := &ModMeterTask{}
			if got := mmt.Timestamp(); got != tt.want {
				t.Errorf("ModMeterTask.Timestamp() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModMeterTask_Stop(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "ModMeterTask_Stop",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mmt := &ModMeterTask{}
			mmt.Stop()
		})
	}
}
