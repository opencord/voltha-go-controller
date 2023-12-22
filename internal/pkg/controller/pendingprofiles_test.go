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
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestPendingProfilesTask_Start(t *testing.T) {
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
			name: "PendingProfilesTask_Start",
			args: args{
				ctx:    context.Background(),
				taskID: uint8(1),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ppt := &PendingProfilesTask{
				device: &Device{
					ID: "test_device",
				},
			}
			appMock := mocks.NewMockApp(gomock.NewController(t))
			_ = NewController(context.Background(), appMock)
			appMock.EXPECT().SetRebootFlag(gomock.Any()).AnyTimes()
			appMock.EXPECT().TriggerPendingProfileDeleteReq(gomock.Any(), gomock.Any()).AnyTimes()
			appMock.EXPECT().TriggerPendingMigrateServicesReq(gomock.Any(), gomock.Any()).AnyTimes()
			appMock.EXPECT().UpdateMvlanProfilesForDevice(gomock.Any(), gomock.Any()).AnyTimes()
			if err := ppt.Start(tt.args.ctx, tt.args.taskID); (err != nil) != tt.wantErr {
				t.Errorf("PendingProfilesTask.Start() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewPendingProfilesTask(t *testing.T) {
	type args struct {
		device *Device
	}
	tests := []struct {
		name string
		args args
		want *PendingProfilesTask
	}{
		{
			name: "NewPendingProfilesTask",
			args: args{
				device: &Device{
					ctx: context.Background(),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewPendingProfilesTask(tt.args.device)
			assert.NotNil(t, got)
		})
	}
}

func TestPendingProfilesTask_Name(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "PendingProfilesTask_Name",
			want: "Pending Profiles Task",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ppt := &PendingProfilesTask{}
			if got := ppt.Name(); got != tt.want {
				t.Errorf("PendingProfilesTask.Name() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPendingProfilesTask_TaskID(t *testing.T) {
	tests := []struct {
		name string
		want uint8
	}{
		{
			name: "PendingProfilesTask_TaskID",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ppt := &PendingProfilesTask{}
			if got := ppt.TaskID(); got != tt.want {
				t.Errorf("PendingProfilesTask.TaskID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPendingProfilesTask_Timestamp(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "PendingProfilesTask_Timestamp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ppt := &PendingProfilesTask{}
			if got := ppt.Timestamp(); got != tt.want {
				t.Errorf("PendingProfilesTask.Timestamp() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPendingProfilesTask_Stop(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "PendingProfilesTask_Stop",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ppt := &PendingProfilesTask{}
			ppt.Stop()
		})
	}
}
# [EOF] - delta:force
