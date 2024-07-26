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

package application

import (
	"context"
	"testing"
	"voltha-go-controller/internal/pkg/of"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
)

func TestTickTask_Name(t *testing.T) {
	tt := &TickTask{}
	got := tt.Name()
	assert.NotNil(t, got)
	got1 := tt.TaskID()
	assert.NotNil(t, got1)
	got2 := tt.Timestamp()
	assert.NotNil(t, got2)
	ipk := IgmpPacketTask{}
	got3 := ipk.Name()
	assert.NotNil(t, got3)
	got4 := ipk.TaskID()
	assert.NotNil(t, got4)
	got5 := ipk.Timestamp()
	assert.NotNil(t, got5)
	mt := &UpdateMvlanTask{}
	got6 := mt.Name()
	assert.NotNil(t, got6)
	got7 := mt.TaskID()
	assert.NotNil(t, got7)
	got8 := mt.Timestamp()
	assert.NotNil(t, got8)
	got9 := NewTickTask()
	assert.NotNil(t, got9)
}

func TestTickTask_Start(t *testing.T) {
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
			name: "TickTask_Start",
			args: args{
				ctx: context.Background(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt1 := &TickTask{}
			if err := tt1.Start(tt.args.ctx, tt.args.taskID); (err != nil) != tt.wantErr {
				t.Errorf("TickTask.Start() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewIgmpPacketTask(t *testing.T) {
	type args struct {
		device string
		port   string
		pkt    gopacket.Packet
	}
	tests := []struct {
		name string
		args args
		want *IgmpPacketTask
	}{
		{
			name: "NewIgmpPacketTask",
			args: args{
				device: "SDX6320031",
				port:   "16777472",
			},
			want: &IgmpPacketTask{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewIgmpPacketTask(tt.args.device, tt.args.port, tt.args.pkt)
			assert.NotNil(t, got)
		})
	}
}

func TestNewUpdateMvlanTask(t *testing.T) {
	type args struct {
		mvp      *MvlanProfile
		deviceID string
	}
	tests := []struct {
		name string
		args args
		want *UpdateMvlanTask
	}{
		{
			name: "NewUpdateMvlanTask",
			args: args{
				mvp:      &MvlanProfile{},
				deviceID: "SDX6320031",
			},
			want: &UpdateMvlanTask{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewUpdateMvlanTask(tt.args.mvp, tt.args.deviceID)
			assert.NotNil(t, got)
		})
	}
}

func TestUpdateMvlanTask_Start(t *testing.T) {
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
			name: "UpdateMvlanTask_Start",
			args: args{
				ctx:    context.Background(),
				taskID: uint8(123),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mt := &UpdateMvlanTask{
				DeviceID: "SDX6320031",
				mvp: &MvlanProfile{
					Mvlan: of.VlanAny,
				},
			}
			if err := mt.Start(tt.args.ctx, tt.args.taskID); (err != nil) != tt.wantErr {
				t.Errorf("UpdateMvlanTask.Start() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
