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

package tasks

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTasks(t *testing.T) {
	type args struct {
		ctx context.Context
	}
	tasks := &Tasks{}
	tests := []struct {
		name string
		args args
		want *Tasks
	}{
		{
			name: "NewTasks",
			args: args{
				ctx: context.Background(),
			},
			want: tasks,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTasks(tt.args.ctx)
			assert.NotNil(t, got)
		})
	}
}

func TestTasks_CheckAndInitialize(t *testing.T) {
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Tasks_CheckAndInitialize",
			args: args{
				ctx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := &Tasks{}
			ts.CheckAndInitialize(tt.args.ctx)
		})
	}
}

func TestTasks_StopAll(t *testing.T) {
	task := []Task{
		NewTaskSet("task1"),
	}
	tests := []struct {
		name string
	}{
		{
			name: "Tasks_StopAll",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := &Tasks{
				queued: task,
			}
			ts.StopAll()
		})
	}
}

func TestTasks_executeTasks(t *testing.T) {
	task := []Task{
		NewTaskSet("task1"),
	}
	tests := []struct {
		name string
	}{
		{
			name: "Tasks_executeTasks",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := &Tasks{
				queued: task,
			}
			ts.executeTasks()
		})
	}
}

func TestTaskSet_Start(t *testing.T) {
	type args struct {
		ctx    context.Context
		taskID uint8
	}
	task := []Task{
		NewTaskSet("task1"),
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Tasks_TaskSet_Start",
			args: args{
				ctx:    context.Background(),
				taskID: 25,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := &TaskSet{
				queued: task,
			}
			if err := ts.Start(tt.args.ctx, tt.args.taskID); (err != nil) != tt.wantErr {
				t.Errorf("TaskSet.Start() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
