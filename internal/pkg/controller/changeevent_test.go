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

	ofp "github.com/opencord/voltha-protos/v5/go/openflow_13"
	"github.com/stretchr/testify/assert"
)

func TestNewChangeEventTask(t *testing.T) {
	type args struct {
		ctx    context.Context
		event  *ofp.ChangeEvent
		device *Device
	}
	tests := []struct {
		name string
		args args
		want *ChangeEventTask
	}{
		{
			name: "NewChangeEventTask",
			args: args{
				ctx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewChangeEventTask(tt.args.ctx, tt.args.event, tt.args.device)
			assert.NotNil(t, got)
		})
	}
}

func TestChangeEventTask_Name(t *testing.T) {
	cet := &ChangeEventTask{}
	got := cet.Name()
	assert.NotNil(t, got)
	got1 := cet.TaskID()
	assert.NotNil(t, got1)
	got2 := cet.Timestamp()
	assert.NotNil(t, got2)
}
# [EOF] - delta:force
