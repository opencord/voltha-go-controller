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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPadString(t *testing.T) {
	type args struct {
		value   string
		padSize int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "PadString",
			args: args{
				value:   "test_value",
				padSize: 20,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PadString(tt.args.value, tt.args.padSize)
			assert.NotNil(t, got)
		})
	}
}

func TestGetXid(t *testing.T) {
	tests := []struct {
		name string
		want uint32
	}{
		{
			name: "GetXid",
			want: uint32(2),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetXid(); got != tt.want {
				t.Errorf("GetXid() = %v, want %v", got, tt.want)
			}
		})
	}
}
