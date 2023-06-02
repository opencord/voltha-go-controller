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
	"testing"
	"voltha-go-controller/internal/pkg/of"
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
