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

// Package vpagent Common Logger initialization
package vpagent

import (
	"context"
	"errors"
	"testing"
)

func Test_isConnCanceled(t *testing.T) {
	type args struct {
		err error
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "isConnCanceled",
			args: args{
				err: context.Canceled,
			},
			want: true,
		},
		{
			name: "error_nil",
			args: args{
				err: nil,
			},
			want: false,
		},
		{
			name: "the client connection is closing",
			args: args{
				err: errors.New("Not Found"),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "isConnCanceled":
				if got := isConnCanceled(tt.args.err); got != tt.want {
					t.Errorf("isConnCanceled() = %v, want %v", got, tt.want)
				}
			case "error_nil":
				if got := isConnCanceled(tt.args.err); got != tt.want {
					t.Errorf("isConnCanceled() = %v, want %v", got, tt.want)
				}
			case "the client connection is closing":
				if got := isConnCanceled(tt.args.err); got != tt.want {
					t.Errorf("isConnCanceled() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
