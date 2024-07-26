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
	"testing"

	"github.com/google/gopacket/layers"
)

func TestGetMetadataForL2Protocol(t *testing.T) {
	type args struct {
		etherType layers.EthernetType
	}
	tests := []struct {
		name    string
		args    args
		want    uint8
		wantErr bool
	}{
		{
			name: "EthernetTypeDot1QDoubleTag",
			args: args{
				etherType: layers.EthernetTypeDot1QDoubleTag,
			},
			want: 2,
		},
		{
			name: "EthernetTypeQinQDoubleTag",
			args: args{
				etherType: layers.EthernetTypeQinQDoubleTag,
			},
			want: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "EthernetTypeDot1QDoubleTag", "EthernetTypeQinQDoubleTag":
				got, err := GetMetadataForL2Protocol(tt.args.etherType)
				if (err != nil) != tt.wantErr {
					t.Errorf("GetMetadataForL2Protocol() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if got != tt.want {
					t.Errorf("GetMetadataForL2Protocol() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func Test_convertToUInt64(t *testing.T) {
	type args struct {
		data string
	}
	tests := []struct {
		name string
		args args
		want uint64
	}{
		{
			name: "ParseUint_error",
			args: args{
				data: "test",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := convertToUInt64(tt.args.data); got != tt.want {
				t.Errorf("convertToUInt64() = %v, want %v", got, tt.want)
			}
		})
	}
}
