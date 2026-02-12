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

package application

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"voltha-go-controller/internal/test/mocks"

	"go.uber.org/mock/gomock"
	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
)

func TestDeleteDbPathKeys(t *testing.T) {
	type args struct {
		cntx    context.Context
		keyPath string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Positive_Case_DeleteDbPathKeys",
			args: args{
				cntx:    context.Background(),
				keyPath: "test_key",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().DeleteAll(gomock.Any(), gomock.Any()).AnyTimes()
			if err := DeleteDbPathKeys(tt.args.cntx, tt.args.keyPath); (err != nil) != tt.wantErr {
				t.Errorf("DeleteDbPathKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMigrateVnets(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	voltVnet_test := &VoltVnet{
		Version: "v3",
		VnetConfig: VnetConfig{
			Name:      "2310-4096-4096",
			VnetType:  "Encapsulation",
			SVlan:     2310,
			CVlan:     4096,
			UniVlan:   4096,
			SVlanTpid: 0,
			DhcpRelay: true,
		},
		VnetOper: VnetOper{
			PendingDeviceToDelete: "SDX63200313",
		},
	}

	byteData, _ := json.Marshal(voltVnet_test)
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_DeleteDbPathKeys",
			args: args{
				cntx: context.Background(),
				data: byteData,
			},
			want: string(byteData),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateVnets(tt.args.cntx, tt.args.data); reflect.DeepEqual(got, tt.want) {
				t.Errorf("MigrateVnets() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateServices(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	vsmap := make(map[string]interface{})
	vsmap["MecLearning"] = true
	byteData, _ := json.Marshal(&vsmap)
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateServices",
			args: args{
				cntx: context.Background(),
				data: byteData,
			},
			want: string(byteData),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateServices(tt.args.cntx, tt.args.data); reflect.DeepEqual(got, tt.want) {
				t.Errorf("MigrateServices() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateVpvs(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	vpvmap := make(map[string]interface{})
	vpvmap["MacLearning"] = true
	vpvmap["UsFlowsApplied"] = true
	vpvmap["DsFlowsApplied"] = true
	byteData, _ := json.Marshal(&vpvmap)
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateVpvs",
			args: args{
				cntx: context.Background(),
				data: byteData,
			},
			want: string(byteData),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateVpvs(tt.args.cntx, tt.args.data); reflect.DeepEqual(got, tt.want) {
				t.Errorf("MigrateVpvs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateMvlans(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	devicesList := make(map[string]OperInProgress)
	devicesList["SDX6320031"] = opt82
	mvp := &MvlanProfile{
		DevicesList: devicesList,
	}
	byteData, _ := json.Marshal(mvp)
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateMvlans",
			args: args{
				cntx: context.Background(),
				data: byteData,
			},
			want: string(byteData),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateMvlans(tt.args.cntx, tt.args.data); reflect.DeepEqual(got, tt.want) {
				t.Errorf("MigrateMvlans() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateIgmpConfs(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	igmpProfile_data := IgmpProfile{
		ProfileID: "test_profile_id",
	}
	b, err := json.Marshal(igmpProfile_data)
	if err != nil {
		panic(err)
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test_MigrateIgmpConfs",
			args: args{
				cntx: context.Background(),
				data: b,
			},
			want: "ModuleToBeDeleted",
		},
		{
			name: "unmarshal error",
			args: args{
				cntx: context.Background(),
				data: []byte{},
			},
		},
		{
			name: "WriteToDb_error",
			args: args{
				cntx: context.Background(),
				data: b,
			},
			want: "ModuleToBeDeleted",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "test_MigrateIgmpConfs":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutIgmpProfile(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				if got := MigrateIgmpConfs(tt.args.cntx, tt.args.data); got != tt.want {
					t.Errorf("MigrateIgmpConfs() = %v, want %v", got, tt.want)
				}
			case "unmarshal error":
				if got := MigrateIgmpConfs(tt.args.cntx, tt.args.data); got != tt.want {
					t.Errorf("MigrateIgmpConfs() = %v, want %v", got, tt.want)
				}
			case "WriteToDb_error":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutIgmpProfile(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("error"))
				if got := MigrateIgmpConfs(tt.args.cntx, tt.args.data); got != tt.want {
					t.Errorf("MigrateIgmpConfs() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestMigrateIgmpGroups(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateIgmpGroups",
			args: args{
				cntx: context.Background(),
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateIgmpGroups(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateIgmpGroups() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateIgmpDevices(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateIgmpDevices",
			args: args{
				cntx: context.Background(),
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateIgmpDevices(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateIgmpDevices() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateIgmpChannels(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateIgmpChannels",
			args: args{
				cntx: context.Background(),
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateIgmpChannels(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateIgmpChannels() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateIgmpPorts(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateIgmpPorts",
			args: args{
				cntx: context.Background(),
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateIgmpPorts(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateIgmpPorts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateIgmpProfs(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateIgmpProfs",
			args: args{
				cntx: context.Background(),
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateIgmpProfs(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateIgmpProfs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateMcastConfs(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateMcastConfs",
			args: args{
				cntx: context.Background(),
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateMcastConfs(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateMcastConfs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateLogLevels(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateLogLevels",
			args: args{
				cntx: context.Background(),
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateLogLevels(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateLogLevels() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateHealth(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateHealth",
			args: args{
				cntx: context.Background(),
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateHealth(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateHealth() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigratePonCounters(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigratePonCounters",
			args: args{
				cntx: context.Background(),
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigratePonCounters(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigratePonCounters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateChannelCounters(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateChannelCounters",
			args: args{
				cntx: context.Background(),
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateChannelCounters(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateChannelCounters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateServiceCounters(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateServiceCounters",
			args: args{
				cntx: context.Background(),
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateServiceCounters(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateServiceCounters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateNbDevices(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateNbDevices",
			args: args{
				cntx: context.Background(),
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateNbDevices(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateNbDevices() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateFlowHash(t *testing.T) {
	type args struct {
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateFlowHash",
			args: args{
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateFlowHash(tt.args.data); got != tt.want {
				t.Errorf("MigrateFlowHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateMeters(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateMeters",
			args: args{
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateMeters(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateMeters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateDevices(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateFlowHash",
			args: args{
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateDevices(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateDevices() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateDevicePorts(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateFlowHash",
			args: args{
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateDevicePorts(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateDevicePorts() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateDeviceFlows(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateFlowHash",
			args: args{
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateDeviceFlows(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateDeviceFlows() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateDeviceGroups(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateFlowHash",
			args: args{
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateDeviceGroups(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateDeviceGroups() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateDeviceMeters(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateFlowHash",
			args: args{
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateDeviceMeters(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateDeviceMeters() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMigrateDeviceFlowHash(t *testing.T) {
	type args struct {
		cntx context.Context
		data []byte
	}
	data := []byte{}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Positive_Case_MigrateFlowHash",
			args: args{
				data: data,
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MigrateDeviceFlowHash(tt.args.cntx, tt.args.data); got != tt.want {
				t.Errorf("MigrateDeviceFlowHash() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFetchAndMigrateDeviceDBData(t *testing.T) {
	type args struct {
		module string
	}
	var module string
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Positive_Case_MigrateFlowHash",
			args: args{
				module: module,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := FetchAndMigrateDeviceDBData(tt.args.module); (err != nil) != tt.wantErr {
				t.Errorf("FetchAndMigrateDeviceDBData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDataMigration_WriteToDb(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Positive_Case_MigrateFlowHash",
			args: args{
				cntx: context.Background(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := &DataMigration{}
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutMigrationInfo(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			if err := md.WriteToDb(tt.args.cntx); (err != nil) != tt.wantErr {
				t.Errorf("DataMigration.WriteToDb() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetMigrationInfo(t *testing.T) {
	type args struct {
		cntx   context.Context
		dmInfo *DataMigration
	}
	dmInfo := &DataMigration{
		Version: "v1",
		Status:  "done",
	}
	dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
	db = dbintf
	dbintf.EXPECT().GetMigrationInfo(gomock.Any()).Return("migrationInfo", nil).AnyTimes()
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Positive_Case_GetMigrationInfo",
			args: args{
				cntx:   context.Background(),
				dmInfo: dmInfo,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := GetMigrationInfo(tt.args.cntx, tt.args.dmInfo); (err != nil) != tt.wantErr {
				t.Errorf("GetMigrationInfo() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckIfMigrationRequired(t *testing.T) {
	type args struct {
		ctx context.Context
	}

	dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
	db = dbintf
	dbintf.EXPECT().GetMigrationInfo(gomock.Any()).Return("Migration_Info", nil).AnyTimes()
	dbintf.EXPECT().PutMigrationInfo(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Positive_Case_CheckIfMigrationRequired",
			args: args{
				ctx: context.Background(),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckIfMigrationRequired(tt.args.ctx); got != tt.want {
				t.Errorf("CheckIfMigrationRequired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDataMigration_DelFromDb(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Positive_Case_DelFromDb",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "Negetive_Case_DelFromDb",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := &DataMigration{}
			switch tt.name {
			case "Positive_Case_DelFromDb":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().DelMigrationInfo(gomock.Any()).Return(nil).AnyTimes()
			case "Negetive_Case_DelFromDb":
				myError := errors.New("WRONG MESSAGE")
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().DelMigrationInfo(gomock.Any()).Return(myError).AnyTimes()
			}
			md.DelFromDb(tt.args.cntx)
		})
	}
}

func TestMigrateDBData(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	byteArr := []byte{23}
	dbPathKeysValueMap := map[string]*kvstore.KVPair{}
	dbPathKeysValueMap["devices/%s/flows/"] = &kvstore.KVPair{
		Key:   "devices/%s/flows/",
		Value: byteArr,
	}

	dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
	db = dbintf
	dbintf.EXPECT().List(gomock.Any(), gomock.Any()).Return(dbPathKeysValueMap, nil).AnyTimes()

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Positive_Case_DelFromDb",
			args: args{
				cntx: context.Background(),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := MigrateDBData(tt.args.cntx); (err != nil) != tt.wantErr {
				t.Errorf("MigrateDBData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
