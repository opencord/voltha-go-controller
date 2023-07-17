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
	"testing"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
)

var Del_error = "Del_error"

func TestUpdateDbData(t *testing.T) {
	type args struct {
		cntx   context.Context
		dbPath string
		hash   string
		value  interface{}
	}
	val := &VoltVnet{
		Version: "test_version",
		VnetConfig: VnetConfig{
			Name:     "test_name",
			VnetType: "test_vnet_type",
		},
		VnetOper: VnetOper{
			PendingDeviceToDelete: "test_PendingDeviceToDelete",
		},
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Update_Db_Data",
			args: args{
				cntx:   context.Background(),
				dbPath: "vnets/",
				hash:   "test_hash",
				value:  val,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().DelVnet(tt.args.cntx, tt.args.hash).Return(nil).Times(1)
			if err := UpdateDbData(tt.args.cntx, tt.args.dbPath, tt.args.hash, tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("UpdateDbData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_updateServices(t *testing.T) {
	type args struct {
		cntx  context.Context
		hash  string
		value interface{}
	}
	val := &VoltService{
		VoltServiceOper: VoltServiceOper{
			Device: test_device,
		},
		Version: "test_version",
		VoltServiceCfg: VoltServiceCfg{
			Name: "test_name",
		},
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "updateServices",
			args: args{
				cntx:  context.Background(),
				hash:  "test_hash",
				value: val,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := updateServices(tt.args.cntx, tt.args.hash, tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("updateServices() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_updateVpvs(t *testing.T) {
	type args struct {
		cntx  context.Context
		hash  string
		value interface{}
	}
	val := &VoltPortVnet{
		Device: test_device,
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "updateVpvs",
			args: args{
				cntx:  context.Background(),
				hash:  "test_hash",
				value: val,
			},
		},
		{
			name: "Del error",
			args: args{
				cntx:  context.Background(),
				hash:  "hash-hash1",
				value: val,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "updateVpvs":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutVpv(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				dbintf.EXPECT().Del(tt.args.cntx, gomock.Any()).Return(nil).Times(1)
				if err := updateVpvs(tt.args.cntx, tt.args.hash, tt.args.value); (err != nil) != tt.wantErr {
					t.Errorf("updateVpvs() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "Del error":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutVpv(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				dbintf.EXPECT().Del(tt.args.cntx, gomock.Any()).Return(errors.New("error")).Times(1)
				if err := updateVpvs(tt.args.cntx, tt.args.hash, tt.args.value); (err != nil) != tt.wantErr {
					t.Errorf("updateVpvs() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func Test_updateMvlans(t *testing.T) {
	type args struct {
		cntx  context.Context
		hash  string
		value interface{}
	}
	grp := make(map[string]*MvlanGroup)
	grp["static"] = &MvlanGroup{
		Name: "test_name",
	}
	val := &MvlanProfile{
		Version: "test_version",
		Name:    "test_name",
		Groups:  grp,
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "updateMvlans",
			args: args{
				cntx:  context.Background(),
				hash:  "test_hash",
				value: val,
			},
		},
		{
			name: write_to_db_error,
			args: args{
				cntx:  context.Background(),
				hash:  "test_hash",
				value: val,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "updateMvlans":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutMvlan(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				if err := updateMvlans(tt.args.cntx, tt.args.hash, tt.args.value); (err != nil) != tt.wantErr {
					t.Errorf("updateMvlans() error = %v, wantErr %v", err, tt.wantErr)
				}
			case write_to_db_error:
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutMvlan(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("error")).Times(1)
				if err := updateMvlans(tt.args.cntx, tt.args.hash, tt.args.value); (err != nil) != tt.wantErr {
					t.Errorf("updateMvlans() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func Test_updateIgmpGroups(t *testing.T) {
	type args struct {
		cntx  context.Context
		hash  string
		value interface{}
	}
	val := &IgmpGroup{
		Version: "test_version",
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "updateIgmpGroups",
			args: args{
				cntx:  context.Background(),
				hash:  "test_hash",
				value: val,
			},
		},
		{
			name: "PutIgmpGroup_error",
			args: args{
				cntx:  context.Background(),
				hash:  "test_hash",
				value: val,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "updateIgmpGroups":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutIgmpGroup(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				if err := updateIgmpGroups(tt.args.cntx, tt.args.hash, tt.args.value); (err != nil) != tt.wantErr {
					t.Errorf("updateIgmpGroups() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "PutIgmpGroup_error":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutIgmpGroup(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("error")).Times(1)
				if err := updateIgmpGroups(tt.args.cntx, tt.args.hash, tt.args.value); (err != nil) != tt.wantErr {
					t.Errorf("updateIgmpGroups() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func Test_updateIgmpDevices(t *testing.T) {
	type args struct {
		cntx  context.Context
		hash  string
		value interface{}
	}
	val := &IgmpGroupDevice{
		Device: test_device,
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "updateIgmpDevices",
			args: args{
				cntx:  context.Background(),
				hash:  "test_hash",
				value: val,
			},
		},
		{
			name: "PutIgmpDevice_error",
			args: args{
				cntx:  context.Background(),
				hash:  "test_hash",
				value: val,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "updateIgmpDevices":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutIgmpDevice(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				if err := updateIgmpDevices(tt.args.cntx, tt.args.hash, tt.args.value); (err != nil) != tt.wantErr {
					t.Errorf("updateIgmpDevices() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "PutIgmpDevice_error":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutIgmpDevice(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("error")).Times(1)
				if err := updateIgmpDevices(tt.args.cntx, tt.args.hash, tt.args.value); (err != nil) != tt.wantErr {
					t.Errorf("updateIgmpDevices() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func Test_updateIgmpProfiles(t *testing.T) {
	type args struct {
		cntx  context.Context
		hash  string
		value interface{}
	}
	val := &IgmpProfile{
		ProfileID: "test_profile_id",
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "updateIgmpProfiles",
			args: args{
				cntx:  context.Background(),
				hash:  "test_hash",
				value: val,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := updateIgmpProfiles(tt.args.cntx, tt.args.hash, tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("updateIgmpProfiles() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIgmpGroup_migrateIgmpDevices(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "IgmpGroup_migrateIgmpDevices",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: invalid_value,
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: Del_error,
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "NewIgmpGroupDeviceFromBytes_error",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ig := &IgmpGroup{}
			switch tt.name {
			case "IgmpGroup_migrateIgmpDevices":
				val := &IgmpGroupDevice{
					Device: test_device,
				}
				b, err := json.Marshal(val)
				if err != nil {
					panic(err)
				}
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: b,
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetPrevIgmpDevices(gomock.Any(), gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				dbintf.EXPECT().Del(tt.args.cntx, gomock.Any()).Return(nil).Times(1)
				dbintf.EXPECT().PutIgmpDevice(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				ig.migrateIgmpDevices(tt.args.cntx)
			case invalid_value:
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: "invalid",
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetPrevIgmpDevices(gomock.Any(), gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				ig.migrateIgmpDevices(tt.args.cntx)
			case Del_error:
				val := &IgmpGroupDevice{
					Device: test_device,
				}
				b, err := json.Marshal(val)
				if err != nil {
					panic(err)
				}
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: b,
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetPrevIgmpDevices(gomock.Any(), gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				dbintf.EXPECT().Del(tt.args.cntx, gomock.Any()).Return(errors.New("error")).Times(1)
				dbintf.EXPECT().PutIgmpDevice(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				ig.migrateIgmpDevices(tt.args.cntx)
			case "NewIgmpGroupDeviceFromBytes_error":
				b, err := json.Marshal("test")
				if err != nil {
					panic(err)
				}
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: b,
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetPrevIgmpDevices(gomock.Any(), gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				ig.migrateIgmpDevices(tt.args.cntx)
			}
		})
	}
}

func TestIgmpGroupDevice_migrateIgmpChannels(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "IgmpGroupDevice_migrateIgmpChannels",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: invalid_value,
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: Del_error,
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "NewIgmpGroupChannelFromBytes_error",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			igd := &IgmpGroupDevice{}
			switch tt.name {
			case "IgmpGroupDevice_migrateIgmpChannels":
				val := IgmpGroupChannel{
					Device: test_device,
				}
				b, err := json.Marshal(val)
				if err != nil {
					panic(err)
				}
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: b,
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetPrevIgmpChannels(gomock.Any(), gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				dbintf.EXPECT().Del(tt.args.cntx, gomock.Any()).Return(nil).Times(1)
				dbintf.EXPECT().PutIgmpChannel(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				igd.migrateIgmpChannels(tt.args.cntx)
			case invalid_value:
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: "invalid",
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetPrevIgmpChannels(gomock.Any(), gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				igd.migrateIgmpChannels(tt.args.cntx)
			case Del_error:
				val := IgmpGroupChannel{
					Device: test_device,
				}
				b, err := json.Marshal(val)
				if err != nil {
					panic(err)
				}
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: b,
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetPrevIgmpChannels(gomock.Any(), gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				dbintf.EXPECT().Del(tt.args.cntx, gomock.Any()).Return(errors.New("error")).Times(1)
				dbintf.EXPECT().PutIgmpChannel(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("error")).Times(1)
				igd.migrateIgmpChannels(tt.args.cntx)
			case "NewIgmpGroupChannelFromBytes_error":
				b, err := json.Marshal("test")
				if err != nil {
					panic(err)
				}
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: b,
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetPrevIgmpChannels(gomock.Any(), gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				igd.migrateIgmpChannels(tt.args.cntx)
			}
		})
	}
}

func TestIgmpGroupChannel_migrateIgmpPorts(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "IgmpGroupChannel_migrateIgmpPorts",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: invalid_value,
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: Del_error,
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "NewIgmpGroupPortFromBytes_error",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			igc := &IgmpGroupChannel{}
			switch tt.name {
			case "IgmpGroupChannel_migrateIgmpPorts":
				val := IgmpGroupPort{
					Port: "test_port",
				}
				b, err := json.Marshal(val)
				if err != nil {
					panic(err)
				}
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: b,
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetPrevIgmpRcvrs(gomock.Any(), gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				dbintf.EXPECT().Del(tt.args.cntx, gomock.Any()).Return(nil).Times(1)
				dbintf.EXPECT().PutIgmpRcvr(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				igc.migrateIgmpPorts(tt.args.cntx)
			case invalid_value:
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: "invalid",
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetPrevIgmpRcvrs(gomock.Any(), gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				igc.migrateIgmpPorts(tt.args.cntx)
			case Del_error:
				val := IgmpGroupPort{
					Port: "test_port",
				}
				b, err := json.Marshal(val)
				if err != nil {
					panic(err)
				}
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: b,
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetPrevIgmpRcvrs(gomock.Any(), gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				dbintf.EXPECT().Del(tt.args.cntx, gomock.Any()).Return(errors.New("error")).Times(1)
				dbintf.EXPECT().PutIgmpRcvr(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("error")).Times(1)
				igc.migrateIgmpPorts(tt.args.cntx)
			case "NewIgmpGroupPortFromBytes_error":
				b, err := json.Marshal("invalid")
				if err != nil {
					panic(err)
				}
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: b,
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetPrevIgmpRcvrs(gomock.Any(), gomock.Any(), gomock.Any()).Return(test, nil).Times(1)
				// dbintf.EXPECT().Del(tt.args.cntx, gomock.Any()).Return(nil).Times(1)
				// dbintf.EXPECT().PutIgmpRcvr(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				igc.migrateIgmpPorts(tt.args.cntx)
			}
		})
	}
}
