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
	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/test/mocks"

	"go.uber.org/mock/gomock"
	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
	"github.com/stretchr/testify/assert"
)

var vm = &VoltMeter{
	Name:    "test_name",
	Version: "test_version",
}
var write_to_db_error = "WriteToDb_error"
var invalid_value = "invalid_value"

func TestVoltApplication_DelMeterProf(t *testing.T) {
	type args struct {
		cntx context.Context
		name string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "VoltApplication_DelMeterProf",
			args: args{
				cntx: context.Background(),
				name: "test_name",
			},
		},
		{
			name: "GetMeterByName_!ok",
			args: args{
				cntx: context.Background(),
				name: "test_name",
			},
		},
		{
			name: "cfg.AssociatedServices != 0",
			args: args{
				cntx: context.Background(),
				name: "test_name",
			},
		},
		{
			name: "delmeterFromDevice",
			args: args{
				cntx: context.Background(),
				name: "test_name",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			switch tt.name {
			case "VoltApplication_DelMeterProf":
				vm1 := &VoltMeter{
					Name:    "test_name",
					Version: "test_version",
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().DelMeter(tt.args.cntx, tt.args.name).Return(nil).Times(1)
				va.MeterMgr.Meters.Store("test_name", vm1)
				if err := va.DelMeterProf(tt.args.cntx, tt.args.name); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.DelMeterProf() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "GetMeterByName_!ok":
				vm2 := &VoltMeter{
					Name:    "test_name",
					Version: "test_version",
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				va.MeterMgr.Meters.Store("test_name1", vm2)
				err := va.DelMeterProf(tt.args.cntx, tt.args.name)
				assert.NotNil(t, err)
			case "cfg.AssociatedServices != 0":
				vm3 := &VoltMeter{
					Name:               "test_name",
					Version:            "test_version",
					AssociatedServices: 1,
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				va.MeterMgr.Meters.Store("test_name", vm3)
				err := va.DelMeterProf(tt.args.cntx, tt.args.name)
				assert.NotNil(t, err)
			case "delmeterFromDevice":
				vd := &VoltDevice{
					Name: test_device,
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				_ = cntlr.NewController(context.Background(), mocks.NewMockApp(gomock.NewController(t)))
				dbintf.EXPECT().DelMeter(tt.args.cntx, tt.args.name).Return(nil).Times(1)
				va.MeterMgr.Meters.Store("test_name", vm)
				va.DevicesDisc.Store(test_device, vd)
				if err := va.DelMeterProf(tt.args.cntx, tt.args.name); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.DelMeterProf() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestMeterMgr_GetMeterByProfID(t *testing.T) {
	type args struct {
		id uint32
	}
	tests := []struct {
		name    string
		args    args
		want    *VoltMeter
		wantErr bool
	}{
		{
			name: "MeterMgr_GetMeterByProfID",
			args: args{
				id: uint32(1),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MeterMgr{}
			vm4 := &VoltMeter{
				Name: "test_name",
			}
			m.MetersByID.Store(tt.args.id, vm4)
			got, err := m.GetMeterByProfID(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("MeterMgr.GetMeterByProfID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.NotNil(t, got)
		})
	}
}

func TestVoltApplication_UpdateMeterProf(t *testing.T) {
	type args struct {
		cntx context.Context
		cfg  VoltMeter
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_UpdateMeterProf",
			args: args{
				cntx: context.Background(),
				cfg: VoltMeter{
					Name: "test_name",
				},
			},
		},
		{
			name: write_to_db_error,
			args: args{
				cntx: context.Background(),
				cfg: VoltMeter{
					Name: "test_name",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			switch tt.name {
			case "VoltApplication_UpdateMeterProf":
				va.MeterMgr.Meters.Store("test_name", vm)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutMeter(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				va.UpdateMeterProf(tt.args.cntx, tt.args.cfg)
			case write_to_db_error:
				va.MeterMgr.Meters.Store("test_name", vm)
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutMeter(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("error")).Times(1)
				va.UpdateMeterProf(tt.args.cntx, tt.args.cfg)
			}
		})
	}
}

func TestVoltApplication_AddMeterProf(t *testing.T) {
	type args struct {
		cntx context.Context
		cfg  VoltMeter
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_AddMeterProf",
			args: args{
				cntx: context.Background(),
				cfg:  VoltMeter{Name: "test_name"},
			},
		},
		{
			name: "GetMeterByName_ok",
			args: args{
				cntx: context.Background(),
				cfg:  VoltMeter{Name: "test_name"},
			},
		},
		{
			name: write_to_db_error,
			args: args{
				cntx: context.Background(),
				cfg:  VoltMeter{Name: "test_name"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			switch tt.name {
			case "VoltApplication_AddMeterProf":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutMeter(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
				va.AddMeterProf(tt.args.cntx, tt.args.cfg)
			case "GetMeterByName_ok":
				mm := &va.MeterMgr
				mm.Meters.Store(tt.args.cfg.Name, vm)
				va.AddMeterProf(tt.args.cntx, tt.args.cfg)
			case write_to_db_error:
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutMeter(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("error")).Times(1)
				va.AddMeterProf(tt.args.cntx, tt.args.cfg)
			}
		})
	}
}

func TestMeterMgr_RestoreMetersFromDb(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "MeterMgr_RestoreMetersFromDb",
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
			name: "unmarshal_error",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MeterMgr{}
			switch tt.name {
			case "MeterMgr_RestoreMetersFromDb":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				vm.ID = uint32(3)
				m.LastMeterID = uint32(2)
				b, err := json.Marshal(vm)
				if err != nil {
					panic(err)
				}
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: b,
				}
				dbintf.EXPECT().GetMeters(gomock.Any()).Return(test, nil).Times(1)
				m.RestoreMetersFromDb(tt.args.cntx)
			case invalid_value:
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: "test",
				}
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().GetMeters(gomock.Any()).Return(test, nil).Times(1)
				m.RestoreMetersFromDb(tt.args.cntx)
			case "unmarshal_error":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				vm.ID = uint32(3)
				m.LastMeterID = uint32(2)
				b, err := json.Marshal("test")
				if err != nil {
					panic(err)
				}
				test := map[string]*kvstore.KVPair{}
				test["test_device_id"] = &kvstore.KVPair{
					Key:   "test_device_id",
					Value: b,
				}
				dbintf.EXPECT().GetMeters(gomock.Any()).Return(test, nil).Times(1)
				m.RestoreMetersFromDb(tt.args.cntx)
			}
		})
	}
}

func TestMeterMgr_AddMeterToDevice(t *testing.T) {
	type args struct {
		port       string
		device     string
		meterID    uint32
		aggMeterID uint32
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "MeterMgr_AddMeterToDevice",
			args: args{
				port:       "test_port",
				device:     test_device,
				meterID:    uint32(3),
				aggMeterID: uint32(2),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MeterMgr{}
			m.MetersByID.Store(tt.args.meterID, vm)
			m.AddMeterToDevice(tt.args.port, tt.args.device, tt.args.meterID, tt.args.aggMeterID)
		})
	}
}

func TestVoltMeter_AddToDevice(t *testing.T) {
	type args struct {
		port   string
		device string
		aggVM  *VoltMeter
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltMeter_AddToDevice",
			args: args{
				port:   "test_port",
				device: test_device,
			},
		},
		{
			name: "Gir == 0",
			args: args{
				port:   "test_port",
				device: test_device,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vm1 := &VoltMeter{}
			switch tt.name {
			case "VoltMeter_AddToDevice":
				vm1.Cir = uint32(1)
				vm1.Air = uint32(1)
				vm1.Pir = uint32(1)
				vm1.Gir = uint32(1)
				vm1.Pbs = uint32(1)
				vm1.AddToDevice(tt.args.port, tt.args.device, tt.args.aggVM)
			case "Gir == 0":
				vm1.Cir = uint32(1)
				vm1.Air = uint32(1)
				vm1.Pir = uint32(1)
				vm1.Pbs = uint32(1)
				vm1.AddToDevice(tt.args.port, tt.args.device, tt.args.aggVM)
			}
		})
	}
}
