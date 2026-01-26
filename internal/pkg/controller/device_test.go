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
	"reflect"
	"testing"
	"voltha-go-controller/internal/pkg/holder"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	ofp "github.com/opencord/voltha-protos/v5/go/openflow_13"
	"github.com/stretchr/testify/assert"
)

func TestNewDevicePort(t *testing.T) {
	type args struct {
		mp *ofp.OfpPort
	}
	tests := []struct {
		name string
		args args
		want *DevicePort
	}{
		{
			name: "NewDevicePort",
			args: args{
				mp: &ofp.OfpPort{
					PortNo: uint32(1),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewDevicePort(tt.args.mp)
			assert.NotNil(t, got)
		})
	}
}

func TestDevice_UpdateFlows(t *testing.T) {
	type args struct {
		flow    *of.VoltFlow
		devPort *DevicePort
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Device_UpdateFlows",
			args: args{
				flow: &of.VoltFlow{
					PortName: "test_port_name",
				},
				devPort: &DevicePort{
					Name: "test_name",
				},
			},
		},
	}
	for _, tt := range tests {
		flushQueue := make(map[uint32]*UniIDFlowQueue)
		flushQueue[uint32(1)] = &UniIDFlowQueue{
			ID: uint32(1),
		}
		t.Run(tt.name, func(t *testing.T) {
			d := &Device{
				flowQueue: flushQueue,
				flowHash:  uint32(1),
			}
			d.UpdateFlows(tt.args.flow, tt.args.devPort)
		})
	}
}

func TestNewDevice(t *testing.T) {
	type args struct {
		cntx         context.Context
		id           string
		slno         string
		vclientHldr  *holder.VolthaServiceClientHolder
		southBoundID string
		mfr          string
		hwDesc       string
		swDesc       string
	}
	tests := []struct {
		name string
		args args
		want *Device
	}{
		{
			name: "TestNewDevice",
			args: args{
				cntx: context.Background(),
				id:   "test_id",
				slno: "test_sl_no",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().GetFlowHash(gomock.Any(), gomock.Any()).Return("1", nil).Times(1)
			got := NewDevice(tt.args.cntx, tt.args.id, tt.args.slno, tt.args.vclientHldr, tt.args.southBoundID, tt.args.mfr, tt.args.hwDesc, tt.args.swDesc)
			assert.NotNil(t, got)
		})
	}
}

func TestDevice_triggerFlowResultNotification(t *testing.T) {
	type args struct {
		cntx      context.Context
		cookie    uint64
		flow      *of.VoltSubFlow
		oper      of.Command
		bwDetails of.BwAvailDetails
		err       error
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Device_triggerFlowResultNotification",
			args: args{
				cntx:   context.Background(),
				cookie: uint64(1),
				flow: &of.VoltSubFlow{
					Cookie: uint64(1),
				},
				oper: of.CommandAdd,
				bwDetails: of.BwAvailDetails{
					PrevBw: "test_prev_bw",
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flows := make(map[uint64]*of.VoltSubFlow)
			flows[uint64(1)] = &of.VoltSubFlow{
				Cookie: uint64(1),
			}
			d := &Device{
				flows: flows,
			}
			appMock := mocks.NewMockApp(gomock.NewController(t))
			_ = NewController(context.Background(), appMock)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			appMock.EXPECT().ProcessFlowModResultIndication(gomock.Any(), gomock.Any()).Times(1)
			d.triggerFlowResultNotification(tt.args.cntx, tt.args.cookie, tt.args.flow, tt.args.oper, tt.args.bwDetails, tt.args.err)
		})
	}
}

func TestDevice_ResetCache(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "Device_ResetCache",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Device{}
			d.ResetCache()
		})
	}
}

func TestDevice_GetAllFlows(t *testing.T) {
	tests := []struct {
		name string
		want []*of.VoltSubFlow
	}{
		{
			name: "Device_GetAllFlows",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Device{}
			if got := d.GetAllFlows(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Device.GetAllFlows() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDevice_PacketOutReq(t *testing.T) {
	type args struct {
		outport     string
		inport      string
		data        []byte
		isCustomPkt bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Device_PacketOutReq",
			args: args{
				outport: "test_out_port",
				inport:  "test_in_port",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			portByName := make(map[string]*DevicePort)
			portByName["test_in_port"] = &DevicePort{
				Name: "test_device",
			}
			portByName["test_out_port"] = &DevicePort{
				Name: "test_device",
			}
			packetOutChannel := make(chan *ofp.PacketOut, 2)

			d := &Device{
				packetOutChannel: packetOutChannel,
				PortsByName:      portByName,
			}
			if err := d.PacketOutReq(tt.args.outport, tt.args.inport, tt.args.data, tt.args.isCustomPkt); (err != nil) != tt.wantErr {
				t.Errorf("Device.PacketOutReq() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDevice_SetFlowHash(t *testing.T) {
	type args struct {
		cntx context.Context
		hash uint32
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "Device_SetFlowHash",
			args: args{
				cntx: context.Background(),
				hash: uint32(2),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Device{}
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutFlowHash(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			d.SetFlowHash(tt.args.cntx, tt.args.hash)
		})
	}
}
