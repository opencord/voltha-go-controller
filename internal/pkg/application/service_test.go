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
	"sync"
	"testing"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/opencord/voltha-lib-go/v7/pkg/db/kvstore"
	"github.com/stretchr/testify/assert"
)

func TestVoltApplication_RestoreSvcsFromDb(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_RestoreSvcsFromDb",
			args: args{
				cntx: context.Background(),
			},
		},
		{
			name: "invalid_value_type",
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
			voltService := &VoltService{
				VoltServiceOper: VoltServiceOper{
					Device:           "SDX6320031",
					ForceDelete:      true,
					DeleteInProgress: true,
				},
				VoltServiceCfg: VoltServiceCfg{
					Name: "test_service_name",
				},
			}
			serviceToDelete := map[string]bool{}
			serviceToDelete[voltService.VoltServiceCfg.Name] = true
			va := &VoltApplication{
				ServicesToDelete: serviceToDelete,
			}
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			switch tt.name {
			case "VoltApplication_RestoreSvcsFromDb":

				b, err := json.Marshal(voltService)
				if err != nil {
					panic(err)
				}
				kvPair := map[string]*kvstore.KVPair{}
				kvPair["key"] = &kvstore.KVPair{
					Key:     "test_key",
					Value:   b,
					Version: 1,
				}
				dbintf.EXPECT().GetServices(tt.args.cntx).Return(kvPair, nil).Times(1)
				va.RestoreSvcsFromDb(tt.args.cntx)
			case "invalid_value_type":
				kvPair := map[string]*kvstore.KVPair{}
				kvPair["key"] = &kvstore.KVPair{
					Key:     "test_key",
					Value:   "invalid_value",
					Version: 1,
				}
				dbintf.EXPECT().GetServices(tt.args.cntx).Return(kvPair, nil).Times(1)
				va.RestoreSvcsFromDb(tt.args.cntx)
			case "unmarshal_error":
				b, err := json.Marshal("test")
				if err != nil {
					panic(err)
				}
				kvPair := map[string]*kvstore.KVPair{}
				kvPair["key"] = &kvstore.KVPair{
					Key:     "test_key",
					Value:   b,
					Version: 1,
				}
				dbintf.EXPECT().GetServices(tt.args.cntx).Return(kvPair, nil).Times(1)
				va.RestoreSvcsFromDb(tt.args.cntx)
			}
		})
	}
}

func TestVoltService_FlowRemoveFailure(t *testing.T) {
	type args struct {
		cntx      context.Context
		cookie    string
		errorCode uint32
		errReason string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltService_FlowRemoveFailure",
			args: args{
				cntx:      context.Background(),
				cookie:    "test_cookie",
				errorCode: 200,
				errReason: "test_reason",
			},
		},
		{
			name: "cookie_not_found",
			args: args{
				cntx:      context.Background(),
				cookie:    "test_cookie",
				errorCode: 200,
				errReason: "test_reason",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.name {
			case "VoltService_FlowRemoveFailure":
				associatedFlows := map[string]bool{}
				associatedFlows["test_cookie"] = true
				vs := &VoltService{
					VoltServiceOper: VoltServiceOper{
						AssociatedFlows: associatedFlows,
					},
				}
				vs.FlowRemoveFailure(tt.args.cntx, tt.args.cookie, tt.args.errorCode, tt.args.errReason)
			case "cookie_not_found":
				associatedFlows := map[string]bool{}
				associatedFlows["cookie"] = true
				vs := &VoltService{
					VoltServiceOper: VoltServiceOper{
						AssociatedFlows: associatedFlows,
					},
				}
				vs.FlowRemoveFailure(tt.args.cntx, tt.args.cookie, tt.args.errorCode, tt.args.errReason)
			}
		})
	}
}

func TestVoltApplication_GetServiceNameFromCookie(t *testing.T) {
	type args struct {
		cookie        uint64
		portName      string
		pbit          uint8
		device        string
		tableMetadata uint64
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "VoltApplication_GetServiceNameFromCookie",
			args: args{
				cookie:        uint64(1),
				portName:      "test_port_name",
				device:        "SDX6320031",
				pbit:          2,
				tableMetadata: uint64(2),
			},
		},
	}
	voltDev := &VoltDevice{
		Name:           "SDX6320031",
		SerialNum:      "SDX6320031",
		NniDhcpTrapVid: 123,
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t1 := GetApplication()
			t1.DevicesDisc = sync.Map{}
			t1.DevicesDisc.Store("SDX6320031", voltDev)
			voltPortVnets := make([]*VoltPortVnet, 0)
			voltPortVnet := &VoltPortVnet{
				Device:      "test_device",
				VlanControl: ONUCVlanOLTSVlan,
			}
			voltPortVnets = append(voltPortVnets, voltPortVnet)
			t1.VnetsByPort.Store("test_port_name", voltPortVnets)
			got := t1.GetServiceNameFromCookie(tt.args.cookie, tt.args.portName, tt.args.pbit, tt.args.device, tt.args.tableMetadata)
			assert.Nil(t, got)
		})
	}
}
