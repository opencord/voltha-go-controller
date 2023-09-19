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
	"testing"
	common "voltha-go-controller/internal/pkg/types"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
)

func TestVoltApplication_InitIgmpSrcMac(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			va.InitIgmpSrcMac()
		})
	}
}

func TestVoltApplication_UpdateIgmpProfile(t *testing.T) {
	type args struct {
		cntx              context.Context
		igmpProfileConfig *common.IGMPConfig
	}
	igmpConfig := &common.IGMPConfig{
		ProfileID:      "test_profile_id",
		FastLeave:      &vgcRebooted,
		PeriodicQuery:  &isUpgradeComplete,
		WithRAUpLink:   &isUpgradeComplete,
		WithRADownLink: &isUpgradeComplete,
	}
	igmpProfile_data := &IgmpProfile{
		ProfileID: "test_profile_id",
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "UpdateIgmpProfile",
			args: args{
				cntx:              context.Background(),
				igmpProfileConfig: igmpConfig,
			},
		},
		{
			name: "UpdateIgmpProfile_Profile_not_found",
			args: args{
				cntx:              context.Background(),
				igmpProfileConfig: igmpConfig,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			switch tt.name {
			case "UpdateIgmpProfile":
				dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
				db = dbintf
				dbintf.EXPECT().PutIgmpProfile(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				va.IgmpProfilesByName.Store("test_profile_id", igmpProfile_data)
				if err := va.UpdateIgmpProfile(tt.args.cntx, tt.args.igmpProfileConfig); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.UpdateIgmpProfile() error = %v, wantErr %v", err, tt.wantErr)
				}
			case "UpdateIgmpProfile_Profile_not_found":
				igmpConfig.ProfileID = ""
				if err := va.UpdateIgmpProfile(tt.args.cntx, tt.args.igmpProfileConfig); (err != nil) != tt.wantErr {
					t.Errorf("VoltApplication.UpdateIgmpProfile() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestVoltApplication_resetIgmpProfileToDefault(t *testing.T) {
	type args struct {
		cntx context.Context
	}
	igmpProfile_data := &IgmpProfile{
		ProfileID: "test_profile_id",
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "resetIgmpProfileToDefault",
			args: args{
				cntx: context.Background(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := &VoltApplication{}
			va.IgmpProfilesByName.Store("", igmpProfile_data)
			dbintf := mocks.NewMockDBIntf(gomock.NewController(t))
			db = dbintf
			dbintf.EXPECT().PutIgmpProfile(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			va.resetIgmpProfileToDefault(tt.args.cntx)
		})
	}
}
