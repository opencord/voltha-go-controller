/*
* Copyright 2023-2024present Open Networking Foundation
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

package nbi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	app "voltha-go-controller/internal/pkg/application"

	"github.com/gorilla/mux"
)

func TestProfileHandle_GetProfile(t *testing.T) {
	req, err := http.NewRequest("GET", "/get_profile/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	vars := map[string]string{
		"id": "upstream_bw_profile_gpon",
	}
	req = mux.SetURLVars(req, vars)

	rr := httptest.NewRecorder()

	type args struct {
		cntx context.Context
		w    http.ResponseWriter
		r    *http.Request
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "GetProfile",
			args: args{
				cntx: context.Background(),
				w:    rr,
				r:    req,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mh := &ProfileHandle{}
			mh.GetProfile(tt.args.cntx, tt.args.w, tt.args.r)
		})
	}
}

func TestProfileHandle_DelProfile(t *testing.T) {
	var jsonStr = []byte(`{"id":"test_id"}`)

	req, err := http.NewRequest("DELETE", "/del_profile/", bytes.NewBuffer(jsonStr))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	var jsonStr1 = []byte(`{"id":123}`)

	req1, err1 := http.NewRequest("DELETE", "/del_profile/", bytes.NewBuffer(jsonStr1))
	if err1 != nil {
		t.Fatal(err1)
	}
	req1.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	type args struct {
		cntx context.Context
		w    http.ResponseWriter
		r    *http.Request
	}
	tests := []struct {
		name string
		mh   *ProfileHandle
		args args
	}{
		{
			name: "DelProfile",
			args: args{
				cntx: context.Background(),
				w:    rr,
				r:    req,
			},
		},
		{
			name: "DelProfile_unmarshal_error",
			args: args{
				cntx: context.Background(),
				w:    rr,
				r:    req1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mh := &ProfileHandle{}
			switch tt.name {
			case "DelProfile", "DelProfile_unmarshal_error":
				mh.DelProfile(tt.args.cntx, tt.args.w, tt.args.r)
			}
		})
	}
}

func TestProfileHandle_ServeHTTP(t *testing.T) {
	var jsonStr = []byte(`{"id": "upstream_bw_profile_gpon", "cir":"1000"}`)
	req, err := http.NewRequest("POST", "/profiles/upstream_bw_profile_gpon", bytes.NewBuffer(jsonStr))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc((&ProfileHandle{}).ServeHTTP)
	handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusConflict {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
}

func TestProfileHandle_AddProfile(t *testing.T) {
	type args struct {
		cntx context.Context
		w    http.ResponseWriter
		r    *http.Request
	}
	var jsonStr = []byte(`{"id": "upstream_bw_profile_gpon", "cir":"1000"}`)
	req, err := http.NewRequest("POST", "/profiles/upstream_bw_profile_gpon", bytes.NewBuffer(jsonStr))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	var jsonStr1 = []byte(`{
		"id":"upstream_bw_profile_gpon",
		"GuaranteedInformationRate":50000,
		"cCommittedBurstSizebs":10000,
		"CommittedInformationRate":50000,
		"PeakBurstSize":1000,
		"PeakInformationRate":300000
	 }`)
	req1, err1 := http.NewRequest("POST", "/profiles/upstream_bw_profile_gpon", bytes.NewBuffer(jsonStr1))
	if err1 != nil {
		t.Fatal(err1)
	}

	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	app.GetApplication()
	tests := []struct {
		name string
		mh   *ProfileHandle
		args args
	}{
		{
			name: "AddProfile_unmarshal_Error",
			args: args{
				cntx: context.Background(),
				w:    rr,
				r:    req,
			},
		},
		{
			name: "DelProfile",
			args: args{
				cntx: context.Background(),
				w:    rr,
				r:    req1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mh := &ProfileHandle{}
			switch tt.name {
			case "DelProfile_unmarshal_Error":
				mh.AddProfile(tt.args.cntx, tt.args.w, tt.args.r)
				// case "DelProfile":
				// 	// voltAppIntrface := mocks.NewMockVoltAppInterface(gomock.NewController(t))
				// 	// voltAppIntrface.EXPECT().AddMeterProf(gomock.Any(), gomock.Any()).Times(1)
				// 	mh.AddProfile(tt.args.cntx, tt.args.w, tt.args.r)
			}
		})
	}
}
