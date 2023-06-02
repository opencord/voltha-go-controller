/*
* Copyright 2023-present Open Networking Foundation
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mh := &ProfileHandle{}
			mh.DelProfile(tt.args.cntx, tt.args.w, tt.args.r)
		})
	}
}

func TestProfileHandle_AddProfile(t *testing.T) {
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
