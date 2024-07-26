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

package onosnbi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestMacLearnerHandle_ServeHTTP(t *testing.T) {
	req, err := http.NewRequest("GET", "/serve_http/", nil)
	if err != nil {
		t.Fatal(err)
	}

	vars := map[string]string{
		"deviceId":   "1",
		"portNumber": "2",
		"vlanId":     "3",
	}
	req = mux.SetURLVars(req, vars)

	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "MacLearnerHandle_ServeHTTP",
			args: args{
				w: rr,
				r: req,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mlh := &MacLearnerHandle{}
			mlh.ServeHTTP(tt.args.w, tt.args.r)
		})
	}
}

func TestMacLearnerHandle_GetAllMacLearnerInfo_ServeHTTP(t *testing.T) {
	req, err := http.NewRequest("GET", "/serve_http/", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "MacLearnerHandle_GetAllMacLearnerInfo_ServeHTTP",
			args: args{
				w: rr,
				r: req,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mlh := &MacLearnerHandle{}
			mlh.ServeHTTP(tt.args.w, tt.args.r)
		})
	}
}
