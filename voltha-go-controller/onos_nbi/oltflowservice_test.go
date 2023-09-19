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

package onosnbi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOltFlowServiceHandle_ServeHTTP(t *testing.T) {
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
		oh   *OltFlowServiceHandle
		args args
	}{
		{
			name: "OltFlowServiceHandle_ServeHTTP",
			args: args{
				w: rr,
				r: req,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oh := &OltFlowServiceHandle{}
			oh.ServeHTTP(tt.args.w, tt.args.r)
		})
	}
}

func TestOltFlowServiceHandle_configureOltFlowService(t *testing.T) {
	type args struct {
		cntx context.Context
		w    http.ResponseWriter
		r    *http.Request
	}
	tests := []struct {
		name string
		oh   *OltFlowServiceHandle
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oh := &OltFlowServiceHandle{}
			oh.configureOltFlowService(tt.args.cntx, tt.args.w, tt.args.r)
		})
	}
}
