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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestDeviceConfigHandle_ServeHTTP(t *testing.T) {
	req, err := http.NewRequest("GET", "/feth_device_config/", nil)
	if err != nil {
		t.Fatal(err)
	}

	vars := map[string]string{
		"id": "1",
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
			name: "DeviceConfigHandle_ServeHTTP",
			args: args{
				w: rr,
				r: req,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oh := &DeviceConfigHandle{}
			oh.ServeHTTP(tt.args.w, tt.args.r)
		})
	}
}
# [EOF] - delta:force
