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

func TestMulticastHandle_ServeHTTP(t *testing.T) {
	req, err := http.NewRequest("DELETE", "/serve_http/", nil)
	if err != nil {
		t.Fatal(err)
	}

	vars := map[string]string{
		"egressvlan": "1",
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
			name: "MulticastHandle_ServeHTTP",
			args: args{
				w: rr,
				r: req,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iph := &MulticastHandle{}
			iph.ServeHTTP(tt.args.w, tt.args.r)
		})
	}
}

func TestMulticastHandle_AddMvlanInfo(t *testing.T) {
	var jsonStr = []byte(`{"ingressvlan":1,"egressvlan":2,"egressinnervlan":3,}`)
	req, err := http.NewRequest("POST", "/add_mvlan_info/", bytes.NewBuffer(jsonStr))
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
		args args
	}{
		{
			name: "AddMvlanInfo unmarshal error",
			args: args{
				cntx: context.Background(),
				w:    rr,
				r:    req,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iph := &MulticastHandle{}
			iph.AddMvlanInfo(tt.args.cntx, tt.args.w, tt.args.r)
		})
	}
}
