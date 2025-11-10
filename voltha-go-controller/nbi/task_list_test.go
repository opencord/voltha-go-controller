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
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	app "voltha-go-controller/internal/pkg/application"

	"github.com/gorilla/mux"
)

func TestTaskListHandle_ServeHTTP(t *testing.T) {
	req, err := http.NewRequest("GET", "/serve_http/", nil)
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{
		"id": "SDX6320031",
	}
	req = mux.SetURLVars(req, vars)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	d := &app.VoltDevice{
		Name:      "SDX6320031",
		SerialNum: "SDX6320031",
		Ports:     sync.Map{},
	}
	// Setup the device in the application
	voltApp := app.GetApplication()
	voltApp.DevicesDisc.Store("SDX6320031", d)

	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "GetTaskList invalid input",
			args: args{
				w: rr,
				r: req,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dh := &TaskListHandle{}
			dh.ServeHTTP(tt.args.w, tt.args.r)
		})
	}
}

func TestTaskListHandle_GetTaskList(t *testing.T) {
	req, err := http.NewRequest("GET", "/serve_http/", nil)
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{
		"id": "SDX6320031",
	}
	req = mux.SetURLVars(req, vars)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	d := &app.VoltDevice{
		Name:      "SDX6320031",
		SerialNum: "SDX6320031",
		Ports:     sync.Map{},
	}
	// Setup the device in the application
	voltApp := app.GetApplication()
	voltApp.DevicesDisc.Store("SDX6320031", d)

	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name string
		dh   *TaskListHandle
		args args
	}{
		{
			name: "GetTaskList invalid input",
			args: args{
				w: rr,
				r: req,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dh := &TaskListHandle{}
			dh.GetTaskList(tt.args.w, tt.args.r)
		})
	}
}
