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

package onosnbi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	app "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/test/mocks"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
)

func TestMetersHandle_GetMeter(t *testing.T) {
	type args struct {
		cntx    context.Context
		meterID string
		w       http.ResponseWriter
		r       *http.Request
	}
	req, err := http.NewRequest("GET", "/vgc/v1/meters/", nil)
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{
		"id": "1234",
	}
	req = mux.SetURLVars(req, vars)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	metersHandle := &MetersHandle{}
	appMock := mocks.NewMockApp(gomock.NewController(t))
	app.NewController(ctx, appMock)
	tests := []struct {
		name string
		mh   *MetersHandle
		args args
	}{
		{
			name: "Get_Meters",
			mh:   metersHandle,
			args: args{
				cntx:    context.Background(),
				meterID: "1234",
				w:       rr,
				r:       req,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mh := &MetersHandle{}
			mh.GetMeter(tt.args.cntx, tt.args.meterID, tt.args.w, tt.args.r)
		})
	}
}
