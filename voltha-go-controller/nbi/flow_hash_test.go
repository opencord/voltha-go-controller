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

package nbi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"voltha-go-controller/internal/test/mocks"

	app "voltha-go-controller/internal/pkg/controller"
	//"voltha-go-controller/internal/test/mocks"

	mocksCntrlr "voltha-go-controller/voltha-go-controller/tests/mocks"

	"github.com/golang/mock/gomock"
	"github.com/gorilla/mux"
)

func TestFlowHashHandle_PutFlowHash(t *testing.T) {
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	vars := map[string]string{
		"id": "SDX6320031",
	}
	request := uint32(256)
	b, _ := json.Marshal(request)
	req, err := http.NewRequest("PUT", "/FlowHah", bytes.NewBuffer(b))
	if err != nil {
		t.Fatal(err)
	}
	req = mux.SetURLVars(req, vars)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	vars1 := map[string]string{
		"id": "SDX6320031",
	}
	request1 := uint32(256)
	b1, _ := json.Marshal(request1)
	req1, err1 := http.NewRequest("PUT", "/FlowHah", bytes.NewBuffer(b1))
	if err1 != nil {
		t.Fatal(err1)
	}
	req1 = mux.SetURLVars(req1, vars1)
	req1.Header.Set("Content-Type", "application/json")

	var jsonStr1 = []byte(`{
		 2 "id": "BBSM00010001-1"}`)
	req2, err2 := http.NewRequest("PUT", "/FlowHah", bytes.NewBuffer(jsonStr1))
	if err2 != nil {
		t.Fatal(err2)
	}
	tests := []struct {
		name string
		fh   *FlowHashHandle
		args args
	}{
		{
			name: "PutFlowHash_Success",
			fh:   &FlowHashHandle{},
			args: args{
				r: req,
				w: rr,
			},
		},
		{
			name: "PutFlowHash_Device_Not_Found",
			fh:   &FlowHashHandle{},
			args: args{
				r: req1,
				w: rr,
			},
		},
		{
			name: "PutFlowHash_ParseUint_Failure",
			fh:   &FlowHashHandle{},
			args: args{
				r: req2,
				w: rr,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fh := &FlowHashHandle{}
			switch tt.name {
			case "PutFlowHash_Device_Not_Found":
				appMock := mocks.NewMockApp(gomock.NewController(t))
				app.NewController(ctx, appMock)
				idea := mocksCntrlr.NewMockVoltControllerInterface(gomock.NewController(t))
				idea.EXPECT().GetDevice(gomock.Any()).Return(nil, errors.New("not found")).Times(1)
				fh.PutFlowHash(tt.args.w, tt.args.r)
			case "PutFlowHash_ParseUint_Failure":
				fh.PutFlowHash(tt.args.w, tt.args.r)
				// case "PutFlowHash_Success":
				// 	appMock := mocks.NewMockApp(gomock.NewController(t))
				// 	app.NewController(ctx, appMock)
				// 	cntrlr := app.GetController()
				// 	device := &app.Device{
				// 		ID: "SDX6320031",
				// 	}
				// 	dev := map[string]*app.Device{}
				// 	dev["SDX6320031"] = device
				// 	cntrlr.Devices = dev
				// 	idea := mocksCntrlr.NewMockVoltControllerInterface(gomock.NewController(t))
				// 	//cntrlr.VoltCntrlrIntr = idea
				// 	idea.EXPECT().GetDevice(gomock.Any()).Return(device, nil).Times(1)
				// 	devIntr := mocksCntrlr.NewMockDeviceInterface(gomock.NewController(t))
				// 	//device.DeviceIntr = devIntr
				// 	devIntr.EXPECT().SetFlowHash(gomock.Any(), gomock.Any()).Times(1)
				// 	fh.PutFlowHash(tt.args.w, tt.args.r)
			}
		})
	}
}
