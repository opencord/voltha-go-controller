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

func TestSubscriberHandle_DelSubscriberInfo(t *testing.T) {
	var jsonStr = []byte(`{
		"id": "BBSM00010001-1",
		"nasPortId": "BBSM00010001-1",
		"circuitId": "BBSM00010001-1",
		"remoteId": "BBSM00010001",
		"uniTagList": [
		  {
			"uniTagMatch": 4096,
			"ponCTag": 4096,
			"ponSTag": 900,
			"usPonCTagPriority": 0,
			"usPonSTagPriority": 0,
			"dsPonCTagPriority": 0,
			"dsPonSTagPriority": 0,
			"technologyProfileId": 64,
			"downstreamBandwidthProfile": "High-Speed-Internet",
			"upstreamBandwidthProfile": "High-Speed-Internet",
			"serviceName": "FTTB_SUBSCRIBER_TRAFFIC"
		  }
		]
	  }`)

	var jsonStr1 = []byte(`{
		2 "id": "BBSM00010001-1"}`)

	req, err := http.NewRequest("DELETE", "/subscriber_device_info/", bytes.NewBuffer(jsonStr))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req1, err1 := http.NewRequest("DELETE", "/subscriber_device_info/", bytes.NewBuffer(jsonStr1))
	if err1 != nil {
		t.Fatal(err1)
	}
	req1.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	var jsonStr2 = []byte(`{
		"id": "BBSM00010001-1",
		"nasPortId": "BBSM00010001-1",
		"circuitId": "BBSM00010001-1",
		"remoteId": "BBSM00010001",
		"uniTagList": [
		  {
			"uniTagMatch": 4096,
			"ponCTag": 4096,
			"ponSTag": 900,
			"usPonCTagPriority": 0,
			"usPonSTagPriority": 0,
			"dsPonCTagPriority": 0,
			"dsPonSTagPriority": 0,
			"technologyProfileId": 64,
			"downstreamBandwidthProfile": "High-Speed-Internet",
			"upstreamBandwidthProfile": "High-Speed-Internet",
			"serviceName": "FTTB_SUBSCRIBER_TRAFFIC"
		  }
		]
	  }`)
	req2, err2 := http.NewRequest("DELETE", "/subscriber_device_info/", bytes.NewBuffer(jsonStr2))
	if err2 != nil {
		t.Fatal(err2)
	}
	req2.Header.Set("Content-Type", "application/json")

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
			name: "SubscriberHandle_DelSubscriberInfo",
			args: args{
				cntx: context.Background(),
				w:    rr,
				r:    req,
			},
		},
		{
			name: "DelSubscriberInfo_Unmarshal_Error",
			args: args{
				cntx: context.Background(),
				w:    rr,
				r:    req1,
			},
		},
		{
			name: "SubscriberHandle_Delete_Failed",
			args: args{
				cntx: context.Background(),
				w:    rr,
				r:    req2,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sh := &SubscriberHandle{}
			switch tt.name {
			case "SubscriberHandle_DelSubscriberInfo":
				// Tests use the application singleton directly
				sh.DelSubscriberInfo(tt.args.cntx, tt.args.w, tt.args.r)
			case "DelSubscriberInfo_Unmarshal_Error":
				sh.DelSubscriberInfo(tt.args.cntx, tt.args.w, tt.args.r)
			case "SubscriberHandle_Delete_Failed":
				// Tests use the application singleton directly
				sh.DelSubscriberInfo(tt.args.cntx, tt.args.w, tt.args.r)
			}
		})
	}
}

func TestSubscriberHandle_GetSubscriberAndFlowProvisionStatus(t *testing.T) {
	type args struct {
		cntx context.Context
		w    http.ResponseWriter
		r    *http.Request
	}
	req, err := http.NewRequest("GET", "/vgc/v1/flow-status", nil)
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{
		"portName": "SDX6320031-1",
	}
	req = mux.SetURLVars(req, vars)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	tests := []struct {
		name string
		sh   *SubscriberHandle
		args args
	}{
		{
			name: "GetSubscriberAndFlowProvisionStatus",
			sh:   &SubscriberHandle{},
			args: args{
				cntx: context.Background(),
				w:    rr,
				r:    req,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sh := &SubscriberHandle{}
			switch tt.name {
			case "GetSubscriberAndFlowProvisionStatus":
				sh.GetSubscriberAndFlowProvisionStatus(tt.args.cntx, tt.args.w, tt.args.r)
			}
		})
	}
}
