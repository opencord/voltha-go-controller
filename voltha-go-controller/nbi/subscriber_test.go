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
)

func TestSubscriberHandle_DelSubscriberInfo(t *testing.T) {
	var jsonStr = []byte(`{"id":"test_id"}`)

	req, err := http.NewRequest("DELETE", "/subscriber_device_info/", bytes.NewBuffer(jsonStr))
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
			name: "SubscriberHandle_DelSubscriberInfo",
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
			sh.DelSubscriberInfo(tt.args.cntx, tt.args.w, tt.args.r)
		})
	}
}
