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

package onos_nbi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/log"

	"github.com/gorilla/mux"
)

// DeviceConfigHandle handles DeviceConfig Requests
type DeviceConfigHandle struct {
}

// ServeHTTP to serve HTTP requests
func (oh *DeviceConfigHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case "POST":
		oh.AddDeviceConfig(context.Background(), w, r)
	case "GET":
		oh.FetchDeviceConfig(context.Background(), w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

func (oh *DeviceConfigHandle) AddDeviceConfig(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	logger.Info(cntx, "Inside AddDeviceConfig method")
	// Get the payload to process the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body); err != nil {
		logger.Warnw(ctx, "Error reading buffer", log.Fields{"Reason": err.Error()})
		return
	}
	// Unmarshal the request into device configuration structure
	req := &app.DeviceConfig{}
	if err := json.Unmarshal(d.Bytes(), req); err != nil {
		logger.Warnw(ctx, "Unmarshal Failed", log.Fields{"Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	app.GetApplication().UpdateDeviceConfig(cntx, req)
}

func (oh *DeviceConfigHandle) FetchDeviceConfig(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	logger.Info(cntx, "Inside FetchDeviceConfig method")
	vars := mux.Vars(r)
	serialNum := vars["serialNumber"]
	deviceInfo := DeviceConfigPayload{}
	dc := app.GetApplication().GetDeviceConfig(serialNum)
	deviceInfo.DeviceConfig = dc
	oltInfoJSON, err := json.Marshal(deviceInfo)
	if err != nil {
		logger.Errorw(ctx, "Failed to marshal olt payload response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(oltInfoJSON)
	if err != nil {
		logger.Errorw(ctx, "Failed to write olt payload response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}

}
