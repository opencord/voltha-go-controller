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
	"encoding/json"
	"net/http"

	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/log"
)

// DeviceIDListHandle Handle DeviceIDList Requests
type DeviceIDListHandle struct {
}

// ServeHTTP to serve HTTP requests
func (dh *DeviceIDListHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case "GET":
		dh.GetDeviceIDList(w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

// GetDeviceIDList to get device id list
func (dh *DeviceIDListHandle) GetDeviceIDList(w http.ResponseWriter, r *http.Request) {

	va := app.GetApplication()
	var deviceID string
	var deviceIDListResp []string

	getDeviceIDList := func(key, value interface{}) bool {
		voltDevice := value.(*app.VoltDevice)
		deviceID = voltDevice.Name
		deviceIDListResp = append(deviceIDListResp, deviceID)
		return true
	}
	va.DevicesDisc.Range(getDeviceIDList)

	deviceIDListJSON, err := json.Marshal(deviceIDListResp)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling device id list response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(deviceIDListJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending deviceIDList response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}

}
