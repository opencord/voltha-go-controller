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

	"github.com/gorilla/mux"
)

// DeviceInfoHandle Handle DeviceInfo Requests
type DeviceInfoHandle struct {
}

// DeviceInfo for Device Information
type DeviceInfo struct {
	State string
}

// getDeviceFields returns device information for device
func getDeviceFields(state string) *DeviceInfo {
	dInfo := &DeviceInfo{State: state}
	return dInfo
}

// ServeHTTP for actions performed on API.
func (dh *DeviceInfoHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cGet:
		dh.getDeviceInfo(w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

// getDeviceInfo to retrieve device information.
func (dh *DeviceInfoHandle) getDeviceInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	logger.Infow(ctx, "Received get Device Info from Device Id", log.Fields{"Device ID": id})

	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	var deviceID string
	deviceInfoOnSN := map[string]*DeviceInfo{}
	deviceInfoResp := map[string]map[string]*DeviceInfo{}

	if len(id) > 0 {
		// If Get for single Device
		deviceID = id
		voltDevice := voltAppIntr.GetDevice(deviceID)
		if voltDevice != nil {
			serialNumber := voltDevice.SerialNum
			deviceInfoOnSN[serialNumber] = getDeviceFields(string(voltDevice.State))
			deviceInfoResp[deviceID] = deviceInfoOnSN
		} else {
			logger.Warnw(ctx, "Invalid Device Id", log.Fields{"Device": id})
			return
		}
	} else {
		// Else If GetAll
		getDeviceInfo := func(key, value interface{}) bool {
			voltDevice := value.(*app.VoltDevice)
			deviceID = voltDevice.Name
			serialNumber := voltDevice.SerialNum
			deviceInfoOnSN[serialNumber] = getDeviceFields(string(voltDevice.State))
			deviceInfoResp[deviceID] = deviceInfoOnSN
			return true
		}
		voltApp.DevicesDisc.Range(getDeviceInfo)
	}

	deviceInfoJSON, err := json.Marshal(deviceInfoResp)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling device info response", log.Fields{"DeviceInfo": deviceInfoResp, "Error": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(deviceInfoJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending device info response", log.Fields{"DeviceInfo": deviceInfoResp, "Error": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logger.Debugw(ctx, "Fetching Device Info from Device Id", log.Fields{"DeviceInfo": deviceInfoResp, "Device ID": id})
}
