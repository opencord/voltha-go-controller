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
	"encoding/json"
	"net/http"

	app "voltha-go-controller/internal/pkg/application"
	errorCodes "voltha-go-controller/internal/pkg/errorcodes"
	"voltha-go-controller/log"

	"github.com/gorilla/mux"
)

// DeviceHandle Handle DeviceIDList Requests
type DeviceHandle struct {
}

// DevicePortHandle Handle Ports Requests
type DevicePortHandle struct {
}

// ServeHTTP to serve HTTP requests
func (dh *DeviceHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cGet:
		dh.GetDeviceList(w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
		err := errorCodes.ErrOperationNotSupported
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// GetDeviceList to get device id list
func (dh *DeviceHandle) GetDeviceList(w http.ResponseWriter, r *http.Request) {
	va := app.GetApplication()
	var deviceListResp DeviceEntry
	deviceListResp.Devices = []Device{}

	getDeviceList := func(key, value interface{}) bool {
		voltDevice := value.(*app.VoltDevice)
		device := convertVoltDeviceToDevice(voltDevice)
		deviceListResp.Devices = append(deviceListResp.Devices, device)
		return true
	}
	va.DevicesDisc.Range(getDeviceList)

	deviceListJSON, err := json.Marshal(deviceListResp)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling device list response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(deviceListJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending deviceList response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// ServeHTTP to serve HTTP requests
func (dh *DevicePortHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cGet:
		dh.GetPortList(w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
		err := errorCodes.ErrOperationNotSupported
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// ServeHTTPWithDeviceID to serve HTTP request for ports with deviceID
func (dh *DevicePortHandle) ServeHTTPWithDeviceID(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cGet:
		dh.GetPortListPerDevice(w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
		err := errorCodes.ErrOperationNotSupported
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// GetPortListPerDevice to get port list for a given device
func (dh *DevicePortHandle) GetPortListPerDevice(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars["olt_of_id"]

	var devicePortListResp DevicePortEntry
	devicePortListResp.Device = Device{}
	devicePortListResp.Ports = []Port{}

	getPortList := func(key, value interface{}) bool {
		voltPort := value.(*app.VoltPort)
		port := convertVoltPortToPort(voltPort)
		devicePortListResp.Ports = append(devicePortListResp.Ports, port)
		return true
	}
	if len(deviceID) > 0 {
		logger.Infow(ctx, "Received Port get request for device", log.Fields{"deviceID": deviceID})
		voltDevice := app.GetApplication().GetDevice(deviceID)
		if voltDevice != nil {
			logger.Infow(ctx, "Found device", log.Fields{"deviceID": deviceID})
			devicePortListResp.Device = convertVoltDeviceToDevice(voltDevice)
			voltDevice.Ports.Range(getPortList)
		}
	}
	portListJSON, err := json.Marshal(devicePortListResp)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling port list response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(portListJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending portList response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// GetPortList to get device id list
func (dh *DevicePortHandle) GetPortList(w http.ResponseWriter, r *http.Request) {
	va := app.GetApplication()
	var portListResp PortEntry
	portListResp.Ports = []Port{}

	getPortList := func(key, value interface{}) bool {
		voltPort := value.(*app.VoltPort)
		port := convertVoltPortToPort(voltPort)
		portListResp.Ports = append(portListResp.Ports, port)
		return true
	}

	getDeviceList := func(key, value interface{}) bool {
		voltDevice := value.(*app.VoltDevice)
		voltDevice.Ports.Range(getPortList)
		return true
	}
	va.DevicesDisc.Range(getDeviceList)

	portListJSON, err := json.Marshal(portListResp)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling port list response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(portListJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending portList response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}
}