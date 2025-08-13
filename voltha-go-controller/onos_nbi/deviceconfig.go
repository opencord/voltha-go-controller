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
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	app "voltha-go-controller/internal/pkg/application"
	errorCodes "voltha-go-controller/internal/pkg/errorcodes"
	"voltha-go-controller/log"

	"github.com/gorilla/mux"
)

const (
	cPost   = "POST"
	cGet    = "GET"
	cDelete = "DELETE"
)

// DeviceConfigHandle handles DeviceConfig Requests
type DeviceConfigHandle struct {
}

// ServeHTTP to serve HTTP requests
func (oh *DeviceConfigHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cPost:
		oh.AddDeviceConfig(context.Background(), w, r)
	case cGet:
		oh.FetchDeviceConfig(context.Background(), w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
		err := errorCodes.ErrOperationNotSupported
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (oh *DeviceConfigHandle) AddDeviceConfig(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	logger.Debug(cntx, "Inside AddDeviceConfig method")
	// Get the payload to process the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body); err != nil {
		logger.Errorw(ctx, "Error reading buffer", log.Fields{"Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	// Unmarshal the request into device configuration structure
	req := &app.DeviceConfig{}
	if err := json.Unmarshal(d.Bytes(), req); err != nil {
		logger.Errorw(ctx, "Unmarshal Failed", log.Fields{"Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	app.GetApplication().UpdateDeviceConfig(cntx, req)
	logger.Debugw(ctx, "Added Device Config ", log.Fields{"Req": req})
}

func (oh *DeviceConfigHandle) FetchDeviceConfig(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serialNum := vars["serialNumber"]
	logger.Infow(cntx, "Inside FetchDeviceConfig method", log.Fields{"serialNum": serialNum})
	deviceInfo := DeviceConfigPayload{}
	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	dc := voltAppIntr.GetDeviceConfig(serialNum)
	if dc != nil {
		deviceInfo.DeviceConfig = dc
		oltInfoJSON, err := json.Marshal(deviceInfo)
		if err != nil {
			logger.Errorw(ctx, "Failed to marshal olt payload response", log.Fields{"deviceInfo": deviceInfo, "Error": err})
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Add("Content-Type", "application/json")
		_, err = w.Write(oltInfoJSON)
		if err != nil {
			logger.Errorw(ctx, "Failed to write olt payload response", log.Fields{"deviceInfo": deviceInfo, "Error": err})
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	} else {
		logger.Warnw(ctx, "Device not found", log.Fields{"serialNum": serialNum})
		err := errorCodes.ErrDeviceNotFound
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}
