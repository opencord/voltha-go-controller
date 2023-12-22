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
	"encoding/json"
	"net/http"

	app "voltha-go-controller/internal/pkg/application"
	errorCodes "voltha-go-controller/internal/pkg/errorcodes"
	"voltha-go-controller/log"

	"github.com/gorilla/mux"
)

var logger log.CLogger
var ctx = context.TODO()

const DeviceID string = "deviceId"

func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.AddPackageWithDefaultParam()
	if err != nil {
		panic(err)
	}
}

// DhcpRelayHandle struct to handle dhcprelay related REST calls
type DhcpRelayHandle struct {
}

func (dh *DhcpRelayHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cGet:
		dh.GetAllocations(context.Background(), w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
		err := errorCodes.ErrOperationNotSupported
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (dh *DhcpRelayHandle) GetAllocations(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars[DeviceID]
	logger.Debugw(ctx, "Received Get DhcpAllocation info for device ID", log.Fields{"deviceID": deviceID})
	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	Allocations, err := voltAppIntr.GetAllocations(cntx, deviceID)
	if err != nil {
		logger.Errorw(ctx, "Failed to get dhcp allocations", log.Fields{"deviceID": deviceID, "Reason": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	AllocRespJSON, err := json.Marshal(Allocations)
	if err != nil {
		logger.Errorw(ctx, "Failed to Marshal dhcp allocation response", log.Fields{"Allocations": Allocations, "Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(AllocRespJSON)
	if err != nil {
		logger.Errorw(ctx, "Failed to write dhcp allocations response", log.Fields{"Allocations": Allocations, "Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logger.Debugw(ctx, "Fetching DhcpAllocation info for device ID", log.Fields{"Allocations": Allocations, "deviceID": deviceID})
}
# [EOF] - delta:force
