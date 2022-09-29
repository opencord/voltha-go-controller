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
	"context"
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"voltha-go-controller/log"
	app "voltha-go-controller/internal/pkg/application"
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
	case "GET":
		dh.GetAllocations(context.Background(), w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

func (dh *DhcpRelayHandle) GetAllocations(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	deviceID := vars[DeviceID]
	Allocations, err := app.GetApplication().GetAllocations(cntx, deviceID)
	if err != nil {
		logger.Errorw(ctx, "Failed to get dhcp allocations", log.Fields{"Reason": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	AllocRespJSON, err := json.Marshal(Allocations)
	if err != nil {
		logger.Errorw(ctx, "Failed to Marshal dhcp allocation response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(AllocRespJSON)
	if err != nil {
		logger.Errorw(ctx, "Failed to write dhcp allocations response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}

}
