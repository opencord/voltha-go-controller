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
	//"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"

	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/log"

	"github.com/gorilla/mux"
)

// FlowHashHandle Handle flowhash Requests
type FlowHashHandle struct {
}

// ServeHTTP to serve HTTP requests
func (fh *FlowHashHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case "PUT":
		fh.PutFlowHash(w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

// PutFlowHash to put flowhash
func (fh *FlowHashHandle) PutFlowHash(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	reqBody, readErr := ioutil.ReadAll(r.Body)
	if readErr != nil {
		logger.Errorw(ctx, "Failed to read put flowhash request", log.Fields{"device": id, "Error": readErr.Error()})
		return
	}

	flowhash, parseErr := strconv.ParseUint(string(reqBody), 10, 32)
	if parseErr != nil {
		logger.Errorw(ctx, "Failed to parse string to uint32", log.Fields{"device": id, "Reason": parseErr.Error()})
		return
	}

	if len(id) > 0 {
		device, err := cntlr.GetController().GetDevice(id)
		if err != nil {
			logger.Errorw(ctx, "Failed to get device", log.Fields{"device": id, "Error": err.Error()})
			return
		}
		device.SetFlowHash(ctx, uint32(flowhash))
		logger.Infow(ctx, "Device flow hash", log.Fields{"Flow hash": flowhash})
	}

	logger.Debugw(ctx, "flowhash data is ", log.Fields{"vars": vars})
}
