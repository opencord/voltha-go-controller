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

type MacLearnerHandle struct {
}

func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.AddPackageWithDefaultParam()
	if err != nil {
		panic(err)
	}
}

// ServeHTTP to serve http request
func (mlh *MacLearnerHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	vars := mux.Vars(r)
	deviceID := vars["deviceId"]
	portNum := vars["portNumber"]
	vlanID := vars["vlanId"]
	switch r.Method {
	case cGet:
		if deviceID == "" && portNum == "" && vlanID == "" {
			mlh.GetAllMacLearnerInfo(context.Background(), w, r)
		} else {
			mlh.GetMacLearnerInfo(context.Background(), deviceID, portNum, vlanID, w, r)
		}
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
		err := errorCodes.ErrOperationNotSupported
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (mlh *MacLearnerHandle) GetAllMacLearnerInfo(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	logger.Info(cntx, "Inside GetAllMacLearnerInfo method")
	MacLearnerInfo, err := app.GetApplication().GetAllMacLearnerInfo()
	if err != nil {
		logger.Errorw(ctx, "Failed to get mac learning info", log.Fields{"Reason": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	MliRespJSON, err := json.Marshal(MacLearnerInfo)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling mac learner response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(MliRespJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending mac learner response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (mlh *MacLearnerHandle) GetMacLearnerInfo(cntx context.Context, deviceID, portNum, vlanID string, w http.ResponseWriter, r *http.Request) {
	logger.Infow(cntx, "Inside GetMacLearnerInfo method", log.Fields{"deviceID": deviceID, "portNum": portNum, "vlanId": vlanID})
	MacLearnerInfo, err := app.GetApplication().GetMacLearnerInfo(cntx, deviceID, portNum, vlanID)
	if err != nil {
		logger.Errorw(ctx, "Failed to get mac learning info", log.Fields{"Reason": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	MliRespJSON, err := json.Marshal(MacLearnerInfo)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling mac learner response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(MliRespJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending mac learner response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}
}