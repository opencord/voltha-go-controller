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
	"strconv"
	app "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/log"

	"github.com/gorilla/mux"
)

type MetersHandle struct {
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
func (mh *MetersHandle) MeterServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	vars := mux.Vars(r)
	meterID := vars["id"]

	switch r.Method {
	case "GET":
		if meterID != "" {
			logger.Warnw(ctx, "Calling GetMeter method", log.Fields{"MeterId": meterID})
			mh.GetMeter(context.Background(), meterID, w, r)
		} else {
			mh.GetAllMeters(context.Background(), w, r)
		}

	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

func (mh *MetersHandle) GetMeter(cntx context.Context, meterId string, w http.ResponseWriter, r *http.Request) {
	logger.Info(cntx, "Inside GetMeter method")
	meterListResp := MeterList{}
	meterListResp.Meters = []Meters{}
	mId, err := strconv.ParseUint(meterId, 10, 32)
	if err != nil {
		logger.Errorw(ctx, "Failed to parse string to uint32", log.Fields{"Reason": err.Error()})
	}
	id := uint32(mId)
	logger.Infow(ctx, "Meter Id", log.Fields{"metreId": id})
	meterInfo, err := app.GetController().GetMeterInfo(cntx, id)
	if err != nil {
		logger.Errorw(ctx, "Failed to get meter info", log.Fields{"Reason": err.Error()})
		w.WriteHeader(http.StatusNotFound)
	}

	for deviceId, meter := range meterInfo {
		meterResp := mh.MeterObjectMapping(meter, deviceId)
		meterListResp.Meters = append(meterListResp.Meters, meterResp)
	}
	MeterRespJSON, err := json.Marshal(meterListResp)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling meter response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(MeterRespJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending meter response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (mh *MetersHandle) GetAllMeters(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	logger.Info(cntx, "Inside GetAllMeters method")
	metersList := MeterList{}
	metersList.Meters = []Meters{}
	meterInfo, err := app.GetController().GetAllMeterInfo()
	if err != nil {
		logger.Errorw(ctx, "Failed to get meter info", log.Fields{"Reason": err.Error()})
		w.WriteHeader(http.StatusNotFound)
	}
	for deviceId, meters := range meterInfo {
		for _, meter := range meters {
			mtr := mh.MeterObjectMapping(meter, deviceId)
			metersList.Meters = append(metersList.Meters, mtr)
		}
	}
	MeterRespJSON, err := json.Marshal(metersList)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling meter response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(MeterRespJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending meter response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}

}