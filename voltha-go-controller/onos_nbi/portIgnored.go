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
	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/log"
)

type PortIgnoredHandle struct {
}

func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.AddPackageWithDefaultParam()
	if err != nil {
		panic(err)
	}
}

func (pih *PortIgnoredHandle) PortsIgnoredServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case "GET":
		logger.Info(ctx, "calling GetIgnoredPortsInfo handler")
		pih.GetIgnoredPortsInfo(context.Background(), w, r)

	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

func (pih *PortIgnoredHandle) GetIgnoredPortsInfo(cntx context.Context, w http.ResponseWriter, r *http.Request) {

	PortIgnoredInfo, err := app.GetApplication().GetIgnoredPorts()
	if err != nil {
		logger.Errorw(ctx, "Failed to get ignored port info", log.Fields{"Reason": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	PortIgnoredRespJSON, err := json.Marshal(PortIgnoredInfo)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling ignored port response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(PortIgnoredRespJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending ignored port response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}

}