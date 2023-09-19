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
)

// OltFlowServiceHandle handles OltFlowService Requests
type OltFlowServiceHandle struct {
}

// ServeHTTP to serve HTTP requests
func (oh *OltFlowServiceHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cPost:
		oh.configureOltFlowService(context.Background(), w, r)
	case cGet:
		oh.fetchOltFlowService(context.Background(), w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
		err := errorCodes.ErrOperationNotSupported
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (oh *OltFlowServiceHandle) configureOltFlowService(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	// Get the payload to process the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body); err != nil {
		logger.Errorw(ctx, "Error reading buffer", log.Fields{"Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	// Unmarshal the request into service configuration structure
	req := &app.OltFlowService{}
	if err := json.Unmarshal(d.Bytes(), req); err != nil {
		logger.Errorw(ctx, "Unmarshal Failed", log.Fields{"req": req, "Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	voltAppIntr.UpdateOltFlowService(cntx, *req)
}

func (oh *OltFlowServiceHandle) fetchOltFlowService(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	oltFlowSer := OltFlowServiceConfig{}
	va := app.GetApplication()

	oltFlowSer.OltFlowService = va.OltFlowServiceConfig
	OltFlowRespJSON, err := json.Marshal(oltFlowSer)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling oltFlowService response", log.Fields{"OltFlowService": oltFlowSer.OltFlowService, "Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(OltFlowRespJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending olt flow service response", log.Fields{"OltFlowService": oltFlowSer.OltFlowService, "Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logger.Debugw(cntx, "Request for Fetching Olt Flow Service", log.Fields{"OltFlowService": oltFlowSer.OltFlowService})
}
