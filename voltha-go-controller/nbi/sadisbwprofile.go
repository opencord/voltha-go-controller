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
	"bytes"
	"encoding/json"
	"net/http"

	app "voltha-go-controller/internal/pkg/application"
	"github.com/opencord/voltha-lib-go/v7/pkg/log"
)

//BWProfile - Sadis BW Profile
type BWProfile struct {
	ID                        string `json:"id"`
	PeakInformationRate       uint32 `json:"pir"`
	PeakBurstSize             uint32 `json:"pbs"`
	CommittedInformationRate  uint32 `json:"cir"`
	CommittedBurstSize        uint32 `json:"cbs"`
	ExceededInformationRate   uint32 `json:"eir"`
	ExceededBurstSize         uint32 `json:"ebs"`
	AssuredInformationRate    uint32 `json:"air"`
	GuaranteedInformationRate uint32 `json:"gir"`
}

// ProfileDelReq structure
type ProfileDelReq struct {
	ID string
}

// ProfileHandle handle Profile Requests
type ProfileHandle struct {
}

// ServeHTTP to serve the HTTP request
func (mh *ProfileHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case "GET":
		mh.GetProfile(w, r)
	case "POST":
		mh.AddProfile(w, r)
	case "DELETE":
		mh.DelProfile(w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

// AddProfile to add meter
func (mh *ProfileHandle) AddProfile(w http.ResponseWriter, r *http.Request) {
	// Get the payload to process the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body);  err != nil {
		logger.Warnw(ctx, "Error reading buffer", log.Fields{"Reason": err.Error()})
		return
	}

	// Unmarshal the request into service configuration structure
	req := &BWProfile{}
	if err := json.Unmarshal(d.Bytes(), req); err != nil {
		logger.Warnw(ctx, "Unmarshal Failed", log.Fields{"Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	logger.Debugw(ctx, "Received-northbound-add-meter-request", log.Fields{"req": req, "d": d.String()})
	metercfg := app.VoltMeter{
		Name: req.ID,
		Cir:  req.CommittedInformationRate,
		Cbs:  req.CommittedBurstSize,
		Pir:  req.PeakInformationRate,
		Pbs:  req.PeakBurstSize,
		Air:  req.AssuredInformationRate,
		Gir:  req.GuaranteedInformationRate,
		Eir:  req.ExceededInformationRate,
		Ebs:  req.ExceededBurstSize,
	}
	app.GetApplication().AddMeterProf(metercfg)
	logger.Debugw(ctx, "northbound-add-meter-successful", log.Fields{"req": req})
}

// GetProfile to get meter
func (mh *ProfileHandle) GetProfile(w http.ResponseWriter, r *http.Request) {
}

// DelProfile to delete meter
func (mh *ProfileHandle) DelProfile(w http.ResponseWriter, r *http.Request) {
	//TODO : Change the URL and Mux to fetch meter id from the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body);  err != nil {
		logger.Warnw(ctx, "Error reading buffer", log.Fields{"Reason": err.Error()})
		return
	}

	req := &ProfileDelReq{}
	if err := json.Unmarshal(d.Bytes(), req); err != nil {
		logger.Warnw(ctx, "Unmarshal Failed", log.Fields{"Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	logger.Debugw(ctx, "Received-northbound-del-meter-request", log.Fields{"req": req})

	meterName := req.ID
	if err := app.GetApplication().DelMeterProf(meterName); err != nil {
		logger.Errorw(ctx, "northbound-del-meter-failed", log.Fields{"req": req})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	logger.Debugw(ctx, "northbound-del-meter-successful", log.Fields{"req": req})
}
