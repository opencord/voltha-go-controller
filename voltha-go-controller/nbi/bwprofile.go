/* -----------------------------------------------------------------------
 * Copyright 2022-2024 Open Networking Foundation Contributors
 *
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
 * -----------------------------------------------------------------------
 * SPDX-FileCopyrightText: 2022-2024 Open Networking Foundation Contributors
 * SPDX-License-Identifier: Apache-2.0
 * -----------------------------------------------------------------------
 */

package nbi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/log"

	"github.com/gorilla/mux"
)

const (
	cPost   = "POST"
	cGet    = "GET"
	cDelete = "DELETE"
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
	case cGet:
		mh.GetProfile(context.Background(), w, r)
	case cPost:
		mh.AddProfile(context.Background(), w, r)
	case cDelete:
		mh.DelProfile(context.Background(), w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

// AddProfile to add meter
func (mh *ProfileHandle) AddProfile(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	profileName := vars["id"]
	// Get the payload to process the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body); err != nil {
		logger.Errorw(ctx, "Error reading buffer", log.Fields{"ProfileName": profileName, "Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	// Unmarshal the request into service configuration structure
	req := &BWProfile{}
	if err := json.Unmarshal(d.Bytes(), req); err != nil {
		logger.Errorw(ctx, "Failed to Unmarshal Adding Profile", log.Fields{"ProfileName": profileName, "Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	logger.Infow(ctx, "Received-northbound-add-meter-request", log.Fields{"req": req})
	metercfg := app.VoltMeter{
		Name: profileName,
		Cir:  req.CommittedInformationRate,
		Cbs:  req.CommittedBurstSize,
		Pir:  req.PeakInformationRate,
		Pbs:  req.PeakBurstSize,
		Air:  req.AssuredInformationRate,
		Gir:  req.GuaranteedInformationRate,
		Eir:  req.ExceededInformationRate,
		Ebs:  req.ExceededBurstSize,
	}
	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	voltAppIntr.AddMeterProf(cntx, metercfg)
	logger.Debugw(ctx, "northbound-add-meter-successful", log.Fields{"req": req})
}

// GetProfile to get meter
func (mh *ProfileHandle) GetProfile(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	profileName := vars["id"]

	logger.Infow(ctx, "Received-northbound-get-meter-request", log.Fields{"ProfileName": profileName})
	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	cfg, ok := voltAppIntr.GetMeterByName(profileName)
	if !ok {
		logger.Warnw(ctx, "Meter profile does not exist", log.Fields{"Name": profileName})
		w.WriteHeader(http.StatusConflict)
		return
	}
	profileResp := BWProfile{
		ID:                        cfg.Name,
		CommittedInformationRate:  cfg.Cir,
		CommittedBurstSize:        cfg.Cbs,
		PeakInformationRate:       cfg.Pir,
		PeakBurstSize:             cfg.Pbs,
		AssuredInformationRate:    cfg.Air,
		GuaranteedInformationRate: cfg.Gir,
		ExceededInformationRate:   cfg.Eir,
		ExceededBurstSize:         cfg.Ebs,
	}
	profileRespJSON, err := json.Marshal(profileResp)
	if err != nil {
		logger.Errorw(ctx, "Failed to marshal profile response", log.Fields{"ProfileResp": profileResp, "Error": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(profileRespJSON)
	if err != nil {
		logger.Errorw(ctx, "Failed to write profile response", log.Fields{"ProfileResp": profileResp, "Error": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logger.Debugw(ctx, "Fetching ProfileResp from Profilename", log.Fields{"profileResp": profileResp})
}

// DelProfile to delete meter
func (mh *ProfileHandle) DelProfile(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	profileName := vars["id"]
	logger.Infow(ctx, "Received-northbound-del-meter-request", log.Fields{"profileName": profileName})

	// TODO : Change the URL and Mux to fetch meter id from the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body); err != nil {
		logger.Errorw(ctx, "Error reading buffer", log.Fields{"ProfileName": profileName, "Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	req := &ProfileDelReq{}
	if err := json.Unmarshal(d.Bytes(), req); err != nil {
		logger.Errorw(ctx, "Failed to Unmarshal Deleting Profile", log.Fields{"ProfileName": profileName, "Req": req, "Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	meterName := profileName
	if err := voltAppIntr.DelMeterProf(cntx, meterName); err != nil {
		logger.Errorw(ctx, "northbound-del-meter-failed", log.Fields{"Req": req, "Error": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	logger.Debugw(ctx, "northbound-del-meter-successful", log.Fields{"req": req})
}
