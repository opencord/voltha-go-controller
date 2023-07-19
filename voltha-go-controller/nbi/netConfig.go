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
	"context"
	"encoding/json"
	"net/http"
	app "voltha-go-controller/internal/pkg/application"
	errorCodes "voltha-go-controller/internal/pkg/errorcodes"
	"voltha-go-controller/log"
)

type NetConfig struct {
	App Apps `json:"apps"`
}

type Apps struct {
	IgmpProxy    *IgmpProxy   `json:"org.opencord.igmpproxy"`
	McastInfo    *McastInfo   `json:"org.onosproject.core"`
	SubscriberBW SubscriberBW `json:"org.opencord.sadis"`
}
type SubscriberBW struct {
	Bandwidthprofile BWEnteries `json:"bandwidthprofile"`
	Subscriber       Subscriber `json:"sadis"`
}

type BWEnteries struct {
	BWInfo []BWProfile `json:"entries"`
}
type Subscriber struct {
	SubscriberInfo []SubscriberDeviceInfo `json:"entries"`
}

type McastInfo struct {
	Multicast *Mvlan `json:"multicast"`
}

type NetConfigHandle struct {
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
func (nch *NetConfigHandle) NetConfigServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cPost:
		nch.AddNetConfigInfo(ctx, w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
		err := errorCodes.ErrOperationNotSupported
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// Populate the network configuration information
func (nch *NetConfigHandle) AddNetConfigInfo(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	// Get the payload to process the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body); err != nil {
		logger.Errorw(ctx, "Error reading buffer", log.Fields{"Reason": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Unmarshal the request into Network configuration structure
	req := &NetConfig{}
	if err := json.Unmarshal(d.Bytes(), req); err != nil {
		logger.Errorw(ctx, "Failed to Unmarshal Adding Network Config", log.Fields{"req": req, "Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	logger.Infow(ctx, "Received-northbound-network-configuration-request", log.Fields{"req": req})

	//va := app.VoltApplication{}

	for _, bwprofile := range req.App.SubscriberBW.Bandwidthprofile.BWInfo {
		metercfg := app.VoltMeter{
			Name: bwprofile.ID,
			Cir:  bwprofile.CommittedInformationRate,
			Cbs:  bwprofile.CommittedBurstSize,
			Pir:  bwprofile.PeakInformationRate,
			Pbs:  bwprofile.PeakBurstSize,
			Air:  bwprofile.AssuredInformationRate,
			Gir:  bwprofile.GuaranteedInformationRate,
			Eir:  bwprofile.ExceededInformationRate,
			Ebs:  bwprofile.ExceededBurstSize,
		}
		app.GetApplication().AddMeterProf(cntx, metercfg)
	}

	for i := range req.App.SubscriberBW.Subscriber.SubscriberInfo {
		addAllService(cntx, &req.App.SubscriberBW.Subscriber.SubscriberInfo[i])
	}

	if req.App.McastInfo != nil {
		mch := MulticastHandle{}
		mch.addMvlan(cntx, w, req.App.McastInfo.Multicast)
	}

	if req.App.IgmpProxy != nil {
		iph := IgmpProxyHandle{}
		iph.addIgmpProxy(cntx, w, req.App.IgmpProxy)
	}
}
