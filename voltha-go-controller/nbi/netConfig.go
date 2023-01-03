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
	"voltha-go-controller/log"
)

type NetConfig struct {
	App Apps `json:"apps"`
}

type Apps struct {
	OrgOpencordSadis     OrgOpencordSadis   `json:"org.opencord.sadis"`
	OrgOpencordIgmpproxy IgmpProxy          `json:"org.opencord.igmpproxy"`
	OrgOnosprojectCore   OrgOnosprojectCore `json:"org.onosproject.core"`
}
type OrgOpencordSadis struct {
	Bandwidthprofile BWEnteries `json:"bandwidthprofile"`
	SadisInfo        Sadis      `json:"sadis"`
}

type BWEnteries struct {
	BWInfo []BWProfile `json:"entries"`
}
type Sadis struct {
	SubscriberInfo []SubscriberDeviceInfo `json:"entries"`
}

type OrgOnosprojectCore struct {
	Multicast Mvlan `json:"multicast"`
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
	case "POST":
		nch.AddNetConfigInfo(ctx, w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

// AddSubscriberInfo to add service
func (nch *NetConfigHandle) AddNetConfigInfo(cntx context.Context, w http.ResponseWriter, r *http.Request) {

	// Get the payload to process the request
	d := new(bytes.Buffer)
	if _, err := d.ReadFrom(r.Body); err != nil {
		logger.Warnw(ctx, "Error reading buffer", log.Fields{"Reason": err.Error()})
		return
	}

	// Unmarshal the request into Network configuration structure
	req := &NetConfig{}
	if err := json.Unmarshal(d.Bytes(), req); err != nil {
		logger.Warnw(ctx, "Unmarshal Failed", log.Fields{"Reason": err.Error()})
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	logger.Debugw(ctx, "Received-northbound-network-configuration-request", log.Fields{"req": req, "d": d.String()})

	va := app.VoltApplication{}

	for _, bwprofile := range req.App.OrgOpencordSadis.Bandwidthprofile.BWInfo {
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

	for _, subscriberInfo := range req.App.OrgOpencordSadis.SadisInfo.SubscriberInfo {
		if len(subscriberInfo.UniTagList) == 0 {
			err := va.AddDeviceConfig(cntx, subscriberInfo.ID, subscriberInfo.HardwareIdentifier, subscriberInfo.NasID, string(subscriberInfo.IPAddress), subscriberInfo.UplinkPort, subscriberInfo.NniDhcpTrapVid)
			if err != nil {
				logger.Errorw(ctx, "Add device config failed", log.Fields{"Error": err})
			}
			continue
		}
		addAllService(cntx, &subscriberInfo)
	}

	mch := MulticastHandle{}
	mch.addMvlan(cntx, w, &req.App.OrgOnosprojectCore.Multicast)

	iph := IgmpProxyHandle{}
	iph.addIgmpProxy(cntx, w, &req.App.OrgOpencordIgmpproxy)
}
