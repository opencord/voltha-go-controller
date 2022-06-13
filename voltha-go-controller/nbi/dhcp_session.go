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
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	app "voltha-go-controller/internal/pkg/application"
	"github.com/opencord/voltha-lib-go/v7/pkg/log"
)

//DHCPSessionInfoHandle handle dhcp session Requests
type DHCPSessionInfoHandle struct {
}

// DhcpSessionInfo Information
type DhcpSessionInfo struct {
	DeviceID    string
	Uniport     string
	Svlan       string
	Cvlan       string
	UniVlan     string
	MacAddress  string
	IPAddress   string
	Ipv6Address string
	State       string
	Statev6     string
	LeaseTime   string
	LeaseTimev6 string
}

// getDhcpSessionFields returns dhcp session information
func getDhcpSessionFields(id string, port string, svlan string, cvlan string, univlan string, macAddr string, ipAddr net.IP, ipv6Addr net.IP, rState app.DhcpRelayState, rStatev6 app.Dhcpv6RelayState, lTime time.Time, l6Time time.Time) *DhcpSessionInfo {
	ip := ipAddr.String()
	ipv6 := ipv6Addr.String()
	relayState := strconv.Itoa(int(rState))
	relayStatev6 := strconv.Itoa(int(rStatev6))
	leaseTime := (lTime.Format(time.RubyDate))
	leasev6Time := (l6Time.Format(time.RubyDate))
	dInfo := &DhcpSessionInfo{DeviceID: id, Uniport: port, Svlan: svlan, Cvlan: cvlan, UniVlan: univlan, MacAddress: macAddr, IPAddress: ip, Ipv6Address: ipv6, State: relayState, Statev6: relayStatev6, LeaseTime: leaseTime, LeaseTimev6: leasev6Time}
	return dInfo
}

// validateArgs validate the arguements
func validateArgs(sv string, cv string, macAddr string, svlan string, cvlan string, mac string) bool {
	var vlanFlag bool
	var macFlag bool

	if ((sv == svlan) || (len(svlan) == 0)) && ((cv == cvlan) || (len(cvlan) == 0)) {
		vlanFlag = true
	}

	if mac == macAddr || len(mac) == 0 {
		macFlag = true
	}

	if macFlag && vlanFlag {
		return true
	}
	return false
}

// serveHTTP for actions performed on API.
func (dh *DHCPSessionInfoHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case "GET":
		dh.getDhcpSessionInfo(w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

// getDhcpSessionInfo to retrieve dhcp session information.
func (dh *DHCPSessionInfoHandle) getDhcpSessionInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	mac := vars["mac"]
	svlan := vars["svlan"]
	cvlan := vars["cvlan"]

	var dhcpData *DhcpSessionInfo

	va := app.GetApplication()
	dhcpSessionInfoResp := []*DhcpSessionInfo{}

	getPorts := func(key, value interface{}) bool {
		port := key.(string)
		vp := value.(*app.VoltPort)

		//Ignore if UNI port is not UP
		if vp.State != app.PortStateUp {
			return true
		}

		//Obtain all VPVs associated with the port
		vnets, ok := va.VnetsByPort.Load(port)
		if !ok {
			return true
		}

		for _, vpv := range vnets.([]*app.VoltPortVnet) {
			// When only device id is provided as arguement
			sv := strconv.Itoa(int(vpv.SVlan))
			cv := strconv.Itoa(int(vpv.CVlan))
			uv := strconv.Itoa(int(vpv.UniVlan))
			macAddr := (vpv.MacAddr).String()

			validData := validateArgs(sv, cv, macAddr, svlan, cvlan, mac)

			if validData {
				dhcpData = getDhcpSessionFields(id, vpv.Port, sv, cv, uv, macAddr, vpv.Ipv4Addr, vpv.Ipv6Addr, vpv.RelayState, vpv.RelayStatev6, vpv.DhcpExpiryTime, vpv.Dhcp6ExpiryTime)
				dhcpSessionInfoResp = append(dhcpSessionInfoResp, dhcpData)
			}
		}
		return true
	}

	if len(id) == 0 {
		logger.Errorw(ctx, "No Device Id Provided for Dhcp session Info", log.Fields{"DeviceID": id})
		return
	}
	voltDevice := va.GetDevice(id)
	if voltDevice != nil {
		voltDevice.Ports.Range(getPorts)
	}

	dhcpSessionInfoJSON, err := json.Marshal(dhcpSessionInfoResp)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling dhcp session info response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(dhcpSessionInfoJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending dhcp session info response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}

}
