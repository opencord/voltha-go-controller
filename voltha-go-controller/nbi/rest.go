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
	"context"
	"net/http"

	"github.com/gorilla/mux"

	"voltha-go-controller/log"
	"voltha-go-controller/voltha-go-controller/onos_nbi"
)

var logger log.CLogger
var ctx = context.TODO()

const (
	SubscribersPath string = "/subscribers/{id}"
	ProfilesPath    string = "/profiles/{id}"
	IgmpProxyPath   string = "/igmp-proxy/"
	MulticastPath   string = "/multicast/"
	FlowsPath       string = "/flows/"
	FlowsPerDeviceIDPath string = "/flows/{deviceId}"
	FlowPerDeviceIDFlowIDPath string = "/flows/{deviceId}/{flowId}"
	PendingFlowsPath          string = "/flows/pending/"
	ProgrammedSubscribersPath string = "/programmed-subscribers/"
	ServiceDevicePortPath     string = "/services/{device}/{port}"
	ServicePortNamePath       string = "/services/{portName}"
	ServicePortStagCtagTpIDPath string = "/services/{portName}/{sTag}/{cTag}/{tpId}"
	AllocationsPath             string = "/allocations/"
	AllocationsDeviceIDPath     string = "/allocations/{deviceId}"
)
// RestStart to execute for API
func RestStart() {
	mu := mux.NewRouter()
	logger.Info(ctx, "Rest Server Starting...")
	mu.HandleFunc(SubscribersPath, (&SubscriberHandle{}).ServeHTTP)
	mu.HandleFunc(ProfilesPath, (&ProfileHandle{}).ServeHTTP)
	mu.HandleFunc(IgmpProxyPath, (&IgmpProxyHandle{}).ServeHTTP)
	mu.HandleFunc(MulticastPath, (&MulticastHandle{}).ServeHTTP)

        mu.HandleFunc(FlowsPath, (&onos_nbi.FlowHandle{}).ServeHTTP)
        mu.HandleFunc(FlowsPerDeviceIDPath, (&onos_nbi.FlowHandle{}).ServeHTTP)
        mu.HandleFunc(FlowPerDeviceIDFlowIDPath, (&onos_nbi.FlowHandle{}).ServeHTTP)
        mu.HandleFunc(PendingFlowsPath, (&onos_nbi.PendingFlowHandle{}).ServeHTTP)
        mu.HandleFunc(ProgrammedSubscribersPath, (&onos_nbi.ServiceAdapter{}).ServeHTTP)
        mu.HandleFunc(ServiceDevicePortPath, (&onos_nbi.ServiceAdapter{}).ServeHTTP)
        mu.HandleFunc(ServicePortNamePath, (&onos_nbi.ServiceAdapter{}).ServeHTTPWithPortName)
        mu.HandleFunc(ServicePortStagCtagTpIDPath, (&onos_nbi.ServiceAdapter{}).ServeHTTPWithPortName)
        mu.HandleFunc(AllocationsPath, (&onos_nbi.DhcpRelayHandle{}).ServeHTTP)
        mu.HandleFunc(AllocationsDeviceIDPath, (&onos_nbi.DhcpRelayHandle{}).ServeHTTP)

	err := http.ListenAndServe(":8181", mu)
	logger.Infow(ctx, "Rest Server Started", log.Fields{"Error": err})
}

func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.AddPackageWithDefaultParam()
	if err != nil {
		panic(err)
	}
}

