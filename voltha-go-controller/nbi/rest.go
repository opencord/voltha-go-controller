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

	onosnbi "voltha-go-controller/voltha-go-controller/onos_nbi"

	"github.com/gorilla/mux"

	"voltha-go-controller/log"
)

var logger log.CLogger
var ctx = context.TODO()

const (
	BasePath                          string = "/vgc/v1"
	SubscribersPath                   string = "/subscribers/{id}"
	ProfilesPath                      string = "/profiles/{id}"
	IgmpProxyPath                     string = "/igmp-proxy"
	IgmpProxyDeletePath               string = "/igmp-proxy/{outgoingigmpvlanid}"
	MulticastPath                     string = "/multicast/"
	MulticastDeletePath               string = "/multicast/{egressvlan}"
	FlowsPath                         string = "/flows"
	DevicesPath                       string = "/devices"
	PortsPath                         string = "/devices/ports"
	PortsPerDeviceIDPath              string = "/devices/{olt_of_id}/ports"
	FlowsPerDeviceIDPath              string = "/flows/{deviceId}"
	FlowPerDeviceIDFlowIDPath         string = "/flows/{deviceId}/{flowId}"
	PendingFlowsPath                  string = "/flows/pending"
	ProgrammedSubscribersPath         string = "/programmed-subscribers"
	ServiceDevicePortPath             string = "/services/{device}/{port}"
	ServicePortNamePath               string = "/services/{portName}"
	ServicePortStagCtagTpIDPath       string = "/services/{portName}/{sTag}/{cTag}/{tpId}"
	AllocationsPath                   string = "/allocations"
	AllocationsDeviceIDPath           string = "/allocations/{deviceId}"
	MecLearnerPath                    string = "/mapping/all"
	MecLearnerDeviceIDAndPortNoPath   string = "/mapping/{deviceId}/{portNumber}"
	MecLearnerDevicePortAndVlanIDPath string = "/mapping/{deviceId}/{portNumber}/{vlanId}"
	PortIgnoredPath                   string = "/ports/ignored"
	MetersParh                        string = "/meters"
	MetersByIDPath                    string = "/meters/{id}"
	GroupsPath                        string = "/groups"
	GroupsByIDPath                    string = "/groups/{id}"
	OltFlowServicePath                string = "/oltflowservice"
	NetConfigPath                     string = "/network/configurations"
	DeviceConfigPath                  string = "/olt/{serialNumber}"
)

// RestStart to execute for API
func RestStart() {
	mu := mux.NewRouter()
	logger.Info(ctx, "Rest Server Starting...")
	mu.HandleFunc(BasePath+SubscribersPath, (&SubscriberHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+ProfilesPath, (&ProfileHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+IgmpProxyPath, (&IgmpProxyHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+IgmpProxyDeletePath, (&IgmpProxyHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+MulticastPath, (&MulticastHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+MulticastDeletePath, (&MulticastHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+FlowsPath, (&onosnbi.FlowHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+FlowsPerDeviceIDPath, (&onosnbi.FlowHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+FlowPerDeviceIDFlowIDPath, (&onosnbi.FlowHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+PendingFlowsPath, (&onosnbi.PendingFlowHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+ProgrammedSubscribersPath, (&onosnbi.ServiceAdapter{}).ServeHTTP)
	mu.HandleFunc(BasePath+ServiceDevicePortPath, (&onosnbi.ServiceAdapter{}).ServeHTTP)
	mu.HandleFunc(BasePath+ServicePortNamePath, (&onosnbi.ServiceAdapter{}).ServeHTTPWithPortName)
	mu.HandleFunc(BasePath+ServicePortStagCtagTpIDPath, (&onosnbi.ServiceAdapter{}).ServeHTTPWithPortName)
	mu.HandleFunc(BasePath+AllocationsPath, (&onosnbi.DhcpRelayHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+AllocationsDeviceIDPath, (&onosnbi.DhcpRelayHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+DevicesPath, (&onosnbi.DeviceHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+PortsPath, (&onosnbi.DevicePortHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+PortsPerDeviceIDPath, (&onosnbi.DevicePortHandle{}).ServeHTTPWithDeviceID)
	mu.HandleFunc(BasePath+MecLearnerPath, (&onosnbi.MacLearnerHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+MecLearnerDeviceIDAndPortNoPath, (&onosnbi.MacLearnerHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+MecLearnerDevicePortAndVlanIDPath, (&onosnbi.MacLearnerHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+PortIgnoredPath, (&onosnbi.PortIgnoredHandle{}).PortsIgnoredServeHTTP)
	mu.HandleFunc(BasePath+MetersParh, (&onosnbi.MetersHandle{}).MeterServeHTTP)
	mu.HandleFunc(BasePath+MetersByIDPath, (&onosnbi.MetersHandle{}).MeterServeHTTP)
	mu.HandleFunc(BasePath+GroupsPath, (&onosnbi.GroupsHandle{}).GroupServeHTTP)
	mu.HandleFunc(BasePath+GroupsByIDPath, (&onosnbi.GroupsHandle{}).GroupServeHTTP)
	mu.HandleFunc(BasePath+OltFlowServicePath, (&onosnbi.OltFlowServiceHandle{}).ServeHTTP)
	mu.HandleFunc(BasePath+NetConfigPath, (&NetConfigHandle{}).NetConfigServeHTTP)
	mu.HandleFunc(BasePath+DeviceConfigPath, (&onosnbi.DeviceConfigHandle{}).ServeHTTP)

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
