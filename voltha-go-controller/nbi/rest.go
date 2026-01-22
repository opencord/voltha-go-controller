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
	"github.com/opencord/voltha-lib-go/v7/pkg/probe"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"voltha-go-controller/log"
)

var (
	logger log.CLogger
	ctx    = context.TODO()
	// Prometheus metrics
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rest_server_http_requests_total",
			Help: "Total number of HTTP requests received by the REST server",
		},
		[]string{"method", "path", "status"},
	)
	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "rest_server_http_request_duration_seconds",
			Help:    "Histogram of response time for handler in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)
)

const (
	VGCService = "vgc-nbi-rest"
)
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
	ProgrammedSubscribersByIdPath     string = "/programmed-subscribers/{device}/{port}"
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
	NetConfigPath                     string = "/network-configurations"
	DeviceConfigPath                  string = "/olt/{serialNumber}"
	FlowProvisionStatus               string = "/flow-status/{portName}"
	Uplinkpath                        string = "/uplink/{deviceId}"
)

// RestStart to execute for API
func RestStart() {
	// If the context contains a k8s probe then register services
	p := probe.GetProbeFromContext(ctx)
	if p != nil {
		p.RegisterService(ctx, VGCService)
	}
	mu := mux.NewRouter()
	logger.Info(ctx, "Rest Server Starting...")
	// Add Prometheus metrics handler
	mu.Handle("/metrics", promhttp.Handler())
	// Wrap handlers with Prometheus middleware
	mu.HandleFunc(BasePath+SubscribersPath, prometheusMiddleware((&SubscriberHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+ProfilesPath, prometheusMiddleware((&ProfileHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+IgmpProxyPath, prometheusMiddleware((&IgmpProxyHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+IgmpProxyDeletePath, prometheusMiddleware((&IgmpProxyHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+MulticastPath, prometheusMiddleware((&MulticastHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+MulticastDeletePath, prometheusMiddleware((&MulticastHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+FlowsPath, prometheusMiddleware((&onosnbi.FlowHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+FlowsPerDeviceIDPath, prometheusMiddleware((&onosnbi.FlowHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+FlowPerDeviceIDFlowIDPath, prometheusMiddleware((&onosnbi.FlowHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+PendingFlowsPath, prometheusMiddleware((&onosnbi.PendingFlowHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+ProgrammedSubscribersPath, prometheusMiddleware((&onosnbi.ServiceAdapter{}).ServeHTTP))
	mu.HandleFunc(BasePath+ProgrammedSubscribersByIdPath, prometheusMiddleware((&onosnbi.ServiceAdapter{}).ServeHTTP))
	mu.HandleFunc(BasePath+ServiceDevicePortPath, prometheusMiddleware((&onosnbi.ServiceAdapter{}).ServeHTTP))
	mu.HandleFunc(BasePath+ServicePortNamePath, prometheusMiddleware((&onosnbi.ServiceAdapter{}).ServeHTTPWithPortName))
	mu.HandleFunc(BasePath+ServicePortStagCtagTpIDPath, prometheusMiddleware((&onosnbi.ServiceAdapter{}).ServeHTTPWithPortName))
	mu.HandleFunc(BasePath+AllocationsPath, prometheusMiddleware((&onosnbi.DhcpRelayHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+AllocationsDeviceIDPath, prometheusMiddleware((&onosnbi.DhcpRelayHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+DevicesPath, prometheusMiddleware((&onosnbi.DeviceHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+PortsPath, prometheusMiddleware((&onosnbi.DevicePortHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+PortsPerDeviceIDPath, prometheusMiddleware((&onosnbi.DevicePortHandle{}).ServeHTTPWithDeviceID))
	mu.HandleFunc(BasePath+MecLearnerPath, prometheusMiddleware((&onosnbi.MacLearnerHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+MecLearnerDeviceIDAndPortNoPath, prometheusMiddleware((&onosnbi.MacLearnerHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+MecLearnerDevicePortAndVlanIDPath, prometheusMiddleware((&onosnbi.MacLearnerHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+PortIgnoredPath, prometheusMiddleware((&onosnbi.PortIgnoredHandle{}).PortsIgnoredServeHTTP))
	mu.HandleFunc(BasePath+MetersParh, prometheusMiddleware((&onosnbi.MetersHandle{}).MeterServeHTTP))
	mu.HandleFunc(BasePath+MetersByIDPath, prometheusMiddleware((&onosnbi.MetersHandle{}).MeterServeHTTP))
	mu.HandleFunc(BasePath+GroupsPath, prometheusMiddleware((&onosnbi.GroupsHandle{}).GroupServeHTTP))
	mu.HandleFunc(BasePath+GroupsByIDPath, prometheusMiddleware((&onosnbi.GroupsHandle{}).GroupServeHTTP))
	mu.HandleFunc(BasePath+OltFlowServicePath, prometheusMiddleware((&onosnbi.OltFlowServiceHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+NetConfigPath, prometheusMiddleware((&NetConfigHandle{}).NetConfigServeHTTP))
	mu.HandleFunc(BasePath+DeviceConfigPath, prometheusMiddleware((&onosnbi.DeviceConfigHandle{}).ServeHTTP))
	mu.HandleFunc(BasePath+FlowProvisionStatus, prometheusMiddleware((&SubscriberHandle{}).StatusServeHTTP))
	mu.HandleFunc(BasePath+Uplinkpath, (&onosnbi.UpdateUplinkDeviceConfigHandle{}).ServeHTTP)

	err := http.ListenAndServe(":8181", mu)
	if p != nil {
		p.UpdateStatus(ctx, VGCService, probe.ServiceStatusRunning)
	}
	logger.Infow(ctx, "Rest Server Started", log.Fields{"Error": err})
}

// prometheusMiddleware wraps an HTTP handler to collect Prometheus metrics
func prometheusMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Normalize the path by extracting the route template
		route := mux.CurrentRoute(r)
		pathTemplate, err := route.GetPathTemplate()
		if err != nil {
			// If the path template cannot be determined, fall back to the raw path
			pathTemplate = r.URL.Path
		}

		// Start the timer for request duration
		timer := prometheus.NewTimer(httpRequestDuration.WithLabelValues(r.Method, pathTemplate))
		defer timer.ObserveDuration()

		// Record the status code
		rec := &statusRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rec, r)

		// Increment the request counter
		httpRequestsTotal.WithLabelValues(r.Method, pathTemplate, http.StatusText(rec.statusCode)).Inc()
	}
}

// statusRecorder is a wrapper to capture the HTTP status code
type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rec *statusRecorder) WriteHeader(code int) {
	rec.statusCode = code
	rec.ResponseWriter.WriteHeader(code)
}

func init() {
	// Setup this package so that its log level can be modified at runtime
	var err error
	logger, err = log.AddPackageWithDefaultParam()
	if err != nil {
		panic(err)
	}

	// Register Prometheus metrics
	prometheus.MustRegister(httpRequestsTotal)
	prometheus.MustRegister(httpRequestDuration)
}
