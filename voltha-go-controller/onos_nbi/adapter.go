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
        "net/http"

        "github.com/gorilla/mux"

        "voltha-go-controller/log"
)

var logger log.CLogger
var ctx = context.TODO()

func StartRestAdapter() {
	mu := mux.NewRouter()
	logger.Info(ctx, "Rest Adapter Starting...")

        mu.HandleFunc("/flows/", (&FlowHandle{}).ServeHTTP)
        mu.HandleFunc("/flows/{deviceId}", (&FlowHandle{}).ServeHTTP)
        mu.HandleFunc("/flows/{deviceId}/{flowId}", (&FlowHandle{}).ServeHTTP)
        mu.HandleFunc("/flows/pending/", (&PendingFlowHandle{}).ServeHTTP)
        mu.HandleFunc("/programmed-subscribers/", (&ServiceAdapter{}).ServeHTTP)
        mu.HandleFunc("/services/{device}/{port}", (&ServiceAdapter{}).ServeHTTP)
        mu.HandleFunc("/services/{portName}", (&ServiceAdapter{}).ServeHTTPWithPortName)
        mu.HandleFunc("/services/{portName}/{sTag}/{cTag}/{tpId}", (&ServiceAdapter{}).ServeHTTPWithPortName)

	_ = http.ListenAndServe(":8181", mu)
}

func init() {
        // Setup this package so that it's log level can be modified at run time
        var err error
        logger, err = log.AddPackageWithDefaultParam()
        if err != nil {
                panic(err)
        }
}
