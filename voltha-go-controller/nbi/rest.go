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

	"github.com/opencord/voltha-lib-go/v7/pkg/log"
)

var logger log.CLogger
var ctx = context.TODO()

// RestStart to execute for API
func RestStart() {
	mu := mux.NewRouter()
	logger.Info(ctx, "Rest Server Starting...")
	mu.HandleFunc("/subscribers/{id}", (&SubscriberHandle{}).ServeHTTP)
	mu.HandleFunc("/profiles/{id}", (&ProfileHandle{}).ServeHTTP)
	mu.HandleFunc("/igmp-proxy/", (&IgmpProxyHandle{}).ServeHTTP)
	mu.HandleFunc("/multicast/", (&MulticastHandle{}).ServeHTTP)
	err := http.ListenAndServe(":8181", mu)
	logger.Infow(ctx, "Rest Server Started", log.Fields{"Error": err})
}

func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.RegisterPackage(log.JSON, log.ErrorLevel, log.Fields{})
	if err != nil {
		panic(err)
	}
}
