//go:build profile
// +build profile

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
*
*
 */

package pprofcontroller

import (
	"net/http"

	// using for init
	"context"
	_ "net/http/pprof"
	"voltha-go-controller/log"
)

var logger log.CLogger
var ctx = context.TODO()

func Init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.RegisterPackage(log.JSON, log.ErrorLevel, log.Fields{})
	if err != nil {
		panic(err)
	}
	logger.Error(ctx, "Profiling is ENABLED")
	go func() {
		err := http.ListenAndServe("0.0.0.0:6060", nil)
		logger.Error(ctx, "Profiling enable FAILURE", log.Opts{"Error": err})
	}()
}
