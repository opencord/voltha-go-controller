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
	"net/http"

	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/log"

	"github.com/gorilla/mux"
)

// TaskListHandle handle TaskList Requests
type TaskListHandle struct {
}

// ServeHTTP to serve http request
func (dh *TaskListHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	switch r.Method {
	case cGet:
		dh.GetTaskList(w, r)
	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

// GetTaskList to get task list
func (dh *TaskListHandle) GetTaskList(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var voltAppIntr app.VoltAppInterface
	voltApp := app.GetApplication()
	voltAppIntr = voltApp
	var deviceID string
	taskListResp := map[string]map[int]*app.TaskInfo{}
	logger.Infow(ctx, "Received get TaskList", log.Fields{"DeviceID": id})

	if len(id) > 0 {
		// If Get for single Device
		deviceID = id
		voltDevice := voltAppIntr.GetDevice(deviceID)
		if voltDevice != nil {
			taskList := voltAppIntr.GetTaskList(deviceID)
			taskListResp[deviceID] = taskList
		} else {
			logger.Warnw(ctx, "Invalid Device Id", log.Fields{"Device": id})
			return
		}
	} else {
		// Else If GetAll
		getDeviceTaskList := func(key, value interface{}) bool {
			voltDevice := value.(*app.VoltDevice)
			deviceID = voltDevice.Name
			taskList := voltAppIntr.GetTaskList(deviceID)
			taskListResp[deviceID] = taskList
			return true
		}
		voltApp.DevicesDisc.Range(getDeviceTaskList)
	}

	taskListJSON, err := json.Marshal(taskListResp)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling task list response", log.Fields{"TaskList": taskListResp, "Error": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(taskListJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending task list response", log.Fields{"TaskList": taskListResp, "Error": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logger.Debugw(ctx, "Fetching TaskListResp for device id", log.Fields{"TaskListResp": taskListResp})
}
# [EOF] - delta:force
