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

package onosnbi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	app "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/log"

	"github.com/gorilla/mux"
)

type GroupsHandle struct {
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
func (gh *GroupsHandle) GroupServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
	vars := mux.Vars(r)
	groupID := vars["id"]

	switch r.Method {
	case cGet:
		if groupID != "" {
			gh.GetGroupInfo(context.Background(), groupID, w, r)
		} else {
			gh.GetAllGroups(context.Background(), w, r)
		}

	default:
		logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
	}
}

func (gh *GroupsHandle) GetGroupInfo(cntx context.Context, groupID string, w http.ResponseWriter, r *http.Request) {
	groupResp := GroupList{}
	groupResp.Groups = []*GroupsInfo{}
	grpID, err := strconv.ParseUint(groupID, 10, 32)
	if err != nil {
		logger.Errorw(ctx, "Failed to parse string to uint32", log.Fields{"Reason": err.Error()})
	}
	id := uint32(grpID)

	logger.Infow(ctx, "Inside GetGroupInfo method", log.Fields{"groupId": id})

	Groups, err := app.GetController().GetGroups(ctx, id)
	if err != nil {
		logger.Errorw(ctx, "Failed to fetch group info", log.Fields{"Reason": err.Error()})
		w.WriteHeader(http.StatusNotFound)
		return
	}

	GroupResp := gh.convertGroupsToOnosGroup(Groups)
	groupResp.Groups = append(groupResp.Groups, GroupResp)

	GroupsRespJSON, err := json.Marshal(groupResp)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling group response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(GroupsRespJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending group response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (gh *GroupsHandle) GetAllGroups(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	logger.Info(cntx, "Inside GetAllGroups method")
	groupListResp := GroupList{}
	groupListResp.Groups = []*GroupsInfo{}

	GroupsInfo, err := app.GetController().GetGroupList()
	if err != nil {
		logger.Errorw(ctx, "Failed to fetch group info", log.Fields{"Reason": err.Error()})
		w.WriteHeader(http.StatusNotFound)
		return
	}

	for _, groups := range GroupsInfo {
		grpResp := gh.convertGroupsToOnosGroup(groups)
		groupListResp.Groups = append(groupListResp.Groups, grpResp)
	}

	GroupRespJSON, err := json.Marshal(groupListResp)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling meter response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(GroupRespJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending meter response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}
}
