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
	cntlr "voltha-go-controller/internal/pkg/controller"
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
	vars := mux.Vars(r)
	groupID := vars["id"]
	logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "groupId": groupID, "URL": r.URL})

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
		logger.Errorw(ctx, "Failed to parse received groupID from string to uint32", log.Fields{"groupID": groupID, "Reason": err.Error()})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	id := uint32(grpID)
	var voltContrIntr cntlr.VoltControllerInterface
	cntrlr := cntlr.GetController()
	voltContrIntr = cntrlr
	Groups, err := voltContrIntr.GetGroups(ctx, id)
	if err != nil {
		logger.Errorw(ctx, "Failed to fetch group info from Device through grpID", log.Fields{"groupID": groupID, "Reason": err.Error()})
		w.WriteHeader(http.StatusNotFound)
		return
	}

	GroupResp := gh.convertGroupsToOnosGroup(Groups)
	groupResp.Groups = append(groupResp.Groups, GroupResp)

	GroupsRespJSON, err := json.Marshal(groupResp)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling group response specific to received groupID", log.Fields{"groupId": id, "GroupResp": groupResp, "Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(GroupsRespJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending group response specific to received groupID", log.Fields{"groupId": id, "GroupResp": groupResp, "Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logger.Debugw(ctx, "Fetching GroupInfo specific to received groupID", log.Fields{"groupId": id, "GroupResp": groupResp})
}

func (gh *GroupsHandle) GetAllGroups(cntx context.Context, w http.ResponseWriter, r *http.Request) {
	groupListResp := GroupList{}
	groupListResp.Groups = []*GroupsInfo{}

	var voltContrIntr cntlr.VoltControllerInterface
	cntrlr := cntlr.GetController()
	voltContrIntr = cntrlr
	GroupsInfo, err := voltContrIntr.GetGroupList()
	if err != nil {
		logger.Errorw(ctx, "Failed to fetch group info from VoltController Device", log.Fields{"Reason": err.Error()})
		w.WriteHeader(http.StatusNotFound)
		return
	}

	for _, groups := range GroupsInfo {
		grpResp := gh.convertGroupsToOnosGroup(groups)
		groupListResp.Groups = append(groupListResp.Groups, grpResp)
	}

	GroupRespJSON, err := json.Marshal(groupListResp)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling group List response", log.Fields{"groupListResp": groupListResp, "Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(GroupRespJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending group List response", log.Fields{"groupListResp": groupListResp, "Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	logger.Debugw(ctx, "Fetching All GroupInfo", log.Fields{"groupListResp": groupListResp})
}
