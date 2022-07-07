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

package application

import (
	"encoding/json"
	"net"

	"voltha-go-controller/internal/pkg/of"
        "voltha-go-controller/log"
)

// IgmpGroupPort : IGMP port implements a port which is associated with an IGMP
// version and the list of sources it implements for a given IGMP
// channel. We may improve this to have all IGMP channels so that
// we can implement per subscriber IGMP channel registration limits
// As a rule a single port cannot have both include and exclude
// lists. If we receive a include list we should purge the other
// list which is TODO
type IgmpGroupPort struct {
        Port              string
        CVlan             uint16
        Pbit              uint8
        Version           uint8
        Exclude           bool
        ExcludeList       []net.IP
        IncludeList       []net.IP
        QueryTimeoutCount uint32
        PonPortID         uint32
}

// NewIgmpGroupPort is constructor for a port
func NewIgmpGroupPort(port string, cvlan uint16, pbit uint8, version uint8, incl bool, ponPortID uint32) *IgmpGroupPort {
        var igp IgmpGroupPort
        igp.Port = port
        igp.CVlan = cvlan
        igp.Pbit = pbit
        igp.Version = version
        igp.Exclude = !incl
        igp.QueryTimeoutCount = 0
        igp.PonPortID = ponPortID
        return &igp
}

// InclSourceIsIn checks if a source is in include list
func (igp *IgmpGroupPort) InclSourceIsIn(src net.IP) bool {
        return IsIPPresent(src, igp.IncludeList)
}

// ExclSourceIsIn checks if a source is in exclude list
func (igp *IgmpGroupPort) ExclSourceIsIn(src net.IP) bool {
        return IsIPPresent(src, igp.ExcludeList)
}

// AddInclSource adds a source is in include list
func (igp *IgmpGroupPort) AddInclSource(src net.IP) {
        logger.Debugw(ctx, "Adding Include Source", log.Fields{"Port": igp.Port, "Src": src})
        igp.IncludeList = append(igp.IncludeList, src)
}

// AddExclSource adds a source is in exclude list
func (igp *IgmpGroupPort) AddExclSource(src net.IP) {
        logger.Debugw(ctx, "Adding Exclude Source", log.Fields{"Port": igp.Port, "Src": src})
        igp.ExcludeList = append(igp.ExcludeList, src)
}

// DelInclSource deletes a source is in include list
func (igp *IgmpGroupPort) DelInclSource(src net.IP) {
        logger.Debugw(ctx, "Deleting Include Source", log.Fields{"Port": igp.Port, "Src": src})
        for i, addr := range igp.IncludeList {
                if addr.Equal(src) {
                        igp.IncludeList = append(igp.IncludeList[:i], igp.IncludeList[i+1:]...)
                        return
                }
        }
}

// DelExclSource deletes a source is in exclude list
func (igp *IgmpGroupPort) DelExclSource(src net.IP) {
        logger.Debugw(ctx, "Deleting Exclude Source", log.Fields{"Port": igp.Port, "Src": src})
        for i, addr := range igp.ExcludeList {
                if addr.Equal(src) {
                        igp.ExcludeList = append(igp.ExcludeList[:i], igp.ExcludeList[i+1:]...)
                        return
                }
        }
}

// WriteToDb is utility to write IGMP Group Port Info to database
func (igp *IgmpGroupPort) WriteToDb(mvlan of.VlanType, gip net.IP, device string) error {
        b, err := json.Marshal(igp)
        if err != nil {
                return err
        }
        if err1 := db.PutIgmpRcvr(mvlan, gip, device, igp.Port, string(b)); err1 != nil {
                return err1
        }
        return nil
}

// NewIgmpGroupPortFromBytes create the IGMP group port from a byte slice
func NewIgmpGroupPortFromBytes(b []byte) (*IgmpGroupPort, error) {
        var igp IgmpGroupPort
        if err := json.Unmarshal(b, &igp); err != nil {
                logger.Warnw(ctx, "Decode of port failed", log.Fields{"str": string(b)})
                return nil, err
        }
        return &igp, nil
}
