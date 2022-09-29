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
	"encoding/json"
        "net/http"
	"strconv"

	"github.com/gorilla/mux"
        "voltha-go-controller/internal/pkg/of"
        "voltha-go-controller/log"
	cntlr "voltha-go-controller/internal/pkg/controller"
)

// FlowHandle struct to handle flow related REST calls
type FlowHandle struct {
}

// FlowHandle struct to handle flow related REST calls
type PendingFlowHandle struct {
}

const (
        /** Switch input port. */
        IN_PORT int = iota

        /** Switch physical input port. */
        IN_PHY_PORT

        /** Metadata passed between tables. */
        METADATA

        /** Ethernet destination address. */
        ETH_DST

        /** Ethernet destination address with masking. */
        ETH_DST_MASKED

        /** Ethernet source address. */
        ETH_SRC

        /** Ethernet source address with masking. */
        ETH_SRC_MASKED

        /** Ethernet frame type. */
        ETH_TYPE

        /** VLAN id. */
        VLAN_VID

        /** VLAN priority. */
        VLAN_PCP
        /**
         * Inner VLAN id.
         *
         * Note: Some drivers may not support this.
         */
        INNER_VLAN_VID

        /**
         * Inner VLAN pcp.
         *
         * Note: Some drivers may not support this.
         */
        INNER_VLAN_PCP

        /** IP DSCP (6 bits in ToS field). */
        IP_DSCP

        /** IP ECN (2 bits in ToS field). */
        IP_ECN

        /** IP protocol. */
        IP_PROTO

        /** IPv4 source address. */
        IPV4_SRC

        /** IPv4 destination address. */
        IPV4_DST

        /** TCP source port. */
        TCP_SRC

        /** TCP source port with masking. */
        TCP_SRC_MASKED

        /** TCP destination port. */
        TCP_DST

        /** TCP destination port with masking. */
        TCP_DST_MASKED

        /** UDP source port. */
        UDP_SRC

        /** UDP source port with masking. */
        UDP_SRC_MASKED

        /** UDP destination port. */
        UDP_DST

        /** UDP destination port with masking. */
        UDP_DST_MASKED

        /** SCTP source port. */
        SCTP_SRC

        /** SCTP source port with masking. */
        SCTP_SRC_MASKED

        /** SCTP destination port. */
        SCTP_DST

        /** SCTP destination port with masking. */
        SCTP_DST_MASKED

        /** ICMP type. */
        ICMPV4_TYPE

        /** ICMP code. */
        ICMPV4_CODE

        /** ARP opcode. */
        ARP_OP

        /** ARP source IPv4 address. */
        ARP_SPA

        /** ARP target IPv4 address. */
        ARP_TPA

        /** ARP source hardware address. */
        ARP_THA

        /** IPv6 source address. */
        IPV6_SRC

        /** IPv6 destination address. */
        IPV6_DST

        /** IPv6 Flow Label. */
        IPV6_FLABEL

        /** ICMPv6 type. */
        ICMPV6_TYPE

        /** ICMPv6 code. */
        ICMPV6_CODE

        /** Target address for ND. */
        IPV6_ND_TARGET

        /** Source link-layer for ND. */
        IPV6_ND_SLL

        /** Target link-layer for ND. */
        IPV6_ND_TLL

        /** MPLS label. */
        MPLS_LABEL

        /** MPLS TC. */
        MPLS_TC

        /**  MPLS BoS bit. */
        MPLS_BOS

        /** PBB I-SID. */
        PBB_ISID

        /** Logical Port Metadata. */
        TUNNEL_ID

        /** IPv6 Extension Header pseudo-field. */
        IPV6_EXTHDR

        /** Unassigned value: 40. */
        UNASSIGNED_40

        /** PBB UCA header field. */
        PBB_UCA

        /** TCP flags. */
        TCP_FLAGS

        /** Output port from action set metadata. */
        ACTSET_OUTPUT

        /** Packet type value. */
        PACKET_TYPE

        //
        // NOTE: Everything below is defined elsewhere: ONOS-specific,
        // extensions, etc.
        //
        /** Optical channel signal ID (lambda). */
        OCH_SIGID

        /** Optical channel signal type (fixed or flexible). */
        OCH_SIGTYPE

        /** ODU (Optical channel Data Unit) signal ID. */
        ODU_SIGID

        /** ODU (Optical channel Data Unit) signal type. */
        ODU_SIGTYPE

        /** Protocol-independent. */
        PROTOCOL_INDEPENDENT

        /** Extension criterion. */
        EXTENSION

        /** An empty criterion. */
        DUMMY
)

type TrafficSelector struct {

}

type TrafficTreatment struct {

}

type FlowEntry struct {
	TrafficSelector
	TrafficTreatment
	FlowID int
	AppID  int
	GroupID int
	Priority int
	DeviceID string
	TimeOut int
	TableID int
	
}

func (fh *FlowHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
        logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
        switch r.Method {
        case "GET":
                fh.GetFlows(context.Background(), w, r)
        default:
                logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
        }
}

func (pfh *PendingFlowHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
        logger.Infow(ctx, "Received-northbound-request", log.Fields{"Method": r.Method, "URL": r.URL})
        switch r.Method {
        case "GET":
                pfh.GetPendingFlows(context.Background(), w, r)
        default:
                logger.Warnw(ctx, "Unsupported Method", log.Fields{"Method": r.Method})
        }
}

func (pfh *PendingFlowHandle) GetPendingFlows(cntx context.Context, w http.ResponseWriter, r *http.Request) {

}

func (fh *FlowHandle) GetFlows(cntx context.Context, w http.ResponseWriter, r *http.Request) {
        vars := mux.Vars(r)
        deviceID := vars["deviceId"]
        flowIDStr := vars["flowId"]
	flowID, _ := strconv.ParseUint(flowIDStr, 10, 64)
	var flowResp []*of.VoltSubFlow
	if len(deviceID) > 0 && len(flowIDStr) > 0 {
		flow, err := fh.getFlow(deviceID, flowID)
		if err != nil {
			logger.Errorw(ctx, "Get flow returned error", log.Fields{"Error": err})
			return
		}
		// TODO confirm the exact format
		//flowEntry := fh.convertFlowToFlowEntry(flow)
		flowResp = append(flowResp, flow)
	} else {
		flows, err := fh.getAllFlows(deviceID)
		if err != nil {
			logger.Errorw(ctx, "Get flow returned error", log.Fields{"Error": err})
			return
		}
		for _, f := range flows {
		// TODO confirm the exact format
		//	flowEntry := fh.convertFlowToFlowEntry(f)
			flowResp = append(flowResp, f)
		}
	}
	FlowRespJSON, err := json.Marshal(flowResp)
	if err != nil {
		logger.Errorw(ctx, "Error occurred while marshaling flow response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	_, err = w.Write(FlowRespJSON)
	if err != nil {
		logger.Errorw(ctx, "error in sending flow response", log.Fields{"Error": err})
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (fh *FlowHandle) getAllFlows(deviceID string) ([]*of.VoltSubFlow, error) {
	if len(deviceID) == 0 {
		return cntlr.GetController().GetAllFlows()
	}
	return cntlr.GetController().GetFlows(deviceID)
}

func (fh *FlowHandle) getFlow(deviceID string, flowID uint64) (*of.VoltSubFlow, error) {
	return cntlr.GetController().GetFlow(deviceID, flowID)
}
func (fh *FlowHandle) convertFlowToFlowEntry (flow *of.VoltSubFlow) *FlowEntry {
	//TODO
//	var flowEntry := &flowEntry {

//	}
	return nil
}
