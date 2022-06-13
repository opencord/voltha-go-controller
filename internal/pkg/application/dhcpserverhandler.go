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
	"sync"
	"time"

	"github.com/opencord/voltha-lib-go/v7/pkg/log"
)

const (
	dhcpTimeout uint8 = 60
)

// done channel required to gracefully stop dhcp server handler thread
var done = make(chan bool)

// dhcpServerInfo map having dhcp network as key and dhcp request response transaction as value
var dhcpServerInfo map[dhcpServerTag]dhcpTransactionInfo

// alarmsRaised is struct having array of dhcp network for which dhcp unreachable alarm raised
var alarmsRaised alarmsRaisedInfo

// mux is mutex variable used for lock unlock
var mux sync.Mutex

// StartDhcpServerHandler starts go routine periodically(every second) to verify DHCP server reachability.
func StartDhcpServerHandler() {
	// Intialize global dhcp map and ticker as one second
	dhcpServerInfo = make(map[dhcpServerTag]dhcpTransactionInfo)
	ticker := time.NewTicker(1 * time.Second)

	// go routine runs checkDhcpTimeout every second and exit if done value is set.
	go func() {
		for {
			select {
			case <-done:
				ticker.Stop()
				return
			case <-ticker.C:
				mux.Lock()
				checkDhcpTimeout()
				mux.Unlock()

			}
		}
	}()
}

// checkDhcpTimeout method called every second to verify dhcp timeout for each DHCP network
func checkDhcpTimeout() {
	// logger.Debugw(ctx, "[dhcptimeout] DHCP MAP Info", log.Fields{"Map": dhcpServerInfo})
	for dsTag, dtInfo := range dhcpServerInfo {
		dtInfo.decrementTimer()
		if dtInfo.getTimer() == 0 {
			logger.Debugw(ctx, "[dhcptimeout]Timer Expired", log.Fields{"ctag": dsTag.cTag, "stag": dsTag.sTag})
			if dtInfo.getReceivedResponseCount() == 0 && !alarmsRaised.isexist(dsTag) {
				alarmsRaised.add(dsTag)
				logger.Infow(ctx, "Alarms Raised", log.Fields{"ctag": dsTag.cTag, "stag": dsTag.sTag})
			}

			// Reset helps in
			// case 1: when 2 requests, 1 response received within timeout interval.
			// case 2: 1 request and no response even after timeout. (Unreachable alarm raised)
			// In both cases, reset method provides additional timeout to receive response before deleting
			dtInfo.resetRequestResponseCount(dhcpTimeout)

			// Delete dhcp entry in map and continue to process next entry if pending request set to 0
			if dtInfo.getPendingRequestCount() == 0 {
				delete(dhcpServerInfo, dsTag)
				logger.Debugw(ctx, "[dhcptimeout]DhcpServerTag info removed", log.Fields{"ctag": dsTag.cTag, "stag": dsTag.sTag})
				// logger.Debugw(ctx, "[dhcptimeout] DHCP MAP Info", log.Fields{"Map": dhcpServerInfo})
				continue
			}
		}
		// Update decremented timer value and continue loop
		dhcpServerInfo[dsTag] = dtInfo
	}
}

// dhcpRequestReceived called for every DHCP request received from client.
func dhcpRequestReceived(cTag, sTag uint16, smac string) {
	var dtInfo dhcpTransactionInfo
	var valueExist bool
	dsTag := newDhcpServerTag(cTag, sTag)

	mux.Lock()
	logger.Debugw(ctx, "dhcpRequestReceived", log.Fields{"ctag": cTag, "stag": sTag, "smac": smac})
	if dtInfo, valueExist = dhcpServerInfo[dsTag]; !valueExist {
		dtInfo = newDhcpTransactionInfo(dhcpTimeout, smac)
		dtInfo.incrementPendingRequestCount()
	}

	// Source mac received in dhcp request is not same as dtInfo mac then
	// Its new subscriber request, hence increment pending request count.
	// If multiple dhcp request received with same mac are ignored.
	if dtInfo.smac != smac {
		dtInfo.incrementPendingRequestCount()
	}

	dhcpServerInfo[dsTag] = dtInfo
	mux.Unlock()
}

// dhcpResponseReceived called for every DHCP response received from dhcp server.
func dhcpResponseReceived(cTag, sTag uint16) {
	var dtInfo dhcpTransactionInfo
	var valueExist bool
	dsTag := newDhcpServerTag(cTag, sTag)

	mux.Lock()
	logger.Debugw(ctx, "dhcpResponseReceived", log.Fields{"ctag": cTag, "stag": sTag})
	if dtInfo, valueExist = dhcpServerInfo[dsTag]; !valueExist {
		logger.Warnw(ctx, "Ignore unknown response", log.Fields{"DhcpResp": dsTag})
		mux.Unlock()
		return
	}

	// If already unreachable alarm raised, clear and remove from array
	if alarmsRaised.isexist(dsTag) {
		alarmsRaised.remove(dsTag)
		logger.Infow(ctx, "Alarm Cleared", log.Fields{"ctag": dsTag.cTag, "stag": dsTag.sTag})
	}

	// Increments received count and decrement pending count
	dtInfo.responseReceived()
	logger.Debugw(ctx, "Updated dtInfo", log.Fields{"pendingReq": dtInfo.pendingRequestCount, "receivedReq": dtInfo.receivedResponseCount})

	if dtInfo.getPendingRequestCount() == 0 {
		delete(dhcpServerInfo, dsTag)
	} else {
		dhcpServerInfo[dsTag] = dtInfo
	}
	mux.Unlock()
}

// StopDhcpServerHandler stops dhcp server handler go routine
func StopDhcpServerHandler() {
	done <- true
}

// dhcpServerTag contains unique dhcp network information
type dhcpServerTag struct {
	sTag uint16
	cTag uint16
}

func newDhcpServerTag(cTag, sTag uint16) dhcpServerTag {
	var d dhcpServerTag
	d.sTag = sTag
	d.cTag = cTag
	return d
}

// dhcpTransactionInfo contains DHCP request response transaction information.
type dhcpTransactionInfo struct {
	timer                 uint8
	pendingRequestCount   uint32
	receivedResponseCount uint32
	previousRequestCount  uint32
	smac                  string
}

func newDhcpTransactionInfo(timer uint8, smac string) dhcpTransactionInfo {
	var dt dhcpTransactionInfo
	dt.timer = timer
	dt.smac = smac
	return dt
}

func (dt *dhcpTransactionInfo) getTimer() uint8 {
	return dt.timer
}

func (dt *dhcpTransactionInfo) decrementTimer() uint8 {
	dt.timer--
	return dt.timer
}

func (dt *dhcpTransactionInfo) getPendingRequestCount() uint32 {
	return dt.pendingRequestCount
}

func (dt *dhcpTransactionInfo) incrementPendingRequestCount() {
	dt.pendingRequestCount++
}

func (dt *dhcpTransactionInfo) getReceivedResponseCount() uint32 {
	return dt.receivedResponseCount
}

func (dt *dhcpTransactionInfo) responseReceived() {
	dt.receivedResponseCount++
	dt.pendingRequestCount--
}

func (dt *dhcpTransactionInfo) resetRequestResponseCount(timer uint8) {
	if dt.pendingRequestCount >= dt.previousRequestCount {
		dt.pendingRequestCount = dt.pendingRequestCount - dt.previousRequestCount
	}
	dt.previousRequestCount = dt.pendingRequestCount
	dt.receivedResponseCount = 0
	dt.timer = timer
}

// alarmsRaisedInfo contains the all networks alarm raised information
type alarmsRaisedInfo struct {
	arrayInfo []dhcpServerTag
}

// add an entry into alarm raised array
func (a *alarmsRaisedInfo) add(val dhcpServerTag) {
	a.arrayInfo = append(a.arrayInfo, val)
}

// isexist check if entry exist in alarm raised array
func (a *alarmsRaisedInfo) isexist(val dhcpServerTag) bool {
	for _, srvTag := range a.arrayInfo {
		if srvTag == val {
			return true
		}
	}
	return false
}

// remove deletes given entry from alarm raised array
func (a *alarmsRaisedInfo) remove(val dhcpServerTag) {
	for ind := range a.arrayInfo {
		if a.arrayInfo[ind] == val {
			a.arrayInfo = append(a.arrayInfo[:ind], a.arrayInfo[ind+1:]...)
			break
		}
	}
}
