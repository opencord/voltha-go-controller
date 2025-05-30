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
	"context"
	"sync"
	"time"
	"voltha-go-controller/log"
)

// TimerType - type of timer used
type TimerType string

const (
	tickTimer        TimerType = "TickTimer"
	pendingPoolTimer TimerType = "PendingPoolTimer"
)

var timerMap = map[TimerType]bool{
	tickTimer:        false,
	pendingPoolTimer: false,
}

var timerChannels = sync.Map{}

// TimerCfg structure
type TimerCfg struct {
	tick time.Duration
}

// Start to start timer
func (va *VoltApplication) Start(cntx context.Context, cfg TimerCfg, timerType TimerType) {
	logger.Infow(ctx, " Timer Starts", log.Fields{"Duration ": cfg})
	if timerMap[timerType] {
		logger.Warn(ctx, "Duplicate Timer!!! Timer already running")
		return
	}
	timerMap[timerType] = true
	ch := make(chan bool)
	timerChannels.Store(timerType, ch)
	for {
		select {
		case <-time.After(cfg.tick):
			switch timerType {
			case tickTimer:
				va.Tick()
			case pendingPoolTimer:
				va.removeExpiredGroups(cntx)
			}
		case <-ch:
			return
		}
	}
}

// StopTimer to stop timers
func StopTimer() {
	timerChannels.Range(func(key, value interface{}) bool {
		ch := value.(chan bool)
		ch <- true
		/* Range calls function sequentially for each key and value present in the map.
		If function returns false, range stops the iteration. */
		return true
	})
}
