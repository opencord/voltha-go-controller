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

package vpagent

import (
	"context"

	"voltha-go-controller/log"

	"google.golang.org/grpc"
)

func (vpa *VPAgent) streamPacketOut(ctx context.Context) {
	logger.Debug(ctx, "packet-out-started")
	// If we exit, assume disconnected
	defer func() {
		vpa.events <- vpaEventVolthaDisconnected
		logger.Debug(ctx, "packet-out-finished")
	}()
	if vpa.volthaClient == nil {
		logger.Fatal(ctx, "no-voltha-connection")
		return
	}
	opt := grpc.EmptyCallOption{}
	streamCtx, streamDone := context.WithCancel(context.Background())
	outClient, err := vpa.volthaClient.Get().StreamPacketsOut(streamCtx, opt)
	defer streamDone()
	if err != nil {
		logger.Errorw(ctx, "streamPacketOut Error creating packetout stream ", log.Fields{"error": err})
		return
	}
top:
	for {
		select {
		case <-ctx.Done():
			break top
		case ofPacketOut := <-vpa.packetOutChannel:
			logger.Debug(ctx, "streamPacketOut Receive PacketOut from Channel")
			if err := outClient.Send(ofPacketOut); err != nil {
				logger.Errorw(ctx, "packet-out-send-error",
					log.Fields{"error": err.Error()})
				break top
			}
			logger.Debug(ctx, "packet-out-send")
		}
	}
}
