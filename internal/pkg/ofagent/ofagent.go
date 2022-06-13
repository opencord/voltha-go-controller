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

package ofagent

import (
	"context"
	"sync"
	"time"

	"voltha-go-controller/database"
	"voltha-go-controller/internal/pkg/holder"
	"voltha-go-controller/internal/pkg/intf"
	"github.com/opencord/voltha-lib-go/v7/pkg/log"
	"github.com/opencord/voltha-lib-go/v7/pkg/probe"
	"github.com/opencord/voltha-protos/v5/go/voltha"
	ofp "github.com/opencord/voltha-protos/v5/go/openflow_13"
	"google.golang.org/grpc"
)

var logger log.CLogger
var ctx = context.TODO()

func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.RegisterPackage(log.JSON, log.ErrorLevel, log.Fields{})
	if err != nil {
		panic(err)
	}
}

type ofaEvent byte
type ofaState byte

var db database.DBIntf

const (
	ofaEventStart = ofaEvent(iota)
	ofaEventVolthaConnected
	ofaEventVolthaDisconnected
	ofaEventError

	ofaStateConnected = ofaState(iota)
	ofaStateConnecting
	ofaStateDisconnected
)

var ofAgent *OFAgent

// OFAgent structure
type OFAgent struct {
	VolthaAPIEndPoint         string
	DeviceListRefreshInterval time.Duration
	ConnectionMaxRetries      int
	ConnectionRetryDelay      time.Duration
	state                     ofaState

	volthaConnection *grpc.ClientConn
	volthaClient     *holder.VolthaServiceClientHolder
	mapLock          sync.Mutex
	clientMap        map[string]intf.IOFClient
	events           chan ofaEvent

	packetInChannel    chan *ofp.PacketIn
	packetOutChannel   chan *ofp.PacketOut
	changeEventChannel chan *ofp.ChangeEvent
	OFClientAgent      intf.IOFClientAgent
}

// NewOFAgent is constructor for OFAgent
func NewOFAgent(config *OFAgent) (*OFAgent, error) {
	ofa := OFAgent{
		VolthaAPIEndPoint:         config.VolthaAPIEndPoint,
		DeviceListRefreshInterval: config.DeviceListRefreshInterval,
		ConnectionMaxRetries:      config.ConnectionMaxRetries,
		ConnectionRetryDelay:      config.ConnectionRetryDelay,
		OFClientAgent:             config.OFClientAgent,
		volthaClient:              &holder.VolthaServiceClientHolder{},
		packetInChannel:           make(chan *ofp.PacketIn),
		// customPacketIndChannel:    make(chan *voltha.CustomPacketIn),
		packetOutChannel:   make(chan *ofp.PacketOut),
		changeEventChannel: make(chan *ofp.ChangeEvent),
		// ofpCommandNotiChannel:     make(chan *voltha.OfpCmdRespNotification),
		// oltRebootNotiChannel:      make(chan *voltha.OltRebootNotification),
		clientMap: make(map[string]intf.IOFClient),
		events:    make(chan ofaEvent, 100),
	}

	if ofa.DeviceListRefreshInterval <= 0 {
		logger.Warnw(ctx, "device list refresh internal not valid, setting to default",
			log.Fields{
				"value":   ofa.DeviceListRefreshInterval.String(),
				"default": (10 * time.Second).String()})
		ofa.DeviceListRefreshInterval = 1 * time.Minute
	}

	if ofa.ConnectionRetryDelay <= 0 {
		logger.Warnw(ctx, "connection retry delay not value, setting to default",
			log.Fields{
				"value":   ofa.ConnectionRetryDelay.String(),
				"default": (3 * time.Second).String()})
		ofa.ConnectionRetryDelay = 3 * time.Second
	}

	if db == nil {
		db = database.GetDatabase()
	}
	ofAgent = &ofa
	return &ofa, nil
}

//GetOFAgent - returns ofAgent object
func GetOFAgent() *OFAgent {
	return ofAgent
}

// VolthaSvcClient for Voltha Svc client
func (ofa *OFAgent) VolthaSvcClient() voltha.VolthaServiceClient {
	return ofa.volthaClient.Get()
}

// Run - make the inital connection to voltha and kicks off io streams
func (ofa *OFAgent) Run(ctx context.Context) {

	logger.Debugw(ctx, "Starting GRPC - VOLTHA client",
		log.Fields{
			"voltha-endpoint": ofa.VolthaAPIEndPoint})

	// If the context contains a k8s probe then register services
	p := probe.GetProbeFromContext(ctx)
	if p != nil {
		p.RegisterService(ctx, "voltha")
	}

	ofa.events <- ofaEventStart

	/*
	 * Two sub-contexts are created here for different purposes so we can
	 * control the lifecyle of processing loops differently.
	 *
	 * volthaCtx -  controls those processes that rely on the GRPC
	 *              GRPCconnection to voltha and will be restarted when the
	 *              GRPC connection is interrupted.
	 * hdlCtx    -  controls those processes that listen to channels and
	 *              process each message. these will likely never be
	 *              stopped until the ofagent is stopped.
	 */
	var volthaCtx, hdlCtx context.Context
	var volthaDone, hdlDone func()
	state := ofaStateDisconnected

	for {
		select {
		case <-ctx.Done():
			logger.Errorw(ctx, "Context Done", log.Fields{"Context": ctx})
			if volthaDone != nil {
				volthaDone()
			}
			if hdlDone != nil {
				hdlDone()
			}
			return
		case event := <-ofa.events:
			switch event {
			case ofaEventStart:
				logger.Debug(ctx, "ofagent-voltha-start-event")

				// Start the loops that process messages
				hdlCtx, hdlDone = context.WithCancel(context.Background())
				go ofa.handlePacketsIn(hdlCtx)
				go ofa.handleChangeEvents(hdlCtx)

				// Kick off process to attempt to establish
				// connection to voltha
				state = ofaStateConnecting
				go func() {
					if err := ofa.establishConnectionToVoltha(hdlCtx, p); err != nil {
						logger.Errorw(ctx, "voltha-connection-failed", log.Fields{"error": err})
						panic(err)
					}
				}()

			case ofaEventVolthaConnected:
				logger.Debug(ctx, "ofagent-voltha-connect-event")

				// Start the loops that poll from voltha
				if state != ofaStateConnected {
					state = ofaStateConnected
					volthaCtx, volthaDone = context.WithCancel(context.Background())
					go ofa.receiveChangeEvents(volthaCtx)
					go ofa.receivePacketsIn(volthaCtx)
					go ofa.streamPacketOut(volthaCtx)
					go ofa.synchronizeDeviceList(volthaCtx)
				}

			case ofaEventVolthaDisconnected:
				if p != nil {
					p.UpdateStatus(ctx, "voltha", probe.ServiceStatusNotReady)
				}
				logger.Debug(ctx, "ofagent-voltha-disconnect-event")
				if state == ofaStateConnected {
					state = ofaStateDisconnected
					ofa.volthaClient.Clear()
					volthaDone()
					volthaDone = nil
				}
				if state != ofaStateConnecting {
					state = ofaStateConnecting
					go func() {
						hdlCtx, _ = context.WithCancel(context.Background())
						if err := ofa.establishConnectionToVoltha(hdlCtx, p); err != nil {
							logger.Errorw(ctx, "voltha-connection-failed", log.Fields{"error": err})
							panic(err)
						}
					}()
				}

			case ofaEventError:
				logger.Debug(ctx, "ofagent-error-event")
			default:
				logger.Fatalw(ctx, "ofagent-unknown-event",
					log.Fields{"event": event})
			}
		}
	}
}
