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

package event

import (
	"context"
	"errors"
	"time"
	"voltha-go-controller/log"

	"github.com/opencord/voltha-lib-go/v7/pkg/events"
	"github.com/opencord/voltha-lib-go/v7/pkg/events/eventif"
	"github.com/opencord/voltha-lib-go/v7/pkg/kafka"
	"github.com/opencord/voltha-protos/v5/go/voltha"

	common "voltha-go-controller/internal/pkg/types"
)

var logger log.CLogger

type Event struct {
	clientType  string
	address     string
	kafkaClient kafka.Client
	eventProxy  eventif.EventProxy
}

func InitializeKafkaClient(ctx context.Context, clientType string, address string, producermaxRetries int, metadatMaxRetries int) (*Event, error) {
	logger.Infow(ctx, "common-client-type", log.Fields{"client": clientType})
	var eventHandler Event
	eventHandler.clientType = clientType
	eventHandler.address = address
	switch clientType {
	case "sarama":
		eventHandler.kafkaClient = kafka.NewSaramaClient(
			kafka.Address(address),
			kafka.ProducerReturnOnErrors(true),
			kafka.ProducerReturnOnSuccess(true),
			kafka.ProducerMaxRetries(producermaxRetries),
			kafka.ProducerRetryBackoff(time.Millisecond*30),
			kafka.MetadatMaxRetries(metadatMaxRetries))
		return &eventHandler, nil
	}

	return nil, errors.New("unsupported client type")
}

func InitializeEventProxy(ctx context.Context, eventHandler *Event, topic string) (eventif.EventProxy, error) {
	switch eventHandler.clientType {
	case "sarama":
		eventHandler.eventProxy = events.NewEventProxy(events.MsgClient(eventHandler.kafkaClient), events.MsgTopic(kafka.Topic{Name: topic}))
		return eventHandler.eventProxy, nil
	}

	return nil, errors.New("unsupported client type")
}

func GetEventProxy(eventHandler *Event) eventif.EventProxy {
	return eventHandler.eventProxy
}

func GetKafkaClient(eventHandler *Event) kafka.Client {
	return eventHandler.kafkaClient
}

// SendSubscriberStateEvent - sends subscriber state event to the event proxy
func (ev *Event) SendSubscriberStateEvent(ctx context.Context, onuSerial string, subState common.SubscriberStatus_Types, oltSerial string, sTag string, subType string, raisedTs int64) {
	if ev.eventProxy == nil {
		logger.Error(ctx, "Event proxy is not initialized")
		return
	}

	// Create event context with device state, onu serial and olt serial
	eventContext := make(map[string]string)
	// convert device state to string
	eventContext["subscriber-state"] = subState.String()
	eventContext["serial-number"] = onuSerial
	eventContext["olt-serial-number"] = oltSerial
	eventContext["subscriber-type"] = subType
	eventContext["olt-s-tag"] = sTag

	// Create device event
	deviceEvent := &voltha.DeviceEvent{
		Context:         eventContext,
		ResourceId:      onuSerial,
		DeviceEventName: "ONU_STATE_UPDATE_EVENT",
	}

	// Send event using event proxy
	if err := ev.eventProxy.SendDeviceEventWithKey(ctx, deviceEvent, voltha.EventCategory_EQUIPMENT, voltha.EventSubCategory_ONU, raisedTs, onuSerial); err != nil {
		logger.Errorw(ctx, "Failed to send device state event", log.Fields{"OnuSerial": onuSerial, "OltSerial": oltSerial, "SubscriberState": subState, "Error": err})
		return
	}

	logger.Infow(ctx, "Device state event sent successfully", log.Fields{"OnuSerial": onuSerial, "OltSerial": oltSerial, "SubscriberState": subState, "olt-s-tag": sTag})
}

func init() {
	// Setup this package so that it's log level can be modified at run time
	var err error
	logger, err = log.AddPackageWithDefaultParam()
	if err != nil {
		panic(err)
	}
}
