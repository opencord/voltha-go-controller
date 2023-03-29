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
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/log"
)

// UniPortList : UNI Port list per channle has stores the UNI port list for this
// channel.
type UniPortList struct {
	UNIList *util.ConcurrentMap // [UNIPort] UNIPort
}

// NewUniPortsList is Constructor for UniPortList structure
func NewUniPortsList() *UniPortList {
	var uniPortsList UniPortList

	uniPortsList.UNIList = util.NewConcurrentMap()
	return &uniPortsList
}

// GetUniPortCount returns the number of UNI ports subscribed to
// current channel.
func (uniPortsList *UniPortList) GetUniPortCount() uint64 {
	return uniPortsList.UNIList.Length()
}

// PonPortChannels : PON port channel map keeps the active channel list and its
// count for this group.
type PonPortChannels struct {
	ChannelList *util.ConcurrentMap // [channelIP]*UniPortList
}

// NewPonPortChannels is constructor for PonPortChannel.
func NewPonPortChannels() *PonPortChannels {
	var ponPortChannel PonPortChannels

	ponPortChannel.ChannelList = util.NewConcurrentMap()
	return &ponPortChannel
}

// GetActiveChannelCount returns the number of active channel count
// for this pon port in the current group.
func (ponPortChannels *PonPortChannels) GetActiveChannelCount() uint32 {
	return uint32(ponPortChannels.ChannelList.Length())
}

// AddChannelToMap Adds new channel to the pon port map
func (ponPortChannels *PonPortChannels) AddChannelToMap(uniPort, channel string) bool {
	isNewChannel := bool(false)
	uniList, ok := ponPortChannels.ChannelList.Get(channel)
	if !ok {
		// Channel doesn't exists. Adding new channel.
		uniList = NewUniPortsList()
		isNewChannel = true
	}
	uniList.(*UniPortList).UNIList.Set(uniPort, uniPort)
	ponPortChannels.ChannelList.Set(channel, uniList)
	return isNewChannel
}

// RemoveChannelFromMap Removed channel from the pon port map
func (ponPortChannels *PonPortChannels) RemoveChannelFromMap(uniPort, channel string) bool {
	isDeleted := bool(false)
	uniList, ok := ponPortChannels.ChannelList.Get(channel)
	if ok {
		uniList.(*UniPortList).UNIList.Remove(uniPort)
		if uniList.(*UniPortList).UNIList.Length() == 0 {
			// Last port from the channel is removed.
			// Removing channel from PON port map.
			ponPortChannels.ChannelList.Remove(channel)
			isDeleted = true
		} else {
			ponPortChannels.ChannelList.Set(channel, uniList)
		}
	} else {
		logger.Warnw(ctx, "Channel doesn't exists in the active channels list", log.Fields{"Channel": channel})
		return isDeleted
	}
	return isDeleted
}
