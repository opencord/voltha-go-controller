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
	"errors"
	"strconv"

	"github.com/google/gopacket/layers"
)

const (
	//EtherType8100 - EtherType dot1q
	EtherType8100 uint8 = 0
	//EtherType88a8 - EtherType dot1ad
	EtherType88a8 uint8 = 1
	//EtherType9100 - EtherType dot1ad doubleTag
	EtherType9100 uint8 = 2
	//EtherType9200 - EtherType dot1q doubleTag
	EtherType9200 uint8 = 3
)

//GetMetadataForL2Protocol - returns metadata value for provide ethertype
func GetMetadataForL2Protocol(etherType layers.EthernetType) (uint8, error) {
	switch etherType {
	case layers.EthernetTypeDot1Q:
		return EtherType8100, nil
	case layers.EthernetTypeQinQ:
		return EtherType88a8, nil
	case layers.EthernetTypeDot1QDoubleTag:
		return EtherType9100, nil
	case layers.EthernetTypeQinQDoubleTag:
		return EtherType9200, nil
	default:
		return 0, errors.New("EtherType not supported")
	}
}

func convertToInt(data string) int {

	value, err := strconv.Atoi(data)
	if err != nil {
		return 0
	}
	return value

}

func convertToUInt64(data string) uint64 {

	value, err := strconv.ParseUint(data, 10, 64)
	if err != nil {
		return 0
	}
	return value

}
