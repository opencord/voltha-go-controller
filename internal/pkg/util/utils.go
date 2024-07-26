/*
* Copyright 2022-2024present Open Networking Foundation
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

package util

import (
	"encoding/binary"
	"net"
	"strings"

	"voltha-go-controller/internal/pkg/of"
)

// RemoveFromSlice to remove particular value from given slice.
func RemoveFromSlice(s []string, value string) []string {
	i := 0
	for i = 0; i < len(s); i++ {
		if s[i] == value {
			break
		}
	}
	if i != len(s) {
		//It means value is found in the slice
		s[len(s)-1], s[i] = s[i], s[len(s)-1]
		return s[:len(s)-1]
	}
	return s
}

// IsSliceSame - check and return true if the two slices are identical
func IsSliceSame(ref, rcvd []uint32) bool {
	var found bool
	if len(ref) != len(rcvd) {
		return false
	}

	for _, refEntry := range ref {
		found = false

		for _, rcvdEntry := range rcvd {
			if refEntry == rcvdEntry {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// IsPbitSliceSame - check and return true if the two slices are identical
func IsPbitSliceSame(ref, rcvd []of.PbitType) bool {
	var found bool
	if len(ref) != len(rcvd) {
		return false
	}

	for _, refEntry := range ref {
		found = false

		for _, rcvdEntry := range rcvd {
			if refEntry == rcvdEntry {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// IsNniPort is to check if given port is Nni Port.
func IsNniPort(id uint32) bool {
	return (id >= 0x1000000)
}

// Uint32ToByte to convert uint32 to byte
func Uint32ToByte(value uint32) []byte {
	byteValue := make([]byte, 4)
	binary.BigEndian.PutUint32(byteValue[0:4], value)
	return byteValue
}

// IP2LongConv convert ip address to integer value.
func IP2LongConv(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

// Long2ipConv convert integer to ip address.
func Long2ipConv(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

// GetExpIPList converts list or range of IPs to expanded IP list
func GetExpIPList(ips []string) []net.IP {
	ipList := []net.IP{}

	for _, ipOrRange := range ips {
		if strings.Contains(ipOrRange, "-") {
			var splits = strings.Split(ipOrRange, "-")
			ipStart := IP2LongConv(net.ParseIP(splits[0]))
			ipEnd := IP2LongConv(net.ParseIP(splits[1]))

			for i := ipStart; i <= ipEnd; i++ {
				ipList = append(ipList, Long2ipConv(i))
			}
		} else {
			ipList = append(ipList, net.ParseIP(ipOrRange))
		}
	}
	return ipList
}

// MacAddrsMatch for comparison of MAC addresses and return true if MAC addresses matches
func MacAddrsMatch(addr1 net.HardwareAddr, addr2 net.HardwareAddr) bool {
	if len(addr1) != len(addr2) {
		return false
	}
	for i := 0; i < len(addr1); i++ {
		if addr1[i] != addr2[i] {
			return false
		}
	}
	return true
}
