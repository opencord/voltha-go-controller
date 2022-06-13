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
package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	app "voltha-go-controller/internal/pkg/application"
	"voltha-go-controller/internal/pkg/of"
)

// ProcessAddSub to add sub info
func ProcessAddSub(tokens []string) {
	device := "OpenOLT100"
	port := uint32(100)
	cvlan := uint16(100)
	uvlan := uint16(4096)
	svlan := uint16(4096)
	for _, token := range tokens {
		s := strings.Split(token, "=")
		switch s[0] {
		case "device":
			device = s[1]
		case "port":
			res, _ := strconv.Atoi(s[1])
			port = uint32(res)
		case "cvlan":
			res, _ := strconv.Atoi(s[1])
			cvlan = uint16(res)
		case "uvlan":
			res, _ := strconv.Atoi(s[1])
			uvlan = uint16(res)
		case "svlan":
			res, _ := strconv.Atoi(s[1])
			svlan = uint16(res)
		}
	}
	portStr := "OFPort" + strconv.FormatInt(int64(port), 10)
	var vsc app.VoltServiceCfg
	vsc.UniVlan = of.VlanType(uvlan)
	vsc.CVlan = of.VlanType(cvlan)
	vsc.SVlan = of.VlanType(svlan)
	vsc.CircuitID = device + portStr
	vsc.RemoteID = []byte("test")
	vsc.Port = portStr
	vsc.Name = device + portStr + strconv.FormatInt(int64(cvlan), 10)

	app.GetApplication().AddService(vsc, nil)
}

// ProcessAddSubs to add multiple sub info
func ProcessAddSubs(tokens []string) {
	device := "OpenOLT100"
	cvlan := uint16(1015)
	uvlan := uint16(1015)
	svlan := uint16(2)
	//maclearning := false
	numSubs, _ := strconv.Atoi(tokens[0])
	for _, token := range tokens[1:] {
		s := strings.Split(token, "=")
		switch s[0] {
		case "device":
			device = s[1]
		case "cvlan":
			res, _ := strconv.Atoi(s[1])
			cvlan = uint16(res)
		case "uvlan":
			res, _ := strconv.Atoi(s[1])
			uvlan = uint16(res)
		case "svlan":
			res, _ := strconv.Atoi(s[1])
			svlan = uint16(res)
			// case "maclearning":
			// 	maclearning = true
		}
	}
	fmt.Println("Adding", numSubs, "Subscribers")
	for port := 1; port <= numSubs; port++ {
		for pbit := 0; pbit < 2; pbit++ {
			p := of.PbitType(pbit)
			portStr := "OFPort" + strconv.FormatInt(int64(port), 10)
			var vsc app.VoltServiceCfg
			vsc.UniVlan = of.VlanType(uvlan)
			vsc.CVlan = of.VlanType(cvlan)
			vsc.SVlan = of.VlanType(svlan)
			vsc.Pbits = []of.PbitType{p, p + 2, p + 4, p + 6}
			vsc.CircuitID = device + portStr
			// TODO : need to fix this only if its used.
			//vsc.MacLearning = maclearning
			vsc.RemoteID = []byte("test")
			vsc.Port = portStr
			vsc.Name = portStr + strconv.FormatInt(int64(cvlan), 10) + "PBIT" + strconv.FormatInt(int64(pbit), 10)

			if err := app.GetApplication().AddService(vsc, nil); err != nil {
				fmt.Println("Addition of sub with", port, "Pbit", pbit, "Failed - Reason", err.Error())
			}
		}
	}
}

// ProcessAddVnet to add vnet info
func ProcessAddVnet(tokens []string) {
	// Set the defaults so that each parameter doesn't need to be
	// configured each time
	cvlan := of.VlanType(1015)
	svlan := of.VlanType(2)
	uvlan := of.VlanType(1015)
	dhcprelay := false
	usdhcppbit := uint8(0)
	dsdhcppbit := uint8(6)

	// Read the attributes and set the values
	for _, token := range tokens[:] {
		s := strings.Split(token, "=")
		switch s[0] {
		case "dhcprelay":
			dhcprelay = true
		case "cvlan":
			res, _ := strconv.Atoi(s[1])
			cvlan = of.VlanType(res)
		case "uvlan":
			res, _ := strconv.Atoi(s[1])
			uvlan = of.VlanType(res)
		case "svlan":
			res, _ := strconv.Atoi(s[1])
			svlan = of.VlanType(res)
		case "usdhcppbit":
			res, _ := strconv.Atoi(s[1])
			usdhcppbit = uint8(res)
		case "dsdhcppbit":
			res, _ := strconv.Atoi(s[1])
			usdhcppbit = uint8(res)
		}
	}

	// Perform the configuration
	name := "NW" + strconv.FormatInt(int64(svlan), 10) + "-" + strconv.FormatInt(int64(cvlan), 10)
	cfg := app.VnetConfig{
		Name:      name,
		SVlan:     svlan,
		CVlan:     cvlan,
		UniVlan:   uvlan,
		DhcpRelay: dhcprelay,
	}
	cfg.UsDhcpPbit = append(cfg.UsDhcpPbit, of.PbitType(usdhcppbit))
	cfg.DsDhcpPbit = append(cfg.DsDhcpPbit, of.PbitType(dsdhcppbit))
	if err := app.GetApplication().AddVnet(cfg, nil); err != nil {
		fmt.Println("Error in configuration - Reason :", err.Error())
	}
}

// ProcessDelSubs to delete multiple sub info
func ProcessDelSubs(tokens []string) {
	cvlan := uint16(1015)
	numSubs, _ := strconv.Atoi(tokens[0])
	for _, token := range tokens[1:] {
		s := strings.Split(token, "=")
		switch s[0] {
		// 	case "device":
		// 		device = s[1]
		case "cvlan":
			res, _ := strconv.Atoi(s[1])
			cvlan = uint16(res)
			// 	case "uvlan":
			// 		res, _ := strconv.Atoi(s[1])
			// 		uvlan = uint16(res)
			// 	case "svlan":
			// 		res, _ := strconv.Atoi(s[1])
			// 		svlan = uint16(res)
			// 	case "maclearning":
			// 		maclearning = true
		}
	}
	fmt.Println("Deleting", numSubs, "Subscribers")
	for port := 1; port <= numSubs; port++ {
		for pbit := 0; pbit < 2; pbit++ {
			portStr := "OFPort" + strconv.FormatInt(int64(port), 10)
			name := portStr + strconv.FormatInt(int64(cvlan), 10) + "PBIT" + strconv.FormatInt(int64(pbit), 10)
			app.GetApplication().DelService(name, false, nil, false)
		}
	}
}

// ProcessCli to process cli
func ProcessCli() {
	scanner := bufio.NewScanner(os.Stdin)
	a := regexp.MustCompile(" +")
	for {
		fmt.Print("Controller> Enter Command:")
		scanner.Scan()
		command := scanner.Text()
		s := a.Split(command, -1)
		switch s[0] {
		case "addsub":
			ProcessAddSub(s[1:])
		case "addsubs":
			ProcessAddSubs(s[1:])
		case "delsubs":
			ProcessDelSubs(s[1:])
		case "addvnet":
			ProcessAddVnet(s[1:])
		case "exit":
			return
		case "":

		default:
			fmt.Println("Unknown Command")
		}
	}
}
