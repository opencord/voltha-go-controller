/*
* Copyright 2023-2024present Open Networking Foundation
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

package nbi

import (
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"
	app "voltha-go-controller/internal/pkg/application"

	"github.com/gorilla/mux"
)

func TestDHCPSessionInfoHandle_ServeHTTP(t *testing.T) {
	req, err := http.NewRequest("GET", "/serve_http/", nil)
	if err != nil {
		t.Fatal(err)
	}

	vars := map[string]string{
		"id":    "1",
		"mac":   "test_mac",
		"svlan": "test_svlan",
		"cvlan": "test_cvlan",
	}
	req = mux.SetURLVars(req, vars)

	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "DHCPSessionInfoHandle_ServeHTTP",
			args: args{
				w: rr,
				r: req,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dh := &DHCPSessionInfoHandle{}
			dh.ServeHTTP(tt.args.w, tt.args.r)
		})
	}
}

func Test_validateArgs(t *testing.T) {
	type args struct {
		sv      string
		cv      string
		macAddr string
		svlan   string
		cvlan   string
		mac     string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "DHCPSessionInfoHandle_ServeHTTP",
			args: args{
				sv:      "4096",
				cv:      "4096",
				macAddr: "1.1.1.1.1",
				svlan:   "4096",
				cvlan:   "4096",
				mac:     "1.1.1.1.1",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateArgs(tt.args.sv, tt.args.cv, tt.args.macAddr, tt.args.svlan, tt.args.cvlan, tt.args.mac); got != tt.want {
				t.Errorf("validateArgs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getDhcpSessionFields(t *testing.T) {
	type args struct {
		id       string
		port     string
		svlan    string
		cvlan    string
		univlan  string
		macAddr  string
		ipAddr   net.IP
		ipv6Addr net.IP
		rState   app.DhcpRelayState
		rStatev6 app.Dhcpv6RelayState
		lTime    time.Time
		l6Time   time.Time
	}
	var netIp net.IP
	addr, _ := net.LookupIP("BBSM00010001")
	for _, arr := range addr {
		netIp = arr
	}
	tests := []struct {
		name string
		args args
		want *DhcpSessionInfo
	}{
		{
			name: "getDhcpSessionFields",
			args: args{
				id:       "BBSM00010001",
				port:     "BBSM00010001-1",
				macAddr:  "1.1.1.1.1",
				svlan:    "2169",
				cvlan:    "4096",
				univlan:  "4096",
				ipAddr:   netIp,
				ipv6Addr: netIp,
				rState:   app.DhcpRelayStateAck,
				rStatev6: app.Dhcpv6RelayStateNone,
				lTime:    time.Now(),
				l6Time:   time.Now(),
			},
			want: &DhcpSessionInfo{
				DeviceID:    "BBSM00010001",
				Uniport:     "BBSM00010001-1",
				Svlan:       "2169",
				Cvlan:       "4096",
				UniVlan:     "4096",
				MacAddress:  "1.1.1.1.1",
				IPAddress:   netIp.String(),
				Ipv6Address: netIp.String(),
				State:       strconv.Itoa(int(app.DhcpRelayStateAck)),
				Statev6:     strconv.Itoa(int(app.Dhcpv6RelayStateNone)),
				LeaseTime:   (time.Now().Format(time.RubyDate)),
				LeaseTimev6: (time.Now().Format(time.RubyDate)),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getDhcpSessionFields(tt.args.id, tt.args.port, tt.args.svlan, tt.args.cvlan, tt.args.univlan, tt.args.macAddr, tt.args.ipAddr, tt.args.ipv6Addr, tt.args.rState, tt.args.rStatev6, tt.args.lTime, tt.args.l6Time); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getDhcpSessionFields() = %v, want %v", got, tt.want)
			}
		})
	}
}
