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

package of

import (
	// "voltha-go-controller/log"
	ofp "github.com/opencord/voltha-protos/v5/go/openflow_13"
	// "github.com/opencord/voltha-protos/v5/go/voltha"
)

// MeterCommand :  Meters and bands as stored by VOLT application
type MeterCommand uint32

const (
	// MeterCommandAdd constant
	MeterCommandAdd MeterCommand = 1
	// MeterCommandDel constant
	MeterCommandDel MeterCommand = 2
)

const (
	// MeterOperSuccess constant
	MeterOperSuccess = 0
	// MeterOperFailure constant
	MeterOperFailure = 1
	// MeterOperPending constant
	MeterOperPending = 2
)

// Band structure
type Band struct {
	Type      uint32
	Rate      uint32
	BurstSize uint32
}

// Meter structure
type Meter struct {
	ID          uint32
	Bands       []Band
	State       uint8
	ErrorReason string
}

// NewMeter is constructor for Meter
func NewMeter(id uint32) *Meter {
	var vm Meter
	vm.ID = id
	return &vm
}

// AddBand to add band info to meter
func (vm *Meter) AddBand(rate uint32, bs uint32) {
	vb := Band{Rate: rate, BurstSize: bs}
	vm.Bands = append(vm.Bands, vb)
}

// MeterUpdate for conversion of VOLT to OF for meters and bands
func MeterUpdate(deviceID string, c MeterCommand, m *Meter) (*ofp.MeterModUpdate, error) {
	mmu := &ofp.MeterModUpdate{Id: deviceID}
	mmu.MeterMod = &ofp.OfpMeterMod{
		MeterId: m.ID,
	}
	if c == MeterCommandAdd {
		mmu.MeterMod.Command = ofp.OfpMeterModCommand_OFPMC_ADD
		mmu.MeterMod.Flags = 5
		for _, b := range m.Bands {
			AddBand(mmu, b)
		}
	} else {
		mmu.MeterMod.Command = ofp.OfpMeterModCommand_OFPMC_DELETE
	}
	return mmu, nil
}

// AddBand to add band info
func AddBand(mmu *ofp.MeterModUpdate, b Band) {
	band := &ofp.OfpMeterBandHeader{}
	band.Type = ofp.OfpMeterBandType_OFPMBT_DROP
	band.Rate = b.Rate
	band.BurstSize = b.BurstSize
	// band.Data = &ofp.OfpMeterBandHeader_Drop{
	// 	Drop: &ofp.OfpMeterBandDrop{},
	// }
	mmu.MeterMod.Bands = append(mmu.MeterMod.Bands, band)
}
