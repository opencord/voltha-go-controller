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
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/log"
)

// PppoeIaState type
type PppoeIaState uint8

const (
	// PppoeIaStateNone constant
	PppoeIaStateNone PppoeIaState = iota
	// PppoeIaStatePADI constant
	PppoeIaStatePADI
	// PppoeIaStatePADO constant
	PppoeIaStatePADO
	// PppoeIaStatePADR constant
	PppoeIaStatePADR
	// PppoeIaStatePADS constant
	PppoeIaStatePADS
	// PppoeIaStatePADT constant
	PppoeIaStatePADT
)

const (
	// PPPoEVendorID constant
	PPPoEVendorID uint32 = 0x0DE9
	// TYPECIRCUITID constant
	TYPECIRCUITID byte = 0x01
	// TYPEREMOTEID constant
	TYPEREMOTEID byte = 0x02
	// TYPEMINDATAUS constant
	TYPEMINDATAUS byte = 0x83
	// TYPEMINDATADS constant
	TYPEMINDATADS byte = 0x84
	// TYPEMAXDATAUS constant
	TYPEMAXDATAUS byte = 0x87
	// TYPEMAXDATADS constant
	TYPEMAXDATADS byte = 0x88
)

var (
	// DSLATTRVendorID is PPPoEVendorID in byte format
	DSLATTRVendorID = util.Uint32ToByte(PPPoEVendorID)
)

// IPppoeIaSession interface
type IPppoeIaSession interface {
	GetCircuitID() []byte
	GetRemoteID() []byte
	GetNniVlans() (uint16, uint16)
	GetPppoeIaState() PppoeIaState
	SetPppoeIaState(PppoeIaState)
	SetMacAddr(context.Context, net.HardwareAddr)
}

// PppoeIaRelayVnet : The PppoeIa relay sessions are stored in a map to be retrieved from when
// a response is received from the network. The map uses the VLANs and the
// the MAC address as key to finding the service
// PppoeIa Relay Virtual Network hosts a set of PppoeIa relay sessions that belong
// to the network. It supports two VLANs as its identify. If a single VLAN or
// no VLAN is to be used, those two should be passed as 4096 (VlanNone)
type PppoeIaRelayVnet struct {
	sessions  *util.ConcurrentMap //map[[6]byte]IPppoeIaSession
	OuterVlan uint16
	InnerVlan uint16
}

// PppoeIaNetworks : PppoeIa Networks hosts different PppoeIa networks that in turn hold the PppoeIa
// sessions
type PppoeIaNetworks struct {
	Networks *util.ConcurrentMap //map[uint32]*PppoeIaRelayVnet
}

// NewPppoeIaRelayVnet is constructor for a PppoeIa Relay Virtual network
func NewPppoeIaRelayVnet(outerVlan uint16, innerVlan uint16) *PppoeIaRelayVnet {
	logger.Debugw(ctx, "NewPppoeIaRelayVnet", log.Fields{"OuterVlan": outerVlan, "innerVlan": innerVlan})
	var drv PppoeIaRelayVnet

	drv.OuterVlan = outerVlan
	drv.InnerVlan = innerVlan
	drv.sessions = util.NewConcurrentMap() //make(map[[6]byte]IPppoeIaSession)
	return &drv
}

// AddPppoeIaRelayVnet add pppoeia relay vnet
func (dn *PppoeIaNetworks) AddPppoeIaRelayVnet(outerVlan uint16, innerVlan uint16) *PppoeIaRelayVnet {
	logger.Debugw(ctx, "AddPppoeIaRelayVnet", log.Fields{"OuterVlan": outerVlan, "innerVlan": innerVlan})
	comboVlan := uint32(outerVlan)<<16 + uint32(innerVlan)
	if drv, ok := dn.Networks.Get(comboVlan); ok {
		return drv.(*PppoeIaRelayVnet)
	}
	drv := NewPppoeIaRelayVnet(outerVlan, innerVlan)
	dn.Networks.Set(comboVlan, drv)
	return drv
}

// NewPppoeIaNetworks is constructor for PppoeIa network
func NewPppoeIaNetworks() *PppoeIaNetworks {
	logger.Info(ctx, "NewPppoeIaNetworks")
	var dn PppoeIaNetworks
	dn.Networks = util.NewConcurrentMap() //make(map[uint32]*PppoeIaRelayVnet)
	return &dn
}

// AddPppoeIaSession to add pppoeia session
func (dn *PppoeIaNetworks) AddPppoeIaSession(pkt gopacket.Packet, session IPppoeIaSession) {
	logger.Info(ctx, "AddPppoeIaSession")
	var key [6]byte
	ethl := pkt.Layer(layers.LayerTypeEthernet)
	eth, _ := ethl.(*layers.Ethernet)
	addr := eth.SrcMAC
	copy(key[:], addr[0:6])
	drv := dn.AddPppoeIaRelayVnet(session.GetNniVlans())
	drv.sessions.Set(key, session)
}

// DelPppoeIaSession to delete pppoeia session
func (dn *PppoeIaNetworks) DelPppoeIaSession(pkt gopacket.Packet, session IPppoeIaSession) {
	logger.Info(ctx, "DelPppoeIaSession")
	var key [6]byte
	ethl := pkt.Layer(layers.LayerTypeEthernet)
	eth, _ := ethl.(*layers.Ethernet)
	addr := eth.SrcMAC
	if len(addr) != 6 {
		logger.Errorw(ctx, "Invalid MAC address", log.Fields{"Addr": addr})
		return
	}
	copy(key[:], addr[0:6])
	drv := dn.AddPppoeIaRelayVnet(session.GetNniVlans())
	drv.sessions.Remove(key)
}

// delPppoeIaSessions to delete pppoeia sessions
func delPppoeIaSessions(addr net.HardwareAddr, outervlan of.VlanType, innervlan of.VlanType) {
	logger.Infow(ctx, "delPppoeIaSessions", log.Fields{"Addr": addr, "OuterVlan": outervlan, "innerVlan": innervlan})
	var key [6]byte
	if addr == nil || !NonZeroMacAddress(addr) {
		logger.Warnw(ctx, "Invalid MAC address", log.Fields{"Addr": addr})
		return
	}
	copy(key[:], addr[0:6])
	drv := pppoeIaNws.AddPppoeIaRelayVnet(uint16(outervlan), uint16(innervlan))
	drv.sessions.Remove(key)
	logger.Debugw(ctx, "PppoeIa Sessions deleted", log.Fields{"MAC": addr})
}

// GetPppoeIaSession to get pppoeia sessions
func (dn *PppoeIaNetworks) GetPppoeIaSession(outerVlan uint16, innerVlan uint16, addr net.HardwareAddr) (IPppoeIaSession, error) {
	logger.Debugw(ctx, "GetPppoeIaSession", log.Fields{"Addr": addr, "OuterVlan": outerVlan, "innerVlan": innerVlan})
	var key [6]byte
	if len(addr) != 6 {
		logger.Errorw(ctx, "Invalid MAC address", log.Fields{"Addr": addr})
		return nil, errors.New("Invalid MAC address")
	}
	copy(key[:], addr[0:6])
	drv := dn.AddPppoeIaRelayVnet(outerVlan, innerVlan)
	logger.Debugw(ctx, "Key for PPPoE session", log.Fields{"Key": key})
	if session, ok := drv.sessions.Get(key); ok {
		return session.(IPppoeIaSession), nil
	}
	return nil, ErrSessionDoNotExist
}

// GetVnetForNni to get vnet for nni port
func GetVnetForNni(addr net.HardwareAddr, cvlan of.VlanType, svlan of.VlanType, pbit uint8) (*VoltPortVnet, error) {
	var err error
	var session IPppoeIaSession
	logger.Infow(ctx, "GetVnetForNni, Mac Obtained MAC: ", log.Fields{"Addr": addr})
	if session, err = pppoeIaNws.GetPppoeIaSession(uint16(svlan), uint16(cvlan), addr); err != nil {
		logger.Errorw(ctx, "PPPoE Session retrieval failed", log.Fields{"Error": err})
		if err == ErrSessionDoNotExist {
			logger.Info(ctx, "Finding matching VPV from packet")
			vpvs, err1 := GetApplication().GetVpvsForDsPkt(cvlan, svlan, addr, pbit)
			if len(vpvs) == 1 {
				return vpvs[0], nil
			}
			return nil, err1
		}
		return nil, err
	}

	if session != nil {
		vpv, ok := session.(*VoltPortVnet)

		if ok {
			logger.Infow(ctx, "Session Exist: VPV found", log.Fields{"VPV": vpv})
			return vpv, nil
		}
	}
	logger.Error(ctx, "PPPoE Session retrieved of wrong type")
	return nil, errors.New("The session retrieved of wrong type")
}

// AddIaOption : Addition of PppoeIa Option 82 which codes circuit-id and remote-id
// into the packet. This happens as the request is relayed to the
// PppoeIa servers on the NNI
func AddIaOption(svc *VoltService, pppoe *layers.PPPoE) {
	//NOTE : both cID and rID should not be empty if this function is called
	var data []byte
	cID := svc.GetCircuitID()
	rID := svc.RemoteID
	logger.Debugw(ctx, "AddIaOption", log.Fields{"cID": cID, "rID": rID})

	if len(cID) != 0 || len(rID) != 0 || svc.isDataRateAttrPresent() {
		data = append(data, DSLATTRVendorID...)
	}

	logger.Debugw(ctx, "Vendor Info", log.Fields{"Data": data})

	if len(cID) != 0 {
		data = append(data, TYPECIRCUITID)
		data = append(data, byte(len(cID)))
		data = append(data, cID...)
	}
	if len(rID) != 0 {
		data = append(data, TYPEREMOTEID)
		data = append(data, byte(len(rID)))
		data = append(data, rID...)
	}

	if svc.isDataRateAttrPresent() {
		minDrUs := util.Uint32ToByte(svc.MinDataRateUs)
		data = append(data, TYPEMINDATAUS)
		data = append(data, byte(len(minDrUs)))
		data = append(data, minDrUs...)

		minDrDs := util.Uint32ToByte(svc.MinDataRateDs)
		data = append(data, TYPEMINDATADS)
		data = append(data, byte(len(minDrDs)))
		data = append(data, minDrDs...)

		maxDrUs := util.Uint32ToByte(svc.MaxDataRateUs)
		data = append(data, TYPEMAXDATAUS)
		data = append(data, byte(len(maxDrUs)))
		data = append(data, maxDrUs...)

		maxDrDs := util.Uint32ToByte(svc.MaxDataRateDs)
		data = append(data, TYPEMAXDATADS)
		data = append(data, byte(len(maxDrDs)))
		data = append(data, maxDrDs...)
	}
	option := layers.NewPPPoEOption(layers.PPPoEOptVendorSpecific, data)
	pppoe.Options = append(pppoe.Options, option)
}

// DelIaOption for deletion of IA option from the packet received on the NNI interface.
func DelIaOption(pppoe *layers.PPPoE) {
	logger.Info(ctx, "DelIaOption")
	for index, option := range pppoe.Options {
		if option.Type == layers.PPPoEOptVendorSpecific {
			pppoe.Options = append(pppoe.Options[0:index], pppoe.Options[index+1:]...)
			return
		}
	}
}

// ProcessDsPppoeIaPacket : This function processes DS PppoeIa packet received on the NNI port.
// The services are attached to the access ports. Thus, the PppoeIa
// session is derived from the list of PppoeIa sessions stored in the
// common map. The key for retrieval includes the VLAN tags in the
// the packet and the MAC address of the client.
func (va *VoltApplication) ProcessDsPppoeIaPacket(cntx context.Context, device string, port string, pkt gopacket.Packet) {
	// Retrieve the layers to build the outgoing packet. It is not
	// possible to add/remove layers to the existing packet and thus
	// the lyayers are extracted to build the outgoing packet
	eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	pppoe := pkt.Layer(layers.LayerTypePPPoE).(*layers.PPPoE)

	logger.Infow(ctx, "Processing Southbound DS PppoeIa packet", log.Fields{"Device": device, "Port": port, "Type": pppoe.Code})

	// Retrieve the priority and drop eligible flags from the
	// packet received
	var priority uint8
	var dropEligible bool
	dot1ql := pkt.Layer(layers.LayerTypeDot1Q)
	if dot1ql != nil {
		dot1q := dot1ql.(*layers.Dot1Q)
		priority = dot1q.Priority
		dropEligible = dot1q.DropEligible
	}

	pktInnerlan, pktOuterlan := GetVlansFromPacket(pkt)
	vpv, err := GetVnetForNni(eth.DstMAC, pktInnerlan, pktOuterlan, priority)
	if err != nil {
		logger.Errorw(ctx, "VNET couldn't be found for NNI", log.Fields{"Error": err})
		return
	}

	// Do not modify pppoe header if vnet's mac_learning type is not PPPoE-IA.
	if vpv.PppoeIa {
		// Delete the IA option that may be included in the response
		DelIaOption(pppoe)
		switch pppoe.Code {
		case layers.PPPoECodePADO:
			vpv.SetPppoeIaState(PppoeIaStatePADO)
		case layers.PPPoECodePADS:
			vpv.SetPppoeIaState(PppoeIaStatePADS)
		case layers.PPPoECodePADT:
			vpv.SetPppoeIaState(PppoeIaStatePADT)
		}
		vpv.WriteToDb(cntx)
	}
	// Create the outgoing bufer and set the checksum in the packet
	buff := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	cTagType := layers.EthernetTypePPPoEDiscovery
	eth.EthernetType = layers.EthernetTypeDot1Q
	priority = vpv.GetRemarkedPriority(priority)

	var pktLayers []gopacket.SerializableLayer
	pktLayers = append(pktLayers, eth)

	var qVlans []of.VlanType
	var qVlanLayers []gopacket.SerializableLayer

	if vpv.AllowTransparent {
		vlanThreshold := 2
		// In case of ONU_CVLAN or OLT_SVLAN, the DS pkts have single configured vlan
		// In case of ONU_CVLAN_OLT_SVLAN or OLT_CVLAN_OLT_SVLAN, the DS pkts have 2 configured vlan
		// Based on that, the no. of vlans should be ignored to get only transparent vlans
		if vpv.VlanControl == ONUCVlan || vpv.VlanControl == OLTSVlan || vpv.VlanControl == None {
			vlanThreshold = 1
		}
		nxtLayer := layers.EthernetTypeDot1Q
		if vlans := GetVlans(pkt); len(vlans) > vlanThreshold {
			qVlans = vlans[vlanThreshold:]
			cTagType = layers.EthernetTypeDot1Q
		}
		for i, qVlan := range qVlans {
			vlan := uint16(qVlan)
			if i == (len(qVlans) - 1) {
				nxtLayer = layers.EthernetTypePPPoEDiscovery
			}
			qdot1q := &layers.Dot1Q{Priority: priority, VLANIdentifier: vlan, DropEligible: dropEligible, Type: nxtLayer}
			qVlanLayers = append(qVlanLayers, qdot1q)
		}
	}

	switch vpv.VlanControl {
	case ONUCVlanOLTSVlan:
		cdot1q := &layers.Dot1Q{Priority: priority, VLANIdentifier: uint16(vpv.CVlan), DropEligible: dropEligible, Type: cTagType}
		pktLayers = append(pktLayers, cdot1q)
	case ONUCVlan,
		None:
		sdot1q := &layers.Dot1Q{Priority: priority, VLANIdentifier: uint16(vpv.SVlan), DropEligible: dropEligible, Type: cTagType}
		pktLayers = append(pktLayers, sdot1q)
	case OLTCVlanOLTSVlan,
		OLTSVlan:
		udot1q := &layers.Dot1Q{Priority: priority, VLANIdentifier: uint16(vpv.UniVlan), DropEligible: dropEligible, Type: cTagType}
		pktLayers = append(pktLayers, udot1q)
	default:
		logger.Errorw(ctx, "Invalid Vlan Control Option", log.Fields{"Value": vpv.VlanControl})
		return
	}

	pktLayers = append(pktLayers, qVlanLayers...)
	pktLayers = append(pktLayers, pppoe)

	logger.Debugw(ctx, "Layers Count", log.Fields{"Count": len(pktLayers)})
	if err := gopacket.SerializeMultiLayers(buff, opts, pktLayers); err != nil {
		logger.Errorw(ctx, "Packet Serialization Failed", log.Fields{"Reason": err.Error()})
		return
	}

	if err := cntlr.GetController().PacketOutReq(device, vpv.Port, port, buff.Bytes(), false); err != nil {
		logger.Warnw(ctx, "PacketOutReq Failed", log.Fields{"Device": device, "Error": err})
	}
}

// ProcessUsPppoeIaPacket : The US PppoeIa packet is identified the PppoeIa OP in the packet. A request is considered upstream
// and the service associated with the packet is located by the port and VLANs in the packet
func (va *VoltApplication) ProcessUsPppoeIaPacket(cntx context.Context, device string, port string, pkt gopacket.Packet) {
	logger.Infow(ctx, "Processing Southbound US PppoeIa packet", log.Fields{"Device": device, "Port": port})
	// We received the packet on an access port and the service for the packet can be
	// gotten from the port and the packet
	vpv, svc := va.GetVnetFromPkt(device, port, pkt)
	if vpv == nil {
		logger.Errorw(ctx, "VNET couldn't be found from packet", log.Fields{"Device": device, "Port": port})
		return
	}

	outport, _ := va.GetNniPort(device)
	if outport == "" || outport == "0" {
		logger.Errorw(ctx, "NNI Port not found for device. Dropping Packet", log.Fields{"NNI": outport})
		return
	}

	//Add PPPoE session for reference so that the DS pkts can be processed and re-directed
	pppoeIaNws.AddPppoeIaSession(pkt, vpv)

	// Extract the layers in the packet to prepare the outgoing packet
	// We use the layers to build the outgoing packet from scratch as
	// the packet received can't be modified to add/remove layers
	eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	pppoe := pkt.Layer(layers.LayerTypePPPoE).(*layers.PPPoE)
	msgType := pppoe.Code
	logger.Debugw(ctx, "Processing Southbound US PppoeIa packet", log.Fields{"Device": device, "Port": port, "Type": pppoe.Code})

	AddIaOption(svc, pppoe)

	// Learn the 8021P values from the packet received
	var priority uint8
	dropEligible := false
	dot1ql := pkt.Layer(layers.LayerTypeDot1Q)
	if dot1ql != nil {
		dot1q := dot1ql.(*layers.Dot1Q)
		priority = dot1q.Priority
		dropEligible = dot1q.DropEligible
	}

	if vpv.PppoeIa {
		// Maintain the session MAC as learnt MAC, since MAC is required for deletion of PPPoE session
		if msgType == layers.PPPoECodePADI || msgType == layers.PPPoECodePADR {
			if !util.MacAddrsMatch(vpv.MacAddr, eth.SrcMAC) {
				expectedPort := va.GetMacInPortMap(eth.SrcMAC)
				if expectedPort != "" && expectedPort != vpv.Port {
					logger.Errorw(ctx, "mac-learnt-from-different-port-ignoring-pppoe-message",
						log.Fields{"MsgType": msgType, "ExpectedPort": expectedPort, "ReceivedPort": vpv.Port, "LearntMacAdrr": vpv.MacAddr, "NewMacAdrr": eth.SrcMAC.String()})
					return
				}
			}
			vpv.SetMacAddr(cntx, eth.SrcMAC)
		}

		switch pppoe.Code {
		case layers.PPPoECodePADI:
			vpv.SetPppoeIaState(PppoeIaStatePADI)
		case layers.PPPoECodePADR:
			vpv.SetPppoeIaState(PppoeIaStatePADR)
		}
		vpv.WriteToDb(cntx)
	}

	buff := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	cTagType := layers.EthernetTypePPPoEDiscovery
	outerVlan, innerVlan := vpv.GetNniVlans()
	logger.Debugw(ctx, "Vnet Vlans", log.Fields{"Svlan": outerVlan, "Cvlan": innerVlan})
	eth.EthernetType = vpv.SVlanTpid

	var pktLayers []gopacket.SerializableLayer
	pktLayers = append(pktLayers, eth)

	var qVlans []of.VlanType
	var qVlanLayers []gopacket.SerializableLayer

	if vpv.AllowTransparent {
		nxtLayer := layers.EthernetTypeDot1Q
		if vlans := GetVlans(pkt); len(vlans) > 1 {
			qVlans = vlans[1:]
			logger.Debugw(ctx, "Q Vlans", log.Fields{"Vlan List": qVlans})
			cTagType = layers.EthernetTypeDot1Q
		}
		for i, qVlan := range qVlans {
			vlan := uint16(qVlan)
			if i == (len(qVlans) - 1) {
				nxtLayer = layers.EthernetTypePPPoEDiscovery
			}
			qdot1q := &layers.Dot1Q{Priority: priority, VLANIdentifier: vlan, DropEligible: dropEligible, Type: nxtLayer}
			qVlanLayers = append(qVlanLayers, qdot1q)
		}
	}

	switch vpv.VlanControl {
	case ONUCVlanOLTSVlan,
		OLTCVlanOLTSVlan:
		sdot1q := &layers.Dot1Q{Priority: priority, VLANIdentifier: outerVlan, DropEligible: dropEligible, Type: layers.EthernetTypeDot1Q}
		pktLayers = append(pktLayers, sdot1q)
		cdot1q := &layers.Dot1Q{Priority: priority, VLANIdentifier: innerVlan, DropEligible: dropEligible, Type: cTagType}
		pktLayers = append(pktLayers, cdot1q)
	case ONUCVlan,
		OLTSVlan,
		None:
		cdot1q := &layers.Dot1Q{Priority: priority, VLANIdentifier: outerVlan, DropEligible: dropEligible, Type: cTagType}
		pktLayers = append(pktLayers, cdot1q)
	default:
		logger.Errorw(ctx, "Invalid Vlan Control Option", log.Fields{"Value": vpv.VlanControl})
		return
	}

	pktLayers = append(pktLayers, qVlanLayers...)
	pktLayers = append(pktLayers, pppoe)
	logger.Debugw(ctx, "Layers Count", log.Fields{"Count": len(pktLayers)})
	if err := gopacket.SerializeMultiLayers(buff, opts, pktLayers); err != nil {
		return
	}

	// Now the packet constructed is output towards the switch to be emitted on
	// the NNI port
	if err := cntlr.GetController().PacketOutReq(device, outport, port, buff.Bytes(), false); err != nil {
		logger.Warnw(ctx, "PacketOutReq Failed", log.Fields{"Device": device, "Error": err})
	}
}

// ProcessPPPoEIaPacket to process Pppoeia packet
func (va *VoltApplication) ProcessPPPoEIaPacket(cntx context.Context, device string, port string, pkt gopacket.Packet) {
	logger.Infow(ctx, "Processing PPPoEIa packet", log.Fields{"Device": device, "Port": port})
	// Make some error checks before proceeding
	pppoel := pkt.Layer(layers.LayerTypePPPoE)
	if pppoel == nil {
		return
	}
	_, ok := pppoel.(*layers.PPPoE)
	if !ok {
		return
	}

	// Let us assess the direction of the packet. We can do so by the port
	// which is more reliable or do by the PPPoE code which is less reliable
	isUs := true
	if nni, _ := GetApplication().GetNniPort(device); nni == port {
		isUs = false
	}

	// This is a valid PPPoE packet and can be processed
	if isUs {
		// This is treated as an upstream packet in the VOLT application
		// as VOLT serves access subscribers who use DHCP to acquire IP
		// address and these packets go upstream to the network
		va.ProcessUsPppoeIaPacket(cntx, device, port, pkt)
	} else {
		// This is a downstream packet
		va.ProcessDsPppoeIaPacket(cntx, device, port, pkt)
	}
}

// ProcessPPPoEPacket to process Pppoe packet
func (va *VoltApplication) ProcessPPPoEPacket(device string, port string, pkt gopacket.Packet) {
	logger.Debugw(ctx, "Processing PPPoE packet", log.Fields{"Device": device, "Port": port})
	dpt := NewPppoeIaPacketTask(pkt, device, port)
	va.pppoeTasks.AddTask(dpt)
}

// pppoeIaNws : The DHCP relay application is maintained within the structures below
var pppoeIaNws *PppoeIaNetworks

func init() {
	pppoeIaNws = NewPppoeIaNetworks()
	RegisterPacketHandler(PPPOE, ProcessPPPoEPacket)
}

// ProcessPPPoEPacket : CallBack function registered with application to handle PPPoE packetIn
func ProcessPPPoEPacket(cntx context.Context, device string, port string, pkt gopacket.Packet) {
	GetApplication().ProcessPPPoEPacket(device, port, pkt)
}

// PppoeIaPacketTask : Task to add or delete flows of a service
type PppoeIaPacketTask struct {
	ctx       context.Context
	pkt       gopacket.Packet
	device    string
	port      string
	timestamp string
	taskID    uint8
}

// NewPppoeIaPacketTask constructor for PppoeIaPacketTask
func NewPppoeIaPacketTask(pkt gopacket.Packet, dev string, port string) *PppoeIaPacketTask {
	logger.Debugw(ctx, "New PPPoEIa packet", log.Fields{"Device": dev, "Port": port})
	var dpt PppoeIaPacketTask
	dpt.pkt = pkt
	dpt.device = dev
	dpt.port = port
	dpt.timestamp = (time.Now()).Format(time.RFC3339Nano)
	return &dpt
}

// Name to return name for PppoeIaPacketTask
func (dpt *PppoeIaPacketTask) Name() string {
	return "DHCP Packet Task"
}

// TaskID to return task id for PppoeIaPacketTask
func (dpt *PppoeIaPacketTask) TaskID() uint8 {
	return dpt.taskID
}

// Timestamp to return timestamp for PppoeIaPacketTask
func (dpt *PppoeIaPacketTask) Timestamp() string {
	return dpt.timestamp
}

// Stop to stop the PppoeIaPacketTask
func (dpt *PppoeIaPacketTask) Stop() {
}

// Start to start PppoeIaPacketTask
func (dpt *PppoeIaPacketTask) Start(ctx context.Context, taskID uint8) error {
	logger.Debugw(ctx, "Start PPPoEIa task", log.Fields{"TaskID": taskID})
	dpt.taskID = taskID
	dpt.ctx = ctx
	GetApplication().ProcessPPPoEIaPacket(ctx, dpt.device, dpt.port, dpt.pkt)
	return nil
}
