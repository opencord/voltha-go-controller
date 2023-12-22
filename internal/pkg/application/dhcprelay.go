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
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	cntlr "voltha-go-controller/internal/pkg/controller"
	"voltha-go-controller/internal/pkg/of"
	"voltha-go-controller/internal/pkg/util"
	"voltha-go-controller/log"
)

// DhcpRelayState type
type DhcpRelayState uint8

const (
	// DhcpRelayStateNone constant
	DhcpRelayStateNone DhcpRelayState = iota
	// DhcpRelayStateDiscover constant
	DhcpRelayStateDiscover
	// DhcpRelayStateOffer constant
	DhcpRelayStateOffer
	// DhcpRelayStateRequest constant
	DhcpRelayStateRequest
	// DhcpRelayStateAck constant
	DhcpRelayStateAck
	// DhcpRelayStateNAK constant
	DhcpRelayStateNAK
	// DhcpRelayStateRelease constant
	DhcpRelayStateRelease
)

// RemoteIDType represents data type for various RemoteID types
type RemoteIDType string

// List of RemoteID types supported
const (
	MACAddress      RemoteIDType = "MAC_ADDRESS"
	CustomRemotedID RemoteIDType = "Custom"
)

// MaxLenDhcpv6DUID constant
const MaxLenDhcpv6DUID = 130 // 2: DUID-Type, 128: MaxLen of DUID value

// opt82 constant
const opt82 = 82

// Dhcpv6RelayState type
type Dhcpv6RelayState uint8

const (
	// Dhcpv6RelayStateNone constant
	Dhcpv6RelayStateNone Dhcpv6RelayState = iota
	// Dhcpv6RelayStateSolicit constant
	Dhcpv6RelayStateSolicit
	// Dhcpv6RelayStateReply constant
	Dhcpv6RelayStateReply
	// Dhcpv6RelayStateRelease constant
	Dhcpv6RelayStateRelease
)

var (
	// ErrSessionDoNotExist error type
	ErrSessionDoNotExist = errors.New("Session Doesn't Exist")
)

// IDhcpRelaySession to get dhcp session field value
type IDhcpRelaySession interface {
	GetCircuitID() []byte
	GetRemoteID() []byte
	GetNniVlans() (uint16, uint16)
	GetDhcpState() DhcpRelayState
	GetDhcpv6State() Dhcpv6RelayState
	SetDhcpState(DhcpRelayState)
	SetDhcpv6State(Dhcpv6RelayState)
	SetMacAddr(context.Context, net.HardwareAddr)
	DhcpResultInd(context.Context, *layers.DHCPv4)
	Dhcpv6ResultInd(cntx context.Context, ipv6Addr net.IP, leaseTime uint32)
}

// DhcpRelayVnet : The DHCP relay sessions are stored in a map to be retrieved from when
// a response is received from the network. The map uses the VLANs and the
// the MAC address as key to finding the service
// DHCP Relay Virtual Network hosts a set of DHCP relay sessions that belong
// to the network. It supports two VLANs as its identify. If a single VLAN or
// no VLAN is to be used, those two should be passed as 4096 (VlanNone)
type DhcpRelayVnet struct {
	sessions    map[[6]byte]IDhcpRelaySession
	sessionsv6  map[[MaxLenDhcpv6DUID]byte]IDhcpRelaySession
	sessionLock sync.RWMutex
	OuterVlan   uint16
	InnerVlan   uint16
}

// DhcpNetworks hosts different DHCP networks that in turn hold the DHCP
// sessions
type DhcpNetworks struct {
	Networks map[uint32]*DhcpRelayVnet
}

func init() {
	RegisterPacketHandler(DHCPv4, ProcessUDP4Packet)
	RegisterPacketHandler(DHCPv6, ProcessUDP6Packet)
}

// NewDhcpRelayVnet is constructor for a DHCP Relay Virtual network
func NewDhcpRelayVnet(outerVlan uint16, innerVlan uint16) *DhcpRelayVnet {
	var drv DhcpRelayVnet

	drv.OuterVlan = outerVlan
	drv.InnerVlan = innerVlan
	drv.sessions = make(map[[6]byte]IDhcpRelaySession)
	drv.sessionsv6 = make(map[[MaxLenDhcpv6DUID]byte]IDhcpRelaySession)
	return &drv
}

// GetDhcpVnet to add dhcp vnet
func (dn *DhcpNetworks) GetDhcpVnet(outerVlan uint16, innerVlan uint16) *DhcpRelayVnet {
	logger.Debugw(ctx, "Get Dhcp Vnet", log.Fields{"OuterVlan": outerVlan, "InnerVlan": innerVlan})
	comboVlan := uint32(outerVlan)<<16 + uint32(innerVlan)
	drv, ok := dn.Networks[comboVlan]
	if ok {
		return drv
	}
	return nil
}

// AddDhcpVnet to add dhcp vnet
func (dn *DhcpNetworks) AddDhcpVnet(outerVlan uint16, innerVlan uint16) *DhcpRelayVnet {
	logger.Debugw(ctx, "Add Dhcp Vnet", log.Fields{"OuterVlan": outerVlan, "InnerVlan": innerVlan})
	comboVlan := uint32(outerVlan)<<16 + uint32(innerVlan)
	if drv, ok := dn.Networks[comboVlan]; ok {
		return drv
	}
	drv := NewDhcpRelayVnet(outerVlan, innerVlan)
	dn.Networks[comboVlan] = drv
	return drv
}

// NewDhcpNetworks to get new dhcp network
func NewDhcpNetworks() *DhcpNetworks {
	var dn DhcpNetworks
	dn.Networks = make(map[uint32]*DhcpRelayVnet)
	return &dn
}

// AddDhcpSession to add dhcp session
func (dn *DhcpNetworks) AddDhcpSession(pkt gopacket.Packet, session IDhcpRelaySession) error {
	logger.Info(ctx, "Add Dhcp Session")
	var key [6]byte
	ethl := pkt.Layer(layers.LayerTypeEthernet)
	eth, _ := ethl.(*layers.Ethernet)
	addr := eth.SrcMAC
	if len(addr) != 6 {
		logger.Errorw(ctx, "Invalid MAC address", log.Fields{"Addr": addr})
		return errors.New("Invalid MAC address")
	}
	copy(key[:], addr[0:6])

	drv := dn.AddDhcpVnet(session.GetNniVlans())

	drv.sessionLock.Lock()
	drv.sessions[key] = session
	drv.sessionLock.Unlock()
	return nil
}

// DelDhcpSession to delete dhcp session
func (dn *DhcpNetworks) DelDhcpSession(pkt gopacket.Packet, session IDhcpRelaySession) {
	logger.Info(ctx, "Delete Dhcp Session")
	var key [6]byte
	ethl := pkt.Layer(layers.LayerTypeEthernet)
	eth, _ := ethl.(*layers.Ethernet)
	addr := eth.SrcMAC
	if len(addr) != 6 {
		logger.Errorw(ctx, "Invalid MAC address", log.Fields{"Addr": addr})
		return
	}
	copy(key[:], addr[0:6])
	drv := dn.AddDhcpVnet(session.GetNniVlans())
	drv.sessionLock.Lock()
	delete(drv.sessions, key)
	drv.sessionLock.Unlock()
}

// delDhcpSessions to delete dhcp sessions
func delDhcpSessions(addr net.HardwareAddr, outervlan of.VlanType, innervlan of.VlanType, sessionKey [MaxLenDhcpv6DUID]byte) {
	logger.Debugw(ctx, "Delete Dhcp Sessions", log.Fields{"Addr": addr, "OuterVlan": outervlan, "InnerVlan": innervlan})
	var key [6]byte
	if addr == nil || !NonZeroMacAddress(addr) {
		logger.Warnw(ctx, "Invalid MAC address", log.Fields{"Addr": addr, "OuterVlan": outervlan, "InnerVlan": innervlan})
		return
	}
	copy(key[:], addr[0:6])
	drv := dhcpNws.AddDhcpVnet(uint16(outervlan), uint16(innervlan))
	drv.sessionLock.Lock()
	delete(drv.sessions, key)
	delete(drv.sessionsv6, sessionKey)
	drv.sessionLock.Unlock()
	logger.Infow(ctx, "DHCP Sessions deleted", log.Fields{"MAC": addr})
}

// AddDhcp6Session to add dhcpv6 session
func (dn *DhcpNetworks) AddDhcp6Session(key [MaxLenDhcpv6DUID]byte, session IDhcpRelaySession) error {
	outerVlan, innerVlan := session.GetNniVlans()
	logger.Debugw(ctx, "Adding Dhcp6 Session", log.Fields{"outerVlan": outerVlan, "innerVlan": innerVlan, "Addr": key})
	drv := dn.AddDhcpVnet(outerVlan, innerVlan)
	drv.sessionLock.Lock()
	drv.sessionsv6[key] = session
	drv.sessionLock.Unlock()
	return nil
}

// DelDhcp6Session to delete dhcpv6 session
func (dn *DhcpNetworks) DelDhcp6Session(key [MaxLenDhcpv6DUID]byte, session IDhcpRelaySession) {
	outerVlan, innerVlan := session.GetNniVlans()
	logger.Debugw(ctx, "Delete Dhcp6 Session", log.Fields{"OuterVLAN": outerVlan, "InnerVLAN": innerVlan, "Addr": key})
	drv := dn.GetDhcpVnet(outerVlan, innerVlan)
	drv.sessionLock.Lock()
	delete(drv.sessionsv6, key)
	drv.sessionLock.Unlock()
}

// GetDhcpSession to get dhcp session info
func (dn *DhcpNetworks) GetDhcpSession(outerVlan uint16, innerVlan uint16, addr net.HardwareAddr) (IDhcpRelaySession, error) {
	logger.Debugw(ctx, "Get Dhcp Session", log.Fields{"OuterVLAN": outerVlan, "InnerVLAN": innerVlan, "Addr": addr})
	var key [6]byte
	if len(addr) != 6 {
		logger.Errorw(ctx, "Invalid MAC address", log.Fields{"Addr": addr})
		return nil, errors.New("Invalid MAC address")
	}
	copy(key[:], addr[0:6])
	drv := dn.AddDhcpVnet(outerVlan, innerVlan)
	drv.sessionLock.RLock()
	defer drv.sessionLock.RUnlock()
	if session, ok := drv.sessions[key]; ok {
		return session, nil
	}
	return nil, ErrSessionDoNotExist
}

// GetDhcp6Session to get Dhcp6Session
func (dn *DhcpNetworks) GetDhcp6Session(outerVlan uint16, innerVlan uint16, key [MaxLenDhcpv6DUID]byte) (IDhcpRelaySession, error) {
	logger.Debugw(ctx, "Locating Session", log.Fields{"OuterVlan": outerVlan, "InnerVlan": innerVlan, "key": key})

	drv := dn.AddDhcpVnet(outerVlan, innerVlan)
	drv.sessionLock.RLock()
	defer drv.sessionLock.RUnlock()
	if session, ok := drv.sessionsv6[key]; ok {
		return session, nil
	}
	return nil, ErrSessionDoNotExist
}

// GetVlansFromPacket to get vlans from the packet
func GetVlansFromPacket(pkt gopacket.Packet) (innerVlan of.VlanType, outerVlan of.VlanType) {
	logger.Debugw(ctx, "Get Vlans From Packet", log.Fields{"OuterVlan": outerVlan, "InnerVlan": innerVlan})
	vlans := GetVlans(pkt)
	if len(vlans) == 1 {
		outerVlan = vlans[0]
		innerVlan = of.VlanNone
	} else if len(vlans) == 0 {
		innerVlan = of.VlanNone
		outerVlan = of.VlanNone
	} else {
		innerVlan = vlans[1]
		outerVlan = vlans[0]
	}
	return
}

// GetVnetForV4Nni to get vnet for v4 Nni
func GetVnetForV4Nni(dhcp *layers.DHCPv4, cvlan of.VlanType, svlan of.VlanType, pbit uint8) ([]*VoltPortVnet, error) {
	var err error
	var session IDhcpRelaySession
	var vpvList []*VoltPortVnet
	logger.Debugw(ctx, "Get Vnet For V4 Nni: ", log.Fields{"Addr": dhcp.ClientHWAddr})
	session, err = dhcpNws.GetDhcpSession(uint16(svlan), uint16(cvlan), dhcp.ClientHWAddr)

	if session != nil {
		vpv, ok := session.(*VoltPortVnet)
		logger.Infow(ctx, "Session Exist: VPV found", log.Fields{"VPV": vpv})
		if ok {
			vpvList = append(vpvList, vpv)
			return vpvList, nil
		}
	}

	if err == ErrSessionDoNotExist {
		//No DHCP Session found, find matching VPV to send the packet out
		logger.Warn(ctx, "Session Doesnt Exist: Finding matching VPV")
		return GetApplication().GetVpvsForDsPkt(cvlan, svlan, dhcp.ClientHWAddr, pbit)
	}
	return nil, errors.New("The session retrieved of wrong type")
}

// GetVnetForV6Nni to get vnet for v6 Nni
func GetVnetForV6Nni(dhcp *layers.DHCPv6, cvlan of.VlanType, svlan of.VlanType,
	pbit uint8, clientMAC net.HardwareAddr) ([]*VoltPortVnet, net.HardwareAddr, error) {
	var err error
	var session IDhcpRelaySession
	var vpvList []*VoltPortVnet
	logger.Info(ctx, "Get Vnet For V6 Nni")

	var sessionKey [MaxLenDhcpv6DUID]byte

	clientDuid, decodedDuid := getDhcpv6ClientDUID(dhcp)
	if clientDuid == nil || decodedDuid == nil {
		copy(sessionKey[:], clientMAC)
	} else {
		copy(sessionKey[:], clientDuid[0:])
		if decodedDuid.Type == layers.DHCPv6DUIDTypeLLT || decodedDuid.Type == layers.DHCPv6DUIDTypeLL {
			clientMAC = decodedDuid.LinkLayerAddress
		}
	}
	session, err = dhcpNws.GetDhcp6Session(uint16(svlan), uint16(cvlan), sessionKey)
	if session != nil {
		vpv, ok := session.(*VoltPortVnet)
		logger.Infow(ctx, "Session Exist: VPV found", log.Fields{"VPV": vpv})
		if ok {
			vpvList = append(vpvList, vpv)
			return vpvList, clientMAC, nil
		}
	}

	if err == ErrSessionDoNotExist {
		//No DHCP Session found, find matching VPV to send the packet out
		logger.Info(ctx, "Session Doesnt Exist: Finding matching VPV")
		vpvList, err := GetApplication().GetVpvsForDsPkt(cvlan, svlan, clientMAC, pbit)
		return vpvList, clientMAC, err
	}
	return nil, clientMAC, errors.New("The session retrieved of wrong type")
}

/*
// getDhcpv4ClientMacAddr to get mac address for dhcpv4 client
func getDhcpv4ClientMacAddr(pkt gopacket.Packet) net.HardwareAddr {
	dhcp := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	logger.Infow(ctx, "Mac Obtained v4: ", log.Fields{"Addr": dhcp.ClientHWAddr})
	return dhcp.ClientHWAddr
}

// getDhcpv6ClientMacAddr to get mac address for dhcpv6 client
func getDhcpv6ClientMacAddr(dhcpv6 *layers.DHCPv6) net.HardwareAddr {
	var cID layers.DHCPv6Option
	for _, option := range dhcpv6.Options {
		if option.Code == layers.DHCPv6OptClientID {
			cID = option
		}
	}
	duid := &layers.DHCPv6DUID{}

	//If cID is not found, DecodeFromBytes() returns error on empty cID
	if err := duid.DecodeFromBytes(cID.Data); err == nil {
		logger.Infow(ctx, "Mac Obtained v6: ", log.Fields{"Addr": duid.LinkLayerAddress, "Option": cID.String()})
		return duid.LinkLayerAddress
	}
	return nil
}*/

// getDhcpv6ClientDUID to get Dhcpv6 client DUID
func getDhcpv6ClientDUID(dhcpv6 *layers.DHCPv6) ([]byte, *layers.DHCPv6DUID) {
	logger.Info(ctx, "Get Dhcp v6 Client DUID")
	for _, option := range dhcpv6.Options {
		logger.Debugw(ctx, "DHCPv6 Options", log.Fields{"option": option.Code})
		if option.Code == layers.DHCPv6OptClientID {
			duid := &layers.DHCPv6DUID{}
			err := duid.DecodeFromBytes(option.Data)
			if err == nil {
				logger.Infow(ctx, "ClientIdentifier", log.Fields{"DUID": duid, "Option": option.String()})
				duidLen := len(option.Data)
				if duidLen > 130 {
					duidLen = 130
				}
				return option.Data[0:duidLen], duid
			}
			logger.Warnw(ctx, "Client DUID decode failed", log.Fields{"error": err})
			break
		}
	}
	logger.Warn(ctx, "Client DUID is not present in the packet")
	return nil, nil
}

// AddDhcpv4Option82 : DHCPv4 packet operations
// Addition of DHCP Option 82 which codes circuit-id and remote-id
// into the packet. This happens as the request is relayed to the
// DHCP servers on the NNI
func AddDhcpv4Option82(svc *VoltService, rID []byte, dhcpv4 *layers.DHCPv4) {
	logger.Debugw(ctx, "Add Dhcp v4 Option82", log.Fields{"Addr": dhcpv4.ClientHWAddr})
	//NOTE : both cID and rID should not be empty if this function is called
	cID := svc.GetCircuitID()
	var data []byte
	if len(cID) != 0 {
		data = append(data, 0x01)
		data = append(data, byte(len(cID)))
		data = append(data, cID...)
	}
	if len(rID) != 0 {
		data = append(data, 0x02)
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

	option := layers.NewDHCPOption(82, data)
	dhcpv4.Options = append(dhcpv4.Options, option)
}

// DelOption82 : Deletion of option 82 from the packet received on the NNI interface.
// Once the packet is received, the option 82 is stripped off and the
// packet is forwarded towards access
func DelOption82(dhcpv4 *layers.DHCPv4) {
	logger.Debugw(ctx, "Delete Dhcp v4 Option82", log.Fields{"Addr": dhcpv4.ClientHWAddr})
	for index, option := range dhcpv4.Options {
		if option.Type == opt82 {
			dhcpv4.Options = append(dhcpv4.Options[0:index], dhcpv4.Options[index+1:]...)
			return
		}
	}
}

// DhcpMsgType returns the DHCP message type from the packet
func DhcpMsgType(dhcp *layers.DHCPv4) layers.DHCPMsgType {
	logger.Debugw(ctx, "Dhcp msg type", log.Fields{"Addr": dhcp.ClientHWAddr})
	for _, option := range dhcp.Options {
		if option.Type == layers.DHCPOptMessageType {
			return layers.DHCPMsgType(option.Data[0])
		}
	}
	return layers.DHCPMsgTypeUnspecified
}

// GetIpv4Addr returns the IP address in the DHCP reply
func GetIpv4Addr(dhcp *layers.DHCPv4) (net.IP, int64) {
	logger.Debugw(ctx, "Get Dhcp ipv4 addr", log.Fields{"Addr": dhcp.ClientHWAddr})
	var leaseTime uint32
	for _, opt := range dhcp.Options {
		if opt.Type == layers.DHCPOptLeaseTime {
			leaseTime = GetIPv4LeaseTime(opt)
		}
	}
	return dhcp.YourClientIP, int64(leaseTime)
}

// GetIPv4LeaseTime get ip lease time
func GetIPv4LeaseTime(opt layers.DHCPOption) uint32 {
	return uint32(opt.Data[0])<<24 | uint32(opt.Data[1])<<16 | uint32(opt.Data[2])<<8 | uint32(opt.Data[3])
}

// GetIpv6Addr returns the IPv6 address in the DHCPv6 reply
func GetIpv6Addr(dhcp6 *layers.DHCPv6) (net.IP, uint32) {
	logger.Debugw(ctx, "Get Dhcp ipv6 addr", log.Fields{"Addr": dhcp6.MsgType})
	var ipv6Addr net.IP
	var leaseTime uint32

	//Check for IANA allocation, if not present, then look for IAPD allocation
	if dhcp6.MsgType == layers.DHCPv6MsgTypeReply {
		ipv6Addr, leaseTime = GetIANAAddress(dhcp6)
		if ipv6Addr == nil {
			ipv6Addr, leaseTime = GetIAPDAddress(dhcp6)
		}
	}
	return ipv6Addr, leaseTime
}

// GetIANAAddress returns the IPv6 address in the DHCPv6 reply
func GetIANAAddress(dhcp6 *layers.DHCPv6) (net.IP, uint32) {
	logger.Debugw(ctx, "Get Dhcp IANA addr", log.Fields{"Addr": dhcp6.MsgType})
	var ipv6Addr net.IP
	var leaseTime uint32
	if dhcp6.MsgType == layers.DHCPv6MsgTypeReply {
		for _, o := range dhcp6.Options {
			if o.Code == layers.DHCPv6OptIANA {
				iana := &layers.DHCPv6IANA{}
				err := iana.DecodeFromBytes(o.Data)
				if err == nil {
					ipv6Addr = iana.IA.IPv6Addr
					leaseTime = iana.IA.ValidLifeTime
					logger.Debugw(ctx, "IPv6 Allocated", log.Fields{"IANA IPv6": ipv6Addr})
					return ipv6Addr, leaseTime
				}
				logger.Warnw(ctx, "Decode of IANA Failed", log.Fields{"Reason": err.Error()})
				break
			}
		}
	}
	return nil, 0
}

// GetIAPDAddress returns the IPv6 address in the DHCPv6 reply
func GetIAPDAddress(dhcp6 *layers.DHCPv6) (net.IP, uint32) {
	logger.Debugw(ctx, "Get Dhcp IAPD addr", log.Fields{"Addr": dhcp6.MsgType})
	var ipv6Addr net.IP
	var leaseTime uint32
	if dhcp6.MsgType == layers.DHCPv6MsgTypeReply {
		for _, o := range dhcp6.Options {
			if o.Code == layers.DHCPv6OptIAPD {
				iapd := &layers.DHCPv6IAPD{}
				if err := iapd.DecodeFromBytes(o.Data); err == nil {
					ipv6Addr = iapd.PD.Prefix
					leaseTime = iapd.PD.ValidLifeTime
					logger.Debugw(ctx, "IPv6 Allocated", log.Fields{"IAPD IPv6": ipv6Addr})
					break
				} else {
					logger.Warnw(ctx, "Decode of IAPD Failed", log.Fields{"Reason": err.Error()})
					break
				}
			}
		}
	}
	return ipv6Addr, leaseTime
}

// ProcessDsDhcpv4Packet : DHCPv4 packet processor functions
// This function processes DS DHCP packet received on the NNI port.
// The services are attached to the access ports. Thus, the DHCP
// session is derived from the list of DHCP sessions stored in the
// common map. The key for retrieval includes the VLAN tags in the
// the packet and the MAC address of the client.
func (va *VoltApplication) ProcessDsDhcpv4Packet(cntx context.Context, device string, port string, pkt gopacket.Packet) {
	// Retrieve the layers to build the outgoing packet. It is not
	// possible to add/remove layers to the existing packet and thus
	// the lyayers are extracted to build the outgoing packet
	eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	dhcp4 := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	msgType := DhcpMsgType(dhcp4)

	// Need to locate the service from the packet alone as the services
	// are not attached to NNI port. The service is stored on DHCP relay
	// application
	logger.Infow(ctx, "Processing Southbound DS DHCPv4 packet", log.Fields{"Port": port, "Type": msgType})

	// Retrieve the priority and drop eligible flags from the
	// packet received
	var priority uint8
	var dsPbit uint8
	var dropEligible bool
	dot1ql := pkt.Layer(layers.LayerTypeDot1Q)
	if dot1ql != nil {
		dot1q := dot1ql.(*layers.Dot1Q)
		priority = dot1q.Priority
		dropEligible = dot1q.DropEligible
	}

	pktInnerlan, pktOuterlan := GetVlansFromPacket(pkt)
	vpvList, _ := GetVnetForV4Nni(dhcp4, pktInnerlan, pktOuterlan, priority)
	if len(vpvList) == 0 {
		logger.Warn(ctx, "VNET couldn't be found for NNI")
		return
	}

	// The DHCP option 82, if it exists is removed from the packet
	DelOption82(dhcp4)
	ipAddr, leaseTime := GetIpv4Addr(dhcp4)

	for _, vpv := range vpvList {
		dsPbit = vpv.GetRemarkedPriority(priority)
		// Raise DHCP ACK/NCK indication
		if vpv.DhcpRelay {
			// Inform dhcp response information to dhcp server handler
			dhcpResponseReceived(uint16(vpv.CVlan), uint16(vpv.SVlan))
			// Process the Ack/Nack to track to state of the IP layer of the connection
			if msgType == layers.DHCPMsgTypeAck || msgType == layers.DHCPMsgTypeNak {
				// Install DS HSIA flows after DHCP ACK.
				if msgType == layers.DHCPMsgTypeAck {
					// Voltha will push US and DS HSIA flow on receivng the DS HSIA
					// flow installation request, VGC to update US HSIA flow with leanrt MAC.
					// separate go rotuine is spawned to avoid drop of ACK packet
					// as HSIA flows will be deleted if new MAC is learnt.
					go vpv.SetMacAddr(cntx, dhcp4.ClientHWAddr)
				}
				vpv.DhcpResultInd(cntx, dhcp4)
			}
			raiseDHCPv4Indication(msgType, vpv, dhcp4.ClientHWAddr, ipAddr, dsPbit, device, leaseTime)
		}

		// Create the outgoing bufer and set the checksum in the packet
		buff := gopacket.NewSerializeBuffer()
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			logger.Errorw(ctx, "Error in setting checksum", log.Fields{"Reason": err.Error()})
			return
		}
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		cTagType := layers.EthernetTypeIPv4
		eth.EthernetType = layers.EthernetTypeDot1Q

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
					nxtLayer = layers.EthernetTypeIPv4
				}
				qdot1q := &layers.Dot1Q{Priority: priority, VLANIdentifier: vlan, DropEligible: dropEligible, Type: nxtLayer}
				qVlanLayers = append(qVlanLayers, qdot1q)
			}
		}
		switch vpv.VlanControl {
		case ONUCVlanOLTSVlan:
			cdot1q := &layers.Dot1Q{Priority: dsPbit, VLANIdentifier: uint16(vpv.CVlan), DropEligible: dropEligible, Type: cTagType}
			pktLayers = append(pktLayers, cdot1q)
		case ONUCVlan,
			None:
			sdot1q := &layers.Dot1Q{Priority: dsPbit, VLANIdentifier: uint16(vpv.SVlan), DropEligible: dropEligible, Type: cTagType}
			pktLayers = append(pktLayers, sdot1q)
		case OLTCVlanOLTSVlan,
			OLTSVlan:
			udot1q := &layers.Dot1Q{Priority: dsPbit, VLANIdentifier: uint16(vpv.UniVlan), DropEligible: dropEligible, Type: cTagType}
			pktLayers = append(pktLayers, udot1q)
		default:
			logger.Warnw(ctx, "Invalid Vlan Control Option", log.Fields{"Value": vpv.VlanControl})
		}

		pktLayers = append(pktLayers, qVlanLayers...)
		pktLayers = append(pktLayers, ip)
		pktLayers = append(pktLayers, udp)
		pktLayers = append(pktLayers, dhcp4)
		logger.Debugw(ctx, "Layers Count", log.Fields{"Count": len(pktLayers)})
		if err := gopacket.SerializeMultiLayers(buff, opts, pktLayers); err != nil {
			logger.Errorw(ctx, "Packet Serialization Failed", log.Fields{"Reason": err.Error()})
			return
		}

		if err := cntlr.GetController().PacketOutReq(device, vpv.Port, port, buff.Bytes(), false); err != nil {
			logger.Errorw(ctx, "PacketOutReq Failed", log.Fields{"Error": err})
		}
	}
}

// raiseDHCPv4Indication process DHCPv4 packet and raise indication
func raiseDHCPv4Indication(msgType layers.DHCPMsgType, vpv *VoltPortVnet, smac net.HardwareAddr,
	ip net.IP, pktPbit uint8, device string, leaseTime int64) {
	logger.Debugw(ctx, "Processing Dhcpv4 packet", log.Fields{"ethsrcMac": smac.String(),
		"MacLearningInVPV": vpv.MacLearning, "MacConfigured": vpv.MacAddr, "dhcpType": msgType,
		"vlanPriority": pktPbit, "VPVLearntMac": vpv.LearntMacAddr})

	matchServiceAndRaiseInd := func(key, value interface{}) bool {
		// walk through all svcs under vpv and match pbit with packet.
		svc := value.(*VoltService)

		if svc.IsPbitExist(of.PbitType(pktPbit)) {
			logger.Debugw(ctx, "Matching Pbit found in service config", log.Fields{"ServiceName": svc.Name, "Pbit": pktPbit})
			return false
		}
		return true
	}

	switch msgType {
	case layers.DHCPMsgTypeDiscover, layers.DHCPMsgTypeRequest:
		if msgType == layers.DHCPMsgTypeDiscover {
			vpv.SetDhcpState(DhcpRelayStateDiscover)
		} else if msgType == layers.DHCPMsgTypeRequest {
			vpv.SetDhcpState(DhcpRelayStateRequest)
		}
	// Reset learnt mac address in case of DHCPv4 release
	case layers.DHCPMsgTypeRelease:
		vpv.LearntMacAddr, _ = net.ParseMAC("00:00:00:00:00:00")
		vpv.services.Range(matchServiceAndRaiseInd)
		vpv.SetDhcpState(DhcpRelayStateRelease)

	case layers.DHCPMsgTypeAck, layers.DHCPMsgTypeNak:
		vpv.services.Range(matchServiceAndRaiseInd)
		if msgType == layers.DHCPMsgTypeAck {
			vpv.SetDhcpState(DhcpRelayStateAck)
		} else if msgType == layers.DHCPMsgTypeNak {
			vpv.SetDhcpState(DhcpRelayStateNAK)
		}
	case layers.DHCPMsgTypeOffer:
		vpv.SetDhcpState(DhcpRelayStateOffer)
	}
}

// raiseDHCPv6Indication process DHCPv6 packet and raise indication
func raiseDHCPv6Indication(msgType layers.DHCPv6MsgType, vpv *VoltPortVnet,
	smac net.HardwareAddr, ip net.IP, pktPbit uint8, device string, leaseTime uint32) {
	logger.Debugw(ctx, "Processing DHCPv6 packet", log.Fields{"dhcpType": msgType,
		"vlanPriority": pktPbit, "dhcpClientMac": smac.String(),
		"MacLearningInVPV": vpv.MacLearning, "MacConfigured": vpv.MacAddr,
		"VPVLearntMac": vpv.LearntMacAddr})

	matchServiceAndRaiseInd := func(key, value interface{}) bool {
		svc := value.(*VoltService)
		if svc.IsPbitExist(of.PbitType(pktPbit)) {
			logger.Debugw(ctx, "Matching Pbit found in service config", log.Fields{"ServiceName": svc.Name, "Pbit": pktPbit})
			return false
		}
		return true
	}

	switch msgType {
	case layers.DHCPv6MsgTypeSolicit:
		vpv.SetDhcpv6State(Dhcpv6RelayStateSolicit)
	// Reset learnt mac address in case of DHCPv6 release
	case layers.DHCPv6MsgTypeRelease:
		vpv.LearntMacAddr, _ = net.ParseMAC("00:00:00:00:00:00")
		vpv.services.Range(matchServiceAndRaiseInd)
		vpv.SetDhcpv6State(Dhcpv6RelayStateRelease)

	case layers.DHCPv6MsgTypeReply:
		vpv.services.Range(matchServiceAndRaiseInd)
		vpv.SetDhcpv6State(Dhcpv6RelayStateReply)
	}
}

// ProcessUsDhcpv4Packet : The US DHCPv4 packet is identified the DHCP OP in the packet. A request is considered upstream
// and the service associated with the packet is located by the port and VLANs in the packet
func (va *VoltApplication) ProcessUsDhcpv4Packet(cntx context.Context, device string, port string, pkt gopacket.Packet) {
	logger.Infow(ctx, "Processing Southbound US DHCPv4 packet", log.Fields{"Device": device, "Port": port})
	// We received the packet on an access port and the service for the packet can be
	// gotten from the port and the packet
	vpv, svc := va.GetVnetFromPkt(device, port, pkt)
	if vpv == nil {
		logger.Warn(ctx, "VNET couldn't be found from packet")
		return
	}

	outport, _ := va.GetNniPort(device)
	if outport == "" || outport == "0" {
		logger.Errorw(ctx, "NNI Port not found for device. Dropping Packet", log.Fields{"NNI": outport})
		return
	}

	// Extract the layers in the packet to prepare the outgoing packet
	// We use the layers to build the outgoing packet from scratch as
	// the packet received can't be modified to add/remove layers
	eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	dhcp4 := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	msgType := DhcpMsgType(dhcp4)

	// Learn the 8021P values from the packet received
	var priority uint8
	var dropEligible bool
	dot1ql := pkt.Layer(layers.LayerTypeDot1Q)
	if dot1ql != nil {
		dot1q := dot1ql.(*layers.Dot1Q)
		priority = dot1q.Priority
		dropEligible = dot1q.DropEligible
	}
	// If this is the first message in the DHCP sequence, the service
	// is added to the DHCP relay application. The reply packets locate
	// the associated service/session from the relay application.
	if msgType == layers.DHCPMsgTypeDiscover || msgType == layers.DHCPMsgTypeRequest {
		if err := dhcpNws.AddDhcpSession(pkt, vpv); err != nil {
			logger.Errorw(ctx, "Adding dhcp session failed", log.Fields{"Error": err})
		}
	}

	// Raise mac-learnt(DHCP Discover) indication when mac learning is enabled and learnt mac
	// is not same as received mac address. If mac learning disabled, we have mac address in the
	// service configuration. Hence mac learnt indication is not raised
	// Reset learnt mac address in case of DHCP release and raise the indication
	if vpv.DhcpRelay {
		// If this is the first message in the DHCP sequence, the service
		// is added to the DHCP relay application. The reply packets locate
		// the associated service/session from the relay application.
		// DS HSIA flows will be added after DHCP ACK .
		if msgType == layers.DHCPMsgTypeDiscover || msgType == layers.DHCPMsgTypeRequest {
			if !util.MacAddrsMatch(vpv.MacAddr, dhcp4.ClientHWAddr) {
				// MAC is different and relearning is disabled.
				if NonZeroMacAddress(vpv.MacAddr) && vpv.MacLearning == Learn {
					// update learnt mac for debug purpose
					vpv.LearntMacAddr = dhcp4.ClientHWAddr
					vpv.WriteToDb(cntx)
					logger.Warnw(ctx, "Dropping the packet Mac relearn is disabled",
						log.Fields{"vpv.MacAddr": vpv.MacAddr, "LearntMac": dhcp4.ClientHWAddr})
					return
				}
				expectedPort := va.GetMacInPortMap(dhcp4.ClientHWAddr)
				if expectedPort != "" && expectedPort != vpv.Port {
					logger.Errorw(ctx, "mac-learnt-from-different-port-ignoring-dhcp-message", log.Fields{"MsgType": msgType, "ExpectedPort": expectedPort, "ReceivedPort": vpv.Port, "LearntMacAdrr": vpv.MacAddr, "NewMacAdrr": dhcp4.ClientHWAddr.String()})
					return
				}
			}
		}
		raiseDHCPv4Indication(msgType, vpv, dhcp4.ClientHWAddr, vpv.Ipv4Addr, priority, device, 0)

		// Check IsOption82Enabled flag in configuration. if true(enabled), add option82 into dhcpv4 header.
		// Remote id can be custom or mac address.
		// If remote id is custom, then add service will carry the remote id
		// If remote id is mac address, and if mac is configured, then add service will carry the remote id
		// If remote id is mac address, in mac learning case, then mac has to be taken from dhcp packet
		if svc.IsOption82Enabled {
			var remoteID []byte
			if svc.RemoteIDType == string(MACAddress) {
				remoteID = []byte((dhcp4.ClientHWAddr).String())
			} else if svc.RemoteID != nil {
				remoteID = svc.RemoteID
			}
			AddDhcpv4Option82(svc, remoteID, dhcp4)
		}
	}

	buff := gopacket.NewSerializeBuffer()
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		logger.Error(ctx, "Error in setting checksum")
		return
	}
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	cTagType := layers.EthernetTypeIPv4
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
				nxtLayer = layers.EthernetTypeIPv4
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
	}

	pktLayers = append(pktLayers, qVlanLayers...)
	pktLayers = append(pktLayers, ip)
	pktLayers = append(pktLayers, udp)
	pktLayers = append(pktLayers, dhcp4)
	logger.Debugw(ctx, "Layers Count", log.Fields{"Count": len(pktLayers)})
	if err := gopacket.SerializeMultiLayers(buff, opts, pktLayers); err != nil {
		return
	}

	// Now the packet constructed is output towards the switch to be emitted on
	// the NNI port
	if err := cntlr.GetController().PacketOutReq(device, outport, port, buff.Bytes(), false); err != nil {
		logger.Errorw(ctx, "PacketOutReq Failed", log.Fields{"Error": err})
	}
	if vpv.DhcpRelay {
		// Inform dhcp request information to dhcp server handler
		dhcpRequestReceived(uint16(vpv.CVlan), uint16(vpv.SVlan), eth.SrcMAC.String())
	}
}

// ProcessUDP4Packet : CallBack function registered with application to handle DHCP packetIn
func ProcessUDP4Packet(cntx context.Context, device string, port string, pkt gopacket.Packet) {
	GetApplication().ProcessUDP4Packet(cntx, device, port, pkt)
}

// ProcessUDP4Packet : The packet is a UDP packet and currently only DHCP relay application is supported
// We determine the packet direction and process it based on the direction
func (va *VoltApplication) ProcessUDP4Packet(cntx context.Context, device string, port string, pkt gopacket.Packet) {
	// Currently DHCP is the only application supported by the application
	// We check for DHCP before proceeding further. In future, this could be
	// based on registration and the callbacks
	logger.Debugw(ctx, "Process UDP4 Packet", log.Fields{"Device": device, "Port": port})
	dhcpl := pkt.Layer(layers.LayerTypeDHCPv4)
	if dhcpl == nil {
		return
	}
	//logger.Debugw(ctx, "Received Packet In", log.Fields{"Pkt": hex.EncodeToString(pkt.Data())})
	dhcp4 := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	if dhcp4.Operation == layers.DHCPOpRequest {
		// This is treated as an upstream packet in the VOLT application
		// as VOLT serves access subscribers who use DHCP to acquire IP
		// address and these packets go upstream to the network
		va.ProcessUsDhcpv4Packet(cntx, device, port, pkt)
	} else {
		// This is a downstream packet
		va.ProcessDsDhcpv4Packet(cntx, device, port, pkt)
	}
}

// ProcessUDP6Packet : CallBack function registered with application to handle DHCPv6 packetIn
func ProcessUDP6Packet(cntx context.Context, device string, port string, pkt gopacket.Packet) {
	GetApplication().ProcessUDP6Packet(cntx, device, port, pkt)
}

// ProcessUDP6Packet : As a LDRA node, we expect to see only RelayReply from the DHCP server and we always
// pack the received request and send it to the server as a RelayForward message
// We expect to see Solicit, Request in the most normal cases. Before the lease expires
// we should also see Renew. However, we should always pack the US message by adding
// additional option that identifies to the server that the DHCP packet is forwarded
// by an LDRA node.
func (va *VoltApplication) ProcessUDP6Packet(cntx context.Context, device string, port string, pkt gopacket.Packet) []byte {
	logger.Debugw(ctx, "Processing DHCPv6 packet", log.Fields{"Device": device, "Port": port})
	dhcpl := pkt.Layer(layers.LayerTypeDHCPv6)
	if dhcpl == nil {
		return nil
	}
	dhcpv6 := dhcpl.(*layers.DHCPv6)
	switch dhcpv6.MsgType {
	case layers.DHCPv6MsgTypeSolicit, layers.DHCPv6MsgTypeRequest, layers.DHCPv6MsgTypeRenew,
		layers.DHCPv6MsgTypeRelease, layers.DHCPv6MsgTypeRebind, layers.DHCPv6MsgTypeInformationRequest,
		layers.DHCPv6MsgTypeDecline:
		va.ProcessUsDhcpv6Packet(cntx, device, port, pkt)
	case layers.DHCPv6MsgTypeAdvertise, layers.DHCPv6MsgTypeConfirm, layers.DHCPv6MsgTypeReconfigure:
		logger.Warnw(ctx, "SouthBound DHCPv6 DS Messages Expected For a Relay Agent", log.Fields{"Type": dhcpv6.MsgType})
	case layers.DHCPv6MsgTypeRelayForward:
		logger.Warn(ctx, "As the first DHCPv6 Relay Agent, Unexpected Relay Forward")
	case layers.DHCPv6MsgTypeRelayReply:
		// We received a response from the server
		va.ProcessDsDhcpv6Packet(cntx, device, port, pkt)
	}
	return nil
}

// GetRelayReplyBytes to get relay reply bytes
func GetRelayReplyBytes(dhcp6 *layers.DHCPv6) []byte {
	for _, o := range dhcp6.Options {
		logger.Debugw(ctx, "Received Option", log.Fields{"Code": o.Code})
		if o.Code == layers.DHCPv6OptRelayMessage {
			return o.Data
		}
	}
	return nil
}

// BuildRelayFwd to build forward relay
func BuildRelayFwd(paddr net.IP, intfID []byte, remoteID []byte, payload []byte, isOption82Enabled bool, dhcpRelay bool) *layers.DHCPv6 {
	logger.Debugw(ctx, "Build Relay Fwd", log.Fields{"Paddr": paddr, "isOption82Enabled": isOption82Enabled, "dhcpRelay": dhcpRelay})
	dhcp6 := &layers.DHCPv6{MsgType: layers.DHCPv6MsgTypeRelayForward, LinkAddr: net.ParseIP("::"), PeerAddr: []byte(paddr)}
	dhcp6.Options = append(dhcp6.Options, layers.NewDHCPv6Option(layers.DHCPv6OptRelayMessage, payload))
	// Check IsOption82Enabled flag in configuration. if true(enabled), add remoteID and circuitID into dhcpv6 header.
	if dhcpRelay {
		if isOption82Enabled {
			remote := &layers.DHCPv6RemoteId{RemoteId: remoteID}
			if len(remoteID) != 0 {
				dhcp6.Options = append(dhcp6.Options, layers.NewDHCPv6Option(layers.DHCPv6OptRemoteID, remote.Encode()))
			}
			if len(intfID) != 0 {
				intf := &layers.DHCPv6IntfId{Data: intfID}
				dhcp6.Options = append(dhcp6.Options, layers.NewDHCPv6Option(layers.DHCPv6OptInterfaceID, intf.Encode()))
			}
		}
	}
	return dhcp6
}

// nolint: gocyclo
// ProcessUsDhcpv6Packet to rpocess upstream DHCPv6 packet
func (va *VoltApplication) ProcessUsDhcpv6Packet(cntx context.Context, device string, port string, pkt gopacket.Packet) {
	// We received the packet on an access port and the service for the packet can be
	// gotten from the port and the packet
	logger.Infow(ctx, "Processing Southbound US DHCPv6 packet", log.Fields{"Device": device, "Port": port})
	logger.Debugw(ctx, "Packet IN", log.Fields{"Pkt": hex.EncodeToString(pkt.Data())})
	vpv, svc := va.GetVnetFromPkt(device, port, pkt)
	if vpv == nil {
		logger.Warn(ctx, "VNET couldn't be found from packet")
		return
	}

	outport, _ := va.GetNniPort(device)
	if outport == "" || outport == "0" {
		logger.Errorw(ctx, "NNI Port not found for device. Dropping Packet", log.Fields{"NNI": outport})
		return
	}

	// Extract the layers in the packet to prepare the outgoing packet
	// We use the layers to build the outgoing packet from scratch as
	// the packet received can't be modified to add/remove layers
	eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	idhcp6 := pkt.Layer(layers.LayerTypeDHCPv6).(*layers.DHCPv6)

	// Remote id can be custom or mac address.
	// If remote id is custom, then add service will carry the remote id
	// If remote id is mac address, and if mac is configured, then add service will carry the remote id
	// If remote id is mac address, in mac learning case, then mac has to be taken from dhcp packet
	var remoteID []byte
	if svc.RemoteIDType == string(MACAddress) {
		remoteID = []byte((eth.SrcMAC).String())
	} else if svc.RemoteID != nil {
		remoteID = svc.RemoteID
	}
	dhcp6 := BuildRelayFwd(ip.SrcIP, svc.GetCircuitID(), remoteID, udp.Payload, svc.IsOption82Enabled, vpv.DhcpRelay)

	var sourceMac = eth.SrcMAC
	var sessionKey [MaxLenDhcpv6DUID]byte

	clientDuid, decodedDuid := getDhcpv6ClientDUID(idhcp6)
	if clientDuid == nil || decodedDuid == nil {
		copy(sessionKey[:], eth.SrcMAC)
	} else {
		copy(sessionKey[:], clientDuid[0:])
		if decodedDuid.Type == layers.DHCPv6DUIDTypeLLT || decodedDuid.Type == layers.DHCPv6DUIDTypeLL {
			sourceMac = decodedDuid.LinkLayerAddress
		}
	}
	// Learn the 8021P values from the packet received
	var priority uint8
	var dropEligible bool
	dot1ql := pkt.Layer(layers.LayerTypeDot1Q)
	if dot1ql != nil {
		dot1q := dot1ql.(*layers.Dot1Q)
		priority = dot1q.Priority
		dropEligible = dot1q.DropEligible
	}
	if idhcp6.MsgType == layers.DHCPv6MsgTypeSolicit {
		if err := dhcpNws.AddDhcp6Session(sessionKey, vpv); err != nil {
			logger.Errorw(ctx, "Adding dhcpv6 session failed", log.Fields{"Error": err})
		}
		vpv.DHCPv6DUID = sessionKey
	}

	// Raise mac-learnt(DHCPv6MsgTypeSolicit) indication when mac learning is enabled and learnt mac
	// is not same as received mac address. If mac learning disabled, we have mac address in the
	// service configuration. Hence mac learnt indication is not raised
	if vpv.DhcpRelay {
		if idhcp6.MsgType == layers.DHCPv6MsgTypeSolicit {
			if !util.MacAddrsMatch(vpv.MacAddr, sourceMac) {
				// MAC is different and relearning is disabled.
				if NonZeroMacAddress(vpv.MacAddr) && vpv.MacLearning == Learn {
					// update learnt mac for debug purpose
					vpv.LearntMacAddr = sourceMac
					vpv.WriteToDb(cntx)
					logger.Warnw(ctx, "Dropping the packet Mac relearn is disabled",
						log.Fields{"vpv.MacAddr": vpv.MacAddr, "LearntMac": sourceMac})
					return
				}
				expectedPort := va.GetMacInPortMap(sourceMac)
				if expectedPort != "" && expectedPort != vpv.Port {
					logger.Errorw(ctx, "mac-learnt-from-different-port-ignoring-dhcp-message", log.Fields{"MsgType": idhcp6.MsgType, "ExpectedPort": expectedPort, "ReceivedPort": vpv.Port, "LearntMacAdrr": vpv.MacAddr, "NewMacAdrr": sourceMac.String()})
					return
				}
			}
		}
		raiseDHCPv6Indication(idhcp6.MsgType, vpv, sourceMac, vpv.Ipv6Addr, priority, device, 0)
	}

	// Create the buffer and the encode options for the outgoing packet
	buff := gopacket.NewSerializeBuffer()
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		logger.Error(ctx, "Error in setting checksum")
		return
	}
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	cTagType := layers.EthernetTypeIPv6
	outerVlan, innerVlan := vpv.GetNniVlans()
	eth.EthernetType = vpv.SVlanTpid

	var pktLayers []gopacket.SerializableLayer
	pktLayers = append(pktLayers, eth)

	var qVlans []of.VlanType
	var qVlanLayers []gopacket.SerializableLayer

	if vpv.AllowTransparent {
		nxtLayer := layers.EthernetTypeDot1Q
		if vlans := GetVlans(pkt); len(vlans) > 1 {
			qVlans = vlans[1:]
			cTagType = layers.EthernetTypeDot1Q
		}
		for i, qVlan := range qVlans {
			vlan := uint16(qVlan)
			if i == (len(qVlans) - 1) {
				nxtLayer = layers.EthernetTypeIPv6
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
	}

	pktLayers = append(pktLayers, qVlanLayers...)
	pktLayers = append(pktLayers, ip)
	pktLayers = append(pktLayers, udp)
	pktLayers = append(pktLayers, dhcp6)
	logger.Debugw(ctx, "Layers Count", log.Fields{"Count": len(pktLayers)})
	if err := gopacket.SerializeMultiLayers(buff, opts, pktLayers); err != nil {
		return
	}
	// Now the packet constructed is output towards the switch to be emitted on
	// the NNI port
	if err := cntlr.GetController().PacketOutReq(device, outport, port, buff.Bytes(), false); err != nil {
		logger.Errorw(ctx, "PacketOutReq Failed", log.Fields{"Error": err})
	}
	if vpv.DhcpRelay {
		// Inform dhcp request information to dhcp server handler
		dhcpRequestReceived(uint16(vpv.CVlan), uint16(vpv.SVlan), eth.SrcMAC.String())
	}
}

// GetDhcpv6 to get dhcpv6 info
func GetDhcpv6(payload []byte) (*layers.DHCPv6, error) {
	pkt := gopacket.NewPacket(payload, layers.LayerTypeDHCPv6, gopacket.Default)
	if dl := pkt.Layer(layers.LayerTypeDHCPv6); dl != nil {
		if dhcp6, ok := dl.(*layers.DHCPv6); ok {
			return dhcp6, nil
		}
	}
	return nil, errors.New("Failed to decode DHCPv6")
}

// ProcessDsDhcpv6Packet to process downstream dhcpv6 packet
func (va *VoltApplication) ProcessDsDhcpv6Packet(cntx context.Context, device string, port string, pkt gopacket.Packet) {
	logger.Infow(ctx, "Processing Southbound DS DHCPv6 packet", log.Fields{"Port": port})
	logger.Debugw(ctx, "Packet IN", log.Fields{"Pkt": hex.EncodeToString(pkt.Data())})

	// Retrieve the layers to build the outgoing packet. It is not
	// possible to add/remove layers to the existing packet and thus
	// the lyayers are extracted to build the outgoing packet
	// The DHCP layer is handled differently. The Relay-Reply option
	// of DHCP is extracted and is made the UDP payload.
	eth := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	ip := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
	idhcp6 := pkt.Layer(layers.LayerTypeDHCPv6).(*layers.DHCPv6)
	//var dhcp6 *layers.DHCPv6
	var payload []byte
	if payload = GetRelayReplyBytes(idhcp6); payload == nil {
		logger.Warn(ctx, "Didn't Receive RelayMessage IE")
		return
	}

	dhcp6, err := GetDhcpv6(payload)
	if err != nil {
		logger.Warnw(ctx, "DHCPv6 Decode Failed", log.Fields{"Reason": err.Error()})
		return
	}

	// Learn the 8021P values from the packet received
	var priority uint8
	var dsPbit uint8
	var dropEligible bool
	dot1ql := pkt.Layer(layers.LayerTypeDot1Q)
	if dot1ql != nil {
		dot1q := dot1ql.(*layers.Dot1Q)
		priority = dot1q.Priority
		dropEligible = dot1q.DropEligible
	}

	pktInnerlan, pktOuterlan := GetVlansFromPacket(pkt)
	vpvList, clientMac, err := GetVnetForV6Nni(dhcp6, pktInnerlan, pktOuterlan, priority, eth.DstMAC)
	if len(vpvList) == 0 {
		logger.Warnw(ctx, "VNET couldn't be found for NNI", log.Fields{"Reason": err})
		return
	}

	ipv6Addr, leaseTime := GetIpv6Addr(dhcp6)

	for _, vpv := range vpvList {
		dsPbit = vpv.GetRemarkedPriority(priority)
		// Raise DHCPv6 Reply indication
		if vpv.DhcpRelay {
			// Inform dhcp response information to dhcp server handler
			dhcpResponseReceived(uint16(vpv.CVlan), uint16(vpv.SVlan))

			if dhcp6.MsgType == layers.DHCPv6MsgTypeReply && ipv6Addr != nil {
				// separate go rotuine is spawned to avoid drop of ACK packet
				// as HSIA flows will be deleted if new MAC is learnt.
				if len(vpvList) == 1 {
					go vpv.SetMacAddr(cntx, clientMac)
				}
				vpv.Dhcpv6ResultInd(cntx, ipv6Addr, leaseTime)
			}
			raiseDHCPv6Indication(dhcp6.MsgType, vpv, clientMac, ipv6Addr, dsPbit, device, leaseTime)
		}

		//Replace dst Port value to 546
		udp.DstPort = 546
		logger.Infow(ctx, "Packet Out UDP Port..", log.Fields{"UDP": udp, "Port": udp.DstPort})

		// Create the buffer and the encode options for the outgoing packet
		buff := gopacket.NewSerializeBuffer()
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			logger.Error(ctx, "Error in setting checksum")
			return
		}
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		cTagType := layers.EthernetTypeIPv6
		eth.EthernetType = layers.EthernetTypeDot1Q

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
					nxtLayer = layers.EthernetTypeIPv6
				}
				qdot1q := &layers.Dot1Q{Priority: priority, VLANIdentifier: vlan, DropEligible: dropEligible, Type: nxtLayer}
				qVlanLayers = append(qVlanLayers, qdot1q)
			}
		}
		switch vpv.VlanControl {
		case ONUCVlanOLTSVlan:
			cdot1q := &layers.Dot1Q{Priority: dsPbit, VLANIdentifier: uint16(vpv.CVlan), DropEligible: dropEligible, Type: cTagType}
			pktLayers = append(pktLayers, cdot1q)
		case ONUCVlan,
			None:
			sdot1q := &layers.Dot1Q{Priority: dsPbit, VLANIdentifier: uint16(vpv.SVlan), DropEligible: dropEligible, Type: cTagType}
			pktLayers = append(pktLayers, sdot1q)
		case OLTCVlanOLTSVlan,
			OLTSVlan:
			udot1q := &layers.Dot1Q{Priority: dsPbit, VLANIdentifier: uint16(vpv.UniVlan), DropEligible: dropEligible, Type: cTagType}
			pktLayers = append(pktLayers, udot1q)
		default:
			logger.Errorw(ctx, "Invalid Vlan Control Option", log.Fields{"Value": vpv.VlanControl})
		}

		pktLayers = append(pktLayers, qVlanLayers...)
		pktLayers = append(pktLayers, ip)
		pktLayers = append(pktLayers, udp)
		pktLayers = append(pktLayers, dhcp6)
		logger.Debugw(ctx, "Layers Count", log.Fields{"Count": len(pktLayers)})
		if err := gopacket.SerializeMultiLayers(buff, opts, pktLayers); err != nil {
			logger.Errorw(ctx, "Packet Serialization Failed", log.Fields{"Reason": err.Error()})
			return
		}

		if err := cntlr.GetController().PacketOutReq(device, vpv.Port, port, buff.Bytes(), false); err != nil {
			logger.Errorw(ctx, "PacketOutReq Failed", log.Fields{"Reason": err.Error()})
		}
	}
}

// The DHCP relay application is maintained within the structures below
var dhcpNws *DhcpNetworks

func init() {
	dhcpNws = NewDhcpNetworks()
}

type DhcpAllocation struct {
	SubscriberID        string           `json:"subscriberId"`
	ConnectPoint        string           `json:"connectPoint"`
	AllocationTimeStamp time.Time        `json:"allocationTimestamp"`
	MacAddress          net.HardwareAddr `json:"macAddress"`
	CircuitID           []byte           `json:"circuitId"`
	IPAllocated         net.IP           `json:"ipAllocated"`
	State               int              `json:"state"`
	VlanID              int              `json:"vlanId"`
}

// GetAllocations returns DhcpAllocation info for all devices or for a device ID
func (va *VoltApplication) GetAllocations(cntx context.Context, deviceID string) ([]DhcpAllocation, error) {
	logger.Debugw(ctx, "GetAllocations", log.Fields{"DeviceID": deviceID})
	allocations := []DhcpAllocation{}
	for _, drv := range dhcpNws.Networks {
		drv.sessionLock.RLock()
		for _, session := range drv.sessions {
			vpv, ok := session.(*VoltPortVnet)
			if ok {
				var subscriber string
				// return Name of first service
				vpv.services.Range(func(key, value interface{}) bool {
					svc := value.(*VoltService)
					subscriber = svc.Name
					return false
				})
				// If deviceID is not provided, return all allocations
				// If deviceID exists then filter on deviceID
				if len(deviceID) == 0 || deviceID == vpv.Device {
					allocation := DhcpAllocation{
						SubscriberID:        subscriber,
						ConnectPoint:        vpv.Device,
						MacAddress:          vpv.MacAddr,
						State:               int(vpv.RelayState),
						VlanID:              int(vpv.SVlan),
						CircuitID:           vpv.CircuitID,
						IPAllocated:         vpv.Ipv4Addr,
						AllocationTimeStamp: vpv.DhcpExpiryTime,
					}
					logger.Debugw(ctx, "DHCP Allocation found", log.Fields{"DhcpAlloc": allocation})
					allocations = append(allocations, allocation)
				}
			}
		}
		drv.sessionLock.RUnlock()
	}
	return allocations, nil
}

type MacLearnerInfo struct {
	DeviceID   string `json:"deviceId"`
	PortNumber string `json:"portNumber"`
	VlanID     string `json:"vlanId"`
	MacAddress string `json:"macAddress"`
}

func (va *VoltApplication) GetAllMacLearnerInfo() ([]MacLearnerInfo, error) {
	logger.Info(ctx, "GetMacLearnerInfo")
	macLearner := []MacLearnerInfo{}
	for _, drv := range dhcpNws.Networks {
		logger.Debugw(ctx, "drv found", log.Fields{"drv": drv})
		drv.sessionLock.RLock()
		for _, session := range drv.sessions {
			vpv, ok := session.(*VoltPortVnet)
			if ok {
				macLearn := MacLearnerInfo{
					DeviceID:   vpv.Device,
					PortNumber: vpv.Port,
					VlanID:     vpv.SVlan.String(),
					MacAddress: vpv.MacAddr.String(),
				}
				logger.Debugw(ctx, "MacLerner found", log.Fields{"MacLearn": macLearn})
				macLearner = append(macLearner, macLearn)
			}
		}
		drv.sessionLock.RUnlock()
	}
	return macLearner, nil
}

func (va *VoltApplication) GetMacLearnerInfo(cntx context.Context, deviceID, portNumber, vlanID string) (MacLearnerInfo, error) {
	logger.Debugw(ctx, "GetMecLearnerInfo", log.Fields{"DeviceID": deviceID, "PortNumber": portNumber, "VlanID": vlanID})
	macLearn := MacLearnerInfo{}
	for _, drv := range dhcpNws.Networks {
		logger.Debugw(ctx, "drv found", log.Fields{"drv": drv})
		drv.sessionLock.RLock()
		for _, session := range drv.sessions {
			vpv, ok := session.(*VoltPortVnet)
			if ok {
				if deviceID == vpv.Device && portNumber == vpv.Port && vlanID == vpv.SVlan.String() {
					macLearn = MacLearnerInfo{
						DeviceID:   vpv.Device,
						PortNumber: vpv.Port,
						VlanID:     vpv.SVlan.String(),
						MacAddress: vpv.MacAddr.String(),
					}
					logger.Debugw(ctx, "MacLerner found", log.Fields{"MacLearn": macLearn})
				} else if deviceID == vpv.Device && portNumber == vpv.Port && vlanID == "" {
					macLearn = MacLearnerInfo{
						DeviceID:   vpv.Device,
						PortNumber: vpv.Port,
						VlanID:     vpv.SVlan.String(),
						MacAddress: vpv.MacAddr.String(),
					}
					logger.Debugw(ctx, "MacLerner found", log.Fields{"MacLearn": macLearn})
				}
			}
		}
		drv.sessionLock.RUnlock()
	}
	return macLearn, nil
}

func (va *VoltApplication) GetIgnoredPorts() (map[string][]string, error) {
	logger.Info(ctx, "GetIgnoredPorts")
	IgnoredPorts := make(map[string][]string)
	portIgnored := func(key, value interface{}) bool {
		voltDevice := value.(*VoltDevice)
		logger.Debugw(ctx, "Inside GetIgnoredPorts method", log.Fields{"deviceName": voltDevice.Name})
		voltDevice.Ports.Range(func(key, value interface{}) bool {
			port := key.(string)
			logger.Debugw(ctx, "Inside GetIgnoredPorts method", log.Fields{"port": port})
			//Obtain all VPVs associated with the port
			vnets, ok := GetApplication().VnetsByPort.Load(port)
			if !ok {
				return true
			}
			for _, vpv := range vnets.([]*VoltPortVnet) {
				if vpv.MacLearning == MacLearningNone {
					IgnoredPorts[vpv.Device] = append(IgnoredPorts[vpv.Device], vpv.Port)
				}
			}
			logger.Warnw(ctx, "Ignored Port", log.Fields{"Ignored Port": IgnoredPorts})
			return true
		})
		return true
	}
	va.DevicesDisc.Range(portIgnored)
	logger.Debug(ctx, "GetIgnoredPorts completed")
	return IgnoredPorts, nil
}
# [EOF] - delta:force
