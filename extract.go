package main

import (
	"encoding/binary"
	"fmt"

	conntrack "github.com/florianl/go-conntrack"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

func addIPv6IPs(pkt gopacket.Packet) (attrs []conntrack.ConnAttr) {
	ipLayer := pkt.Layer(layers.LayerTypeIPv6)
	if ipv6, ok := ipLayer.(*layers.IPv6); ok {
		attrs = []conntrack.ConnAttr{
			{Type: conntrack.AttrOrigIPv6Src, Data: ipv6.SrcIP},
			{Type: conntrack.AttrOrigIPv6Dst, Data: ipv6.DstIP},
		}
	}
	return
}

func addIPv4IPs(pkt gopacket.Packet) (attrs []conntrack.ConnAttr) {
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipv4, ok := ipLayer.(*layers.IPv4); ok {
		attrs = []conntrack.ConnAttr{
			{Type: conntrack.AttrOrigIPv4Src, Data: ipv4.SrcIP},
			{Type: conntrack.AttrOrigIPv4Dst, Data: ipv4.DstIP},
		}
	}
	return
}

func addL4Ports(attrs []conntrack.ConnAttr, srcPort, dstPort uint16, proto byte) []conntrack.ConnAttr {
	srcBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(srcBytes, srcPort)
	dstBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(dstBytes, dstPort)
	return append(attrs, []conntrack.ConnAttr{
		{Type: conntrack.AttrOrigL4Proto, Data: []byte{proto}},
		{Type: conntrack.AttrOrigPortSrc, Data: srcBytes},
		{Type: conntrack.AttrOrigPortDst, Data: dstBytes},
	}...)
}

func extractCtAttrsFromCt(data []byte) (family conntrack.CtFamily, attrs []conntrack.ConnAttr, err error) {
	var conn conntrack.Conn
	if conn, err = conntrack.ParseAttributes(data); err != nil {
		return
	}

	// extract family
	if data, ok := conn[conntrack.AttrOrigL3Proto]; ok {
		family = conntrack.CtFamily(data[0])
	} else {
		err = fmt.Errorf("error decoding CT attributes from NFLOG, no AttrOrigL3Proto found")
		return
	}

	// mandatory attrs to copy
	for _, attr := range []conntrack.ConnAttrType{
		conntrack.AttrOrigIPv4Src,
		conntrack.AttrOrigIPv4Dst,
		conntrack.AttrOrigL4Proto,
	} {
		if data, ok := conn[attr]; ok {
			attrs = append(attrs, conntrack.ConnAttr{Type: attr, Data: data})
		} else {
			err = fmt.Errorf("error decoding CT attributes from NFLOG, mandatory attribute 0x%x not found", attr)
			return
		}
	}

	// optional attrs to copy
	for _, attr := range []conntrack.ConnAttrType{
		conntrack.AttrOrigPortSrc,
		conntrack.AttrOrigPortDst,
		conntrack.AttrIcmpType,
		conntrack.AttrIcmpCode,
		conntrack.AttrIcmpID,
	} {
		if data, ok := conn[attr]; ok {
			// xxx: ugly hack, not sure where exactly the problem is originated, but we do not get the proper/correct IcmpType from the NFLOG CT info, thus this heuristic to force the type to ICMP echo request when it was ICMP echo reply
			if family == unix.AF_INET && attr == conntrack.AttrIcmpType && data[0] == 0 {
				data = []byte{8}
			}
			attrs = append(attrs, conntrack.ConnAttr{Type: attr, Data: data})
		}
	}

	return
}

func extractCtAttrsFromPayload(data []byte) (family conntrack.CtFamily, attrs []conntrack.ConnAttr, err error) {
	version := (data)[0] >> 4
	if version == 4 {
		family = conntrack.CtIPv4

		pkt := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.NoCopy)
		attrs = append(attrs, addIPv4IPs(pkt)...)

		if icmpLayer := pkt.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {

			icmp, _ := icmpLayer.(*layers.ICMPv4)
			typeCode := icmp.TypeCode
			icmpType := typeCode.Type()
			icmpCode := typeCode.Code()

			if icmpType != 8 && icmpCode != 0 {
				err = fmt.Errorf("ignoring non-echo-request ICMP packets")
				return
			}

			idBytes := make([]byte, 2)
			binary.BigEndian.PutUint16(idBytes, icmp.Id)
			attrs = append(attrs, []conntrack.ConnAttr{
				{Type: conntrack.AttrOrigL4Proto, Data: []byte{1}},
				{Type: conntrack.AttrIcmpType, Data: []byte{icmpType}},
				{Type: conntrack.AttrIcmpCode, Data: []byte{icmpCode}},
				{Type: conntrack.AttrIcmpID, Data: idBytes},
			}...)

			return
		}
		if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			attrs = addL4Ports(attrs, uint16(udp.SrcPort), uint16(udp.DstPort), 17)
			return
		}
		if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			attrs = addL4Ports(attrs, uint16(tcp.SrcPort), uint16(tcp.DstPort), 6)
			return
		}

		err = fmt.Errorf("could not decode IPv4 packet")
	} else if version == 6 {
		family = conntrack.CtIPv6

		pkt := gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.NoCopy)
		attrs = append(attrs, addIPv6IPs(pkt)...)

		if icmp6Layer := pkt.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {

			icmp6, _ := icmp6Layer.(*layers.ICMPv6)
			typeCode := icmp6.TypeCode
			icmpType := typeCode.Type()
			icmpCode := typeCode.Code()

			if icmpType != 128 && icmpCode != 0 {
				err = fmt.Errorf("ignoring non-echo-request ICMPv6 packets")
				return
			}

			if echoLayer := pkt.Layer(layers.LayerTypeICMPv6Echo); echoLayer != nil {

				echo, _ := echoLayer.(*layers.ICMPv6Echo)

				idBytes := make([]byte, 2)
				binary.BigEndian.PutUint16(idBytes, echo.Identifier)
				attrs = append(attrs, []conntrack.ConnAttr{
					{Type: conntrack.AttrOrigL4Proto, Data: []byte{58}},
					{Type: conntrack.AttrIcmpv6Type, Data: []byte{icmpType}},
					{Type: conntrack.AttrIcmpv6Code, Data: []byte{icmpCode}},
					{Type: conntrack.AttrIcmpv6ID, Data: idBytes},
				}...)
				return
			}
			err = fmt.Errorf("could not decode ICMPv6 packet")
			return
		}
		if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			attrs = addL4Ports(attrs, uint16(udp.SrcPort), uint16(udp.DstPort), 17)
			return
		}
		if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			attrs = addL4Ports(attrs, uint16(tcp.SrcPort), uint16(tcp.DstPort), 6)
			return
		}

		err = fmt.Errorf("could not decode IPv6 packet")
	} else {
		err = fmt.Errorf("could not decode packet (non-IPv4/IPv6)")
	}
	return
}
