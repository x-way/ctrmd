package main

import (
	"encoding/binary"
	"fmt"

	conntrack "github.com/florianl/go-conntrack"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

func addUDP(udp *layers.UDP) []conntrack.ConnAttr {
	srcBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(srcBytes, uint16(udp.SrcPort))
	dstBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(dstBytes, uint16(udp.DstPort))
	return []conntrack.ConnAttr{
		{Type: conntrack.AttrOrigL4Proto, Data: []byte{17}},
		{Type: conntrack.AttrOrigPortSrc, Data: srcBytes},
		{Type: conntrack.AttrOrigPortDst, Data: dstBytes},
	}
}

func addTCP(tcp *layers.TCP) []conntrack.ConnAttr {
	srcBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(srcBytes, uint16(tcp.SrcPort))
	dstBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(dstBytes, uint16(tcp.DstPort))
	return []conntrack.ConnAttr{
		{Type: conntrack.AttrOrigL4Proto, Data: []byte{6}},
		{Type: conntrack.AttrOrigPortSrc, Data: srcBytes},
		{Type: conntrack.AttrOrigPortDst, Data: dstBytes},
	}
}

func extractCtAttrs(data []byte) (family conntrack.CtFamily, attrs []conntrack.ConnAttr, err error) {
	var version = (data)[0] >> 4
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
				err = fmt.Errorf("Ignoring non-echo-request ICMP packets")
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
			attrs = append(attrs, addUDP(udp)...)
			return
		}
		if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			attrs = append(attrs, addTCP(tcp)...)
			return
		}

		err = fmt.Errorf("Could not decode IPv4 packet")
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
				err = fmt.Errorf("Ignoring non-echo-request ICMPv6 packets")
				return
			}

			if echoLayer := pkt.Layer(layers.LayerTypeICMPv6Echo); echoLayer != nil {

				echo, _ := echoLayer.(*layers.ICMPv6Echo)

				idBytes := make([]byte, 2)
				binary.BigEndian.PutUint16(idBytes, echo.Identifier)
				attrs = append(attrs, []conntrack.ConnAttr{
					{Type: conntrack.AttrOrigL4Proto, Data: []byte{58}},
					{Type: conntrack.AttrIcmpType, Data: []byte{icmpType}},
					{Type: conntrack.AttrIcmpCode, Data: []byte{icmpCode}},
					{Type: conntrack.AttrIcmpID, Data: idBytes},
				}...)
				return
			}
			err = fmt.Errorf("Could not decode ICMPv6 packet")
			return
		}
		if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			attrs = append(attrs, addUDP(udp)...)
			return
		}
		if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			attrs = append(attrs, addTCP(tcp)...)
			return
		}

		err = fmt.Errorf("Could not decode IPv6 packet")
	} else {
		err = fmt.Errorf("Could not decode packet (non-IPv4/IPv6)")
	}
	return
}
