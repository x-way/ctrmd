package main

import (
	"fmt"

	conntrack "github.com/florianl/go-conntrack"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func addIPv6IPTuple(con *conntrack.Con, pkt gopacket.Packet) {
	ipLayer := pkt.Layer(layers.LayerTypeIPv6)
	if ipv6, ok := ipLayer.(*layers.IPv6); ok {
		con.Origin = &conntrack.IPTuple{
			Src: &ipv6.SrcIP,
			Dst: &ipv6.DstIP,
		}
	}
}

func addIPv4IPTuple(con *conntrack.Con, pkt gopacket.Packet) {
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipv4, ok := ipLayer.(*layers.IPv4); ok {
		con.Origin = &conntrack.IPTuple{
			Src: &ipv4.SrcIP,
			Dst: &ipv4.DstIP,
		}
	}
}

func addL4Ports(con *conntrack.Con, srcPort, dstPort uint16, proto uint8) {
	con.Origin.Proto = &conntrack.ProtoTuple{
		Number:  &proto,
		SrcPort: &srcPort,
		DstPort: &dstPort,
	}
}

func extractConFromPayload(data []byte) (conntrack.Con, error) {
	var con conntrack.Con
	version := (data)[0] >> 4
	if version == 4 {
		pkt := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.NoCopy)
		addIPv4IPTuple(&con, pkt)
		if icmpLayer := pkt.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {

			icmp, _ := icmpLayer.(*layers.ICMPv4)
			typeCode := icmp.TypeCode
			icmpType := typeCode.Type()
			icmpCode := typeCode.Code()

			if icmpType != 8 || icmpCode != 0 {
				return nil, fmt.Errorf("ignoring non-echo-request ICMP packets")
			}

			var protoNumber uint8 = 1
			con.Origin.Proto = &conntrack.ProtoTuple{
				Number:   &protoNumber,
				IcmpType: &icmpType,
				IcmpCode: &icmpCode,
				IcmpID:   &icmp.Id,
			}

			return con, nil
		}
		if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			addL4Ports(&con, uint16(udp.SrcPort), uint16(udp.DstPort), 17)
			return con, nil
		}
		if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			addL4Ports(&con, uint16(tcp.SrcPort), uint16(tcp.DstPort), 6)
			return con, nil
		}
		return nil, fmt.Errorf("could not decode IPv4 packet")
	}

	if version == 6 {
		pkt := gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.NoCopy)
		addIPv6IPTuple(&con, pkt)
		if icmp6Layer := pkt.Layer(layers.LayerTypeICMPv6); icmp6Layer != nil {

			icmp6, _ := icmp6Layer.(*layers.ICMPv6)
			typeCode := icmp6.TypeCode
			icmpType := typeCode.Type()
			icmpCode := typeCode.Code()

			if icmpType != 128 || icmpCode != 0 {
				return nil, fmt.Errorf("ignoring non-echo-request ICMPv6 packets")
			}

			if echoLayer := pkt.Layer(layers.LayerTypeICMPv6Echo); echoLayer != nil {

				echo, _ := echoLayer.(*layers.ICMPv6Echo)

				var protoNumber uint8 = 58
				con.Origin.Proto = &conntrack.ProtoTuple{
					Number:     &protoNumber,
					Icmpv6Type: &icmpType,
					Icmpv6Code: &icmpCode,
					Icmpv6ID:   &echo.Identifier,
				}
				return con, nil
			}
			return nil, fmt.Errorf("could not decode ICMPv6 packet")
		}
		if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			addL4Ports(&con, uint16(udp.SrcPort), uint16(udp.DstPort), 17)
			return con, nil
		}
		if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			addL4Ports(&con, uint16(tcp.SrcPort), uint16(tcp.DstPort), 6)
			return con, nil
		}
		return nil, fmt.Errorf("could not decode IPv6 packet")
	}
	return nil, fmt.Errorf("could not decode packet (non-IPv4/IPv6)")
}
