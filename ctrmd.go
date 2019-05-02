package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"time"

	conntrack "github.com/florianl/go-conntrack"
	nflog "github.com/florianl/go-nflog"
	ctprint "github.com/x-way/iptables-tracer/pkg/ctprint"
	format "github.com/x-way/iptables-tracer/pkg/format"
)

var nflogGroup = flag.Int("g", 666, "NFLOG group to listen on")
var debug = flag.Bool("d", false, "debug output")

func main() {
	logger, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "ctrmd")
	if err != nil {
		log.Fatal("Could not create logger: ", err)
	}
	flag.Parse()

	logger.Info("Opening conntrack socket")
	nfct, err := conntrack.Open(&conntrack.Config{})
	if err != nil {
		log.Fatal(logger.Err(fmt.Sprintf("Could not open conntrack socket: %v\n", err)))
	}
	defer nfct.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := nflog.Config{
		Group:       uint16(*nflogGroup),
		Copymode:    nflog.NfUlnlCopyPacket,
		Flags:       nflog.NfUlnlCfgFConntrack,
		ReadTimeout: 30 * time.Second,
	}
	logger.Info(fmt.Sprintf("Opening NFLOG socket for group %d", *nflogGroup))
	if *debug {
		fmt.Printf("Opening NFLOG socket for group %d\n", *nflogGroup)
	}
	nfl, err := nflog.Open(&config)
	if err != nil {
		log.Fatal(logger.Err(fmt.Sprintf("Could not open nflog socket: %v\n", err)))
	}
	defer nfl.Close()

	fn := func(m nflog.Msg) int {
		var ctFamily conntrack.CtFamily
		var attrs []conntrack.ConnAttr
		var err error
		var ct interface{}
		var payload interface{}
		var ctBytes []byte
		var payloadBytes []byte
		var ok bool
		var fwMark uint32
		var iif string
		var oif string
		if ct, ok = m[nflog.AttrCt]; ok {
			ctBytes = ct.([]byte)
			if ctFamily, attrs, err = extractCtAttrsFromCt(ctBytes); err != nil {
				logger.Warning(fmt.Sprintf("Could not extract CT attrs from CT info: %v\n", err))
				if *debug {
					fmt.Printf("Could not extract CT attrs from CT info: %v\n", err)
				}
				return 0
			}
		} else {
			if *debug {
				fmt.Println("No NFLOG CT info found, decoding information from payload")
			}
		}
		if payload, ok = m[nflog.AttrPayload]; ok {
			payloadBytes = payload.([]byte)
			if len(attrs) == 0 {
				if ctFamily, attrs, err = extractCtAttrsFromPayload(payloadBytes); err != nil {
					logger.Warning(fmt.Sprintf("Could not extract CT attrs from packet payload: %v\n", err))
					if *debug {
						fmt.Printf("Could not extract CT attrs from CT info: %v\n", err)
					}
					return 0
				}
			}
		} else {
			logger.Warning(fmt.Sprintf("No NFLOG payload found, ignoring packet\n"))
			if *debug {
				fmt.Println("No NFLOG payload found, ignoring packet")
			}
			return 0
		}

		var ctInfo = ^uint32(0)
		if mark, found := m[nflog.AttrMark]; found {
			fwMark = mark.(uint32)
		}
		if iifIx, found := m[nflog.AttrIfindexIndev]; found {
			iif = format.GetIfaceName(iifIx.(uint32))
		}
		if oifIx, found := m[nflog.AttrIfindexOutdev]; found {
			oif = format.GetIfaceName(oifIx.(uint32))
		}
		if ct, found := m[nflog.AttrCt]; found {
			ctBytes = ct.([]byte)
		}
		if cti, found := m[nflog.AttrCtInfo]; found {
			ctInfo = cti.(uint32)
		}
		if len(attrs) > 0 {
			logger.Info(fmt.Sprintf("Deleting CT entry: family: %v attrs: %v\n", ctFamily, attrs))
			logger.Info(fmt.Sprintf(" Packet: %s\n", formatPkt(false, time.Now(), fwMark, iif, oif, payloadBytes, ctBytes, ctInfo)))
			if *debug {
				fmt.Printf("Deleting CT entry: family: %v attrs: %v\n", ctFamily, attrs)
				fmt.Printf(" Packet: %s\n", formatPkt(false, time.Now(), fwMark, iif, oif, payloadBytes, ctBytes, ctInfo))
				ctprint.Print(ctBytes)
			}
			if err = nfct.Delete(conntrack.Ct, ctFamily, attrs); err != nil {
				logger.Warning(fmt.Sprintf("conntrack Delete failed: %v\n", err))
				if *debug {
					fmt.Printf("conntrack Delete failed: %v\n", err)
				}
			}
		} else {
			logger.Warning(fmt.Sprintf("List of extracted CT attributes is empty, ignoring packet\n"))
			if *debug {
				fmt.Println("List of extracted CT attributes is empty, ignoring packet")
			}
		}

		return 0
	}
	logger.Info("Registering nflog callback")
	if err := nfl.Register(ctx, fn); err != nil {
		log.Fatal(logger.Err(fmt.Sprintf("Could not register nflog callback: %v\n", err)))
	}

	<-ctx.Done()
	logger.Info("Terminating")
}

func formatPkt(ip6tables bool, ts time.Time, fwMark uint32, iif, oif string, payload []byte, ct []byte, ctInfo uint32) string {
	var output string
	packetStr := format.Packet(payload, ip6tables)
	ctStr := fmt.Sprintf(" %s 0x%08x", ctprint.InfoString(ctInfo), ctprint.GetCtMark(ct))
	fmtStr := "%s 0x%08x%s %s  [In:%s Out:%s]"
	output = fmt.Sprintf(fmtStr, ts.Format("15:04:05.000000"), fwMark, ctStr, packetStr, iif, oif)
	return output
}
