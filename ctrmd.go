package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"time"

	conntrack "github.com/florianl/go-conntrack"
	nflog "github.com/florianl/go-nflog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	ctprint "github.com/x-way/iptables-tracer/pkg/ctprint"
	format "github.com/x-way/iptables-tracer/pkg/format"
	"golang.org/x/sys/unix"
)

var (
	nflogGroup    = flag.Int("g", 666, "NFLOG group to listen on")
	debug         = flag.Bool("d", false, "debug output")
	metricsSocket = flag.String("m", "", "path of UNIX socket to use for exposing prometheus metrics")
)

var (
	errorCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ctrmd_errors_total",
			Help: "The total number of errors",
		},
		[]string{"family", "protocol", "ctinfo", "type"},
	)
	deleteCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ctrmd_deletions_total",
			Help: "The total number of deleted conntrack entries",
		},
		[]string{"family", "protocol", "ctinfo"},
	)
)

func init() {
	prometheus.MustRegister(errorCounter)
	prometheus.MustRegister(deleteCounter)
}

func main() {
	logger, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "ctrmd")
	if err != nil {
		log.Fatal("Could not create logger: ", err)
	}
	flag.Parse()

	if *metricsSocket != "" {
		logger.Info(fmt.Sprintf("Opening metrics socket %s", *metricsSocket))
		if *debug {
			fmt.Printf("Opening metrics socket %s\n", *metricsSocket)
		}
		unixListener, err := net.Listen("unix", *metricsSocket)
		if err != nil {
			log.Fatal("Could not create metrics socket: ", err)
		}
		defer unixListener.Close()
		metricsServer := &http.Server{
			Handler: promhttp.Handler(),
		}
		go func() {
			if err := metricsServer.Serve(unixListener); err != nil {
				log.Fatal("Metrics server failed: ", err)
			}
		}()
	}

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

	fn := func(a nflog.Attribute) int {
		var ctFamily conntrack.CtFamily
		var attrs []conntrack.ConnAttr
		var err error
		var ctBytes []byte
		var payloadBytes []byte
		var fwMark uint32
		var iif string
		var oif string
		familyStr := "unknown"
		protoStr := "0"
		ctinfoStr := "0x0"
		if a.Ct != nil {
			ctBytes = *a.Ct
			if ctFamily, attrs, err = extractCtAttrsFromCt(ctBytes); err != nil {
				logger.Warning(fmt.Sprintf("Could not extract CT attrs from CT info: %v\n", err))
				if *debug {
					fmt.Printf("Could not extract CT attrs from CT info: %v\n", err)
				}
				errorCounter.WithLabelValues(familyStr, protoStr, ctinfoStr, "ctinfo_extract").Inc()
				return 0
			}
			familyStr, protoStr = familyProto(ctFamily, attrs)
		} else {
			if *debug {
				fmt.Println("No NFLOG CT info found, decoding information from payload")
			}
		}
		if a.Payload != nil {
			payloadBytes = *a.Payload
			if len(attrs) == 0 {
				if ctFamily, attrs, err = extractCtAttrsFromPayload(payloadBytes); err != nil {
					logger.Warning(fmt.Sprintf("Could not extract CT attrs from packet payload: %v\n", err))
					if *debug {
						fmt.Printf("Could not extract CT attrs from CT packet payload: %v\n", err)
					}
					errorCounter.WithLabelValues(familyStr, protoStr, ctinfoStr, "payload_extract").Inc()
					return 0
				}
				familyStr, protoStr = familyProto(ctFamily, attrs)
			}
		} else {
			logger.Warning(fmt.Sprintf("No NFLOG payload found, ignoring packet\n"))
			if *debug {
				fmt.Println("No NFLOG payload found, ignoring packet")
			}
			errorCounter.WithLabelValues(familyStr, protoStr, ctinfoStr, "no_payload").Inc()
			return 0
		}

		var ctInfo = ^uint32(0)
		if a.Mark != nil {
			fwMark = *a.Mark
		}
		if a.InDev != nil {
			iif = format.GetIfaceName(*a.InDev)
		}
		if a.OutDev != nil {
			oif = format.GetIfaceName(*a.OutDev)
		}
		if a.Ct != nil {
			ctBytes = *a.Ct
		}
		if a.CtInfo != nil {
			ctInfo = *a.CtInfo
			ctinfoStr = fmt.Sprintf("0x%x", ctInfo)
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
				errorCounter.WithLabelValues(familyStr, protoStr, ctinfoStr, "delete").Inc()
			} else {
				deleteCounter.WithLabelValues(familyStr, protoStr, ctinfoStr).Inc()
			}
		} else {
			logger.Warning(fmt.Sprintf("List of extracted CT attributes is empty, ignoring packet\n"))
			if *debug {
				fmt.Println("List of extracted CT attributes is empty, ignoring packet")
			}
			errorCounter.WithLabelValues(familyStr, protoStr, ctinfoStr, "no_ctattrs").Inc()
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

func familyProto(ctFamily conntrack.CtFamily, attrs []conntrack.ConnAttr) (family string, proto string) {
	if ctFamily == unix.AF_INET {
		family = "inet"
	} else {
		family = "inet6"
	}
	proto = "0"
	for _, attr := range attrs {
		if attr.Type == conntrack.AttrOrigL4Proto && len(attr.Data) > 0 {
			proto = fmt.Sprintf("%d", attr.Data[0])
		}
	}
	return
}
