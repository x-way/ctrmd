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
	nflog "github.com/florianl/go-nflog/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	ctprint "github.com/x-way/iptables-tracer/pkg/ctprint"
	"github.com/x-way/pktdump"
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *metricsSocket != "" {
		startMetricsServer(ctx, logger, *metricsSocket)
	}

	logger.Info("Opening conntrack socket")
	nfct, err := conntrack.Open(&conntrack.Config{})
	if err != nil {
		log.Fatal(logger.Err(fmt.Sprintf("Could not open conntrack socket: %v\n", err)))
	}
	defer nfct.Close()

	config := nflog.Config{
		Group:       uint16(*nflogGroup),
		Copymode:    nflog.CopyPacket,
		Flags:       nflog.FlagConntrack,
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

	fn := func(m nflog.Attribute) int {
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
		if m.Ct != nil {
			ctBytes = *m.Ct
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
		if m.Payload != nil {
			payloadBytes = *m.Payload
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
			logger.Warning("No NFLOG payload found, ignoring packet\n")
			if *debug {
				fmt.Println("No NFLOG payload found, ignoring packet")
			}
			errorCounter.WithLabelValues(familyStr, protoStr, ctinfoStr, "no_payload").Inc()
			return 0
		}

		ctInfo := ^uint32(0)
		if m.Mark != nil {
			fwMark = *m.Mark
		}
		if m.InDev != nil {
			iif = GetIfaceName(*m.InDev)
		}
		if m.OutDev != nil {
			oif = GetIfaceName(*m.OutDev)
		}
		if m.CtInfo != nil {
			ctInfo = *m.CtInfo
			ctinfoStr = fmt.Sprintf("0x%x", ctInfo)
		}
		if len(attrs) > 0 {
			logger.Info(fmt.Sprintf("Deleting CT entry: family: %v attrs: %v\n", ctFamily, attrs))
			logger.Info(fmt.Sprintf(" Packet: %s\n", formatPkt(ctFamily, time.Now(), fwMark, iif, oif, payloadBytes, ctBytes, ctInfo)))
			if *debug {
				fmt.Printf("Deleting CT entry: family: %v attrs: %v\n", ctFamily, attrs)
				fmt.Printf(" Packet: %s\n", formatPkt(ctFamily, time.Now(), fwMark, iif, oif, payloadBytes, ctBytes, ctInfo))
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
			logger.Warning("List of extracted CT attributes is empty, ignoring packet\n")
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

func formatPkt(ctFamily conntrack.CtFamily, ts time.Time, fwMark uint32, iif, oif string, payload, ct []byte, ctInfo uint32) string {
	var output string
	packetStr := ""
	if ctFamily == unix.AF_INET {
		packetStr = pktdump.Format(gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default))
	} else {
		packetStr = pktdump.Format(gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.Default))
	}
	ctStr := fmt.Sprintf(" %s 0x%08x", ctprint.InfoString(ctInfo), ctprint.GetCtMark(ct))
	fmtStr := "%s 0x%08x%s %s  [In:%s Out:%s]"
	output = fmt.Sprintf(fmtStr, ts.Format("15:04:05.000000"), fwMark, ctStr, packetStr, iif, oif)
	return output
}

func familyProto(ctFamily conntrack.CtFamily, attrs []conntrack.ConnAttr) (family, proto string) {
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

// GetIfaceName takes a network interface index and returns the corresponding name
func GetIfaceName(index uint32) string {
	var iface *net.Interface
	var err error
	if iface, err = net.InterfaceByIndex(int(index)); err != nil {
		return ""
	}
	return iface.Name
}

func startMetricsServer(ctx context.Context, logger *syslog.Writer, socket string) {
	logger.Info(fmt.Sprintf("Opening metrics socket %s", socket))
	if *debug {
		fmt.Printf("Opening metrics socket %s\n", socket)
	}
	unixListener, err := net.Listen("unix", socket)
	if err != nil {
		logger.Err(fmt.Sprintf("Could not create metrics socket: %s", err))
		return
	}
	metricsServer := &http.Server{
		Handler: promhttp.Handler(),
	}
	go func() {
		if err := metricsServer.Serve(unixListener); err != nil && err != http.ErrServerClosed {
			logger.Err(fmt.Sprintf("Metrics server failed: %s", err))
		}
		unixListener.Close()
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			logger.Err(fmt.Sprintf("Could not gracefully shutdown the metrics server: %s", err))
		}
	}()
}
