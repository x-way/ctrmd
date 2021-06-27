package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"time"

	conntrack "github.com/florianl/go-conntrack"
	nflog "github.com/florianl/go-nflog/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/netlink"
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
	syslogger, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "ctrmd")
	if err != nil {
		log.Fatal("Could not create syslog logger: ", err)
	}
	logger := log.New(syslogger, "", log.LstdFlags)
	flag.Parse()

	if *debug {
		logger.SetOutput(os.Stdout)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if *metricsSocket != "" {
		startMetricsServer(ctx, logger, *metricsSocket)
	}

	logger.Print("Opening conntrack socket")
	nfct, err := conntrack.Open(&conntrack.Config{})
	if err != nil {
		logger.Fatalf("Could not open conntrack socket: %v", err)
	}
	defer nfct.Close()

	config := nflog.Config{
		Group:       uint16(*nflogGroup),
		Copymode:    nflog.CopyPacket,
		Flags:       nflog.FlagConntrack,
		ReadTimeout: 30 * time.Second,
		Logger:      logger,
	}
	logger.Printf("Opening NFLOG socket for group %d", *nflogGroup)
	nfl, err := nflog.Open(&config)
	if err != nil {
		logger.Fatalf("Could not open nflog socket: %v", err)
	}
	defer nfl.Close()

	fn := func(m nflog.Attribute) int {
		var ctFamily conntrack.Family
		var con conntrack.Con
		var err error
		var ctBytes []byte
		var payloadBytes []byte
		var fwMark uint32
		var iif string
		var oif string
		familyStr := "unknown"
		protoStr := "0"
		ctinfoStr := "0x0"
		ctInfo := ^uint32(0)
		if m.CtInfo != nil {
			ctInfo = *m.CtInfo
			ctinfoStr = fmt.Sprintf("0x%x", ctInfo)
		}
		if m.HwProtocol != nil {
			switch *m.HwProtocol {
			case unix.ETH_P_IP:
				ctFamily = conntrack.IPv4
				familyStr = "inet"
			case unix.ETH_P_IPV6:
				ctFamily = conntrack.IPv6
				familyStr = "inet6"
			}
		}
		if m.Ct != nil {
			ctBytes = *m.Ct
			if con, err = conntrack.ParseAttributes(logger, ctBytes); err != nil {
				logger.Printf("Could not extract Con from CT info: %v", err)
				errorCounter.WithLabelValues(familyStr, protoStr, ctinfoStr, "ctinfo_extract").Inc()
				return 0
			}
		} else {
			if *debug {
				logger.Print("No NFLOG CT info found, decoding information from payload")
			}
		}
		if m.Payload != nil {
			payloadBytes = *m.Payload
			if con.Origin == nil {
				if con, err = extractConFromPayload(payloadBytes); err != nil {
					logger.Printf("Could not extract CT attrs from packet payload: %v", err)
					errorCounter.WithLabelValues(familyStr, protoStr, ctinfoStr, "payload_extract").Inc()
					return 0
				}
			}
		} else {
			logger.Print("No NFLOG payload found, ignoring packet")
			errorCounter.WithLabelValues(familyStr, protoStr, ctinfoStr, "no_payload").Inc()
			return 0
		}
		if m.Mark != nil {
			fwMark = *m.Mark
		}
		if m.InDev != nil {
			iif = GetIfaceName(*m.InDev)
		}
		if m.OutDev != nil {
			oif = GetIfaceName(*m.OutDev)
		}
		if con.Origin != nil {
			if con.Origin.Proto != nil && con.Origin.Proto.Number != nil {
				protoStr = fmt.Sprintf("%d", *con.Origin.Proto.Number)
			}
			var ctEntry string
			if ctEntry, err = ctprint.Format(ctBytes); err != nil {
				logger.Printf("Could not format ctBytes: %s", err)
			}
			logger.Printf("Deleting CT entry: %s", ctEntry)
			if *debug {
				logger.Printf("  Packet: %s", formatPkt(ctFamily, time.Now(), fwMark, iif, oif, payloadBytes, ctBytes, ctInfo))
			}
			if err = nfct.Delete(conntrack.Conntrack, ctFamily, con); err != nil {
				logger.Printf("conntrack Delete failed: %v", err)
				errorCounter.WithLabelValues(familyStr, protoStr, ctinfoStr, "delete").Inc()
			} else {
				deleteCounter.WithLabelValues(familyStr, protoStr, ctinfoStr).Inc()
			}
		} else {
			logger.Print("List of extracted CT attributes is empty, ignoring packet")
			errorCounter.WithLabelValues(familyStr, protoStr, ctinfoStr, "no_ctattrs").Inc()
		}

		return 0
	}
	errorFn := func(err error) int {
		if opError, ok := err.(*netlink.OpError); ok {
			if opError.Timeout() || opError.Temporary() {
				return 0
			}
		}
		logger.Printf("Could not receive message: %v\n", err)
		return 1
	}
	logger.Print("Registering nflog callback")
	if err := nfl.RegisterWithErrorFunc(ctx, fn, errorFn); err != nil {
		logger.Fatalf("Could not register nflog callback: %v", err)
	}

	<-ctx.Done()
	logger.Print("Terminating")
}

func formatPkt(ctFamily conntrack.Family, ts time.Time, fwMark uint32, iif, oif string, payload, ct []byte, ctInfo uint32) string {
	var output string
	packetStr := ""
	if ctFamily == unix.AF_INET {
		packetStr = pktdump.Format(gopacket.NewPacket(payload, layers.LayerTypeIPv4, gopacket.Default))
	} else {
		packetStr = pktdump.Format(gopacket.NewPacket(payload, layers.LayerTypeIPv6, gopacket.Default))
	}
	ctStr := fmt.Sprintf(" %s 0x%08x", ctprint.InfoString(ctInfo), ctprint.GetCtMark(ct))
	fmtStr := "0x%08x%s %s  [In:%s Out:%s]"
	output = fmt.Sprintf(fmtStr, fwMark, ctStr, packetStr, iif, oif)
	return output
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

func startMetricsServer(ctx context.Context, logger *log.Logger, socket string) {
	logger.Printf("Opening metrics socket %s", socket)
	unixListener, err := net.Listen("unix", socket)
	if err != nil {
		logger.Printf("Could not create metrics socket: %s", err)
		return
	}
	metricsServer := &http.Server{
		Handler: promhttp.Handler(),
	}
	go func() {
		if err := metricsServer.Serve(unixListener); err != nil && err != http.ErrServerClosed {
			logger.Printf("Metrics server failed: %s", err)
		}
		unixListener.Close()
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			logger.Printf("Could not gracefully shutdown the metrics server: %s", err)
		}
	}()
}
