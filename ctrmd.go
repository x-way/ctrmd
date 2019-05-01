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
)

var nflogGroup = flag.Int("g", 666, "NFLOG group to listen on")

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
		ReadTimeout: 30 * time.Second,
	}
	logger.Info(fmt.Sprintf("Opening NFLOG socket for group %d", *nflogGroup))
	nfl, err := nflog.Open(&config)
	if err != nil {
		log.Fatal(logger.Err(fmt.Sprintf("Could not open nflog socket: %v\n", err)))
	}
	defer nfl.Close()

	fn := func(m nflog.Msg) int {
		if ctFamily, attrs, err := extractCtAttrs(m[nflog.AttrPayload].([]byte)); err != nil {
			logger.Warning(fmt.Sprintf("Could not extract CT attrs from packet: %v\n", err))
		} else {
			//fmt.Printf("extracted: err: %v family: %v attrs: %v\n", err, ctFamily, attrs)
			if err = nfct.Delete(conntrack.Ct, ctFamily, attrs); err != nil {
				logger.Warning(fmt.Sprintf("conntrack Delete failed: %v\n", err))
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
