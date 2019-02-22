package main

import (
	"context"
	"fmt"

	conntrack "github.com/florianl/go-conntrack"
	nflog "github.com/florianl/go-nflog"
)

func main() {
	nfct, err := conntrack.Open()
	if err != nil {
		fmt.Printf("Could not open conntrack socket: %v\n", err)
		return
	}
	defer nfct.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := nflog.Config{
		Group:    666,
		Copymode: nflog.NfUlnlCopyPacket,
	}
	nfl, err := nflog.Open(&config)
	if err != nil {
		fmt.Printf("Could not open nflog socket: %v\n", err)
		return
	}
	defer nfl.Close()

	fn := func(m nflog.Msg) int {
		if err, ctFamily, attrs := extractCtAttrs(m[nflog.AttrPayload].([]byte)); err != nil {
			fmt.Printf("Could not extract CT attrs from packet: %v\n", err)
		} else {
			//fmt.Printf("extracted: err: %v family: %v attrs: %v\n", err, ctFamily, attrs)
			if err = nfct.Delete(conntrack.Ct, ctFamily, attrs); err != nil {
				fmt.Printf("conntrack Delete failed: %v\n", err)
			}
		}

		return 0
	}
	if err := nfl.Register(ctx, fn); err != nil {
		fmt.Printf("Could not open nflog socket: %v\n", err)
		return
	}

	<-ctx.Done()
}
