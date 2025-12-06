package main

import (
	"fmt"
	"log"

	"github.com/HeadLikeAHole/vpn/tun"
)

func main() {
	dev, err := tun.New("tun0")
	if err != nil {
		log.Fatal("err")
	}
	i := 0
	buf := make([]byte, 1024)
	log.Printf("TUN name: %s\n", dev.Name())
	for {
		n, err := dev.Read(buf)
		if err != nil {
			fmt.Println(err)
		}
		i++
		log.Printf("packet # %d received: %x\n", i, buf[:n])
	}
}