// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
//  _  _____                            
// (_)/ ____|                           
//  _| (___   ___  __ _  __ _ _ __ ___  
// | |\___ \ / _ \/ _` |/ _` | '__/ _ \ 
// | |____) |  __/ (_| | (_| | | | (_) | & Hiddify
// |_|_____/ \___|\__, |\__,_|_|  \___/ 
//                __/ |                
//                |___/                 
//
// Package main implements a TURN client with support for TCP
package hiddify

import (
	"fmt"
	"github.com/pion/logging"
	"github.com/pion/turn/v3"
	"log"
	"net"
	"strings"
	"time"
	"math/rand"

)

type Bale struct {
	Host string
	Port uint16
	RelayPort uint16
	Forwarder *Forwarder
}
func ApplyBale(udp_host string,udp_port uint16)(*Bale,error) {
	server:=fmt.Sprintf("%s:%d", udp_host, udp_port)
	host := "meet-turn.bale.sh"
	port := 443
	user := "balelivekit=GygZPHQSgAV7L5L8"

	// Dial TURN Server
	turnServerAddr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("udp", turnServerAddr)
	if err != nil {
		log.Panicf("Failed to connect to TURN server: %s", err)
	}

	cred := strings.SplitN(user, "=", 2)

	// Start a new TURN Client and wrap our net.Conn in a STUNConn
	// This allows us to simulate datagram based communication over a net.Conn
	cfg := &turn.ClientConfig{
		STUNServerAddr: turnServerAddr,
		TURNServerAddr: turnServerAddr,
		Conn:           turn.NewSTUNConn(conn),
		Username:       cred[0],
		Password:       cred[1],
		Realm:          "bale.ai",
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	}

	client, err := turn.NewClient(cfg)
	if err != nil {
		log.Panicf("Failed to create TURN client: %s", err)
	}
	defer client.Close()

	// Start listening on the conn provided.
	err = client.Listen()
	if err != nil {
		log.Panicf("Failed to listen: %s", err)
	}

	// Allocate a relay socket on the TURN server. On success, it
	// will return a net.PacketConn which represents the remote
	// socket.
	relayConn, err := client.Allocate()
	if err != nil {
		log.Panicf("Failed to allocate: %s", err)
	}
	defer func() {
		if closeErr := relayConn.Close(); closeErr != nil {
			log.Fatalf("Failed to close connection: %s", closeErr)
		}
	}()
	rnd_port,err:=getRandomPort(10000,30000)
	if err!=nil{
		log.Panicf("Failed to get random port: %s", err)
		return nil,err
	}
	// The relayConn's local address is actually the transport
	// address assigned on the TURN server.
	log.Printf("relayed-address=%s", relayConn.LocalAddr().String())
	
	// Forward(src, dst). It's asynchronous.
	forwarder, err := Forward(fmt.Sprint("127.0.0.1:%d",rnd_port), server, relayConn, DefaultTimeout)
	if err != nil {
		return nil,err
	}
	forwarder.Run()
	return &Bale{
		Host:udp_host,
		Port:udp_port,
		RelayPort:rnd_port,
		Forwarder:forwarder,
	},nil
}
func (f *Bale) Close() {
	f.Forwarder.Close()
}


func getRandomPort(startPort uint16, endPort uint16) (uint16, error) {
    rand.Seed(time.Now().UnixNano())
    for i := 0; i < 100; i++ {
        port := uint16(rand.Intn(int(endPort-startPort+1))) + startPort
        if portAvailable(port) {
            return port, nil
        }
    }
    return 0, fmt.Errorf("Failed to find an available random port in the range %d-%d", startPort, endPort)
}

func portAvailable(port uint16) bool {
    addr := fmt.Sprintf("127.0.0.1:%d", port)
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        return false
    }
    listener.Close()
    return true
}
