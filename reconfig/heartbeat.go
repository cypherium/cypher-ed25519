package reconfig

import (
	"fmt"
	"net"
	"time"

	"github.com/cypherium/cypherBFT/log"
	"github.com/cypherium/cypherBFT/params"
	"github.com/cypherium/cypherBFT/reconfig/bftview"
)

type heartBeat struct {
	conn      *net.UDPConn
	isRunning bool
	ackMap    map[string]time.Time
}

func Heartbeat_New() *heartBeat {
	s := new(heartBeat)
	s.ackMap = make(map[string]time.Time)
	return s
}

func (s *heartBeat) Start() {
	sPort := "9801"
	udpAddr, err := net.ResolveUDPAddr("udp4", ":"+sPort)
	if err != nil {
		log.Error("Heartbeat_start", "Fatal error ", err.Error())
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Error("Heartbeat_start", "Fatal error ", err.Error())
	}
	s.conn = conn

	go s.handleClientHeartbeats(conn)
	s.isRunning = true
	go s.heartBeat_Loop(params.HeatBeatTimeout)
}

func (s *heartBeat) Stop() {
	s.isRunning = false
	s.conn.Close()
}

func (s *heartBeat) SendHeartbeat(address string) {

	udpAddr, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		log.Error("SendHeartbeat", "Fatal error ", err)
		return
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Error("SendHeartbeat", "Fatal error ", err)
		return
	}

	_, err = conn.Write([]byte("HEARTBEAT"))
	if err != nil {
		log.Error("SendHeartbeat", "Fatal error ", err)
	}

	var buf [1024]byte
	for {
		n, err := conn.Read(buf[0:])
		if err != nil {
			log.Error("SendHeartbeat", "Fatal error ", err.Error())
		}
		s.ackMap[GetIP(address)] = time.Now()
		fmt.Println(string(buf[0:n]))
	}
}

func (s *heartBeat) heartBeat_Loop(heatBeatTimeout time.Duration) {
	for s.isRunning {
		if bftview.IamMember() < 0 {
			return
		}
		now := time.Now()
		mb := bftview.GetCurrentMember()
		for _, node := range mb.List {
			if node.IsSelf() {
				continue
			}
			ip := GetIP(node.Address)
			tm, ok := s.ackMap[ip]
			if ok && now.Sub(tm) > heatBeatTimeout {
				s.SendHeartbeat(ip)
				log.Debug("sendHeartBeatMsg", "ip", ip, "tm", time.Now())
			}
			continue
		}
		time.Sleep(200)
	}
}

func (s *heartBeat) handleClientHeartbeats(conn *net.UDPConn) {

	var buf [1024]byte

	for s.isRunning {
		n, addr, err := conn.ReadFromUDP(buf[0:])
		if err != nil {
			log.Error("ReadFromUDP", "Error: Received bad UDP packet\n")
		} else if string(buf[0:n]) != "ping" {
			log.Error("ReadFromUDP", "Error: Received packet without a heatbeat message", string(buf[0:n]))
		} else {
			id := addr.String()
			log.Error("ReadFromUDP", "add", id)
			s.ackMap[GetIP(id)] = time.Now()
		}
	}
}

func GetIP(addr string) string {
	ip := net.ParseIP(addr)
	return ip.String()
}
