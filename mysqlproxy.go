package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"
)

const (
	comQuery  byte   = 3
	clientSSL uint16 = 0x00000800
)

type Config struct {
	ListenAddress string        `toml:"address"`
	MySQLHost     string        `toml:"mysql_host"`
	MySQLUser     string        `toml:"mysql_user"`
	MySQLPassword string        `toml:"mysql_password"`
	Timeout       time.Duration `toml:"timeout"`
}

func NewConfig() *Config {
	return &Config{"127.0.0.1:3307", "127.0.0.1:3306", "", "", time.Second}
}

const (
	serverHandshake = iota
	clientAuth
	established
	stopped
)

type MysqlProxy struct {
	config *Config
	local  net.Conn
	remote net.Conn
	state  int
	cipher []byte
}

func (p *MysqlProxy) Start() {
	defer p.Stop()
	log.Println("start new proxy")
	go p.translate(p.remote, p.local, p.serverFilter)
	p.translate(p.local, p.remote, p.clientFilter)
}

func (p *MysqlProxy) Stop() {
	if p.state != stopped {
		p.state = stopped
		p.remote.Close()
		p.local.Close()
		log.Println("stop proxy")
	}
}

// method to handle handshake package, the data can be modified, returns new size
func (p *MysqlProxy) readHandshake(data []byte, n int) int {
	var b [20]byte
	pos := bytes.IndexByte(data[5:], 0x00)
	if pos != -1 {
		pos += 10 // 5 + 5
		copy(b[:], data[pos:pos+8])
		pos += 9
		serverCaps := binary.LittleEndian.Uint16(data[pos : pos+2])
		// dash ssl flag to prevent using secure connection
		binary.LittleEndian.PutUint16(data[pos:pos+2], serverCaps & ^clientSSL)
		pos += 2 + 1 + 2 + 13
		if n > pos {
			copy(b[8:], data[pos:pos+12])
			p.cipher = b[:]
		} else {
			p.cipher = b[:8]
		}
		p.state = clientAuth
	}
	return n
}

func (p *MysqlProxy) readAuth(data []byte, n int) int {
	if n <= 36 {
		return n
	}

	if len(p.config.MySQLUser) == 0 {
		p.state = established
		return n
	}
	// TODO support old protocol
	pos := bytes.IndexByte(data[36:], 0x00)
	if pos >= 0 {
		pos += 37
		oldScrambleLen := int(data[pos])
		pos++
		posEnd := pos + oldScrambleLen
		scramble := scramblePassword(p.cipher, []byte(p.config.MySQLPassword))
		// the len of scramble should be constant
		copy(data[n:], data[posEnd:n])
		pos = 36
		pos += copy(data[pos:], p.config.MySQLUser)
		data[pos] = 0x00
		pos++
		data[pos] = byte(len(scramble))
		pos++
		pos += copy(data[pos:], scramble)
		copy(data[pos:], data[n:2*n-posEnd])
		n += (pos - posEnd)
		pkgLen := n - 4
		data[0] = byte(pkgLen)
		data[1] = byte(pkgLen >> 8)
		data[2] = byte(pkgLen >> 16)
		p.state = established
	}
	return n
}

func (p *MysqlProxy) readClientPackage(data []byte, n int) int {
	switch data[4] {
	case comQuery:
		log.Printf("query: %s", string(data[5:n]))
	}
	return n
}

func (p *MysqlProxy) serverFilter(data []byte, n int) int {
	switch p.state {
	case serverHandshake:
		n = p.readHandshake(data, n)
	}
	return n
}

func (p *MysqlProxy) clientFilter(data []byte, n int) int {
	switch p.state {
	case clientAuth:
		n = p.readAuth(data, n)
	case established:
		n = p.readClientPackage(data, n)
	}
	return n
}

func (p *MysqlProxy) translate(from, to net.Conn, filter func(data []byte, n int) int) {
	data := make([]byte, 4*1024)
	for {
		n, err := from.Read(data)
		if p.state == stopped {
			log.Println("stop translation")
			return
		}
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			}
			return
		}
		n = filter(data, n)
		_, err = to.Write(data[:n])
		if err != nil {
			if err != io.EOF {
				log.Println(err)
			}
			return
		}
	}
}

func scramblePassword(scramble, password []byte) []byte {
	if len(password) == 0 {
		return nil
	}

	// stage1Hash = SHA1(password)
	crypt := sha1.New()
	crypt.Write(password)
	stage1 := crypt.Sum(nil)

	// scrambleHash = SHA1(scramble + SHA1(stage1Hash))
	// inner Hash
	crypt.Reset()
	crypt.Write(stage1)
	hash := crypt.Sum(nil)

	// outer Hash
	crypt.Reset()
	crypt.Write(scramble)
	crypt.Write(hash)
	scramble = crypt.Sum(nil)

	// token = scrambleHash XOR stage1Hash
	for i := range scramble {
		scramble[i] ^= stage1[i]
	}
	return scramble
}

func proxify(conn net.Conn, config *Config) {
	server, err := net.DialTimeout("tcp", config.MySQLHost, time.Second)
	if err != nil {
		log.Println("Could not dial server")
		log.Println(err)
		conn.Close()
		return
	}
	proxy := MysqlProxy{config, conn, server, serverHandshake, []byte{}}
	proxy.Start()
}

func StartProxy(config *Config) {
	log.Printf("Listening: %v; Proxying %v\n", config.ListenAddress, config.MySQLHost)
	ln, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		log.Fatal(err)
		return
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		log.Println("new connection")
		go proxify(conn, config)
	}
}
