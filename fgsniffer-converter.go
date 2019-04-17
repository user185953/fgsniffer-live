// Copyright 2017 github.com/DirkDuesentrieb
// license that can be found in the LICENSE file.

// a converter for FortiGate session logs to pcap files
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"bytes"
	"time"
)

const (
	globalHeader string = "d4c3b2a1020004000000000000000000ee05000001000000"
	info         string = "\nfgsniffer\n\nConvert text captures to pcap files. On the fortigate use\n\tdiagnose sniffer packet <interface> '<filter>' <3|6> <count> a\nto create a parsable dump.\n\n"
	pathUnsafe   string = "[]{}/\\*!?"
)

type (
	pcaps struct {
		pcap map[string]int
	}
	packet struct {
		data     string // raw hex data
		size     int64
		secs, ms int64  // the packets timestamp
		port     string // the network port (verbose=6)
		direction string // the transit direction (verbose=6)
	}
)

func main() {
	var scanner *bufio.Scanner
	var p packet
	var stdoutfilter string
	now := time.Now()
	fnamebase := now.Format("fgs20060102-1504")

	if len(os.Args) == 2 {
		if os.Args[1] == "-?" || os.Args[1] == "-h" {
			fmt.Println(info)
			os.Exit(0)
		} else {
			stdoutfilter = os.Args[1]
		}
	}
	scanner = bufio.NewScanner(os.Stdin)

	// absolute time
	headLineA := regexp.MustCompile("^([0-9-]+ [0-9][0-9]:[0-9][0-9]:[0-9][0-9])\\.([0-9]+) .*$")
	// local time is not supported
	//headLineL := regexp.MustCompile("NOT SUPPORTED")
	// relative time
	headLineR := regexp.MustCompile("^([0-9]+)\\.([0-9]+) .*$")
	// verbose mode 6
	headLine6 := regexp.MustCompile("\\.[0-9]+ ([^ ]+) (in|out|--) ")
	// packet data
	hexLine := regexp.MustCompile("^0x([0-9a-f]+)[ |\t]+([0-9a-f ]+).*$")

	pcps := pcaps{make(map[string]int)}

	for scanner.Scan() {
		date := ""
		mseconds := ""
		iface := ""
		direction := ""
		match := false
		line := scanner.Text()

		// packet header with absolute time
		header := headLineA.FindStringSubmatch(line)
		if len(header) == 3 {
			match = true
			date = header[1]
			mseconds = header[2]
		}
		// packet header with relative time
		header = headLineR.FindStringSubmatch(line)
		if len(header) == 3 {
			match = true
			sec, err := time.ParseDuration(header[1] + "s")
			if err != nil {
				fmt.Println("time.ParseDuration("+header[1]+")", err)
			}
			date = now.Add(sec).In(time.UTC).Format("2006-01-02 15:04:05")
			mseconds = header[2]
		}
		// verbose mode 6
		header = headLine6.FindStringSubmatch(line)
		if match && len(header) == 3 {
			iface = header[1]
			direction = header[2]
		}
		// flush previous packet
		if match {
			pcps.addPacket(fnamebase, stdoutfilter, p)
			p = newPacket(date, mseconds, iface, direction)
		}

		// packet hex data
		hexData := hexLine.FindStringSubmatch(line)
		if len(hexData) == 3 {
			p.addData(strings.Replace(hexData[2], " ", "", -1))
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	// flush last packet
	pcps.addPacket(fnamebase, stdoutfilter, p)

	for name, packets := range pcps.pcap {
		fmt.Fprintln(os.Stderr, "created output file", name, "with", packets, "packets.")
	}
}

// create file, add global header
func (pcps *pcaps) newPcap(name string) (err error) {
	err = ioutil.WriteFile(name, nil, 0644)
	if err != nil {
		fmt.Println(err)
	}
	err = appendBytesToFile(name, []byte(globalHeader))
	if err != nil {
		fmt.Println(err)
	}
	return err
}

// create a new packet. We need some data from the header
func newPacket(date, mseconds, iface string, direction string) packet {
	t, _ := time.Parse("2006-01-02 15:04:05", date)
	ms, _ := strconv.ParseInt(mseconds, 10, 64)
	return packet{"", 0, t.Unix(), ms, iface, direction}
}

// add a data line to the packet
func (p *packet) addData(data string) {
	p.size += int64(len(data) / 2)
	p.data += data
}

// all hex lines complete, write the packet to the pcap
func (pcps *pcaps) addPacket(fnamebase string, stdoutfilter string, p packet) {
	if p.size == 0 {
		return
	}
	var fnamebuffer bytes.Buffer
	fnamebuffer.WriteString(fnamebase)

	if p.port != "" {
		portClean := []byte(p.port)
		for i := 0; i < len(pathUnsafe); i++ {
			portClean = bytes.Replace(portClean, []byte(string(pathUnsafe[i])), []byte("_"), -1)
		}
		fnamebuffer.WriteString("-");
		fnamebuffer.WriteString(p.direction);
		fnamebuffer.WriteString("-");
		fnamebuffer.Write(portClean);
	}
	fnamebuffer.WriteString(".pcap");
	fname := fnamebuffer.String()
	_, found := pcps.pcap[fname]
	if !found {
		pcps.pcap[fname] = 0
		_ = pcps.newPcap(fname)
	}
	var wbuffer bytes.Buffer
	wbuffer.Write(switchEndian(p.secs))
	wbuffer.Write(switchEndian(p.ms))
	wbuffer.Write(switchEndian(p.size))
	wbuffer.Write(switchEndian(p.size))
	wbuffer.WriteString(p.data)
	err := appendBytesToFile(fname, wbuffer.Bytes())
	if err != nil {
		fmt.Println(err)
	}
	pcps.pcap[fname]++

	// stdout passthrough enabled?
	if stdoutfilter != "" {
		// stdout passthrough rules matched: Packet has no port, port match, any match, direction match, packet has no direction
		if p.port == "" || p.port == stdoutfilter || stdoutfilter == "any" || stdoutfilter == p.direction || p.direction == "--" {
			fname := "/dev/stdout"
			_, found := pcps.pcap[fname]
			if !found {
				pcps.pcap[fname] = 0
				_ = pcps.newPcap(fname)
			}
			err := appendBytesToFile(fname, wbuffer.Bytes())
			if err != nil {
				fmt.Println(err)
			}
			pcps.pcap[fname]++
		}
	}
}

// 11259375 -> 00abcdef -> efcdab00
func switchEndian(n int64) []byte {
	b := fmt.Sprintf("%08x", n)
	var rbuffer bytes.Buffer
	for i := 0; i < 4; i++ {
		start := 6 - 2*i
		rbuffer.WriteString(b[start:start+2])
	}
	return rbuffer.Bytes()
}

// convert the hex data in string to binary and write it to file
func appendBytesToFile(file string, src []byte) error {
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
	if err != nil {
		return err
	}
	defer f.Close()
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err = hex.Decode(dst, src)
	if err != nil {
		return err
	}
	_, err = f.Write(dst)
	if err != nil {
		return err
	}
	return nil
}
