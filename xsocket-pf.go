package main

import (
    "context"
    "encoding/binary"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "net"
    "net/url"
    "os"
    "os/signal"
    "strconv"
    "strings"
    "sync"
    "syscall"
    "time"
)

const (
    XS_PROTOCOL_REQUEST  = 0x58533031
    XS_PROTOCOL_RESPONSE = 0x58533032
)

type xsProtocolRequest struct {
    Signature uint32
    Domain    int32
    Type      int32
    Protocol  int32
}

type xsProtocolResponse struct {
    Signature uint32
    Error     int32
}

type ForwardRule struct {
    Protocol string
    Listen   string
    Target   string

    XSocketIn  string
    XSocketOut string

    Raw     string
    Timeout time.Duration
}

func connectUnixSeqpacket(path string) (int, error) {
	fd, err := syscall.Socket(
		syscall.AF_UNIX,
		syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC,
		0,
	)

	if err != nil {
		return -1, err
	}

	var sa syscall.SockaddrUnix

	if len(path) > 0 && path[0] == '@' {
		sa.Name = "\x00" + path[1:]
	} else {
		sa.Name = path
	}

	if err := syscall.Connect(fd, &sa); err != nil {
		syscall.Close(fd)
		return -1, err
	}

	return fd, nil
}

func xsocket(uds string, domain, xtype, protocol int) (int, error) {
	ctrlFd, err := connectUnixSeqpacket(uds)
	if err != nil {
		return -1, err
	}

	defer syscall.Close(ctrlFd)

	req := xsProtocolRequest{
		Signature: XS_PROTOCOL_REQUEST,
		Domain:    int32(domain),
		Type:      int32(xtype &^ syscall.SOCK_CLOEXEC),
		Protocol:  int32(protocol),
	}

	reqbuf := make([]byte, 16)

	binary.BigEndian.PutUint32(reqbuf[0:], req.Signature)
	binary.BigEndian.PutUint32(reqbuf[4:], uint32(req.Domain))
	binary.BigEndian.PutUint32(reqbuf[8:], uint32(req.Type))
	binary.BigEndian.PutUint32(reqbuf[12:], uint32(req.Protocol))

	if err := writeFull(ctrlFd, reqbuf); err != nil {
		return -1, err
	}

	if err := syscall.Shutdown(ctrlFd, syscall.SHUT_WR); err != nil {
		return -1, err
	}

	data := make([]byte, 8)
	oob := make([]byte, syscall.CmsgSpace(4))

	n, oobn, _, _, err := syscall.Recvmsg(ctrlFd, data, oob, syscall.MSG_CMSG_CLOEXEC)
	if err != nil {
		return -1, err
	}

	if n < 8 {
		return -1, errors.New("short response")
	}

	resp := xsProtocolResponse{
		Signature: binary.BigEndian.Uint32(data[0:4]),
		Error:     int32(binary.BigEndian.Uint32(data[4:8])),
	}

	if resp.Signature != XS_PROTOCOL_RESPONSE {
		return -1, errors.New("invalid response signature")
	}

	if resp.Error != 0 {
		return -1, syscall.Errno(resp.Error)
	}

	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, err
	}

	for _, msg := range msgs {
		fds, err := syscall.ParseUnixRights(&msg)
		if err != nil {
			continue
		}

		if len(fds) > 0 {
			return fds[len(fds)-1], nil
		}
	}

	return -1, errors.New("no fd received")
}

func writeFull(fd int, buf []byte) error {
	for len(buf) > 0 {
		n, err := syscall.Write(fd, buf)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return err
		}

		buf = buf[n:]
	}

	return nil
}

func parseRule(arg string) (*ForwardRule, error) {
    u, err := url.Parse(arg)
    if err != nil {
        return nil, err
    }
    target := strings.TrimPrefix(u.Path, "/")
    if target == "" {
        return nil, errors.New("missing target address in URL path")
    }
    query := u.Query()
    xsocketIn := query.Get("xsocket.in")
    xsocketOut := query.Get("xsocket.out")
    
    if xsocketIn == "" || xsocketOut == "" {
        return nil, errors.New("xsocket.in and xsocket.out are required")
    }

    timeout := 5 * time.Second // Default timeout
    if t := query.Get("timeout"); t != "" {
        if sec, err := strconv.Atoi(t); err == nil && sec > 0 {
            timeout = time.Duration(sec) * time.Second
        } else {
            return nil, fmt.Errorf("invalid timeout value: %q", t)
        }
    }

    return &ForwardRule{
        Protocol:   u.Scheme,
        Listen:     u.Host,
        Target:     target,
        XSocketIn:  xsocketIn,
        XSocketOut: xsocketOut,
        Raw:        arg,
        Timeout:    timeout,
    }, nil
}

func sockaddrFromTCPAddr(addr *net.TCPAddr) syscall.Sockaddr {
	ip := addr.IP
	if ip == nil {
		ip = net.IPv4zero
	}

	if ip4 := ip.To4(); ip4 != nil {
		return &syscall.SockaddrInet4{
			Port: addr.Port,
			Addr: [4]byte(ip4),
		}
	}

	ip16 := ip.To16()
	var arr [16]byte
	copy(arr[:], ip16)

	return &syscall.SockaddrInet6{
		Port: addr.Port,
		Addr: arr,
	}
}

func sockaddrFromUDPAddr(addr *net.UDPAddr) syscall.Sockaddr {
	ip := addr.IP
	if ip == nil {
		ip = net.IPv4zero
	}

	if ip4 := ip.To4(); ip4 != nil {
		return &syscall.SockaddrInet4{
			Port: addr.Port,
			Addr: [4]byte(ip4),
		}
	}

	ip16 := ip.To16()
	var arr [16]byte
	copy(arr[:], ip16)

	return &syscall.SockaddrInet6{
		Port: addr.Port,
		Addr: arr,
	}
}

func sockaddrFromNetAddr(ip net.IP, port int) syscall.Sockaddr {
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4 → map into IPv6 space
		return &syscall.SockaddrInet6{
			Port: port,
			Addr: [16]byte{
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0xff, 0xff,
				ip4[0], ip4[1], ip4[2], ip4[3],
			},
		}
	}

	ip16 := ip.To16()
	return &syscall.SockaddrInet6{
		Port: port,
		Addr: [16]byte(ip16),
	}
}

func sockaddrFamily(sa syscall.Sockaddr) int {
	switch sa.(type) {
	case *syscall.SockaddrInet4:
		return syscall.AF_INET
	case *syscall.SockaddrInet6:
		return syscall.AF_INET6
	default:
		return syscall.AF_UNSPEC
	}
}

func addrFamily(ip net.IP) int {
	if ip4 := ip.To4(); ip4 != nil {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

func xsocketListenTCP(uds, addr string) (net.Listener, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

    sa := sockaddrFromTCPAddr(tcpAddr)
    fd, err := xsocket(uds, sockaddrFamily(sa), syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	if err := syscall.Listen(fd, 128); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "xsocket-listener")
	defer file.Close()

	return net.FileListener(file)
}

func xsocketDialTCP(uds, addr string) (net.Conn, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

    sa := sockaddrFromTCPAddr(tcpAddr)
    fd, err := xsocket(uds, sockaddrFamily(sa), syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}

	if err := syscall.Connect(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "xsocket-conn")
	defer file.Close()

	return net.FileConn(file)
}

func xsocketListenUDP(uds, addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

    sa := sockaddrFromUDPAddr(udpAddr)
    fd, err := xsocket(uds, sockaddrFamily(sa), syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}

	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, err
	}

    file := os.NewFile(uintptr(fd), "xsocket-udp-listener")
    
    pc, err := net.FilePacketConn(file)
    file.Close()
    if err != nil {
        file.Close()
        syscall.Close(fd)
        return nil, err
    }
	if err != nil {
		return nil, err
	}

	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, errors.New("not UDP conn")
	}

	return udpConn, nil
}

func xsocketDialUDP(uds string, addr *net.UDPAddr) (*net.UDPConn, error) {
    sa := sockaddrFromUDPAddr(addr)
    family := addrFamily(addr.IP)
    
    fd, err := xsocket(uds, family, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}

	

	if err := syscall.Connect(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "xsocket-udp-upstream")
	defer file.Close()

	conn, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, errors.New("not UDP conn")
	}

	return udpConn, nil
}

func handleTCP(rule *ForwardRule) error {
    ln, err := xsocketListenTCP(
        rule.XSocketIn,
        rule.Listen,
    )
	if err != nil {
		return fmt.Errorf("listen tcp: %w", err)
	}
	defer ln.Close()

	for {
		connIn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go func(connIn net.Conn) {
			defer connIn.Close()

        connOut, err := xsocketDialTCP(
            rule.XSocketOut,
            rule.Target,
        )
			if err != nil {
				log.Printf("Dial target error: %v", err)
				return
			}
			defer connOut.Close()

			var wg sync.WaitGroup
			copyBufSize := 64 * 1024
			wg.Add(2)

			go func() {
				defer wg.Done()
				_, err := io.CopyBuffer(connOut, connIn, make([]byte, copyBufSize))
				if err != nil && !errors.Is(err, io.EOF) {
					log.Printf("Copy client→target error: %v", err)
				}
				if tcpConn, ok := connOut.(*net.TCPConn); ok {
					tcpConn.CloseWrite()
				}
			}()

			go func() {
				defer wg.Done()
				_, err := io.CopyBuffer(connIn, connOut, make([]byte, copyBufSize))
				if err != nil && !errors.Is(err, io.EOF) {
					log.Printf("Copy target→client error: %v", err)
				}
				if tcpConn, ok := connIn.(*net.TCPConn); ok {
					tcpConn.CloseWrite()
				}
			}()

			wg.Wait()
		}(connIn)
	}
}

type udpClient struct {
	addr     *net.UDPAddr
	lastSeen time.Time
}

func handleUDP(rule *ForwardRule) error {
	inConn, err := xsocketListenUDP(rule.XSocketIn, rule.Listen)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	defer inConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan struct{})

	go func() {
		<-ctx.Done()
		close(stop)
		inConn.Close()
	}()

	type udpClient struct {
		srcAddr  *net.UDPAddr
		outConn  *net.UDPConn
		lastSeen time.Time
		cancel   context.CancelFunc
	}

	clients := make(map[string]*udpClient)
	var mu sync.Mutex

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
			}

			now := time.Now()

			mu.Lock()
			for key, client := range clients {
				if now.Sub(client.lastSeen) > rule.Timeout {
					client.cancel()
					client.outConn.Close()
					delete(clients, key)
				}
			}
			mu.Unlock()
		}
	}()

	buf := make([]byte, 2048)

	for {
		select {
		case <-stop:
			return nil
		default:
		}

		n, srcAddr, err := inConn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) ||
				strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}

			log.Println("UDP read error:", err)
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		clientKey := srcAddr.String()

		mu.Lock()
		client, exists := clients[clientKey]

		if !exists {
			raddr, err := net.ResolveUDPAddr("udp", rule.Target)
			if err != nil {
				mu.Unlock()
				continue
			}

			outConn, err := xsocketDialUDP(rule.XSocketOut, raddr)
			if err != nil {
				mu.Unlock()
				continue
			}

			childCtx, childCancel := context.WithCancel(ctx)

			client = &udpClient{
				srcAddr:  srcAddr,
				outConn:  outConn,
				lastSeen: time.Now(),
				cancel:   childCancel,
			}
			clients[clientKey] = client

			go func(cctx context.Context, conn *net.UDPConn, key string) {
				buf := make([]byte, 2048)
				defer conn.Close()

				for {
					select {
					case <-cctx.Done():
						return
					default:
					}

					n, err := conn.Read(buf)
					if err != nil {
						return
					}

					mu.Lock()
					c := clients[key]
					mu.Unlock()

					if c != nil {
						_, _ = inConn.WriteToUDP(buf[:n], c.srcAddr)
					}
				}
			}(childCtx, outConn, clientKey)
		}

		client.lastSeen = time.Now()
		mu.Unlock()

		_, err = client.outConn.Write(data)
		if err != nil {
			log.Printf("write to target failed: %v", err)
		}
	}
}

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func main() {
	var listenRules multiFlag
    flag.Var(
        &listenRules,
        "L",
        "forward rule: protocol://listen/target?xsocket.in=SOCKET&xsocket.out=SOCKET[&timeout=SECONDS]",
    )
	flag.Parse()

	if len(listenRules) == 0 {
		log.Fatalf("no forwarding rules specified")
	}

	var rules []*ForwardRule
	for _, r := range listenRules {
		rule, err := parseRule(r)
		if err != nil {
			log.Fatalf("invalid rule %q: %v", r, err)
		}
		rules = append(rules, rule)
	}

	for _, rule := range rules {
		switch rule.Protocol {
        case "tcp":
            go func(r *ForwardRule) {
                if err := handleTCP(r); err != nil {
                    log.Fatalf("tcp forward failed: %v", err)
                }
            }(rule)
        
       case "udp":
           go func(r *ForwardRule) {
               if err := handleUDP(r); err != nil {
                   log.Printf("udp forward failed: %v", err)
               }
           }(rule)
        
        default:
    log.Fatalf("unsupported protocol %q", rule.Protocol)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Println("Shutting down...")
	time.Sleep(1 * time.Second)
}
