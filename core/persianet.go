package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"net"
	"net/http"
	"time"
)

type PersiaNetInbound struct {
	Type     string                 `json:"type"`
	Tag      string                 `json:"tag"`
	Protocol string                 `json:"protocol"` // "quic" or "http2"
	Listen   string                 `json:"listen"`
	Port     int                    `json:"port"`
	Fallback option.Fallback        `json:"fallback"`
	Settings PersiaNetSettings       `json:"settings"`
	TLS      option.InboundTLSOptions `json:"tls"`
	listener net.Listener
}

type PersiaNetOutbound struct {
	Type     string                  `json:"type"`
	Tag      string                  `json:"tag"`
	Protocol string                  `json:"protocol"` // "quic" or "http2"
	Server   string                  `json:"server"`
	Port     int                     `json:"server_port"`
	Settings PersiaNetSettings        `json:"settings"`
	TLS      option.OutboundTLSOptions `json:"tls"`
}

type PersiaNetSettings struct {
	Encryption   string `json:"encryption"`
	Obfuscation  string `json:"obfuscation"`
	Fragmentation struct {
		Enabled bool   `json:"enabled"`
		Size    string `json:"size"`
	} `json:"fragmentation"`
}

func (p *PersiaNetInbound) Network() []string {
	return []string{p.Protocol}
}

func (p *PersiaNetInbound) Start(ctx context.Context, router adapter.Router) error {
	log.Info("Starting PersiaNet inbound with protocol: ", p.Protocol)
	if p.Protocol == "quic" {
		return p.startQUIC(ctx, router)
	}
	return p.startHTTP2(ctx, router)
}

func (p *PersiaNetInbound) startQUIC(ctx context.Context, router adapter.Router) error {
	quicConfig := &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	}
	tlsConfig := &tls.Config{
		NextProtos:   p.TLS.ALPN,
		// باید گواهینامه TLS رو اینجا لود کنید
		// Certificates: []tls.Certificate{loadYourTLSCert()},
	}
	listener, err := quic.ListenAddr(fmt.Sprintf("%s:%d", p.Listen, p.Port), tlsConfig, quicConfig)
	if err != nil {
		log.Warn("QUIC failed, switching to HTTP/2: ", err)
		return p.startHTTP2(ctx, router)
	}
	p.listener = listener
	log.Info("PersiaNet QUIC started on ", p.Listen, ":", p.Port)
	go func() {
		for {
			session, err := listener.Accept(ctx)
			if err != nil {
				log.Error("QUIC accept error: ", err)
				return
			}
			go handleQUICSession(session, router)
		}
	}()
	return nil
}

func (p *PersiaNetInbound) startHTTP2(ctx context.Context, router adapter.Router) error {
	http2Server := &http.Server{
		Addr: fmt.Sprintf("%s:%d", p.Listen, p.Fallback.Port),
		TLSConfig: &tls.Config{
			NextProtos: p.TLS.ALPN,
			// Certificates: []tls.Certificate{loadYourTLSCert()},
		},
	}
	listener, err := net.Listen("tcp", http2Server.Addr)
	if err != nil {
		log.Error("HTTP/2 listen error: ", err)
		return err
	}
	p.listener = listener
	log.Info("PersiaNet HTTP/2 started on ", p.Listen, ":", p.Fallback.Port)
	go func() {
		if err := http2Server.ServeTLS(listener, "", ""); err != nil {
			log.Error("HTTP/2 serve error: ", err)
		}
	}()
	return nil
}

func (p *PersiaNetOutbound) DialContext(ctx context.Context) (adapter.Conn, error) {
	if p.Protocol == "quic" {
		return p.dialQUIC(ctx)
	}
	return p.dialHTTP2(ctx)
}

func (p *PersiaNetOutbound) dialQUIC(ctx context.Context) (adapter.Conn, error) {
	quicConfig := &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	}
	session, err := quic.DialAddr(fmt.Sprintf("%s:%d", p.Server, p.Port), &tls.Config{
		NextProtos: p.TLS.ALPN,
	}, quicConfig)
	if err != nil {
		log.Warn("QUIC dial failed, switching to HTTP/2: ", err)
		return p.dialHTTP2(ctx)
	}
	return session, nil
}

func (p *PersiaNetOutbound) dialHTTP2(ctx context.Context) (adapter.Conn, error) {
	http2Client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				NextProtos: p.TLS.ALPN,
			},
		},
	}
	req, err := http.NewRequestWithContext(ctx, "CONNECT", fmt.Sprintf("https://%s:%d", p.Server, p.Port), nil)
	if err != nil {
		return nil, err
	}
	resp, err := http2Client.Do(req)
	if err != nil {
		return nil, err
	}
	// تبدیل پاسخ HTTP/2 به adapter.Conn
	// نیاز به پیاده‌سازی دقیق‌تر دارد
	return nil, fmt.Errorf("HTTP/2 connection not fully implemented")
}

func handleQUICSession(session quic.Session, router adapter.Router) {
	log.Info("New QUIC session established")
	// پردازش ترافیک QUIC و هدایت به router
	// نیاز به پیاده‌سازی بیشتر برای مدیریت جریان‌ها
}

func (p *PersiaNetInbound) Close() error {
	if p.listener != nil {
		log.Info("Closing PersiaNet inbound")
		return p.listener.Close()
	}
	return nil
}

func (p *PersiaNetOutbound) Close() error {
	log.Info("Closing PersiaNet outbound")
	return nil
}
