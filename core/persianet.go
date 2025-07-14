package core

import (
	"context"
	"crypto/tls"
	"github.com/lucas-clemente/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"net/http"
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
	listener, err := quic.ListenAddr(fmt.Sprintf("%s:%d", p.Listen, p.Port), &tls.Config{
		NextProtos: p.TLS.ALPN,
		Certificates: []tls.Certificate{ /* Load your TLS cert */ },
	}, quicConfig)
	if err != nil {
		log.Warn("QUIC failed, switching to HTTP/2: ", err)
		return p.startHTTP2(ctx, router)
	}
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
	http2Client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				NextProtos: p.TLS.ALPN,
			},
		},
	}
	log.Info("PersiaNet HTTP/2 started on ", p.Listen, ":", p.Fallback.Port)
	// منطق اتصال HTTP/2
	return nil
}

func handleQUICSession(session quic.Session, router adapter.Router) {
	log.Info("New QUIC session established")
	// پردازش ترافیک QUIC و هدایت به router
}

func (p *PersiaNetInbound) Close() error {
	log.Info("Closing PersiaNet inbound")
	return nil
}
