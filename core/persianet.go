package core

import (
	"context"
	"crypto/tls"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/lucas-clemente/quic-go"
	"net/http"
)

type PersiaNetInbound struct {
	Type     string          `json:"type"`
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"` // "quic" or "http2"
	Fallback option.Fallback `json:"fallback"`
	Settings PersiaNetSettings `json:"settings"`
	TLS      option.InboundTLSOptions `json:"tls"`
}

type PersiaNetSettings struct {
	Encryption   string `json:"encryption"`
	Obfuscation string `json:"obfuscation"`
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
	quicConfig := &quic.Config{}
	listener, err := quic.ListenAddr(":443", &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
	}, quicConfig)
	if err != nil {
		log.Warn("QUIC failed, switching to HTTP/2: ", err)
		return p.startHTTP2(ctx, router)
	}
	log.Info("PersiaNet QUIC started on :443")
	// مدیریت اتصالات QUIC
	go func() {
		for {
			session, err := listener.Accept(ctx)
			if err != nil {
				log.Error("QUIC accept error: ", err)
				return
			}
			// پردازش اتصال QUIC
			go handleQUICSession(session)
		}
	}()
	return nil
}

func (p *PersiaNetInbound) startHTTP2(ctx context.Context, router adapter.Router) error {
	http2Client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				NextProtos: []string{"h2"},
			},
		},
	}
	log.Info("PersiaNet HTTP/2 started")
	// مدیریت اتصالات HTTP/2
	return nil
}

func handleQUICSession(session quic.Session) {
	// منطق مدیریت جلسه QUIC
	log.Info("New QUIC session established")
}

func (p *PersiaNetInbound) Close() error {
	log.Info("Closing PersiaNet inbound")
	return nil
}
