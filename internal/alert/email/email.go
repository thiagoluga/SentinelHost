// Package email envia alertas por SMTP.
//
// Usa a stdlib (net/smtp) em vez de biblioteca externa: o corpo dos alertas e
// texto simples e HTML basico, e uma dependencia a mais num binario que
// promete "sem dependencias obrigatorias" precisa se justificar melhor que
// isso (Principio VII).
package email

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/config"
)

// DialTimeout da conexao SMTP.
const DialTimeout = 20 * time.Second

// Message e um e-mail pronto para enviar.
type Message struct {
	To      []string
	Subject string
	Text    string
	HTML    string
}

// Sender envia e-mails.
type Sender struct {
	cfg config.EmailConfig
	// dial e injetavel nos testes, para nao precisar de um servidor real.
	dial func(addr string) (net.Conn, error)
}

// New cria o remetente.
func New(cfg config.EmailConfig) *Sender {
	return &Sender{
		cfg: cfg,
		dial: func(addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", addr, DialTimeout)
		},
	}
}

// WithDialer troca o dialer. Uso restrito a testes.
func (s *Sender) WithDialer(fn func(string) (net.Conn, error)) *Sender {
	s.dial = fn
	return s
}

// Send entrega a mensagem.
//
// Devolve o erro REAL do servidor. A spec exige que o botao "enviar teste"
// mostre o erro de verdade: "falha ao enviar" nao ajuda ninguem a descobrir
// que a hospedagem bloqueia a porta 587.
func (s *Sender) Send(ctx context.Context, msg Message) error {
	if s.cfg.Host == "" {
		return errors.New("host SMTP nao configurado")
	}
	destinatarios := msg.To
	if len(destinatarios) == 0 {
		destinatarios = s.cfg.To
	}
	if len(destinatarios) == 0 {
		return errors.New("nenhum destinatario configurado")
	}

	addr := net.JoinHostPort(s.cfg.Host, fmt.Sprint(s.cfg.Port))

	conn, err := s.dial(addr)
	if err != nil {
		return fmt.Errorf("conectando em %s: %w", addr, err)
	}

	// TLS implicito (porta 465) envolve a conexao antes do handshake SMTP.
	if s.cfg.TLS == "tls" {
		conn = tls.Client(conn, &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12})
	}

	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("iniciando sessao SMTP: %w", err)
	}
	defer func() { _ = c.Close() }()

	// Respeita o cancelamento: um SMTP pendurado nao pode segurar o ciclo.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	if s.cfg.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("o servidor %s nao oferece STARTTLS; ajuste alerts.email.tls", s.cfg.Host)
		}
		if err := c.StartTLS(&tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("negociando STARTTLS: %w", err)
		}
	}

	if s.cfg.Username != "" {
		auth := smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("autenticando em %s: %w", s.cfg.Host, err)
		}
	}

	if err := c.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("remetente %q recusado: %w", s.cfg.From, err)
	}
	for _, to := range destinatarios {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("destinatario %q recusado: %w", to, err)
		}
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("iniciando corpo da mensagem: %w", err)
	}
	if _, err := w.Write(build(s.cfg.From, destinatarios, msg)); err != nil {
		_ = w.Close()
		return fmt.Errorf("escrevendo mensagem: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finalizando mensagem: %w", err)
	}
	return c.Quit()
}

// build monta a mensagem MIME.
func build(from string, to []string, msg Message) []byte {
	var b strings.Builder
	fronteira := "sentinelhost-" + fmt.Sprint(time.Now().UnixNano())

	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", encodeSubject(msg.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	// Marca a origem para que filtros e o proprio usuario reconhecam.
	b.WriteString("X-Mailer: SentinelHost\r\n")

	if msg.HTML == "" {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(msg.Text)
		return []byte(b.String())
	}

	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", fronteira)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", fronteira, msg.Text)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s\r\n", fronteira, msg.HTML)
	fmt.Fprintf(&b, "--%s--\r\n", fronteira)
	return []byte(b.String())
}

// encodeSubject aplica RFC 2047 quando ha caractere nao-ASCII.
//
// Sem isso, "Ameaça confirmada" chega ilegivel em boa parte dos clientes — e o
// assunto e a primeira coisa que o usuario ve num alerta de seguranca.
func encodeSubject(s string) string {
	ascii := true
	for _, r := range s {
		if r > 127 {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	return mimeEncode(s)
}
