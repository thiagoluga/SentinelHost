package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/thiagoluga/SentinelHost/internal/store"
)

// Parametros do argon2id.
//
// 64 MiB e 1 iteracao com 4 threads e o perfil "interativo" recomendado pela
// RFC 9106. Numa hospedagem compartilhada, memoria e o recurso mais escasso —
// mas essa e exatamente a proteção que torna o hash caro de quebrar, e um
// login por sessao de 12 horas nao pesa no orcamento da conta.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

const sessionCookie = "sentinelhost_session"

// ErrNoPassword indica que a senha ainda nao foi definida.
var ErrNoPassword = errors.New("senha do painel ainda nao definida")

// hashPassword gera um hash argon2id no formato PHC.
func hashPassword(senha string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("gerando salt: %w", err)
	}
	key := argon2.IDKey([]byte(senha), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// verifyPassword confere a senha contra o hash.
//
// A comparacao e em tempo constante. Comparar hash com `==` vazaria, pelo
// tempo de resposta, quantos bytes iniciais o atacante acertou.
func verifyPassword(senha, phc string) bool {
	partes := strings.Split(phc, "$")
	if len(partes) != 6 || partes[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(partes[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(partes[4])
	if err != nil {
		return false
	}
	esperado, err := base64.RawStdEncoding.DecodeString(partes[5])
	if err != nil {
		return false
	}
	// Exige exatamente o tamanho que hashPassword produz, e deriva com a
	// constante — sem nenhuma conversao de int para uint32.
	//
	// Nao e rigor formal: derivar com um tamanho vindo do proprio hash
	// armazenado deixaria um banco adulterado escolher o parametro, e uma
	// conversao truncada faria o argon2 gerar uma chave de tamanho diferente
	// do esperado, comparando coisas incomparaveis.
	if len(esperado) != argonKeyLen {
		return false
	}
	calculado := argon2.IDKey([]byte(senha), salt, t, m, p, argonKeyLen)
	return subtle.ConstantTimeCompare(calculado, esperado) == 1
}

// newToken gera um token de sessao.
func newToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// rateLimiter limita tentativas de login por IP.
//
// Sem ele, um painel exposto (mesmo por engano) vira alvo de forca bruta, e a
// senha unica do painel e a unica coisa entre o atacante e um botao que move
// arquivos do site.
type rateLimiter struct {
	mu       sync.Mutex
	perMin   int
	janela   time.Duration
	tentando map[string][]time.Time
}

func newRateLimiter(perMin int) *rateLimiter {
	if perMin <= 0 {
		perMin = 10
	}
	return &rateLimiter{perMin: perMin, janela: time.Minute, tentando: map[string][]time.Time{}}
}

// allow registra uma tentativa e diz se ela e permitida.
func (r *rateLimiter) allow(ip string, agora time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	corte := agora.Add(-r.janela)
	recentes := r.tentando[ip][:0]
	for _, t := range r.tentando[ip] {
		if t.After(corte) {
			recentes = append(recentes, t)
		}
	}
	if len(recentes) >= r.perMin {
		r.tentando[ip] = recentes
		return false
	}
	r.tentando[ip] = append(recentes, agora)
	return true
}

// reset limpa o historico de um IP apos login bem-sucedido.
func (r *rateLimiter) reset(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tentando, ip)
}

// clientIP extrai o IP da requisicao.
//
// NAO confia em X-Forwarded-For: o painel escuta em localhost por padrao, e
// aceitar um cabecalho que o cliente controla permitiria a qualquer atacante
// zerar o proprio limite de tentativas mandando um IP diferente por request.
func clientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// authenticated responde se a requisicao tem sessao valida.
func (s *Server) authenticated(req *http.Request) bool {
	c, err := req.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	ok, err := s.store.SessionValid(req.Context(), c.Value)
	return err == nil && ok
}

// passwordSet responde se ja existe senha definida.
func (s *Server) passwordSet(ctx context.Context) bool {
	h, err := s.store.GetSetting(ctx, store.KeyPanelPasswordHash)
	return err == nil && h != ""
}

// setCookie grava o cookie de sessao.
func (s *Server) setCookie(w http.ResponseWriter, token string, expira time.Time, seguro bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expira,
		HttpOnly: true,
		// SameSite=Strict: o painel tem acoes que movem arquivos. Um link
		// malicioso numa outra aba nao pode carregar credencial junto.
		SameSite: http.SameSiteStrictMode,
		// Secure so quando ha TLS de verdade. Marcar Secure num painel
		// acessado por http://127.0.0.1 faria o navegador descartar o cookie
		// e o login nunca funcionaria.
		Secure: seguro,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}
