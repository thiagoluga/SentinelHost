// Package quarantine implementa o cofre reversivel.
//
// Este pacote e onde o Principio I vive: quarentena e mover + registrar +
// bloquear, NUNCA apagar. Um falso positivo tratado aqui nunca pode derrubar o
// site do usuario permanentemente.
//
// A ordem das operacoes nao e negociavel:
//  1. re-hash do arquivo IMEDIATAMENTE antes de agir (FR-018)
//  2. copia para o cofre
//  3. verificacao de que a copia esta integra
//  4. so entao o original e removido
//
// Inverter 3 e 4 significaria, num disco cheio, apagar o arquivo do usuario e
// ficar com uma copia truncada. E o unico jeito de esta ferramenta destruir
// um site — por isso a ordem esta escrita aqui e testada.
package quarantine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thiagoluga/SentinelHost/internal/baseline"
	"github.com/thiagoluga/SentinelHost/internal/config"
	"github.com/thiagoluga/SentinelHost/internal/schema"
	"github.com/thiagoluga/SentinelHost/internal/store"
)

var (
	// ErrHashMismatch indica que o arquivo mudou entre o scan e a acao.
	ErrHashMismatch = errors.New("o arquivo mudou desde o scan")
	// ErrVaultUnwritable indica cofre sem permissao ou disco cheio.
	ErrVaultUnwritable = errors.New("nao foi possivel escrever no cofre de quarentena")
	// ErrNotInVault indica item inexistente ou ja restaurado.
	ErrNotInVault = errors.New("item nao esta no cofre")
	// ErrRestoreTargetExists indica que ja existe arquivo no caminho original.
	ErrRestoreTargetExists = errors.New("ja existe um arquivo no caminho original")
	// ErrVaultCorrupted indica que a copia no cofre nao confere com o hash
	// registrado.
	ErrVaultCorrupted = errors.New("a copia no cofre nao confere com o hash registrado")
)

// Vault e o cofre de quarentena.
type Vault struct {
	dir   string
	cfg   config.QuarantineConfig
	store *store.Store
	// now e injetavel nos testes de retencao.
	now func() time.Time
}

// New cria o cofre.
func New(dir string, cfg config.QuarantineConfig, st *store.Store) *Vault {
	return &Vault{dir: dir, cfg: cfg, store: st, now: time.Now}
}

// WithClock troca o relogio. Uso restrito a testes.
func (v *Vault) WithClock(fn func() time.Time) *Vault {
	v.now = fn
	return v
}

// Dir devolve o diretorio do cofre.
func (v *Vault) Dir() string { return v.dir }

// Quarantine neutraliza um arquivo de forma reversivel.
//
// expectedSHA e o hash que o veredito viu. Se o arquivo mudou desde entao, a
// funcao recusa agir e devolve ErrHashMismatch — o chamador deve reescanear em
// vez de quarentenar as cegas (edge case explicito da spec).
func (v *Vault) Quarantine(ctx context.Context, verdictID, path, expectedSHA string) (store.QuarantineItem, error) {
	var item store.QuarantineItem

	// 1. Re-hash IMEDIATAMENTE antes de agir. Nao ha atalho aqui: o hash do
	//    veredito pode ter minutos de idade, e nesses minutos o arquivo pode
	//    ter sido corrigido pelo proprio usuario.
	atual, err := baseline.HashFile(path)
	if err != nil {
		return item, fmt.Errorf("nao foi possivel reler o arquivo antes de agir: %w", err)
	}
	if expectedSHA != "" && atual != expectedSHA {
		return item, fmt.Errorf("%w: veredito viu %s, disco tem %s", ErrHashMismatch, short(expectedSHA), short(atual))
	}

	info, err := os.Stat(path)
	if err != nil {
		return item, fmt.Errorf("lendo metadados do arquivo: %w", err)
	}

	ref, err := newRef(v.now())
	if err != nil {
		return item, err
	}

	// Extensao neutralizada: se o cofre acabar dentro de um diretorio servido
	// pela web (usuario apontou data_dir para public_html), o arquivo nao pode
	// ser executado pelo servidor.
	vaultPath := filepath.Join(v.vaultSubdir(), ref+v.neutralizedExt())
	if err := os.MkdirAll(filepath.Dir(vaultPath), 0o700); err != nil {
		return item, fmt.Errorf("%w: %v", ErrVaultUnwritable, err)
	}

	// 2 e 3. Copia e verifica ANTES de tocar no original.
	copiedSHA, size, err := copyAndVerify(path, vaultPath)
	if err != nil {
		_ = os.Remove(vaultPath)
		return item, fmt.Errorf("%w: %v", ErrVaultUnwritable, err)
	}
	if copiedSHA != atual {
		_ = os.Remove(vaultPath)
		return item, fmt.Errorf("%w: copia saiu com hash %s, original tem %s",
			ErrVaultUnwritable, short(copiedSHA), short(atual))
	}

	// Neutralizacao: sem execucao, sem escrita, e sem nenhum acesso para
	// grupo ou outros. O diretorio do cofre ja e 0700 e a extensao ja foi
	// trocada; isto fecha o ultimo caminho.
	//
	// 0400 e nao 0000 de proposito: o dono precisa conseguir LER a copia para
	// restaurar e para o `quarantine verify` conferir o hash. Com 0000, a
	// promessa de reversibilidade morre em qualquer sistema que respeite
	// permissoes POSIX — e o Windows nao respeita, o que faz esse defeito
	// passar despercebido na estacao de trabalho e aparecer so em producao.
	if err := os.Chmod(vaultPath, 0o400); err != nil {
		// Nao e fatal: em alguns sistemas de arquivos o chmod falha. O
		// arquivo ja esta neutralizado pela extensao e pelo diretorio 0700.
		_ = err
	}

	item = store.QuarantineItem{
		Ref:            ref,
		VerdictID:      verdictID,
		OriginalPath:   path,
		VaultPath:      vaultPath,
		SHA256:         atual,
		SizeBytes:      size,
		Perms:          fmt.Sprintf("%04o", info.Mode().Perm()),
		Owner:          ownerOf(info),
		OriginalMTime:  info.ModTime(),
		QuarantinedAt:  v.now(),
		RetentionUntil: v.retentionUntil(),
		Status:         store.QuarantineActive,
	}

	// 4. Registra ANTES de remover o original. Se o processo morrer entre o
	//    registro e a remocao, sobra um item registrado com o arquivo ainda
	//    no lugar — inofensivo e detectavel. Na ordem inversa, sobraria um
	//    arquivo no cofre sem registro de como restaura-lo: lixo indecifravel.
	if err := v.store.InsertQuarantineItem(ctx, item); err != nil {
		_ = os.Remove(vaultPath)
		return item, fmt.Errorf("registrando item de quarentena: %w", err)
	}

	if err := os.Remove(path); err != nil {
		// O arquivo continua no lugar e o item esta registrado. Marca como
		// falha para o painel mostrar "nao foi possivel neutralizar" em vez
		// de mentir que quarentenou.
		_ = v.store.ForcePurge(ctx, ref)
		_ = os.Remove(vaultPath)
		return item, fmt.Errorf("copia feita mas nao foi possivel remover o original %s: %w", path, err)
	}

	return item, nil
}

// Restore devolve o arquivo ao caminho original, byte a byte.
func (v *Vault) Restore(ctx context.Context, ref string) (store.QuarantineItem, error) {
	item, err := v.store.GetQuarantineItem(ctx, ref)
	if err != nil {
		return item, err
	}
	if item.Status != store.QuarantineActive {
		return item, fmt.Errorf("%w: %s esta como %q", ErrNotInVault, ref, item.Status)
	}

	// A copia no cofre ainda e o que registramos? Restaurar um arquivo
	// diferente do que foi quarentenado seria pior que nao restaurar.
	atual, err := baseline.HashFile(item.VaultPath)
	if err != nil {
		return item, fmt.Errorf("lendo a copia no cofre: %w", err)
	}
	if atual != item.SHA256 {
		return item, fmt.Errorf("%w: registrado %s, cofre tem %s",
			ErrVaultCorrupted, short(item.SHA256), short(atual))
	}

	// Nao sobrescreve nada: se ha arquivo no caminho original, ele pode ser a
	// versao limpa que o usuario ja repos.
	if _, err := os.Stat(item.OriginalPath); err == nil {
		return item, fmt.Errorf("%w: %s", ErrRestoreTargetExists, item.OriginalPath)
	}

	if err := os.MkdirAll(filepath.Dir(item.OriginalPath), 0o755); err != nil {
		return item, fmt.Errorf("recriando diretorio de destino: %w", err)
	}

	restauradoSHA, _, err := copyAndVerify(item.VaultPath, item.OriginalPath)
	if err != nil {
		_ = os.Remove(item.OriginalPath)
		return item, fmt.Errorf("restaurando arquivo: %w", err)
	}
	if restauradoSHA != item.SHA256 {
		_ = os.Remove(item.OriginalPath)
		return item, fmt.Errorf("%w: a restauracao saiu com hash %s", ErrVaultCorrupted, short(restauradoSHA))
	}

	// Permissoes e mtime originais: restaurar tem que devolver o arquivo
	// exatamente como estava, nao "parecido com como estava".
	if perm, err := parsePerms(item.Perms); err == nil {
		_ = os.Chmod(item.OriginalPath, perm)
	}
	if !item.OriginalMTime.IsZero() {
		_ = os.Chtimes(item.OriginalPath, item.OriginalMTime, item.OriginalMTime)
	}

	if err := v.store.MarkRestored(ctx, ref, item.OriginalPath); err != nil {
		return item, fmt.Errorf("registrando restauracao: %w", err)
	}

	// A copia no cofre so sai depois de o registro confirmar a restauracao.
	if err := os.Remove(item.VaultPath); err != nil && !os.IsNotExist(err) {
		// Copia orfa no cofre e desperdicio de disco, nao risco. Nao falha a
		// restauracao por causa disso.
		_ = err
	}

	item.Status = store.QuarantineRestored
	item.RestoredAt = v.now()
	item.RestoredTo = item.OriginalPath
	return item, nil
}

// Purge remove definitivamente um item.
//
// force ignora a retencao e existe porque a constituicao permite purga
// definitiva por acao manual do usuario. Sem force, so itens expirados passam.
func (v *Vault) Purge(ctx context.Context, ref string, force bool) error {
	item, err := v.store.GetQuarantineItem(ctx, ref)
	if err != nil {
		return err
	}
	if item.Status != store.QuarantineActive {
		return fmt.Errorf("%w: %s esta como %q", ErrNotInVault, ref, item.Status)
	}

	if force {
		if err := v.store.ForcePurge(ctx, ref); err != nil {
			return err
		}
	} else {
		// O store recusa item dentro da retencao. E a ultima barreira antes
		// de uma acao irreversivel.
		if err := v.store.MarkPurged(ctx, ref, v.now()); err != nil {
			return err
		}
	}

	if err := os.Remove(item.VaultPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removendo copia do cofre: %w", err)
	}
	return nil
}

// PurgeExpired remove os itens que passaram da retencao.
//
// Devolve quantos foram purgados. So roda quando auto_purge esta ligado — o
// padrao e desligado, porque apagar arquivo do usuario e decisao dele.
func (v *Vault) PurgeExpired(ctx context.Context) (int, error) {
	itens, err := v.store.ExpiredItems(ctx, v.now())
	if err != nil {
		return 0, err
	}
	n := 0
	var erros []error
	for _, it := range itens {
		if err := v.Purge(ctx, it.Ref, false); err != nil {
			erros = append(erros, fmt.Errorf("%s: %w", it.Ref, err))
			continue
		}
		n++
	}
	return n, errors.Join(erros...)
}

// Verify confere a integridade de todos os itens ativos do cofre.
//
// Existe porque a promessa de reversibilidade so vale se puder ser conferida:
// um cofre com copias corrompidas descobre isso na hora em que o usuario mais
// precisa restaurar.
func (v *Vault) Verify(ctx context.Context) ([]string, error) {
	itens, err := v.store.ListQuarantineItems(ctx, store.QuarantineActive, 0)
	if err != nil {
		return nil, err
	}
	var problemas []string
	for _, it := range itens {
		atual, err := baseline.HashFile(it.VaultPath)
		if err != nil {
			problemas = append(problemas, fmt.Sprintf("%s: copia ilegivel em %s (%v)", it.Ref, it.VaultPath, err))
			continue
		}
		if atual != it.SHA256 {
			problemas = append(problemas, fmt.Sprintf("%s: hash diverge (registrado %s, cofre %s)",
				it.Ref, short(it.SHA256), short(atual)))
		}
	}
	return problemas, nil
}

// Helpers ---------------------------------------------------------------------

func (v *Vault) vaultSubdir() string {
	t := v.now()
	return filepath.Join(v.dir, t.Format("2006"), t.Format("01"))
}

func (v *Vault) neutralizedExt() string {
	if v.cfg.NeutralizedExtension == "" {
		return ".quarantined"
	}
	if !strings.HasPrefix(v.cfg.NeutralizedExtension, ".") {
		return "." + v.cfg.NeutralizedExtension
	}
	return v.cfg.NeutralizedExtension
}

func (v *Vault) retentionUntil() time.Time {
	if v.cfg.RetentionDays <= 0 {
		// Sem retencao definida, o item nunca expira sozinho. Melhor ocupar
		// disco que apagar arquivo por engano.
		return time.Time{}
	}
	return v.now().AddDate(0, 0, v.cfg.RetentionDays)
}

// newRef gera uma referencia unica e ordenavel por tempo.
func newRef(t time.Time) (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("gerando referencia de quarentena: %w", err)
	}
	return fmt.Sprintf("q_%s_%s", t.UTC().Format("20060102150405"), hex.EncodeToString(buf)), nil
}

// copyAndVerify copia origem->destino e devolve o sha256 do que foi ESCRITO.
//
// O hash e calculado sobre o fluxo de escrita, nao sobre a origem: e assim que
// se detecta disco cheio, escrita parcial e corrupcao no meio do caminho.
func copyAndVerify(origem, destino string) (string, int64, error) {
	src, err := os.Open(origem) // caminho vem do veredito sobre a raiz configurada
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = src.Close() }()

	dst, err := os.OpenFile(destino, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, err
	}

	h := newHasher()
	n, copyErr := io.Copy(io.MultiWriter(dst, h), src)
	if copyErr != nil {
		_ = dst.Close()
		return "", 0, copyErr
	}
	// Sync antes de declarar sucesso: sem isso, "copiei" significa apenas
	// "entreguei ao cache do sistema", e um kill do processo levaria junto o
	// unico exemplar do arquivo do usuario.
	if err := dst.Sync(); err != nil {
		_ = dst.Close()
		return "", 0, err
	}
	if err := dst.Close(); err != nil {
		return "", 0, err
	}
	return h.hex(), n, nil
}

func parsePerms(s string) (os.FileMode, error) {
	var mode uint32
	if _, err := fmt.Sscanf(s, "%o", &mode); err != nil {
		return 0, err
	}
	return os.FileMode(mode), nil
}

func short(sha string) string {
	if len(sha) <= 12 {
		return sha
	}
	return sha[:12]
}

// LevelAllowsAction responde se um nivel autoriza quarentena automatica.
//
// Somente confirmed. Repetido aqui, alem de schema.Verdict.Actionable(), para
// que quem chamar este pacote direto tambem passe pela mesma regra.
func LevelAllowsAction(l schema.Level) bool {
	return l == schema.LevelConfirmed
}
