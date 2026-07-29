package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// QuarantineStatus e o estado de um item no cofre.
type QuarantineStatus string

const (
	QuarantineActive   QuarantineStatus = "quarantined"
	QuarantineRestored QuarantineStatus = "restored"
	QuarantinePurged   QuarantineStatus = "purged"
)

// QuarantineItem e o registro que torna a quarentena reversivel.
//
// Sem estes metadados o arquivo no cofre e lixo indecifravel: nao se sabe de
// onde veio, com que permissao voltar nem se ele ainda e o mesmo arquivo.
type QuarantineItem struct {
	Ref           string
	VerdictID     string
	OriginalPath  string
	VaultPath     string
	SHA256        string
	SizeBytes     int64
	Perms         string
	Owner         string
	OriginalMTime time.Time

	QuarantinedAt  time.Time
	RetentionUntil time.Time
	Status         QuarantineStatus
	RestoredAt     time.Time
	RestoredTo     string
	PurgedAt       time.Time
	Note           string
}

// Expired responde se o item ja passou da retencao configurada.
func (q QuarantineItem) Expired(now time.Time) bool {
	if q.Status != QuarantineActive || q.RetentionUntil.IsZero() {
		return false
	}
	return now.After(q.RetentionUntil)
}

// InsertQuarantineItem registra um item recem-movido para o cofre.
func (s *Store) InsertQuarantineItem(ctx context.Context, it QuarantineItem) error {
	if it.Ref == "" || it.VaultPath == "" || it.OriginalPath == "" || it.SHA256 == "" {
		return errors.New("item de quarentena sem ref, caminhos ou hash nao e restauravel")
	}
	if it.Status == "" {
		it.Status = QuarantineActive
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO quarantine_items (
			ref, verdict_id, original_path, vault_path, sha256, size_bytes,
			perms, owner, original_mtime, quarantined_at, retention_until,
			status, note
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		it.Ref, nullString(it.VerdictID), it.OriginalPath, it.VaultPath, it.SHA256,
		it.SizeBytes, it.Perms, nullString(it.Owner), nullTime(it.OriginalMTime),
		formatTime(orNow(it.QuarantinedAt)), nullTime(it.RetentionUntil),
		string(it.Status), nullString(it.Note))
	if err != nil {
		return fmt.Errorf("registrando item de quarentena %s: %w", it.Ref, err)
	}
	return nil
}

// GetQuarantineItem busca um item por referencia.
func (s *Store) GetQuarantineItem(ctx context.Context, ref string) (QuarantineItem, error) {
	row := s.db.QueryRowContext(ctx, quarantineSelect+` WHERE ref = ?`, ref)
	it, err := scanQuarantineItem(row)
	if errors.Is(err, sql.ErrNoRows) {
		return it, fmt.Errorf("%w: item de quarentena %s", ErrNotFound, ref)
	}
	return it, err
}

// ListQuarantineItems lista o cofre. status vazio = todos.
func (s *Store) ListQuarantineItems(ctx context.Context, status QuarantineStatus, limit int) ([]QuarantineItem, error) {
	q := quarantineSelect
	var args []any
	if status != "" {
		q += ` WHERE status = ?`
		args = append(args, string(status))
	}
	q += ` ORDER BY quarantined_at DESC`
	if limit > 0 {
		q += fmt.Sprintf(` LIMIT %d`, limit)
	}

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("listando quarentena: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []QuarantineItem
	for rows.Next() {
		it, err := scanQuarantineItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ExpiredItems devolve os itens ativos cuja retencao ja venceu.
//
// Note que a consulta filtra por status ativo: item ja restaurado ou purgado
// nunca reaparece como candidato a purga.
func (s *Store) ExpiredItems(ctx context.Context, now time.Time) ([]QuarantineItem, error) {
	rows, err := s.db.QueryContext(ctx,
		quarantineSelect+` WHERE status = ? AND retention_until IS NOT NULL AND retention_until < ?
		ORDER BY retention_until`,
		string(QuarantineActive), formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("buscando itens expirados: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []QuarantineItem
	for rows.Next() {
		it, err := scanQuarantineItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// MarkRestored registra a devolucao do arquivo ao lugar de origem.
func (s *Store) MarkRestored(ctx context.Context, ref, restoredTo string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE quarantine_items SET status = ?, restored_at = ?, restored_to = ?
		WHERE ref = ? AND status = ?`,
		string(QuarantineRestored), nowUTC(), restoredTo, ref, string(QuarantineActive))
	if err != nil {
		return fmt.Errorf("marcando %s como restaurado: %w", ref, err)
	}
	return checkAffected(res, ref)
}

// MarkPurged registra a remocao definitiva.
//
// So aceita itens ativos e expirados: e a ultima barreira do Principio I no
// nivel do banco, para que uma chamada errada em outro pacote nao consiga
// apagar o registro de um item ainda dentro da retencao.
func (s *Store) MarkPurged(ctx context.Context, ref string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE quarantine_items SET status = ?, purged_at = ?
		WHERE ref = ? AND status = ? AND retention_until IS NOT NULL AND retention_until < ?`,
		string(QuarantinePurged), nowUTC(), ref, string(QuarantineActive), formatTime(now))
	if err != nil {
		return fmt.Errorf("marcando %s como purgado: %w", ref, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %s nao esta ativo ou ainda esta dentro do periodo de retencao", ErrNotFound, ref)
	}
	return nil
}

// ForcePurge registra remocao definitiva pedida explicitamente pelo usuario,
// sem esperar a retencao. E o unico caminho que ignora o prazo, e existe
// porque a constituicao permite "purga definitiva por acao manual do usuario".
func (s *Store) ForcePurge(ctx context.Context, ref string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE quarantine_items SET status = ?, purged_at = ?
		WHERE ref = ? AND status = ?`,
		string(QuarantinePurged), nowUTC(), ref, string(QuarantineActive))
	if err != nil {
		return fmt.Errorf("purgando %s: %w", ref, err)
	}
	return checkAffected(res, ref)
}

// CountQuarantine conta itens por status.
func (s *Store) CountQuarantine(ctx context.Context) (map[QuarantineStatus]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM quarantine_items GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("contando quarentena: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[QuarantineStatus]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[QuarantineStatus(st)] = n
	}
	return out, rows.Err()
}

const quarantineSelect = `
	SELECT ref, verdict_id, original_path, vault_path, sha256, size_bytes,
	       perms, owner, original_mtime, quarantined_at, retention_until,
	       status, restored_at, restored_to, purged_at, note
	FROM quarantine_items`

func scanQuarantineItem(r rowScanner) (QuarantineItem, error) {
	var (
		it                             QuarantineItem
		verdictID, owner, note         sql.NullString
		mtime, retention               sql.NullString
		restoredAt, restoredTo, purged sql.NullString
		quarantinedAt, status          string
	)
	err := r.Scan(&it.Ref, &verdictID, &it.OriginalPath, &it.VaultPath, &it.SHA256,
		&it.SizeBytes, &it.Perms, &owner, &mtime, &quarantinedAt, &retention,
		&status, &restoredAt, &restoredTo, &purged, &note)
	if err != nil {
		return it, err
	}
	it.VerdictID = strFromNull(verdictID)
	it.Owner = strFromNull(owner)
	it.Note = strFromNull(note)
	it.OriginalMTime = timeFromNull(mtime)
	it.QuarantinedAt = parseTime(quarantinedAt)
	it.RetentionUntil = timeFromNull(retention)
	it.Status = QuarantineStatus(status)
	it.RestoredAt = timeFromNull(restoredAt)
	it.RestoredTo = strFromNull(restoredTo)
	it.PurgedAt = timeFromNull(purged)
	return it, nil
}
