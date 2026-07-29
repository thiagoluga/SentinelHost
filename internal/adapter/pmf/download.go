package pmf

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// maxRulesBytes limita o download das regras. O php.yar tem dezenas de KB;
// 16 MiB e folgado e impede que uma resposta anomala encha o disco da conta.
const maxRulesBytes = 16 << 20

// downloadFile baixa um arquivo para dest de forma atomica.
//
// Escrever direto no destino deixaria regras pela metade se a conexao caisse
// no meio — e regras truncadas fazem o yara falhar em todo ciclo seguinte,
// transformando uma queda de rede momentanea num engine permanentemente morto.
func downloadFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("montando download: %w", err)
	}
	req.Header.Set("User-Agent", "SentinelHost (+https://github.com/thiagoluga/SentinelHost)")

	client := &http.Client{Timeout: time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("baixando %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download de %s respondeu %s", url, resp.Status)
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".download-*")
	if err != nil {
		return fmt.Errorf("criando arquivo temporario: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxRulesBytes))
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("gravando download: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("fechando download: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("download de %s veio vazio", url)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("ajustando permissao: %w", err)
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("instalando em %s: %w", dest, err)
	}
	return nil
}
