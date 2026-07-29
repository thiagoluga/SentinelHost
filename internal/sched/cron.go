package sched

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule e uma agenda cron de 5 campos.
//
// Implementacao propria e minima em vez de uma dependencia: o projeto usa
// exatamente um formato de agenda, para um caso de uso, e "sem dependencias
// externas obrigatorias" e um principio, nao uma preferencia (Principio VII).
type Schedule struct {
	Minutes  []int
	Hours    []int
	Days     []int
	Months   []int
	Weekdays []int
}

// ParseCron interpreta "minuto hora dia mes diadasemana".
//
// Suporta `*`, listas (`1,15`), intervalos (`1-5`) e passos (`*/15`). Nao
// suporta nomes (`MON`, `JAN`) nem `@daily`: o que a ferramenta gera e
// documenta usa so numeros, e aceitar sintaxe que nao geramos aumentaria a
// superficie de bug sem beneficio.
func ParseCron(expr string) (Schedule, error) {
	campos := strings.Fields(expr)
	if len(campos) != 5 {
		return Schedule{}, fmt.Errorf("cron precisa de 5 campos, veio %d em %q", len(campos), expr)
	}

	var s Schedule
	var err error
	if s.Minutes, err = parseField(campos[0], 0, 59); err != nil {
		return s, fmt.Errorf("campo minuto: %w", err)
	}
	if s.Hours, err = parseField(campos[1], 0, 23); err != nil {
		return s, fmt.Errorf("campo hora: %w", err)
	}
	if s.Days, err = parseField(campos[2], 1, 31); err != nil {
		return s, fmt.Errorf("campo dia: %w", err)
	}
	if s.Months, err = parseField(campos[3], 1, 12); err != nil {
		return s, fmt.Errorf("campo mes: %w", err)
	}
	if s.Weekdays, err = parseField(campos[4], 0, 6); err != nil {
		return s, fmt.Errorf("campo dia da semana: %w", err)
	}
	return s, nil
}

// Matches responde se o instante bate com a agenda.
//
// Segue a regra do cron tradicional: quando dia-do-mes e dia-da-semana estao
// ambos restritos, basta UM deles casar. E contraintuitivo, mas e o que todo
// administrador espera de uma linha de cron.
func (s Schedule) Matches(t time.Time) bool {
	if !contains(s.Minutes, t.Minute()) ||
		!contains(s.Hours, t.Hour()) ||
		!contains(s.Months, int(t.Month())) {
		return false
	}

	diaRestrito := len(s.Days) < 31
	semanaRestrita := len(s.Weekdays) < 7
	diaCasa := contains(s.Days, t.Day())
	semanaCasa := contains(s.Weekdays, int(t.Weekday()))

	switch {
	case diaRestrito && semanaRestrita:
		return diaCasa || semanaCasa
	case diaRestrito:
		return diaCasa
	case semanaRestrita:
		return semanaCasa
	default:
		return true
	}
}

func parseField(campo string, min, max int) ([]int, error) {
	var out []int
	visto := map[int]bool{}

	for _, parte := range strings.Split(campo, ",") {
		parte = strings.TrimSpace(parte)
		if parte == "" {
			return nil, fmt.Errorf("valor vazio")
		}

		passo := 1
		if base, p, ok := strings.Cut(parte, "/"); ok {
			n, err := strconv.Atoi(p)
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("passo invalido em %q", parte)
			}
			passo = n
			parte = base
		}

		inicio, fim := min, max
		switch {
		case parte == "*":
			// intervalo inteiro
		case strings.Contains(parte, "-"):
			a, b, _ := strings.Cut(parte, "-")
			var err error
			if inicio, err = strconv.Atoi(strings.TrimSpace(a)); err != nil {
				return nil, fmt.Errorf("inicio invalido em %q", parte)
			}
			if fim, err = strconv.Atoi(strings.TrimSpace(b)); err != nil {
				return nil, fmt.Errorf("fim invalido em %q", parte)
			}
		default:
			n, err := strconv.Atoi(parte)
			if err != nil {
				return nil, fmt.Errorf("valor invalido: %q", parte)
			}
			inicio, fim = n, n
		}

		if inicio < min || fim > max || inicio > fim {
			return nil, fmt.Errorf("valor fora do intervalo %d-%d: %q", min, max, parte)
		}
		for v := inicio; v <= fim; v += passo {
			if !visto[v] {
				visto[v] = true
				out = append(out, v)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("campo sem valores")
	}
	return out, nil
}

func contains(vs []int, v int) bool {
	for _, x := range vs {
		if x == v {
			return true
		}
	}
	return false
}
