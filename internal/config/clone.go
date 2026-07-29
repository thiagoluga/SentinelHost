package config

// Clone devolve uma copia INDEPENDENTE da configuracao.
//
// Copia rasa nao serve: Config carrega mapas e fatias (engines, whitelist,
// exclude, webhooks, destinatarios), e uma copia rasa continuaria apontando
// para as mesmas estruturas. O painel edita a configuracao enquanto um ciclo
// pode estar lendo — sem copia profunda, os dois mexem no mesmo mapa e o
// resultado e uma corrida de dados de verdade, do tipo que o `-race` acusa e
// que em producao aparece como valor impossivel ou panico de mapa.
//
// O custo e irrelevante: a configuracao tem dezenas de campos e e clonada em
// requisicao HTTP, nunca em laco quente.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	out := *c

	out.General.Roots = cloneStrings(c.General.Roots)
	out.Limits.Exclude = cloneStrings(c.Limits.Exclude)
	out.Verdict.Whitelist = cloneStrings(c.Verdict.Whitelist)
	out.Alerts.Email.To = cloneStrings(c.Alerts.Email.To)
	out.Alerts.Email.Levels = cloneStrings(c.Alerts.Email.Levels)

	if c.Engines != nil {
		out.Engines = make(map[string]Engine, len(c.Engines))
		for k, v := range c.Engines {
			v.ExtraArgs = cloneStrings(v.ExtraArgs)
			out.Engines[k] = v
		}
	}

	if c.Alerts.Webhooks != nil {
		out.Alerts.Webhooks = make([]Webhook, len(c.Alerts.Webhooks))
		for i, w := range c.Alerts.Webhooks {
			w.Events = cloneStrings(w.Events)
			out.Alerts.Webhooks[i] = w
		}
	}

	return &out
}

func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
