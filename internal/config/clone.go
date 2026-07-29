package config

// Clone returns an INDEPENDENT copy of the configuration.
//
// A shallow copy will not do: Config carries maps and slices (engines,
// whitelist, exclude, webhooks, recipients), and a shallow copy would keep
// pointing at the same structures. The panel edits the configuration while a
// cycle may be reading it — without a deep copy the two mutate the same map,
// which is a genuine data race: the kind `-race` reports and that in production
// shows up as an impossible value or a map panic.
//
// The cost is irrelevant: the configuration has dozens of fields and is cloned
// once per HTTP request, never in a hot loop.
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
