// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	textTemplate "text/template"

	"github.com/falcosecurity/falcosidekick/types"
)

var (
	gotifyMarkdownTmpl = `- **Priority**: {{ .Priority }}
- **Rule**: {{ .Rule }}
- **Output**: {{ .Output }}
- **Source**: {{ .Source }}
- **Tags**: {{ range .Tags }}{{ . }} {{ end }}
- **Time**: {{ .Time }}
- **Fields**:
{{ range $key, $value := .OutputFields }}	- **{{ $key }}**: {{ $value }}
{{ end -}}
`
	gotifyTextTmpl = `Priority: {{ .Priority }}
Rule: {{ .Rule }}
Output: {{ .Output }}
Source: {{ .Source }}
Tags: {{ range .Tags }}{{ . }} {{ end }}
Time: {{ .Time }}
Fields:
{{ range $key, $value := .OutputFields }}- {{ $key }}: {{ $value }}
{{ end -}}
`
)

type gotifyPayload struct {
	Title    string                       `json:"title"`
	Priority int                          `json:"priority,omitempty"`
	Message  string                       `json:"message"`
	Extras   map[string]map[string]string `json:"extras"`
}

func newGotifyPayload(payload types.Payload, config *types.Configuration) gotifyPayload {
	g := gotifyPayload{
		Title:    "[" + payload.ComponentName + "] [" + payload.TriggerName + "] ",
		Priority: int(types.Priority(payload.Priority)),
		Extras: map[string]map[string]string{
			"client::display": {
				"contentType": "text/markdown",
			},
		},
		//Message: payload.Output,
	}

	var ttmpl *textTemplate.Template
	var outtext bytes.Buffer
	var messageBytes []byte
	var format string
	var err error
	switch strings.ToLower(config.Gotify.Format) {
	case Plaintext, Text:
		format = "plaintext"
		ttmpl, _ = textTemplate.New("gotify").Parse(gotifyTextTmpl)
		err = ttmpl.Execute(&outtext, payload)
	case JSON:
		format = "plaintext"
		messageBytes, err = json.Marshal(payload)
	default:
		format = "markdown"
		ttmpl, _ = textTemplate.New("gotify").Parse(gotifyMarkdownTmpl)
		err = ttmpl.Execute(&outtext, payload)
	}
	if err != nil {
		log.Printf("[ERROR] : Gotify - %v\n", err)
		return g
	}

	switch strings.ToLower(config.Gotify.Format) {
	case JSON:
		g.Message = string(messageBytes)
	default:
		g.Message = outtext.String()
	}

	g.Extras["client::display"]["contentType"] = format

	return g
}

// GotifyPost posts event to Gotify
func (c *Client) GotifyPost(payload types.Payload) {
	// c.Stats.Gotify.Add(Total, 1)

	if c.Config.Gotify.Token != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.AddHeader("X-Gotify-Key", c.Config.Gotify.Token)
	}

	err := c.Post(newGotifyPayload(payload, c.Config))
	if err != nil {
		c.setGotifyErrorMetrics()
		log.Printf("[ERROR] : Gotify - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:gotify", "status:ok"})
	// c.Stats.Gotify.Add(OK, 1)
	// c.PromStats.Outputs.With(map[string]string{"destination": "gotify", "status": OK}).Inc()
}

// setGotifyErrorMetrics set the error stats
func (c *Client) setGotifyErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:gotify", "status:error"})
	// c.Stats.Gotify.Add(Error, 1)
	// c.PromStats.Outputs.With(map[string]string{"destination": "gotify", "status": Error}).Inc()
}
