// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"fmt"
	"log"
	"strings"
	textTemplate "text/template"

	"github.com/falcosecurity/falcosidekick/types"
)

func markdownV2EscapeText(text interface{}) string {

	replacer := strings.NewReplacer(
		"_", "\\_", "*", "\\*", "[", "\\[", "]", "\\]", "(",
		"\\(", ")", "\\)", "~", "\\~", "`", "\\`", ">", "\\>",
		"#", "\\#", "+", "\\+", "-", "\\-", "=", "\\=", "|",
		"\\|", "{", "\\{", "}", "\\}", ".", "\\.", "!", "\\!",
	)

	return replacer.Replace(fmt.Sprintf("%v", text))
}

// • *Tags*: {{ range .Tags }}{{markdownV2EscapeText . }} {{ end }}
// **Output**: {{markdownV2EscapeText .Output }}
var (
	telegramMarkdownV2Tmpl = `*\[{{markdownV2EscapeText .Hostname }}\] \[{{markdownV2EscapeText .ComponentName }}\] {{markdownV2EscapeText .Priority }}*

• *Trigger Name*: {{markdownV2EscapeText .TriggerName }}
• *Cluster Name*: {{markdownV2EscapeText .ClusterName }}
• *Filter Query*: {{markdownV2EscapeText .FilterQuery }}
• *Fields*:
{{ range $key, $value := .OutputFields }}	  • *{{markdownV2EscapeText $key }}*: {{markdownV2EscapeText $value }}
{{ end }}

`
)

// Payload
type telegramPayload struct {
	Text                  string `json:"text,omitempty"`
	ParseMode             string `json:"parse_mode,omitempty"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview,omitempty"`
	ChatID                string `json:"chat_id,omitempty"`
}

func newTelegramPayload(payload types.Payload, config *types.Configuration) telegramPayload {
	telegramPayload := telegramPayload{

		ParseMode:             "MarkdownV2",
		DisableWebPagePreview: true,
		ChatID:                config.Telegram.ChatID,
	}

	// template engine
	var textBuffer bytes.Buffer
	funcs := textTemplate.FuncMap{
		"markdownV2EscapeText": markdownV2EscapeText,
	}
	ttmpl, _ := textTemplate.New("telegram").Funcs(funcs).Parse(telegramMarkdownV2Tmpl)
	err := ttmpl.Execute(&textBuffer, payload)
	if err != nil {
		log.Printf("[ERROR] : Telegram - %v\n", err)
		return telegramPayload
	}
	telegramPayload.Text = textBuffer.String()

	return telegramPayload
}

// TelegramPost posts event to Telegram
func (c *Client) TelegramPost(payload types.Payload) {
	// c.Stats.Telegram.Add(Total, 1)

	err := c.Post(newTelegramPayload(payload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:telegram", "status:error"})
		// c.Stats.Telegram.Add(Error, 1)
		// c.PromStats.Outputs.With(map[string]string{"destination": "telegram", "status": Error}).Inc()
		log.Printf("[ERROR] : Telegram - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:telegram", "status:ok"})
	// c.Stats.Telegram.Add(OK, 1)
	// c.PromStats.Outputs.With(map[string]string{"destination": "telegram", "status": OK}).Inc()
}
