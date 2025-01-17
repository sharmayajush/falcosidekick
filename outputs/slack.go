// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"fmt"
	"log"

	"github.com/falcosecurity/falcosidekick/types"
)

// Field
type slackAttachmentField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// Attachment
type slackAttachment struct {
	Fallback   string                 `json:"fallback"`
	Color      string                 `json:"color"`
	Text       string                 `json:"text,omitempty"`
	Fields     []slackAttachmentField `json:"fields"`
	Footer     string                 `json:"footer,omitempty"`
	FooterIcon string                 `json:"footer_icon,omitempty"`
}

// Payload
type slackPayload struct {
	Text        string            `json:"text,omitempty"`
	Username    string            `json:"username,omitempty"`
	IconURL     string            `json:"icon_url,omitempty"`
	Channel     string            `json:"channel,omitempty"`
	Attachments []slackAttachment `json:"attachments,omitempty"`
}

func newSlackPayload(payload types.Payload, config *types.Configuration) slackPayload {
	var (
		messageText string
		attachments []slackAttachment
		attachment  slackAttachment
		fields      []slackAttachmentField
		field       slackAttachmentField
	)
	if config.Slack.OutputFormat == All || config.Slack.OutputFormat == Fields || config.Slack.OutputFormat == "" {
		field.Title = Priority
		field.Value = payload.Priority
		field.Short = true
		fields = append(fields, field)
		field.Title = Source
		field.Value = payload.OutputFields["pod_name"].(string)
		field.Short = true
		fields = append(fields, field)
		if payload.Hostname != "" {
			field.Title = Hostname
			field.Value = payload.Hostname
			field.Short = true
			fields = append(fields, field)
		}
		for _, i := range getSortedStringKeys(payload.OutputFields) {
			j := payload.OutputFields[i]
			switch v := j.(type) {
			case string:
				field.Title = i
				field.Value = payload.OutputFields[i].(string)
				if len([]rune(payload.OutputFields[i].(string))) < 36 {
					field.Short = true
				} else {
					field.Short = false
				}
				fields = append(fields, field)
			default:
				vv := fmt.Sprint(v)
				field.Title = i
				field.Value = vv
				if len([]rune(vv)) < 36 {
					field.Short = true
				} else {
					field.Short = false
				}
				fields = append(fields, field)

			}
		}

		field.Title = Time
		field.Short = false
		field.Value = fmt.Sprint(payload.Timestamp)
		fields = append(fields, field)

		attachment.Footer = DefaultFooter
		if config.Slack.Footer != "" {
			attachment.Footer = config.Slack.Footer
		}
		attachment.Fields = fields
	}

	if config.Slack.MessageFormatTemplate != nil {
		buf := &bytes.Buffer{}
		if err := config.Slack.MessageFormatTemplate.Execute(buf, payload); err != nil {
			log.Printf("[ERROR] : Slack - Error expanding Slack message %v", err)
		} else {
			messageText = buf.String()
		}
	}

	var color string
	switch payload.Priority {
	case "Alert":
		color = Orange
	case "Log":
		color = LigthBlue
	}
	attachment.Color = color

	attachments = append(attachments, attachment)

	s := slackPayload{
		Text:        messageText,
		Username:    config.Slack.Username,
		IconURL:     config.Slack.Icon,
		Attachments: attachments}

	if config.Slack.Channel != "" {
		s.Channel = config.Slack.Channel
	}

	return s
}

// SlackPost posts event to Slack
func (c *Client) SlackPost(payload types.Payload) {
	// c.Stats.Slack.Add(Total, 1)

	err := c.Post(newSlackPayload(payload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:slack", "status:error"})
		// c.Stats.Slack.Add(Error, 1)
		// c.PromStats.Outputs.With(map[string]string{"destination": "slack", "status": Error}).Inc()
		log.Printf("[ERROR] : Slack - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:slack", "status:ok"})
	// c.Stats.Slack.Add(OK, 1)
	// c.PromStats.Outputs.With(map[string]string{"destination": "slack", "status": OK}).Inc()
}

// func (c *Client) WatchSlackAlerts() error {
// 	// c.SlackPost()
// 	// uid := "slack"

// 	// conn := make(chan types.Payload, 1000)
// 	// defer close(conn)
// 	// addAlertStruct(uid, conn)
// 	// defer removeAlertStruct(uid)

// 	// for AlertRunning {
// 	// 	select {
// 	// 	// case <-Context().Done():
// 	// 	// 	return nil
// 	// 	case resp := <-conn:
// 	// 		c.SlackPost(resp)
// 	// 	default:
// 	// 		time.Sleep(time.Millisecond * 10)

// 	// 	}
// 	// }

// 	// return nil
// }
