// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"bytes"
	"fmt"
	"log"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"
)

// Cliq API reference: https://www.zoho.com/cliq/help/restapi/v2/

// Cliq constants
const (
	tableSlideType = "table"
	textSlideType  = "text"
	botName        = "Falco Sidekick"
)

// Table slide fields
var tableSlideHeaders = []string{"field", "value"}

// Emoji runes
const (
	emergencyEmoji   = '\U0001F6A8'
	errorEmoji       = '\U0001F7E0'
	warningEmoji     = '\U0001F7E1'
	noticeEmoji      = '\U0001F535'
	informationEmoji = '\U0001F7E2'
	debugEmoji       = '\U000026AA'
)

// Cliq table slide: https://www.zoho.com/cliq/help/restapi/v2/#attaching_content_table

// Table slide row
type cliqTableRow struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

// Table slide data
type cliqTableData struct {
	Headers []string       `json:"headers"`
	Rows    []cliqTableRow `json:"rows"`
}

// Slide
type cliqSlide struct {
	Type  string      `json:"type"`
	Title string      `json:"title,omitempty"`
	Data  interface{} `json:"data"`
}

type cliqBot struct {
	Name  string `json:"name"`
	Image string `json:"image,omitempty"`
}

// Payload
type cliqPayload struct {
	Text   string      `json:"text"`
	Bot    cliqBot     `json:"bot,omitempty"`
	Slides []cliqSlide `json:"slides,omitempty"`
}

func newCliqPayload(payload types.Payload, config *types.Configuration) cliqPayload {
	var (
		cpayload cliqPayload
		field    cliqTableRow
		table    cliqTableData
	)

	cpayload.Bot.Name = botName

	if config.Cliq.MessageFormatTemplate != nil {
		buf := &bytes.Buffer{}
		if err := config.Cliq.MessageFormatTemplate.Execute(buf, payload); err != nil {
			log.Printf("[ERROR] : Cliq - Error expanding Cliq message %v", err)
		} else {
			cpayload.Text = buf.String()

			if config.Cliq.OutputFormat == All || config.Cliq.OutputFormat == Text || config.Cliq.OutputFormat == "" {
				slide := cliqSlide{
					Type: textSlideType,
					Data: payload.TriggerName,
				}
				cpayload.Slides = append(cpayload.Slides, slide)
			}
		}
	} else {
		cpayload.Text = payload.TriggerName
	}

	if config.Cliq.OutputFormat == All || config.Cliq.OutputFormat == Fields || config.Cliq.OutputFormat == "" {
		field.Field = "Event"
		field.Value = payload.TriggerName
		table.Rows = append(table.Rows, field)

		if payload.Hostname != "" {
			field.Field = Hostname
			field.Value = payload.Hostname
			table.Rows = append(table.Rows, field)
		}

		for _, i := range getSortedStringKeys(payload.OutputFields) {
			j := payload.OutputFields[i]
			switch j.(type) {
			case string:
				field.Field = i
				field.Value = payload.OutputFields[i].(string)
				table.Rows = append(table.Rows, field)
			default:
				field.Field = i
				field.Value = fmt.Sprint(j)
				table.Rows = append(table.Rows, field)
			}
		}

		field.Field = Time
		field.Value = fmt.Sprint(payload.Timestamp)
		table.Rows = append(table.Rows, field)

		table.Headers = tableSlideHeaders
		slide := cliqSlide{
			Type: tableSlideType,
			Data: &table,
		}
		cpayload.Slides = append(cpayload.Slides, slide)
	}

	if config.Cliq.UseEmoji {
		var emoji rune
		switch payload.Priority {
		case "Alert":
			emoji = errorEmoji
		case "Log":
			emoji = informationEmoji
		default:
			emoji = '?'
		}
		cpayload.Text = fmt.Sprintf("%c %s", emoji, cpayload.Text)
	}

	if config.Cliq.Icon != "" {
		cpayload.Bot.Image = config.Cliq.Icon
	} else {
		cpayload.Bot.Image = DefaultIconURL
	}

	return cpayload
}

// CliqPost posts event to cliq
func (c *Client) CliqPost(Payload types.Payload) {
	c.Stats.Cliq.Add(Total, 1)

	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()
	c.AddHeader(ContentTypeHeaderKey, "application/json")
	err := c.Post(newCliqPayload(Payload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:cliq", "status:error"})
		c.Stats.Cliq.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "cliq", "status": Error}).Inc()
		log.Printf("[ERROR] : Cliq - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:cliq", "status:ok"})
	c.Stats.Cliq.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "cliq", "status": OK}).Inc()
}

func (c *Client) WatchCliqPostAlerts() error {
	uid := uuid.Must(uuid.NewRandom()).String()

	conn := make(chan types.Payload, 1000)
	defer close(conn)
	addAlertStruct(uid, conn)
	defer removeAlertStruct(uid)

	for AlertRunning {
		select {
		// case <-Context().Done():
		// 	return nil
		case resp := <-conn:
			c.CliqPost(resp)
		default:
			time.Sleep(time.Millisecond * 10)

		}
	}

	return nil
}
