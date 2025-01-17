// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"log"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

type discordPayload struct {
	Content   string                `json:"content"`
	AvatarURL string                `json:"avatar_url,omitempty"`
	Embeds    []discordEmbedPayload `json:"embeds"`
}

type discordEmbedPayload struct {
	Title       string                     `json:"title"`
	URL         string                     `json:"url"`
	Description string                     `json:"description"`
	Color       string                     `json:"color"`
	Fields      []discordEmbedFieldPayload `json:"fields"`
}

type discordEmbedFieldPayload struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

func newDiscordPayload(payload types.Payload, config *types.Configuration) discordPayload {
	var iconURL string
	if config.Discord.Icon != "" {
		iconURL = config.Discord.Icon
	} else {
		iconURL = DefaultIconURL
	}

	var color string
	switch payload.Priority {
	case "Medium":
		color = "11027200" // dark orange
	case "Low":
		color = "3447003" // blue
	}

	embeds := make([]discordEmbedPayload, 0)

	embedFields := make([]discordEmbedFieldPayload, 0)
	var embedField discordEmbedFieldPayload
	if payload.Hostname != "" {
		embedFields = append(embedFields, discordEmbedFieldPayload{Hostname, payload.Hostname, true})
	}
	embedFields = append(embedFields, discordEmbedFieldPayload{"Trigger Name", payload.TriggerName, true})

	for i, j := range payload.OutputFields {
		switch v := j.(type) {
		case string:
			jj := j.(string)
			if jj == "" {
				continue
			}
			embedField = discordEmbedFieldPayload{i, fmt.Sprintf("```%s```", jj), true}
		default:
			vv := fmt.Sprint(v)
			embedField = discordEmbedFieldPayload{i, fmt.Sprintf("```%v```", vv), true}
		}
		embedFields = append(embedFields, embedField)
	}

	embedFields = append(embedFields, discordEmbedFieldPayload{Time, fmt.Sprint(payload.Timestamp), true})

	embed := discordEmbedPayload{
		Title:       payload.ComponentName,
		Description: payload.TriggerName,
		Color:       color,
		Fields:      embedFields,
	}
	embeds = append(embeds, embed)
	fmt.Println("embeds: ", embeds)

	return discordPayload{
		Content:   fmt.Sprintf("🚨 %s: %s", payload.Priority, payload.TriggerName),
		AvatarURL: iconURL,
		Embeds:    embeds,
	}
}

// DiscordPost posts events to discord
func (c *Client) DiscordPost(Payload types.Payload) {
	// c.Stats.Discord.Add(Total, 1)

	err := c.Post(newDiscordPayload(Payload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:discord", "status:error"})
		// c.Stats.Discord.Add(Error, 1)
		// c.PromStats.Outputs.With(map[string]string{"destination": "discord", "status": Error}).Inc()
		log.Printf("[ERROR] : Discord - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:discord", "status:ok"})
	// c.Stats.Discord.Add(OK, 1)
	// c.PromStats.Outputs.With(map[string]string{"destination": "discord", "status": OK}).Inc()
}

func (c *Client) WatchDiscordAlerts() error {
	uid := "Discord"

	conn := make(chan types.Payload, 1000)
	defer close(conn)
	addAlertStruct(uid, conn)
	defer removeAlertStruct(uid)

	fmt.Println("discord running")
	for AlertRunning {
		select {
		case resp := <-conn:
			c.DiscordPost(resp)
		default:
			time.Sleep(time.Millisecond * 10)

		}
	}
	fmt.Println("discord stopped")
	return nil
}
