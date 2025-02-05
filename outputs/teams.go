// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"log"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"
)

type teamsFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type teamsSection struct {
	ActivityTitle    string      `json:"activityTitle"`
	ActivitySubTitle string      `json:"activitySubtitle"`
	ActivityImage    string      `json:"activityImage,omitempty"`
	Text             string      `json:"text"`
	Facts            []teamsFact `json:"facts,omitempty"`
}

// Payload
type teamsPayload struct {
	Type       string         `json:"@type"`
	Summary    string         `json:"summary,omitempty"`
	ThemeColor string         `json:"themeColor,omitempty"`
	Sections   []teamsSection `json:"sections"`
}

func newTeamsPayload(payload types.Payload, config *types.Configuration) teamsPayload {
	var (
		sections []teamsSection
		section  teamsSection
		facts    []teamsFact
		fact     teamsFact
	)

	section.ActivityTitle = "Kubearmor Sidekick"
	section.ActivitySubTitle = fmt.Sprint(payload.Timestamp)

	if config.Teams.ActivityImage != "" {
		section.ActivityImage = config.Teams.ActivityImage
	}

	if config.Teams.OutputFormat == All || config.Teams.OutputFormat == "facts" || config.Teams.OutputFormat == "" {
		for i, j := range payload.OutputFields {
			switch v := j.(type) {
			case string:
				fact.Name = i
				fact.Value = v
			default:
				vv := fmt.Sprint(v)
				fact.Name = i
				fact.Value = vv

			}

			facts = append(facts, fact)
		}

		fact.Name = Priority
		fact.Value = payload.TriggerName
		facts = append(facts, fact)
		fact.Name = Source
		fact.Value = "alert"
		facts = append(facts, fact)
		if payload.Hostname != "" {
			fact.Name = Hostname
			fact.Value = payload.Hostname
			facts = append(facts, fact)
		}
	}

	section.Facts = facts

	var color string
	switch payload.Priority {
	case "Alert":
		color = "ff5400"
	case "Log":
		color = "68c2ff"
	}

	sections = append(sections, section)

	t := teamsPayload{
		Type:       "MessageCard",
		Summary:    "This is an alert by accuknox",
		ThemeColor: color,
		Sections:   sections,
	}

	return t
}

// TeamsPost posts event to Teams
func (c *Client) TeamsPost(payload types.Payload) {
	// c.Stats.Teams.Add(Total, 1)

	err := c.Post(newTeamsPayload(payload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:teams", "status:error"})
		// c.Stats.Teams.Add(Error, 1)
		// c.PromStats.Outputs.With(map[string]string{"destination": "teams", "status": Error}).Inc()
		log.Printf("[ERROR] : Teams - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:teams", "status:ok"})
	// c.Stats.Teams.Add(OK, 1)
	// c.PromStats.Outputs.With(map[string]string{"destination": "teams", "status": OK}).Inc()
}

func (c *Client) WatchTeamsPostAlerts() error {
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
			c.TeamsPost(resp)
		default:
			time.Sleep(time.Millisecond * 10)

		}
	}

	return nil
}
