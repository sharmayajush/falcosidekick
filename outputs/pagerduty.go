// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/PagerDuty/go-pagerduty"

	"github.com/falcosecurity/falcosidekick/types"
)

const (
	USEndpoint string = "https://events.pagerduty.com"
	EUEndpoint string = "https://events.eu.pagerduty.com"
)

// PagerdutyPost posts alert event to Pagerduty
func (c *Client) PagerdutyPost(payload types.Payload) {
	c.Stats.Pagerduty.Add(Total, 1)

	event := createPagerdutyEvent(payload, c.Config.Pagerduty)

	if strings.ToLower(c.Config.Pagerduty.Region) == "eu" {
		pagerduty.WithV2EventsAPIEndpoint(EUEndpoint)
	} else {
		pagerduty.WithV2EventsAPIEndpoint(USEndpoint)
	}

	if _, err := pagerduty.ManageEventWithContext(context.Background(), event); err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:pagerduty", "status:error"})
		c.Stats.Pagerduty.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "pagerduty", "status": Error}).Inc()
		log.Printf("[ERROR] : PagerDuty - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:pagerduty", "status:ok"})
	c.Stats.Pagerduty.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "pagerduty", "status": OK}).Inc()
	log.Printf("[INFO]  : Pagerduty - Create Incident OK\n")
}

func createPagerdutyEvent(payload types.Payload, config types.PagerdutyConfig) pagerduty.V2Event {
	details := make(map[string]interface{}, len(payload.OutputFields)+4)
	details["priority"] = payload.Priority
	details["source"] = payload.OutputFields["PodName"].(string)
	if len(payload.Hostname) != 0 {
		payload.OutputFields[Hostname] = payload.Hostname
	}
	timestamp := time.Unix(payload.Timestamp, 0)
	event := pagerduty.V2Event{
		RoutingKey: config.RoutingKey,
		Action:     "trigger",
		Payload: &pagerduty.V2Payload{
			Source:    "Kubearmor",
			Summary:   payload.TriggerName + " for " + payload.OutputFields["PodName"].(string),
			Severity:  "critical",
			Timestamp: timestamp.Format(time.RFC3339),
			Details:   payload.OutputFields,
		},
	}
	return event
}
