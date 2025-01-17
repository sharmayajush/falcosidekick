// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"log"
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

type opsgeniePayload struct {
	Message     string            `json:"message"`
	Entity      string            `json:"entity,omitempty"`
	Description string            `json:"description,omitempty"`
	Details     map[string]string `json:"details,omitempty"`
	Priority    string            `json:"priority,omitempty"`
}

func newOpsgeniePayload(payload types.Payload, config *types.Configuration) opsgeniePayload {
	details := make(map[string]string, len(payload.OutputFields))
	for i, j := range payload.OutputFields {
		switch v := j.(type) {
		case string:
			details[strings.ReplaceAll(i, ".", "_")] = v
		default:
			vv := fmt.Sprint(v)
			details[strings.ReplaceAll(i, ".", "_")] = vv
		}
	}

	details["source"] = payload.ComponentName
	details["priority"] = payload.Priority
	if payload.Hostname != "" {
		details[Hostname] = payload.Hostname
	}

	var prio string
	switch payload.Priority {
	case "Alert":
		prio = "P1"
	default:
		prio = "P5"
	}

	return opsgeniePayload{
		Message:     payload.TriggerName + " for " + payload.OutputFields["PodName"].(string),
		Entity:      "Kubearmor",
		Description: payload.FilterQuery,
		Details:     details,
		Priority:    prio,
	}
}

// OpsgeniePost posts event to OpsGenie
func (c *Client) OpsgeniePost(payload types.Payload) {
	c.Stats.Opsgenie.Add(Total, 1)
	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()
	c.AddHeader(AuthorizationHeaderKey, "GenieKey "+c.Config.Opsgenie.APIKey)

	err := c.Post(newOpsgeniePayload(payload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:opsgenie", "status:error"})
		c.Stats.Opsgenie.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "opsgenie", "status": Error}).Inc()
		log.Printf("[ERROR] : OpsGenie - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:opsgenie", "status:ok"})
	c.Stats.Opsgenie.Add("ok", 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "opsgenie", "status": OK}).Inc()
}
