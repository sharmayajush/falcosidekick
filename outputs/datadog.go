// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"log"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"
)

const (
	// DatadogPath is the path of Datadog's event API
	DatadogPath string = "/api/v1/events"
)

type datadogPayload struct {
	Title      string   `json:"title,omitempty"`
	Text       string   `json:"text,omitempty"`
	AlertType  string   `json:"alert_type,omitempty"`
	SourceType string   `json:"source_type_name,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

func newDatadogPayload(Payload types.Payload) datadogPayload {
	var d datadogPayload
	tags := make([]string, 0)

	for i, j := range Payload.OutputFields {
		switch v := j.(type) {
		case string:
			tags = append(tags, i+":"+v)
		default:
			vv := fmt.Sprintln(v)
			tags = append(tags, i+":"+vv)
			continue
		}
	}

	d.Tags = tags

	d.SourceType = "kubearmor"

	var status string
	switch Payload.Priority {
	case "Alert":
		status = Error
	default:
		status = Info
	}
	d.AlertType = status

	return d
}

// DatadogPost posts event to Datadog
func (c *Client) DatadogPost(Payload types.Payload) {
	c.Stats.Datadog.Add(Total, 1)

	err := c.Post(newDatadogPayload(Payload))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:datadog", "status:error"})
		c.Stats.Datadog.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "datadog", "status": Error}).Inc()
		log.Printf("[ERROR] : Datadog - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:datadog", "status:ok"})
	c.Stats.Datadog.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "datadog", "status": OK}).Inc()
}

func (c *Client) WatchDatadogPostAlerts() error {
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
			c.DatadogPost(resp)
		default:
			time.Sleep(time.Millisecond * 10)

		}
	}

	return nil
}
