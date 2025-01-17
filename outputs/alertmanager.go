// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

type alertmanagerPayload struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	EndsAt      time.Time         `json:"endsAt,omitempty"`
}

var defaultSeverityMap = map[types.PriorityType]string{
	types.Debug:         "information",
	types.Informational: "information",
	types.Notice:        "information",
	types.Warning:       "warning",
	types.Error:         "warning",
	types.Critical:      "critical",
	types.Alert:         "critical",
	types.Emergency:     "critical",
}

// labels should match [a-zA-Z_][a-zA-Z0-9_]*
var (
	reg = regexp.MustCompile("[^a-zA-Z0-9_]")
)

func newAlertmanagerPayload(Payload types.Payload, config *types.Configuration) []alertmanagerPayload {
	var amPayload alertmanagerPayload
	amPayload.Labels = make(map[string]string)
	amPayload.Annotations = make(map[string]string)

	for i, j := range Payload.OutputFields {
		switch v := j.(type) {
		case string:
			jj := j.(string)
			amPayload.Labels[i] = jj
		default:
			vv := fmt.Sprint(v)
			amPayload.Labels[i] = vv
		}

	}

	amPayload.Labels["source"] = "Kubearmor"

	if config.Alertmanager.ExpiresAfter != 0 {
		timestamp := time.Unix(Payload.Timestamp, 0)
		amPayload.EndsAt = timestamp.Add(time.Duration(config.Alertmanager.ExpiresAfter) * time.Second)
	}
	for label, value := range config.Alertmanager.ExtraLabels {
		amPayload.Labels[label] = value
	}
	for annotation, value := range config.Alertmanager.ExtraAnnotations {
		amPayload.Annotations[annotation] = value
	}

	var a []alertmanagerPayload

	a = append(a, amPayload)

	return a
}

// AlertmanagerPost posts event to AlertManager
func (c *Client) AlertmanagerPost(Payload types.Payload) {
	c.Stats.Alertmanager.Add(Total, 1)
	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()
	for i, j := range c.Config.Alertmanager.CustomHeaders {
		c.AddHeader(i, j)
	}

	err := c.Post(newAlertmanagerPayload(Payload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:alertmanager", "status:error"})
		c.Stats.Alertmanager.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "alertmanager", "status": Error}).Inc()
		log.Printf("[ERROR] : AlertManager - %v\n", err)
		return
	}

	go c.CountMetric(Outputs, 1, []string{"output:alertmanager", "status:ok"})
	c.Stats.Alertmanager.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "alertmanager", "status": OK}).Inc()
}

func alertmanagerSafeLabel(label string) string {
	// replace all unsafe characters with _
	replaced := reg.ReplaceAllString(label, "_")
	// remove double __
	replaced = strings.ReplaceAll(replaced, "__", "_")
	// remove trailing _
	replaced = strings.TrimRight(replaced, "_")
	// remove leading _
	return strings.TrimLeft(replaced, "_")
}

func (c *Client) WatchAlertmanagerPostAlerts() error {
	uid := "Alertmaneger"

	conn := make(chan types.Payload, 1000)
	defer close(conn)
	addAlertStruct(uid, conn)
	defer removeAlertStruct(uid)

	for AlertRunning {
		select {
		// case <-Context().Done():
		// 	return nil
		case resp := <-conn:
			c.AlertmanagerPost(resp)
		default:
			time.Sleep(time.Millisecond * 10)

		}
	}

	return nil
}
