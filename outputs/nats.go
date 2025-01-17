// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"encoding/json"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	nats "github.com/nats-io/nats.go"

	"github.com/falcosecurity/falcosidekick/types"
)

var slugRegularExpression = regexp.MustCompile("[^a-z0-9]+")

// NatsPublish publishes event to NATS
func (c *Client) NatsPublish(payload types.Payload) {
	c.Stats.Nats.Add(Total, 1)

	nc, err := nats.Connect(c.EndpointURL.String())
	if err != nil {
		c.setNatsErrorMetrics()
		log.Printf("[ERROR] : NATS - %v\n", err)
		return
	}
	defer nc.Flush()
	defer nc.Close()

	j, err := json.Marshal(payload)
	if err != nil {
		c.setStanErrorMetrics()
		log.Printf("[ERROR] : STAN - %v\n", err.Error())
		return
	}

	err = nc.Publish(strings.ToLower(payload.ComponentName)+"."+strings.ToLower(payload.TriggerName), j)
	if err != nil {
		c.setNatsErrorMetrics()
		log.Printf("[ERROR] : NATS - %v\n", err)
		return
	}

	go c.CountMetric("outputs", 1, []string{"output:nats", "status:ok"})
	c.Stats.Nats.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "nats", "status": OK}).Inc()
	log.Printf("[INFO]  : NATS - Publish OK\n")
}

// setNatsErrorMetrics set the error stats
func (c *Client) setNatsErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:nats", "status:error"})
	c.Stats.Nats.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "nats", "status": Error}).Inc()
}

func (c *Client) WatchNatsPublishAlerts() error {
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
			c.NatsPublish(resp)
		default:
			time.Sleep(time.Millisecond * 10)

		}
	}

	return nil
}
