// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"log"
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"
)

type influxdbPayload string

func newInfluxdbPayload(payload types.Payload, config *types.Configuration) influxdbPayload {
	s := "events,rule=" + strings.Replace(payload.TriggerName, " ", "_", -1) + ",priority=" + payload.Priority + ",source=" + payload.OutputFields["PodName"].(string)

	for i, j := range payload.OutputFields {
		switch v := j.(type) {
		case string:
			s += "," + i + "=" + strings.Replace(v, " ", "_", -1)
		default:
			vv := fmt.Sprint(v)
			s += "," + i + "=" + strings.Replace(vv, " ", "_", -1)
			continue
		}
	}

	if payload.Hostname != "" {
		s += "," + Hostname + "=" + payload.Hostname
	}

	return influxdbPayload(s)
}

// InfluxdbPost posts event to InfluxDB
func (c *Client) InfluxdbPost(payload types.Payload) {
	c.Stats.Influxdb.Add(Total, 1)

	c.httpClientLock.Lock()
	defer c.httpClientLock.Unlock()
	c.AddHeader("Accept", "application/json")

	if c.Config.Influxdb.Token != "" {
		c.AddHeader("Authorization", "Token "+c.Config.Influxdb.Token)
	}

	err := c.Post(newInfluxdbPayload(payload, c.Config))
	if err != nil {
		go c.CountMetric(Outputs, 1, []string{"output:influxdb", "status:error"})
		c.Stats.Influxdb.Add(Error, 1)
		c.PromStats.Outputs.With(map[string]string{"destination": "influxdb", "status": Error}).Inc()
		log.Printf("[ERROR] : InfluxDB - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:influxdb", "status:ok"})
	c.Stats.Influxdb.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "influxdb", "status": OK}).Inc()
}

func (c *Client) WatchInfluxdbPostAlerts() error {
	uid := uuid.Must(uuid.NewRandom()).String()

	conn := make(chan types.Payload, 1000)
	defer close(conn)
	addAlertStruct(uid, conn)
	defer removeAlertStruct(uid)

	fmt.Println("discord running")
	for AlertRunning {
		select {
		case resp := <-conn:
			fmt.Println("response \n", resp)
			c.InfluxdbPost(resp)
		}
	}
	fmt.Println("discord stopped")
	return nil
}
