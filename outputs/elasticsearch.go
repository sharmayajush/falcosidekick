// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"
)

type eSPayload struct {
	types.Payload
	Timestamp time.Time `json:"@timestamp"`
}

type mappingError struct {
	Error struct {
		RootCause []struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		} `json:"root_cause"`
		Type   string `json:"type"`
		Reason string `json:"reason"`
	} `json:"error"`
	Status int `json:"status"`
}

// ElasticsearchPost posts event to Elasticsearch
func (c *Client) ElasticsearchPost(payload types.Payload) {
	c.Stats.Elasticsearch.Add(Total, 1)

	current := time.Now()
	var eURL string
	switch c.Config.Elasticsearch.Suffix {
	case "none":
		eURL = c.Config.Elasticsearch.HostPort + "/" + c.Config.Elasticsearch.Index + "/" + c.Config.Elasticsearch.Type
	case "monthly":
		eURL = c.Config.Elasticsearch.HostPort + "/" + c.Config.Elasticsearch.Index + "-" + current.Format("2006.01") + "/" + c.Config.Elasticsearch.Type
	case "annually":
		eURL = c.Config.Elasticsearch.HostPort + "/" + c.Config.Elasticsearch.Index + "-" + current.Format("2006") + "/" + c.Config.Elasticsearch.Type
	default:
		eURL = c.Config.Elasticsearch.HostPort + "/" + c.Config.Elasticsearch.Index + "-" + current.Format("2006.01.02") + "/" + c.Config.Elasticsearch.Type
	}

	endpointURL, err := url.Parse(eURL)
	if err != nil {
		c.setElasticSearchErrorMetrics()
		log.Printf("[ERROR] : %v - %v\n", c.OutputType, err.Error())
		return
	}

	c.EndpointURL = endpointURL
	if c.Config.Elasticsearch.Username != "" && c.Config.Elasticsearch.Password != "" {
		c.httpClientLock.Lock()
		defer c.httpClientLock.Unlock()
		c.BasicAuth(c.Config.Elasticsearch.Username, c.Config.Elasticsearch.Password)
	}

	for i, j := range c.Config.Elasticsearch.CustomHeaders {
		c.AddHeader(i, j)
	}

	err = c.Post(payload)
	if err != nil {
		c.setElasticSearchErrorMetrics()
		log.Printf("[ERROR] : ElasticSearch - %v\n", err)
		return
	}

	// Setting the success status
	go c.CountMetric(Outputs, 1, []string{"output:elasticsearch", "status:ok"})
	c.Stats.Elasticsearch.Add(OK, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "elasticsearch", "status": OK}).Inc()
}

// setElasticSearchErrorMetrics set the error stats
func (c *Client) setElasticSearchErrorMetrics() {
	go c.CountMetric(Outputs, 1, []string{"output:elasticsearch", "status:error"})
	c.Stats.Elasticsearch.Add(Error, 1)
	c.PromStats.Outputs.With(map[string]string{"destination": "elasticsearch", "status": Error}).Inc()
}

func (c *Client) WatchElasticsearchPostAlerts() error {
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
			c.ElasticsearchPost(resp)
		}
	}
	fmt.Println("discord stopped")
	return nil
}
