package outputs

import (
	"bytes"
	"encoding/json"
	"log"

	elasticsearch "github.com/elastic/go-elasticsearch/v8"
	"github.com/falcosecurity/falcosidekick/types"
)

func (c *Client) SendToElastic(payload types.Payload) {

	es, err := elasticsearch.NewClient(c.Config.Elasticsearch)
	if err != nil {
		log.Printf("Error creating the client: %s", err)
		return
	}

	metadata := map[string]interface{}{
		"index": map[string]interface{}{},
	}
	metadataBytes, err := json.Marshal(metadata)
	if err != nil {
		log.Println("Error marshaling metadata:", err)
		return
	}

	// Marshal the payload
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Println("Error marshaling payload:", err)
		return
	}

	// Combine metadata and payload into a single buffer
	var buf bytes.Buffer
	buf.Write(metadataBytes)
	buf.WriteString("\n") // Newline between metadata and payload
	buf.Write(payloadBytes)
	buf.WriteString("\n") // Newline at the end of the bulk request

	ingestResult, err := es.Bulk(
		bytes.NewReader(buf.Bytes()),
		es.Bulk.WithIndex("falco"),
		es.Bulk.WithPipeline("ent-search-generic-ingestion"),
	)

	log.Println(ingestResult, err)

}
