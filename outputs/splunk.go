package outputs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ZachtimusPrime/Go-Splunk-HTTP/splunk/v2"
	"github.com/falcosecurity/falcosidekick/types"
)

func (c *Client) SendMessageToSplunk(tenant_id string, payload types.Payload) error {
	result, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("error in marshalling payload")
		return err
	}
	var message map[string]interface{}

	err = json.Unmarshal(result, &message)
	if err != nil {
		log.Println("error in unmarshalling logs for splunk")
		return errors.New("error in unmarshalling logs in splunk")
	}

	// create splunk client
	client, err := createsplunkClient(c.Config.Splunk.Url, c.Config.Splunk.Token, c.Config.Splunk.Source, c.Config.Splunk.SourceType, c.Config.Splunk.SplunkIndex, c.Config.Splunk.Certificate, c.Config.Splunk.SkipTls)
	if err != nil {
		log.Println("error in creating splunk client")
		return errors.New("error in creating splunk client")
	}

	maxRetries := 10
	for retry := 1; retry <= maxRetries; retry++ {
		err = client.Log(message)
		if err == nil {
			// successfully pushed the event to splunk
			log.Printf("message sent successfully to splunk")
			return nil
		}

		log.Printf("retrying in %v seconds, attempted %v / %v", retry, retry, maxRetries)

		// we failed to push the event to splunk, hence perform exponential retries
		time.Sleep(time.Duration(retry) * time.Second)
	}

	// we are not able to send event to splunk after multiple retries
	log.Printf("failed to push log to splunk with error: [%v]", err)
	return errors.New("failed to send logs to splunk")
}

func createsplunkClient(url, token, source, sourcetype, index, caCertificate string, skipTls bool) (*splunk.Client, error) {

	if !skipTls && caCertificate == "" {
		splunk := splunk.NewClient(nil, url, token, source, sourcetype, index)
		return splunk, nil
	}

	client, err := GetHTTPClient(caCertificate, skipTls)
	if err != nil {
		log.Printf("error in creating http client for custom caCertificate.")
		return nil, err
	}
	splunk := splunk.NewClient(client, url, token, source, sourcetype, index)
	return splunk, nil
}

func GetHTTPClient(caCertificate string, skipTls bool) (*http.Client, error) {

	if caCertificate == "" && !skipTls {
		return http.DefaultClient, nil
	}
	// Create a default TLS configuration
	tlsConfig := &tls.Config{}

	// If a CA certificate is provided, use it to set up a trusted cert pool
	if skipTls {
		// If skip tls is true, skip TLS verification
		tlsConfig.InsecureSkipVerify = true

	}
	if caCertificate != "" {
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM([]byte(caCertificate)) {
			log.Println("failed to append ca certificate")
			return nil, fmt.Errorf("failed to append certificate")
		}
		tlsConfig.RootCAs = certPool
	}
	// Create HTTP client with the configured TLS settings
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return client, nil
}

func ValidateSplunkCredentials(url string, token string, source string, sourcetype string, index string, certificateID int, skipTls bool) (bool, error) {
	splunkclient, err := createsplunkClient(url, token, source, sourcetype, index, strconv.Itoa(certificateID), skipTls)
	if err != nil {
		log.Println("unable to create splunk client. " + err.Error())
		return false, err
	}
	err = splunkclient.Log("This is a Test Message.")
	if err != nil {
		log.Println("unable to send logs to splunk " + err.Error())
		if strings.Contains(err.Error(), "certificate") {
			return false, errors.New("valid ssl not present")
		}
		return false, errors.New("invalid inputs provided")
	}
	return true, nil
}
