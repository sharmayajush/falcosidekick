package outputs

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"

	"github.com/andygrunwald/go-jira"
	"github.com/falcosecurity/falcosidekick/types"
)

// PrettyString formats the string
func PrettyString(str string) (string, error) {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, []byte(str), "", "    "); err != nil {
		return "", err
	}
	return prettyJSON.String(), nil
}

// SendMsgtoJira to send message to jira integration
func (c *Client) SendMsgtoJira(payload types.Payload) error {
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Println("unable to marshal the payload")
		return err
	}
	sendAlert := string(jsonPayload)

	resJson, err := PrettyString(sendAlert)
	if err != nil {
		log.Println("Err in creating pretty res_json in Jira " + err.Error())
		return errors.New("Err in creating pretty res_json in Jira")
	}

	jiraClient, err := createClient(c.Config.Jira.UserEmail, c.Config.Jira.Token, c.Config.Jira.Site)
	if err != nil {
		log.Println("Err in creating a new Jira Client " + err.Error())
		return errors.New("Err in creating a new Jira Client ")
	}

	i := jira.Issue{
		Fields: &jira.IssueFields{
			Description: resJson,
			Type: jira.IssueType{
				Name: c.Config.Jira.IssueType,
			},
			Project: jira.Project{
				Key: c.Config.Jira.Project,
			},
			Summary: c.Config.Jira.IssueSummary,
		},
	}
	issue, _, err := jiraClient.Issue.Create(&i)
	if err != nil {
		log.Println("Failed to create Jira Ticket " + err.Error())
		return errors.New("Failed to create Jira Ticket ")
	}
	log.Printf("Jira Ticket Created Successfully :> %v", issue)
	return nil

}

func createClient(userEmail, token, siteUrl string) (*jira.Client, error) {
	tp := jira.BasicAuthTransport{
		Username: userEmail,
		Password: token,
	}

	jiraClient, err := jira.NewClient(tp.Client(), siteUrl)
	if err != nil {
		log.Println("Err in creating a new Jira Client " + err.Error())
		return nil, errors.New("Err in creating a new Jira Client ")
	}
	return jiraClient, nil
}

// ValidateToken Validate token that is being sent from UI
func ValidateToken(userEmail, token, siteUrl, project string) bool {
	jiraClient, err := createClient(userEmail, token, siteUrl)
	if err != nil {
		return false
	}
	if _, _, err := jiraClient.Project.Get(project); err != nil {
		return false
	}
	return true
}
