package main

import (
	"fmt"
	"sync"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/outputs"
	"github.com/falcosecurity/falcosidekick/types"
)

var globalMap map[string]*outputs.Client
var AlertLock *sync.RWMutex
var AlertBufferChannel chan []byte
var slackClient *outputs.Client
var statsdClient, dogstatsdClient *statsd.Client

func main() {
	// var e1 types.smtpOutputConfig
	// e1.From = "yajush@accuknox.com"
	// e1.To = "yajushsharma12@gmail.com"
	// e1.OutputFormat = outputs.HtmlTmpl
	// e1.HostPort = ""
	// e1.TLS = true
	// e1.User = ""
	// e1.AuthMechanism = ""

	// var t1 types.SlackOutputConfig

	// t1.WebhookURL = "https://hooks.slack.com/services/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"
	// t1.Channel = "integration-alerts"
	// t1.Footer = "filters"
	// t1.Icon = "https://help.accuknox.com/assets/images/logo.png"
	// t1.Username = "accuknox"
	// cf1 := types.Configuration{
	// 	Slack: t1,
	// }
	// stats := &types.Statistics{}
	// promStats := &types.PromStatistics{}
	// initClientArgs := &types.InitClientArgs{
	// 	Config:          &cf1,
	// 	Stats:           stats,
	// 	DogstatsdClient: dogstatsdClient,
	// 	PromStats:       promStats,
	// }
	// c1, err := outputs.NewClient("Slack", cf1.Slack.WebhookURL, cf1.Slack.MutualTLS, cf1.Slack.CheckCert, *initClientArgs)
	// if err != nil {
	// 	fmt.Println("error---")
	// }

	// var t2 types.DiscordOutputConfig
	// t2.WebhookURL = "https://discord.com/api/webhooks/1319533054661885952/uvfjilJLeHTVfmdIkxKaF5SIGNJ3jhUUEHrDFwARtFNBhRHq8vtnZsA5hpcvoGjzdGtV"
	// t2.Icon = "https://help.accuknox.com/assets/images/logo.png"
	var t3 types.TeamsOutputConfig
	t3.WebhookURL = "https://accuknox981.webhook.office.com/webhookb2/94632bbb-7f4c-4e9b-8cde-1c2ee21e0219@36ddf603-4580-43e4-a49d-353a5de81b7a/IncomingWebhook/708b08a951554c37adf52381c6a0a637/9933e893-62ca-4808-a76e-f9b0780b0379/V2s-BDn6vppgH6DtiI528jZ9J09Q48KMgMS4A4oP103nc1"
	t3.ActivityImage = "https://help.accuknox.com/assets/images/logo.png"
	cf1 := types.Configuration{
		Teams: t3,
	}
	stats := &types.Statistics{}
	promStats := &types.PromStatistics{}
	initClientArgs := &types.InitClientArgs{
		Config:          &cf1,
		Stats:           stats,
		DogstatsdClient: dogstatsdClient,
		PromStats:       promStats,
	}
	// c1, err := outputs.NewClient("Discord", cf1.Discord.WebhookURL, cf1.Discord.MutualTLS, cf1.Discord.CheckCert, *initClientArgs)
	c1, err := outputs.NewClient("Teams", cf1.Teams.WebhookURL, cf1.Teams.MutualTLS, cf1.Teams.CheckCert, *initClientArgs)
	if err != nil {
		fmt.Println("error---")
		return
	}
	// var t3 types.TelegramConfig
	// t3.ChatID = "-4662869329"
	// t3.Token = "8018066119:AAG_S9b2atIZHX6BCy2gocuC-5EucSxbopI"
	// cf3 := types.Configuration{
	// 	Telegram: t3,
	// }
	// stats := &types.Statistics{}
	// promStats := &types.PromStatistics{}
	// initClientArgs := &types.InitClientArgs{
	// 	Config:          &cf3,
	// 	Stats:           stats,
	// 	DogstatsdClient: dogstatsdClient,
	// 	PromStats:       promStats,
	// }
	// var urlFormat = "https://api.telegram.org/bot%s/sendMessage"
	// c1, err := outputs.NewClient("Telegram", fmt.Sprintf(urlFormat, cf3.Telegram.Token), false, cf3.Discord.CheckCert, *initClientArgs)
	// if err != nil {
	// 	fmt.Println("error---")
	// }
	// var t2 types.SlackOutputConfig
	// t2.WebhookURL = ""
	// cf2 := types.Configuration{
	// 	Slack: t2,
	// }

	// c2 := outputs.Client{
	// 	Config: &cf2,
	// }
	// outputs.AlertLock = &sync.RWMutex{}
	// outputs.AlertRunning = true
	fmt.Println(c1)
	// outputs.InitSidekick()

	// go c1.SendAlerts()
	// go c1.AddAlertFromBuffChan()
	// go c1.WatchSlackAlerts()
	c1.SendAlerts()

	select {}
}
