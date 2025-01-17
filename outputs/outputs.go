package outputs

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/falcosecurity/falcosidekick/types"
)

// Podowner struct
type Podowner struct {
	Ref       string `json:"ref,omitempty"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// Alerts struct
type Alerts struct {
	Timestamp         int64     `json:"timestamp,omitempty"`
	UpdatedTime       string    `json:"updated_time,omitempty"`
	ClusterName       string    `json:"cluster_name,omitempty"`
	HostName          string    `json:"host_name,omitempty"`
	NamespaceName     string    `json:"namespace_name,omitempty"`
	Owner             *Podowner `json:"owner,omitempty"`
	PodName           string    `json:"pod_name,omitempty"`
	Labels            string    `json:"labels,omitempty"`
	ContainerID       string    `json:"container_id,omitempty"`
	ContainerName     string    `json:"container_name,omitempty"`
	ContainerImage    string    `json:"container_image,omitempty"`
	HostPPID          int32     `json:"host_ppid,omitempty"`
	HostPID           int32     `json:"host_pid,omitempty"`
	PPID              int32     `json:"ppid,omitempty"`
	PID               int32     `json:"pid,omitempty"`
	UID               int32     `json:"uid,omitempty"`
	ParentProcessName string    `json:"parent_process_name,omitempty"`
	ProcessName       string    `json:"process_name,omitempty"`
	PolicyName        string    `json:"policy_name,omitempty"`
	Severity          string    `json:"severity,omitempty"`
	Tags              string    `json:"tags,omitempty"`
	ATags             []string  `json:"atags,omitempty"`
	Message           string    `json:"message,omitempty"`
	Type              string    `json:"type,omitempty"`
	Source            string    `json:"source,omitempty"`
	Operation         string    `json:"operation,omitempty"`
	Resource          string    `json:"resource,omitempty"`
	Data              string    `json:"data,omitempty"`
	Enforcer          string    `json:"enforcer,omitempty"`
	Action            string    `json:"action,omitempty"`
	Result            string    `json:"result,omitempty"`
}

// AlertStruct Structure
type AlertStruct struct {
	Broadcast chan types.Payload
}

// AlertLock Lock
var AlertLock *sync.RWMutex

// AlertStructs Map
var AlertStructs map[string]AlertStruct

// Running bool
var AlertRunning bool

// AlertBufferChannel store incoming data from msg stream in buffer
var AlertBufferChannel chan []byte

// LogStruct Structure
type LogStruct struct {
	Filter    string
	Broadcast chan types.Payload
}

var LogLock *sync.RWMutex

// LogStructs Map
var LogStructs map[string]LogStruct

func InitSidekick() {

	AlertRunning = true

	//initial buffer struct
	AlertBufferChannel = make(chan []byte, 1000)

	// initialize alert structs
	AlertStructs = make(map[string]AlertStruct)
	AlertLock = &sync.RWMutex{}

	// initialize log structs
	LogStructs = make(map[string]LogStruct)
	LogLock = &sync.RWMutex{}

}

func addAlertStruct(uid string, conn chan types.Payload) {
	AlertLock.Lock()
	defer AlertLock.Unlock()

	alertStruct := AlertStruct{}
	alertStruct.Broadcast = conn

	AlertStructs[uid] = alertStruct

	fmt.Println("Added a new client (" + uid + ") for WatchAlerts")
}
func removeAlertStruct(uid string) {
	AlertLock.Lock()
	defer AlertLock.Unlock()

	delete(AlertStructs, uid)
	fmt.Println("Deleted a new client (" + uid + ") for WatchAlerts")

}

func (c *Client) AddAlertFromBuffChan() {
	for AlertRunning {
		select {
		case res := <-AlertBufferChannel:

			alert := types.Payload{}
			// further updates needed
			alert.Timestamp = time.Now().Unix()
			alert.UpdatedTime = time.Now().String()
			alert.ClusterName = "cluster_1"
			alert.Hostname = "host"
			alert.ComponentName = "Alert"
			alert.OutputFields = make(map[string]interface{})

			json.Unmarshal(res, &alert.OutputFields)

			AlertLock.RLock()
			for uid := range AlertStructs {
				select {
				case AlertStructs[uid].Broadcast <- (alert):
				default:
				}
			}
			AlertLock.RUnlock()

		default:
			time.Sleep(time.Millisecond * 10)
		}

	}
}

func (c *Client) SendAlerts() error {
	defer c.WgServer.Done()

	// for {
	var res Alerts

	res = Alerts{
		Timestamp:     1622487600,
		UpdatedTime:   "2024-07-25T14:20:00Z",
		ClusterName:   "example-cluster",
		HostName:      "example-host",
		NamespaceName: "default",
		Owner: &Podowner{
			Ref:       "owner-ref-value",
			Name:      "owner-name-value",
			Namespace: "owner-namespace-value",
		},
		PodName:           "example-pod",
		Labels:            "key=value",
		ContainerID:       "container-id",
		ContainerName:     "example-container",
		ContainerImage:    "example-image",
		HostPPID:          1,
		HostPID:           2,
		PPID:              3,
		PID:               4,
		UID:               1000,
		ParentProcessName: "parent-process",
		ProcessName:       "process",
		PolicyName:        "example-policy",
		Severity:          "high",
		Tags:              "tag1,tag2",
		ATags:             []string{"tag1", "tag2"},
		Message:           "new message",
		Type:              "alert-type",
		Source:            "source",
		Operation:         "operation",
		Resource:          "resource",
		Data:              "data",
		Enforcer:          "enforcer",
		Action:            "action",
		Result:            "result",
	}

	jsonData, err := json.Marshal(res)
	if err != nil {
		log.Fatalf("Error marshaling to JSON: %v", err)
	}

	alert := types.Payload{}
	// further updates needed
	alert.Timestamp = time.Now().Unix()
	alert.TriggerName = "local_test_trigger"
	alert.UpdatedTime = time.Now().String()
	alert.ClusterName = "cluster_1"
	alert.Hostname = "Accuknox"
	alert.ComponentName = "KubeArmor"
	alert.Priority = "Medium"
	alert.TenantID = "11"
	alert.FilterQuery = "abc:a"
	alert.OutputFields = make(map[string]interface{})

	json.Unmarshal(jsonData, &alert.OutputFields)

	// select {
	// case AlertBufferChannel <- jsonData:
	// default:
	// }
	c.DiscordPost(alert)
	time.Sleep(10 * time.Second)
	// }
	return nil
}
