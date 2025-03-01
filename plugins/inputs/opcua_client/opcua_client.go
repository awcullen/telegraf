//go:generate ../../../tools/readme_config_includer/generator
package opcua_client

import (
	"context"
	_ "embed"
	"os"
	"os/signal"
	"sync"
	"time"

	uaclient "github.com/awcullen/opcua/client"
	"github.com/awcullen/opcua/ua"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	common_tls "github.com/influxdata/telegraf/plugins/common/tls"
	"github.com/influxdata/telegraf/plugins/inputs"
)

//go:embed sample.conf
var sampleConfig string

type DataFieldDefinition struct {
	NodeID string `toml:"node_id"`
}

type EventFieldDefinition struct {
	TypeDefinitionID string `toml:"typedefinition_id"`
	BrowsePath       string `toml:"browse_path"`
}

type MetricDefinition struct {
	Name               string                          `toml:"name"`
	PublishingInterval config.Duration                 `toml:"publishing_interval"`
	DataFields         map[string]DataFieldDefinition  `toml:"data_fields"`
	EventFields        map[string]EventFieldDefinition `toml:"event_fields"`
	Tags               map[string]string               `toml:"tags"`
}

type Input struct {
	common_tls.ClientConfig
	EndpointURL    string             `toml:"endpoint_url"`
	SecurityPolicy string             `toml:"security_policy"`
	Username       string             `toml:"username"`
	Password       string             `toml:"password"`
	ConnectTimeout *config.Duration   `toml:"connect_timeout"`
	RequestTimeout *config.Duration   `toml:"request_timeout"`
	SessionTimeout *config.Duration   `toml:"session_timeout"`
	Metrics        []MetricDefinition `toml:"metric"`

	Log telegraf.Logger `toml:"-"`

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	telegraf.Accumulator
}

func (*Input) SampleConfig() string {
	return sampleConfig
}

func (input *Input) Start(acc telegraf.Accumulator) error {
	input.Log.Info("Starting service input.")
	input.Accumulator = acc
	ctx, cancel := context.WithCancel(context.Background())
	input.ctx, input.cancel = ctx, cancel
	input.startSignalMonitor(ctx)
	input.startSession(ctx)

	return nil
}

func (input *Input) Stop() {
	input.Log.Info("Stopping service input.")
	input.cancel()
	input.wg.Wait()
}

func (*Input) Gather(telegraf.Accumulator) error {
	return nil
}

// startSignalMonitor begins monitoring for interrupt signals from the os.
func (input *Input) startSignalMonitor(ctx context.Context) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	input.wg.Add(1)
	go func() {
		defer input.wg.Done()

		select {
		case <-ctx.Done():
			return
		case <-signalChan:
			input.cancel()
			return
		}
	}()
}

// startSession opens a session with the opcua server.
func (input *Input) startSession(ctx context.Context) {
	input.wg.Add(1)
	go func() {
		defer input.cancel()
		defer input.wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			default:

				// begin by opening a secure channel to the opcua server
				input.Log.Infof("Opening secure channel to endpoint url '%s'", input.EndpointURL)
				ch, err := uaclient.Dial(ctx, input.EndpointURL, input.getOptions()...)
				if err != nil {
					input.Log.Errorf("Error while opening secure channel to endpoint url '%s'. %s", input.EndpointURL, err)
					time.Sleep(5 * time.Second)
					continue
				}

				// runtime state
				type rtMetric struct {
					Name                 string
					Tags                 map[string]string
					DataFields           map[string]any
					DataFieldNameLookup  map[uint32]string
					EventFields          map[string]any
					EventFieldNameLookup map[int]string
				}

				// for each metric, create a subscription
				rtMetricMap := make(map[uint32]*rtMetric)

				for _, metric := range input.Metrics {

					input.Log.Debugf("Creating subscription at endpoint url '%s'", input.EndpointURL)
					publishingInterval := float64(time.Duration(metric.PublishingInterval).Milliseconds())
					req := &ua.CreateSubscriptionRequest{
						RequestedPublishingInterval: publishingInterval,
						RequestedMaxKeepAliveCount:  3,
						RequestedLifetimeCount:      3 * 3,
						PublishingEnabled:           true,
					}
					res, err := ch.CreateSubscription(ctx, req)
					if err != nil {
						input.Log.Errorf("Error while creating subscription at endpoint url '%s'. %s", input.EndpointURL, err)
						ch.Abort(context.Background())
						time.Sleep(5 * time.Second)
						continue
					}

					rtm := &rtMetric{Name: metric.Name}
					rtm.Tags = metric.Tags
					rtMetricMap[res.SubscriptionID] = rtm

					// for each field, prepare a monitored item
					itemsToCreate := make([]ua.MonitoredItemCreateRequest, 0, len(metric.DataFields)+1)
					handle := uint32(0)
					rtm.DataFields = make(map[string]any, len(metric.DataFields))
					rtm.DataFieldNameLookup = make(map[uint32]string, len(metric.DataFields))

					for k, o := range metric.DataFields {
						handle++
						rtm.DataFieldNameLookup[handle] = k

						itemsToCreate = append(itemsToCreate, ua.MonitoredItemCreateRequest{
							ItemToMonitor: ua.ReadValueID{
								NodeID:      ua.ParseNodeID(o.NodeID),
								AttributeID: ua.AttributeIDValue,
							},
							MonitoringMode: ua.MonitoringModeReporting,
							RequestedParameters: ua.MonitoringParameters{
								ClientHandle:     handle,
								SamplingInterval: publishingInterval / 2.0, //oversample
								QueueSize:        1,
								DiscardOldest:    true,
							},
						})
					}

					rtm.EventFields = make(map[string]any, len(metric.EventFields))
					rtm.EventFieldNameLookup = make(map[int]string, len(metric.EventFields))
					selectClauses := make([]ua.SimpleAttributeOperand, len(metric.EventFields))
					idx := 0
					for k, o := range metric.EventFields {
						rtm.EventFieldNameLookup[idx] = k
						selectClauses[idx] =
							ua.SimpleAttributeOperand{
								TypeDefinitionID: ua.ParseNodeID(o.TypeDefinitionID),
								BrowsePath:       ua.ParseBrowsePath(o.BrowsePath),
								AttributeID:      ua.AttributeIDValue,
							}
						idx++
					}

					handle++
					itemsToCreate = append(itemsToCreate, ua.MonitoredItemCreateRequest{
						ItemToMonitor: ua.ReadValueID{
							NodeID:      ua.ParseNodeID("i=2253"), // server
							AttributeID: ua.AttributeIDEventNotifier,
						},
						MonitoringMode: ua.MonitoringModeReporting,
						RequestedParameters: ua.MonitoringParameters{
							ClientHandle:     handle,
							SamplingInterval: 0.0,
							Filter: ua.EventFilter{
								SelectClauses: selectClauses,
							},
							QueueSize:     100,
							DiscardOldest: true,
						},
					})

					// create monitored items for subscription
					input.Log.Debugf("Creating %d monitored item(s) for subscription '%d' at endpoint url '%s'", len(itemsToCreate), res.SubscriptionID, input.EndpointURL)
					req2 := &ua.CreateMonitoredItemsRequest{
						SubscriptionID:     res.SubscriptionID,
						TimestampsToReturn: ua.TimestampsToReturnNeither,
						ItemsToCreate:      itemsToCreate,
					}
					res2, err := ch.CreateMonitoredItems(ctx, req2)
					if err != nil {
						input.Log.Errorf("Error while creating monitored items for subscription '%d' at endpoint url '%s'. %s", res.SubscriptionID, input.EndpointURL, err)
						ch.Abort(context.Background())
						time.Sleep(5 * time.Second)
						continue
					}

					// check each monitored item was successfully created.
					for i, item := range req2.ItemsToCreate {
						if code := res2.Results[i].StatusCode; code.IsBad() {
							input.Log.Errorf("Error while creating monitored item '%s' for subscription '%d' at endpoint url '%s'. %s", item.ItemToMonitor.NodeID, res.SubscriptionID, input.EndpointURL, code.Error())
						}
					}
				}

				// send publish request
				req := &ua.PublishRequest{
					RequestHeader:                ua.RequestHeader{TimeoutHint: 120000},
					SubscriptionAcknowledgements: []ua.SubscriptionAcknowledgement{},
				}

				for {
					res, err := ch.Publish(ctx, req)
					if err != nil {
						break
					}

					// lookup runtime metric from subscriptionid
					if rtm, ok := rtMetricMap[res.SubscriptionID]; ok {

						// loop thru the notification to update the metric fields
						for _, obj := range res.NotificationMessage.NotificationData {
							switch data := obj.(type) {
							case ua.DataChangeNotification:
								input.Log.Debugf("Received %d data change(s) for subscription '%d' at endpoint url '%s'", len(data.MonitoredItems), res.SubscriptionID, input.EndpointURL)
								for _, item := range data.MonitoredItems {

									// lookup field name from client handle
									if name, ok := rtm.DataFieldNameLookup[item.ClientHandle]; ok {
										v := item.Value
										// update field value
										if !v.StatusCode.IsBad() {
											rtm.DataFields[name] = v.Value
										} else {
											rtm.DataFields[name] = nil
										}
									}
								}
								// send data fields to agent accumulator
								input.AddFields(rtm.Name, rtm.DataFields, rtm.Tags)
								input.Log.Debugf("Sent %d field(s) to metric '%s'", len(rtm.DataFields), rtm.Name)

							case ua.EventNotificationList:
								input.Log.Debugf("Received %d event(s) for subscription '%d' at endpoint url '%s'", len(data.Events), res.SubscriptionID, input.EndpointURL)
								for _, item := range data.Events {

									// update event fields
									for j, ef := range item.EventFields {
										if name, ok := rtm.EventFieldNameLookup[j]; ok {
											switch v := ef.(type) {
											case time.Time:
												rtm.EventFields[name] = v.UnixNano()
											case ua.LocalizedText:
												rtm.EventFields[name] = v.Text
											default:
												rtm.EventFields[name] = v
											}
										}
									}

									// send event fields to agent accumulator
									input.AddFields(rtm.Name, rtm.EventFields, rtm.Tags)
									input.Log.Debugf("Sent %d field(s) to metric '%s'", len(rtm.EventFields), rtm.Name)
								}
							}
						}

					}

					req = &ua.PublishRequest{
						RequestHeader: ua.RequestHeader{TimeoutHint: 120000},
						SubscriptionAcknowledgements: []ua.SubscriptionAcknowledgement{
							{
								SubscriptionID: res.SubscriptionID,
								SequenceNumber: res.NotificationMessage.SequenceNumber,
							},
						},
					}
				}

				input.Log.Infof("Closing secure channel to endpoint url '%s'", input.EndpointURL)
				err = ch.Close(context.Background())
				if err != nil {
					input.Log.Errorf("Error while closing secure channel to endpoint url '%s'. %s", input.EndpointURL, err)
					ch.Abort(context.Background())
					time.Sleep(5 * time.Second)
					continue
				}
			}
		}
	}()
}

func (input *Input) getOptions() []uaclient.Option {
	opts := make([]uaclient.Option, 0, 8)
	opts = append(opts, uaclient.WithApplicationName("telegraf"))
	switch input.SecurityPolicy {
	case "None", "none":
		opts = append(opts, uaclient.WithSecurityPolicyURI(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone))
	case "Basic128Rsa15":
		opts = append(opts, uaclient.WithSecurityPolicyURI(ua.SecurityPolicyURIBasic128Rsa15, ua.MessageSecurityModeSignAndEncrypt))
	case "Basic256":
		opts = append(opts, uaclient.WithSecurityPolicyURI(ua.SecurityPolicyURIBasic256, ua.MessageSecurityModeSignAndEncrypt))
	case "Basic256Sha256":
		opts = append(opts, uaclient.WithSecurityPolicyURI(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt))
	case "Aes128_Sha256_RsaOaep":
		opts = append(opts, uaclient.WithSecurityPolicyURI(ua.SecurityPolicyURIAes128Sha256RsaOaep, ua.MessageSecurityModeSignAndEncrypt))
	case "Aes256_Sha256_RsaPss":
		opts = append(opts, uaclient.WithSecurityPolicyURI(ua.SecurityPolicyURIAes256Sha256RsaPss, ua.MessageSecurityModeSignAndEncrypt))
	}
	if input.TLSCert != "" {
		opts = append(opts, uaclient.WithClientCertificatePaths(input.TLSCert, input.TLSKey))
	}
	if input.TLSCA != "" {
		opts = append(opts, uaclient.WithTrustedCertificatesPaths(input.TLSCA, ""))
	}
	if input.InsecureSkipVerify {
		opts = append(opts, uaclient.WithInsecureSkipVerify())
	}
	if input.Username != "" {
		opts = append(opts, uaclient.WithUserNameIdentity(input.Username, input.Password))
	}
	if input.ConnectTimeout != nil {
		opts = append(opts, uaclient.WithConnectTimeout(time.Duration(*input.ConnectTimeout).Milliseconds()))
	}
	if input.RequestTimeout != nil {
		opts = append(opts, uaclient.WithTimeoutHint(uint32(time.Duration(*input.RequestTimeout).Milliseconds())))
	}
	if input.SessionTimeout != nil {
		opts = append(opts, uaclient.WithSessionTimeout(float64(time.Duration(*input.ConnectTimeout).Milliseconds())))
	}

	return opts
}

func new() *Input {
	return &Input{}
}

func init() {
	inputs.Add("opcua_client", func() telegraf.Input { return new() })
}
