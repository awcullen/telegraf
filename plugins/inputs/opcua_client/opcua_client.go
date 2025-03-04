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

type DataMetricDefinition struct {
	Name               string                         `toml:"name"`
	PublishingInterval config.Duration                `toml:"publishing_interval"`
	Fields             map[string]DataFieldDefinition `toml:"fields"`
	Tags               map[string]string              `toml:"tags"`
}

type EventMetricDefinition struct {
	Name               string                          `toml:"name"`
	PublishingInterval config.Duration                 `toml:"publishing_interval"`
	Fields             map[string]EventFieldDefinition `toml:"fields"`
	Tags               map[string]string               `toml:"tags"`
}

type Input struct {
	common_tls.ClientConfig
	EndpointURL    string                  `toml:"endpoint_url"`
	SecurityPolicy string                  `toml:"security_policy"`
	Username       string                  `toml:"username"`
	Password       string                  `toml:"password"`
	ConnectTimeout *config.Duration        `toml:"connect_timeout"`
	RequestTimeout *config.Duration        `toml:"request_timeout"`
	SessionTimeout *config.Duration        `toml:"session_timeout"`
	DataMetrics    []DataMetricDefinition  `toml:"data_metric"`
	EventMetrics   []EventMetricDefinition `toml:"event_metric"`

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

	retry:
		for {
			select {
			case <-ctx.Done():
				return
			default:

				// metric info
				type info struct {
					Name            string
					Tags            map[string]string
					Fields          map[string]any
					FieldNameLookup map[uint32]string
				}

				// map subscriptionID to metric info
				infoMap := make(map[uint32]*info, len(input.DataMetrics)+len(input.EventMetrics))

				// begin by opening a secure channel to the opcua server
				input.Log.Infof("Opening secure channel to endpoint url '%s'", input.EndpointURL)
				ch, err := uaclient.Dial(ctx, input.EndpointURL, input.getOptions()...)
				if err != nil {
					input.Log.Errorf("Error while opening secure channel to endpoint url '%s'. %s", input.EndpointURL, err)
					time.Sleep(5 * time.Second)
					continue retry
				}

				// for each data metric, create a subscription
				for _, metric := range input.DataMetrics {

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
						continue retry
					}

					info := &info{
						Name:            metric.Name,
						Tags:            metric.Tags,
						Fields:          make(map[string]any, len(metric.Fields)),
						FieldNameLookup: make(map[uint32]string, len(metric.Fields)),
					}
					infoMap[res.SubscriptionID] = info

					// for each field, prepare a monitored item
					itemsToCreate := make([]ua.MonitoredItemCreateRequest, 0, len(metric.Fields))
					handle := uint32(0)

					for k, o := range metric.Fields {
						handle++
						info.FieldNameLookup[handle] = k

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
						continue retry
					}

					// check each monitored item was successfully created.
					for i, item := range req2.ItemsToCreate {
						if code := res2.Results[i].StatusCode; code.IsBad() {
							input.Log.Errorf("Error while creating monitored item '%s' for subscription '%d' at endpoint url '%s'. %s", item.ItemToMonitor.NodeID, res.SubscriptionID, input.EndpointURL, code.Error())
						}
					}
				}

				// for each event metric, create a subscription
				for _, metric := range input.EventMetrics {

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
						continue retry
					}

					info := &info{
						Name:            metric.Name,
						Tags:            metric.Tags,
						Fields:          make(map[string]any, len(metric.Fields)),
						FieldNameLookup: make(map[uint32]string, len(metric.Fields)),
					}
					infoMap[res.SubscriptionID] = info

					// for each field, prepare a monitored item
					itemsToCreate := make([]ua.MonitoredItemCreateRequest, 0, len(metric.Fields))
					handle := uint32(0)

					selectClauses := make([]ua.SimpleAttributeOperand, len(metric.Fields))
					idx := uint32(0)
					for k, o := range metric.Fields {
						info.FieldNameLookup[idx] = k
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
						continue retry
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
						input.Log.Errorf("Error while publishing monitored items at endpoint url '%s'. %s", input.EndpointURL, err)
						break
					}

					// loop thru the notification to update the metric fields
					for _, obj := range res.NotificationMessage.NotificationData {
						switch data := obj.(type) {
						case ua.DataChangeNotification:
							input.Log.Debugf("Received %d data change(s) for subscription '%d' at endpoint url '%s'", len(data.MonitoredItems), res.SubscriptionID, input.EndpointURL)

							// lookup data metric from subscriptionid
							if info, ok := infoMap[res.SubscriptionID]; ok {

								for _, item := range data.MonitoredItems {

									// lookup field name from client handle
									if name, ok := info.FieldNameLookup[item.ClientHandle]; ok {
										dv := item.Value

										// update field value
										if !dv.StatusCode.IsBad() {
											switch value := dv.Value.(type) {
											case time.Time:
												info.Fields[name] = value.UnixNano()
											case ua.LocalizedText:
												info.Fields[name] = value.Text
											default:
												info.Fields[name] = value
											}
										} else {
											info.Fields[name] = nil
										}
									}
								}
								// send data fields to agent accumulator
								input.AddFields(info.Name, info.Fields, info.Tags)
								input.Log.Debugf("Sent %d field(s) to metric '%s'", len(info.Fields), info.Name)
							}

						case ua.EventNotificationList:
							input.Log.Debugf("Received %d event(s) for subscription '%d' at endpoint url '%s'", len(data.Events), res.SubscriptionID, input.EndpointURL)

							// lookup event metric from subscriptionid
							if info, ok := infoMap[res.SubscriptionID]; ok {
								for _, item := range data.Events {

									// update event fields
									for j, ef := range item.EventFields {
										if name, ok := info.FieldNameLookup[uint32(j)]; ok {
											switch value := ef.(type) {
											case time.Time:
												info.Fields[name] = value.UnixNano()
											case ua.LocalizedText:
												info.Fields[name] = value.Text
											default:
												info.Fields[name] = value
											}
										}
									}

									// send event fields to agent accumulator
									input.AddFields(info.Name, info.Fields, info.Tags)
									input.Log.Debugf("Sent %d field(s) to metric '%s'", len(info.Fields), info.Name)
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
					continue retry
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
