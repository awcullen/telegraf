# opcua_client Input Plugin

A service input to capture metrics published by OPC Unified Architecture (OPCUA) servers.

Telegraf minimum version: Telegraf 1.33
Plugin minimum tested version: 1.33

## Service Input <!-- @/docs/includes/service_input.md -->

This plugin is a service input. Normal plugins gather metrics determined by the
interval setting. Service plugins start a service to listen and wait for
metrics or events to occur. Service plugins have two key differences from
normal plugins:

1. The global or plugin specific `interval` setting may not apply
2. The CLI options of `--test`, `--test-wait`, and `--once` may not produce
   output for this plugin


## Secret-store support

This plugin supports secrets from secret-stores for the `username` and
`password` option.
See the [secret-store documentation][SECRETSTORE] for more details on how
to use them.

[SECRETSTORE]: ../../../docs/CONFIGURATION.md#secret-store-secrets

## Configuration

```toml @sample.conf
## Capture metrics published by an OPC Unified Architecture (OPCUA) server.
[[inputs.opcua_client]]

  ## Endpoint URL of the server.
  # endpoint_url = "opc.tcp://[host]:[port]"

  ## Optional security policy, one of "none", "Basic128Rsa15", "Basic256", "Basic256Sha256", "Aes128_Sha256_RsaOaep", or "Aes256_Sha256_RsaPss".
  ## Default selects the most secure policy offered by the server.
  # security_policy = ""

  ## Optional paths to client certificate and private key files. Required when security policy is not "none".
  # tls_cert = "./pki/client.crt"
  # tls_key = "./pki/client.key"

  ## Optional path to root certificate file. Required for verifying server certificates.
  # tls_ca = "./pki/ca.crt"

  ## Optional flag to skip chain & host verification
  # insecure_skip_verify = true

  ## Optional username identity. Default is anonymous identity.
  # username = ""
  # password = ""

  ## Optional time to wait for a connection response.
  # connect_timeout = "5000ms"

  ## Optional time before a request is cancelled.
  # request_timeout = "1500ms"

  ## Optional time the session will remain open without activity.
  # session_timeout = "2m"

  ## Optional override of the log-level for this plugin. Possible values are "error", "warn", "info", "debug" and "trace".
  # log_level = "info"

  ## A data metric subscribes to data changes of the server. 
  ## A metric containing the last value of each field will be generated at the publishing interval.
  # [[inputs.opcua_client.data_metric]]

  ## Name of the metric. (also know as Measurement or Table)
  # name = "data_metric"

  ## Interval to publish the data.
  # publishing_interval = "5s"

  ## The data values to collect from the OPCUA server.
  ## Use:
  ## field_name = { node_id = "" }
  ## where:
  ## field_name - Alphanumeric and must begin with a letter or a number. Names can contain dashes (-) and underscores (_).
  ## node_id    - NodeID of the variable to read. Supports numeric, string, guid, and opaque identifiers.
  # [inputs.opcua_client.data_metric.fields]
  # float_field = { node_id = "ns=3;s=Demo.Dynamic.Scalar.Float" }
  # int32_field = { node_id = "ns=3;s=Demo.Dynamic.Scalar.Int32" } 
 
  ## Optional list of tags
  # [inputs.opcua_client.data_metric.tags]
  # dev = "device_1"
  # loc = "location_1"


  ## An event metric subscribes to events of the server. 
  ## A list of metrics containing the event fields of each event will be generated at the publishing interval.
  # [[inputs.opcua_client.event_metric]]

  ## Name of the metric. (also know as Measurement or Table)
  # name = "event_metric"

  ## Interval to publish events.
  # publishing_interval = "5s"

  ## The event fields to collect from the OPCUA server.
  ## Use:
  ## field_name = { typedefinition_id = "", browse_path = "" }
  ## where:
  ## field_name        - Alphanumeric and must begin with a letter or a number. Names can contain dashes (-) and underscores (_).
  ## typedefinition_id - NodeID of an event type. Supports numeric, string, guid, and opaque identifiers.
  ## browse_path       - A sequence of browse names that specify which event field to read.
  # [inputs.opcua_client.event_metric.fields]
  # source = { typedefinition_id = "i=2041", browse_path = "SourceName" }
  # message = { typedefinition_id = "i=2041", browse_path = "Message" }
  # severity = { typedefinition_id = "i=2041", browse_path = "Severity" }
  # ackedState = { typedefinition_id = "i=2881", browse_path = "AckedState/Id" }
  # activeState = { typedefinition_id = "i=2915", browse_path = "ActiveState/Id" }

  ## Optional list of tags
  # [inputs.opcua_client.event_metric.tags]
  # dev = "device_1"
  # loc = "location_1"
  
```

## Example Output

```text
example_1,device=device_1,location=location_1 int32_field=1404915i,float_field=1566449.875 1740785411436651000
example_1,device=device_1,location=location_1 event_active=true,event_source="ExclusiveLevelAlarmTrigger",event_message="Exclusive level alarm active in HighHigh",event_severity=800i,event_acked=false 1740785411437385200
example_1,device=device_1,location=location_1 int32_field=1404979i,float_field=1566521.875 1740785416443808900

```
