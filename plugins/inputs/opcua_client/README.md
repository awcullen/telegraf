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

  ## Optional security policy, one of "None", "Basic128Rsa15", "Basic256", "Basic256Sha256", "Aes128_Sha256_RsaOaep", or "Aes256_Sha256_RsaPss".
  ## Default selects the most secure policy offered by the server.
  # security_policy = ""

  ## Optional paths to client certificate and private key files. Required when security policy is not "none".
  # tls_cert = "./pki/cert.pem"
  # tls_key = "./pki/key.pem"

  ## Optional path to root certificate file. Required for verifying server certificates.
  # tls_ca = "./pki/ca.pem"

  ## Optional flag to skip chain & host verification. (default false)
  # insecure_skip_verify = false

  ## Optional username identity. (default is anonymous identity)
  # username = ""
  # password = ""

  ## Optional time to wait for a connection response. (default 5000ms)
  # connect_timeout = ""

  ## Optional time before a request is cancelled. (default 1500ms)
  # request_timeout = ""

  ## Optional time the session will remain open without activity. (default 2m)
  # session_timeout = ""

  ## Optional override of the log-level. Possible values are "error", "warn", "info", "debug" and "trace".
  # log_level = ""

  ## A metric consists of a name, a publishing interval, a list of fields, and an optional list of tags. 
  # [[inputs.opcua_client.metric]]

  ## Name of the metric (also known as Measurement or Table).
  # name = "example_1"

  ## Interval to publish the metric.
  # publishing_interval = "5s"

  ## Data Fields specify which data values to collect from the OPCUA server.
  ## A single metric containing the last value of each data field will be generated at the publishing interval.
  ## Use the form:
  ## name = { node_id = "" }
  ## where:
  ## name          - Alphanumeric and must begin with a letter or a number. Names can contain dashes (-) and underscores (_).
  ## node_id       - NodeID of the variable to read. Supports numeric, string, guid, and opaque identifiers.
  # [inputs.opcua_client.metric.data_fields]
  # float_field = { node_id = "ns=3;s=Demo.Dynamic.Scalar.Float" }
  # int32_field = { node_id = "ns=3;s=Demo.Dynamic.Scalar.Int32" } 
 
  ## Event Fields specify which fields of OPCUA event type to collect from the OPCUA server.
  ## Multiple metrics, where each metric contains the fields of a single event, may be generated the publishing interval.
  ## Use the form:
  ## name = { typedefinition_id = "", browse_path = "" }
  ## where:
  ## name              - Alphanumeric and must begin with a letter or a number. Names can contain dashes (-) and underscores (_).
  ## typedefinition_id - NodeID of the event type. Supports numeric, string, guid, and opaque identifiers.
  ## browse_path       - A sequence of browse names that specify which event field to read.
  # [inputs.opcua_client.metric.event_fields]
  # event_source = { typedefinition_id = "i=2041", browse_path = "SourceName" }
  # event_message = { typedefinition_id = "i=2041", browse_path = "Message" }
  # event_severity = { typedefinition_id = "i=2041", browse_path = "Severity" }
  # event_acked = { typedefinition_id = "i=2881", browse_path = "AckedState/Id" }
  # event_active = { typedefinition_id = "i=2915", browse_path = "ActiveState/Id" }

  ## Optional list of tags
  # [inputs.opcua_client.metric.tags]
  # device = "device_1"
  # location = "location_1"

```

## Example Output

```text
example_1,device=device_1,location=location_1 int32_field=1404915i,float_field=1566449.875 1740785411436651000
example_1,device=device_1,location=location_1 event_active=true,event_source="ExclusiveLevelAlarmTrigger",event_message="Exclusive level alarm active in HighHigh",event_severity=800i,event_acked=false 1740785411437385200
example_1,device=device_1,location=location_1 int32_field=1404979i,float_field=1566521.875 1740785416443808900

```
