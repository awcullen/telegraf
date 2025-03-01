//go:build !custom || inputs || inputs.opcua_client

package all

import _ "github.com/influxdata/telegraf/plugins/inputs/opcua_client" // register plugin
