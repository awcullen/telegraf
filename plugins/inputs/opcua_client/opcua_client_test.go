package opcua_client_test

import (
	"testing"

	"github.com/awcullen/opcua/server"
	"github.com/awcullen/opcua/ua"
	"github.com/stretchr/testify/require"

	"github.com/influxdata/telegraf/plugins/common/tls"
	"github.com/influxdata/telegraf/plugins/inputs/opcua_client"
	"github.com/influxdata/telegraf/testutil"
)

func TestClient(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	srv, err := startOpcUaServer(t)
	if err != nil {
		t.Error(err)
	}
	defer srv.Close()

	input := &opcua_client.Input{
		EndpointURL:    "opc.tcp://127.0.0.1:46010",
		SecurityPolicy: "none",
		DataMetrics: []opcua_client.DataMetricDefinition{
			{
				Name:               "test",
				PublishingInterval: 1000.0,
				Fields:             map[string]opcua_client.DataFieldDefinition{"ServerTime": {NodeID: "i=2258"}},
				Tags:               map[string]string{"foo": "bar"},
			},
		},
		ClientConfig: tls.ClientConfig{
			InsecureSkipVerify: true,
		},
		Log: testutil.Logger{},
	}

	var acc testutil.Accumulator

	require.NoError(t, input.Start(&acc))
	require.NoError(t, input.Gather(&acc))
	acc.Wait(1)
	input.Stop()
	require.True(t, acc.HasField("test", "ServerTime"))
	require.True(t, acc.HasTag("test", "foo"))

}

func TestClientWithSecurity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	srv, err := startOpcUaServer(t)
	if err != nil {
		t.Error(err)
	}
	defer srv.Close()

	input := &opcua_client.Input{
		EndpointURL:    "opc.tcp://127.0.0.1:46010",
		SecurityPolicy: "Basic256Sha256",
		DataMetrics: []opcua_client.DataMetricDefinition{
			{
				Name:               "test",
				PublishingInterval: 1000.0,
				Fields:             map[string]opcua_client.DataFieldDefinition{"ServerTime": {NodeID: "i=2258"}},
				Tags:               map[string]string{"foo": "bar"},
			},
		},
		ClientConfig: tls.ClientConfig{
			TLSCert: "./pki/client.crt",
			TLSKey:  "./pki/client.key",
			TLSCA:   "./pki/server.crt",
		},
		Log: testutil.Logger{},
	}

	var acc testutil.Accumulator

	require.NoError(t, input.Start(&acc))
	require.NoError(t, input.Gather(&acc))
	acc.Wait(1)
	input.Stop()
	require.True(t, acc.HasField("test", "ServerTime"))
	require.True(t, acc.HasTag("test", "foo"))

}

func startOpcUaServer(t *testing.T) (*server.Server, error) {
	srv, err := server.New(
		ua.ApplicationDescription{
			ApplicationURI:      "urn:localhost:testserver",
			ProductURI:          "http://github.com/awcullen/opcua",
			ApplicationName:     ua.LocalizedText{Text: "testserver", Locale: "en"},
			ApplicationType:     ua.ApplicationTypeServer,
			GatewayServerURI:    "",
			DiscoveryProfileURI: "",
			DiscoveryURLs:       []string{"opc.tcp://127.0.0.1:46010"},
		},
		"./pki/server.crt",
		"./pki/server.key",
		"opc.tcp://localhost:46010",
		server.WithAuthenticateAnonymousIdentityFunc(func(_ ua.AnonymousIdentity, _ string, _ string) error { return nil }),
		server.WithSecurityPolicyNone(true),
		server.WithTrustedCertificatesPaths("./pki/client.crt", ""),
	)
	if err != nil {
		return nil, err
	}
	go func() {
		if err := srv.ListenAndServe(); err != ua.BadServerHalted {
			t.Error(err)
		}
	}()
	return srv, nil
}
