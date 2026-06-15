package etcd

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/k3s-io/k3s/pkg/daemons/config"
	certutil "k8s.io/client-go/util/cert"
)

func Test_UnitToTLSConfigReloadsClientCert(t *testing.T) {
	dir := t.TempDir()
	runtime := &config.ControlRuntime{
		ClientETCDCert: filepath.Join(dir, "client.crt"),
		ClientETCDKey:  filepath.Join(dir, "client.key"),
	}
	runtime.ETCDServerCA = filepath.Join(dir, "server-ca.crt")

	writeCert := func(host string, writeKey bool) []byte {
		certPEM, keyPEM, err := certutil.GenerateSelfSignedCertKey(host, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(runtime.ClientETCDCert, certPEM, 0600)
		if writeKey {
			os.WriteFile(runtime.ClientETCDKey, keyPEM, 0600)
		}
		certs, _ := certutil.ParseCertsPEM(certPEM)
		return certs[0].Raw
	}
	clientCert := func(tlsConfig *tls.Config) []byte {
		cert, err := tlsConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
		if err != nil {
			t.Fatal(err)
		}
		return cert.Certificate[0]
	}

	caPEM, _, _ := certutil.GenerateSelfSignedCertKey("etcd-server-ca", nil, nil)
	os.WriteFile(runtime.ETCDServerCA, caPEM, 0600)
	writeCert("first", true)
	tlsConfig, err := toTLSConfig(runtime)
	if err != nil {
		t.Fatal(err)
	}

	second := writeCert("second", true)
	if !bytes.Equal(clientCert(tlsConfig), second) {
		t.Error("Expected renewed client cert to be used")
	}

	// a cert that does not match the key, as seen while the files are being replaced,
	// falls back to the previously loaded cert
	writeCert("third", false)
	if !bytes.Equal(clientCert(tlsConfig), second) {
		t.Error("Expected previously loaded client cert to be used")
	}
}
