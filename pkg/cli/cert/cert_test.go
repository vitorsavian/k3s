package cert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	//revive:disable:dot-imports
	. "github.com/onsi/gomega"

	"github.com/k3s-io/k3s/pkg/cli/cmds"
	certutil "github.com/rancher/dynamiclistener/cert"
	"github.com/urfave/cli/v2"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// newTestKey returns a new private key and its PEM encoding.
func newTestKey(t *testing.T) (crypto.Signer, []byte) {
	g := NewWithT(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	g.Expect(err).ToNot(HaveOccurred())
	keyPEM, err := certutil.MarshalPrivateKeyToPEM(key)
	g.Expect(err).ToNot(HaveOccurred())
	return key, keyPEM
}

// newTestCert returns a PEM-encoded cert for key, signed by a throwaway CA.
func newTestCert(t *testing.T, key crypto.Signer, cn string, ips ...net.IP) []byte {
	g := NewWithT(t)
	caKey, _ := newTestKey(t)
	caCert, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: "test-ca"}, caKey)
	g.Expect(err).ToNot(HaveOccurred())
	cert, err := certutil.NewSignedCert(certutil.Config{
		CommonName: cn,
		Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		AltNames:   certutil.AltNames{IPs: ips},
	}, key, caCert, caKey)
	g.Expect(err).ToNot(HaveOccurred())
	return certutil.EncodeCertPEM(cert)
}

func fileMode(t *testing.T, path string) os.FileMode {
	fi, err := os.Stat(path)
	NewWithT(t).Expect(err).ToNot(HaveOccurred())
	return fi.Mode().Perm()
}

func Test_UnitWriteFilesAtomic(t *testing.T) {
	g := NewWithT(t)
	dir := t.TempDir()
	certFile := filepath.Join(dir, "serving.crt")
	keyFile := filepath.Join(dir, "serving.key")
	g.Expect(os.WriteFile(certFile, []byte("old"), 0644)).To(Succeed())

	// a failed write leaves the existing files unchanged
	err := writeFilesAtomic(fileData{certFile, []byte("new")}, fileData{filepath.Join(dir, "missing", "serving.key"), []byte("new")})
	g.Expect(err).To(HaveOccurred())
	g.Expect(os.ReadFile(certFile)).To(BeEquivalentTo("old"))

	// existing file modes are preserved, and new files are created 0600
	g.Expect(writeFilesAtomic(fileData{certFile, []byte("new")}, fileData{keyFile, []byte("new")})).To(Succeed())
	g.Expect(os.ReadFile(certFile)).To(BeEquivalentTo("new"))
	if runtime.GOOS != "windows" {
		g.Expect(fileMode(t, certFile)).To(Equal(os.FileMode(0644)))
		g.Expect(fileMode(t, keyFile)).To(Equal(os.FileMode(0600)))
	}
	g.Expect(filepath.Glob(filepath.Join(dir, ".*.tmp-*"))).To(BeEmpty())
}

func Test_UnitUpdateKubeconfigClientCert(t *testing.T) {
	g := NewWithT(t)
	path := filepath.Join(t.TempDir(), "k3s.yaml")
	adminKey, adminKeyPEM := newTestKey(t)
	otherKey, otherKeyPEM := newTestKey(t)
	oldCert := newTestCert(t, adminKey, "system:admin")
	newCert := newTestCert(t, adminKey, "system:admin")
	otherCert := newTestCert(t, otherKey, "other")

	kc := clientcmdapi.NewConfig()
	kc.AuthInfos["admin"] = &clientcmdapi.AuthInfo{ClientCertificateData: oldCert, ClientKeyData: adminKeyPEM}
	kc.AuthInfos["other"] = &clientcmdapi.AuthInfo{ClientCertificateData: otherCert, ClientKeyData: otherKeyPEM}
	kc.AuthInfos["files"] = &clientcmdapi.AuthInfo{ClientCertificate: "client-admin.crt", ClientKey: "client-admin.key"}
	g.Expect(clientcmd.WriteToFile(*kc, path)).To(Succeed())
	g.Expect(os.Chmod(path, 0640)).To(Succeed())

	users, err := updateKubeconfigClientCert(path, adminKeyPEM, newCert, nil)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(users).To(ConsistOf("admin"))

	got, err := clientcmd.LoadFromFile(path)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(got.AuthInfos["admin"].ClientCertificateData).To(Equal(newCert))
	g.Expect(got.AuthInfos["admin"].ClientKeyData).To(Equal(adminKeyPEM))
	g.Expect(got.AuthInfos["other"].ClientCertificateData).To(Equal(otherCert))
	g.Expect(got.AuthInfos["files"].ClientCertificate).To(Equal("client-admin.crt"))
	if runtime.GOOS != "windows" {
		g.Expect(fileMode(t, path)).To(Equal(os.FileMode(0640)))
	}
}

func Test_UnitResolveNodeIdentity(t *testing.T) {
	key, _ := newTestKey(t)
	servingCert := newTestCert(t, key, "node-a", net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.5"))
	clientCert := newTestCert(t, key, "system:node:node-b")
	config := map[string][]string{"node-name": {"from-config"}, "node-ip": {"192.0.2.1"}}

	tests := []struct {
		name     string
		certFile string
		certPEM  []byte
		flags    cmds.CertReload
		wantName string
		wantIP   string
	}{
		{"serving cert takes precedence over config", "serving-kubelet.crt", servingCert, cmds.CertReload{}, "node-a", "10.0.0.5"},
		{"client cert name with config ip", "client-kubelet.crt", clientCert, cmds.CertReload{}, "node-b", "192.0.2.1"},
		{"flags take precedence over certs", "serving-kubelet.crt", servingCert, cmds.CertReload{NodeName: "flag", NodeIPs: *cli.NewStringSlice("192.0.2.10")}, "flag", "192.0.2.10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			agentDir := t.TempDir()
			g.Expect(os.WriteFile(filepath.Join(agentDir, tt.certFile), tt.certPEM, 0600)).To(Succeed())

			name, ips, err := resolveNodeIdentity(context.Background(), &tt.flags, agentDir, config)
			g.Expect(err).ToNot(HaveOccurred())
			g.Expect(name).To(Equal(tt.wantName))
			g.Expect(ips).To(HaveLen(1))
			g.Expect(ips[0].String()).To(Equal(tt.wantIP))
		})
	}
}
