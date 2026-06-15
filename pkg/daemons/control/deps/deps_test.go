package deps

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/k3s-io/k3s/pkg/daemons/config"
	certutil "github.com/rancher/dynamiclistener/cert"
)

func Test_UnitAddSANs(t *testing.T) {
	type args struct {
		altNames *certutil.AltNames
		sans     []string
	}
	tests := []struct {
		name string
		args args
		want certutil.AltNames
	}{
		{
			name: "One IP, One DNS",
			args: args{
				altNames: &certutil.AltNames{},
				sans:     []string{"192.168.205.10", "192.168.205.10.nip.io"},
			},
			want: certutil.AltNames{
				IPs:      []net.IP{net.ParseIP("192.168.205.10")},
				DNSNames: []string{"192.168.205.10.nip.io"},
			},
		},
		{
			name: "Two IP, No DNS",
			args: args{
				altNames: &certutil.AltNames{},
				sans:     []string{"192.168.205.10", "10.168.21.15"},
			},
			want: certutil.AltNames{
				IPs: []net.IP{net.ParseIP("192.168.205.10"), net.ParseIP("10.168.21.15")},
			},
		},
		{
			name: "Duplicates",
			args: args{
				altNames: &certutil.AltNames{DNSNames: []string{"kubernetes"}},
				sans:     []string{"kubernetes", "::1", "0:0:0:0:0:0:0:1", "localhost", "localhost"},
			},
			want: certutil.AltNames{
				IPs:      []net.IP{net.ParseIP("::1")},
				DNSNames: []string{"kubernetes", "localhost"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addSANs(tt.args.altNames, tt.args.sans)
			if !reflect.DeepEqual(*tt.args.altNames, tt.want) {
				t.Errorf("addSANs() = %v, want %v", *tt.args.altNames, tt.want)
			}
		})
	}
}

// Test_UnitMigrateCertKey checks that a cert in the legacy location is moved instead of
// regenerated, and that the kubeconfig referencing it is updated to the new path.
func Test_UnitMigrateCertKey(t *testing.T) {
	control := &config.Control{DataDir: t.TempDir(), Runtime: config.NewRuntime()}
	CreateRuntimeCertFiles(control)
	for _, dir := range []string{"cred", "etc"} {
		os.MkdirAll(filepath.Join(control.DataDir, dir), 0700)
	}
	if err := GenServerDeps(control); err != nil {
		t.Fatal(err)
	}

	rt := control.Runtime
	legacyCert := filepath.Join(control.DataDir, "tls", "client-scheduler.crt")
	legacyKey := filepath.Join(control.DataDir, "tls", "client-scheduler.key")
	for src, dst := range map[string]string{rt.ClientSchedulerCert: legacyCert, rt.ClientSchedulerKey: legacyKey} {
		if err := os.Rename(src, dst); err != nil {
			t.Fatal(err)
		}
	}
	if err := KubeConfig(rt.KubeConfigScheduler, "https://127.0.0.1:6443", rt.ServerCA, legacyCert, legacyKey); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(legacyCert)

	if err := GenServerDeps(control); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(rt.ClientSchedulerCert); err != nil || !bytes.Equal(got, want) {
		t.Errorf("cert was not moved to %s: %v", rt.ClientSchedulerCert, err)
	}
	if exists(legacyCert) || exists(legacyKey) {
		t.Errorf("legacy cert or key was not removed")
	}
	if kubeconfig, _ := os.ReadFile(rt.KubeConfigScheduler); !strings.Contains(string(kubeconfig), "client-key: "+rt.ClientSchedulerKey) {
		t.Errorf("kubeconfig does not reference %s:\n%s", rt.ClientSchedulerKey, kubeconfig)
	}
}
