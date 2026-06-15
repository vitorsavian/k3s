package handlers

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/daemons/control/deps"
	"github.com/k3s-io/k3s/pkg/util"
	"github.com/k3s-io/k3s/pkg/util/errors"
	"github.com/k3s-io/k3s/pkg/version"
	certutil "github.com/rancher/dynamiclistener/cert"
	"k8s.io/apiserver/pkg/authentication/user"
)

// ServingKubeAPICert returns a freshly-signed serving certificate for kube-apiserver.
// The requesting node provides its hostname and IPs via X-K3s-Node-Name / X-K3s-Node-IP
// headers so the resulting cert has the correct SANs for that node.
func ServingKubeAPICert(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		altNames, err := nodeAltNames(req, control, []string{
			"kubernetes",
			"kubernetes.default",
			"kubernetes.default.svc",
			"kubernetes.default.svc." + control.ClusterDomain,
		}, true)
		if err != nil {
			util.SendError(err, resp, req)
			return
		}
		signAndSend(resp, req, control.Runtime.ServerCA, control.Runtime.ServerCAKey, control.Runtime.ServingKubeAPIKey, certutil.Config{
			CommonName: "kube-apiserver",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			AltNames:   altNames,
		})
	})
}

// ServingKubeSchedulerCert returns a freshly-signed serving certificate for kube-scheduler.
// Scheduler only listens on loopback so SANs are fixed.
func ServingKubeSchedulerCert(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ServerCA, control.Runtime.ServerCAKey, control.Runtime.ServingKubeSchedulerKey, certutil.Config{
			CommonName: "kube-scheduler",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			AltNames:   loopbackAltNames(),
		})
	})
}

// ServingKubeControllerCert returns a freshly-signed serving certificate for kube-controller-manager.
func ServingKubeControllerCert(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ServerCA, control.Runtime.ServerCAKey, control.Runtime.ServingKubeControllerKey, certutil.Config{
			CommonName: "kube-controller-manager",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			AltNames:   loopbackAltNames(),
		})
	})
}

// ServingETCDServerCert returns a freshly-signed server-client cert for etcd.
func ServingETCDServerCert(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		altNames, err := nodeAltNames(req, control, []string{"kine.sock"}, false)
		if err != nil {
			util.SendError(err, resp, req)
			return
		}
		signAndSend(resp, req, control.Runtime.ETCDServerCA, control.Runtime.ETCDServerCAKey, control.Runtime.ServerETCDKey, certutil.Config{
			CommonName: "etcd-server",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			AltNames:   altNames,
		})
	})
}

// ServingETCDPeerCert returns a freshly-signed peer-server-client cert for etcd.
func ServingETCDPeerCert(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		altNames, err := nodeAltNames(req, control, []string{"kine.sock"}, false)
		if err != nil {
			util.SendError(err, resp, req)
			return
		}
		signAndSend(resp, req, control.Runtime.ETCDPeerCA, control.Runtime.ETCDPeerCAKey, control.Runtime.PeerServerClientETCDKey, certutil.Config{
			CommonName: "etcd-peer",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			AltNames:   altNames,
		})
	})
}

// ClientETCDCert returns a freshly-signed client cert used by the control plane to talk to etcd.
func ClientETCDCert(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ETCDServerCA, control.Runtime.ETCDServerCAKey, control.Runtime.ClientETCDKey, certutil.Config{
			CommonName: "etcd-client",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	})
}

// ClientAdminCert returns a freshly-signed admin (cluster-admin) client cert.
func ClientAdminCert(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ClientCA, control.Runtime.ClientCAKey, control.Runtime.ClientAdminKey, certutil.Config{
			CommonName:   "system:admin",
			Organization: []string{user.SystemPrivilegedGroup},
			Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	})
}

// ClientSupervisorCert returns a freshly-signed supervisor client cert.
func ClientSupervisorCert(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ClientCA, control.Runtime.ClientCAKey, control.Runtime.ClientSupervisorKey, certutil.Config{
			CommonName:   "system:" + version.Program + "-supervisor",
			Organization: []string{user.SystemPrivilegedGroup},
			Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	})
}

// ClientControllerManagerCert returns a freshly-signed kube-controller-manager client cert.
func ClientControllerManagerCert(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ClientCA, control.Runtime.ClientCAKey, control.Runtime.ClientControllerKey, certutil.Config{
			CommonName: user.KubeControllerManager,
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	})
}

// ClientSchedulerCert returns a freshly-signed kube-scheduler client cert.
func ClientSchedulerCert(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ClientCA, control.Runtime.ClientCAKey, control.Runtime.ClientSchedulerKey, certutil.Config{
			CommonName: user.KubeScheduler,
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	})
}

// ClientKubeAPIServerCert returns the apiserver's client cert (used to talk to the kubelet).
func ClientKubeAPIServerCert(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ClientCA, control.Runtime.ClientCAKey, control.Runtime.ClientKubeAPIKey, certutil.Config{
			CommonName:   user.APIServerUser,
			Organization: []string{user.SystemPrivilegedGroup},
			Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	})
}

// ClientCloudControllerCert returns the cloud-controller-manager client cert.
func ClientCloudControllerCert(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ClientCA, control.Runtime.ClientCAKey, control.Runtime.ClientCloudControllerKey, certutil.Config{
			CommonName: version.Program + "-cloud-controller-manager",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	})
}

// ClientAuthProxyCert returns the auth-proxy client cert. Note this one is signed by the
// request-header CA, not the client CA.
func ClientAuthProxyCert(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.RequestHeaderCA, control.Runtime.RequestHeaderCAKey, control.Runtime.ClientAuthProxyKey, certutil.Config{
			CommonName: deps.RequestHeaderCN,
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	})
}

// DynamicListenerRegenerate triggers an in-place regeneration of the supervisor / apiserver
// TLS cert presented by the dynamiclistener on port 6443. No restart required — the new cert
// is written to storage and the listener's next handshake uses it.
func DynamicListenerRegenerate(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		regen := control.Runtime.RegenerateSupervisorCert
		if regen == nil {
			util.SendError(errors.New("dynamic listener regeneration is not available"), resp, req, http.StatusServiceUnavailable)
			return
		}
		if err := regen(); err != nil {
			util.SendErrorWithID(err, "dynamic-listener", resp, req, http.StatusInternalServerError)
			return
		}
		resp.WriteHeader(http.StatusNoContent)
	})
}

// nodeAltNames builds an AltNames combining caller-provided dnsNames with the requesting node's
// hostname and IPs (read from X-K3s-Node-Name / X-K3s-Node-IP headers). If includeLoopback is
// true, 127.0.0.1 and ::1 are always added — needed for apiserver serving certs.
func nodeAltNames(req *http.Request, control *config.Control, dnsNames []string, includeLoopback bool) (certutil.AltNames, error) {
	altNames := certutil.AltNames{DNSNames: append([]string{}, dnsNames...)}

	if nodeName := req.Header.Get(version.Program + "-Node-Name"); nodeName != "" {
		altNames.DNSNames = append(altNames.DNSNames, nodeName)
	}

	if includeLoopback {
		altNames.IPs = append(altNames.IPs, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
	}

	if nodeIP := req.Header.Get(version.Program + "-Node-IP"); nodeIP != "" {
		for _, v := range strings.Split(nodeIP, ",") {
			ip := net.ParseIP(strings.TrimSpace(v))
			if ip == nil {
				return altNames, fmt.Errorf("invalid node IP address %q", v)
			}
			altNames.IPs = append(altNames.IPs, ip)
		}
	}

	for _, san := range control.SANs {
		if ip := net.ParseIP(san); ip != nil {
			altNames.IPs = append(altNames.IPs, ip)
		} else {
			altNames.DNSNames = append(altNames.DNSNames, san)
		}
	}

	return altNames, nil
}

func loopbackAltNames() certutil.AltNames {
	return certutil.AltNames{
		DNSNames: []string{"localhost"},
		IPs:      []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
}

// CertStatusEntry is a single row in the cert status report.
type CertStatusEntry struct {
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	DiskSerial   string    `json:"disk_serial,omitempty"`
	NotBefore    time.Time `json:"not_before,omitempty"`
	NotAfter     time.Time `json:"not_after,omitempty"`
	ServedSerial string    `json:"served_serial,omitempty"`
	HotReloaded  *bool     `json:"hot_reloaded,omitempty"`
	Error        string    `json:"error,omitempty"`
}

// CertStatus returns the on-disk and currently-served serial of every managed certificate, so
// a caller can verify whether a reload was actually picked up by the components.
func CertStatus(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		entries := collectCertStatus(control)
		resp.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(resp).Encode(entries); err != nil {
			util.SendError(errors.WithMessage(err, "failed to encode cert status"), resp, req, http.StatusInternalServerError)
		}
	})
}

func collectCertStatus(control *config.Control) []CertStatusEntry {
	rt := control.Runtime
	type target struct {
		name   string
		path   string
		dialTo string
	}

	// Agent-side client certs live next to the kubelet under <datadir>/agent on every node
	// that runs the agent components. The server-side ClientK3sControllerCert /
	// ClientKubeProxyCert paths are intentionally deleted at startup by cleanupLegacyCerts
	// in pkg/daemons/control/deps/deps.go, so we point to the agent paths here.
	agentDir := filepath.Join(control.DataDir, "..", "agent")

	apiHost := control.Loopback(true)
	targets := []target{
		{"serving-kube-apiserver", rt.ServingKubeAPICert, net.JoinHostPort(apiHost, fmt.Sprintf("%d", control.APIServerPort))},
		{"serving-kube-scheduler", rt.ServingKubeSchedulerCert, "127.0.0.1:10259"},
		{"serving-kube-controller-manager", rt.ServingKubeControllerCert, "127.0.0.1:10257"},
		{"client-kube-apiserver", rt.ClientKubeAPICert, ""},
		{"client-controller", rt.ClientControllerCert, ""},
		{"client-scheduler", rt.ClientSchedulerCert, ""},
		{"client-admin", rt.ClientAdminCert, ""},
		{"client-supervisor", rt.ClientSupervisorCert, ""},
		{"client-auth-proxy", rt.ClientAuthProxyCert, ""},
		{"client-k3s-cloud-controller", rt.ClientCloudControllerCert, ""},
		{"server-ca", rt.ServerCA, ""},
		{"client-ca", rt.ClientCA, ""},
		{"request-header-ca", rt.RequestHeaderCA, ""},
		{"etcd-server-ca", rt.ETCDServerCA, ""},
		{"etcd-peer-ca", rt.ETCDPeerCA, ""},
		{"serving-etcd-server", rt.ServerETCDCert, ""},
		{"serving-etcd-peer", rt.PeerServerClientETCDCert, ""},
		{"client-etcd", rt.ClientETCDCert, ""},
		{"serving-kubelet", filepath.Join(agentDir, "serving-kubelet.crt"), "127.0.0.1:10250"},
		{"client-kubelet", filepath.Join(agentDir, "client-kubelet.crt"), ""},
		{"client-kube-proxy", filepath.Join(agentDir, "client-kube-proxy.crt"), ""},
		{"client-k3s-controller", filepath.Join(agentDir, "client-"+version.Program+"-controller.crt"), ""},
	}

	entries := make([]CertStatusEntry, 0, len(targets))
	for _, t := range targets {
		if t.path == "" {
			continue
		}
		entry := CertStatusEntry{Name: t.name, Path: t.path}

		if _, err := os.Stat(t.path); err != nil {
			entry.Error = err.Error()
			entries = append(entries, entry)
			continue
		}

		certs, err := certutil.CertsFromFile(t.path)
		if err != nil || len(certs) == 0 {
			if err != nil {
				entry.Error = err.Error()
			} else {
				entry.Error = "no certificates parsed from file"
			}
			entries = append(entries, entry)
			continue
		}

		leaf := certs[0]
		entry.DiskSerial = formatSerial(leaf)
		entry.NotBefore = leaf.NotBefore
		entry.NotAfter = leaf.NotAfter

		if t.dialTo != "" {
			if served, err := fetchServedSerial(t.dialTo); err == nil {
				entry.ServedSerial = served
				match := served == entry.DiskSerial
				entry.HotReloaded = &match
			}
		}

		entries = append(entries, entry)
	}
	return entries
}

func formatSerial(cert *x509.Certificate) string {
	if cert == nil || cert.SerialNumber == nil {
		return ""
	}
	return cert.SerialNumber.Text(16)
}

func fetchServedSerial(addr string) (string, error) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("no peer certificates")
	}
	return formatSerial(certs[0]), nil
}

// CertReloadPath returns the URL path used for the cert reload endpoint of the given service name.
// Centralized so CLI and server stay in sync.
func CertReloadPath(name string) string {
	return path.Join("/v1-"+version.Program+"/cert", name)
}
