package handlers

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/daemons/control/deps"
	"github.com/k3s-io/k3s/pkg/util"
	"github.com/k3s-io/k3s/pkg/util/errors"
	"github.com/k3s-io/k3s/pkg/version"
	certutil "github.com/rancher/dynamiclistener/cert"
	"k8s.io/apiserver/pkg/authentication/user"
)

// CertReloadPath returns the URL path of the cert reload endpoint for the named certificate.
func CertReloadPath(name string) string {
	return path.Join("/v1-"+version.Program+"/cert", name)
}

// The cert reload handlers re-sign the server's certificates with the existing CAs,
// using the public key from the client's CSR. The certificate fields must match the
// ones used by deps.GenServerDeps when generating the certificates at startup.

func ServingKubeAPICert(control *config.Control) http.Handler {
	return localOnly(requireCSR(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ServerCA, control.Runtime.ServerCAKey, control.Runtime.ServingKubeAPIKey, certutil.Config{
			CommonName: "kube-apiserver",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			AltNames:   *deps.APIServerAltNames(control),
		})
	})))
}

func ServingKubeSchedulerCert(control *config.Control) http.Handler {
	return requireCSR(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ServerCA, control.Runtime.ServerCAKey, control.Runtime.ServingKubeSchedulerKey, certutil.Config{
			CommonName: "kube-scheduler",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			AltNames:   *deps.LoopbackAltNames(),
		})
	}))
}

func ServingKubeControllerCert(control *config.Control) http.Handler {
	return requireCSR(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ServerCA, control.Runtime.ServerCAKey, control.Runtime.ServingKubeControllerKey, certutil.Config{
			CommonName: "kube-controller-manager",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			AltNames:   *deps.LoopbackAltNames(),
		})
	}))
}

func ServingETCDServerCert(control *config.Control) http.Handler {
	return localOnly(requireCSR(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if control.DisableETCD {
			util.SendError(errors.New("etcd is disabled on this server"), resp, req, http.StatusBadRequest)
			return
		}
		signAndSend(resp, req, control.Runtime.ETCDServerCA, control.Runtime.ETCDServerCAKey, control.Runtime.ServerETCDKey, certutil.Config{
			CommonName: "etcd-server",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			AltNames:   *deps.ETCDAltNames(control),
		})
	})))
}

func ServingETCDPeerCert(control *config.Control) http.Handler {
	return localOnly(requireCSR(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ETCDPeerCA, control.Runtime.ETCDPeerCAKey, control.Runtime.PeerServerClientETCDKey, certutil.Config{
			CommonName: "etcd-peer",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			AltNames:   *deps.ETCDAltNames(control),
		})
	})))
}

func ClientETCDCert(control *config.Control) http.Handler {
	return requireCSR(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ETCDServerCA, control.Runtime.ETCDServerCAKey, control.Runtime.ClientETCDKey, certutil.Config{
			CommonName: "etcd-client",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	}))
}

func ClientAdminCert(control *config.Control) http.Handler {
	return requireCSR(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ClientCA, control.Runtime.ClientCAKey, control.Runtime.ClientAdminKey, certutil.Config{
			CommonName:   "system:admin",
			Organization: []string{user.SystemPrivilegedGroup},
			Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	}))
}

func ClientSupervisorCert(control *config.Control) http.Handler {
	return requireCSR(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ClientCA, control.Runtime.ClientCAKey, control.Runtime.ClientSupervisorKey, certutil.Config{
			CommonName:   "system:" + version.Program + "-supervisor",
			Organization: []string{user.SystemPrivilegedGroup},
			Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	}))
}

func ClientControllerManagerCert(control *config.Control) http.Handler {
	return requireCSR(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ClientCA, control.Runtime.ClientCAKey, control.Runtime.ClientControllerKey, certutil.Config{
			CommonName: user.KubeControllerManager,
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	}))
}

func ClientSchedulerCert(control *config.Control) http.Handler {
	return requireCSR(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ClientCA, control.Runtime.ClientCAKey, control.Runtime.ClientSchedulerKey, certutil.Config{
			CommonName: user.KubeScheduler,
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	}))
}

func ClientKubeAPIServerCert(control *config.Control) http.Handler {
	return requireCSR(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ClientCA, control.Runtime.ClientCAKey, control.Runtime.ClientKubeAPIKey, certutil.Config{
			CommonName:   user.APIServerUser,
			Organization: []string{user.SystemPrivilegedGroup},
			Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	}))
}

func ClientCloudControllerCert(control *config.Control) http.Handler {
	return requireCSR(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.ClientCA, control.Runtime.ClientCAKey, control.Runtime.ClientCloudControllerKey, certutil.Config{
			CommonName: version.Program + "-cloud-controller-manager",
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	}))
}

func ClientAuthProxyCert(control *config.Control) http.Handler {
	return requireCSR(http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		signAndSend(resp, req, control.Runtime.RequestHeaderCA, control.Runtime.RequestHeaderCAKey, control.Runtime.ClientAuthProxyKey, certutil.Config{
			CommonName: deps.RequestHeaderCN,
			Usages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
	}))
}

// DynamicListenerRegenerate regenerates the certificate served by the supervisor listener.
func DynamicListenerRegenerate(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			util.SendError(errors.New("method not allowed"), resp, req, http.StatusMethodNotAllowed)
			return
		}
		regen := control.Runtime.RegenerateSupervisorCert
		if regen == nil {
			util.SendError(errors.New("supervisor certificate regeneration is not available"), resp, req, http.StatusServiceUnavailable)
			return
		}
		if err := regen(); err != nil {
			util.SendErrorWithID(err, "dynamic-listener", resp, req, http.StatusInternalServerError)
			return
		}
		resp.WriteHeader(http.StatusNoContent)
	})
}

// requireCSR rejects requests that do not contain a valid CSR, so that signAndSend
// never falls back to signing and returning the legacy shared key.
func requireCSR(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			util.SendError(errors.New("method not allowed"), resp, req, http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			util.SendError(err, resp, req, http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(body)
		if err != nil {
			util.SendError(errors.WithMessage(err, "invalid certificate signing request"), resp, req, http.StatusBadRequest)
			return
		}
		if err := csr.CheckSignature(); err != nil {
			util.SendError(errors.WithMessage(err, "invalid certificate signing request signature"), resp, req, http.StatusBadRequest)
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(resp, req)
	})
}

// localOnly rejects requests that do not originate from this node. Serving certificates for
// the apiserver and etcd include this server's node-specific SANs, so issuing them to
// another node would produce a certificate that is not valid for that node.
func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		if !isLocalAddress(req.RemoteAddr) {
			util.SendError(errors.New("serving certificates can only be requested from the local server"), resp, req, http.StatusForbidden)
			return
		}
		next.ServeHTTP(resp, req)
	})
}

// isLocalAddress returns true if the host portion of addr is a loopback address,
// or an address assigned to one of this node's interfaces.
func isLocalAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// CertStatusEntry describes a certificate on disk, and the certificate currently
// served by the component that uses it, if the component can be dialed.
type CertStatusEntry struct {
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	DiskSerial   string    `json:"disk_serial,omitempty"`
	NotBefore    time.Time `json:"not_before,omitzero"`
	NotAfter     time.Time `json:"not_after,omitzero"`
	ServedSerial string    `json:"served_serial,omitempty"`
	HotReloaded  *bool     `json:"hot_reloaded,omitempty"`
	Error        string    `json:"error,omitempty"`
}

// CertStatus returns the serial of each certificate on disk, along with the serial
// of the certificate currently served by the component that uses it.
func CertStatus(control *config.Control) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		entries := collectCertStatus(req.Context(), control)
		resp.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(resp).Encode(entries); err != nil {
			util.SendError(errors.WithMessage(err, "failed to encode cert status"), resp, req, http.StatusInternalServerError)
		}
	})
}

type certStatusTarget struct {
	name   string
	path   string
	dialTo string
}

func certStatusTargets(control *config.Control) []certStatusTarget {
	rt := control.Runtime
	loopback := control.Loopback(false)
	apiServerHost := loopback
	if ip := net.ParseIP(control.APIServerBindAddress); ip != nil && !ip.IsUnspecified() {
		apiServerHost = control.APIServerBindAddress
	}
	etcdPeerDial := ""
	if !control.DisableETCD {
		etcdPeerDial = net.JoinHostPort(loopback, "2380")
	}

	targets := []certStatusTarget{
		{"server-ca", rt.ServerCA, ""},
		{"client-ca", rt.ClientCA, ""},
		{"request-header-ca", rt.RequestHeaderCA, ""},
		{"etcd-server-ca", rt.ETCDServerCA, ""},
		{"etcd-peer-ca", rt.ETCDPeerCA, ""},
		{"serving-kube-apiserver", rt.ServingKubeAPICert, net.JoinHostPort(apiServerHost, strconv.Itoa(control.APIServerPort))},
		{"serving-kube-scheduler", rt.ServingKubeSchedulerCert, net.JoinHostPort(loopback, "10259")},
		{"serving-kube-controller-manager", rt.ServingKubeControllerCert, net.JoinHostPort(loopback, "10257")},
		{"serving-etcd-peer", rt.PeerServerClientETCDCert, etcdPeerDial},
		{"client-etcd", rt.ClientETCDCert, ""},
		{"client-admin", rt.ClientAdminCert, ""},
		{"client-supervisor", rt.ClientSupervisorCert, ""},
		{"client-controller", rt.ClientControllerCert, ""},
		{"client-scheduler", rt.ClientSchedulerCert, ""},
		{"client-kube-apiserver", rt.ClientKubeAPICert, ""},
		{"client-cloud-controller", rt.ClientCloudControllerCert, ""},
		{"client-auth-proxy", rt.ClientAuthProxyCert, ""},
	}

	if !control.DisableETCD {
		targets = append(targets, certStatusTarget{"serving-etcd-server", rt.ServerETCDCert, net.JoinHostPort(loopback, "2379")})
	}

	if !control.DisableAgent {
		// Agent certs are not tracked by the control runtime; ClientKubeProxyCert and
		// ClientK3sControllerCert are legacy paths removed at startup.
		agentDir := filepath.Join(filepath.Dir(control.DataDir), "agent")
		targets = append(targets,
			certStatusTarget{"serving-kubelet", filepath.Join(agentDir, "serving-kubelet.crt"), net.JoinHostPort(loopback, "10250")},
			certStatusTarget{"client-kubelet", filepath.Join(agentDir, "client-kubelet.crt"), ""},
			certStatusTarget{"client-kube-proxy", filepath.Join(agentDir, "kube-proxy", "client-kube-proxy.crt"), ""},
			certStatusTarget{"client-" + version.Program + "-controller", filepath.Join(agentDir, "client-"+version.Program+"-controller.crt"), ""},
		)
	}

	return targets
}

func collectCertStatus(ctx context.Context, control *config.Control) []CertStatusEntry {
	targets := certStatusTargets(control)
	entries := make([]CertStatusEntry, 0, len(targets))
	for _, t := range targets {
		if t.path == "" {
			continue
		}
		entry := CertStatusEntry{Name: t.name, Path: t.path}
		certs, err := certutil.CertsFromFile(t.path)
		if err != nil {
			if os.IsNotExist(err) {
				err = errors.New("file not found")
			}
			entry.Error = err.Error()
			entries = append(entries, entry)
			continue
		}

		entry.DiskSerial = formatSerial(certs[0])
		entry.NotBefore = certs[0].NotBefore
		entry.NotAfter = certs[0].NotAfter

		if t.dialTo != "" {
			if served, err := fetchServedSerial(ctx, t.dialTo); err == nil {
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

// fetchServedSerial returns the serial of the certificate served at addr. The certificate is
// captured during the handshake, as servers that require client certificates may reject the
// connection once it completes.
func fetchServedSerial(ctx context.Context, addr string) (string, error) {
	var served *x509.Certificate
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 3 * time.Second},
		Config: &tls.Config{
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) > 0 {
					served, _ = x509.ParseCertificate(rawCerts[0])
				}
				return nil
			},
		},
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if conn != nil {
		conn.Close()
	}
	if served == nil {
		if err == nil {
			err = errors.New("no peer certificates")
		}
		return "", err
	}
	return formatSerial(served), nil
}
