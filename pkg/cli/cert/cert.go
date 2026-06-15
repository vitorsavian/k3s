package cert

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/k3s-io/k3s/pkg/agent/util"
	"github.com/k3s-io/k3s/pkg/bootstrap"
	"github.com/k3s-io/k3s/pkg/cli/cmds"
	"github.com/k3s-io/k3s/pkg/clientaccess"
	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/daemons/control/deps"
	"github.com/k3s-io/k3s/pkg/datadir"
	"github.com/k3s-io/k3s/pkg/proctitle"
	"github.com/k3s-io/k3s/pkg/server"
	"github.com/k3s-io/k3s/pkg/server/handlers"
	k3sutil "github.com/k3s-io/k3s/pkg/util"
	"github.com/k3s-io/k3s/pkg/util/errors"
	"github.com/k3s-io/k3s/pkg/util/services"
	"github.com/k3s-io/k3s/pkg/version"
	"github.com/otiai10/copy"
	certutil "github.com/rancher/dynamiclistener/cert"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"
)

// Certificate defines a single certificate data structure
type Certificate struct {
	Filename     string
	Subject      string
	Issuer       string
	Usages       []string
	ExpiryTime   time.Time
	ResidualTime time.Duration
	Status       string // "OK", "WARNING", "EXPIRED", "NOT YET VALID"
}

// CertificateInfo defines the structure for storing certificate information
type CertificateInfo struct {
	Certificates  []Certificate
	ReferenceTime time.Time `json:"-" yaml:"-"`
}

// collectCertInfo collects information about certificates
func collectCertInfo(controlConfig config.Control, servicesList []string) (*CertificateInfo, error) {
	result := &CertificateInfo{}
	now := time.Now()
	warn := now.Add(time.Hour * 24 * config.CertificateRenewDays)

	fileMap, err := services.FilesForServices(controlConfig, servicesList)
	if err != nil {
		return nil, err
	}

	for _, files := range fileMap {
		for _, file := range files {
			certs, err := certutil.CertsFromFile(file)
			if err != nil {
				logrus.Debugf("%v", err)
				continue
			}

			for _, cert := range certs {
				expiration := cert.NotAfter
				status := k3sutil.GetCertStatus(cert, now, warn)
				if status == k3sutil.CertStatusNotYetValid {
					expiration = cert.NotBefore
				}
				usages := k3sutil.GetCertUsages(cert)
				result.Certificates = append(result.Certificates, Certificate{
					Filename:     filepath.Base(file),
					Subject:      cert.Subject.CommonName,
					Issuer:       cert.Issuer.CommonName,
					Usages:       usages,
					ExpiryTime:   expiration,
					ResidualTime: cert.NotAfter.Sub(now),
					Status:       status,
				})
			}
		}
	}
	result.ReferenceTime = now
	return result, nil
}

// Formatter defines the interface for formatting certificate information
type Formatter interface {
	Format(*CertificateInfo) error
}

// TextFormatter implements text format output
type TextFormatter struct {
	Writer io.Writer
}

func (f *TextFormatter) Format(certInfo *CertificateInfo) error {
	for _, cert := range certInfo.Certificates {
		usagesStr := strings.Join(cert.Usages, ",")
		switch cert.Status {
		case k3sutil.CertStatusNotYetValid:
			logrus.Errorf("%s: certificate %s (%s) is not valid before %s",
				cert.Filename, cert.Subject, usagesStr, cert.ExpiryTime.Format(time.RFC3339))
		case k3sutil.CertStatusExpired:
			logrus.Errorf("%s: certificate %s (%s) expired at %s",
				cert.Filename, cert.Subject, usagesStr, cert.ExpiryTime.Format(time.RFC3339))
		case k3sutil.CertStatusWarning:
			logrus.Warnf("%s: certificate %s (%s) will expire within %d days at %s",
				cert.Filename, cert.Subject, usagesStr, config.CertificateRenewDays, cert.ExpiryTime.Format(time.RFC3339))
		default:
			logrus.Infof("%s: certificate %s (%s) is ok, expires at %s",
				cert.Filename, cert.Subject, usagesStr, cert.ExpiryTime.Format(time.RFC3339))
		}
	}
	return nil
}

// TableFormatter implements table format output
type TableFormatter struct {
	Writer io.Writer
}

func (f *TableFormatter) Format(certInfo *CertificateInfo) error {
	w := tabwriter.NewWriter(f.Writer, 0, 0, 3, ' ', 0)
	now := certInfo.ReferenceTime
	defer w.Flush()

	fmt.Fprint(w, "\nFILENAME\tSUBJECT\tUSAGES\tEXPIRES\tRESIDUAL TIME\tSTATUS\n")
	fmt.Fprint(w, "--------\t-------\t------\t-------\t-------------\t------\n")

	for _, cert := range certInfo.Certificates {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			cert.Filename,
			cert.Subject,
			strings.Join(cert.Usages, ","),
			cert.ExpiryTime.Format("Jan 02, 2006 15:04 MST"),
			humanize.RelTime(now, now.Add(cert.ResidualTime), "", ""),
			cert.Status)
	}
	return nil
}

// JSONFormatter implements JSON format output
type JSONFormatter struct {
	Writer io.Writer
}

func (f *JSONFormatter) Format(certInfo *CertificateInfo) error {
	return json.NewEncoder(f.Writer).Encode(certInfo)
}

// YAMLFormatter implements YAML format output
type YAMLFormatter struct {
	Writer io.Writer
}

func (f *YAMLFormatter) Format(certInfo *CertificateInfo) error {
	return yaml.NewEncoder(f.Writer).Encode(certInfo)
}

func commandSetup(app *cli.Context, cfg *cmds.Server, sc *server.Config) (string, error) {
	proctitle.SetProcTitle(os.Args[0])

	dataDir, err := datadir.Resolve(cfg.DataDir)
	if err != nil {
		return "", err
	}
	sc.ControlConfig.DataDir = filepath.Join(dataDir, "server")

	if cfg.Token == "" {
		fp := filepath.Join(sc.ControlConfig.DataDir, "token")
		tokenByte, err := os.ReadFile(fp)
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		cfg.Token = string(bytes.TrimRight(tokenByte, "\n"))
	}
	sc.ControlConfig.Token = cfg.Token
	sc.ControlConfig.Runtime = config.NewRuntime()

	return dataDir, nil
}

func Check(app *cli.Context) error {
	if err := cmds.InitLogging(); err != nil {
		return err
	}
	return check(app, &cmds.ServerConfig)
}

// check checks the status of the certificates
func check(app *cli.Context, cfg *cmds.Server) error {
	var serverConfig server.Config

	_, err := commandSetup(app, cfg, &serverConfig)
	if err != nil {
		return err
	}

	deps.CreateRuntimeCertFiles(&serverConfig.ControlConfig)

	if err := validateCertConfig(); err != nil {
		return err
	}

	if len(cmds.ServicesList.Value()) == 0 {
		// detecting if the command is being run on an agent or server based on presence of the server data-dir
		_, err := os.Stat(serverConfig.ControlConfig.DataDir)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			logrus.Infof("Agent detected, checking agent certificates")
			cmds.ServicesList = *cli.NewStringSlice(services.Agent...)
		} else {
			logrus.Infof("Server detected, checking agent and server certificates")
			cmds.ServicesList = *cli.NewStringSlice(services.All...)
		}
	}

	certInfo, err := collectCertInfo(serverConfig.ControlConfig, cmds.ServicesList.Value())
	if err != nil {
		return err
	}
	outFmt := app.String("output")

	var formatter Formatter
	switch outFmt {
	case "text":
		formatter = &TextFormatter{Writer: os.Stdout}
	case "table":
		formatter = &TableFormatter{Writer: os.Stdout}
	case "json":
		formatter = &JSONFormatter{Writer: os.Stdout}
	case "yaml":
		formatter = &YAMLFormatter{Writer: os.Stdout}
	default:
		return fmt.Errorf("invalid output format %s", outFmt)
	}

	return formatter.Format(certInfo)
}

func Rotate(app *cli.Context) error {
	if err := cmds.InitLogging(); err != nil {
		return err
	}
	return rotate(app, &cmds.ServerConfig)
}

func rotate(app *cli.Context, cfg *cmds.Server) error {
	var serverConfig server.Config

	dataDir, err := commandSetup(app, cfg, &serverConfig)
	if err != nil {
		return err
	}

	deps.CreateRuntimeCertFiles(&serverConfig.ControlConfig)

	if err := validateCertConfig(); err != nil {
		return err
	}

	if len(cmds.ServicesList.Value()) == 0 {
		// detecting if the command is being run on an agent or server based on presence of the server data-dir
		_, err := os.Stat(serverConfig.ControlConfig.DataDir)
		if err != nil {
			if !os.IsNotExist(err) {
				return err
			}
			logrus.Infof("Agent detected, rotating agent certificates")
			cmds.ServicesList = *cli.NewStringSlice(services.Agent...)
		} else {
			logrus.Infof("Server detected, rotating agent and server certificates")
			cmds.ServicesList = *cli.NewStringSlice(services.All...)
		}
	}

	fileMap, err := services.FilesForServices(serverConfig.ControlConfig, cmds.ServicesList.Value())
	if err != nil {
		return err
	}

	// back up all the files
	agentDataDir := filepath.Join(dataDir, "agent")
	tlsBackupDir, err := backupCertificates(serverConfig.ControlConfig.DataDir, agentDataDir, fileMap)
	if err != nil {
		return err
	}

	// The dynamiclistener cache file can't be simply deleted, we need to create a trigger
	// file to indicate that the cert needs to be regenerated on startup.
	for _, service := range cmds.ServicesList.Value() {
		if service == version.Program+services.ProgramServer {
			dynamicListenerRegenFilePath := filepath.Join(serverConfig.ControlConfig.DataDir, "tls", "dynamic-cert-regenerate")
			if err := os.WriteFile(dynamicListenerRegenFilePath, []byte{}, 0600); err != nil {
				return err
			}
			logrus.Infof("Rotating dynamic listener certificate")
		}
	}

	// remove all files
	for service, files := range fileMap {
		logrus.Info("Rotating certificates for " + service)
		for _, file := range files {
			if err := os.Remove(file); err == nil {
				logrus.Debugf("file %s is deleted", file)
			}
		}
	}
	logrus.Infof("Successfully backed up certificates to %s, please restart %s server or agent to rotate certificates", tlsBackupDir, version.Program)
	return nil
}

func backupCertificates(serverDataDir, agentDataDir string, fileMap map[string][]string) (string, error) {
	backupDirName := fmt.Sprintf("tls-%d", time.Now().Unix())
	serverTLSDir := filepath.Join(serverDataDir, "tls")
	tlsBackupDir := filepath.Join(agentDataDir, backupDirName)

	// backup the server TLS dir if it exists
	if _, err := os.Stat(serverTLSDir); err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
	} else {
		tlsBackupDir = filepath.Join(serverDataDir, backupDirName)
		if err := copy.Copy(serverTLSDir, tlsBackupDir); err != nil {
			return "", err
		}
	}

	for _, files := range fileMap {
		for _, file := range files {
			if strings.HasPrefix(file, agentDataDir) {
				cert := filepath.Base(file)
				tlsBackupCert := filepath.Join(tlsBackupDir, cert)
				if err := util.CopyFile(file, tlsBackupCert, true); err != nil {
					return "", err
				}
			}
		}
	}

	return tlsBackupDir, nil
}

func validateCertConfig() error {
	for _, s := range cmds.ServicesList.Value() {
		if !services.IsValid(s) {
			return errors.New("service " + s + " is not recognized")
		}
	}
	return nil
}

func RotateCA(app *cli.Context) error {
	if err := cmds.InitLogging(); err != nil {
		return err
	}
	return rotateCA(app, &cmds.ServerConfig, &cmds.CertRotateCAConfig)
}

func rotateCA(app *cli.Context, cfg *cmds.Server, sync *cmds.CertRotateCA) error {
	var serverConfig server.Config

	_, err := commandSetup(app, cfg, &serverConfig)
	if err != nil {
		return err
	}

	info, err := clientaccess.ParseAndValidateToken(cmds.ServerConfig.ServerURL, serverConfig.ControlConfig.Token, clientaccess.WithUser("server"))
	if err != nil {
		return err
	}

	// Set up dummy server config for reading new bootstrap data from disk.
	tmpServer := &config.Control{
		Runtime: config.NewRuntime(),
		DataDir: sync.CACertPath,
	}
	deps.CreateRuntimeCertFiles(tmpServer)

	// Override these paths so that we don't get warnings when they don't exist, as the user is not expected to provide them.
	tmpServer.Runtime.PasswdFile = "/dev/null"
	tmpServer.Runtime.IPSECKey = "/dev/null"

	buf := &bytes.Buffer{}
	if err := bootstrap.ReadFromDisk(buf, &tmpServer.Runtime.ControlRuntimeBootstrap); err != nil {
		return err
	}

	url := fmt.Sprintf("/v1-%s/cert/cacerts?force=%t", version.Program, sync.Force)
	if err = info.Put(url, buf.Bytes()); err != nil {
		return errors.WithMessage(err, "see server log for details")
	}

	fmt.Println("certificates saved to datastore")
	return nil
}

// reloadTarget describes one cert file that the reload flow regenerates against the cluster server.
type reloadTarget struct {
	service     string // service name from pkg/util/services (used to filter via --service)
	urlPath     string // server-side URL path returning a fresh signed cert
	certFile    string // local file where the cert PEM is written
	keyFile     string // local file where the key PEM is written (if the server returns one)
	sendNodeHdr bool   // include X-K3s-Node-Name / X-K3s-Node-IP headers for SAN-bearing certs
}

// Reload is the entry point for `k3s certificate reload`.
func Reload(app *cli.Context) error {
	if err := cmds.InitLogging(); err != nil {
		return err
	}
	return reload(app, &cmds.ServerConfig, &cmds.CertReloadConfig)
}

func reload(app *cli.Context, cfg *cmds.Server, rl *cmds.CertReload) error {
	var serverConfig server.Config

	dataDir, err := commandSetup(app, cfg, &serverConfig)
	if err != nil {
		return err
	}

	deps.CreateRuntimeCertFiles(&serverConfig.ControlConfig)

	if err := validateCertConfig(); err != nil {
		return err
	}

	_, serverErr := os.Stat(serverConfig.ControlConfig.DataDir)
	isServer := serverErr == nil
	if !isServer && !os.IsNotExist(serverErr) {
		return serverErr
	}

	if len(cmds.ServicesList.Value()) == 0 {
		if isServer {
			logrus.Infof("Server detected, reloading agent and server certificates")
			cmds.ServicesList = *cli.NewStringSlice(services.All...)
		} else {
			logrus.Infof("Agent detected, reloading agent certificates")
			cmds.ServicesList = *cli.NewStringSlice(services.Agent...)
		}
	}
	selected := stringSet(cmds.ServicesList.Value())

	nodeName, nodeIPs, err := resolveNodeIdentity(rl)
	if err != nil {
		return err
	}

	if isServer {
		return reloadServer(app, cfg, &serverConfig, dataDir, selected, nodeName, nodeIPs)
	}
	return reloadAgent(cfg, &serverConfig, dataDir, selected, nodeName, nodeIPs)
}

// reloadServer pulls fresh server-side certificates from the cluster server and overwrites them
// on disk. Components with file-watching support pick the new certs up automatically. If agent
// services are selected (default on every node that also runs kubelet/kube-proxy), the local
// agent certs are refreshed in the same pass using the same server token — the agent routes
// also accept the k3s:server role.
func reloadServer(app *cli.Context, cfg *cmds.Server, serverConfig *server.Config, dataDir string, selected map[string]bool, nodeName string, nodeIPs []net.IP) error {
	info, err := clientaccess.ParseAndValidateToken(cmds.ServerConfig.ServerURL, serverConfig.ControlConfig.Token, clientaccess.WithUser("server"))
	if err != nil {
		return err
	}

	rt := serverConfig.ControlConfig.Runtime
	targets := []reloadTarget{
		// Serving certs the local control plane components actually present on the wire.
		{service: services.APIServer, urlPath: handlers.CertReloadPath("serving-kube-apiserver"), certFile: rt.ServingKubeAPICert, keyFile: rt.ServingKubeAPIKey, sendNodeHdr: true},
		{service: services.Scheduler, urlPath: handlers.CertReloadPath("serving-kube-scheduler"), certFile: rt.ServingKubeSchedulerCert, keyFile: rt.ServingKubeSchedulerKey},
		{service: services.ControllerManager, urlPath: handlers.CertReloadPath("serving-kube-controller-manager"), certFile: rt.ServingKubeControllerCert, keyFile: rt.ServingKubeControllerKey},
		{service: services.ETCD, urlPath: handlers.CertReloadPath("serving-etcd-server"), certFile: rt.ServerETCDCert, keyFile: rt.ServerETCDKey, sendNodeHdr: true},
		{service: services.ETCD, urlPath: handlers.CertReloadPath("serving-etcd-peer"), certFile: rt.PeerServerClientETCDCert, keyFile: rt.PeerServerClientETCDKey, sendNodeHdr: true},
		{service: services.ETCD, urlPath: handlers.CertReloadPath("client-etcd"), certFile: rt.ClientETCDCert, keyFile: rt.ClientETCDKey},
		// Client certs consumed via kubeconfigs by in-process components. These don't hot-reload
		// (kubeconfig client cert isn't file-watched) but the user asked for every leaf cert to
		// be refreshed in one pass — the new files will be picked up on the next process restart.
		{service: services.Admin, urlPath: handlers.CertReloadPath("client-admin"), certFile: rt.ClientAdminCert, keyFile: rt.ClientAdminKey},
		{service: services.Supervisor, urlPath: handlers.CertReloadPath("client-supervisor"), certFile: rt.ClientSupervisorCert, keyFile: rt.ClientSupervisorKey},
		{service: services.ControllerManager, urlPath: handlers.CertReloadPath("client-controller"), certFile: rt.ClientControllerCert, keyFile: rt.ClientControllerKey},
		{service: services.Scheduler, urlPath: handlers.CertReloadPath("client-scheduler"), certFile: rt.ClientSchedulerCert, keyFile: rt.ClientSchedulerKey},
		{service: services.APIServer, urlPath: handlers.CertReloadPath("client-kube-apiserver"), certFile: rt.ClientKubeAPICert, keyFile: rt.ClientKubeAPIKey},
		{service: services.CloudController, urlPath: handlers.CertReloadPath("client-cloud-controller"), certFile: rt.ClientCloudControllerCert, keyFile: rt.ClientCloudControllerKey},
		{service: services.AuthProxy, urlPath: handlers.CertReloadPath("client-auth-proxy"), certFile: rt.ClientAuthProxyCert, keyFile: rt.ClientAuthProxyKey},
	}

	reloaded := 0
	for _, t := range targets {
		if !selected[t.service] {
			continue
		}
		logrus.Infof("Reloading %s", filepath.Base(t.certFile))
		if err := fetchAndWriteServerCert(info, t, nodeName, nodeIPs); err != nil {
			return errors.WithMessagef(err, "failed to reload %s", filepath.Base(t.certFile))
		}
		reloaded++
	}

	// Refresh local agent certs in the same pass — single-node deployments and any server that
	// also runs kubelet have these files under <datadir>/agent/.  Skipped when --disable-agent is
	// in effect (no node-password file present).
	agentReloaded, agentErr := reloadAgentCerts(info, dataDir, selected, nodeName, nodeIPs)
	if agentErr != nil {
		return agentErr
	}
	reloaded += agentReloaded

	// Regenerate the supervisor / apiserver-facing TLS cert served by dynamiclistener on the
	// HTTPS port. Different from serving-kube-apiserver: that cert is what kube-apiserver
	// presents internally; this is what external kubectl clients actually see at :6443.
	if selected[services.APIServer] || selected[version.Program+services.ProgramServer] {
		logrus.Infof("Regenerating dynamic listener (supervisor) certificate")
		if _, err := info.Post(handlers.CertReloadPath("dynamic-listener"), nil); err != nil {
			logrus.Warnf("Failed to regenerate dynamic listener cert: %v", err)
		} else {
			reloaded++
		}
	}

	if reloaded == 0 {
		logrus.Warnf("No certificates matched the selected services; nothing to reload")
	}

	if err := reportServedStatus(info); err != nil {
		logrus.Warnf("Failed to query cert status endpoint: %v", err)
	}
	return nil
}

// reloadAgent re-fetches per-node agent certs (serving-kubelet, client-kubelet, kube-proxy,
// k3s-controller) from existing agent routes. Authentication uses the supplied cluster token
// plus the node-password headers already validated by the cluster server.
func reloadAgent(cfg *cmds.Server, serverConfig *server.Config, dataDir string, selected map[string]bool, nodeName string, nodeIPs []net.IP) error {
	if cfg.Token == "" {
		return errors.New("a cluster token is required to reload agent certificates; pass --token or set " + version.ProgramUpper + "_TOKEN")
	}
	info, err := clientaccess.ParseAndValidateToken(cmds.ServerConfig.ServerURL, cfg.Token, clientaccess.WithUser("node"))
	if err != nil {
		return err
	}

	reloaded, err := reloadAgentCerts(info, dataDir, selected, nodeName, nodeIPs)
	if err != nil {
		return err
	}
	if reloaded == 0 {
		logrus.Warnf("No agent certificates matched the selected services; nothing to reload")
	}
	logrus.Infof("kubelet manages its own client/serving cert via CSR; the refreshed files take effect via fsnotify or the next kubelet rotation")
	return nil
}

// reloadAgentCerts walks the agent-side certificate routes (the same ones a joining kubelet hits)
// and overwrites the local copies. Used by both the standalone agent flow and the server flow
// (since every server that runs kubelet locally also needs these refreshed). Returns the number
// of files actually refreshed.
func reloadAgentCerts(info *clientaccess.Info, dataDir string, selected map[string]bool, nodeName string, nodeIPs []net.IP) (int, error) {
	nodePasswordFile := filepath.Join(dataDir, "agent", "node-password.txt")
	if _, err := os.Stat(nodePasswordFile); err != nil {
		nodePasswordFile = "/etc/rancher/node/password"
	}
	if _, err := os.Stat(nodePasswordFile); err != nil {
		// No node-password on this host means the local kubelet was never bootstrapped here
		// (e.g. --disable-agent). Skip agent refresh quietly.
		return 0, nil
	}

	agentDir := filepath.Join(dataDir, "agent")
	type agentTarget struct {
		service     string
		urlPath     string
		certFile    string
		keyFile     string
		sendNodeHdr bool
	}
	targets := []agentTarget{
		{services.Kubelet, "/v1-" + version.Program + "/serving-kubelet.crt", filepath.Join(agentDir, "serving-kubelet.crt"), filepath.Join(agentDir, "serving-kubelet.key"), true},
		{services.Kubelet, "/v1-" + version.Program + "/client-kubelet.crt", filepath.Join(agentDir, "client-kubelet.crt"), filepath.Join(agentDir, "client-kubelet.key"), true},
		{services.KubeProxy, "/v1-" + version.Program + "/client-kube-proxy.crt", filepath.Join(agentDir, "client-kube-proxy.crt"), filepath.Join(agentDir, "client-kube-proxy.key"), false},
		{version.Program + services.ProgramController, "/v1-" + version.Program + "/client-" + version.Program + "-controller.crt", filepath.Join(agentDir, "client-"+version.Program+"-controller.crt"), filepath.Join(agentDir, "client-"+version.Program+"-controller.key"), false},
	}

	reloaded := 0
	for _, t := range targets {
		if !selected[t.service] {
			continue
		}
		logrus.Infof("Reloading %s", filepath.Base(t.certFile))
		csr, err := buildCSR(t.keyFile)
		if err != nil {
			return reloaded, errors.WithMessagef(err, "failed to build CSR for %s", filepath.Base(t.certFile))
		}
		body, err := postWithNodeHeaders(info, t.urlPath, csr, nodeName, nodeIPs, nodePasswordFile, t.sendNodeHdr)
		if err != nil {
			return reloaded, errors.WithMessagef(err, "failed to fetch %s", filepath.Base(t.certFile))
		}
		if err := writeCertAndKey(body, t.certFile, t.keyFile); err != nil {
			return reloaded, err
		}
		reloaded++
	}
	return reloaded, nil
}

// fetchAndWriteServerCert POSTs a CSR built from the local key file (preserving the existing
// private key on disk so the response only contains a fresh cert) and overwrites the cert PEM.
// If the server falls back to legacy behaviour and ships a key, that key replaces the local one.
func fetchAndWriteServerCert(info *clientaccess.Info, t reloadTarget, nodeName string, nodeIPs []net.IP) error {
	csr, err := buildCSR(t.keyFile)
	if err != nil {
		return errors.WithMessagef(err, "failed to build CSR using %s", t.keyFile)
	}
	var body []byte
	if t.sendNodeHdr {
		body, err = postWithNodeHeaders(info, t.urlPath, csr, nodeName, nodeIPs, "", true)
	} else {
		body, err = info.Post(t.urlPath, csr)
	}
	if err != nil {
		return err
	}
	return writeCertAndKey(body, t.certFile, t.keyFile)
}

// buildCSR loads or generates the private key at keyFile and returns a DER-encoded CSR for it.
// The same key is reused so that the new cert lines up with the on-disk key without a restart.
func buildCSR(keyFile string) ([]byte, error) {
	keyBytes, _, err := certutil.LoadOrGenerateKeyFile(keyFile, false)
	if err != nil {
		return nil, err
	}
	key, err := certutil.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificateRequest(cryptorand.Reader, &x509.CertificateRequest{}, key)
}

// writeCertAndKey splits a server response (cert PEM, optionally followed by key PEM for legacy
// clients) and writes each part to disk. fsnotify watchers reload the components on rewrite.
func writeCertAndKey(body []byte, certFile, keyFile string) error {
	certBytes, keyBytes := splitCertKeyPEM(body)
	if len(certBytes) == 0 {
		return errors.New("server response did not contain a certificate")
	}
	if err := writeAtomic(certFile, certBytes, 0600); err != nil {
		return errors.WithMessagef(err, "failed to write %s", certFile)
	}
	if len(keyBytes) > 0 {
		if err := writeAtomic(keyFile, keyBytes, 0600); err != nil {
			return errors.WithMessagef(err, "failed to write %s", keyFile)
		}
	}
	return nil
}

// splitCertKeyPEM splits a concatenated PEM stream into the certificate block(s) and an optional
// trailing private key block. Mirrors the agent-side helper used for the same legacy fallback.
func splitCertKeyPEM(bytes []byte) ([]byte, []byte) {
	idx := strings.Index(string(bytes), "-----BEGIN RSA PRIVATE KEY-----")
	if idx == -1 {
		idx = strings.Index(string(bytes), "-----BEGIN EC PRIVATE KEY-----")
	}
	if idx == -1 {
		idx = strings.Index(string(bytes), "-----BEGIN PRIVATE KEY-----")
	}
	if idx == -1 {
		return bytes, nil
	}
	return bytes[:idx], bytes[idx:]
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// postWithNodeHeaders POSTs body with node identity headers. The node-password file is only
// included when nodePasswordFile is set (agent flow); server-to-server reloads skip it.
func postWithNodeHeaders(info *clientaccess.Info, urlPath string, body []byte, nodeName string, nodeIPs []net.IP, nodePasswordFile string, includeIP bool) ([]byte, error) {
	opts := []any{}
	if nodeName != "" {
		opts = append(opts, clientaccess.WithHeader(version.Program+"-Node-Name", nodeName))
	}
	if includeIP && len(nodeIPs) > 0 {
		opts = append(opts, clientaccess.WithHeader(version.Program+"-Node-IP", k3sutil.JoinIPs(nodeIPs)))
	}
	if nodePasswordFile != "" {
		password, err := os.ReadFile(nodePasswordFile)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to read node password file %s", nodePasswordFile)
		}
		opts = append(opts, clientaccess.WithHeader(version.Program+"-Node-Password", strings.TrimSpace(string(password))))
	}
	return info.Post(urlPath, body, opts...)
}

// reportServedStatus queries the /cert/status endpoint and logs a one-line summary per cert so
// the operator can see immediately whether the running components picked up the new files.
func reportServedStatus(info *clientaccess.Info) error {
	body, err := info.Get("/v1-" + version.Program + "/cert/status")
	if err != nil {
		return err
	}
	var entries []handlers.CertStatusEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	defer w.Flush()
	fmt.Fprintln(w, "\nCERT\tDISK_SERIAL\tSERVED_SERIAL\tHOT_RELOADED\tEXPIRES")
	fmt.Fprintln(w, "----\t-----------\t-------------\t------------\t-------")
	for _, e := range entries {
		served := e.ServedSerial
		if served == "" {
			served = "-"
		}
		reloaded := "-"
		if e.HotReloaded != nil {
			if *e.HotReloaded {
				reloaded = "yes"
			} else {
				reloaded = "no"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", e.Name, truncate(e.DiskSerial, 16), truncate(served, 16), reloaded, e.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// resolveNodeIdentity returns the node hostname and IPs to advertise in SAN-bearing certificate
// requests. CLI flags win; otherwise the OS hostname and the default routing interface are used.
func resolveNodeIdentity(rl *cmds.CertReload) (string, []net.IP, error) {
	nodeName := rl.NodeName
	if nodeName == "" {
		h, err := os.Hostname()
		if err != nil {
			return "", nil, err
		}
		nodeName = strings.ToLower(h)
	}

	var ips []net.IP
	for _, raw := range rl.NodeIPs.Value() {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			return "", nil, fmt.Errorf("invalid --node-ip %q", raw)
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		if ip, err := defaultOutboundIP(); err == nil {
			ips = append(ips, ip)
		}
	}
	return nodeName, ips, nil
}

// defaultOutboundIP returns the local IP used to reach an outside address, without actually
// sending a packet. Useful as a fallback when the user didn't pass --node-ip.
func defaultOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errors.New("unexpected local address type")
	}
	return addr.IP, nil
}

func stringSet(in []string) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, s := range in {
		out[s] = true
	}
	return out
}
