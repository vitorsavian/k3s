package cert

import (
	"bytes"
	"context"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/k3s-io/k3s/pkg/agent/loadbalancer"
	"github.com/k3s-io/k3s/pkg/agent/util"
	"github.com/k3s-io/k3s/pkg/bootstrap"
	"github.com/k3s-io/k3s/pkg/cli/cmds"
	"github.com/k3s-io/k3s/pkg/clientaccess"
	"github.com/k3s-io/k3s/pkg/configfilearg"
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
	"k8s.io/client-go/tools/clientcmd"
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

	// Move certs left in their legacy locations by an older version, so that they are rotated.
	agentDataDir := filepath.Join(dataDir, "agent")
	if _, err := os.Stat(serverConfig.ControlConfig.DataDir); err == nil {
		if err := deps.MigrateLegacyCerts(serverConfig.ControlConfig.Runtime); err != nil {
			return err
		}
	}
	if _, err := os.Stat(agentDataDir); err == nil {
		kubeProxyDir := filepath.Join(agentDataDir, "kube-proxy")
		if err := deps.MigrateCertKey(filepath.Join(kubeProxyDir, "client-kube-proxy.crt"), filepath.Join(kubeProxyDir, "client-kube-proxy.key")); err != nil {
			return err
		}
	}

	fileMap, err := services.FilesForServices(serverConfig.ControlConfig, cmds.ServicesList.Value())
	if err != nil {
		return err
	}

	// back up all the files
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

// reloadTarget is a leaf certificate that can be re-issued by the server for the existing key.
type reloadTarget struct {
	service   string
	urlPath   string
	certFile  string
	keyFile   string
	localOnly bool // can only be requested from the local server
	etcd      bool // only present on nodes running embedded etcd
	nodeAuth  bool // send the node name, IPs, and password, as required by the kubelet cert routes
}

type fileData struct {
	path string
	data []byte
}

func Reload(app *cli.Context) error {
	if err := cmds.InitLogging(); err != nil {
		return err
	}
	return reload(app, &cmds.ServerConfig, &cmds.CertReloadConfig)
}

// reload requests new leaf certificates from the server for the existing private keys, and
// writes them to disk. CA certificates and private keys are not changed.
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

	// detecting if the command is being run on an agent or server based on presence of the server data-dir
	isServer := true
	if _, err := os.Stat(serverConfig.ControlConfig.DataDir); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		isServer = false
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

	configValues, err := readConfigValues(app.String("config"))
	if err != nil {
		return errors.WithMessage(err, "failed to read config file")
	}

	agentDataDir := filepath.Join(dataDir, "agent")
	targets := agentReloadTargets(agentDataDir)
	var info *clientaccess.Info
	localServer := false
	if isServer {
		targets = append(serverReloadTargets(serverConfig.ControlConfig.Runtime), targets...)
		info, err = serverReloadAccess(cfg)
		localServer = isLocalURL(cfg.ServerURL)
		if !localServer {
			logrus.Warnf("Server %s is not a local address; skipping serving certificates and the dynamic listener certificate, which can only be renewed by the local server", cfg.ServerURL)
		}
	} else {
		info, err = agentReloadAccess(app, cfg, agentDataDir, configValues)
	}
	if err != nil {
		return err
	}

	// detecting if embedded etcd is in use based on presence of the etcd data-dir
	_, err = os.Stat(filepath.Join(serverConfig.ControlConfig.DataDir, "db", "etcd"))
	etcdMember := err == nil

	targets = selectReloadTargets(targets, cmds.ServicesList.Value(), localServer, etcdMember)

	var nodeName string
	var nodeIPs []net.IP
	if slices.ContainsFunc(targets, func(t reloadTarget) bool { return t.nodeAuth }) {
		nodeName, nodeIPs, err = resolveNodeIdentity(app.Context, rl, agentDataDir, configValues)
		if err != nil {
			return err
		}
		logrus.Infof("Requesting certificates for node %s with IPs %s", nodeName, k3sutil.JoinIPs(nodeIPs))
	}

	var failed []string
	reloaded := 0
	for _, t := range targets {
		name := filepath.Base(t.certFile)
		logrus.Infof("Reloading %s", name)
		// The admin kubeconfig embeds the admin client cert, and is updated after the cert is
		// reloaded. Read the current key first, as down-level servers may replace it.
		var adminKey []byte
		if isServer && t.service == services.Admin {
			adminKey, _ = os.ReadFile(t.keyFile)
		}
		if err := reloadCert(info, t, nodeName, nodeIPs, findNodePasswordFile(agentDataDir)); err != nil {
			logrus.Errorf("Failed to reload %s: %v", name, err)
			failed = append(failed, name)
			continue
		}
		reloaded++
		if len(adminKey) > 0 {
			rootless, _ := strconv.ParseBool(lastValue(configValues, "rootless"))
			paths := adminKubeconfigPaths(serverConfig.ControlConfig.DataDir, cfg.Rootless || rootless, configValues)
			failed = append(failed, updateAdminKubeconfigs(paths, adminKey, t.certFile, t.keyFile)...)
		}
	}

	// The dynamiclistener cert is not stored in a file; the server regenerates it in place.
	if localServer && slices.Contains(cmds.ServicesList.Value(), version.Program+services.ProgramServer) {
		logrus.Infof("Regenerating dynamic listener certificate")
		if _, err := info.Post(handlers.CertReloadPath("dynamic-listener"), nil); err != nil {
			logrus.Errorf("Failed to regenerate dynamic listener certificate: %v", err)
			failed = append(failed, "dynamic-listener")
		} else {
			reloaded++
		}
	}

	if isServer {
		if err := reportServedStatus(info); err != nil {
			logrus.Warnf("Failed to query certificate status: %v", err)
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("failed to reload certificates: %s", strings.Join(failed, ", "))
	}
	if reloaded == 0 {
		logrus.Warnf("No certificates found for the selected services")
		return nil
	}
	logrus.Infof("Successfully reloaded %d certificates", reloaded)
	return nil
}

// serverReloadTargets returns the server certs that can be reloaded. The serving certs for the
// apiserver and etcd include this server's SANs, and can only be requested from the local server.
func serverReloadTargets(rt *config.ControlRuntime) []reloadTarget {
	return []reloadTarget{
		{service: services.APIServer, urlPath: handlers.CertReloadPath("serving-kube-apiserver"), certFile: rt.ServingKubeAPICert, keyFile: rt.ServingKubeAPIKey, localOnly: true},
		{service: services.Scheduler, urlPath: handlers.CertReloadPath("serving-kube-scheduler"), certFile: rt.ServingKubeSchedulerCert, keyFile: rt.ServingKubeSchedulerKey},
		{service: services.ControllerManager, urlPath: handlers.CertReloadPath("serving-kube-controller-manager"), certFile: rt.ServingKubeControllerCert, keyFile: rt.ServingKubeControllerKey},
		{service: services.Admin, urlPath: handlers.CertReloadPath("client-admin"), certFile: rt.ClientAdminCert, keyFile: rt.ClientAdminKey},
		{service: services.Supervisor, urlPath: handlers.CertReloadPath("client-supervisor"), certFile: rt.ClientSupervisorCert, keyFile: rt.ClientSupervisorKey},
		{service: services.ControllerManager, urlPath: handlers.CertReloadPath("client-controller"), certFile: rt.ClientControllerCert, keyFile: rt.ClientControllerKey},
		{service: services.Scheduler, urlPath: handlers.CertReloadPath("client-scheduler"), certFile: rt.ClientSchedulerCert, keyFile: rt.ClientSchedulerKey},
		{service: services.APIServer, urlPath: handlers.CertReloadPath("client-kube-apiserver"), certFile: rt.ClientKubeAPICert, keyFile: rt.ClientKubeAPIKey},
		{service: services.CloudController, urlPath: handlers.CertReloadPath("client-cloud-controller"), certFile: rt.ClientCloudControllerCert, keyFile: rt.ClientCloudControllerKey},
		{service: services.AuthProxy, urlPath: handlers.CertReloadPath("client-auth-proxy"), certFile: rt.ClientAuthProxyCert, keyFile: rt.ClientAuthProxyKey},
		{service: services.ETCD, urlPath: handlers.CertReloadPath("serving-etcd-server"), certFile: rt.ServerETCDCert, keyFile: rt.ServerETCDKey, localOnly: true, etcd: true},
		{service: services.ETCD, urlPath: handlers.CertReloadPath("serving-etcd-peer"), certFile: rt.PeerServerClientETCDCert, keyFile: rt.PeerServerClientETCDKey, localOnly: true, etcd: true},
		{service: services.ETCD, urlPath: handlers.CertReloadPath("client-etcd"), certFile: rt.ClientETCDCert, keyFile: rt.ClientETCDKey},
	}
}

func agentReloadTargets(agentDataDir string) []reloadTarget {
	prefix := "/v1-" + version.Program + "/"
	controller := "client-" + version.Program + "-controller"
	return []reloadTarget{
		{service: services.Kubelet, urlPath: prefix + "serving-kubelet.crt", certFile: filepath.Join(agentDataDir, "serving-kubelet.crt"), keyFile: filepath.Join(agentDataDir, "serving-kubelet.key"), nodeAuth: true},
		{service: services.Kubelet, urlPath: prefix + "client-kubelet.crt", certFile: filepath.Join(agentDataDir, "client-kubelet.crt"), keyFile: filepath.Join(agentDataDir, "client-kubelet.key"), nodeAuth: true},
		{service: services.KubeProxy, urlPath: prefix + "client-kube-proxy.crt", certFile: filepath.Join(agentDataDir, "kube-proxy", "client-kube-proxy.crt"), keyFile: filepath.Join(agentDataDir, "kube-proxy", "client-kube-proxy.key")},
		{service: version.Program + services.ProgramController, urlPath: prefix + controller + ".crt", certFile: filepath.Join(agentDataDir, controller+".crt"), keyFile: filepath.Join(agentDataDir, controller+".key")},
	}
}

// selectReloadTargets returns the targets for the selected services, skipping certs that do not
// exist on this node, or that can only be renewed by the local server or embedded etcd member.
func selectReloadTargets(targets []reloadTarget, selected []string, localServer, etcdMember bool) []reloadTarget {
	var result []reloadTarget
	for _, t := range targets {
		if !slices.Contains(selected, t.service) || (t.localOnly && !localServer) || (t.etcd && !etcdMember) {
			continue
		}
		if _, err := os.Stat(t.certFile); err != nil {
			logrus.Debugf("Skipping %s: %v", filepath.Base(t.certFile), err)
			continue
		}
		result = append(result, t)
	}
	return result
}

func serverReloadAccess(cfg *cmds.Server) (*clientaccess.Info, error) {
	if cfg.Token == "" {
		return nil, errors.New("server token file not found; pass --token or set " + version.ProgramUpper + "_TOKEN")
	}
	return clientaccess.ParseAndValidateToken(cfg.ServerURL, cfg.Token, clientaccess.WithUser("server"))
}

// agentReloadAccess returns a client for the server the agent is joined to. If no token is
// available, the existing kubelet client certificate is used for node identity auth.
func agentReloadAccess(app *cli.Context, cfg *cmds.Server, agentDataDir string, configValues map[string][]string) (*clientaccess.Info, error) {
	serverURL := cfg.ServerURL
	if !app.IsSet("server") {
		serverURL = agentServerURL(agentDataDir, configValues)
		if serverURL == "" {
			return nil, errors.New("unable to determine server URL; pass --server or set " + version.ProgramUpper + "_URL")
		}
	}

	token := cfg.Token
	if token == "" {
		token = lastValue(configValues, "token")
	}
	if tokenFile := lastValue(configValues, "token-file"); token == "" && tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, err
		}
		token = strings.TrimSpace(string(b))
	}
	if token != "" {
		return clientaccess.ParseAndValidateToken(serverURL, token, clientaccess.WithUser("node"))
	}

	caCerts, err := os.ReadFile(filepath.Join(agentDataDir, "server-ca.crt"))
	if err != nil {
		return nil, errors.WithMessage(err, "no token provided, and failed to load server CA for node identity auth")
	}
	logrus.Infof("No token provided, authenticating with the kubelet client certificate")
	return &clientaccess.Info{
		BaseURL:  serverURL,
		CACerts:  caCerts,
		CertFile: filepath.Join(agentDataDir, "client-kubelet.crt"),
		KeyFile:  filepath.Join(agentDataDir, "client-kubelet.key"),
	}, nil
}

// agentServerURL returns the server URL from the config file, or from the agent's load-balancer
// state file if the server URL was provided via the environment when the agent was started.
func agentServerURL(agentDataDir string, configValues map[string][]string) string {
	if serverURL := lastValue(configValues, "server"); serverURL != "" {
		return serverURL
	}
	b, err := os.ReadFile(filepath.Join(agentDataDir, "etc", loadbalancer.SupervisorServiceName+".json"))
	if err != nil {
		return ""
	}
	lbConfig := struct {
		ServerURL string `json:"ServerURL"`
	}{}
	if err := json.Unmarshal(b, &lbConfig); err != nil {
		return ""
	}
	return lbConfig.ServerURL
}

// readConfigValues returns the values set in the config file and its drop-in directory, keyed
// by flag name. The certificate commands do not otherwise load the config file.
func readConfigValues(configFile string) (map[string][]string, error) {
	parser := &configfilearg.Parser{
		After:         []string{"reload"},
		DefaultConfig: configFile,
	}
	args, err := parser.Parse([]string{"reload"})
	if err != nil {
		return nil, err
	}
	values := map[string][]string{}
	for _, arg := range args[1:] {
		if k, v, ok := strings.Cut(strings.TrimLeft(arg, "-"), "="); ok {
			values[k] = append(values[k], v)
		}
	}
	return values, nil
}

func lastValue(values map[string][]string, key string) string {
	if v := values[key]; len(v) > 0 {
		return v[len(v)-1]
	}
	return ""
}

// resolveNodeIdentity returns the node name and IPs sent with requests for the kubelet certs.
// The identity in the existing kubelet certs is preferred over the config file, so that the new
// certs are issued with the same SANs as the current ones.
func resolveNodeIdentity(ctx context.Context, rl *cmds.CertReload, agentDataDir string, configValues map[string][]string) (string, []net.IP, error) {
	certName, certIPs := nodeIdentityFromCerts(agentDataDir)

	nodeName := rl.NodeName
	if nodeName == "" {
		nodeName = certName
	}
	if nodeName == "" {
		nodeName = lastValue(configValues, "node-name")
		if nodeName == "" {
			hostname, err := os.Hostname()
			if err != nil {
				return "", nil, err
			}
			nodeName = hostname
		}
		if withNodeID, _ := strconv.ParseBool(lastValue(configValues, "with-node-id")); withNodeID {
			id, err := os.ReadFile(filepath.Join(nodeConfigDir(agentDataDir), "id"))
			if err != nil {
				return "", nil, errors.WithMessage(err, "failed to read node ID; use --node-name")
			}
			nodeName += "-" + strings.TrimSpace(string(id))
		}
	}

	nodeIPs := rl.NodeIPs.Value()
	if len(nodeIPs) == 0 {
		for _, ip := range certIPs {
			nodeIPs = append(nodeIPs, ip.String())
		}
	}
	if len(nodeIPs) == 0 {
		nodeIPs = configValues["node-ip"]
	}

	name, ips, err := k3sutil.GetHostnameAndIPs(ctx, nodeName, nodeIPs)
	if err != nil {
		return "", nil, errors.WithMessage(err, "failed to determine node name and IPs; use --node-name and --node-ip")
	}
	return name, ips, nil
}

// nodeIdentityFromCerts returns the node name and IPs from the existing kubelet certs. The server
// issues these with the node name and IPs that the agent registered with, plus loopback addresses.
func nodeIdentityFromCerts(agentDataDir string) (string, []net.IP) {
	var nodeName string
	var nodeIPs []net.IP
	if certs, err := certutil.CertsFromFile(filepath.Join(agentDataDir, "serving-kubelet.crt")); err == nil {
		nodeName = certs[0].Subject.CommonName
		for _, ip := range certs[0].IPAddresses {
			if !ip.IsLoopback() {
				nodeIPs = append(nodeIPs, ip)
			}
		}
	}
	if nodeName == "" {
		if certs, err := certutil.CertsFromFile(filepath.Join(agentDataDir, "client-kubelet.crt")); err == nil {
			if name, ok := strings.CutPrefix(certs[0].Subject.CommonName, "system:node:"); ok {
				nodeName = name
			}
		}
	}
	return nodeName, nodeIPs
}

// nodeConfigDir returns the directory holding the node password and ID files. Rootless agents
// store these under the agent data-dir instead of /etc.
func nodeConfigDir(agentDataDir string) string {
	rootlessDir := filepath.Join(agentDataDir, "etc", "rancher", "node")
	if _, err := os.Stat(rootlessDir); err == nil {
		return rootlessDir
	}
	return filepath.Join("/", "etc", "rancher", "node")
}

func findNodePasswordFile(agentDataDir string) string {
	for _, file := range []string{
		filepath.Join(nodeConfigDir(agentDataDir), "password"),
		filepath.Join(agentDataDir, "node-password.txt"),
	} {
		if _, err := os.Stat(file); err == nil {
			return file
		}
	}
	return ""
}

// isLocalURL returns true if the URL host is a loopback address, or resolves to an address
// assigned to one of this node's interfaces.
func isLocalURL(serverURL string) bool {
	u, err := url.Parse(serverURL)
	if err != nil {
		return false
	}
	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() {
			return true
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.Equal(ip) {
				return true
			}
		}
	}
	return false
}

// reloadCert posts a CSR for the existing private key to the server, and writes the new cert to disk.
func reloadCert(info *clientaccess.Info, t reloadTarget, nodeName string, nodeIPs []net.IP, nodePasswordFile string) error {
	keyBytes, err := os.ReadFile(t.keyFile)
	if err != nil {
		return err
	}
	csr, err := createCSR(keyBytes)
	if err != nil {
		return errors.WithMessagef(err, "failed to create certificate request for %s", t.keyFile)
	}

	var options []any
	if t.nodeAuth {
		if nodePasswordFile == "" {
			return errors.New("node password file not found")
		}
		password, err := os.ReadFile(nodePasswordFile)
		if err != nil {
			return err
		}
		options = append(options,
			clientaccess.WithHeader(version.Program+"-Node-Name", nodeName),
			clientaccess.WithHeader(version.Program+"-Node-IP", k3sutil.JoinIPs(nodeIPs)),
			clientaccess.WithHeader(version.Program+"-Node-Password", strings.TrimSpace(string(password))))
	}

	body, err := info.Post(t.urlPath, csr, options...)
	if err != nil {
		return err
	}
	return writeCertAndKey(body, keyBytes, t.certFile, t.keyFile)
}

func createCSR(keyBytes []byte) ([]byte, error) {
	key, err := certutil.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return nil, err
	}
	return x509.CreateCertificateRequest(cryptorand.Reader, &x509.CertificateRequest{}, key)
}

// writeCertAndKey writes the cert from the server response to disk, after checking that it
// matches the private key. Down-level servers may ignore the CSR and send back a cert and
// key; if the response includes a key it is written as well.
func writeCertAndKey(body, currentKey []byte, certFile, keyFile string) error {
	certPEM, keyPEM := splitCertKeyPEM(body)
	if len(certPEM) == 0 {
		return errors.New("server response did not contain a certificate")
	}
	files := []fileData{{path: certFile, data: certPEM}}
	if len(keyPEM) > 0 {
		files = append(files, fileData{path: keyFile, data: keyPEM})
	} else {
		keyPEM = currentKey
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return errors.WithMessage(err, "invalid certificate in server response")
	}
	return writeFilesAtomic(files...)
}

func splitCertKeyPEM(bytes []byte) (certPEM []byte, keyPEM []byte) {
	for {
		b, rest := pem.Decode(bytes)
		if b == nil {
			break
		}
		bytes = rest

		if strings.Contains(b.Type, "PRIVATE KEY") {
			keyPEM = append(keyPEM, pem.EncodeToMemory(b)...)
		} else {
			certPEM = append(certPEM, pem.EncodeToMemory(b)...)
		}
	}
	return certPEM, keyPEM
}

// writeFilesAtomic writes all files to temporary files before renaming any into place, so that file
// watchers never see a partially written file or a cert that does not match its key.
func writeFilesAtomic(files ...fileData) error {
	var tmpFiles []string
	defer func() {
		for _, tmp := range tmpFiles {
			os.Remove(tmp)
		}
	}()

	for _, f := range files {
		tmp, err := writeTempFile(f.path, f.data)
		if err != nil {
			return errors.WithMessagef(err, "failed to write %s", f.path)
		}
		tmpFiles = append(tmpFiles, tmp)
	}
	for i, f := range files {
		if err := os.Rename(tmpFiles[i], f.path); err != nil {
			return errors.WithMessagef(err, "failed to write %s", f.path)
		}
	}
	return nil
}

func writeTempFile(path string, data []byte) (string, error) {
	mode := os.FileMode(0600)
	uid, gid, hasOwner := -1, -1, false
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
		uid, gid, hasOwner = fileOwner(fi)
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	// Set the owner of the existing file, such as the group set by --write-kubeconfig-group.
	if err == nil && hasOwner {
		var fi os.FileInfo
		if fi, err = f.Stat(); err == nil {
			if tmpUID, tmpGID, ok := fileOwner(fi); ok && (tmpUID != uid || tmpGID != gid) {
				err = f.Chown(uid, gid)
			}
		}
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// adminKubeconfigPaths returns the admin kubeconfig files that the server may have written on
// startup, with symlinks resolved. A --write-kubeconfig path passed on the server command line
// cannot be known here, but the server symlinks the default path to it, so it is still found.
func adminKubeconfigPaths(serverDataDir string, rootless bool, configValues map[string][]string) []string {
	var candidates []string
	output := lastValue(configValues, "write-kubeconfig")
	if output == "" {
		output = lastValue(configValues, "o")
	}
	if output == "" {
		output = os.Getenv(version.ProgramUpper + "_KUBECONFIG_OUTPUT")
	}
	if output != "" {
		candidates = append(candidates, output)
	}
	if p, err := server.HomeKubeConfig(true, rootless); err == nil {
		candidates = append(candidates, p)
	}
	candidates = append(candidates, filepath.Join(serverDataDir, "kubeconfig-"+version.Program+".yaml"))

	var paths []string
	for _, c := range candidates {
		p, err := filepath.EvalSymlinks(c)
		if err != nil {
			logrus.Debugf("Skipping admin kubeconfig %s: %v", c, err)
			continue
		}
		if !slices.Contains(paths, p) {
			paths = append(paths, p)
		}
	}
	return paths
}

// updateAdminKubeconfigs replaces the embedded admin client cert in the given kubeconfig files,
// and returns the paths of files that could not be updated.
func updateAdminKubeconfigs(paths []string, oldKeyPEM []byte, certFile, keyFile string) []string {
	var failed []string
	newCertPEM, err := os.ReadFile(certFile)
	if err != nil {
		logrus.Errorf("Failed to read %s: %v", certFile, err)
		return paths
	}
	newKeyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		logrus.Errorf("Failed to read %s: %v", keyFile, err)
		return paths
	}
	if bytes.Equal(newKeyPEM, oldKeyPEM) {
		newKeyPEM = nil
	}
	for _, path := range paths {
		users, err := updateKubeconfigClientCert(path, oldKeyPEM, newCertPEM, newKeyPEM)
		if err != nil {
			logrus.Errorf("Failed to update admin client certificate in kubeconfig %s: %v", path, err)
			failed = append(failed, path)
			continue
		}
		if len(users) == 0 {
			logrus.Infof("Kubeconfig %s has no embedded admin client certificate, not updating", path)
			continue
		}
		logrus.Infof("Updated admin client certificate for user %s in kubeconfig %s", strings.Join(users, ", "), path)
	}
	return failed
}

// updateKubeconfigClientCert updates users whose embedded client cert was issued for oldKeyPEM,
// and returns their names. The base64 data is replaced in place so that hand edits to the file
// are preserved; if that does not produce the expected config, the file is re-encoded instead.
func updateKubeconfigClientCert(path string, oldKeyPEM, newCertPEM, newKeyPEM []byte) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	kc, err := clientcmd.Load(data)
	if err != nil {
		return nil, err
	}
	oldKey, err := certutil.ParsePrivateKeyPEM(oldKeyPEM)
	if err != nil {
		return nil, err
	}
	signer, ok := oldKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("unsupported private key type")
	}

	var users []string
	replacements := map[string]string{}
	for name, ai := range kc.AuthInfos {
		if len(ai.ClientCertificateData) == 0 || !certMatchesKey(ai.ClientCertificateData, signer.Public()) {
			continue
		}
		users = append(users, name)
		if !bytes.Equal(ai.ClientCertificateData, newCertPEM) {
			replacements[base64.StdEncoding.EncodeToString(ai.ClientCertificateData)] = base64.StdEncoding.EncodeToString(newCertPEM)
			ai.ClientCertificateData = newCertPEM
		}
		if len(newKeyPEM) > 0 && len(ai.ClientKeyData) > 0 && !bytes.Equal(ai.ClientKeyData, newKeyPEM) {
			replacements[base64.StdEncoding.EncodeToString(ai.ClientKeyData)] = base64.StdEncoding.EncodeToString(newKeyPEM)
			ai.ClientKeyData = newKeyPEM
		}
	}
	slices.Sort(users)
	if len(replacements) == 0 {
		return users, nil
	}

	out := data
	for o, n := range replacements {
		if !bytes.Contains(out, []byte(o)) {
			out = nil
			break
		}
		out = bytes.ReplaceAll(out, []byte(o), []byte(n))
	}
	if out != nil {
		if check, err := clientcmd.Load(out); err != nil || !reflect.DeepEqual(check, kc) {
			out = nil
		}
	}
	if out == nil {
		logrus.Debugf("Re-encoding kubeconfig %s", path)
		if out, err = clientcmd.Write(*kc); err != nil {
			return nil, err
		}
	}
	return users, writeFilesAtomic(fileData{path: path, data: out})
}

func certMatchesKey(certPEM []byte, pub crypto.PublicKey) bool {
	certs, err := certutil.ParseCertsPEM(certPEM)
	if err != nil || len(certs) == 0 {
		return false
	}
	certPub, ok := certs[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && certPub.Equal(pub)
}

// reportServedStatus prints the on-disk and currently served serial of each cert, so that the
// user can see which components have picked up the new certs.
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
