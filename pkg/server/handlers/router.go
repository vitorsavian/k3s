package handlers

import (
	"context"
	"net/http"
	"path/filepath"

	"github.com/k3s-io/k3s/pkg/cli/cmds"
	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/nodepassword"
	"github.com/k3s-io/k3s/pkg/server/auth"
	"github.com/k3s-io/k3s/pkg/util/mux"
	"github.com/k3s-io/k3s/pkg/version"
	"k8s.io/apiserver/pkg/authentication/user"
	bootstrapapi "k8s.io/cluster-bootstrap/token/api"
)

const (
	staticURL = "/static/"
)

var (
	// When starting, each agent sequentially makes requests for certs, config, and apiservers, and will poll the readyz endpoint
	// before starting kube-proxy. These limits effectively cap the number of agents that can join simultaneously.
	// Agents will automatically retry with jitter when rate-limited.
	maxNonMutatingAgentRequests = 20 // max concurrent get/list/watch requests
	maxMutatingAgentRequests    = 10 // max concurrent other requests; cert generation with client-provided private key uses post.
)

func NewHandler(ctx context.Context, control *config.Control, cfg *cmds.Server) http.Handler {
	nodeAuth := nodepassword.GetNodeAuthValidator(ctx, control)

	prefix := "/v1-" + version.Program
	authed := mux.NewRouter()
	authed.NotFoundHandler = APIServer(control, cfg)
	authed.Use(auth.HasRole(control, version.Program+":agent", version.Program+":server", user.NodesGroup, bootstrapapi.BootstrapDefaultGroup), auth.RequestInfo(), auth.MaxInFlight(maxNonMutatingAgentRequests, maxMutatingAgentRequests))
	authed.Handle(prefix+"/serving-kubelet.crt", ServingKubeletCert(control, nodeAuth))
	authed.Handle(prefix+"/client-kubelet.crt", ClientKubeletCert(control, nodeAuth))
	authed.Handle(prefix+"/client-kube-proxy.crt", ClientKubeProxyCert(control))
	authed.Handle(prefix+"/client-"+version.Program+"-controller.crt", ClientControllerCert(control))
	authed.Handle(prefix+"/client-ca.crt", File(control.Runtime.ClientCA))
	authed.Handle(prefix+"/server-ca.crt", File(control.Runtime.ServerCA))
	authed.Handle(prefix+"/apiservers", APIServers(control))
	authed.Handle(prefix+"/config", Config(control, cfg))
	authed.Handle(prefix+"/readyz", Readyz(control))

	nodeAuthed := mux.NewRouter()
	nodeAuthed.NotFoundHandler = authed
	nodeAuthed.Use(auth.HasRole(control, user.NodesGroup))
	nodeAuthed.Handle(prefix+"/connect", control.Runtime.Tunnel)

	serverAuthed := mux.NewRouter()
	serverAuthed.NotFoundHandler = nodeAuthed
	serverAuthed.Use(auth.HasRole(control, version.Program+":server"))
	serverAuthed.Handle(prefix+"/encrypt/status", EncryptionStatus(control))
	serverAuthed.Handle(prefix+"/encrypt/config", EncryptionConfig(ctx, control))
	serverAuthed.Handle(prefix+"/cert/cacerts", CACertReplace(control))
	serverAuthed.Handle(prefix+"/server-bootstrap", Bootstrap(control))
	serverAuthed.Handle(prefix+"/token", TokenRequest(ctx, control))
	serverAuthed.Handle(CertReloadPath("serving-kube-apiserver"), ServingKubeAPICert(control))
	serverAuthed.Handle(CertReloadPath("serving-kube-scheduler"), ServingKubeSchedulerCert(control))
	serverAuthed.Handle(CertReloadPath("serving-kube-controller-manager"), ServingKubeControllerCert(control))
	serverAuthed.Handle(CertReloadPath("serving-etcd-server"), ServingETCDServerCert(control))
	serverAuthed.Handle(CertReloadPath("serving-etcd-peer"), ServingETCDPeerCert(control))
	serverAuthed.Handle(CertReloadPath("client-etcd"), ClientETCDCert(control))
	serverAuthed.Handle(CertReloadPath("client-admin"), ClientAdminCert(control))
	serverAuthed.Handle(CertReloadPath("client-supervisor"), ClientSupervisorCert(control))
	serverAuthed.Handle(CertReloadPath("client-controller"), ClientControllerManagerCert(control))
	serverAuthed.Handle(CertReloadPath("client-scheduler"), ClientSchedulerCert(control))
	serverAuthed.Handle(CertReloadPath("client-kube-apiserver"), ClientKubeAPIServerCert(control))
	serverAuthed.Handle(CertReloadPath("client-cloud-controller"), ClientCloudControllerCert(control))
	serverAuthed.Handle(CertReloadPath("client-auth-proxy"), ClientAuthProxyCert(control))
	serverAuthed.Handle(CertReloadPath("dynamic-listener"), DynamicListenerRegenerate(control))
	serverAuthed.Handle(prefix+"/cert/status", CertStatus(control))

	systemAuthed := mux.NewRouter()
	systemAuthed.NotFoundHandler = serverAuthed
	systemAuthed.Use(auth.HasRole(control, user.SystemPrivilegedGroup))
	systemAuthed.Handle("CONNECT /", control.Runtime.Tunnel)

	router := mux.NewRouter()
	router.NotFoundHandler = systemAuthed
	router.Handle(staticURL, Static(staticURL, filepath.Join(control.DataDir, "static")))
	router.Handle("/cacerts", CACerts(control))
	router.Handle("/ping", Ping())

	return router
}
