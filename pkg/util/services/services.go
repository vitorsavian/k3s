package services

import (
	"fmt"
	"path/filepath"

	"github.com/k3s-io/k3s/pkg/daemons/config"
	"github.com/k3s-io/k3s/pkg/version"
)

const (
	APIServer            = "api-server"
	Admin                = "admin"
	AuthProxy            = "auth-proxy"
	CertificateAuthority = "certificate-authority"
	CloudController      = "cloud-controller"
	ControllerManager    = "controller-manager"
	ETCD                 = "etcd"
	KubeProxy            = "kube-proxy"
	Kubelet              = "kubelet"
	ProgramController    = "-controller"
	ProgramServer        = "-server"
	Scheduler            = "scheduler"
	Supervisor           = "supervisor"
)

type Cert struct {
	Cert string
	Key  string
}

var Agent = []string{
	KubeProxy,
	Kubelet,
	version.Program + ProgramController,
}

var Server = []string{
	APIServer,
	Admin,
	AuthProxy,
	CloudController,
	ControllerManager,
	ETCD,
	Scheduler,
	Supervisor,
	version.Program + ProgramServer,
}

var All = append(Server, Agent...)

// CA is intentionally not included in agent, server, or all as it
// requires manual action by the user to rotate these certs.
var CA = []string{
	CertificateAuthority,
}

func CertsForServices(controlConfig config.Control, services []string) (map[string][]Cert, error) {
	agentDataDir := filepath.Join(controlConfig.DataDir, "..", "agent")
	fileMap := map[string][]Cert{}

	for _, service := range services {
		switch service {
		case Admin:
			fileMap[service] = []Cert{
				{Cert: controlConfig.Runtime.ClientAdminCert, Key: controlConfig.Runtime.ClientAdminKey},
			}
		case APIServer:
			fileMap[service] = []Cert{
				{Cert: controlConfig.Runtime.ClientKubeAPICert, Key: controlConfig.Runtime.ClientKubeAPIKey},
				{Cert: controlConfig.Runtime.ServingKubeAPICert, Key: controlConfig.Runtime.ServingKubeAPIKey},
			}
		case ControllerManager:
			fileMap[service] = []Cert{
				{Cert: controlConfig.Runtime.ClientControllerCert, Key: controlConfig.Runtime.ClientControllerKey},
				{Cert: controlConfig.Runtime.ServingKubeControllerCert, Key: controlConfig.Runtime.ServingKubeControllerKey},
			}
		case Scheduler:
			fileMap[service] = []Cert{
				{Cert: controlConfig.Runtime.ClientSchedulerCert, Key: controlConfig.Runtime.ClientSchedulerKey},
				{Cert: controlConfig.Runtime.ServingKubeSchedulerCert, Key: controlConfig.Runtime.ServingKubeSchedulerKey},
			}
		case ETCD:
			fileMap[service] = []Cert{
				{Cert: controlConfig.Runtime.ClientETCDCert, Key: controlConfig.Runtime.ClientETCDKey},
				{Cert: controlConfig.Runtime.ServerETCDCert, Key: controlConfig.Runtime.ServerETCDKey},
				{Cert: controlConfig.Runtime.PeerServerClientETCDCert, Key: controlConfig.Runtime.PeerServerClientETCDKey},
			}
		case CloudController:
			fileMap[service] = []Cert{
				{Cert: controlConfig.Runtime.ClientCloudControllerCert, Key: controlConfig.Runtime.ClientCloudControllerKey},
			}
		case version.Program + ProgramController:
			fileMap[service] = []Cert{
				{Cert: "", Key: controlConfig.Runtime.ClientK3sControllerKey},
				{Cert: filepath.Join(agentDataDir, "client-"+version.Program+"-controller.crt"), Key: filepath.Join(agentDataDir, "client-"+version.Program+"-controller.key")},
			}
		case Supervisor:
			fileMap[service] = []Cert{
				{Cert: controlConfig.Runtime.ClientSupervisorCert, Key: controlConfig.Runtime.ClientSupervisorKey},
			}
		case AuthProxy:
			fileMap[service] = []Cert{
				{Cert: controlConfig.Runtime.ClientAuthProxyCert, Key: controlConfig.Runtime.ClientAuthProxyKey},
			}
		case Kubelet:
			fileMap[service] = []Cert{
				{Cert: "", Key: controlConfig.Runtime.ClientKubeletKey},
				{Cert: "", Key: controlConfig.Runtime.ServingKubeletKey},
				{Cert: filepath.Join(agentDataDir, "client-kubelet.crt"), Key: filepath.Join(agentDataDir, "client-kubelet.key")},
				{Cert: filepath.Join(agentDataDir, "serving-kubelet.crt"), Key: filepath.Join(agentDataDir, "serving-kubelet.key")},
			}
		case KubeProxy:
			fileMap[service] = []Cert{
				{Cert: "", Key: controlConfig.Runtime.ClientKubeProxyKey},
				{Cert: filepath.Join(agentDataDir, "client-kube-proxy.crt"), Key: filepath.Join(agentDataDir, "client-kube-proxy.key")},
			}
		case CertificateAuthority:
			fileMap[service] = []Cert{
				{Cert: controlConfig.Runtime.ServerCA, Key: controlConfig.Runtime.ServerCAKey},
				{Cert: controlConfig.Runtime.ClientCA, Key: controlConfig.Runtime.ClientCAKey},
				{Cert: controlConfig.Runtime.RequestHeaderCA, Key: controlConfig.Runtime.RequestHeaderCAKey},
				{Cert: controlConfig.Runtime.ETCDPeerCA, Key: controlConfig.Runtime.ETCDPeerCAKey},
				{Cert: controlConfig.Runtime.ETCDServerCA, Key: controlConfig.Runtime.ETCDServerCAKey},
			}
		case version.Program + ProgramServer:
			// not handled here, as the dynamiclistener cert cache is not a standard cert
		default:
			return nil, fmt.Errorf("%s is not a recognized service", service)
		}
	}

	return fileMap, nil
}

func FilesForServices(controlConfig config.Control, services []string) (map[string][]string, error) {
	agentDataDir := filepath.Join(controlConfig.DataDir, "..", "agent")
	fileMap := map[string][]string{}
	for _, service := range services {
		switch service {
		case Admin:
			fileMap[service] = []string{
				controlConfig.Runtime.ClientAdminCert,
				controlConfig.Runtime.ClientAdminKey,
			}
		case APIServer:
			fileMap[service] = []string{
				controlConfig.Runtime.ClientKubeAPICert,
				controlConfig.Runtime.ClientKubeAPIKey,
				controlConfig.Runtime.ServingKubeAPICert,
				controlConfig.Runtime.ServingKubeAPIKey,
			}
		case ControllerManager:
			fileMap[service] = []string{
				controlConfig.Runtime.ClientControllerCert,
				controlConfig.Runtime.ClientControllerKey,
				controlConfig.Runtime.ServingKubeControllerCert,
				controlConfig.Runtime.ServingKubeControllerKey,
			}
		case Scheduler:
			fileMap[service] = []string{
				controlConfig.Runtime.ClientSchedulerCert,
				controlConfig.Runtime.ClientSchedulerKey,
				controlConfig.Runtime.ServingKubeSchedulerCert,
				controlConfig.Runtime.ServingKubeSchedulerKey,
			}
		case ETCD:
			fileMap[service] = []string{
				controlConfig.Runtime.ClientETCDCert,
				controlConfig.Runtime.ClientETCDKey,
				controlConfig.Runtime.ServerETCDCert,
				controlConfig.Runtime.ServerETCDKey,
				controlConfig.Runtime.PeerServerClientETCDCert,
				controlConfig.Runtime.PeerServerClientETCDKey,
			}
		case CloudController:
			fileMap[service] = []string{
				controlConfig.Runtime.ClientCloudControllerCert,
				controlConfig.Runtime.ClientCloudControllerKey,
			}
		case version.Program + ProgramController:
			fileMap[service] = []string{
				controlConfig.Runtime.ClientK3sControllerCert,
				controlConfig.Runtime.ClientK3sControllerKey,
				filepath.Join(agentDataDir, "client-"+version.Program+"-controller.crt"),
				filepath.Join(agentDataDir, "client-"+version.Program+"-controller.key"),
			}
		case Supervisor:
			fileMap[service] = []string{
				controlConfig.Runtime.ClientSupervisorCert,
				controlConfig.Runtime.ClientSupervisorKey,
			}
		case AuthProxy:
			fileMap[service] = []string{
				controlConfig.Runtime.ClientAuthProxyCert,
				controlConfig.Runtime.ClientAuthProxyKey,
			}
		case Kubelet:
			fileMap[service] = []string{
				controlConfig.Runtime.ClientKubeletKey,
				controlConfig.Runtime.ServingKubeletKey,
				filepath.Join(agentDataDir, "client-kubelet.crt"),
				filepath.Join(agentDataDir, "client-kubelet.key"),
				filepath.Join(agentDataDir, "serving-kubelet.crt"),
				filepath.Join(agentDataDir, "serving-kubelet.key"),
			}
		case KubeProxy:
			fileMap[service] = []string{
				controlConfig.Runtime.ClientKubeProxyCert,
				controlConfig.Runtime.ClientKubeProxyKey,
				filepath.Join(agentDataDir, "client-kube-proxy.crt"),
				filepath.Join(agentDataDir, "client-kube-proxy.key"),
			}
		case CertificateAuthority:
			fileMap[service] = []string{
				controlConfig.Runtime.ServerCA,
				controlConfig.Runtime.ServerCAKey,
				controlConfig.Runtime.ClientCA,
				controlConfig.Runtime.ClientCAKey,
				controlConfig.Runtime.RequestHeaderCA,
				controlConfig.Runtime.RequestHeaderCAKey,
				controlConfig.Runtime.ETCDPeerCA,
				controlConfig.Runtime.ETCDPeerCAKey,
				controlConfig.Runtime.ETCDServerCA,
				controlConfig.Runtime.ETCDServerCAKey,
			}
		case version.Program + ProgramServer:
			// not handled here, as the dynamiclistener cert cache is not a standard cert
		default:
			return nil, fmt.Errorf("%s is not a recognized service", service)
		}
	}
	return fileMap, nil
}

func IsValid(svc string) bool {
	for _, service := range All {
		if svc == service {
			return true
		}
	}
	return false
}
