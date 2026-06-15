package cmds

import (
	"github.com/k3s-io/k3s/pkg/version"
	"github.com/urfave/cli/v2"
)

const CertCommand = "certificate"

type CertRotateCA struct {
	CACertPath string
	Force      bool
}

type CertReload struct {
	NodeName string
	NodeIPs  cli.StringSlice
}

var (
	ServicesList           cli.StringSlice
	CertRotateCAConfig     CertRotateCA
	CertReloadConfig       CertReload
	CertReloadCommandFlags = []cli.Flag{
		DebugFlag,
		ConfigFlag,
		LogFile,
		AlsoLogToStderr,
		DataDirFlag,
		&cli.StringSliceFlag{
			Name:        "service",
			Usage:       "List of services to reload certificates for. Defaults to all services for the detected node type.",
			Destination: &ServicesList,
		},
		&cli.StringFlag{
			Name:        "server",
			Aliases:     []string{"s"},
			Usage:       "(cluster) Server to connect to",
			EnvVars:     []string{version.ProgramUpper + "_URL"},
			Value:       "https://127.0.0.1:6443",
			Destination: &ServerConfig.ServerURL,
		},
		&cli.StringFlag{
			Name:        "token",
			Aliases:     []string{"t"},
			Usage:       "(cluster) Shared secret used to join the cluster. Required on agents; on servers, defaults to the value of the server token file.",
			EnvVars:     []string{version.ProgramUpper + "_TOKEN"},
			Destination: &ServerConfig.Token,
		},
		&cli.StringFlag{
			Name:        "node-name",
			Usage:       "(agent) Override the node name reported when requesting per-node certificates. Defaults to the local hostname.",
			Destination: &CertReloadConfig.NodeName,
		},
		&cli.StringSliceFlag{
			Name:        "node-ip",
			Usage:       "(agent) Override the node IP addresses included in serving certificates. Can be repeated.",
			Destination: &CertReloadConfig.NodeIPs,
		},
	}
	CertRotateCommandFlags = []cli.Flag{
		DebugFlag,
		ConfigFlag,
		LogFile,
		AlsoLogToStderr,
		DataDirFlag,
		&cli.StringSliceFlag{
			Name:        "service",
			Aliases:     []string{"s"},
			Usage:       "List of services to manage certificates for. Options include (admin, api-server, controller-manager, scheduler, supervisor, " + version.Program + "-controller, " + version.Program + "-server, cloud-controller, etcd, auth-proxy, kubelet, kube-proxy)",
			Destination: &ServicesList,
		},
	}
	CertRotateCACommandFlags = []cli.Flag{
		DataDirFlag,
		&cli.StringFlag{
			Name:        "server",
			Aliases:     []string{"s"},
			Usage:       "(cluster) Server to connect to",
			EnvVars:     []string{version.ProgramUpper + "_URL"},
			Value:       "https://127.0.0.1:6443",
			Destination: &ServerConfig.ServerURL,
		},
		&cli.StringFlag{
			Name:        "path",
			Usage:       "Path to directory containing new CA certificates",
			Destination: &CertRotateCAConfig.CACertPath,
			Required:    true,
		},
		&cli.BoolFlag{
			Name:        "force",
			Usage:       "Force certificate replacement, even if consistency checks fail",
			Destination: &CertRotateCAConfig.Force,
		},
	}
)

func NewCertCommands(check, rotate, rotateCA, reload func(ctx *cli.Context) error) *cli.Command {
	return &cli.Command{
		Name:            CertCommand,
		Usage:           "Manage K3s certificates",
		SkipFlagParsing: false,
		Subcommands: []*cli.Command{
			{
				Name:            "check",
				Usage:           "Check " + version.Program + " component certificates on disk",
				SkipFlagParsing: false,
				Action:          check,
				Flags: append(CertRotateCommandFlags, &cli.StringFlag{
					Name:    "output",
					Aliases: []string{"o"},
					Usage:   "Format output. Options: text, table, json, yaml",
					Value:   "text",
				}),
			},
			{
				Name:            "rotate",
				Usage:           "Rotate " + version.Program + " component certificates on disk",
				SkipFlagParsing: false,
				Action:          rotate,
				Flags:           CertRotateCommandFlags,
				Subcommands: []*cli.Command{
					{
						Name:            "reload",
						Usage:           "Refresh " + version.Program + " leaf certificates in place without restarting. CAs are not touched (use rotate-ca for that). Components that support file-watch reload pick up the new certificate automatically; the rest keep using the old certificate until the next process restart.",
						SkipFlagParsing: false,
						Action:          reload,
						Flags:           CertReloadCommandFlags,
					},
				},
			},
			{
				Name:            "rotate-ca",
				Usage:           "Write updated " + version.Program + " CA certificates to the datastore",
				SkipFlagParsing: false,
				Action:          rotateCA,
				Flags:           CertRotateCACommandFlags,
			},
		},
	}
}
