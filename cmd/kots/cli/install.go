package cli

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/ahmetalpbalkan/go-cursor"
	"github.com/replicatedhq/kots/pkg/k8sutil"
	"github.com/replicatedhq/kots/pkg/kotsadm"
	"github.com/replicatedhq/kots/pkg/logger"
	"github.com/replicatedhq/kots/pkg/pull"
	"github.com/replicatedhq/kots/pkg/upload"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func InstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "install [upstream uri]",
		Short:         "",
		Long:          ``,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRun: func(cmd *cobra.Command, args []string) {
			viper.BindPFlags(cmd.Flags())
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			v := viper.GetViper()

			if len(args) == 0 {
				cmd.Help()
				os.Exit(1)
			}

			fmt.Print(cursor.Hide())
			defer fmt.Print(cursor.Show())

			rootDir, err := ioutil.TempDir("", "kotsadm")
			if err != nil {
				return err
			}
			defer os.RemoveAll(rootDir)

			pullOptions := pull.PullOptions{
				HelmRepoURI: v.GetString("repo"),
				RootDir:     rootDir,
				Namespace:   v.GetString("namespace"),
				Downstreams: []string{
					"local", // this is the auto-generated operator downstream
				},
				LocalPath:           ExpandDir(v.GetString("local-path")),
				LicenseFile:         ExpandDir(v.GetString("license-file")),
				ExcludeAdminConsole: true,
				HelmOptions:         v.GetStringSlice("set"),
			}

			canPull, err := pull.CanPullUpstream(args[0], pullOptions)
			if err != nil {
				return err
			}

			if canPull {
				if _, err := pull.Pull(args[0], pullOptions); err != nil {
					return err
				}
			}

			applicationMetadata, err := pull.PullApplicationMetadata(args[0])
			if err != nil {
				return err
			}

			deployOptions := kotsadm.DeployOptions{
				Namespace:           v.GetString("namespace"),
				Kubeconfig:          v.GetString("kubeconfig"),
				IncludeShip:         v.GetBool("include-ship"),
				IncludeGitHub:       v.GetBool("include-github"),
				SharedPassword:      v.GetString("shared-password"),
				ServiceType:         v.GetString("service-type"),
				NodePort:            v.GetInt32("node-port"),
				Hostname:            v.GetString("hostname"),
				ApplicationMetadata: applicationMetadata,
			}

			log := logger.NewLogger()
			log.ActionWithoutSpinner("Deploying Admin Console")
			if err := kotsadm.Deploy(deployOptions); err != nil {
				return err
			}

			// upload the kots app to kotsadm
			uploadOptions := upload.UploadOptions{
				Namespace:   v.GetString("namespace"),
				Kubeconfig:  v.GetString("kubeconfig"),
				NewAppName:  v.GetString("name"),
				UpstreamURI: args[0],
				Endpoint:    "http://localhost:3000",
			}

			if canPull {
				stopCh, err := upload.StartPortForward(uploadOptions.Namespace, uploadOptions.Kubeconfig)
				if err != nil {
					return err
				}
				defer close(stopCh)

				if err := upload.Upload(rootDir, uploadOptions); err != nil {
					return err
				}
			}

			// port forward
			podName, err := k8sutil.WaitForWeb(v.GetString("namespace"))
			if err != nil {
				return err
			}

			stopCh, err := k8sutil.PortForward(v.GetString("kubeconfig"), 8800, 3000, v.GetString("namespace"), podName)
			if err != nil {
				return err
			}
			defer close(stopCh)

			log.ActionWithoutSpinner("")
			log.ActionWithoutSpinner("Press Ctrl+C to exit")
			log.ActionWithoutSpinner("Go to http://localhost:8800 to access the Admin Console")
			log.ActionWithoutSpinner("")

			signalChan := make(chan os.Signal, 1)
			signal.Notify(signalChan, os.Interrupt)

			<-signalChan

			log.ActionWithoutSpinner("Cleaning up")
			log.ActionWithoutSpinner("")
			log.ActionWithoutSpinner("To access the Admin Console again, run kubectl kots admin-console %s", v.GetString("namespace"))
			log.ActionWithoutSpinner("")

			return nil
		},
	}

	cmd.Flags().String("kubeconfig", filepath.Join(homeDir(), ".kube", "config"), "the kubeconfig to use")
	cmd.Flags().StringP("namespace", "n", "default", "the namespace to deploy to")
	cmd.Flags().Bool("include-ship", false, "include the shipinit/edit/update and watch components")
	cmd.Flags().Bool("include-github", false, "set up for github login")
	cmd.Flags().String("shared-password", "", "shared password to apply")
	cmd.Flags().String("service-type", "ClusterIP", "the service type to create")
	cmd.Flags().Int32("node-port", 0, "the nodeport to assign to the service, when service-type is set to NodePort")
	cmd.Flags().String("hostname", "localhost:8800", "the hostname to that the admin console will be exposed on")
	cmd.Flags().String("name", "", "name of the application to use in the Admin Console")
	cmd.Flags().String("local-path", "", "specify a local-path to test the behavior of rendering a replicated app locally (only supported on replicated app types currently)")
	cmd.Flags().String("license-file", "", "path to a license file to use when download a replicated app")

	cmd.Flags().String("repo", "", "repo uri to use when installing a helm chart")
	cmd.Flags().StringSlice("set", []string{}, "values to pass to helm when running helm template")

	return cmd
}
