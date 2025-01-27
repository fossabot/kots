package cli

import (
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/replicatedhq/kots/pkg/download"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func DownloadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "download [app-slug]",
		Short:         "",
		Long:          ``,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRun: func(cmd *cobra.Command, args []string) {
			viper.BindPFlags(cmd.Flags())
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			v := viper.GetViper()

			appSlug := ""
			if len(args) > 0 {
				appSlug = args[0]
			}

			downloadOptions := download.DownloadOptions{
				Namespace:  v.GetString("namespace"),
				Kubeconfig: v.GetString("kubeconfig"),
				Overwrite:  v.GetBool("overwrite"),
			}

			if err := download.Download(appSlug, ExpandDir(v.GetString("dest")), downloadOptions); err != nil {
				return errors.Cause(err)
			}

			return nil
		},
	}

	cmd.Flags().String("kubeconfig", filepath.Join(homeDir(), ".kube", "config"), "the kubeconfig to use")
	cmd.Flags().String("namespace", "default", "the namespace to download from")
	cmd.Flags().String("dest", homeDir(), "the directory to store the application in")
	cmd.Flags().Bool("overwrite", false, "overwrite any local files, if present")

	return cmd
}
