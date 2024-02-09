/*
Copyright AppsCode Inc. and Contributors

Licensed under the AppsCode Free Trial License 1.0.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://github.com/appscode/licenses/raw/1.0.0/AppsCode-Free-Trial-1.0.0.md

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package pkg

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	api_v1beta1 "stash.appscode.dev/apimachinery/apis/stash/v1beta1"
	"stash.appscode.dev/apimachinery/pkg/restic"

	"github.com/mediocregopher/radix/v3"
	"github.com/spf13/cobra"
	"github.com/yannh/redis-dump-go/pkg/config"
	"github.com/yannh/redis-dump-go/pkg/redisdump"
	license "go.bytebuilders.dev/license-verifier/kubernetes"
	"gomodules.xyz/flags"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	appcatalog "kmodules.xyz/custom-resources/apis/appcatalog/v1alpha1"
	appcatalog_cs "kmodules.xyz/custom-resources/client/clientset/versioned"
	v1 "kmodules.xyz/offshoot-api/api/v1"
)

func NewCmdRestore() *cobra.Command {
	var (
		masterURL      string
		kubeconfigPath string
		opt            = redisOptions{
			setupOptions: restic.SetupOptions{
				ScratchDir:  restic.DefaultScratchDir,
				EnableCache: false,
			},
			waitTimeout: 300,
			dumpOptions: restic.DumpOptions{
				Host:     restic.DefaultHost,
				FileName: RedisDumpFile,
			},
		}
	)

	cmd := &cobra.Command{
		Use:               "restore-redis",
		Short:             "Restores Redis DB Backup",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			flags.EnsureRequiredFlags(cmd, "appbinding", "provider", "storage-secret-name", "storage-secret-namespace")

			// prepare client
			config, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfigPath)
			if err != nil {
				return err
			}
			opt.config = config

			opt.kubeClient, err = kubernetes.NewForConfig(config)
			if err != nil {
				return err
			}
			opt.catalogClient, err = appcatalog_cs.NewForConfig(config)
			if err != nil {
				return err
			}

			targetRef := api_v1beta1.TargetRef{
				APIVersion: appcatalog.SchemeGroupVersion.String(),
				Kind:       appcatalog.ResourceKindApp,
				Name:       opt.appBindingName,
				Namespace:  opt.appBindingNamespace,
			}

			var restoreOutput *restic.RestoreOutput
			restoreOutput, err = opt.restoreRedis(targetRef)
			if err != nil {
				restoreOutput = &restic.RestoreOutput{
					RestoreTargetStatus: api_v1beta1.RestoreMemberStatus{
						Ref: targetRef,
						Stats: []api_v1beta1.HostRestoreStats{
							{
								Hostname: opt.dumpOptions.Host,
								Phase:    api_v1beta1.HostRestoreFailed,
								Error:    err.Error(),
							},
						},
					},
				}
			}
			// If output directory specified, then write the output in "output.json" file in the specified directory
			if opt.outputDir != "" {
				return restoreOutput.WriteOutput(filepath.Join(opt.outputDir, restic.DefaultOutputFileName))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&opt.redisArgs, "redis-args", opt.redisArgs, "Additional arguments")
	cmd.Flags().Int32Var(&opt.waitTimeout, "wait-timeout", opt.waitTimeout, "Time limit to wait for the database to be ready")

	cmd.Flags().StringVar(&masterURL, "master", masterURL, "The address of the Kubernetes API server (overrides any value in kubeconfig)")
	cmd.Flags().StringVar(&kubeconfigPath, "kubeconfig", kubeconfigPath, "Path to kubeconfig file with authorization information (the master location is set by the master flag).")
	cmd.Flags().StringVar(&opt.namespace, "namespace", "default", "Namespace of Backup/Restore Session")
	cmd.Flags().StringVar(&opt.appBindingName, "appbinding", opt.appBindingName, "Name of the app binding")
	cmd.Flags().StringVar(&opt.appBindingNamespace, "appbinding-namespace", opt.appBindingNamespace, "Namespace of the app binding")
	cmd.Flags().StringVar(&opt.storageSecret.Name, "storage-secret-name", opt.storageSecret.Name, "Name of the storage secret")
	cmd.Flags().StringVar(&opt.storageSecret.Namespace, "storage-secret-namespace", opt.storageSecret.Namespace, "Namespace of the storage secret")

	cmd.Flags().StringVar(&opt.setupOptions.Provider, "provider", opt.setupOptions.Provider, "Backend provider (i.e. gcs, s3, azure etc)")
	cmd.Flags().StringVar(&opt.setupOptions.Bucket, "bucket", opt.setupOptions.Bucket, "Name of the cloud bucket/container (keep empty for local backend)")
	cmd.Flags().StringVar(&opt.setupOptions.Endpoint, "endpoint", opt.setupOptions.Endpoint, "Endpoint for s3/s3 compatible backend or REST backend URL")
	cmd.Flags().BoolVar(&opt.setupOptions.InsecureTLS, "insecure-tls", opt.setupOptions.InsecureTLS, "InsecureTLS for TLS secure s3/s3 compatible backend")
	cmd.Flags().StringVar(&opt.setupOptions.Region, "region", opt.setupOptions.Region, "Region for s3/s3 compatible backend")
	cmd.Flags().StringVar(&opt.setupOptions.Path, "path", opt.setupOptions.Path, "Directory inside the bucket where backup will be stored")
	cmd.Flags().StringVar(&opt.setupOptions.ScratchDir, "scratch-dir", opt.setupOptions.ScratchDir, "Temporary directory")
	cmd.Flags().BoolVar(&opt.setupOptions.EnableCache, "enable-cache", opt.setupOptions.EnableCache, "Specify whether to enable caching for restic")
	cmd.Flags().Int64Var(&opt.setupOptions.MaxConnections, "max-connections", opt.setupOptions.MaxConnections, "Specify maximum concurrent connections for GCS, Azure and B2 backend")

	cmd.Flags().StringVar(&opt.dumpOptions.Host, "hostname", opt.dumpOptions.Host, "Name of the host machine")
	cmd.Flags().StringVar(&opt.dumpOptions.SourceHost, "source-hostname", opt.dumpOptions.SourceHost, "Name of the host from where data will be restored")
	// TODO: sliceVar
	cmd.Flags().StringVar(&opt.dumpOptions.Snapshot, "snapshot", opt.dumpOptions.Snapshot, "Snapshot to dump")

	cmd.Flags().StringVar(&opt.outputDir, "output-dir", opt.outputDir, "Directory where output.json file will be written (keep empty if you don't need to write output in file)")

	cmd.Flags().IntVar(&opt.NWorkers, "n", 10, "Parallel workers")

	return cmd
}

func (opt *redisOptions) restoreRedis(targetRef api_v1beta1.TargetRef) (*restic.RestoreOutput, error) {
	var err error
	err = license.CheckLicenseEndpoint(opt.config, licenseApiService, SupportedProducts)
	if err != nil {
		return nil, err
	}

	opt.setupOptions.StorageSecret, err = opt.kubeClient.CoreV1().Secrets(opt.storageSecret.Namespace).Get(context.TODO(), opt.storageSecret.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	// apply nice, ionice settings from env
	opt.setupOptions.Nice, err = v1.NiceSettingsFromEnv()
	if err != nil {
		return nil, err
	}
	opt.setupOptions.IONice, err = v1.IONiceSettingsFromEnv()
	if err != nil {
		return nil, err
	}

	appBinding, err := opt.catalogClient.AppcatalogV1alpha1().AppBindings(opt.appBindingNamespace).Get(context.TODO(), opt.appBindingName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	hostname, err := appBinding.Hostname()
	if err != nil {
		return nil, err
	}
	port, err := appBinding.Port()
	if err != nil {
		return nil, err
	}
	username, password, err := getDatabaseCredentials(opt.kubeClient, appBinding)
	if err != nil {
		return nil, err
	}

	err = opt.writeTLSCertsToFile(appBinding)
	if err != nil {
		return nil, err
	}

	var tlsHandler *redisdump.TlsHandler = nil
	ca, cert, key := opt.getTLSParameter(appBinding)
	if ca != "" {
		tlsHandler = &redisdump.TlsHandler{
			CACertPath: ca,
			CertPath:   cert,
			KeyPath:    key,
		}
	}

	s := redisdump.Host{
		Host:       hostname,
		Port:       int(port),
		Username:   username,
		Password:   password,
		TlsHandler: tlsHandler,
	}

	if hosts, err := redisdump.GetHosts(s, opt.NWorkers); err != nil {
		return nil, err
	} else {
		redisCluster := len(hosts) > 1
		// Start clock to measure total restore duration
		startTime := time.Now()
		beforeKeys := 0
		afterKeys := 0
		if appBinding.Spec.ClientConfig.CABundle != nil {
			for i := range hosts {
				hosts[i].TlsHandler = &redisdump.TlsHandler{
					SkipVerify: true,
				}
			}
		}

		for _, host := range hosts {
			session := opt.newSessionWrapper(RedisRestoreCMD)

			session.setDatabaseCredentials(host.Password)
			if err != nil {
				return nil, err
			}

			opt.setTLSParametersToCMD(appBinding, session.cmd)
			if err != nil {
				return nil, err
			}

			err = session.waitForDBReady(host)
			if err != nil {
				return nil, err
			}

			session.cmd.Args = append(session.cmd.Args, "--pipe")

			session.cmd.Args = append(session.cmd.Args, "-h", host.Host)

			// if port is specified, append port in the arguments
			if host.Port != 0 {
				session.cmd.Args = append(session.cmd.Args, "-p", strconv.Itoa(host.Port))
			}

			session.setUserArgs(opt.redisArgs)

			// append the restore command to the pipeline
			opt.dumpOptions.StdoutPipeCommands = []restic.Command{*session.cmd}
			resticWrapper, err := restic.NewResticWrapperFromShell(opt.setupOptions, session.sh)
			if err != nil {
				return nil, err
			}

			// if source host is not specified then use current host as source host
			if opt.dumpOptions.SourceHost == "" {
				opt.dumpOptions.SourceHost = opt.dumpOptions.Host
			}

			var client *radix.Pool
			if redisCluster {
				client, err = redisdump.NewClient(host, nil, opt.NWorkers)
				if err != nil {
					return nil, err
				}
				if size, err := DBSize(client); err != nil {
					return nil, err
				} else {
					beforeKeys += size
				}
			}

			// Run dump
			// Redis cluster restore will always return error. So, ignore error for redis clusters
			_, err = resticWrapper.DumpOnce(opt.dumpOptions)
			if !redisCluster && err != nil {
				return nil, err
			}

			if redisCluster {
				if size, err := DBSize(client); err != nil {
					return nil, err
				} else {
					afterKeys += size
				}
				client.Close()
			}
		}

		if redisCluster {
			client, err := redisdump.NewCluster(hosts)
			if err != nil {
				return nil, err
			}
			defer client.Close()

			var strBackedupKeys string
			err = client.Do(radix.Cmd(&strBackedupKeys, "GET", config.KeyTotalKeys))
			if err != nil {
				return nil, err
			}
			backedupKeys, err := strconv.Atoi(strBackedupKeys)
			if err != nil {
				return nil, err
			}
			fmt.Printf("Total keys found in backuped data: %d\n", backedupKeys)
			fmt.Printf("Total keys in redis before restore: %d, after restore: %d\n", beforeKeys, afterKeys)

			_ = client.Do(radix.Cmd(nil, "DEL", config.KeyTotalKeys))
		} else {
			client, err := redisdump.NewClient(s, nil, opt.NWorkers)
			if err != nil {
				return nil, err
			}
			defer client.Close()

			_ = client.Do(radix.Cmd(nil, "DEL", config.KeyTotalKeys))
		}

		restoreStats := api_v1beta1.HostRestoreStats{
			Hostname: opt.dumpOptions.Host,
		}
		// Dump successful. Now, calculate total session duration.
		restoreStats.Duration = time.Since(startTime).String()
		restoreStats.Phase = api_v1beta1.HostRestoreSucceeded
		restoreOutput := &restic.RestoreOutput{
			RestoreTargetStatus: api_v1beta1.RestoreMemberStatus{
				Ref:   targetRef,
				Stats: []api_v1beta1.HostRestoreStats{restoreStats},
			},
		}
		return restoreOutput, nil
	}
}

func DBSize(client *radix.Pool) (int, error) {
	var dbSize string
	if err := client.Do(radix.Cmd(&dbSize, "dbsize")); err != nil {
		return 0, err
	}
	return strconv.Atoi(dbSize)
}
