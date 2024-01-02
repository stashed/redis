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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	stash "stash.appscode.dev/apimachinery/client/clientset/versioned"
	"stash.appscode.dev/apimachinery/pkg/restic"

	"github.com/yannh/redis-dump-go/pkg/redisdump"
	shell "gomodules.xyz/go-sh"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	appcatalog "kmodules.xyz/custom-resources/apis/appcatalog/v1alpha1"
	appcatalog_cs "kmodules.xyz/custom-resources/client/clientset/versioned"
	"kubedb.dev/apimachinery/apis/config/v1alpha1"
)

const (
	RedisDumpFile      = "dumpfile.resp"
	RedisDumpCMD       = "redis-dump-go"
	RedisRestoreCMD    = "redis-cli"
	EnvRedisCLIAuth    = "REDISCLI_AUTH"
	EnvRedisDumpGoAuth = "REDISDUMPGO_AUTH"
)

type redisOptions struct {
	kubeClient    kubernetes.Interface
	stashClient   stash.Interface
	catalogClient appcatalog_cs.Interface

	namespace           string
	backupSessionName   string
	appBindingNamespace string
	appBindingName      string
	redisArgs           string
	waitTimeout         int32
	outputDir           string
	storageSecret       kmapi.ObjectReference

	setupOptions  restic.SetupOptions
	backupOptions restic.BackupOptions
	dumpOptions   restic.DumpOptions
	config        *restclient.Config

	NWorkers int
}

type sessionWrapper struct {
	sh  *shell.Session
	cmd *restic.Command
}

func (opt *redisOptions) newSessionWrapper(cmd string) *sessionWrapper {
	return &sessionWrapper{
		sh: shell.NewSession(),
		cmd: &restic.Command{
			Name: cmd,
		},
	}
}

func getDatabaseCredentials(kc kubernetes.Interface, appBinding *appcatalog.AppBinding) (string, string, error) {
	if appBinding.Spec.Secret == nil {
		return "", "", nil
	}
	appBindingSecret, err := kc.CoreV1().Secrets(appBinding.Namespace).Get(context.TODO(), appBinding.Spec.Secret.Name, metav1.GetOptions{})
	if err != nil {
		return "", "", err
	}

	err = appBinding.TransformSecret(kc, appBindingSecret.Data)
	if err != nil {
		return "", "", err
	}
	return string(appBindingSecret.Data[core.BasicAuthUsernameKey]), string(appBindingSecret.Data[core.BasicAuthPasswordKey]), nil
}

func (session *sessionWrapper) setDatabaseCredentials(password string) {
	if password == "" {
		return
	}

	// set auth env for redis-cli
	session.sh.SetEnv(EnvRedisCLIAuth, password)

	// set auth env for redis-dump-go
	session.sh.SetEnv(EnvRedisDumpGoAuth, password)
}

func (opt *redisOptions) writeTLSCertsToFile(appBinding *appcatalog.AppBinding) error {
	// if ssl enabled, add ca.crt in the arguments
	if appBinding.Spec.ClientConfig.CABundle != nil {
		parameters := v1alpha1.RedisConfiguration{}
		if appBinding.Spec.Parameters != nil {
			if err := json.Unmarshal(appBinding.Spec.Parameters.Raw, &parameters); err != nil {
				klog.Errorf("unable to unmarshal appBinding.Spec.Parameters.Raw. Reason: %v", err)
			}
		}

		if err := os.WriteFile(filepath.Join(opt.setupOptions.ScratchDir, core.ServiceAccountRootCAKey), appBinding.Spec.ClientConfig.CABundle, 0o600); err != nil {
			return err
		}

		if parameters.ClientCertSecret != nil {
			clientSecret, err := opt.kubeClient.CoreV1().Secrets(opt.namespace).Get(context.TODO(), parameters.ClientCertSecret.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}

			certByte, ok := clientSecret.Data[core.TLSCertKey]
			if !ok {
				return fmt.Errorf("can't find client cert")
			}
			if err := os.WriteFile(filepath.Join(opt.setupOptions.ScratchDir, core.TLSCertKey), certByte, 0o600); err != nil {
				return err
			}

			keyByte, ok := clientSecret.Data[core.TLSPrivateKeyKey]
			if !ok {
				return fmt.Errorf("can't find client private key")
			}

			if err := os.WriteFile(filepath.Join(opt.setupOptions.ScratchDir, core.TLSPrivateKeyKey), keyByte, 0o600); err != nil {
				return err
			}

		}
	}
	return nil
}

func (opt *redisOptions) setTLSParametersToCMD(appBinding *appcatalog.AppBinding, cmd *restic.Command) {
	// if ssl enabled, add ca.crt in the arguments
	if appBinding.Spec.ClientConfig.CABundle != nil {
		parameters := v1alpha1.RedisConfiguration{}
		if appBinding.Spec.Parameters != nil {
			if err := json.Unmarshal(appBinding.Spec.Parameters.Raw, &parameters); err != nil {
				klog.Errorf("unable to unmarshal appBinding.Spec.Parameters.Raw. Reason: %v", err)
			}
		}

		caPath := filepath.Join(opt.setupOptions.ScratchDir, core.ServiceAccountRootCAKey)
		cmd.Args = append(cmd.Args, "--tls")
		cmd.Args = append(cmd.Args, "--cacert", caPath)

		if parameters.ClientCertSecret != nil {
			certPath := filepath.Join(opt.setupOptions.ScratchDir, core.TLSCertKey)

			keyPath := filepath.Join(opt.setupOptions.ScratchDir, core.TLSPrivateKeyKey)

			cmd.Args = append(cmd.Args, "--cert", certPath, "--key", keyPath)
		}
	}
}

func (opt *redisOptions) getTLSParameter(appBinding *appcatalog.AppBinding) (string, string, string) {
	// if ssl enabled, add ca.crt in the arguments
	if appBinding.Spec.ClientConfig.CABundle != nil {
		parameters := v1alpha1.RedisConfiguration{}
		if appBinding.Spec.Parameters != nil {
			if err := json.Unmarshal(appBinding.Spec.Parameters.Raw, &parameters); err != nil {
				klog.Errorf("unable to unmarshal appBinding.Spec.Parameters.Raw. Reason: %v", err)
			}
		}

		caPath := filepath.Join(opt.setupOptions.ScratchDir, core.ServiceAccountRootCAKey)

		if parameters.ClientCertSecret != nil {
			certPath := filepath.Join(opt.setupOptions.ScratchDir, core.TLSCertKey)

			keyPath := filepath.Join(opt.setupOptions.ScratchDir, core.TLSPrivateKeyKey)

			return caPath, certPath, keyPath
		}
		return caPath, "", ""
	}
	return "", "", ""
}

func (session *sessionWrapper) setUserArgs(args string) {
	for _, arg := range strings.Fields(args) {
		session.cmd.Args = append(session.cmd.Args, arg)
	}
}

func (session *sessionWrapper) waitForDBReady(host redisdump.Host) error {
	klog.Infoln("Waiting for the database to be ready.....")
	sh := shell.NewSession()
	for k, v := range session.sh.Env {
		sh.SetEnv(k, v)
	}
	sh.ShowCMD = true

	args := append(session.cmd.Args, "-h", host.Host)

	// if port is specified, append port in the arguments
	if host.Port != 0 {
		args = append(args, "-p", strconv.Itoa(host.Port))
	}

	args = append(args, "ping")

	return wait.PollUntilContextTimeout(context.Background(), time.Second*5, time.Minute*5, true, func(ctx context.Context) (bool, error) {
		err := sh.Command("redis-cli", args...).Run()
		if err != nil {
			return false, nil
		}
		return true, nil
	})
}
