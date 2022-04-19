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
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	stash "stash.appscode.dev/apimachinery/client/clientset/versioned"
	"stash.appscode.dev/apimachinery/pkg/restic"

	shell "gomodules.xyz/go-sh"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	kmapi "kmodules.xyz/client-go/api/v1"
	appcatalog "kmodules.xyz/custom-resources/apis/appcatalog/v1alpha1"
	appcatalog_cs "kmodules.xyz/custom-resources/client/clientset/versioned"
	"kubedb.dev/apimachinery/apis/config/v1alpha1"
)

const (
	RedisUser          = "username"
	RedisPassword      = "password"
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

func (session *sessionWrapper) setDatabaseCredentials(kubeClient kubernetes.Interface, appBinding *appcatalog.AppBinding) error {
	if appBinding.Spec.Secret != nil {
		appBindingSecret, err := kubeClient.CoreV1().Secrets(appBinding.Namespace).Get(context.TODO(), appBinding.Spec.Secret.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		err = appBinding.TransformSecret(kubeClient, appBindingSecret.Data)
		if err != nil {
			return err
		}

		// set auth env for redis-cli
		session.sh.SetEnv(EnvRedisCLIAuth, string(appBindingSecret.Data[RedisPassword]))

		// set auth env for redis-dump-go
		session.sh.SetEnv(EnvRedisDumpGoAuth, string(appBindingSecret.Data[RedisPassword]))
	}

	return nil
}

func (opt redisOptions) setTLSParameters(appBinding *appcatalog.AppBinding, cmd *restic.Command) error {
	// if ssl enabled, add ca.crt in the arguments
	if appBinding.Spec.ClientConfig.CABundle != nil {
		parameters := v1alpha1.RedisConfiguration{}
		if appBinding.Spec.Parameters != nil {
			if err := json.Unmarshal(appBinding.Spec.Parameters.Raw, &parameters); err != nil {
				klog.Errorf("unable to unmarshal appBinding.Spec.Parameters.Raw. Reason: %v", err)
			}
		}

		if err := ioutil.WriteFile(filepath.Join(opt.setupOptions.ScratchDir, core.ServiceAccountRootCAKey), appBinding.Spec.ClientConfig.CABundle, 0o600); err != nil {
			return err
		}
		caPath := filepath.Join(opt.setupOptions.ScratchDir, core.ServiceAccountRootCAKey)
		cmd.Args = append(cmd.Args, "--tls")
		cmd.Args = append(cmd.Args, "--cacert", caPath)

		if parameters.ClientCertSecret != nil {
			clientSecret, err := opt.kubeClient.CoreV1().Secrets(opt.namespace).Get(context.TODO(), parameters.ClientCertSecret.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}

			certByte, ok := clientSecret.Data[core.TLSCertKey]
			if !ok {
				return fmt.Errorf("can't find client cert")
			}
			if err := ioutil.WriteFile(filepath.Join(opt.setupOptions.ScratchDir, core.TLSCertKey), certByte, 0o600); err != nil {
				return err
			}
			certPath := filepath.Join(opt.setupOptions.ScratchDir, core.TLSCertKey)

			keyByte, ok := clientSecret.Data[core.TLSPrivateKeyKey]
			if !ok {
				return fmt.Errorf("can't find client private key")
			}

			if err := ioutil.WriteFile(filepath.Join(opt.setupOptions.ScratchDir, core.TLSPrivateKeyKey), keyByte, 0o600); err != nil {
				return err
			}
			keyPath := filepath.Join(opt.setupOptions.ScratchDir, core.TLSPrivateKeyKey)

			cmd.Args = append(cmd.Args, "--cert", certPath, "--key", keyPath)
		}
	}
	return nil
}

func (session *sessionWrapper) setUserArgs(args string) {
	for _, arg := range strings.Fields(args) {
		session.cmd.Args = append(session.cmd.Args, arg)
	}
}

func (session sessionWrapper) waitForDBReady(appBinding *appcatalog.AppBinding) error {
	klog.Infoln("Waiting for the database to be ready.....")
	sh := shell.NewSession()
	for k, v := range session.sh.Env {
		sh.SetEnv(k, v)
	}
	sh.ShowCMD = true

	hostname, err := appBinding.Hostname()
	if err != nil {
		return err
	}

	args := append(session.cmd.Args, "-h", hostname)

	port, err := appBinding.Port()
	if err != nil {
		return err
	}

	// if port is specified, append port in the arguments
	if port != 0 {
		args = append(args, "-p", strconv.Itoa(int(port)))
	}

	args = append(args, "ping")

	return wait.PollImmediate(time.Second*5, time.Minute*5, func() (bool, error) {
		err := sh.Command("redis-cli", args...).Run()
		if err != nil {
			return false, nil
		}
		return true, nil
	})
}
