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
	"time"

	stash "stash.appscode.dev/apimachinery/client/clientset/versioned"
	"stash.appscode.dev/apimachinery/pkg/restic"

	shell "gomodules.xyz/go-sh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	appcatalog "kmodules.xyz/custom-resources/apis/appcatalog/v1alpha1"
	appcatalog_cs "kmodules.xyz/custom-resources/client/clientset/versioned"
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

	namespace         string
	backupSessionName string
	appBindingName    string
	redisArgs         string
	waitTimeout       int32
	outputDir         string

	setupOptions  restic.SetupOptions
	backupOptions restic.BackupOptions
	dumpOptions   restic.DumpOptions
}

type Shell interface {
	SetEnv(key, value string)
}

type SessionWrapper struct {
	*shell.Session
}

func NewSessionWrapper() *SessionWrapper {
	return &SessionWrapper{
		shell.NewSession(),
	}
}
func (wrapper *SessionWrapper) SetEnv(key, value string) {
	wrapper.Session.SetEnv(key, value)
}

func (opt *redisOptions) waitForDBReady(appBinding *appcatalog.AppBinding) error {
	klog.Infoln("Waiting for the database to be ready.....")
	sh := NewSessionWrapper()
	args := []interface{}{
		"-h", appBinding.Spec.ClientConfig.Service.Name,
		"ping",
	}

	//if port is specified, append port in the arguments
	if appBinding.Spec.ClientConfig.Service.Port != 0 {
		args = append(args, "-p", appBinding.Spec.ClientConfig.Service.Port)
	}

	// set access credentials
	err := opt.setCredentials(sh, appBinding)
	if err != nil {
		return err
	}

	return wait.PollImmediate(time.Second*5, time.Minute*5, func() (bool, error) {
		err := sh.Command("redis-cli", args...).Run()
		if err != nil {
			return false, nil
		}
		return true, nil
	})
}

func (opt *redisOptions) setCredentials(sh Shell, appBinding *appcatalog.AppBinding) error {
	// if credential secret is not provided in AppBinding, then nothing to do.
	if appBinding.Spec.Secret == nil {
		return nil
	}

	// get the Secret
	secret, err := opt.kubeClient.CoreV1().Secrets(opt.namespace).Get(context.TODO(), appBinding.Spec.Secret.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	// perform necessary transform if secretTransforms section is provided in the AppBinding
	err = appBinding.TransformSecret(opt.kubeClient, secret.Data)
	if err != nil {
		return err
	}

	// set auth env for redis-cli
	sh.SetEnv(EnvRedisCLIAuth, string(secret.Data[RedisPassword]))

	// set auth env for redis-dump-go
	sh.SetEnv(EnvRedisDumpGoAuth, string(secret.Data[RedisPassword]))
	return nil
}
