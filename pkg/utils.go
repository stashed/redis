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
	"time"

	stash "stash.appscode.dev/apimachinery/client/clientset/versioned"
	"stash.appscode.dev/apimachinery/pkg/restic"

	"github.com/codeskyblue/go-sh"
	"gomodules.xyz/x/log"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"kmodules.xyz/custom-resources/apis/appcatalog/v1alpha1"
	appcatalog_cs "kmodules.xyz/custom-resources/client/clientset/versioned"
)

const (
	RedisUser        = "username"
	RedisPassword    = "password"
	RedisDumpFile    = "dumpfile.resp"
	RedisDumpCMD     = "redis-dump-go"
	RedisRestoreCMD  = "redis-cli"
	EnvRedisPassword = "REDIS_PWD"
)

type redisOptions struct {
	kubeClient    kubernetes.Interface
	stashClient   stash.Interface
	catalogClient appcatalog_cs.Interface

	namespace         string
	backupSessionName string
	appBindingName    string
	myArgs            string
	waitTimeout       int32
	outputDir         string

	setupOptions  restic.SetupOptions
	backupOptions restic.BackupOptions
	dumpOptions   restic.DumpOptions
}

func waitForDBReady(appBinding *v1alpha1.AppBinding) error {
	log.Infoln("Waiting for the database to be ready.....")
	shell := sh.NewSession()
	args := []interface{}{
		"-h", appBinding.Spec.ClientConfig.Service.Name,
		"ping",
	}
	//if port is specified, append port in the arguments
	if appBinding.Spec.ClientConfig.Service.Port != 0 {
		args = append(args, "-p", appBinding.Spec.ClientConfig.Service.Port)
	}
	return wait.PollImmediate(time.Second*5, time.Minute*5, func() (bool, error) {
		err := shell.Command("redis-cli", args...).Run()
		if err != nil {
			return false, nil
		}
		return true, nil
	})
}
