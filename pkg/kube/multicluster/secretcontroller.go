// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package multicluster

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	alifeatures "istio.io/istio/pkg/ali/features"
	"istio.io/istio/pkg/ali/global"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"go.uber.org/atomic"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"istio.io/istio/pilot/pkg/features"
	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/config/mesh"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/controllers"
	"istio.io/istio/pkg/kube/kclient"
	"istio.io/istio/pkg/log"
	"istio.io/istio/pkg/monitoring"
	"istio.io/istio/pkg/slices"
	"istio.io/istio/pkg/util/sets"
)

const (
	MultiClusterSecretLabel = "istio/multiCluster"
)

var (
	clusterLabel = monitoring.CreateLabel("cluster")
	timeouts     = monitoring.NewSum(
		"remote_cluster_sync_timeouts_total",
		"Number of times remote clusters took too long to sync, causing slow startup that excludes remote clusters.",
	)

	clusterType = monitoring.CreateLabel("cluster_type")

	clustersCount = monitoring.NewGauge(
		"istiod_managed_clusters",
		"Number of clusters managed by istiod",
	)

	localClusters  = clustersCount.With(clusterType.Value("local"))
	remoteClusters = clustersCount.With(clusterType.Value("remote"))
)

type handler interface {
	clusterAdded(cluster *Cluster) ComponentConstraint
	clusterUpdated(cluster *Cluster) ComponentConstraint
	clusterUpdatedInNeed(cluster *Cluster)
	clusterDeleted(clusterID cluster.ID)
	HasSynced() bool
}

// ClientBuilder builds a new kube.Client from a kubeconfig. Mocked out for testing
type ClientBuilder = func(kubeConfig []byte, clusterId cluster.ID, configOverrides ...func(*rest.Config)) (kube.Client, error)

// Controller is the controller implementation for Secret resources
type Controller struct {
	namespace            string
	configClusterID      cluster.ID
	configCluster        *Cluster
	configClusterSyncers []ComponentConstraint

	ClientBuilder ClientBuilder

	queue           controllers.Queue
	secrets         kclient.Client[*corev1.Secret]
	configOverrides []func(*rest.Config)

	cs *ClusterStore

	meshWatcher mesh.Watcher
	handlers    []handler

	// Added by ingress
	mutex sync.Mutex
	// End added by ingress
}

// NewController returns a new secret controller
func NewController(kubeclientset kube.Client, namespace string, clusterID cluster.ID,
	meshWatcher mesh.Watcher, configOverrides ...func(*rest.Config),
) *Controller {
	// Added by ingress
	labels := MultiClusterSecretLabel + "=true"
	if alifeatures.WatchResourcesByLabelForPrimaryCluster != "" {
		labels += ", " + alifeatures.WatchResourcesByLabelForPrimaryCluster
	}
	// End added by ingress

	informerClient := kubeclientset

	// When these two are set to true, Istiod will be watching the namespace in which
	// Istiod is running on the external cluster. Use the inCluster credentials to
	// create a kubeclientset
	if features.LocalClusterSecretWatcher && features.ExternalIstiod {
		config, err := kube.InClusterConfig(configOverrides...)
		if err != nil {
			log.Errorf("Could not get istiod incluster configuration: %v", err)
			return nil
		}
		log.Info("Successfully retrieved incluster config.")

		localKubeClient, err := kube.NewClient(kube.NewClientConfigForRestConfig(config), clusterID)
		if err != nil {
			log.Errorf("Could not create a client to access local cluster API server: %v", err)
			return nil
		}
		log.Infof("Successfully created in cluster kubeclient at %s", localKubeClient.RESTConfig().Host)
		informerClient = localKubeClient
	}

	secrets := kclient.NewFiltered[*corev1.Secret](informerClient, kclient.Filter{
		Namespace:     namespace,
		LabelSelector: labels,
	})

	// init gauges
	localClusters.Record(1.0)
	remoteClusters.Record(0.0)

	controller := &Controller{
		ClientBuilder:   DefaultBuildClientsFromConfig,
		namespace:       namespace,
		configClusterID: clusterID,
		configCluster:   &Cluster{Client: kubeclientset, ID: clusterID},
		cs:              newClustersStore(),
		secrets:         secrets,
		configOverrides: configOverrides,
		meshWatcher:     meshWatcher,
	}

	// Queue does NOT retry. The only error that can occur is if the kubeconfig is
	// malformed. This is a static analysis that cannot be resolved by retry. Actual
	// connectivity issues would result in HasSynced returning false rather than an
	// error. In this case, things will be retried automatically (via informers or
	// others), and the time is capped by RemoteClusterTimeout).
	controller.queue = controllers.NewQueue("multicluster secret",
		controllers.WithReconciler(controller.processItem))

	secrets.AddEventHandler(controllers.ObjectHandler(controller.queue.AddObject))
	return controller
}

type ComponentBuilder interface {
	registerHandler(h handler)
}

// BuildMultiClusterComponent constructs a new multicluster component. For each cluster, the constructor will be called.
// If the cluster is removed, the T.Close() method will be called.
// Constructors MUST not do blocking IO; they will block other operations.
// During a cluster update, a new component is constructed before the old one is removed for seamless migration.
func BuildMultiClusterComponent[T ComponentConstraint](c ComponentBuilder, constructor func(cluster *Cluster) T) *Component[T] {
	comp := &Component[T]{
		constructor: constructor,
		clusters:    make(map[cluster.ID]T),
	}
	c.registerHandler(comp)
	return comp
}

func (c *Controller) registerHandler(h handler) {
	// Intentionally no lock. The controller today requires that handlers are registered before execution and not in parallel.
	c.handlers = append(c.handlers, h)
}

// Run starts the controller until it receives a message over stopCh
func (c *Controller) Run(stopCh <-chan struct{}) error {
	// run handlers for the config cluster; do not store this *Cluster in the ClusterStore or give it a SyncTimeout
	for _, secretHandler := range c.handlers {
		global.CacheSyncs = append(global.CacheSyncs, secretHandler.HasSynced)
	}

	// run handlers for the config cluster; do not store this *Cluster in the ClusterStore or give it a SyncTimeout
	// this is done outside the goroutine, we should block other Run/startFuncs until this is registered
	c.configClusterSyncers = c.handleAdd(c.configCluster)
	go func() {
		t0 := time.Now()
		log.Info("Starting multicluster remote secrets controller")
		// we need to start here when local cluster secret watcher enabled
		if features.LocalClusterSecretWatcher && features.ExternalIstiod {
			c.secrets.Start(stopCh)
		}
		if !kube.WaitForCacheSync("multicluster remote secrets", stopCh, c.secrets.HasSynced) {
			c.queue.ShutDownEarly()
			return
		}
		log.Infof("multicluster remote secrets controller cache synced in %v", time.Since(t0))
		c.queue.Run(stopCh)
		c.handleDelete(c.configClusterID)
	}()
	return nil
}

func (c *Controller) HasSynced() bool {
	if !c.queue.HasSynced() {
		log.Debug("secret controller did not sync secrets presented at startup")
		// we haven't finished processing the secrets that were present at startup
		return false
	}
	// Check all config cluster components are synced
	// c.ConfigClusterHandler.HasSynced does not work; config cluster is handle specially
	if !kube.AllSynced(c.configClusterSyncers) {
		return false
	}
	// Check all remote clusters are synced (or timed out)
	return c.cs.HasSynced()
}

func (c *Controller) processItem(key types.NamespacedName) error {
	// Added by ingress
	c.mutex.Lock()
	defer c.mutex.Unlock()
	// End added by ingress

	log.Infof("processing secret event for secret %s", key)
	scrt := c.secrets.Get(key.Name, key.Namespace)
	if scrt != nil {
		log.Debugf("secret %s exists in informer cache, processing it", key)
		if err := c.addSecret(key, scrt); err != nil {
			return fmt.Errorf("error adding secret %s: %v", key, err)
		}
	} else {
		log.Debugf("secret %s does not exist in informer cache, deleting it", key)
		c.deleteSecret(key.String())
	}
	remoteClusters.Record(float64(c.cs.Len()))

	return nil
}

// DefaultBuildClientsFromConfig creates kube.Clients from the provided kubeconfig. This is overridden for testing only
func DefaultBuildClientsFromConfig(kubeConfig []byte, clusterID cluster.ID, configOverrides ...func(*rest.Config)) (kube.Client, error) {
	restConfig, err := kube.NewUntrustedRestConfig(kubeConfig, configOverrides...)
	if err != nil {
		return nil, err
	}

	clients, err := kube.NewClient(kube.NewClientConfigForRestConfig(restConfig), clusterID)
	if err != nil {
		return nil, fmt.Errorf("failed to create kube clients: %v", err)
	}

	// We need to read remote gateways in ambient multicluster mode
	if features.WorkloadEntryCrossCluster || features.EnableAmbientMultiNetwork {
		clients = kube.EnableCrdWatcher(clients)
	}

	return clients, nil
}

func (c *Controller) createRemoteCluster(kubeConfig []byte, clusterID string) (*Cluster, error) {
	// Added by ingress
	clusterInfo := ConvertToClusterInfo(clusterID)
	// End added by ingress

	clients, err := c.ClientBuilder(kubeConfig, cluster.ID(clusterID), c.configOverrides...)
	if err != nil {
		return nil, err
	}
	return &Cluster{
		ID:     cluster.ID(clusterInfo.ClusterID),
		Client: clients,
		stop:   make(chan struct{}),
		// for use inside the package, to close on cleanup
		initialSync:        atomic.NewBool(false),
		initialSyncTimeout: atomic.NewBool(false),
		kubeConfigSha:      sha256.Sum256(kubeConfig),
		// Added by ingress
		ClusterInfo:   clusterInfo,
		RawKubeConfig: kubeConfig,
		RawClusterID:  clusterID,
		// End added by ingress
	}, nil
}

func (c *Controller) addSecret(name types.NamespacedName, s *corev1.Secret) error {
	// Added by ingress
	clusterInfoMapping := map[string]ClusterInfo{}
	kubeConfigMapping := map[string][]byte{}
	for key, kubeConfig := range s.Data {
		clusterInfo := ConvertToClusterInfo(key)
		clusterInfoMapping[key] = clusterInfo
		kubeConfigMapping[clusterInfo.ClusterID] = kubeConfig
	}
	// End added by ingress

	secretKey := name.String()
	// First delete clusters
	existingClusters := c.cs.GetExistingClustersFor(secretKey)
	for _, existingCluster := range existingClusters {
		if _, ok := kubeConfigMapping[string(existingCluster.ID)]; !ok { // Updated by ingress
			c.deleteCluster(secretKey, existingCluster)
		}
	}

	var errs *multierror.Error
	for clusterKey, kubeConfig := range s.Data {
		clusterInfo := clusterInfoMapping[clusterKey]
		if cluster.ID(clusterInfo.ClusterID) == c.configClusterID {
			log.Infof("ignoring cluster %v from secret %v as it would overwrite the config cluster", clusterInfo.ClusterID, secretKey)
			continue
		}

		action := Add
		if prev := c.cs.Get(secretKey, cluster.ID(clusterInfo.ClusterID)); prev != nil {
			action = Update
			// clusterID must be unique even across multiple secrets
			kubeConfigSha := sha256.Sum256(kubeConfig)
			if bytes.Equal(kubeConfigSha[:], prev.kubeConfigSha[:]) {
				if !prev.ClusterInfo.Equal(clusterInfo) {
					log.Infof("ClusterID %s has no changes, but the ingress extra options %s has changes", clusterInfo.ClusterID, clusterKey)
				} else {
					if prev.ClusterInfo.EnableIngressStatus != clusterInfo.EnableIngressStatus {
						log.Infof("ClusterID %s has no changes, but the ingress status %s has changes", clusterInfo.ClusterID, clusterKey)
						prev.ClusterInfo = clusterInfo
						c.handleUpdateInNeed(prev)
					}
					log.Infof("skipping update of cluster_id=%v from secret=%v: (kubeconfig are identical)", clusterInfo.ClusterID, secretKey)
					continue
				}
			}
			global.BlockPush()

			// stop previous remote cluster
			prev.Stop()
		} else if c.cs.Contains(cluster.ID(clusterInfo.ClusterID)) {
			// if the cluster has been registered before by another secret, ignore the new one.
			log.Warnf("cluster %d from secret %s has already been registered", clusterInfo.ClusterID, secretKey)
			continue
		}
		log.Infof("%s cluster %v cluster key %v from secret %v", action, clusterInfo.ClusterID, clusterKey, secretKey)

		remoteCluster, err := c.createRemoteCluster(kubeConfig, clusterKey)
		if err != nil {
			log.Errorf("%s cluster_id=%v from secret=%v: %v", action, clusterInfo.ClusterID, secretKey, err)
			errs = multierror.Append(errs, err)
			continue
		}
		// We run cluster async so we do not block, as this requires actually connecting to the cluster and loading configuration.
		c.cs.Store(secretKey, remoteCluster.ID, remoteCluster)

		// Added by ingress
		if action == Update {
			go global.TriggerPush(remoteCluster.stop)
		}
		// End added by ingress

		go func() {
			remoteCluster.Run(c.meshWatcher, c.handlers, action)
		}()
	}

	log.Infof("Number of remote clusters: %d", c.cs.Len())
	return errs.ErrorOrNil()
}

func (c *Controller) deleteSecret(secretKey string) {
	for _, cluster := range c.cs.GetExistingClustersFor(secretKey) {
		if cluster.ID == c.configClusterID {
			log.Infof("ignoring delete cluster %v from secret %v as it would overwrite the config cluster", c.configClusterID, secretKey)
			continue
		}

		c.deleteCluster(secretKey, cluster)
	}

	log.Infof("Number of remote clusters: %d", c.cs.Len())
}

func (c *Controller) deleteCluster(secretKey string, cluster *Cluster) {
	log.Infof("Deleting cluster_id=%v configured by secret=%v", cluster.ID, secretKey)
	cluster.Stop()
	c.handleDelete(cluster.ID)
	c.cs.Delete(secretKey, cluster.ID)

	log.Infof("Number of remote clusters: %d", c.cs.Len())
}

func (c *Controller) handleAdd(cluster *Cluster) []ComponentConstraint {
	syncers := make([]ComponentConstraint, 0, len(c.handlers))
	for _, handler := range c.handlers {
		syncers = append(syncers, handler.clusterAdded(cluster))
	}
	return syncers
}

func (c *Controller) handleDelete(key cluster.ID) {
	for _, handler := range c.handlers {
		handler.clusterDeleted(key)
	}
}

// Added by ingress
func (c *Controller) handleUpdateInNeed(cluster *Cluster) {
	for _, handler := range c.handlers {
		handler.clusterUpdatedInNeed(cluster)
	}
}

// End added by ingress

// ListRemoteClusters provides debug info about connected remote clusters.
func (c *Controller) ListRemoteClusters() []cluster.DebugInfo {
	// Start with just the config cluster
	configCluster := "syncing"
	if kube.AllSynced(c.configClusterSyncers) {
		configCluster = "synced"
	}
	out := []cluster.DebugInfo{{
		ID:         c.configClusterID,
		SyncStatus: configCluster,
	}}
	// Append each cluster derived from secrets
	for secretName, clusters := range c.cs.All() {
		for clusterID, c := range clusters {
			syncStatus := "syncing"
			if c.Closed() {
				syncStatus = "closed"
			} else if c.SyncDidTimeout() {
				syncStatus = "timeout"
			} else if c.HasSynced() {
				syncStatus = "synced"
			}
			out = append(out, cluster.DebugInfo{
				ID:         clusterID,
				SecretName: secretName,
				SyncStatus: syncStatus,
			})
		}
	}
	return out
}

func (c *Controller) GetRemoteKubeClient(clusterID cluster.ID) kubernetes.Interface {
	if remoteCluster := c.cs.GetByID(clusterID); remoteCluster != nil {
		return remoteCluster.Client.Kube()
	}
	return nil
}

func (c *Controller) ListClusters() []cluster.ID {
	return slices.Map(sets.SortedList(c.cs.clusters), func(e string) cluster.ID {
		return cluster.ID(e)
	})
}

// added by ingress
func (c *Controller) UpdateCluster(clusterID cluster.ID) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	secretKey, prev := c.cs.GetIndexByID(clusterID)
	if prev == nil {
		log.Infof("cluster %s not found, no need to update", clusterID)
		return
	}

	remoteCluster, err := c.createRemoteCluster(prev.RawKubeConfig, prev.RawClusterID)
	if err != nil {
		log.Errorf("updating cluster_id=%v from v1beta to v1 fail, err: %v", clusterID, err)
		return
	}

	prev.Stop()
	global.BlockPush()
	defer func() {
		go global.TriggerPush(remoteCluster.stop)
	}()

	c.cs.Store(secretKey, remoteCluster.ID, remoteCluster)

	action := Update
	log.Infof("updating cluster_id=%v from v1beta to v1 success", clusterID)
	go func() {
		remoteCluster.Run(c.meshWatcher, c.handlers, action)
	}()
}

// end added by ingress
