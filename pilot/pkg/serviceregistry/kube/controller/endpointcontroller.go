// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package controller

import (
	"istio.io/istio/pilot/pkg/model"
	"istio.io/istio/pkg/config/host"
)

// Pilot can get EDS information from Kubernetes from two mutually exclusive sources, Endpoints and
// EndpointSlices. The kubeEndpointsController abstracts these details and provides a common interface
// that both sources implement.
type kubeEndpointsController interface {
	// sync(name, ns string, event model.Event, filtered bool) error
	//NameForService(name, namespace string) []types.NamespacedName
	// InstancesByPort(svc *model.Service, reqSvcPort int) []*model.ServiceInstance
	// GetProxyServiceInstances(proxy *model.Proxy) []*model.ServiceInstance

	HasSynced() bool
	GetProxyServiceTargets(proxy *model.Proxy) []model.ServiceTarget
	buildIstioEndpointsWithService(name, namespace string, host host.Name, clearCache bool) []*model.IstioEndpoint
	pushEDS(hostnames []host.Name, namespace string)
	initializeNamespace(ns string, filtered bool) error
	podArrived(name, ns string) error
}
