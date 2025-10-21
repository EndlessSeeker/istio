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

package xds_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	meshconfig "istio.io/api/mesh/v1alpha1"
	credentials "istio.io/istio/pilot/pkg/credentials/kube"
	"istio.io/istio/pilot/pkg/model"
	v3 "istio.io/istio/pilot/pkg/xds/v3"
	"istio.io/istio/pilot/test/xds"
	"istio.io/istio/pilot/test/xdstest"
	"istio.io/istio/pkg/config/constants"
	"istio.io/istio/pkg/config/schema/kind"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/spiffe"
	"istio.io/istio/pkg/test/env"
	"istio.io/istio/pkg/test/util/assert"
	"istio.io/istio/pkg/util/sets"
	xdsserver "istio.io/istio/pkg/xds"
)

//
//// Added by ingress
//type PrivateKeyProviderType int8
//
//func (p PrivateKeyProviderType) String() string {
//	switch p {
//	case CryptoMbPrivateKeyProviderType:
//		return "cryptomb"
//	case QATPrivateKeyProviderType:
//		return "qat"
//	default:
//		return "empty"
//	}
//}
//
//const (
//	EmptyPrivateKeyProviderType    PrivateKeyProviderType = 0
//	CryptoMbPrivateKeyProviderType PrivateKeyProviderType = 1
//	QATPrivateKeyProviderType      PrivateKeyProviderType = 2
//
//	nodeInstanceType = "instance-type"
//	cpuInfo          = "cpu-info"
//	envoyVersion     = "ENVOY_VERSION"
//)

func makeSecret(name string, data map[string]string) *corev1.Secret {
	bdata := map[string][]byte{}
	for k, v := range data {
		bdata[k] = []byte(v)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "istio-system",
		},
		Data: bdata,
	}
}

var (
	certDir      = filepath.Join(env.IstioSrc, "./tests/testdata/certs")
	simpleCaCert = makeSecret("ca-only", map[string]string{
		credentials.GenericScrtCaCert: readFile(filepath.Join(certDir, "dns/root-cert.pem")),
	})
	// A secret with -cacert in the suffix, referenced directly in the credential
	trickyCaCert = makeSecret("tricky-cacert", map[string]string{
		credentials.GenericScrtCert:   readFile(filepath.Join(certDir, "dns/cert-chain.pem")),
		credentials.GenericScrtKey:    readFile(filepath.Join(certDir, "dns/key.pem")),
		credentials.GenericScrtCaCert: readFile(filepath.Join(certDir, "dns/root-cert.pem")),
	})
	genericCert = makeSecret("generic", map[string]string{
		credentials.GenericScrtCert: readFile(filepath.Join(certDir, "default/cert-chain.pem")),
		credentials.GenericScrtKey:  readFile(filepath.Join(certDir, "default/key.pem")),
	})
	genericMtlsCert = makeSecret("generic-mtls", map[string]string{
		credentials.GenericScrtCert:   readFile(filepath.Join(certDir, "dns/cert-chain.pem")),
		credentials.GenericScrtKey:    readFile(filepath.Join(certDir, "dns/key.pem")),
		credentials.GenericScrtCaCert: readFile(filepath.Join(certDir, "dns/root-cert.pem")),
	})
	genericMtlsCertCrl = makeSecret("generic-mtls-crl", map[string]string{
		credentials.GenericScrtCert:   readFile(filepath.Join(certDir, "dns/cert-chain.pem")),
		credentials.GenericScrtKey:    readFile(filepath.Join(certDir, "dns/key.pem")),
		credentials.GenericScrtCaCert: readFile(filepath.Join(certDir, "dns/root-cert.pem")),
		credentials.GenericScrtCRL:    readFile(filepath.Join(certDir, "dns/cert-chain.pem")),
	})
	genericMtlsCertSplit = makeSecret("generic-mtls-split", map[string]string{
		credentials.GenericScrtCert: readFile(filepath.Join(certDir, "mountedcerts-client/cert-chain.pem")),
		credentials.GenericScrtKey:  readFile(filepath.Join(certDir, "mountedcerts-client/key.pem")),
	})
	genericMtlsCertSplitCa = makeSecret("generic-mtls-split-cacert", map[string]string{
		credentials.GenericScrtCaCert: readFile(filepath.Join(certDir, "mountedcerts-client/root-cert.pem")),
	})
)

func readFile(name string) string {
	cacert, _ := os.ReadFile(name)
	return string(cacert)
}

func TestGenerateSDS(t *testing.T) {
	type Expected struct {
		Key    string
		Cert   string
		CaCert string
		CaCrl  string
	}
	allResources := []string{
		"kubernetes://generic", "kubernetes://generic-mtls", "kubernetes://generic-mtls-cacert", "kubernetes://ca-only-cacert",
		"kubernetes://generic-mtls-split", "kubernetes://generic-mtls-split-cacert", "kubernetes://generic-mtls-crl",
		"kubernetes://generic-mtls-crl-cacert",
	}
	cases := []struct {
		name                 string
		proxy                *model.Proxy
		resources            []string
		request              *model.PushRequest
		expect               map[string]Expected
		accessReviewResponse func(action k8stesting.Action) (bool, runtime.Object, error)
		objects              []runtime.Object
	}{
		{
			name:      "simple",
			proxy:     &model.Proxy{VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"}, Type: model.Router},
			resources: []string{"kubernetes://generic"},
			request:   &model.PushRequest{Full: true, Forced: true},
			expect: map[string]Expected{
				"kubernetes://generic": {
					Key:  string(genericCert.Data[credentials.GenericScrtKey]),
					Cert: string(genericCert.Data[credentials.GenericScrtCert]),
				},
			},
		},
		{
			name:      "sidecar",
			proxy:     &model.Proxy{VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"}},
			resources: []string{"kubernetes://generic"},
			request:   &model.PushRequest{Full: true, Forced: true},
			expect: map[string]Expected{
				"kubernetes://generic": {
					Key:  string(genericCert.Data[credentials.GenericScrtKey]),
					Cert: string(genericCert.Data[credentials.GenericScrtCert]),
				},
			},
		},
		{
			name:      "unauthenticated",
			proxy:     &model.Proxy{Type: model.Router},
			resources: []string{"kubernetes://generic"},
			request:   &model.PushRequest{Full: true, Forced: true},
			expect:    map[string]Expected{},
		},
		{
			name:      "multiple",
			proxy:     &model.Proxy{VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"}, Type: model.Router},
			resources: allResources,
			request:   &model.PushRequest{Full: true, Forced: true},
			expect: map[string]Expected{
				"kubernetes://generic": {
					Key:  string(genericCert.Data[credentials.GenericScrtKey]),
					Cert: string(genericCert.Data[credentials.GenericScrtCert]),
				},
				"kubernetes://generic-mtls": {
					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
				},
				"kubernetes://ca-only-cacert": {
					CaCert: string(simpleCaCert.Data[credentials.GenericScrtCaCert]),
				},
				"kubernetes://generic-mtls-cacert": {
					CaCert: string(genericMtlsCert.Data[credentials.GenericScrtCaCert]),
				},
				"kubernetes://generic-mtls-split": {
					Key:  string(genericMtlsCertSplit.Data[credentials.GenericScrtKey]),
					Cert: string(genericMtlsCertSplit.Data[credentials.GenericScrtCert]),
				},
				"kubernetes://generic-mtls-split-cacert": {
					CaCert: string(genericMtlsCertSplitCa.Data[credentials.GenericScrtCaCert]),
				},
				"kubernetes://generic-mtls-crl": {
					Key:  string(genericMtlsCertCrl.Data[credentials.GenericScrtKey]),
					Cert: string(genericMtlsCertCrl.Data[credentials.GenericScrtCert]),
				},
				"kubernetes://generic-mtls-crl-cacert": {
					CaCert: string(genericMtlsCertCrl.Data[credentials.GenericScrtCaCert]),
					CaCrl:  string(genericMtlsCertCrl.Data[credentials.GenericScrtCRL]),
				},
			},
		},
		{
			name:      "full push with updates",
			proxy:     &model.Proxy{VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"}, Type: model.Router},
			resources: []string{"kubernetes://generic", "kubernetes://generic-mtls", "kubernetes://generic-mtls-cacert"},
			request: &model.PushRequest{Full: true, ConfigsUpdated: sets.New(model.ConfigKey{
				Kind:      kind.Secret,
				Name:      "generic-mtls",
				Namespace: "istio-system",
			})},
			expect: map[string]Expected{
				"kubernetes://generic": {
					Key:  string(genericCert.Data[credentials.GenericScrtKey]),
					Cert: string(genericCert.Data[credentials.GenericScrtCert]),
				},
				"kubernetes://generic-mtls": {
					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
				},
				"kubernetes://generic-mtls-cacert": {
					CaCert: string(genericMtlsCert.Data[credentials.GenericScrtCaCert]),
				},
			},
		},
		{
			name:      "incremental push with updates",
			proxy:     &model.Proxy{VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"}, Type: model.Router},
			resources: allResources,
			request:   &model.PushRequest{Full: false, ConfigsUpdated: sets.New(model.ConfigKey{Kind: kind.Secret, Name: "generic", Namespace: "istio-system"})},
			expect: map[string]Expected{
				"kubernetes://generic": {
					Key:  string(genericCert.Data[credentials.GenericScrtKey]),
					Cert: string(genericCert.Data[credentials.GenericScrtCert]),
				},
			},
		},
		{
			name:      "incremental push with updates - mtls",
			proxy:     &model.Proxy{VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"}, Type: model.Router},
			resources: allResources,
			request: &model.PushRequest{
				Full:           false,
				ConfigsUpdated: sets.New(model.ConfigKey{Kind: kind.Secret, Name: "generic-mtls", Namespace: "istio-system"}),
			},
			expect: map[string]Expected{
				"kubernetes://generic-mtls": {
					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
				},
				"kubernetes://generic-mtls-cacert": {
					CaCert: string(genericMtlsCert.Data[credentials.GenericScrtCaCert]),
				},
			},
		},
		{
			name:      "incremental push with updates - mtls with crl",
			proxy:     &model.Proxy{VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"}, Type: model.Router},
			resources: allResources,
			request: &model.PushRequest{
				Full:           false,
				ConfigsUpdated: sets.New(model.ConfigKey{Kind: kind.Secret, Name: "generic-mtls-crl", Namespace: "istio-system"}),
			},
			expect: map[string]Expected{
				"kubernetes://generic-mtls-crl": {
					Key:  string(genericMtlsCertCrl.Data[credentials.GenericScrtKey]),
					Cert: string(genericMtlsCertCrl.Data[credentials.GenericScrtCert]),
				},
				"kubernetes://generic-mtls-crl-cacert": {
					CaCert: string(genericMtlsCertCrl.Data[credentials.GenericScrtCaCert]),
					CaCrl:  string(genericMtlsCertCrl.Data[credentials.GenericScrtCRL]),
				},
			},
		},
		{
			name:      "incremental push with updates - mtls split",
			proxy:     &model.Proxy{VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"}, Type: model.Router},
			resources: allResources,
			request: &model.PushRequest{
				Full:           false,
				ConfigsUpdated: sets.New(model.ConfigKey{Kind: kind.Secret, Name: "generic-mtls-split", Namespace: "istio-system"}),
			},
			expect: map[string]Expected{
				"kubernetes://generic-mtls-split": {
					Key:  string(genericMtlsCertSplit.Data[credentials.GenericScrtKey]),
					Cert: string(genericMtlsCertSplit.Data[credentials.GenericScrtCert]),
				},
				"kubernetes://generic-mtls-split-cacert": {
					CaCert: string(genericMtlsCertSplitCa.Data[credentials.GenericScrtCaCert]),
				},
			},
		},
		{
			name:      "incremental push with updates - mtls split ca update",
			proxy:     &model.Proxy{VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"}, Type: model.Router},
			resources: allResources,
			request: &model.PushRequest{
				Full:           false,
				ConfigsUpdated: sets.New(model.ConfigKey{Kind: kind.Secret, Name: "generic-mtls-split-cacert", Namespace: "istio-system"}),
			},
			expect: map[string]Expected{
				"kubernetes://generic-mtls-split": {
					Key:  string(genericMtlsCertSplit.Data[credentials.GenericScrtKey]),
					Cert: string(genericMtlsCertSplit.Data[credentials.GenericScrtCert]),
				},
				"kubernetes://generic-mtls-split-cacert": {
					CaCert: string(genericMtlsCertSplitCa.Data[credentials.GenericScrtCaCert]),
				},
			},
		},
		{
			// If an unknown resource is request, we return all the ones we do know about
			name:      "unknown",
			proxy:     &model.Proxy{VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"}, Type: model.Router},
			resources: []string{"kubernetes://generic", "foo://invalid", "kubernetes://not-found", "default", "builtin://"},
			request:   &model.PushRequest{Full: true, Forced: true},
			expect: map[string]Expected{
				"kubernetes://generic": {
					Key:  string(genericCert.Data[credentials.GenericScrtKey]),
					Cert: string(genericCert.Data[credentials.GenericScrtCert]),
				},
			},
		},
		{
			// proxy without authorization
			name:      "unauthorized",
			proxy:     &model.Proxy{VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"}, Type: model.Router},
			resources: []string{"kubernetes://generic"},
			request:   &model.PushRequest{Full: true, Forced: true},
			// Should get a response, but it will be empty
			expect: map[string]Expected{},
			accessReviewResponse: func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("not authorized")
			},
		},
		{
			// proxy without authorization -- can get CA certs only
			name:      "partially unauthorized",
			proxy:     &model.Proxy{VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"}, Type: model.Router},
			resources: allResources,
			request:   &model.PushRequest{Full: true, Forced: true},
			// Should get a response, but it will be empty
			expect: map[string]Expected{
				"kubernetes://ca-only-cacert": {
					CaCert: string(simpleCaCert.Data[credentials.GenericScrtCaCert]),
				},
				// Note: below are a little strange, since we split a mTLS secret (with 3 parts) into 2 resources
				// We allow only the public part.
				// Ultimately it doesn't matter that we allow this; the client will need both parts to do anything
				"kubernetes://generic-mtls-split-cacert": {
					CaCert: string(genericMtlsCertSplitCa.Data[credentials.GenericScrtCaCert]),
				},
				"kubernetes://generic-mtls-crl-cacert": {
					CaCert: string(genericMtlsCertCrl.Data[credentials.GenericScrtCaCert]),
					CaCrl:  string(genericMtlsCertCrl.Data[credentials.GenericScrtCRL]),
				},
				"kubernetes://generic-mtls-cacert": {
					CaCert: string(genericMtlsCert.Data[credentials.GenericScrtCaCert]),
				},
			},
			accessReviewResponse: func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("not authorized")
			},
		},
		{
			// proxy without authorization -- can get CA certs only.
			// If a credential name is poorly named with a -cacert suffix, we shouldn't let that be accesses
			name:      "tricky cacert name",
			proxy:     &model.Proxy{VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"}, Type: model.Router},
			resources: []string{"kubernetes://tricky-cacert", "kubernetes://tricky-cacert-cacert"},
			request:   &model.PushRequest{Full: true, Forced: true},
			expect: map[string]Expected{
				// They should NOT be able to get the private key material
				"kubernetes://tricky-cacert": {
					CaCert: string(trickyCaCert.Data[credentials.GenericScrtCaCert]),
				},
				"kubernetes://tricky-cacert-cacert": {
					CaCert: string(trickyCaCert.Data[credentials.GenericScrtCaCert]),
				},
			},
			objects: []runtime.Object{trickyCaCert},
			accessReviewResponse: func(action k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, errors.New("not authorized")
			},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.proxy.Metadata == nil {
				tt.proxy.Metadata = &model.NodeMetadata{}
			}
			obj := tt.objects
			if obj == nil {
				// Default set
				obj = []runtime.Object{
					genericCert,
					genericMtlsCert,
					simpleCaCert,
					genericMtlsCertCrl,
					genericMtlsCertSplit,
					genericMtlsCertSplitCa,
				}
			}
			tt.proxy.Metadata.ClusterID = constants.DefaultClusterName
			s := xds.NewFakeDiscoveryServer(t, xds.FakeOptions{
				KubernetesObjects: obj,
			})
			cc := s.KubeClient().Kube().(*fake.Clientset)

			cc.Fake.Lock()
			if tt.accessReviewResponse != nil {
				cc.Fake.PrependReactor("create", "subjectaccessreviews", tt.accessReviewResponse)
			} else {
				xds.DisableAuthorizationForSecret(cc)
			}
			cc.Fake.Unlock()

			gen := s.Discovery.Generators[v3.SecretType]
			tt.request.Start = time.Now()
			secrets, _, _ := gen.Generate(s.SetupProxy(tt.proxy), &model.WatchedResource{ResourceNames: sets.New(tt.resources...)}, tt.request)
			raw := xdstest.ExtractTLSSecrets(t, xdsserver.ResourcesToAny(secrets))

			got := map[string]Expected{}
			for _, scrt := range raw {
				got[scrt.Name] = Expected{
					Key:    string(scrt.GetTlsCertificate().GetPrivateKey().GetInlineBytes()),
					Cert:   string(scrt.GetTlsCertificate().GetCertificateChain().GetInlineBytes()),
					CaCert: string(scrt.GetValidationContext().GetTrustedCa().GetInlineBytes()),
					CaCrl:  string(scrt.GetValidationContext().GetCrl().GetInlineBytes()),
				}
			}
			assert.Equal(t, got, tt.expect)
		})
	}
}

// TestCaching ensures we don't have cross-proxy cache generation issues. This is split from TestGenerate
// since it is order dependent.
// Regression test for https://github.com/istio/istio/issues/33368
func TestCaching(t *testing.T) {
	s := xds.NewFakeDiscoveryServer(t, xds.FakeOptions{
		KubernetesObjects: []runtime.Object{genericCert},
		KubeClientModifier: func(c kube.Client) {
			cc := c.Kube().(*fake.Clientset)
			xds.DisableAuthorizationForSecret(cc)
		},
	})
	gen := s.Discovery.Generators[v3.SecretType]

	fullPush := &model.PushRequest{Full: true, Start: time.Now(), Forced: true}
	istiosystem := &model.Proxy{
		Metadata:         &model.NodeMetadata{ClusterID: constants.DefaultClusterName},
		VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
		Type:             model.Router,
		ConfigNamespace:  "istio-system",
	}
	otherNamespace := &model.Proxy{
		Metadata:         &model.NodeMetadata{ClusterID: constants.DefaultClusterName},
		VerifiedIdentity: &spiffe.Identity{Namespace: "other-namespace"},
		Type:             model.Router,
		ConfigNamespace:  "other-namespace",
	}

	secrets, _, _ := gen.Generate(s.SetupProxy(istiosystem), &model.WatchedResource{ResourceNames: sets.New("kubernetes://generic")}, fullPush)
	raw := xdstest.ExtractTLSSecrets(t, xdsserver.ResourcesToAny(secrets))
	if len(raw) != 1 {
		t.Fatalf("failed to get expected secrets for authorized proxy: %v", raw)
	}

	// We should not get secret returned, even though we are asking for the same one
	secrets, _, _ = gen.Generate(s.SetupProxy(otherNamespace), &model.WatchedResource{ResourceNames: sets.New("kubernetes://generic")}, fullPush)
	raw = xdstest.ExtractTLSSecrets(t, xdsserver.ResourcesToAny(secrets))
	if len(raw) != 0 {
		t.Fatalf("failed to get expected secrets for unauthorized proxy: %v", raw)
	}
}

func TestPrivateKeyProviderProxyConfig(t *testing.T) {
	pkpProxy := &model.Proxy{
		VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
		Type:             model.Router,
		Metadata: &model.NodeMetadata{
			ClusterID: constants.DefaultClusterName,
			ProxyConfig: &model.NodeMetaProxyConfig{
				PrivateKeyProvider: &meshconfig.PrivateKeyProvider{
					Provider: &meshconfig.PrivateKeyProvider_Cryptomb{
						Cryptomb: &meshconfig.PrivateKeyProvider_CryptoMb{
							PollDelay: &durationpb.Duration{
								Seconds: 0,
								Nanos:   10000,
							},
						},
					},
				},
			},
		},
	}
	rawProxy := &model.Proxy{
		VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
		Type:             model.Router,
		Metadata:         &model.NodeMetadata{ClusterID: constants.DefaultClusterName},
	}
	s := xds.NewFakeDiscoveryServer(t, xds.FakeOptions{
		KubernetesObjects: []runtime.Object{genericCert},
		KubeClientModifier: func(c kube.Client) {
			cc := c.Kube().(*fake.Clientset)
			xds.DisableAuthorizationForSecret(cc)
		},
	})
	gen := s.Discovery.Generators[v3.SecretType]
	fullPush := &model.PushRequest{Full: true, Start: time.Now(), Forced: true}
	secrets, _, _ := gen.Generate(s.SetupProxy(rawProxy), &model.WatchedResource{ResourceNames: sets.New("kubernetes://generic")}, fullPush)
	raw := xdstest.ExtractTLSSecrets(t, xdsserver.ResourcesToAny(secrets))
	for _, scrt := range raw {
		if scrt.GetTlsCertificate().GetPrivateKeyProvider() != nil {
			t.Fatal("expect no private key provider in secret")
		}
	}

	// add private key provider in proxy-config
	secrets, _, _ = gen.Generate(s.SetupProxy(pkpProxy), &model.WatchedResource{ResourceNames: sets.New("kubernetes://generic")}, fullPush)
	raw = xdstest.ExtractTLSSecrets(t, xdsserver.ResourcesToAny(secrets))
	for _, scrt := range raw {
		privateKeyProvider := scrt.GetTlsCertificate().GetPrivateKeyProvider()
		if privateKeyProvider == nil {
			t.Fatal("expect private key provider in secret")
		}
		// update by ingress
		//if privateKeyProvider.GetFallback() {
		//	t.Fatal("expect fallback for private key provider in secret as false")
		//}
	}

	// erase private key provider in proxy-config
	secrets, _, _ = gen.Generate(s.SetupProxy(rawProxy), &model.WatchedResource{ResourceNames: sets.New("kubernetes://generic")}, fullPush)
	raw = xdstest.ExtractTLSSecrets(t, xdsserver.ResourcesToAny(secrets))
	for _, scrt := range raw {
		if scrt.GetTlsCertificate().GetPrivateKeyProvider() != nil {
			t.Fatal("expect no private key provider in secret")
		}
	}
}

//
//// Added by Ingress
//func TestCryptoMBConfig(t *testing.T) {
//	type Expected struct {
//		Key                    string
//		Cert                   string
//		CaCert                 string
//		PrivateName            string
//		PrivateProviderTypeUrl string
//		CryptoPrivateKeyConfig cryptomb.CryptoMbPrivateKeyMethodConfig
//	}
//	poolDelay, _ := time.ParseDuration("2ms")
//	cases := []struct {
//		name                 string
//		proxy                *model.Proxy
//		resources            []string
//		request              *model.PushRequest
//		expect               map[string]Expected
//		accessReviewResponse func(action k8stesting.Action) (bool, runtime.Object, error)
//	}{
//		{
//			name: "second polldelay",
//			proxy: &model.Proxy{
//				VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
//				Type:             model.Router,
//				Metadata: &model.NodeMetadata{
//					PlatformMetadata: map[string]string{
//						"instance-type": "ecs.c7.8xlarge",
//					},
//				},
//			},
//			resources: []string{"kubernetes://generic-mtls-split", "kubernetes://generic-mtls"},
//			request: &model.PushRequest{
//				Full: true,
//				ConfigsUpdated: map[model.ConfigKey]struct{}{
//					{Name: "generic-mtls-split", Namespace: "istio-system", Kind: kind.Secret}: {},
//					{Name: "generic-mtls", Namespace: "istio-system", Kind: kind.Secret}:       {},
//				},
//				Push: &model.PushContext{
//					Mesh: &meshconfig.MeshConfig{
//						CryptombConfig: &meshconfig.MeshConfig_CryptombPrivateKeyConfig{
//							EnableCryptomb: true,
//							PoolDelay: &duration.Duration{
//								Seconds: 2,
//							},
//						},
//					},
//				},
//			},
//			expect: map[string]Expected{
//				"kubernetes://generic-mtls-split": {
//					Key:  string(genericCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericCert.Data[credentials.GenericScrtCert]),
//					CryptoPrivateKeyConfig: cryptomb.CryptoMbPrivateKeyMethodConfig{
//						PollDelay: &duration.Duration{
//							Seconds: 2,
//						},
//					},
//				},
//				"kubernetes://generic-mtls": {
//					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
//					CryptoPrivateKeyConfig: cryptomb.CryptoMbPrivateKeyMethodConfig{
//						PollDelay: &duration.Duration{
//							Seconds: 2,
//						},
//					},
//				},
//			},
//		},
//		{
//			name: "millisecond polldelay",
//			proxy: &model.Proxy{
//				VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
//				Type:             model.Router,
//				Metadata: &model.NodeMetadata{
//					PlatformMetadata: map[string]string{
//						"instance-type": "ecs.c7se.4xlarge",
//					},
//				},
//			},
//			resources: []string{"kubernetes://generic-mtls", "kubernetes://generic-mtls-split"},
//			request: &model.PushRequest{
//				Full: true,
//				ConfigsUpdated: map[model.ConfigKey]struct{}{
//					{Name: "generic-mtls", Namespace: "istio-system", Kind: kind.Secret}:       {},
//					{Name: "generic-mtls-split", Namespace: "istio-system", Kind: kind.Secret}: {},
//				},
//				Push: &model.PushContext{
//					Mesh: &meshconfig.MeshConfig{
//						CryptombConfig: &meshconfig.MeshConfig_CryptombPrivateKeyConfig{
//							EnableCryptomb: true,
//							PoolDelay:      durationpb.New(poolDelay),
//						},
//					},
//				},
//			},
//			expect: map[string]Expected{
//				"kubernetes://generic-mtls": {
//					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
//					CryptoPrivateKeyConfig: cryptomb.CryptoMbPrivateKeyMethodConfig{
//						PollDelay: durationpb.New(poolDelay),
//					},
//				},
//				"kubernetes://generic-mtls-split": {
//					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
//					CryptoPrivateKeyConfig: cryptomb.CryptoMbPrivateKeyMethodConfig{
//						PollDelay: durationpb.New(poolDelay),
//					},
//				},
//			},
//		},
//		{
//			name: "cpu info",
//			proxy: &model.Proxy{
//				VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
//				Type:             model.Router,
//				Metadata: &model.NodeMetadata{
//					PlatformMetadata: map[string]string{
//						cpuInfo: "Intel(R) Xeon(R) Platinum 8369B ",
//					},
//				},
//			},
//			resources: []string{"kubernetes://generic-mtls", "kubernetes://generic-mtls-split"},
//			request: &model.PushRequest{
//				Full: true,
//				ConfigsUpdated: map[model.ConfigKey]struct{}{
//					{Name: "generic-mtls", Namespace: "istio-system", Kind: kind.Secret}:       {},
//					{Name: "generic-mtls-split", Namespace: "istio-system", Kind: kind.Secret}: {},
//				},
//				Push: &model.PushContext{
//					Mesh: &meshconfig.MeshConfig{
//						CryptombConfig: &meshconfig.MeshConfig_CryptombPrivateKeyConfig{
//							EnableCryptomb: true,
//							PoolDelay:      durationpb.New(poolDelay),
//						},
//					},
//				},
//			},
//			expect: map[string]Expected{
//				"kubernetes://generic-mtls": {
//					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
//					CryptoPrivateKeyConfig: cryptomb.CryptoMbPrivateKeyMethodConfig{
//						PollDelay: durationpb.New(poolDelay),
//					},
//				},
//				"kubernetes://generic-mtls-split": {
//					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
//					CryptoPrivateKeyConfig: cryptomb.CryptoMbPrivateKeyMethodConfig{
//						PollDelay: durationpb.New(poolDelay),
//					},
//				},
//			},
//		},
//	}
//
//	for _, tt := range cases {
//		t.Run(tt.name, func(t *testing.T) {
//			if tt.proxy.Metadata == nil {
//				tt.proxy.Metadata = &model.NodeMetadata{}
//			}
//			tt.proxy.Metadata.ClusterID = "Kubernetes"
//			s := xds.NewFakeDiscoveryServer(t, xds.FakeOptions{
//				KubernetesObjects: []runtime.Object{genericCert, genericMtlsCert, genericMtlsCertSplit, genericMtlsCertSplitCa},
//			})
//			cc := s.KubeClient().Kube().(*fake.Clientset)
//
//			cc.Fake.Lock()
//			if tt.accessReviewResponse != nil {
//				cc.Fake.PrependReactor("create", "subjectaccessreviews", tt.accessReviewResponse)
//			} else {
//				xds.DisableAuthorizationForSecret(cc)
//			}
//			cc.Fake.Unlock()
//
//			gen := s.Discovery.Generators[v3.SecretType]
//			tt.request.Start = time.Now()
//			secrets, _, _ := gen.Generate(s.SetupProxy(tt.proxy), &model.WatchedResource{ResourceNames: sets.New(tt.resources...)}, tt.request)
//			raw := xdstest.ExtractTLSSecrets(t, model.ResourcesToAny(secrets))
//
//			got := map[string]Expected{}
//			for _, scrt := range raw {
//				log.Infof("secret: %v \n", scrt)
//				t.Logf("typeurl %s \n", scrt.GetTlsCertificate().GetPrivateKeyProvider().GetTypedConfig().TypeUrl)
//				t.Logf("name %s \n", scrt.GetTlsCertificate().GetPrivateKeyProvider().GetProviderName())
//
//				provider := &cryptomb.CryptoMbPrivateKeyMethodConfig{}
//				if err := scrt.GetTlsCertificate().GetPrivateKeyProvider().GetTypedConfig().UnmarshalTo(provider); err != nil {
//					t.Fatalf("Failed to unmarsha to privatekeyprivider %v", err)
//				}
//				log.Infof("secret xxx: %v \n", scrt)
//				got[scrt.Name] = Expected{
//					Key:                    string(scrt.GetTlsCertificate().GetPrivateKey().GetInlineBytes()),
//					Cert:                   string(scrt.GetTlsCertificate().GetCertificateChain().GetInlineBytes()),
//					CaCert:                 string(scrt.GetValidationContext().GetTrustedCa().GetInlineBytes()),
//					PrivateName:            scrt.GetTlsCertificate().GetPrivateKeyProvider().GetProviderName(),
//					PrivateProviderTypeUrl: scrt.GetTlsCertificate().GetPrivateKeyProvider().GetTypedConfig().TypeUrl,
//					CryptoPrivateKeyConfig: *provider,
//				}
//
//				if got[scrt.Name].CryptoPrivateKeyConfig.PollDelay.AsDuration().String() != tt.expect[scrt.Name].CryptoPrivateKeyConfig.PollDelay.AsDuration().String() {
//					t.Fatalf("got %v, want %v", got[scrt.Name].CryptoPrivateKeyConfig.PollDelay, tt.expect[scrt.Name].CryptoPrivateKeyConfig.PollDelay)
//				}
//			}
//		})
//	}
//}
//
//func TestQATConfig(t *testing.T) {
//	type Expected struct {
//		Key                    string
//		Cert                   string
//		CaCert                 string
//		PrivateName            string
//		PrivateProviderTypeUrl string
//		PrivateKeyConfig       qat.QatPrivateKeyMethodConfig
//	}
//	poolDelay, _ := time.ParseDuration("2ms")
//	cases := []struct {
//		name                 string
//		proxy                *model.Proxy
//		resources            []string
//		request              *model.PushRequest
//		expect               map[string]Expected
//		accessReviewResponse func(action k8stesting.Action) (bool, runtime.Object, error)
//	}{
//		{
//			name: "second polldelay",
//			proxy: &model.Proxy{
//				VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
//				Type:             model.Router,
//				Metadata: &model.NodeMetadata{
//					PlatformMetadata: map[string]string{
//						"instance-type": "ecs.c8a.8xlarge",
//					},
//				},
//			},
//			resources: []string{"kubernetes://generic-mtls-split", "kubernetes://generic-mtls"},
//			request: &model.PushRequest{
//				Full: true,
//				ConfigsUpdated: map[model.ConfigKey]struct{}{
//					{Name: "generic-mtls-split", Namespace: "istio-system", Kind: kind.Secret}: {},
//					{Name: "generic-mtls", Namespace: "istio-system", Kind: kind.Secret}:       {},
//				},
//				Push: &model.PushContext{
//					Mesh: &meshconfig.MeshConfig{
//						CryptombConfig: &meshconfig.MeshConfig_CryptombPrivateKeyConfig{
//							EnableCryptomb: true,
//							PoolDelay: &duration.Duration{
//								Seconds: 2,
//							},
//						},
//					},
//				},
//			},
//			expect: map[string]Expected{
//				"kubernetes://generic-mtls-split": {
//					Key:  string(genericCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericCert.Data[credentials.GenericScrtCert]),
//					PrivateKeyConfig: qat.QatPrivateKeyMethodConfig{
//						PollDelay: &duration.Duration{
//							Seconds: 2,
//						},
//					},
//				},
//				"kubernetes://generic-mtls": {
//					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
//					PrivateKeyConfig: qat.QatPrivateKeyMethodConfig{
//						PollDelay: &duration.Duration{
//							Seconds: 2,
//						},
//					},
//				},
//			},
//		},
//		{
//			name: "millisecond polldelay",
//			proxy: &model.Proxy{
//				VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
//				Type:             model.Router,
//				Metadata: &model.NodeMetadata{
//					PlatformMetadata: map[string]string{
//						"instance-type": "ecs.g8a.2xlarge",
//					},
//				},
//			},
//			resources: []string{"kubernetes://generic-mtls", "kubernetes://generic-mtls-split"},
//			request: &model.PushRequest{
//				Full: true,
//				ConfigsUpdated: map[model.ConfigKey]struct{}{
//					{Name: "generic-mtls", Namespace: "istio-system", Kind: kind.Secret}:       {},
//					{Name: "generic-mtls-split", Namespace: "istio-system", Kind: kind.Secret}: {},
//				},
//				Push: &model.PushContext{
//					Mesh: &meshconfig.MeshConfig{
//						CryptombConfig: &meshconfig.MeshConfig_CryptombPrivateKeyConfig{
//							EnableCryptomb: true,
//							PoolDelay:      durationpb.New(poolDelay),
//						},
//					},
//				},
//			},
//			expect: map[string]Expected{
//				"kubernetes://generic-mtls": {
//					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
//					PrivateKeyConfig: qat.QatPrivateKeyMethodConfig{
//						PollDelay: durationpb.New(poolDelay),
//					},
//				},
//				"kubernetes://generic-mtls-split": {
//					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
//					PrivateKeyConfig: qat.QatPrivateKeyMethodConfig{
//						PollDelay: durationpb.New(poolDelay),
//					},
//				},
//			},
//		},
//	}
//
//	for _, tt := range cases {
//		t.Run(tt.name, func(t *testing.T) {
//			if tt.proxy.Metadata == nil {
//				tt.proxy.Metadata = &model.NodeMetadata{}
//			}
//			tt.proxy.Metadata.ClusterID = "Kubernetes"
//			s := xds.NewFakeDiscoveryServer(t, xds.FakeOptions{
//				KubernetesObjects: []runtime.Object{genericCert, genericMtlsCert, genericMtlsCertSplit, genericMtlsCertSplitCa},
//			})
//			cc := s.KubeClient().Kube().(*fake.Clientset)
//
//			cc.Fake.Lock()
//			if tt.accessReviewResponse != nil {
//				cc.Fake.PrependReactor("create", "subjectaccessreviews", tt.accessReviewResponse)
//			} else {
//				xds.DisableAuthorizationForSecret(cc)
//			}
//			cc.Fake.Unlock()
//
//			gen := s.Discovery.Generators[v3.SecretType]
//			tt.request.Start = time.Now()
//			secrets, _, _ := gen.Generate(s.SetupProxy(tt.proxy), &model.WatchedResource{ResourceNames: sets.New(tt.resources...)}, tt.request)
//			raw := xdstest.ExtractTLSSecrets(t, model.ResourcesToAny(secrets))
//
//			got := map[string]Expected{}
//			for _, scrt := range raw {
//				log.Infof("secret: %v \n", scrt)
//				t.Logf("typeurl %s \n", scrt.GetTlsCertificate().GetPrivateKeyProvider().GetTypedConfig().TypeUrl)
//				t.Logf("name %s \n", scrt.GetTlsCertificate().GetPrivateKeyProvider().GetProviderName())
//
//				provider := &qat.QatPrivateKeyMethodConfig{}
//				if err := scrt.GetTlsCertificate().GetPrivateKeyProvider().GetTypedConfig().UnmarshalTo(provider); err != nil {
//					t.Fatalf("Failed to unmarsha to privatekeyprivider %v", err)
//				}
//				log.Infof("secret xxx: %v \n", scrt)
//				got[scrt.Name] = Expected{
//					Key:                    string(scrt.GetTlsCertificate().GetPrivateKey().GetInlineBytes()),
//					Cert:                   string(scrt.GetTlsCertificate().GetCertificateChain().GetInlineBytes()),
//					CaCert:                 string(scrt.GetValidationContext().GetTrustedCa().GetInlineBytes()),
//					PrivateName:            scrt.GetTlsCertificate().GetPrivateKeyProvider().GetProviderName(),
//					PrivateProviderTypeUrl: scrt.GetTlsCertificate().GetPrivateKeyProvider().GetTypedConfig().TypeUrl,
//					PrivateKeyConfig:       *provider,
//				}
//
//				if got[scrt.Name].PrivateKeyConfig.PollDelay.AsDuration().String() != tt.expect[scrt.Name].PrivateKeyConfig.PollDelay.AsDuration().String() {
//					t.Fatalf("got %v, want %v", got[scrt.Name].PrivateKeyConfig.PollDelay, tt.expect[scrt.Name].PrivateKeyConfig.PollDelay)
//				}
//			}
//		})
//	}
//}
//
//func TestCryptoMBConfigWithUnsupportedInstanceType(t *testing.T) {
//	type Expected struct {
//		Key                    string
//		Cert                   string
//		CaCert                 string
//		PrivateName            string
//		PrivateProviderTypeUrl string
//		CryptoPrivateKeyConfig cryptomb.CryptoMbPrivateKeyMethodConfig
//	}
//
//	cases := []struct {
//		name                 string
//		proxy                *model.Proxy
//		resources            []string
//		request              *model.PushRequest
//		expect               map[string]Expected
//		accessReviewResponse func(action k8stesting.Action) (bool, runtime.Object, error)
//	}{
//		{
//			name: "second polldelay",
//			proxy: &model.Proxy{
//				VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
//				Type:             model.Router,
//				Metadata: &model.NodeMetadata{
//					PlatformMetadata: map[string]string{
//						"instance-type": "ecs.c9.8xlarge", // unsupported instance type
//					},
//				},
//			},
//			resources: []string{"kubernetes://generic-mtls-split", "kubernetes://generic-mtls"},
//			request: &model.PushRequest{
//				Full: true,
//				ConfigsUpdated: map[model.ConfigKey]struct{}{
//					{Name: "generic-mtls-split", Namespace: "istio-system", Kind: kind.Secret}: {},
//					{Name: "generic-mtls", Namespace: "istio-system", Kind: kind.Secret}:       {},
//				},
//				Push: &model.PushContext{
//					Mesh: &meshconfig.MeshConfig{
//						CryptombConfig: &meshconfig.MeshConfig_CryptombPrivateKeyConfig{
//							EnableCryptomb: true,
//							PoolDelay: &duration.Duration{
//								Seconds: 2,
//							},
//						},
//					},
//				},
//			},
//			expect: map[string]Expected{
//				"kubernetes://generic-mtls-split": {
//					Key:  string(genericCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericCert.Data[credentials.GenericScrtCert]),
//				},
//				"kubernetes://generic-mtls": {
//					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
//				},
//			},
//		},
//		{
//			name: "missing metadata",
//			proxy: &model.Proxy{
//				VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
//				Type:             model.Router,
//				Metadata:         &model.NodeMetadata{},
//			},
//			resources: []string{"kubernetes://generic-mtls-split", "kubernetes://generic-mtls"},
//			request: &model.PushRequest{
//				Full: true,
//				ConfigsUpdated: map[model.ConfigKey]struct{}{
//					{Name: "generic-mtls-split", Namespace: "istio-system", Kind: kind.Secret}: {},
//					{Name: "generic-mtls", Namespace: "istio-system", Kind: kind.Secret}:       {},
//				},
//				Push: &model.PushContext{
//					Mesh: &meshconfig.MeshConfig{
//						CryptombConfig: &meshconfig.MeshConfig_CryptombPrivateKeyConfig{
//							EnableCryptomb: true,
//							PoolDelay: &duration.Duration{
//								Seconds: 2,
//							},
//						},
//					},
//				},
//			},
//			expect: map[string]Expected{
//				"kubernetes://generic-mtls-split": {
//					Key:  string(genericCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericCert.Data[credentials.GenericScrtCert]),
//				},
//				"kubernetes://generic-mtls": {
//					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
//				},
//			},
//		},
//		{
//			name: "wrong cpu",
//			proxy: &model.Proxy{
//				VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
//				Type:             model.Router,
//				Metadata: &model.NodeMetadata{
//					PlatformMetadata: map[string]string{
//						cpuInfo: "Intel Xeon(Ice Lake) Platinum 8369Bxxx",
//					},
//				},
//			},
//			resources: []string{"kubernetes://generic-mtls-split", "kubernetes://generic-mtls"},
//			request: &model.PushRequest{
//				Full: true,
//				ConfigsUpdated: map[model.ConfigKey]struct{}{
//					{Name: "generic-mtls-split", Namespace: "istio-system", Kind: kind.Secret}: {},
//					{Name: "generic-mtls", Namespace: "istio-system", Kind: kind.Secret}:       {},
//				},
//				Push: &model.PushContext{
//					Mesh: &meshconfig.MeshConfig{
//						CryptombConfig: &meshconfig.MeshConfig_CryptombPrivateKeyConfig{
//							EnableCryptomb: true,
//							PoolDelay: &duration.Duration{
//								Seconds: 2,
//							},
//						},
//					},
//				},
//			},
//			expect: map[string]Expected{
//				"kubernetes://generic-mtls-split": {
//					Key:  string(genericCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericCert.Data[credentials.GenericScrtCert]),
//				},
//				"kubernetes://generic-mtls": {
//					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
//				},
//			},
//		},
//		{
//			name: "wrong cpu",
//			proxy: &model.Proxy{
//				VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
//				Type:             model.Router,
//				Metadata: &model.NodeMetadata{
//					PlatformMetadata: map[string]string{
//						cpuInfo: "xxx",
//					},
//				},
//			},
//			resources: []string{"kubernetes://generic-mtls-split", "kubernetes://generic-mtls"},
//			request: &model.PushRequest{
//				Full: true,
//				ConfigsUpdated: map[model.ConfigKey]struct{}{
//					{Name: "generic-mtls-split", Namespace: "istio-system", Kind: kind.Secret}: {},
//					{Name: "generic-mtls", Namespace: "istio-system", Kind: kind.Secret}:       {},
//				},
//				Push: &model.PushContext{
//					Mesh: &meshconfig.MeshConfig{
//						CryptombConfig: &meshconfig.MeshConfig_CryptombPrivateKeyConfig{
//							EnableCryptomb: true,
//							PoolDelay: &duration.Duration{
//								Seconds: 2,
//							},
//						},
//					},
//				},
//			},
//			expect: map[string]Expected{
//				"kubernetes://generic-mtls-split": {
//					Key:  string(genericCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericCert.Data[credentials.GenericScrtCert]),
//				},
//				"kubernetes://generic-mtls": {
//					Key:  string(genericMtlsCert.Data[credentials.GenericScrtKey]),
//					Cert: string(genericMtlsCert.Data[credentials.GenericScrtCert]),
//				},
//			},
//		},
//	}
//
//	for _, tt := range cases {
//		t.Run(tt.name, func(t *testing.T) {
//			if tt.proxy.Metadata == nil {
//				tt.proxy.Metadata = &model.NodeMetadata{}
//			}
//			tt.proxy.Metadata.ClusterID = "Kubernetes"
//			s := xds.NewFakeDiscoveryServer(t, xds.FakeOptions{
//				KubernetesObjects: []runtime.Object{genericCert, genericMtlsCert, genericMtlsCertSplit, genericMtlsCertSplitCa},
//			})
//			cc := s.KubeClient().Kube().(*fake.Clientset)
//
//			cc.Fake.Lock()
//			if tt.accessReviewResponse != nil {
//				cc.Fake.PrependReactor("create", "subjectaccessreviews", tt.accessReviewResponse)
//			} else {
//				xds.DisableAuthorizationForSecret(cc)
//			}
//			cc.Fake.Unlock()
//
//			gen := s.Discovery.Generators[v3.SecretType]
//			tt.request.Start = time.Now()
//			secrets, _, _ := gen.Generate(s.SetupProxy(tt.proxy), &model.WatchedResource{ResourceNames: sets.New(tt.resources...)}, tt.request)
//			raw := xdstest.ExtractTLSSecrets(t, model.ResourcesToAny(secrets))
//
//			for _, scrt := range raw {
//				log.Infof("secret: %v \n", scrt)
//
//				if scrt.GetTlsCertificate().GetPrivateKeyProvider() != nil {
//					t.Fatalf("expected empty private key config, got %v", scrt.GetTlsCertificate().GetPrivateKeyProvider())
//				}
//			}
//		})
//	}
//}
//
//var (
//	istiosystemNode1 = &model.Proxy{
//		ID: "1",
//		Metadata: &model.NodeMetadata{
//			ClusterID: "Kubernetes",
//			PlatformMetadata: map[string]string{
//				"instance-type": "ecs.c7.8xlarge", // unsupported instance type
//			},
//		},
//		VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
//		Type:             model.Router,
//		ConfigNamespace:  "istio-system",
//	}
//	istiosystemNode2 = &model.Proxy{
//		ID: "2",
//		Metadata: &model.NodeMetadata{
//			ClusterID: "Kubernetes",
//			PlatformMetadata: map[string]string{
//				"instance-type": "ecs.c8a.8xlarge", // unsupported instance type
//			},
//		},
//		VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
//		Type:             model.Router,
//		ConfigNamespace:  "istio-system",
//	}
//	istiosystemNode3 = &model.Proxy{
//		ID: "3",
//		Metadata: &model.NodeMetadata{
//			ClusterID: "Kubernetes",
//			PlatformMetadata: map[string]string{
//				"instance-type": "x.y.z", // unsupported instance type
//			},
//		},
//		VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
//		Type:             model.Router,
//		ConfigNamespace:  "istio-system",
//	}
//	istiosystemNode4 = &model.Proxy{
//		ID: "4",
//		Metadata: &model.NodeMetadata{
//			ClusterID: "Kubernetes",
//		},
//		VerifiedIdentity: &spiffe.Identity{Namespace: "istio-system"},
//		Type:             model.Router,
//		ConfigNamespace:  "istio-system",
//	}
//)
//
//func TestCachingWithEmptyKeyProvider(t *testing.T) {
//	s := xds.NewFakeDiscoveryServer(t, xds.FakeOptions{
//		KubernetesObjects: []runtime.Object{genericCert},
//		KubeClientModifier: func(c kube.Client) {
//			cc := c.Kube().(*fake.Clientset)
//			xds.DisableAuthorizationForSecret(cc)
//		},
//	})
//	gen := s.Discovery.Generators[v3.SecretType]
//
//	fullPush := &model.PushRequest{
//		Full:  true,
//		Start: time.Now(),
//	}
//
//	// node1
//	secrets, logDetail, _ := gen.Generate(s.SetupProxy(istiosystemNode1), &model.WatchedResource{ResourceNames: sets.New("kubernetes://generic")}, fullPush)
//	raw := xdstest.ExtractTLSSecrets(t, model.ResourcesToAny(secrets))
//	if len(raw) != 1 {
//		t.Fatalf("failed to get expected secrets for authorized proxy: %v", raw)
//	}
//	if logDetail.AdditionalInfo != "cached:0/1" {
//		t.Fatal("should cache")
//	}
//	for _, secret := range raw {
//		if secret.GetTlsCertificate().GetPrivateKeyProvider() != nil {
//			t.Fatal("should not use private key provider")
//		}
//	}
//
//	// node2
//	secrets, logDetail, _ = gen.Generate(s.SetupProxy(istiosystemNode2), &model.WatchedResource{ResourceNames: sets.New("kubernetes://generic")}, fullPush)
//	raw = xdstest.ExtractTLSSecrets(t, model.ResourcesToAny(secrets))
//	if len(raw) != 1 {
//		t.Fatalf("failed to get expected secrets for authorized proxy: %v", raw)
//	}
//	if logDetail.AdditionalInfo != "cached:1/1" {
//		t.Fatal("should cache")
//	}
//	for _, secret := range raw {
//		if secret.GetTlsCertificate().GetPrivateKeyProvider() != nil {
//			t.Fatal("should not use private key provider")
//		}
//	}
//
//	// node3
//	secrets, logDetail, _ = gen.Generate(s.SetupProxy(istiosystemNode3), &model.WatchedResource{ResourceNames: sets.New("kubernetes://generic")}, fullPush)
//	raw = xdstest.ExtractTLSSecrets(t, model.ResourcesToAny(secrets))
//	if len(raw) != 1 {
//		t.Fatalf("failed to get expected secrets for authorized proxy: %v", raw)
//	}
//	if logDetail.AdditionalInfo != "cached:1/1" {
//		t.Fatal("should cache")
//	}
//	for _, secret := range raw {
//		if secret.GetTlsCertificate().GetPrivateKeyProvider() != nil {
//			t.Fatal("should not use private key provider")
//		}
//	}
//
//	// node4
//	secrets, logDetail, _ = gen.Generate(s.SetupProxy(istiosystemNode4), &model.WatchedResource{ResourceNames: sets.New("kubernetes://generic")}, fullPush)
//	raw = xdstest.ExtractTLSSecrets(t, model.ResourcesToAny(secrets))
//	if len(raw) != 1 {
//		t.Fatalf("failed to get expected secrets for authorized proxy: %v", raw)
//	}
//	if logDetail.AdditionalInfo != "cached:1/1" {
//		t.Fatal("should cache")
//	}
//	for _, secret := range raw {
//		if secret.GetTlsCertificate().GetPrivateKeyProvider() != nil {
//			t.Fatal("should not use private key provider")
//		}
//	}
//}
//
//func TestCachingWithKeyProvider(t *testing.T) {
//	s := xds.NewFakeDiscoveryServer(t, xds.FakeOptions{
//		KubernetesObjects: []runtime.Object{genericCert},
//		KubeClientModifier: func(c kube.Client) {
//			cc := c.Kube().(*fake.Clientset)
//			xds.DisableAuthorizationForSecret(cc)
//		},
//	})
//	gen := s.Discovery.Generators[v3.SecretType]
//
//	fullPush := &model.PushRequest{
//		Full:  true,
//		Start: time.Now(),
//		Push: &model.PushContext{
//			Mesh: &meshconfig.MeshConfig{
//				CryptombConfig: &meshconfig.MeshConfig_CryptombPrivateKeyConfig{
//					EnableCryptomb: true,
//					PoolDelay: &duration.Duration{
//						Seconds: 2,
//					},
//				},
//			},
//		},
//	}
//
//	// node1
//	secrets, logDetail, _ := gen.Generate(s.SetupProxy(istiosystemNode1), &model.WatchedResource{ResourceNames: sets.New("kubernetes://generic")}, fullPush)
//	raw := xdstest.ExtractTLSSecrets(t, model.ResourcesToAny(secrets))
//	if len(raw) != 1 {
//		t.Fatalf("failed to get expected secrets for authorized proxy: %v", raw)
//	}
//	if logDetail.AdditionalInfo != "cached:0/1" {
//		t.Fatal("should not cache")
//	}
//	for _, secret := range raw {
//		if secret.GetTlsCertificate().GetPrivateKeyProvider().GetProviderName() != CryptoMbPrivateKeyProviderType.String() {
//			t.Fatal("should use cry rivate key provider")
//		}
//	}
//
//	// node2
//	secrets, logDetail, _ = gen.Generate(s.SetupProxy(istiosystemNode2), &model.WatchedResource{ResourceNames: sets.New("kubernetes://generic")}, fullPush)
//	raw = xdstest.ExtractTLSSecrets(t, model.ResourcesToAny(secrets))
//	if len(raw) != 1 {
//		t.Fatalf("failed to get expected secrets for authorized proxy: %v", raw)
//	}
//	if logDetail.AdditionalInfo != "cached:0/1" {
//		t.Fatal("should not cache")
//	}
//	for _, secret := range raw {
//		if secret.GetTlsCertificate().GetPrivateKeyProvider().GetProviderName() != QATPrivateKeyProviderType.String() {
//			t.Fatal("should use qat private key provider")
//		}
//	}
//
//	// node3
//	secrets, logDetail, _ = gen.Generate(s.SetupProxy(istiosystemNode3), &model.WatchedResource{ResourceNames: sets.New("kubernetes://generic")}, fullPush)
//	raw = xdstest.ExtractTLSSecrets(t, model.ResourcesToAny(secrets))
//	if len(raw) != 1 {
//		t.Fatalf("failed to get expected secrets for authorized proxy: %v", raw)
//	}
//	if logDetail.AdditionalInfo != "cached:0/1" {
//		t.Fatal("should not cache")
//	}
//	for _, secret := range raw {
//		if secret.GetTlsCertificate().GetPrivateKeyProvider() != nil {
//			t.Fatal("should not use key provider")
//		}
//	}
//
//	// node3
//	secrets, logDetail, _ = gen.Generate(s.SetupProxy(istiosystemNode4), &model.WatchedResource{ResourceNames: sets.New("kubernetes://generic")}, fullPush)
//	raw = xdstest.ExtractTLSSecrets(t, model.ResourcesToAny(secrets))
//	if len(raw) != 1 {
//		t.Fatalf("failed to get expected secrets for authorized proxy: %v", raw)
//	}
//	if logDetail.AdditionalInfo != "cached:1/1" {
//		t.Fatal("should cache")
//	}
//	for _, secret := range raw {
//		if secret.GetTlsCertificate().GetPrivateKeyProvider() != nil {
//			t.Fatal("should not use private key provider")
//		}
//	}
//}
