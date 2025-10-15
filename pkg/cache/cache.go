// Copyright 2017 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cache provides general-purpose in-memory caches.
// Different caches provide different eviction policies suitable for
// specific use cases.
package cache

import (
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	anypb "github.com/golang/protobuf/ptypes/any"
	"istio.io/istio/pkg/log"
)

var XdsCache = log.RegisterScope("xds-cache", "Xds entire cache.")

type XdsResourceCache interface {
	// Initialize try to load cache without returning error
	Initialize()

	// Load xds resource base on the discovery request.
	Load(req *discovery.DiscoveryRequest) (*discovery.DiscoveryResponse, error)

	// Add xds resource into memory but not store, we should wait an ack to
	// make sure these resources are valid and accepted by envoy.
	Add(resp *discovery.DiscoveryResponse) error

	// Store xds resource into store base on the ack discovery request.
	// Caller should make sure this discovery request is ack request.
	Store(req *discovery.DiscoveryRequest) error

	// GetLatestXdsResource get latest xds resource in memory.
	GetLatestXdsResource() []*anypb.Any
}
