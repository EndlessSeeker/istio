package mseingress

import (
	lrlhttppb "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/local_ratelimit/v3"
	rbachttppb "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	httppb "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"istio.io/istio/pilot/pkg/model"
	mseingress2 "istio.io/istio/pilot/pkg/networking/core/mseingress"
	"istio.io/istio/pilot/pkg/util/protoconv"
)

var (
	DefaultRBACFilter = &httppb.HttpFilter{
		Name: wellknown.HTTPRoleBasedAccessControl,
		ConfigType: &httppb.HttpFilter_TypedConfig{
			TypedConfig: protoconv.MessageToAny(&rbachttppb.RBAC{}),
		},
	}

	GlobalLocalRateLimitFilter = &httppb.HttpFilter{
		Name: mseingress2.LocalRateLimitFilterName,
		ConfigType: &httppb.HttpFilter_TypedConfig{
			TypedConfig: protoconv.MessageToAny(&lrlhttppb.LocalRateLimit{
				StatPrefix: mseingress2.DefaultLocalRateLimitStatPrefix,
			}),
		},
	}
)

type Builder struct {
	push  *model.PushContext
	proxy *model.Proxy
}

func NewBuilder(push *model.PushContext, proxy *model.Proxy) *Builder {
	return &Builder{
		push:  push,
		proxy: proxy,
	}
}

func (b *Builder) BuildHTTPFilters(cur []*httppb.HttpFilter) []*httppb.HttpFilter {
	if b == nil {
		return nil
	}
	if b.proxy.Type != model.Router {
		return nil
	}

	var result []*httppb.HttpFilter
	if filter := b.addRBACFilterWithNeed(cur); filter != nil {
		result = append(result, filter)
	}
	if filter := b.addLocalRateLimitWithNeed(cur); filter != nil {
		result = append(result, filter)
	}
	return result
}

func (b *Builder) addRBACFilterWithNeed(cur []*httppb.HttpFilter) *httppb.HttpFilter {
	hasRBAC := false
	httpFilters := b.push.GetHTTPFiltersFromEnvoyFilter(b.proxy)
	for _, filter := range httpFilters {
		if mseingress2.HasRBACFilter(filter) {
			hasRBAC = true
			break
		}
	}
	if hasRBAC {
		return nil
	}

	for _, filter := range cur {
		if filter.Name == wellknown.HTTPRoleBasedAccessControl {
			hasRBAC = true
			break
		}
	}

	if hasRBAC {
		return nil
	}

	return DefaultRBACFilter
}

func (b *Builder) addLocalRateLimitWithNeed(cur []*httppb.HttpFilter) *httppb.HttpFilter {
	hasLocalRateLimit := false
	httpFilters := b.push.GetHTTPFiltersFromEnvoyFilter(b.proxy)
	for _, filter := range httpFilters {
		if mseingress2.GetLocalRateLimitFilter(filter) != nil {
			hasLocalRateLimit = true
			break
		}
	}
	if hasLocalRateLimit {
		return nil
	}

	for _, filter := range cur {
		if filter.Name == mseingress2.LocalRateLimitFilterName {
			hasLocalRateLimit = true
			break
		}
	}

	if hasLocalRateLimit {
		return nil
	}

	return GlobalLocalRateLimitFilter
}
