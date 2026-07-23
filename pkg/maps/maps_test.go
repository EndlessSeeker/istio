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

package maps

import (
	"testing"

	"istio.io/istio/pkg/test/util/assert"
)

func TestMergeCopy(t *testing.T) {
	base := map[string]int{"base": 1, "shared": 1}
	override := map[string]int{"override": 2, "shared": 2}

	got := MergeCopy(base, override)

	assert.Equal(t, got, map[string]int{"base": 1, "override": 2, "shared": 2})
	assert.Equal(t, base, map[string]int{"base": 1, "shared": 1})
	assert.Equal(t, override, map[string]int{"override": 2, "shared": 2})
}
