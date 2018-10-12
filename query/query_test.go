// Copyright 2014 Google Inc. All rights reserved.
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

package query

import (
	"testing"
        "time"
)

func TestParsingValidQueries(t *testing.T) {
	for _, test := range []string{
		"net 1.2.3.4/8",
		"net 1.2.3.4 mask 255.255.254.0",
		"host 1.2.3.4",
		"port 80",
		"ip proto 6",
		"tcp",
		"udp",
		"icmp",
		"before 45m ago",
		"after 3h ago",
		"after 2015-01-01T13:14:15Z",
		"before 2015-01-01T13:14:15+01:00",
		"host 1.2.3.4 and port 255",
		"(port 80 or (host 1.2.3.4 and tcp) or port 7)",
		"udp and port 514 or tcp and port 80",
		"(udp && port 514) or (tcp and port 80)",
		"(port 80 && after 2015-01-01T13:14:15Z) || (host 1.2.3.4 && before 2015-01-01T13:14:15Z)",
		"between 2018-01-01T12:00:00Z and 2018-01-01T13:00:00Z",
		"between 3h ago and 2h ago",
	} {
		if q, start, stop, err := NewQuery(test); err != nil {
			t.Fatalf("could not parse valid query %q: %v", test, err)
		} else {
			t.Log(q)
			t.Log(start)
			t.Log(stop)
                        start2, stop2 := q.GetTimeSpan(time.Time{}, time.Time{})
                        t.Log(start2)
                        t.Log(stop2)
		}
	}
}

func TestParsingInvalidQuery(t *testing.T) {
	for _, test := range []string{
		"host 1.2.3",
		"net 1.2.3.4/44",
		"port 8 and port 77777",
		"port 77777 and port 8",
		"protocol -1",
		"protocol 256",
		"last 4",
		"between 2h ago and 3h ago",
		"between 2018-01-01T13:00:00Z and 2018-01-01T12:00:00Z",
	} {
		if q, _, _, err := NewQuery(test); err == nil {
			t.Fatalf("parsed invalid query %q: %v", test, q)
		} else {
			t.Log(err)
		}
	}
}
