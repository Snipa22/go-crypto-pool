// Copyright and license: see repository LICENSE (MIT).
package leaflib

import "testing"

func TestIsHTTPConnectProbe(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "real CONNECT probe",
			line: "CONNECT example.com:443 HTTP/1.1\r\n",
			want: true,
		},
		{
			name: "lowercase connect probe",
			line: "connect example.com:443 HTTP/1.1\r\n",
			want: true,
		},
		{
			name: "mixed-case Connect probe",
			line: "CoNnEcT example.com:443 HTTP/1.1",
			want: true,
		},
		{
			name: "leading whitespace before CONNECT",
			line: "   CONNECT example.com:443 HTTP/1.1",
			want: true,
		},
		{
			name: "substring connect elsewhere must NOT match",
			line: `{"method":"connect","params":{}}`,
			want: false,
		},
		{
			name: "word connect appearing later in the line must NOT match",
			line: "please connect me to the pool",
			want: false,
		},
		{
			name: "ordinary valid stratum login line",
			line: `{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"addr","pass":"x"}}`,
			want: false,
		},
		{
			name: "ordinary valid stratum submit line",
			line: `{"id":2,"jsonrpc":"2.0","method":"submit","params":{"job_id":"1","nonce":"abcd1234","result":"deadbeef"}}`,
			want: false,
		},
		{
			name: "ordinary valid stratum keepalived line",
			line: `{"id":3,"jsonrpc":"2.0","method":"keepalived"}`,
			want: false,
		},
		{
			name: "empty line",
			line: "",
			want: false,
		},
		{
			name: "whitespace-only line",
			line: "   \t  ",
			want: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsHTTPConnectProbe(tc.line); got != tc.want {
				t.Errorf("IsHTTPConnectProbe(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
}
