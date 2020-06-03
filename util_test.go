package aws4

import (
	"net/http"
	"testing"
)

func TestAccessKeyIDFromRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		url        string
		auth       string
		expectedID string
	}{
		{
			name:       "Presigned",
			url:        "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fiam%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=60&X-Amz-SignedHeaders=content-type%3Bhost%3Bx-amz-date&X-Amz-Signature=63613d9c6a68b0e499ed9beeeabe0c4f3295742554209d6f109fe3c9563f56c3",
			expectedID: "AKIDEXAMPLE",
		},
		{
			name:       "Presigned_malformed_len",
			url:        "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=60&X-Amz-SignedHeaders=content-type%3Bhost%3Bx-amz-date&X-Amz-Signature=63613d9c6a68b0e499ed9beeeabe0c4f3295742554209d6f109fe3c9563f56c3",
			expectedID: "",
		},
		{
			name:       "Presigned_malformed_request_type",
			url:        "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fiam%2Faws3_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=60&X-Amz-SignedHeaders=content-type%3Bhost%3Bx-amz-date&X-Amz-Signature=63613d9c6a68b0e499ed9beeeabe0c4f3295742554209d6f109fe3c9563f56c3",
			expectedID: "",
		},
		{
			name:       "Signed",
			url:        "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
			auth:       "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
			expectedID: "AKIDEXAMPLE",
		},
		{
			name:       "Signed_malformed_auth_len",
			url:        "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
			auth:       "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
			expectedID: "",
		},
		{
			name:       "Signed_malformed_cred_len",
			url:        "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
			auth:       "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
			expectedID: "",
		},
		{
			name:       "Signed_malformed_cred_prefix",
			url:        "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
			auth:       "AWS4-HMAC-SHA256 AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
			expectedID: "",
		},
		{
			name:       "Signed_malformed_request_type",
			url:        "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
			auth:       "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws3_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
			expectedID: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req, err := http.NewRequest("GET", tt.url, nil)
			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if len(tt.auth) > 0 {
				req.Header.Set("Authorization", tt.auth)
			}

			if e, g := tt.expectedID, AccessKeyIDFromRequest(req); e != g {
				t.Errorf("%s: expected %q, got %q", tt.name, e, g)
			}
		})
	}
}
