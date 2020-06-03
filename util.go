package aws4

import (
	"net/http"
	"strings"

	"github.com/allaboutapps/aws4/pkg/util"
)

// AccessKeyIDFromRequest attempts to retrieve the access key ID used for signing the request,
// checking for a presigned query parameter first before trying to parse a signed Authorization header.
//
// If no credentials are found or they appear malformed, an empty string is returned.
func AccessKeyIDFromRequest(req *http.Request) string {
	cred := req.URL.Query().Get("X-Amz-Credential")
	if len(cred) == 0 {
		authParts := strings.Split(req.Header.Get("Authorization"), ", ")
		if len(authParts) != authHeaderPartsLen {
			return ""
		}

		c := authParts[0][len(util.Algorithm)+1:]
		if !strings.HasPrefix(c, "Credential=") {
			return ""
		}

		cred = strings.TrimPrefix(c, "Credential=")
	}

	credParts := strings.Split(cred, "/")
	if len(credParts) != credentialPartsLen {
		return ""
	}

	if credParts[4] != util.RequestTypeAWS4 {
		return ""
	}

	return credParts[0]
}
