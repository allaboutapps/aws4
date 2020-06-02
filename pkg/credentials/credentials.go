package credentials

import (
	"fmt"
	"time"

	"github.com/allaboutapps/aws4/pkg/util"
)

// Credentials represents a set of credentials consisting of an access key ID and
// its corresponding secret as well as an optional session token.
type Credentials struct {
	// AWS Access Key ID
	AccessKeyID string
	// AWS Secret Access Key
	SecretAccessKey string
	// AWS Session Token
	SessionToken string
	// Name of provider used to retrieve credentials
	ProviderName string
}

// DeriveSigningKey derives a HMAC signing key from the credentials in accordance
// with the AWS Signature Version 4 specification using the signing time as well as
// the region and service of the request.
func (c Credentials) DeriveSigningKey(t time.Time, region string, service string) []byte {
	kDate := util.HMACSHA256([]byte(fmt.Sprintf("AWS4%s", c.SecretAccessKey)), []byte(util.FormatDate(t)))
	kRegion := util.HMACSHA256(kDate, []byte(region))
	kService := util.HMACSHA256(kRegion, []byte(service))
	kSigning := util.HMACSHA256(kService, []byte(util.RequestTypeAWS4))
	return kSigning
}
