package credentials

import (
	"fmt"
	"time"

	"github.com/allaboutapps/aws4/pkg/util"
)

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	ProviderName    string
}

func (c Credentials) DeriveSigningKey(t time.Time, region string, service string) []byte {
	kDate := util.HMACSHA256([]byte(fmt.Sprintf("AWS4%s", c.SecretAccessKey)), []byte(t.Format("20060102")))
	kRegion := util.HMACSHA256(kDate, []byte(region))
	kService := util.HMACSHA256(kRegion, []byte(service))
	kSigning := util.HMACSHA256(kService, []byte(util.RequestTypeAWS4))
	return kSigning
}
