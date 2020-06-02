// Package aws4 allows for signing requests and verifying signatures using AWS Signature Version 4.
//
// Signing follows the Signature Version 4 format as specified by AWS in the AWS General Reference, section
// Signing AWS requests: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html (2020-06-02T09:07:55+00:00).
// The official AWS SDK for Go was consulted for compatibility and implementation details:
// https://docs.aws.amazon.com/sdk-for-go/api/aws/signer/v4/ (2020-06-02T09:07:55+00:00).
//
// Verification of signatures compatible with AWS Signature Version 4 has been added as well.
package aws4
