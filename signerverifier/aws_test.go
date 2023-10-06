package signerverifier

import (
	"context"
	"crypto"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/secure-systems-lab/go-securesystemslib/signerverifier/aws_mock"
)

/*
This is an integration test.
It does require a connection to AWS and existing KMS keys.
See test cases for which key aliases are required.
*/
// func TestSignVerify(t *testing.T) {
// 	cases := []struct {
// 		aws_key_id   string
// 		payload_type string
// 		payload      []byte
// 	}{
// 		{"alias/in-toto-rsa-2048", "application/vnd.in-toto+json", []byte("This is test data")},
// 		{"alias/in-toto-rsa-3072", "application/vnd.in-toto+json", []byte("Even more test data")},
// 		{"alias/in-toto-rsa-4096", "application/vnd.in-toto+json", []byte("Even more test data")},
// 		{"alias/in-toto-ecc-nist-p256", "application/vnd.in-toto+json", []byte("Even more test data")},
// 		{"alias/in-toto-ecc-nist-p384", "application/vnd.in-toto+json", []byte("Even more test data")},
// 		{"alias/in-toto-ecc-nist-p512", "application/vnd.in-toto+json", []byte("Even more test data")},
// 	}

// 	cfg, err := config.LoadDefaultConfig(context.TODO())
// 	if err != nil {
// 		t.Errorf(err.Error())
// 	}

// 	kms := kms.NewFromConfig(cfg)

// 	for _, value := range cases {
// 		signer, _ := NewAwsSignerVerifier(kms, value.aws_key_id)

// 		envelope_signer, err := dsse.NewEnvelopeSigner(signer)
// 		if err != nil {
// 			t.Errorf(err.Error())
// 		}

// 		envelope, err := envelope_signer.SignPayload(context.TODO(), value.payload_type, value.payload)
// 		if err != nil {
// 			t.Errorf(err.Error())
// 		}

// 		verifier, err := dsse.NewEnvelopeVerifier(signer)
// 		if err != nil {
// 			t.Errorf(err.Error())
// 		}

// 		_, err = verifier.Verify(context.TODO(), envelope)
// 		if err != nil {
// 			t.Errorf(err.Error())
// 		}
// 	}
// }

/*
This test doesn't do very much at the moment
Because our mock always returns true the pass data isn't relevant for this test
Possibly remove this test and instead rely on the more helpful TestSignVerify
*/
func TestVerify(t *testing.T) {
	cases := []struct {
		aws_key_id   string
		payload_type string
		payload      []byte
		signature    []byte
	}{
		{"alias/in-toto", "application/vnd.in-toto+json", []byte("This is test data"), []byte("signature")},
	}

	mock_kms := aws_mock.MockKmsAPI{}

	for _, value := range cases {
		signer, _ := NewAwsSignerVerifier(mock_kms, value.aws_key_id)

		err := signer.Verify(context.TODO(), value.payload, value.signature)
		if err != nil {
			t.Error(err.Error())
		}
	}
}

func TestGetSigningConfig(t *testing.T) {
	cases := []struct {
		key_spec        types.KeySpec
		expected_output *awsSigningConfig
	}{
		{types.KeySpecRsa2048, &awsSigningConfig{types.SigningAlgorithmSpecRsassaPssSha256, "rsa", "rsassa-pss-sha256", crypto.SHA256}},
	}

	for _, value := range cases {
		result, err := getSigningConfig(value.key_spec)
		if err != nil {
			t.Errorf("error should be nil, got %q", err)
		}

		if !reflect.DeepEqual(result, value.expected_output) {
			t.Errorf("got %v, expected %v", result, value.expected_output)
		}
	}
}

func TestErrorGetSigningConfig(t *testing.T) {
	cases := []struct {
		key_spec        types.KeySpec
		expected_output string
	}{
		{types.KeySpecSm2, "failed to determine signing config"},
	}

	for _, value := range cases {
		_, err := getSigningConfig(value.key_spec)
		if err.Error() != value.expected_output {
			t.Errorf("got %v, expected %v", err.Error(), value.expected_output)
		}
	}
}
