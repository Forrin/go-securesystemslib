package signerverifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

var awsSigningConfigMap = map[types.KeySpec]awsSigningConfig{
	types.KeySpecRsa2048:     {types.SigningAlgorithmSpecRsassaPssSha256, "rsa", "rsassa-pss-sha256", crypto.SHA256},
	types.KeySpecRsa3072:     {types.SigningAlgorithmSpecRsassaPssSha384, "rsa", "rsassa-pss-sha384", crypto.SHA384},
	types.KeySpecRsa4096:     {types.SigningAlgorithmSpecRsassaPssSha512, "rsa", "rsassa-pss-sha512", crypto.SHA512},
	types.KeySpecEccNistP256: {types.SigningAlgorithmSpecEcdsaSha256, "ecdsa", "ecdsa-sha2-nistp246", crypto.SHA256},
	types.KeySpecEccNistP384: {types.SigningAlgorithmSpecEcdsaSha384, "ecdsa", "ecdsa-sha2-nistp384", crypto.SHA384},
	types.KeySpecEccNistP521: {types.SigningAlgorithmSpecEcdsaSha512, "ecdsa", "ecdsa-sha2-nistp512", crypto.SHA512},
}

type awsSigningConfig struct {
	aws_algorithm        types.SigningAlgorithmSpec
	key_type             string
	key_scheme           string
	key_id_hash_function crypto.Hash
}

type kmsAPI interface {
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error)
}

type AwsSignerVerifier struct {
	client        kmsAPI
	keyID         string
	awsKeyID      string
	publicKey     crypto.PublicKey
	signingConfig *awsSigningConfig
}

func NewAwsSignerVerifier(client kmsAPI, aws_key_id string) (dsse.SignerVerifier, error) {
	input := &kms.GetPublicKeyInput{
		KeyId: aws.String(aws_key_id),
	}

	pk_result, err := client.GetPublicKey(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	signing_config, err := getSigningConfig(pk_result.KeySpec)
	if err != nil {
		return nil, err
	}

	key, err := getKeyId(pk_result.PublicKey, signing_config.key_type, signing_config.key_scheme)
	if err != nil {
		return nil, err
	}

	public_key, err := x509.ParsePKIXPublicKey(pk_result.PublicKey)
	if err != nil {
		return nil, err
	}

	signer := AwsSignerVerifier{
		client:        client,
		keyID:         key.KeyID,
		awsKeyID:      aws_key_id,
		publicKey:     public_key,
		signingConfig: signing_config,
	}

	return &signer, nil
}

func (sv *AwsSignerVerifier) Sign(ctx context.Context, data []byte) ([]byte, error) {
	digest, err := getDigest(data, sv.signingConfig.key_id_hash_function)
	if err != nil {
		return nil, err
	}

	input := &kms.SignInput{
		KeyId:            aws.String(sv.awsKeyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: sv.signingConfig.aws_algorithm,
	}

	result, err := sv.client.Sign(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	return result.Signature, nil
}

func (sv *AwsSignerVerifier) KeyID() (string, error) {
	return sv.keyID, nil
}

func (sv *AwsSignerVerifier) Verify(ctx context.Context, data, signature []byte) error {
	digest, err := getDigest(data, sv.signingConfig.key_id_hash_function)
	if err != nil {
		return err
	}

	input := &kms.VerifyInput{
		KeyId:            aws.String(sv.awsKeyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		Signature:        signature,
		SigningAlgorithm: sv.signingConfig.aws_algorithm,
	}

	_, err = sv.client.Verify(context.TODO(), input)
	if err != nil {
		return err
	}

	return nil
}

func (sv *AwsSignerVerifier) Public() crypto.PublicKey {
	return sv.publicKey
}

func getSigningConfig(key_spec types.KeySpec) (*awsSigningConfig, error) {
	config, exists := awsSigningConfigMap[key_spec]
	if exists {
		return &config, nil
	}

	return nil, errors.New("failed to determine signing config")
}

/*
Get key ID from pubKeyBytes

pubKeyBytes is PXIX, ASN.1 DER form
*/
func getKeyId(pubKeyBytes []byte, key_type string, key_scheme string) (*SSLibKey, error) {
	key := &SSLibKey{
		KeyType:             key_type,
		Scheme:              key_scheme,
		KeyIDHashAlgorithms: KeyIDHashAlgorithms,
		KeyVal:              KeyVal{},
	}

	key.KeyVal.Public = strings.TrimSpace(string(generatePEMBlock(pubKeyBytes, PublicKeyPEM)))

	if len(key.KeyID) == 0 {
		keyID, err := calculateKeyID(key)
		if err != nil {
			return nil, fmt.Errorf("unable to calculate aws key: %w", err)
		}

		key.KeyID = keyID
	}

	return key, nil
}
