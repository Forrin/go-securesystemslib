package aws_mock

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type MockKmsAPI struct {
}

func (m MockKmsAPI) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if *params.KeyId == "" {
		return nil, errors.New("expect key id to not be blank")
	}

	public_key := "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6+0Z0GsKeV/j9ZCbdn/KXevKByeAY1qsRJOxGht49SpTtXhbcSgl/zH46AUT3eQ5BRuEMZQdQbp8f9q17LMhG+K10fTl/AZxrSHd11siVN9NxYYlL2BjOzVT95oRWXWrXGwwAt417tc3W9Sk3+65KD6m8vnPqchRGiYlVQ4LnQIhA347w1kVvWVruj/iJ7/xC3hQy1rHv7qxTjn5P6adzP+zzUl5KmuuGW87cGJ/sMBglJbJECfZfR2XgadMMHTXtgtnGGvSBQ3EB68gRmWIy1mSrYoaylZDbFda9bHsTGL20M7MKakNVxhbfV3UMsf2cle6KWMBqOKiujuxXjBCx+5xt2vlQ4nEQJ/GKPU7byUu6QZMdmsZbv5utoTe2g/MCNAWSZDRJ7Ll9PJLfxFNihOt3WcuQDTmh6lcf7G+ObXWIbecVCk8L09OvLZ7XMg1OmfaA7TPIbFZPw8n0/EJsXl+zItExiyfLxHpsDukk+jCl/q/Li69LTHwAqqqnVAP/UwgvkvvggJ3xOO5t+A3FCKX3U8rYhegOeGxyNYpN93rZEcNHpcW3pSFj16WtQzO8lohpfZcpr3PSzzlopdVUvvuOpd56E3U8ngVJ5l4NtOkFpbw3zGn/XJR/9C9yvXNwiuwYsJec1T1MKkBp97JQJsd5y4L9ovoboP/ilWMLZUCAwEAAQ=="

	public_key_bytes, err := base64.StdEncoding.DecodeString(public_key)
	if err != nil {
		return nil, err
	}

	return &kms.GetPublicKeyOutput{
		KeyId:     params.KeyId,
		PublicKey: public_key_bytes,
		KeySpec:   types.KeySpecRsa2048,
	}, nil
}

func (m MockKmsAPI) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if *params.KeyId == "" {
		return nil, errors.New("expect key id to not be blank")
	}

	var keyspec types.KeySpec
	if *params.KeyId == "alias/rsa2048" {
		keyspec = types.KeySpecRsa2048
	} else {
		keyspec = types.KeySpecRsa4096
	}

	return &kms.DescribeKeyOutput{
		KeyMetadata: &types.KeyMetadata{
			KeyId:   params.KeyId,
			KeySpec: keyspec,
		},
	}, nil
}

func (m MockKmsAPI) Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error) {
	if *params.KeyId == "" {
		return nil, errors.New("expect key id to not be blank")
	}

	if params.MessageType != types.MessageTypeDigest {
		return nil, errors.New("expect message type digest")
	}

	if params.SigningAlgorithm == "" {
		return nil, errors.New("expect signing algorithm")
	}

	return &kms.SignOutput{
		Signature: []byte(""),
	}, nil
}

func (m MockKmsAPI) Verify(ctx context.Context, params *kms.VerifyInput, optFns ...func(*kms.Options)) (*kms.VerifyOutput, error) {
	if *params.KeyId == "" {
		return nil, errors.New("expect key id to not be blank")
	}

	if params.MessageType != types.MessageTypeDigest {
		return nil, errors.New("expect message type digest")
	}

	if params.SigningAlgorithm == "" {
		return nil, errors.New("expect signing algorithm")
	}

	return &kms.VerifyOutput{
		SignatureValid: true,
	}, nil
}
