// Code generated by apbr generate. DO NOT EDIT.
// versions:
// 	apbr generate v1.2

//go:build !codeanalysis

package model

import (
	"github.com/apibrew/apibrew/pkg/model"
	"github.com/apibrew/apibrew/pkg/util"
	"google.golang.org/protobuf/types/known/structpb"
)

var Oauth2ProviderResource = &model.Resource{
	Name:      "Oauth2Provider",
	Namespace: "sso",
	Types: []*model.ResourceSubType{
		{
			Name:        "UserInfoExtract",
			Description: "Extract user information with json path",
			Properties: []*model.ResourceProperty{
				{
					Name: "username",
					Type: model.ResourceProperty_STRING,
				},
			},
		},
	},
	Properties: []*model.ResourceProperty{
		{
			Name:         "id",
			Type:         model.ResourceProperty_UUID,
			Primary:      true,
			Required:     true,
			Immutable:    true,
			ExampleValue: structpb.NewStringValue("a39621a4-6d48-11ee-b962-0242ac120002"),

			Annotations: map[string]string{
				"SpecialProperty": "true",
			},
		},
		{
			Name: "defaultScopes",
			Type: model.ResourceProperty_LIST,
			Item: &model.ResourceProperty{
				Name: "",
				Type: model.ResourceProperty_STRING,
			},
		},
		{
			Name:     "name",
			Type:     model.ResourceProperty_STRING,
			Required: true,
			Unique:   true,
		},
		{
			Name:     "authUrl",
			Type:     model.ResourceProperty_STRING,
			Required: true,
		},
		{
			Name:     "tokenUrl",
			Type:     model.ResourceProperty_STRING,
			Required: true,
		},
		{
			Name:     "userInfoUrl",
			Type:     model.ResourceProperty_STRING,
			Required: true,
		},
		{
			Name:    "userInfoExtractConfig",
			Type:    model.ResourceProperty_STRUCT,
			TypeRef: util.Pointer("UserInfoExtract"),
		},
		{
			Name:         "version",
			Type:         model.ResourceProperty_INT32,
			Required:     true,
			DefaultValue: structpb.NewNumberValue(1),
			ExampleValue: structpb.NewNumberValue(1),

			Annotations: map[string]string{
				"SpecialProperty":     "true",
				"AllowEmptyPrimitive": "true",
			},
		},
	},
}
