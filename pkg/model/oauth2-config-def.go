// Code generated by apbr generate. DO NOT EDIT.
// versions:
// 	apbr generate v1.2

//go:build !codeanalysis

package model

import (
	"github.com/apibrew/apibrew/pkg/model"
	"google.golang.org/protobuf/types/known/structpb"
)

var Oauth2ConfigResource = &model.Resource{
	Name:      "Oauth2Config",
	Namespace: "sso",
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
			Name: "scopes",
			Type: model.ResourceProperty_LIST,
			Item: &model.ResourceProperty{
				Name: "",
				Type: model.ResourceProperty_STRING,
			},
		},
		{
			Name: "newUserRoles",
			Type: model.ResourceProperty_LIST,
			Item: &model.ResourceProperty{
				Name: "",
				Type: model.ResourceProperty_STRING,
			},
		},
		{
			Name: "redirectUrl",
			Type: model.ResourceProperty_STRING,
		},
		{
			Name:         "enabled",
			Type:         model.ResourceProperty_BOOL,
			Required:     true,
			DefaultValue: structpb.NewBoolValue(true),
		},
		{
			Name:     "name",
			Type:     model.ResourceProperty_STRING,
			Required: true,
			Unique:   true,
		},
		{
			Name:      "provider",
			Type:      model.ResourceProperty_REFERENCE,
			Reference: &model.Reference{Resource: "Oauth2Provider", Namespace: "sso"},
		},
		{
			Name:     "clientId",
			Type:     model.ResourceProperty_STRING,
			Required: true,
		},
		{
			Name:     "clientSecret",
			Type:     model.ResourceProperty_STRING,
			Required: true,
		},
		{
			Name:         "version",
			Type:         model.ResourceProperty_INT32,
			Required:     true,
			DefaultValue: structpb.NewNumberValue(1),
			ExampleValue: structpb.NewNumberValue(1),

			Annotations: map[string]string{
				"AllowEmptyPrimitive": "true",
				"SpecialProperty":     "true",
			},
		},
	},
}
