// Code generated by apbr generate. DO NOT EDIT.
// versions:
// 	apbr generate v1.2

//go:build !codeanalysis

package model

import "github.com/google/uuid"

type Oauth2Authenticate struct {
	Id      *uuid.UUID    `json:"id,omitempty"`
	Config  *Oauth2Config `json:"config,omitempty"`
	Code    string        `json:"code,omitempty"`
	Token   *string       `json:"token,omitempty"`
	Version int32         `json:"version,omitempty"`
}

func (s Oauth2Authenticate) GetId() *uuid.UUID {
	return s.Id
}
func (s Oauth2Authenticate) GetConfig() *Oauth2Config {
	return s.Config
}
func (s Oauth2Authenticate) GetCode() string {
	return s.Code
}
func (s Oauth2Authenticate) GetToken() *string {
	return s.Token
}
func (s Oauth2Authenticate) GetVersion() int32 {
	return s.Version
}
