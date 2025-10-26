//go:build tools

package tools

import (
	_ "github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
)
