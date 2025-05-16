//go:build tools

package tools

import (
    _ "google.golang.org/protobuf/cmd/protoc-gen-go"
    _ "github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto"
)
