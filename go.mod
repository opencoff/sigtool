module github.com/opencoff/sigtool

go 1.24.3

//replace github.com/opencoff/go-mmap => ../go-mmap
//replace github.com/opencoff/go-utils => ../go-utils

require (
	github.com/dchest/bcrypt_pbkdf v0.0.0-20150205184540-83f37f9c154a
	github.com/opencoff/go-fio v0.5.15
	github.com/opencoff/go-mmap v0.1.6
	github.com/opencoff/go-utils v1.0.3
	github.com/opencoff/pflag v1.0.7
	github.com/planetscale/vtprotobuf v0.6.0
	golang.org/x/crypto v0.38.0
	google.golang.org/protobuf v1.36.6
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/pkg/xattr v0.4.10 // indirect
	github.com/puzpuzpuz/xsync/v3 v3.5.1 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/term v0.32.0 // indirect
)
