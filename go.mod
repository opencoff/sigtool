module github.com/opencoff/sigtool

go 1.23.4

require (
	github.com/dchest/bcrypt_pbkdf v0.0.0-20150205184540-83f37f9c154a
	github.com/opencoff/go-fio v0.5.7
	github.com/opencoff/go-mmap v0.1.5
	github.com/opencoff/go-utils v1.0.1
	github.com/opencoff/pflag v1.0.6-sh1
	github.com/planetscale/vtprotobuf v0.6.0
	golang.org/x/crypto v0.31.0
	google.golang.org/protobuf v1.36.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/pkg/xattr v0.4.10 // indirect
	github.com/puzpuzpuz/xsync/v3 v3.4.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/term v0.27.0 // indirect
)

//replace github.com/opencoff/go-mmap => ../go-mmap
//replace github.com/opencoff/go-utils => ../go-utils
