module github.com/opencoff/sigtool

go 1.21.1

require (
	github.com/dchest/bcrypt_pbkdf v0.0.0-20150205184540-83f37f9c154a
	github.com/opencoff/go-mmap v0.1.1
	github.com/opencoff/go-utils v0.9.0
	github.com/opencoff/pflag v1.0.6-sh1
	golang.org/x/crypto v0.17.0
	google.golang.org/protobuf v1.32.0
	gopkg.in/yaml.v2 v2.4.0
)

require (
	golang.org/x/sys v0.16.0 // indirect
	golang.org/x/term v0.15.0 // indirect
)

//replace github.com/opencoff/go-mmap => ../go-mmap
