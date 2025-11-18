module voltha-go-controller

go 1.25.3

replace (
	github.com/coreos/bbolt v1.3.4 => go.etcd.io/bbolt v1.3.4
	github.com/google/gopacket => github.com/tinojj/gopacket v1.1.20-0.20220525133109-3e65a52a1a61
	go.etcd.io/bbolt v1.3.4 => github.com/coreos/bbolt v1.3.4
	google.golang.org/grpc => google.golang.org/grpc v1.25.1
)

require (
	github.com/go-redis/redis/v8 v8.11.5
	github.com/golang/mock v1.4.4
	github.com/golang/protobuf v1.5.4
	github.com/google/gopacket v0.0.0-00010101000000-000000000000
	github.com/gorilla/mux v1.8.1
	github.com/guumaster/tablewriter v0.0.10
	github.com/jessevdk/go-flags v1.5.0
	github.com/opencord/voltha-lib-go/v7 v7.6.5
	github.com/opencord/voltha-protos/v5 v5.6.2
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/stretchr/testify v1.8.2
	go.uber.org/atomic v1.9.0
	google.golang.org/grpc v1.56.2
)

require (
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cevaris/ordered_map v0.0.0-20190319150403-3adeae072e73 // indirect
	github.com/coreos/etcd v3.3.25+incompatible // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/coreos/pkg v0.0.0-20180928190104-399ea9e2e55f // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/mattn/go-runewidth v0.0.10 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rivo/uniseg v0.1.0 // indirect
	github.com/uber/jaeger-client-go v2.29.1+incompatible // indirect
	github.com/uber/jaeger-lib v2.4.1+incompatible // indirect
	go.etcd.io/etcd v3.3.25+incompatible // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.18.1 // indirect
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e // indirect
	golang.org/x/sys v0.0.0-20211216021012-1d35b9e2eb4e // indirect
	golang.org/x/text v0.3.6 // indirect
	google.golang.org/genproto v0.0.0-20220208230804-65c12eb4c068 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
