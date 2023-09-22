module voltha-go-controller

go 1.16

replace (
	github.com/coreos/bbolt v1.3.4 => go.etcd.io/bbolt v1.3.4
	github.com/google/gopacket => github.com/tinojj/gopacket v1.1.20-0.20220525133109-3e65a52a1a61
	go.etcd.io/bbolt v1.3.4 => github.com/coreos/bbolt v1.3.4
	google.golang.org/grpc => google.golang.org/grpc v1.25.1
)

require (
	github.com/go-redis/redis/v8 v8.11.5
	github.com/golang/mock v1.4.4
	github.com/golang/protobuf v1.5.3
	github.com/google/gopacket v0.0.0-00010101000000-000000000000
	github.com/gorilla/mux v1.8.0
	github.com/guumaster/tablewriter v0.0.10
	github.com/jessevdk/go-flags v1.5.0
	github.com/opencord/voltha-lib-go/v7 v7.2.1
	github.com/opencord/voltha-protos/v5 v5.2.4
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/stretchr/testify v1.8.2
	go.uber.org/atomic v1.9.0
	google.golang.org/grpc v1.44.0
)
