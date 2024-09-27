module sso

go 1.23.0

replace github.com/tyomll/sso-go/protos => ../protos

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/golang-migrate/migrate/v4 v4.18.1
	github.com/ilyakaznacheev/cleanenv v1.5.0
	github.com/tyomll/sso-go/protos v0.0.0-20240927115749-69ae208b3e77
	golang.org/x/crypto v0.27.0
	google.golang.org/grpc v1.67.0
)

require (
	github.com/BurntSushi/toml v1.2.1 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/text v0.18.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240814211410-ddb44dafa142 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	olympos.io/encoding/edn v0.0.0-20201019073823-d3554ca0b0a3 // indirect
)
