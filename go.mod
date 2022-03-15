module github.com/darkedges/ldifcmd

go 1.17

require (
	github.com/go-ldap/ldap/v3 v3.4.1
	github.com/go-ldap/ldif v0.0.0-20200320164324-fd88d9b715b3
	github.com/ilyakaznacheev/cleanenv v1.2.5
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20200615164410-66371956d46c // indirect
	github.com/BurntSushi/toml v0.3.1 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.1 // indirect
	github.com/joho/godotenv v1.3.0 // indirect
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9 // indirect
	gopkg.in/yaml.v2 v2.2.2 // indirect
	olympos.io/encoding/edn v0.0.0-20200308123125-93e3b8dd0e24 // indirect
)

replace github.com/go-ldap/ldif => github.com/darkedges/ldif v0.0.0-20211107071923-6fbdf6e29744
