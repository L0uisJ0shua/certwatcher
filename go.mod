module github.com/drfabiocastro/certwatcher

go 1.19

replace internal/runner => ./internal/runner

replace pkg/core => ./pkg/core

replace pkg/stream => ./pkg/stream

replace internal/colorizer => ./internal/colorizer

replace pkg/config => ./pkg/config

replace pkg/utils => ./pkg/utils

replace pkg/certstream => ./pkg/certstream

replace pkg/types => ./pkg/types

replace pkg/yamlreader => ./pkg/yamlreader

replace pkg/templates => ./pkg/templates

replace pkg/matchers => ./pkg/matchers

require (
	github.com/projectdiscovery/gologger v1.1.8
	internal/runner v0.0.0-00010101000000-000000000000
)

require (
	github.com/projectdiscovery/goflags v0.1.6
	github.com/projectdiscovery/nuclei/v2 v2.8.9
	pkg/config v0.0.0-00010101000000-000000000000
	pkg/core v0.0.0-00010101000000-000000000000
	pkg/matchers v0.0.0-00010101000000-000000000000
	pkg/stream v0.0.0-00010101000000-000000000000
	pkg/types v0.0.0-00010101000000-000000000000
)

require (
	github.com/PuerkitoBio/goquery v1.8.0 // indirect
	github.com/alecthomas/jsonschema v0.0.0-20211022214203-8b29eab41725 // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/asaskevich/govalidator v0.0.0-20210307081110-f21760c49a8d // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/briandowns/spinner v1.23.0 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cnf/structhash v0.0.0-20201127153200-e1b16c1ebc08 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/fatih/color v1.7.0 // indirect
	github.com/go-playground/locales v0.14.0 // indirect
	github.com/go-playground/universal-translator v0.18.0 // indirect
	github.com/go-playground/validator/v10 v10.11.1 // indirect
	github.com/go-redis/redis/v8 v8.11.5 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/gorilla/css v1.0.0 // indirect
	github.com/gorilla/websocket v1.4.2 // indirect
	github.com/gosuri/uilive v0.0.4 // indirect
	github.com/gosuri/uiprogress v0.0.1 // indirect
	github.com/iancoleman/orderedmap v0.0.0-20190318233801-ac98e3ecb4b0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible // indirect
	github.com/logrusorgru/aurora/v4 v4.0.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/mholt/archiver v3.1.1+incompatible // indirect
	github.com/microcosm-cc/bluemonday v1.0.22 // indirect
	github.com/miekg/dns v1.1.50 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/nwaples/rardecode v1.1.2 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/projectdiscovery/utils v0.0.9 // indirect
	github.com/saintfish/chardet v0.0.0-20230101081208-5e3ef4b5456d // indirect
	github.com/sirupsen/logrus v1.9.0 // indirect
	github.com/ulikunitz/xz v0.5.11 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	golang.org/x/crypto v0.5.0 // indirect
	golang.org/x/exp v0.0.0-20230206171751-46f607a40771 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/net v0.6.0 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/term v0.5.0 // indirect
	golang.org/x/text v0.7.0 // indirect
	golang.org/x/tools v0.5.0 // indirect
	gopkg.in/djherbis/times.v1 v1.3.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	internal/colorizer v0.0.0-00010101000000-000000000000 // indirect
	pkg/certstream v0.0.0-00010101000000-000000000000 // indirect
	pkg/templates v0.0.0-00010101000000-000000000000 // indirect
	pkg/utils v0.0.0-00010101000000-000000000000 // indirect
	pkg/yamlreader v0.0.0-00010101000000-000000000000 // indirect
)
