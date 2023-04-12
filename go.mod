module github.com/drfabiocastro/certwatcher

go 1.19

replace internal/runner => ./internal/runner

replace pkg/core => ./pkg/core

replace pkg/stream => ./pkg/stream

replace internal/colorizer => ./internal/colorizer

replace pkg/templates/log => ./pkg/templates/log

replace pkg/config => ./pkg/config

replace pkg/utils => ./pkg/utils

replace pkg/certstream => ./pkg/certstream

replace pkg/types => ./pkg/types

replace pkg/yamlreader => ./pkg/yamlreader

replace pkg/templates => ./pkg/templates

replace pkg/matchers => ./pkg/matchers

replace pkg/catalog/disk => ./pkg/catalog/disk

replace pkg/http => ./pkg/http

require (
	github.com/projectdiscovery/gologger v1.1.8
	internal/runner v0.0.0-00010101000000-000000000000
)

require (
	github.com/projectdiscovery/nuclei/v2 v2.9.0
	pkg/core v0.0.0-00010101000000-000000000000
	pkg/matchers v0.0.0-00010101000000-000000000000
	pkg/stream v0.0.0-00010101000000-000000000000
	pkg/templates v0.0.0-00010101000000-000000000000
	pkg/types v0.0.0-00010101000000-000000000000
	pkg/utils v0.0.0-00010101000000-000000000000
)

require (
	github.com/EDDYCJY/fake-useragent v0.2.0 // indirect
	github.com/Mzack9999/go-http-digest-auth-client v0.6.1-0.20220414142836-eb8883508809 // indirect
	github.com/PuerkitoBio/goquery v1.8.1 // indirect
	github.com/alecthomas/jsonschema v0.0.0-20211022214203-8b29eab41725 // indirect
	github.com/andybalholm/cascadia v1.3.1 // indirect
	github.com/antchfx/htmlquery v1.3.0 // indirect
	github.com/antchfx/xmlquery v1.3.15 // indirect
	github.com/antchfx/xpath v1.2.3 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/aymerick/douceur v0.2.0 // indirect
	github.com/briandowns/spinner v1.23.0 // indirect
	github.com/cnf/structhash v0.0.0-20201127153200-e1b16c1ebc08 // indirect
	github.com/dsnet/compress v0.0.1 // indirect
	github.com/fatih/color v1.14.1 // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.11.2 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gocolly/colly/v2 v2.1.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/gorilla/css v1.0.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/iancoleman/orderedmap v0.0.0-20190318233801-ac98e3ecb4b0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kennygrant/sanitize v1.2.4 // indirect
	github.com/leodido/go-urn v1.2.1 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible // indirect
	github.com/logrusorgru/aurora/v4 v4.0.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.17 // indirect
	github.com/mholt/archiver v3.1.1+incompatible // indirect
	github.com/microcosm-cc/bluemonday v1.0.23 // indirect
	github.com/miekg/dns v1.1.52 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/nwaples/rardecode v1.1.2 // indirect
	github.com/pelletier/go-toml/v2 v2.0.6 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/projectdiscovery/goflags v0.1.8 // indirect
	github.com/projectdiscovery/retryablehttp-go v1.0.13 // indirect
	github.com/projectdiscovery/utils v0.0.16 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	github.com/saintfish/chardet v0.0.0-20230101081208-5e3ef4b5456d // indirect
	github.com/spf13/afero v1.9.3 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.15.0 // indirect
	github.com/subosito/gotenv v1.4.2 // indirect
	github.com/temoto/robotstxt v1.1.1 // indirect
	github.com/ulikunitz/xz v0.5.11 // indirect
	github.com/weppos/publicsuffix-go v0.20.0 // indirect
	github.com/xi2/xz v0.0.0-20171230120015-48954b6210f8 // indirect
	golang.org/x/crypto v0.7.0 // indirect
	golang.org/x/exp v0.0.0-20230310171629-522b1b587ee0 // indirect
	golang.org/x/mod v0.9.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/term v0.6.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	golang.org/x/tools v0.7.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.29.0 // indirect
	gopkg.in/djherbis/times.v1 v1.3.0 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	internal/colorizer v0.0.0-00010101000000-000000000000 // indirect
	pkg/catalog/disk v0.0.0-00010101000000-000000000000 // indirect
	pkg/certstream v0.0.0-00010101000000-000000000000 // indirect
	pkg/config v0.0.0-00010101000000-000000000000 // indirect
	pkg/http v0.0.0-00010101000000-000000000000 // indirect
	pkg/templates/log v0.0.0-00010101000000-000000000000 // indirect
	pkg/yamlreader v0.0.0-00010101000000-000000000000 // indirect
)
