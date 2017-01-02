// Config is put into a different package to prevent cyclic imports in case
// it is needed in several locations

package config

// Config contains the Netsamplebeat configuration
type Config struct {
	Interface InterfaceConfig `config:"interface"`
}

// InterfaceConfig contains the config portion for the interface (network device)
type InterfaceConfig struct {
	Device string `config:"device" validate:"nonzero"`
	// Only support sampling rates between 0 and 10000
	SampleRate         int    `config:"sample_rate" validate:"min=0, max=10000"`
	PreSamplingFilter  string `config:"pre_sampling_filter"`
	PostSamplingFilter string `config:"post_sampling_filter"`
}

// DefaultConfig contains the default configuration for Netsamplebeat
var DefaultConfig = Config{
	InterfaceConfig{
		Device:             "any",
		SampleRate:         1000,
		PreSamplingFilter:  "",
		PostSamplingFilter: "",
	},
}
