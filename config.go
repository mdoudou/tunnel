package main

type ServerConfig struct {
	Compress string
	Transfer string
	Listen   string
	Key      string
}

type ClientConfig struct {
	Server ServerConfig
	Geoip  struct {
		File            string
		AutoDownload    bool
		NameLang        string
		DirectCountries []string
	}
	Listen string
	Rules  struct {
		Proxy  []string
		Direct []string
	}
}

type Config struct {
	Server ServerConfig
	Client ClientConfig
}
