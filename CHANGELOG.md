# Changelog

## [1.3.0](https://github.com/Snipa22/go-crypto-pool/compare/go-crypto-pool-v1.2.0...go-crypto-pool-v1.3.0) (2026-10-02)


### Features

* **leaflib,proxy,direct:** close-and-drop on HTTP CONNECT probe ([c3da6ce](https://github.com/Snipa22/go-crypto-pool/commit/c3da6ce389d4b76877cafc1482b280c7ef3ed082))
* **leaflib,proxy,direct:** generalize HTTP CONNECT probe guard to all HTTP methods ([01e8718](https://github.com/Snipa22/go-crypto-pool/commit/01e87189017a0900de08c74ce3c3306e0f9f8ba3))


### Bug Fixes

* **ci:** match docker-build tag trigger to release-please's actual go-crypto-pool-v* tags ([5515312](https://github.com/Snipa22/go-crypto-pool/commit/5515312846f833e256e1131392c1b434b11620df))

## [1.2.0](https://github.com/Snipa22/go-crypto-pool/compare/go-crypto-pool-v1.1.0...go-crypto-pool-v1.2.0) (2026-10-02)


### Features

* **backend:** add bounded, Postgres-backed hash-history time series ([8617e08](https://github.com/Snipa22/go-crypto-pool/commit/8617e08d6e26219e60426f642af6a20115b0945a))
* **ci:** add release-please automation for versioning ([5b0e753](https://github.com/Snipa22/go-crypto-pool/commit/5b0e753d0a572a18558b24300c934476e2136bf0))
* **direct:** atomic miner identity + re-login tracking + proxy-aware forced vardiff target time ([d91d31c](https://github.com/Snipa22/go-crypto-pool/commit/d91d31c01261923e53fce561cfbb26c907b0ce07))
* **direct:** submit-timing histograms (leaf_direct_submit_{processing,validation}_seconds) ([a970754](https://github.com/Snipa22/go-crypto-pool/commit/a970754d6aff97d131552ce2febc66cb5372361f))
* **leaflib:** add shared MinerIdentity + LoginHistory types ([0d99fa3](https://github.com/Snipa22/go-crypto-pool/commit/0d99fa30b776631d0b8b997726fbc5c9daef2f08))
* Monero/RXM production hardening batch ([66d9c8f](https://github.com/Snipa22/go-crypto-pool/commit/66d9c8ff87484f5f93dd07fb9ddec5e78c9fbd4b))
* **proxy:** atomic miner identity + re-login tracking + proxy-aware forced vardiff target time ([39f525b](https://github.com/Snipa22/go-crypto-pool/commit/39f525b42b84e48d7901660bc8b3f37a4888a5e3))
* **proxy:** leaf-proxy password-gated metrics, log levels, foreground hashrate, miner-stats API, 24h stats retention, IPv6 ports ([d46ea6d](https://github.com/Snipa22/go-crypto-pool/commit/d46ea6da0f987fd151d399507de3c0bf053679a5))
* **proxy:** stats page dark-mode toggle + adjustable auto-refresh ([f9a48e4](https://github.com/Snipa22/go-crypto-pool/commit/f9a48e4825cd7f4433ee4429da0de5469c070d4a))
* **proxy:** submit-timing histograms (leaf_proxy_submit_{processing,validation}_seconds) ([79c2be4](https://github.com/Snipa22/go-crypto-pool/commit/79c2be4746208a6a241c7d7eb52e98c9a702ea1d))
* **solo,direct:** bump -no-share-timeout default from 3m to 5m ([2c5335a](https://github.com/Snipa22/go-crypto-pool/commit/2c5335aa771f87d6560a68bbbb633bd1e3b9a829))
* **solo:** atomic miner identity + re-login tracking + proxy-aware forced vardiff target time ([28b5045](https://github.com/Snipa22/go-crypto-pool/commit/28b5045320a7ceab935d25e77b281089a7233184))
* **solo:** submit-timing histograms (leaf_solo_submit_{processing,validation}_seconds) ([19146ce](https://github.com/Snipa22/go-crypto-pool/commit/19146cedfcbf8939e7a80983712b5fc122d737ef))
* **stats:** add auto-refresh ([00f7d69](https://github.com/Snipa22/go-crypto-pool/commit/00f7d6922b96874a8b803c6143a2e62c11db75d7))
* **transport:** add disk-backed durable backlog for share/block submit failures ([cf89690](https://github.com/Snipa22/go-crypto-pool/commit/cf896902af1a2c01c103a80c7c11186092e18bdb))


### Bug Fixes

* **proxy,metrics:** serialize upstream-reconnect counter refresh before Gather ([2ecfe8d](https://github.com/Snipa22/go-crypto-pool/commit/2ecfe8d6362ff50d01d6886e2a1a8a579a8a26a2))
* **proxy:** always-on fixed-30s hashrate ticker, provably-uncapped /api/miners ([f2ffee2](https://github.com/Snipa22/go-crypto-pool/commit/f2ffee299ee335b9656d32aec5e5c15949f4a1b7))
* **solo,direct:** key the job cache by session identity, not by the 2-byte xn ([10d913d](https://github.com/Snipa22/go-crypto-pool/commit/10d913d2fc2f49f046f3ca66ea1809d54e98e05a))
* **solo,direct:** roll a fresh xn on every re-login to prevent false duplicate_nonce ([2dac5c3](https://github.com/Snipa22/go-crypto-pool/commit/2dac5c3b3f87ae20e4ac59ec77b16d4559b7a833))
* **solo,direct:** throttle pushFreshJobOnStaleSubmit to 1/10s per session ([db4612e](https://github.com/Snipa22/go-crypto-pool/commit/db4612e9712944e76bc4ed29803db69023cff83c))
* **transport,direct:** wire backlog metrics into the real /metrics registry (reconciled) ([0b73ebe](https://github.com/Snipa22/go-crypto-pool/commit/0b73ebe03f3c753151820246e29724b6f29a1ef2))
* update renamed job-cache-key test helper call sites in the new submit-timing-metrics tests ([87043e2](https://github.com/Snipa22/go-crypto-pool/commit/87043e236321802b0a246727af1b8b7473b18e76))
