# s8l6
This measures the AES performance of each encryption library.
## Libraries to compare
- [x] OpenSSL
- [x] WolfSSL 
- [ ] BoringSSL
- [ ] LibreSSL 

## Using algorithms
- [x] CBC
- [ ] CCR
- [ ] GCM

## Requirement
- macOS Sonoma >14.1.2
- OpenSSL >3.2.1 30
- WolfSSL >5.7.0
- ninja.build > 1.11.1

## Build&Test
The command of ninja.build can run all builds & test.
``` bash
ninja
```
If you want to build & test only OpenSSL
``` bash
ninja lib_comparison_openssl
ninja test_openssl
```

and only for WolfSSL
``` bash
ninja lib_comparison_wolfssl
ninja test_wolfssl
```

## Clean
``` bash
ninja -t clean
```
