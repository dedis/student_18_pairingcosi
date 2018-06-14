Local simulation:
```
go build -tags vartime && ./simulation bls_simul.toml
```
Deterlab simulation:

```
go build -tags vartime && ./simulation -platform deterlab bls_simul.toml
```