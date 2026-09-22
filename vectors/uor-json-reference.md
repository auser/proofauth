# UOR-ADDR JSON reference vector

This vector is copied from the official `uor-addr` JSON realization's public
example and is tested directly in `src/lib.rs`.

Input:

```json
{"foo":"bar"}
```

Address:

```text
sha256:7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b
```

The address is a 71-byte ASCII UOR κ-label: `sha256:` followed by 64 lowercase
hexadecimal characters.
