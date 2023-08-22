## Token Withdrawal Module

**A Safe Module, which allows accounts that are not related to the Safe, to withdraw a predetermined amount of a specific token.**

Safe owners can generate a signature, which allows anyone to withdraw tokens from their Safe.

Module is specific to:
-   **Safe**: Safe proxy address.
-   **Token**: ERC20 token.

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Deploy

```shell
$ forge script script/DeployScript.s.sol:DeployScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```
