# Safe Arithmetic and Accounting in NEAR Contracts: Mint, Stake, Burn

**Purpose.** A practical guide for designing a new token contract (NEP-141) with mint, staking and burn mechanics. Written from the analysis of a real mainnet exploit that cost the `usmeme.tg` project all of its liquidity.

This document is self-contained — it can be handed to a team with no additional context.

**Stack:** Rust, near-sdk 5.x, near-contract-standards.

> 📓 **The real case this guide is built on:** full on-chain postmortem — [**usmeme.tg Exploit Chronicle**](https://github.com/dimadze2116/usmeme.tg-Exploit-Chronicle). An $11.2K drain from a single unchecked subtraction, still unpatched 70 days on.

---

## Part I. What happened to usmeme.tg

### The incident

On July 29, 2026 the `usmeme.tg` token was zeroed out by a single transaction costing less than a dollar.

| Parameter | Value |
|---|---|
| Exploit transaction | `2Ct4dj1qXFw5mvHy9jWFE8Ap1QjbfsdgKwn5Cqr5Dk7d` |
| Attacker's account | `25fcb6e98fdca639c878c12c1c2ce8d0fb5d7ce4c647f098e9f4dc2bf9148020` |
| Call | `burn { "amount": "1" }` |
| Balance obtained | `u128::MAX` = 2¹²⁸ − 1 |
| Extracted | ≈ 6,983 NEAR (~$11.2K) |
| Cost of the attack | 1 minimal token unit + < $1 in gas |
| Exploit to payout | ~2 hours 40 minutes |

Account timeline:

```
15:04:28   account created
16:38:47   storage_deposit 0.00125 Ⓝ on usmeme.tg   ← registration, balance 0
16:38:57   burn { amount: "1" }                     ← balance becomes u128::MAX
16:39:04   first ft_transfer_call → Ref Finance
18:2x–18:39  three swaps, dumped into pools 4949 and 4950
19:2x      6,983 NEAR withdrawn to an external account
```

The token's stated supply was around 99.5B. One of the dump transactions sent 59.6B into a pool — roughly 60% of the entire "official" supply. Against the attacker's balance this was not visible at all: what was dumped amounted to 1.75·10⁻²⁰ of what was obtained.

### Seventy days later: still unpatched

Verified by direct mainnet queries on October 7, 2026. The `code_hash` of `usmeme.tg` is identical across blocks from 180,000,000 to 218,899,000 — that is, both long before the exploit and 70 days after it. It has never been redeployed.

The attacker still holds a balance that differs from `u128::MAX` by exactly the sum of the three dumps on July 29. Over two months the pools recovered from 139.67 to 380.94 wNEAR — liquidity extractable in a single transaction at any moment.

Three design takeaways:

1. **The damage is not one-off.** An attacker holding `u128::MAX` is bounded only by liquidity flowing into the pools. Every buyer funds the next possible harvest.

2. **The project had no kill switch.** No pause, no freeze, no revocation. A single `pause()` call would have bought time for a redeploy. See Part VII, "Emergency exits": `pause` / `unpause` belong in the contract from day one — once an exploit is public there is no time left to add them.

3. **Fixing it after the fact is near-impossible.** At the time of the check the token had 301,323 holders. A redeploy migrating that many balances is a project of its own, and evidently nobody took it on. That is why the hole is now in its third month.

### The mechanism

The `burn` method was hand-written and contained an unchecked subtraction:

```rust
// VULNERABLE CODE
let balance = self.accounts.get(&account_id).unwrap_or(0);
self.accounts.insert(&account_id, &(balance - amount));
```

A freshly registered account has a balance of 0. The expression evaluates `0u128 - 1u128`. In Rust this is **neither a compile error nor a runtime error** — under certain build settings the unsigned subtraction wraps around, and the result equals the maximum of the type:

```
u128::MAX = 340,282,366,920,938,463,463,374,607,431,768,211,455
```

The attacker paid one hundred-millionth of a token and received the entire range of the type.

### Why the tests didn't catch it

This is the central lesson of the incident.

Rust handles integer overflow **differently depending on the build profile**:

| Profile | Behavior of `0u128 - 1` | Where it's used |
|---|---|---|
| `debug` | panic: `attempt to subtract with overflow` | `cargo test`, local development |
| `release` (default) | **silent wraparound** → `u128::MAX` | `cargo build --release`, mainnet deployment |

So under `cargo test` the vulnerability **panics and looks like a correctly handled error**. Tests pass green. Meanwhile the WASM that ships to mainnet is built in release and carries the hole.

This is not hypothetical — it is exactly what happened. A gap between what is tested and what is deployed.

### Classification

CWE-191 (Integer Underflow) combined with CWE-1284 (Improper Validation of Specified Quantity in Input). Not exotic: the same class underlies dozens of pre-0.8 Solidity incidents and remains live for Rust contracts, because Rust only protects against it in debug.

---

## Part II. The mandatory foundation

### 1. Build settings

In the `Cargo.toml` of every crate that compiles to WASM:

```toml
[profile.release]
codegen-units = 1
opt-level = "z"
lto = true
debug = false
panic = "abort"
overflow-checks = true    # ← without this line, everything else in this document is moot
```

`overflow-checks = true` enables the same checks as debug: any overflow panics. Combined with `panic = "abort"`, on NEAR this means the whole transaction reverts and state is rolled back.

Gas overhead is a few percent. This is not the place to economize.

#### ⚠️ The workspace trap

If a crate belongs to a workspace, Cargo **completely ignores** the `[profile.*]` section in the member crate's `Cargo.toml`. Only the profile from the workspace root applies. Cargo emits nothing more than a warning, easily missed in noisy build output.

The classic failure: a project starts as a single crate with the correct profile, later grows into a workspace — and the protection is silently disabled while the line stays in the code, exactly where it was.

**Check after every change to project structure:**

```bash
cargo build --release -v 2>&1 | grep -o "overflow-checks=[a-z]*"
```

Expected output: `overflow-checks=on`. Empty or `off` means the profile is not applied.

Worth enforcing in CI as a hard gate:

```yaml
- name: Verify overflow-checks enabled
  run: |
    cargo build --release -v 2>&1 | grep -q "overflow-checks=on" \
      || { echo "FATAL: overflow-checks is not enabled in release profile"; exit 1; }
```

### 2. But build settings are a safety net, not a solution

`overflow-checks` turns a silent catastrophe into a failed transaction. That is the right default, but it cannot be the only line of defense:

- a panic gives the user `Smart contract panicked: attempt to subtract with overflow` instead of a meaningful error;
- one mistake in project structure disables the protection entirely;
- a panic inside a cross-contract callback can leave state desynchronized.

So every subtraction must be explicitly guarded in code, regardless of build profile. `overflow-checks` is the second line, for whatever was missed.

---

## Part III. Rules for handling balances

### Rule 1. Don't hand-write balance accounting

The root reason usmeme was vulnerable: `burn` was written by hand. In `near-contract-standards`, `ft_transfer` and `ft_transfer_call` are implemented correctly and battle-tested, **but `mint` and `burn` are not part of NEP-141** — teams add them themselves. What breaks is what was added.

The fix: never touch the balance map directly; use the standard's internal methods, which are already verified.

```rust
use near_contract_standards::fungible_token::FungibleToken;

// In near-contract-standards, internal_withdraw is implemented as:
//
//   let balance = self.internal_unwrap_balance_of(account_id);   // panics if not registered
//   if let Some(new_balance) = balance.checked_sub(amount) {     // checked_sub, not "-"
//       self.accounts.insert(account_id, &new_balance);
//       self.total_supply = self.total_supply
//           .checked_sub(amount)
//           .unwrap_or_else(|| env::panic_str("Total supply overflow"));
//   } else {
//       env::panic_str("The account doesn't have enough balance");
//   }
```

Note two things absent from usmeme: `internal_unwrap_balance_of` **panics** for an unregistered account instead of returning zero, and the subtraction goes through `checked_sub`.

### Rule 2. `unwrap_or(0)` on a balance is a direct path to an incident

```rust
// FORBIDDEN
let balance = self.accounts.get(&account_id).unwrap_or(0);
```

This line converts "the account does not exist" into "the account has zero". Any subsequent debit then starts from zero and goes negative. It is literally the first line of the usmeme exploit.

```rust
// CORRECT
let balance = self.accounts.get(&account_id)
    .unwrap_or_else(|| env::panic_str("Account is not registered"));
```

An unregistered account is a caller error, not a zero balance.

### Rule 3. All operations through `checked_*`

| Operation | Forbidden | Correct |
|---|---|---|
| Subtraction | `a - b`, `a -= b` | `a.checked_sub(b).unwrap_or_else(\|\| env::panic_str("..."))` |
| Addition | `a + b`, `a += b` | `a.checked_add(b).unwrap_or_else(\|\| env::panic_str("..."))` |
| Multiplication | `a * b` | `a.checked_mul(b).unwrap_or_else(\|\| env::panic_str("..."))` |

An alternative style, if you prefer checking before the operation:

```rust
require!(balance >= amount, "Insufficient balance");
balance -= amount;   // safe: the invariant was checked one line above
```

Both are correct. What matters is that nothing between the check and the operation can change the values — and that the check exists at all.

### Rule 4. `saturating_sub` is not a substitute for `checked_sub` in accounting

```rust
// DANGEROUS in accounting
let new_balance = balance.saturating_sub(amount);   // 0 - 5 = 0, silently
```

`saturating_sub` does not overflow, but it **hides the bug**. An attempt to debit more than exists quietly debits everything and returns zero. The transaction succeeds, the user sees a confirmation, and the invariant `total_supply == sum of balances` is broken — silently, surfacing weeks later.

Balances and supply need a panic. `saturating_sub` is appropriate only where saturation is deliberate semantics: "seconds remaining until unlock, but not below zero" in display logic, for example.

`wrapping_sub` has no use in financial code whatsoever.

### Rule 5. Keep the invariant explicit

```
total_supply == Σ balances[account]   over all accounts
```

Every operation that changes balances must preserve it:

| Operation | balance | total_supply |
|---|---|---|
| `mint` | `+amount` to recipient | `+amount` |
| `burn` | `−amount` from owner | `−amount` |
| `transfer` | `−amount` / `+amount` | unchanged |

The "decremented the balance but forgot the supply" bug (or the reverse) is not directly exploitable, but it breaks every external analytic: exchanges, aggregators and dashboards compute market cap from `ft_total_supply`.

#### ⚠️ `ft_total_supply` does not detect this class of exploit

The intuitive check — "just look at the supply" — **does not work**, and this was verified on usmeme itself.

The vulnerable subtraction was only on the balance line. The `total_supply -= amount` line executed correctly and reduced supply by exactly 1 unit. Actual values:

```
before the exploit:  9,950,212,691,031,686,747
after:               9,950,212,691,031,686,746   (exactly −1)
```

Seventy days on, the supply still looks normal — 99.5B USM, exactly as in the whitepaper. Every aggregator, exchange and dashboard computes market cap from it and sees nothing suspicious. Meanwhile one address holds 3.4·10³⁸ units — 3.4·10¹⁹ times the stated supply.

The working check is supply against the **sum of balances**; in practice it is enough to look at the **largest holder**: if their balance is comparable to `u128::MAX` or exceeds `total_supply`, the invariant is broken.

### Rule 6. Casts are arithmetic too

```rust
let n = big_u128 as u64;   // SILENT TRUNCATION, overflow-checks won't help
```

`as` never panics — it drops the high bits. `overflow-checks` does not cover casts. Use `u64::try_from(x).expect("...")`.

### Rule 7. Multiply before dividing

```rust
// PRECISION LOSS
let reward = amount / 10_000 * apr_bps;

// CORRECT
let reward = amount.checked_mul(apr_bps).expect("overflow") / 10_000;
```

Integer division discards the remainder. In the reverse order, small amounts yield zero reward.

Separately: decide and document who gets the rounding dust. By default it stays in the contract — that is fine, but it should be a deliberate decision, not a side effect.

---

## Part IV. Mint mechanics

### Checklist

```rust
#[payable]
pub fn mint(&mut self, account_id: AccountId, amount: U128) {
    // 1. Full access to the account, not a function-call key
    assert_one_yocto();

    // 2. Authorization
    self.assert_minter();

    // 3. Input validation
    require!(amount.0 > 0, "mint: amount must be positive");

    // 4. Supply cap checked BEFORE any state change
    let new_supply = self.token.total_supply
        .checked_add(amount.0)
        .unwrap_or_else(|| env::panic_str("mint: total supply overflow"));
    require!(new_supply <= MAX_SUPPLY, "mint: exceeds max supply");

    // 5. Credit via the verified internal method
    //    (panics if the recipient is not registered)
    self.token.internal_deposit(&account_id, amount.0);

    // 6. NEP-297 event — without it indexers won't see the issuance
    FtMint { owner_id: &account_id, amount, memo: None }.emit();
}
```

### Decisions to make at design time

**Who may mint.** Options in increasing order of safety: owner → multisig → DAO → no minting after initialization (fixed supply). If minting isn't needed after launch, don't write the method. Code that doesn't exist can't be exploited.

**Is there a cap.** `MAX_SUPPLY` as a compile-time constant is safer than a field in state: it can't be changed by a setter someone forgot to guard.

**Revocation.** A `renounce_minter()` method that irreversibly zeroes the mint right is a strong trust signal for holders and simultaneously closes an attack vector on the owner's key.

**Minting to an unregistered account.** `internal_deposit` panics if the recipient has no storage registration. That is correct behavior — do not work around it by registering accounts at the contract's expense in a loop over an address list: that drains the contract's balance.

### A note on airdrops

An airdrop method taking `Vec<(AccountId, U128)>` is a classic source of two problems at once:

- no limit on vector length → gas limit exceeded, the transaction fails after partial execution in a promise loop;
- storage registration paid by the contract → balance drain on a large list.

Cap the length explicitly (`require!(items.len() <= 50, ...)`) and require recipients to be registered in advance.

---

## Part V. Burn mechanics

This is where usmeme broke. This section is the most important one.

### Reference implementation

```rust
use near_contract_standards::fungible_token::events::FtBurn;
use near_sdk::assert_one_yocto;

#[payable]
pub fn burn(&mut self, amount: U128) {
    // 1. Full access — burning is irreversible
    assert_one_yocto();

    // 2. ONLY the caller's own balance may be burned
    let account_id = env::predecessor_account_id();

    // 3. Reject zero: a meaningless operation that pollutes the event log
    require!(amount.0 > 0, "burn: amount must be positive");

    // 4. Verified debit: panics on insufficient funds and on missing
    //    registration, and updates total_supply
    self.token.internal_withdraw(&account_id, amount.0);

    // 5. Event
    FtBurn { owner_id: &account_id, amount, memo: None }.emit();
}
```

### If you must write the debit by hand

Sometimes the standard `FungibleToken` doesn't fit — a custom account structure, for instance. The bare minimum then:

```rust
fn internal_burn(&mut self, account_id: &AccountId, amount: u128) {
    require!(amount > 0, "burn: amount must be positive");

    // NOT unwrap_or(0)
    let balance = self.accounts.get(account_id)
        .unwrap_or_else(|| env::panic_str("burn: account is not registered"));

    let new_balance = balance
        .checked_sub(amount)
        .unwrap_or_else(|| env::panic_str("burn: insufficient balance"));

    let new_supply = self.total_supply
        .checked_sub(amount)
        .unwrap_or_else(|| env::panic_str("burn: total supply underflow"));

    // Write BOTH values — the invariant from Rule 5
    self.accounts.insert(account_id, &new_balance);
    self.total_supply = new_supply;
}
```

Compare this line by line with the vulnerable usmeme code — there are exactly two differences, and either one alone would have prevented the incident.

### What not to do

**Don't allow burning someone else's balance.** A `burn_from(account_id, amount)` method without strict authorization is an attack vector of its own. If that mechanic is needed (burning on exit from staking, say), it must be reachable only through the contract's internal paths, never as a public method.

**Don't ship `burn` without `assert_one_yocto`.** A function-call access key issued to a frontend lives a long time and leaks far more often than a seed phrase. Burning is irreversible.

**Don't skip the event.** `FtBurn` per NEP-297 is what indexers need. Without it, external services will report the wrong supply even when the contract is correct.

**Don't burn inside a callback without a rollback.** If burning is part of a cross-contract flow, it must either precede the promise with a rollback on failure, or run after success is confirmed. See Part VI.

---

## Part VI. Staking mechanics

Staking adds two classes of problem on top of arithmetic: **cross-contract calls** and **state growth**.

### 1. Receiving tokens: `ft_on_transfer`

The user stakes via `ft_transfer_call` on the token contract. The token then calls you:

```rust
pub fn ft_on_transfer(
    &mut self,
    sender_id: AccountId,
    amount: U128,
    msg: String,
) -> PromiseOrValue<U128>
```

The return value is **how many tokens to return to the sender**. `U128(0)` = all accepted, `amount` = rejected with a full refund.

Mandatory checks:

```rust
// Our token only. Without this, anyone can "stake" a counterfeit token.
require!(
    env::predecessor_account_id() == self.token_contract_id,
    "ft_on_transfer: unauthorized token contract"
);
```

#### An important difference from NFTs

If the project also has NFT mechanics, note the difference in signatures:

| Standard | Callback | Who is the owner |
|---|---|---|
| NEP-141 (FT) | `ft_on_transfer(sender_id, amount, msg)` | `sender_id` — there is no other option |
| NEP-171 (NFT) | `nft_on_transfer(sender_id, previous_owner_id, token_id, msg)` | **`previous_owner_id`** |

For NFTs, `sender_id` is whoever called `nft_transfer_call`, while `previous_owner_id` is the actual owner. With approvals (NEP-178) these diverge, and using `sender_id` as the owner lets an approved account stake someone else's NFT and keep it on exit. This is a real bug, found in the audit of an adjacent project.

Do not carry the habit from FT code over into NFT code.

### 2. Cross-contract calls: change state before the promise

Promises on NEAR are asynchronous. Blocks pass between sending a promise and receiving its result, and the contract keeps accepting calls throughout. Hence the rule:

```rust
pub fn unstake(&mut self, stake_id: String) -> Promise {
    assert_one_yocto();
    let caller = env::predecessor_account_id();

    let mut stake = self.stakes.get(&stake_id)
        .unwrap_or_else(|| env::panic_str("unstake: not found"))
        .clone();
    require!(stake.owner == caller, "unstake: not the owner");
    require!(!stake.claimed, "unstake: already claimed");
    require!(env::block_timestamp() / 1_000_000_000 >= stake.unlock_at, "unstake: still locked");

    // ─── Mark BEFORE sending the promise ───
    // Otherwise a second unstake arriving before the first callback
    // passes every check again and pays the reward twice.
    stake.claimed = true;
    self.stakes.insert(stake_id.clone(), stake.clone());

    ext_ft::ext(self.token_contract_id.clone())
        .with_attached_deposit(NearToken::from_yoctonear(1))
        .with_static_gas(GAS_FT_TRANSFER)
        .ft_transfer(caller.clone(), U128(stake.amount), None)
        .then(
            ext_self::ext(env::current_account_id())
                .with_static_gas(GAS_CALLBACK)
                .on_unstake_complete(stake_id, stake)
        )
}
```

### 3. Rollback in the callback: a rule without exceptions

**Every `Promise::transfer` or `ft_transfer` must have a callback that rolls state back on failure.**

```rust
#[private]
pub fn on_unstake_complete(&mut self, stake_id: String, stake: StakeInfo) {
    let ok = matches!(env::promise_result(0), PromiseResult::Successful(_));
    if !ok {
        // Restore everything that was debited on the way out
        let mut s = stake;
        s.claimed = false;
        self.stakes.insert(stake_id, s);
        self.reward_pool = self.reward_pool
            .checked_add(stake.reward)
            .unwrap_or_else(|| env::panic_str("pool overflow"));
    }
}
```

The most common mistake in practice is **inconsistency**: the rollback is done impeccably in one method and forgotten in the one next to it. This occurred three times across the projects reviewed. Do an audit pass: list every place that sends funds and confirm each has a matching callback.

A distinct variant: **the payout goes out with no callback at all**. The user received the asset, the state is marked complete, and the reward transfer failed — funds lost silently, with nothing to restore them from.

`#[private]` on callbacks is mandatory. Without it, anyone can call the "callback" directly and roll back someone else's state.

### 4. Reward accounting: reserve vs. pay-on-exit

Two workable models:

**Reserve on entry.** At stake time the reward is deducted from the pool and locked to the position.

```rust
let reward = self.calc_reward(amount, period);
require!(self.reward_pool >= reward, "insufficient reward pool");
self.reward_pool -= reward;   // safe: checked one line above
```

Upside: the user is guaranteed what was promised. Downside: if they never claim, the funds hang outside the pool forever — you need `reclaim_expired(stake_id)` returning the reserve N periods after unlock.

**Accrue on exit.** The reward is computed at `unstake` time from actual elapsed time.

Upside: no stranded reserves. Downside: the pool can run dry and the last to exit get nothing — that case needs explicit logic, not a panic.

Record the chosen model in the contract's documentation: it determines how "available pool" is computed in the UI.

### 5. State growth: the main time bomb

```rust
// FORBIDDEN in write methods
let active = self.stakes.iter().filter(|(_, s)| !s.claimed).count();
```

A full scan of the collection reads every record from storage. `storage_read_base` ≈ 56 Ggas; against ~200 TGas available that is on the order of 2–3 thousand reads once deserialization is counted.

Such code works perfectly on testnet and for the first months on mainnet, and then the contract **irreversibly stops accepting new operations** — fixable only by a redeploy with migration.

```rust
// CORRECT: a counter in state
pub struct Contract {
    pub active_count: u64,                            // ++ on stake, -- on exit
    pub active_by_account: LookupMap<AccountId, u32>,
}
```

General rules:

- in write methods — **no** `.iter()` over unbounded collections;
- in view methods — pagination is mandatory (`from_index`, `limit`);
- completed records must be deleted or moved to an archive by a paginated method;
- `LookupMap` instead of `IterableMap` wherever iteration isn't needed: it's cheaper and doesn't invite scans.

### 6. Reward calculation

```rust
fn calc_reward(&self, amount: u128, apr_bps: u128, period_sec: u64) -> u128 {
    amount
        .checked_mul(apr_bps).expect("reward: overflow on apr")
        .checked_mul(period_sec as u128).expect("reward: overflow on period")
        / 10_000
        / SECONDS_PER_YEAR
}
```

Multiplications before divisions (Rule 7), each through `checked_mul`. With large `amount` and long periods the intermediate product can genuinely exceed `u128`, and a clear panic beats a result computed modulo the type.

---

## Part VII. Access control

### `assert_one_yocto` on every privileged method

NEAR has two kinds of key:

- **full-access key** — total control over the account, normally behind a seed phrase;
- **function-call access key** — a restricted key scoped to one contract, issued to frontends, bots and dApps. It cannot attach a deposit.

Hence the idiom: requiring exactly 1 yoctoNEAR makes a method unreachable for function-call keys. Those keys live for months, sit in users' browsers, and leak an order of magnitude more often than seed phrases.

```rust
fn assert_owner(&self) {
    assert_one_yocto();
    require!(
        env::predecessor_account_id() == self.owner_id,
        "Access denied: caller is not the contract owner"
    );
}
```

The method must be marked `#[payable]`, otherwise the attached deposit won't be accepted.

**Required on:** `mint`, `burn`, withdrawals, parameter changes, ownership transfer, any administrative operation, any method that moves assets.

**Not needed on:** methods that are payable by nature (topping up the pool), and pure views.

### Two-step ownership transfer

```rust
#[payable] pub fn propose_owner(&mut self, new_owner: AccountId)  // current owner proposes
#[payable] pub fn accept_owner(&mut self)                          // proposed owner accepts
```

A single-step `set_owner` with a typo in the address means irreversible loss of control over the contract.

### Emergency exits

Both contracts reviewed held other people's assets in escrow and **had no method whatsoever for recovering desynchronized state**. When state broke, users' assets were locked forever.

If a contract holds assets belonging to others, design in advance:

- `admin_return_asset(id, to)` — emergency release of a specific asset;
- `pause()` / `unpause()` — stop accepting new operations without blocking exits;
- a method to delete a corrupted record.

Important: `pause` must not block users from withdrawing funds — otherwise it becomes a vector in its own right.

And the mirror-image warning — **dangerous administrative methods**. A `clear_all()` that wipes every record in one call, with assets held in escrow, means their irreversible loss. If the only route to return an asset is a record in a map, deleting that record destroys the asset.

---

## Part VIII. Testing

### The test that would have caught usmeme

```rust
#[test]
#[should_panic(expected = "insufficient balance")]
fn burn_from_zero_balance_must_panic() {
    let mut contract = setup();
    // Fresh account: registered, zero balance
    contract.storage_deposit(Some(alice()), None);

    testing_env!(context(alice()).attached_deposit(ONE_YOCTO).build());
    contract.burn(U128(1));   // ← must panic, not hand out u128::MAX
}

#[test]
fn total_supply_invariant_holds_after_burn() {
    let mut contract = setup_with_balance(alice(), 1_000);
    testing_env!(context(alice()).attached_deposit(ONE_YOCTO).build());
    contract.burn(U128(400));

    assert_eq!(contract.ft_balance_of(alice()).0, 600);
    assert_eq!(contract.ft_total_supply().0, initial_supply - 400);
}
```

### The mandatory minimum

**Arithmetic and boundaries**
- `burn` on a zero balance → panic
- `burn` exceeding the balance → panic
- `burn(0)` → panic
- `mint` beyond `MAX_SUPPLY` → panic
- `mint` with `total_supply` near `u128::MAX` → panic, not wraparound
- invariant `total_supply == Σ balances` after an arbitrary sequence of operations

**Access**
- `mint` / `burn` / withdrawal without the attached yocto → panic
- privileged methods from a foreign account → panic
- direct external call to a `#[private]` callback → rejected

**Cross-contract scenarios**
- `ft_on_transfer` from an unrelated contract → rejected
- failed `ft_transfer` in `unstake` → state fully rolled back, reward returned to the pool
- repeated `unstake` before the callback arrives → rejected on `claimed`
- `unstake` before the lock expires, and `unstake` of someone else's position → panic

**State growth**
- load test: 1,000 / 5,000 / 10,000 positions, measuring gas on write methods. If consumption grows with record count, a collection scan is still in the code.

### Checking on testnet

Direct verification of the usmeme class on a deployed contract — **testnet only**:

```bash
near call TOKEN.testnet storage_deposit '{}' \
  --accountId probe.testnet --deposit 0.00125

near call TOKEN.testnet burn '{"amount":"1"}' \
  --accountId probe.testnet --depositYocto 1 --gas 30000000000000

near view TOKEN.testnet ft_balance_of '{"account_id":"probe.testnet"}'
```

Expect a panic on the second call. If the third returns `340282366920938463463374607431768211455` — that is `u128::MAX`, the same bug.

A read-only check, applicable to mainnet too. Check **the largest balance, not the supply** — supply stays normal with this bug (see Part I):

```bash
# invariant: no balance can exceed total_supply
near view TOKEN.near ft_total_supply
near view TOKEN.near ft_balance_of '{"account_id":"<largest holder>"}'
```

Any indexer (Pikespeak, NearBlocks) gives the largest holder in its holders section. If that balance exceeds `total_supply` or is comparable to `340282366920938463463374607431768211455`, the contract has already been exploited.

On usmeme it looks like this: supply `9950212691031686746`, top holder's balance `340282366920938463454245943777768211591`.

---

## Part IX. Pre-deployment checklist

### Build
- [ ] `overflow-checks = true` in `[profile.release]`
- [ ] `panic = "abort"`
- [ ] Verified that the profile actually applies (`cargo build --release -v | grep overflow-checks`)
- [ ] If there is a workspace — the profile is in the **root** `Cargo.toml`
- [ ] The check is enforced in CI

### Arithmetic
- [ ] `grep -rn -- "-=" src/` — every occurrence guarded by a `require!` on the line above
- [ ] `grep -rn "unwrap_or(0)" src/` — none for balances
- [ ] `grep -rn " as u" src/` — no narrowing cast without `try_from`
- [ ] No `saturating_sub` / `wrapping_sub` in accounting code
- [ ] Every multiplication in reward math uses `checked_mul`
- [ ] Multiplications precede divisions

### Token
- [ ] `mint` and `burn` use the standard's `internal_deposit` / `internal_withdraw`
- [ ] `burn` debits only `predecessor_account_id()`
- [ ] `total_supply` changes together with the balance in both operations
- [ ] `MAX_SUPPLY` is checked before crediting
- [ ] `FtMint` / `FtBurn` events (NEP-297) are emitted
- [ ] An unregistered account causes a panic, not a zero-balance reading

### Access
- [ ] `assert_one_yocto` on every method that moves assets or changes parameters
- [ ] Those methods are marked `#[payable]`
- [ ] All callbacks are marked `#[private]`
- [ ] `ft_on_transfer` / `nft_on_transfer` verify `predecessor_account_id`
- [ ] Ownership transfer is two-step
- [ ] Mint rights can be irreversibly revoked

### Cross-contract calls
- [ ] State changes **before** the promise is sent
- [ ] Every outgoing transfer has a callback with a rollback
- [ ] Rollbacks are implemented in **all** methods, not some
- [ ] Gas is budgeted per step, batch length capped with `require!`
- [ ] NFTs use `previous_owner_id`, FTs use `sender_id`

### State
- [ ] No `.iter()` over an unbounded collection in write methods
- [ ] Every view is paginated
- [ ] Counters in state instead of recomputation by scanning
- [ ] Completed records are deleted or archived
- [ ] Load test at 10,000 records passes

### Emergency mechanisms
- [ ] There is a method to recover desynchronized state
- [ ] `pause` does not block user withdrawals
- [ ] No method wipes escrowed-asset records in one call
- [ ] A state-migration path for redeploy has been thought through

---

## Appendix. Anti-pattern summary

| Anti-pattern | What it leads to |
|---|---|
| `balance - amount` without a check | The usmeme exploit: `u128::MAX` out of thin air |
| No `overflow-checks` in release | Tests green, mainnet vulnerable |
| `[profile.release]` in a workspace member crate | The profile is silently ignored |
| `accounts.get(&id).unwrap_or(0)` | An unregistered account gets a zero balance and goes negative |
| `saturating_sub` in accounting | The debit error is hidden, the invariant drifts silently |
| Hand-written `burn` instead of `internal_withdraw` | The standard is battle-tested; your code isn't |
| `burn` without `assert_one_yocto` | A leaked FCAK burns irreversibly |
| Changing state after the promise | Double payout in the window before the callback |
| Transferring funds without a callback | Silent loss on failure |
| Rollback in one method, forgotten in the next | The most common mistake in practice |
| `.iter()` over a collection in a write method | The contract dies of gas after months of operation |
| `clear_all()` with assets in escrow | Irreversible loss of other people's property |
| `sender_id` as the NFT owner | NFT theft via NEP-178 approvals |
| `as u64` instead of `try_from` | Silent truncation; `overflow-checks` won't help |
