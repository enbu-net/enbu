# Principalベースの認可Policy

## Status

- 状態: Draft
- 更新日: 2026-08-30
- 実装状況: 未実装
- 対象: enbu OSS
- 将来対象: enbu Cloud

## 背景

enbuではIdentity ProviderとOCI Registryを独立して選択する。

Identity Providerは本人を認証し、Registry Credential ProviderはOCI Registryへ接続するcredentialを提供する。

認証したPrincipalとRegistryへ接続したTransport Principalは一致するとは限らない。

認可をIdP固有のteam、group、repository permissionへ結び付けると、IdPを変更するたびにPolicyの意味が変わる。

そこで、IdPはPrincipalの認証だけを担当し、enbuの認可はOPA/Regoで判断する。

Policyが参照するmember、role、grantは、署名済みControl Stateに保持する。

## 目的

1. 任意のIdPで認証したPrincipalへ、同じ認可Policyを適用する。
2. Secretのread、write、member管理、Policy更新を別のactionとして判断する。
3. Policyと認可dataの改変、差し替え、既知のrollbackを検知する。
4. すべてのSecret Artifact発行経路で同じPolicy Enforcement Pointを通す。
5. 認可判断を後から再現できる証拠をSecret Artifactと監査Eventへ残す。
6. OSSとCloudでPolicy schemaと評価器を共通化する。

## 対象外

- IdPのteam、group、organization membershipを認可規則へ直接使用すること
- GitHub repository permissionやGitHub Teamを認可規則へ使用すること
- Registry credentialまたはRegistry上のpermissionを本人の権限として扱うこと
- OPA/RegoからIdP、Registry、外部APIへ問い合わせること
- Secret名またはSecret値をPolicy inputへ渡すこと
- 取得済みの平文や過去のArtifactを失効によって回収すること
- 悪意のある復号可能な利用者による平文漏えいを防ぐこと

## 用語

**Principal**は、IdPが認証した本人を表す`issuer`と`subject`の組である。

```json
{
  "issuer": "https://example.okta.com/oauth2/default",
  "subject": "00uabc..."
}
```

username、email、display nameはPrincipalの識別子にしない。

**Identity Attestation**は、IdPが認証したPrincipalとDevice Signing Keyおよびage recipient keyを結び付ける署名済みstatementである。

**Control State**は、member、device、grant、Policy digest、失効状態を保持する署名済みsnapshot chainである。

**Policy Artifact**は、Rego module、静的data、manifestを格納した署名済みOPA Bundleである。

**Policy Decision Point**は、Policy Artifactと正規化済みinputを評価するOPAである。

**Policy Enforcement Point**は、OPAの判断を各操作へ強制するenbu Coreである。

**Transport Principal**はRegistry credentialが表す接続主体であり、認可判断には使用しない。

## 責務の分離

```text
Identity Provider
      |
      | authenticates
      v
  Principal
      |
      v
Identity Attestation
      |
      v
signed Control State --------> member, device, grant
      |
      +-----------------------> policy_digest
                                  |
                                  v
                           signed Policy Artifact
                                  |
                                  v
Operation ---- enbu Core -----> OPA/Rego
                   |
                   +---- allow: continue
                   |
                   +---- deny/error: abort

Registry Credential Provider ----> OCI Registry
```

IdPは「誰か」を証明する。

Control Stateは「enbu projectのmemberとしてどの鍵とgrantが承認されているか」を証明する。

OPAは「そのPrincipalが要求したactionを許可するか」を判断する。

enbu Coreは判断結果を実際の復号、暗号化、push、Control State更新へ強制する。

## 認可Model

### Action

MVPでは次のactionを定義する。

| Action | 対象操作 |
|---|---|
| `secret.read` | Artifactの検証、復号、`.env`出力 |
| `secret.write` | `add`、`edit`、`delete` |
| `secret.reencrypt` | `sync`、recipient変更後の再暗号化 |
| `secret.restore` | 過去revisionからの復元 |
| `environment.create` | environment作成 |
| `environment.update` | environment設定変更、rename |
| `environment.delete` | environment削除 |
| `member.grant` | member、device、grantの追加 |
| `member.revoke` | member、device、grantの失効 |
| `policy.update` | Policy Artifactの更新 |

actionはCLI command名から独立させる。

GUI、CLI、将来のCloud APIが同じ操作を行う場合も、同じactionを評価する。

### Resource

Policyのresourceはopaque IDで識別する。

```json
{
  "type": "environment",
  "project_id": "01JPROJECT...",
  "environment_id": "01JENV..."
}
```

人間可読なproject名とenvironment名はPolicy判断および永続監査Eventへ使用しない。

### Grant

**Grant**は、Principalへactionとresource scopeを許可するControl State上のdataである。

```json
{
  "grant_id": "01JGRANT...",
  "principal": {
    "issuer": "https://example.okta.com/oauth2/default",
    "subject": "00uabc..."
  },
  "scope": {
    "project_id": "01JPROJECT...",
    "environment_id": "01JENV..."
  },
  "actions": [
    "secret.read",
    "secret.write"
  ],
  "status": "active"
}
```

project全体のgrantでは`environment_id`を省略する。

grantはIdPのgroup情報から自動生成しない。

member管理権限を持つPrincipalが、署名済みControl State更新としてgrantを追加または失効する。

Roleは複数actionをまとめるPolicy上の便宜的な名前として定義できるが、永続的な認可判断は展開後のactionとscopeで表現する。

## Control State

Control Stateはfull snapshotとして保存し、直前revisionのdigestを署名対象に含める。

```json
{
  "schema_version": 1,
  "project_id": "01JPROJECT...",
  "revision": 12,
  "previous_digest": "sha256:PREVIOUS...",
  "policy_digest": "sha256:POLICY...",
  "members": [
    {
      "principal": {
        "issuer": "https://example.okta.com/oauth2/default",
        "subject": "00uabc..."
      },
      "identity_attestation_digest": "sha256:ATTESTATION...",
      "device_key_ids": ["sha256:DEVICE..."],
      "age_recipient_ids": ["sha256:AGE..."],
      "status": "active"
    }
  ],
  "grants": []
}
```

Control Stateはproject genesisでpinしたroot keyから検証する。

Registry tagは最新revisionを探すcacheとして扱い、tagが指す内容自体は信頼しない。

端末は検証済みrevisionとdigestをhigh-water markとして保存し、観測済みrevisionへのrollbackを拒否する。

## Policy Artifact

Policy ArtifactはOCI ArtifactとしてRegistryへ保存する。

payloadにはOPA Bundleを格納する。

OPA Bundleには次のfileを含める。

```text
.manifest
policy/authz.rego
data.json
```

Policy ArtifactはDevice Signing KeyでDSSE署名し、Sigstore Bundle v0.3を同梱する。

署名形式と鍵解決は[Secret Artifactの整合性と監査ログ](./audit.md)と共通化する。

enbu CoreはSigstore署名、発行者の`policy.update`権限、payload digest、project ID、revision chainを検証してからOPAへloadする。

OPA固有のBundle署名は使用しない。

OPAへ渡す前にenbu CoreがSigstoreとControl Stateで同じ性質を検証するため、二つ目の署名方式を導入する必要がない。

Policy Artifactのin-toto Statementは次のmetadataを署名する。

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "enbu:policy-bundle",
      "digest": {
        "sha256": "abc123..."
      }
    }
  ],
  "predicateType": "https://enbu.net/policy/v1",
  "predicate": {
    "project_id": "01JPROJECT...",
    "revision": 7,
    "previous_policy_digest": "sha256:PREVIOUS...",
    "authorizing_control_digest": "sha256:CONTROL...",
    "device_key_id": "sha256:DEVICE...",
    "created_at": "2026-08-30T02:30:00Z"
  }
}
```

`enbu.toml`にはRego source、grant、role、Principalを書かない。

ローカルfileは署名済みPolicy Artifactを作成するための編集用sourceには使えるが、認可の正本にはしない。

## OPA Input

enbu Coreは外部Provider固有fieldを含まないJSONを生成する。

```json
{
  "schema_version": 1,
  "action": "secret.write",
  "actor": {
    "principal": {
      "issuer": "https://example.okta.com/oauth2/default",
      "subject": "00uabc..."
    },
    "device_key_id": "sha256:DEVICE...",
    "identity_attestation_digest": "sha256:ATTESTATION...",
    "status": "active",
    "grants": [
      {
        "scope": {
          "project_id": "01JPROJECT...",
          "environment_id": "01JENV..."
        },
        "actions": ["secret.read", "secret.write"],
        "status": "active"
      }
    ]
  },
  "resource": {
    "type": "environment",
    "project_id": "01JPROJECT...",
    "environment_id": "01JENV..."
  },
  "state": {
    "control_revision": 12,
    "control_digest": "sha256:CONTROL...",
    "policy_revision": 7,
    "policy_digest": "sha256:POLICY..."
  }
}
```

Policy inputには次のfieldを含めない。

- IdP access tokenまたはID token
- username、email、display name
- IdPのteamまたはgroup
- Registry credential
- Transport Principal
- Secret nameまたはSecret value
- environmentの人間可読名
- 信頼できないクライアント申告role

Control StateとPolicy Artifact以外の外部dataを評価時に取得しない。

これにより、同じinput、Policy digest、Control State digestから同じ判断を再現できる。

## Decision Contract

Rego entrypointは`data.enbu.authz.decision`とする。

返り値は次のschemaに固定する。

```json
{
  "allow": false,
  "reason_code": "grant_not_found"
}
```

`allow`が`true`の場合だけ操作を続行する。

decisionが未定義、型不正、評価error、timeoutの場合はdenyとして扱う。

`reason_code`はSecret metadataを含まない安定したcodeとし、人間向けmessageはCLI側で生成する。

## Default Policy

project genesisにはdefault-deny Policy Artifactを必須で作成する。

genesisを作成したPrincipalには、project scopeの管理actionと、最初のenvironmentに対するSecret actionを明示的にgrantする。

```rego
package enbu.authz

import rego.v1

default decision := {
    "allow": false,
    "reason_code": "default_deny",
}

decision := {
    "allow": true,
    "reason_code": "grant_allowed",
} if {
    input.actor.status == "active"
    some grant in input.actor.grants
    grant.status == "active"
    input.action in grant.actions
    grant.scope.project_id == input.resource.project_id
    scope_matches(grant.scope, input.resource)
}

scope_matches(scope, resource) if {
    not object.get(scope, "environment_id", false)
}

scope_matches(scope, resource) if {
    scope.environment_id == resource.environment_id
}
```

Policy未設定を全許可として扱わない。

Policy ArtifactまたはControl Stateを取得または検証できない場合は、Secret操作を開始しない。

## Enforcement Flow

### Secret read

1. IdPで認証し、PrincipalとDevice Signing Keyのbindingを検証する。
2. 最新Control StateとPolicy Artifactを取得して署名、chain、digestを検証する。
3. `secret.read`をOPAで評価する。
4. denyまたは評価errorならRegistryからSecret Artifactを取得せず終了する。
5. allowならSecret Artifactを取得し、署名、`control_digest`、`policy_digest`、revision chainを検証する。
6. Identity Attestationにbindingされたage keyで復号する。
7. 復号成功後に`artifact.pull`監査Eventを生成する。

Registryへの直接アクセスは防げないため、暗号化とArtifact署名をPolicy enforcementから独立して維持する。

### Secret write

1. Principal、Control State、Policy Artifactを検証する。
2. commandに対応するactionをOPAで評価する。
3. denyまたは評価errorなら復号およびpushを行わない。
4. allowなら現在のSecret Artifactを検証して復号する。
5. activeな各memberについて`secret.read`を評価し、allowになったmemberの有効なage recipient集合をControl Stateから構成する。
6. Secretを更新してrecipient集合へ再暗号化する。
7. `control_digest`と`policy_digest`を含むSecret Artifact statementへDevice Signing Keyで署名する。
8. 競合を検査してRegistryへpushする。

`add`、`edit`、`delete`、`sync`、`restore`は同じ発行処理を使用する。

個別commandがRegistryからrecipientを直接列挙して暗号化する実装は認めない。

### MemberとPolicyの更新

`member.grant`、`member.revoke`、`policy.update`は更新前のControl StateとPolicyで評価する。

更新者が新しいPolicyだけを使って自身へ権限を付与することを防ぐためである。

更新後のControl StateまたはPolicy Artifactは、更新前のdigestを含むchainとして署名する。

Policy更新は次の二段階で行う。

1. 現在のControl State `C[n]`とPolicy Artifact `P[n]`で`policy.update`を評価する。
2. allowなら、`authorizing_control_digest = digest(C[n])`を署名した`P[n+1]`を発行する。
3. `policy_digest = digest(P[n+1])`を含む`C[n+1]`を発行する。
4. `C[n+1]`の検証完了後に`P[n+1]`をactiveにする。

`P[n+1]`の発行後にControl State更新が失敗しても、`C[n]`が参照していないPolicyはactiveにならない。

`member.revoke`後は、対象memberを除いたrecipient集合へ最新Secret Artifactを再暗号化する。

再暗号化が完了するまでControl State更新を完了扱いにするかは、未決定事項とする。

## 認可判断の証拠

Secret Artifact statementには次のfieldを含める。

- `actor`を解決できる`device_key_id`
- `control_digest`
- `policy_digest`
- actionに対応する`operation`
- project ID
- environment ID
- generation
- previous Artifact digest

監査時は該当するControl StateとPolicy Artifactを取得し、発行時のinputを再構築してOPA判断を再評価する。

再評価は「そのPolicyがallowを返すこと」を示す。

発行クライアントが実際に同じOPA評価を実行した事実までは証明しない。

Artifact検証器は、署名者が発行時Control Stateで有効な`secret.write`権限を持つことを独立して検証する。

## 暗号化との関係

OPAはPolicy Decision Pointであり、Secretの機密性を暗号学的に強制する機構ではない。

| 性質 | 機構 | 限界 |
|---|---|---|
| 現在のArtifactを復号できる主体 | age recipient | 取得済み平文は回収できない |
| 操作の許可判断 | OPA/Rego | 改造クライアントは評価をskipできる |
| Artifact発行者の検証 | Device署名とControl State | 承認済み署名者の悪意は防げない |
| Policyの改変検知 | Policy署名とdigest chain | 初回端末へのrollbackは完全には防げない |
| Registryへの接続制御 | Registry | Providerごとに保証が異なる |

改造クライアントがOPAをskipしても、有効なDevice Signing Keyを持たなければ検証可能なArtifactを発行できない。

一方、有効なwrite権限と署名鍵を持つ悪意ある利用者は、平文を漏えいできる。

この脅威はclient-side E2E encryptionの信頼境界に含まれる。

## IdP accountの失効

IdP accountの無効化だけでは、既に発行されたIdentity AttestationとDevice Signing Keyを直ちに失効できない。

enbu上のアクセスを止めるにはControl Stateでmemberまたはdeviceをrevokeする。

IdP account状態を定期的に再確認する場合も、IdP groupは認可inputに使わない。

再認証によってIdentity Attestationの有効期限を更新し、期限切れattestationを持つdeviceをPolicyでdenyする。

Identity Attestationの有効期間は未決定事項とする。

## 設定とCLI

`enbu.toml`はローカル表示および出力設定だけを保持する。

```toml
version = "v2alpha1"
default_env = "dev"

[env.dev]
id = "01JENV..."
output = ".env.local"
```

認可管理には次のCLIを想定する。

```bash
enbu member add --principal <issuer>#<subject>
enbu member revoke --principal <issuer>#<subject>
enbu grant add --principal <issuer>#<subject> --env <env> --action secret.read
enbu grant revoke --grant <grant-id>
enbu policy export
enbu policy test
enbu policy apply <directory>
enbu policy verify
```

`policy apply`はlocal sourceをtestし、現在の`policy.update`権限を確認して署名済みPolicy Artifactを発行する。

`policy test`はtable-driven testを必須で実行し、testが一件もないPolicyを既定では拒否する。

## Failure Behavior

次の場合はfail-closedとする。

- Principalを認証できない。
- Identity Attestationを検証できない。
- Control StateまたはPolicy Artifactを取得できない。
- 署名、digest、chain、schemaを検証できない。
- OPA decisionがdeny、未定義、型不正になる。
- OPA評価がerrorまたはtimeoutになる。
- Artifactの`control_digest`または`policy_digest`が検証対象と一致しない。
- 対象actionまたはresource typeが未知である。

監査Event sinkの障害だけは認可結果を変更せず、[監査設計](./audit.md)に従って警告する。

## 代替案

### IdP groupを直接Rego inputへ渡す

採用しない。

IdPごとにgroup semantics、取得API、freshness、pagination、availabilityが異なり、同じPolicyの判断を再現できないためである。

IdP groupとの同期機能を将来追加する場合は、Control Stateへのgrant提案を生成する補助機能とし、自動的な認可の正本にはしない。

### `enbu.toml`をPolicyの正本にする

採用しない。

ローカルfileの編集者が署名済み履歴を経ずに認可規則を変更できるためである。

### Registry permissionを認可として使う

採用しない。

Registry permissionはTransport Principalへ適用され、IdPが認証したPrincipalと一致する保証がないためである。

### 組み込みroleだけを提供する

採用しない。

実装は単純になるが、environment単位のaction、二者承認、期限付きgrantなどの要件を表現できない。

default Policyとtemplateは提供するが、判断はRego entrypointへ統一する。

### OPAをserverとして必須にする

OSSでは採用しない。

enbu単体利用のために常駐serviceを要求すると運用負荷が増えるため、Go SDKによる組み込み評価を既定とする。

Cloudは同じinputとdecision contractを使う限り、sidecarまたはserverとして実行できる。

### OPA Bundle署名をそのまま信頼する

採用しない。

Control State、Secret Artifact、Audit EventがSigstore BundleとDevice Signing Keyを使うため、OPA固有の署名鍵を追加するとtrust rootと失効手順が二重になる。

## 懸念点

### 悪意あるwrite権限保持者

write権限保持者は復号した平文を任意の相手へ渡せる。

また、age ciphertextだけから全recipientを第三者が列挙してPolicyと照合することは難しい。

署名済みArtifactは発行者と宣言metadataを検証できるが、悪意ある発行者が宣言と異なるrecipientへ暗号化していないことまでは証明しない。

高い保証が必要な環境ではhardware-backed key、複数署名、Cloud上の承認workflowを検討する。

### IdP失効の反映遅延

Identity Attestationを長期間有効にすると、IdP account無効化後もDevice Keyを使用できる期間が延びる。

短くすると、任意IdPへの再認証頻度とoffline利用への影響が増える。

### Regoの安全性と互換性

Rego builtinには時刻、network、nondeterministicな入力へ依存できるものがある。

監査時に判断を再現するには、許可するbuiltin、Rego version、評価timeout、memory limitを固定する必要がある。

Policy Artifactのmanifestでこれらのruntime条件を宣言し、enbu Coreが未対応条件を拒否する。

### 管理者のlockout

誤ったPolicy更新または最後の管理grantの失効により、以後のPolicy修正ができなくなる可能性がある。

適用前validationで最低一つの有効な管理経路が残ることを検査する。

root keyによるrecoveryを許可するかは未決定である。

## 未決定事項

| 項目 | 今決めない理由 | 決定時期 | ブロッカー |
|---|---|---|---|
| Identity Attestationの有効期間 | IdPごとの再認証UXを検証していない | IdP PoC後 | Identity実装 |
| `member.revoke`と再暗号化のatomicity | 大規模Artifactでの所要時間が未計測 | re-encryption計測後 | revoke実装 |
| root recoveryと署名threshold | 個人利用と組織利用で要件が異なる | genesis設計時 | Control State実装 |
| 許可するRego builtin一覧 | Go SDKとWasmの互換性を未検証 | OPA PoC後 | Policy Artifact実装 |
| Policy evaluation timeout | Policy規模と端末性能が未計測 | benchmark後 | なし |
| IdP groupからgrant提案を作る同期機能 | Core認可には不要である | Provider拡張時 | なし |

## 実装と移行

1. 現行config parserで未知の`policy` fieldをerrorにし、未実装Policyが有効だと誤認されないようにする。
2. Principal、Identity Attestation、Control State、Device Signing Keyを実装する。
3. action、resource、decisionのschemaをGo typeとJSON Schemaで固定する。
4. default-deny Regoとtable-driven testを作成する。
5. OPA Go SDKを組み込み、deny、未定義、error、timeoutをfail-closedで処理する。
6. Policy Artifactの署名、push、pull、verificationを実装する。
7. すべてのSecret操作を共通Policy Enforcement Pointへ移す。
8. Secret Artifactへ`control_digest`と`policy_digest`を署名する。
9. member、grant、Policy更新CLIを実装する。
10. unsigned Artifactとusername由来recipient tagをsigned v2へ移行する。

一度signed Control StateとPolicy Artifactを観測したprojectでは、unsigned PolicyまたはローカルPolicyへのfallbackを拒否する。

## 検証計画

- IdPを変更しても同じPrincipal schemaとRego testが動作することを確認する。
- Registry credentialとPrincipalが異なる構成で判断が変わらないことを確認する。
- `add`、`edit`、`delete`、`sync`、`restore`が共通Enforcement Pointを通ることを確認する。
- deny、未定義、Rego compile error、runtime error、timeoutをfail-closedで確認する。
- Policy Artifact、Control State、Secret Artifactのdigest差し替えを拒否することを確認する。
- 観測済みPolicyおよびControl Stateへのrollbackを拒否することを確認する。
- revoke後のArtifactが失効recipientを通常のclientで復号できないことを確認する。
- Policy inputとdecision logにSecret名、Secret値、username、email、tokenが含まれないことを確認する。
- GitHub TeamまたはIdP group APIを呼び出さないことをtest doubleで確認する。

## 決定事項

- IdPはPrincipalの認証だけを担当する。
- 認可はOPA/Regoで判断する。
- member、grant、Policy digestは署名済みControl Stateで管理する。
- GitHub Team、IdP group、repository permissionはCore認可に使用しない。
- Registry credentialとTransport Principalは認可inputに使用しない。
- Policy ArtifactはOPA Bundleをpayloadとし、Sigstore Bundleで署名する。
- enbu CoreをPolicy Enforcement Pointとし、全Secret発行経路でfail-closedにする。
- Policy未設定はdefault denyとする。
- Secret ArtifactへControl State digestとPolicy digestを署名する。
- OSSとCloudでinput schema、decision contract、Policy Artifact形式を共通化する。

## 参考資料

- [Open Policy Agent](https://www.openpolicyagent.org/docs)
- [OPA Policy Language](https://www.openpolicyagent.org/docs/policy-language)
- [OPA Bundles](https://www.openpolicyagent.org/docs/management-bundles)
- [Integrating OPA](https://www.openpolicyagent.org/docs/integration)
