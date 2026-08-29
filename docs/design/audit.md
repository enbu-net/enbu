# Secret Artifactの整合性と監査ログ

## Status

- 状態: Draft
- 更新日: 2026-08-30
- 対象: enbu OSS
- 将来対象: enbu Cloud

## 背景

enbuではIdPとOCI Registryを独立して選択する。

認証した本人とRegistryへ接続した主体は一致するとは限らない。

例えば、Oktaで本人認証を行い、AWS IAM RoleでECRへ接続する構成がある。

Secret名や環境名は値そのものではないが、利用サービス、インフラ構成、重要なcredentialを推測できる機密metadataである。

本設計では、Secret Artifactの整合性と操作監査を別の問題として定義し、必要なmetadataだけを署名する。

## 目的

優先順位は次のとおりとする。

1. Registryから取得したSecret Artifactが、承認されたPrincipalによって発行され、取得までに改変されていないことを復号前に検証する。
2. どのPrincipalが、どのArtifact revisionを発行または復号したかを、Secret名を記録せずに調査できるようにする。
3. IdPとRegistryの組み合わせに依存しないEvent schemaと検証手順を定義する。
4. OSSとCloudでArtifact形式と検証Coreを共通化し、運用上の保証だけを分ける。

## 対象外

本設計だけでは、次の性質を保証しない。

- 取得後にローカルへ出力された平文`.env`が変更されていないこと
- OSSクライアントがすべてのアクセスEventを送信したこと
- 悪意のある承認済み署名者が不正なSecretを発行しないこと
- 初回利用端末に古いControl StateとArtifactを同時に提示する攻撃の完全な検知
- 任意の外部Registryが十分なアクセスログを保存すること
- SOC 2やISO 27001への準拠そのもの

ローカル`.env`の改変検知は、出力時のbyte digestを保持して再検証する別機能として扱う。

Secret Artifactの署名は、取得した暗号化Artifactから生成された`.env`の出所を保証するが、生成後のファイル監視にはならない。

## 用語

**Principal**は、enbu上で操作した本人を表すIdP由来の識別子である。

PrincipalはOIDCの`issuer`と`subject`の組で識別する。

```json
{
  "issuer": "https://example.okta.com/oauth2/default",
  "subject": "00uabc..."
}
```

**Transport Principal**は、Registryへ接続するときにcredentialが表す主体である。

Transport Principalは相関用の補助情報であり、アクセス制御と監査上の本人として扱わない。

```json
{
  "provider": "aws",
  "subject": "arn:aws:iam::123456789012:role/enbu-developer"
}
```

**Device Signing Key**は、Principalに紐づく端末固有の署名鍵である。

Secretの復号に使うage X25519鍵とは用途を分離する。

署名鍵には、Rekor v2の`hashedrekord`へ将来登録できるようECDSA P-256を用いる。

**Identity Attestation**は、IdPが認証したPrincipalとDevice Signing Keyを結び付ける署名済みstatementである。

IdP固有のtokenをSecret ArtifactやAudit Eventへ直接埋め込まず、Control Stateが承認済みIdentity Attestationを参照する。

**Control State**は、Principal、Device Signing Key、age recipient、権限、失効状態の対応を保持する署名済み状態である。

**Secret Artifact**は、暗号化したSecret集合と、その内容およびrevision metadataに対するSigstore Bundleを格納したOCI Artifactである。

**Audit Event**は、Artifactの発行、復号、Control Stateの更新など、操作の事実を表す署名済みEventである。

## 設計上の分離

監査で扱う証拠を三つに分ける。

| 証拠 | 答える問い | OSSでの強さ |
|---|---|---|
| Secret Artifact署名 | 取得した暗号文は誰が発行し、改変されていないか | 強い |
| revision chain | 既知の履歴から巻き戻されていないか | 端末が観測した範囲で強い |
| Access Audit Event | 誰がいつ復号したか | best effort |

Artifactの改変検知をAccess Audit EventやRegistryログへ依存させてはならない。

Registryアクセスログが利用できる場合は補助証拠として相関するが、enbu Coreの保証には含めない。

## 信頼の流れ

```text
Identity Provider
      |
      v
  Principal
      |
      v
Identity Attestation
      |
      v
signed Control State
      |
      +---- Device Signing Key
      |
      +---- age recipient

Device Signing Key
      |
      +---- signs Secret Artifact statement
      |
      +---- signs Access Audit Event
```

検証者はSigstore Bundle内の鍵識別子だけを手掛かりにし、公開鍵とPrincipalのbindingは信頼済みControl StateおよびIdentity Attestationから解決する。

Bundleに埋め込まれた未検証の公開鍵を、そのまま信頼してはならない。

Control Stateの起点は、プロジェクト初期化時に明示的にpinしたgenesis digestとする。

## Secret Artifactの署名

### OCI Artifact構造

一つのOCI Image Manifestへ、次の二つのlayerを格納する。

Manifestの`artifactType`は`application/vnd.enbu.secret-artifact.v2`とする。

必須の`config` descriptorには空のJSON object `{}`を使い、次の値を固定する。

| Field | Value |
|---|---|
| `mediaType` | `application/vnd.oci.empty.v1+json` |
| `digest` | `sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a` |
| `size` | `2` |

| Layer | Media type | 内容 |
|---|---|---|
| Secret payload | `application/vnd.enbu.secrets.age.v2` | ageで暗号化したSecret集合 |
| Signature bundle | `application/vnd.dev.sigstore.bundle.v0.3+json` | DSSE署名と検証material |

OCI Referrers APIはRegistryごとの対応差があるため、必須にしない。

検証器は期待したmedia type、layer数、digest、sizeをすべて検証し、未知の必須layerを無視しない。

### 署名対象

Signature BundleをManifest内へ格納するため、OCI Manifest digest自身を同じBundleから署名すると循環参照になる。

そこで、Secret Artifact statementは暗号化payload layerのdigestをsubjectにする。

Manifest digestはOCI Distributionによる取得時のcontent integrityとrevision chainの識別子として使う。

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "enbu:secret-payload",
      "digest": {
        "sha256": "abc123..."
      }
    }
  ],
  "predicateType": "https://enbu.net/secret-artifact/v1",
  "predicate": {
    "project_id": "01JPROJECT...",
    "environment_id": "01JENV...",
    "generation": 42,
    "previous_artifact_digest": "sha256:AAA...",
    "control_digest": "sha256:CONTROL...",
    "policy_digest": "sha256:POLICY...",
    "device_key_id": "sha256:KEY...",
    "operation": "secret.edit",
    "changes": {
      "added": 0,
      "updated": 2,
      "deleted": 0
    },
    "created_at": "2026-08-30T02:30:00Z"
  }
}
```

DSSE envelopeの`payloadType`は`application/vnd.in-toto+json`とする。

Bundleの`verificationMaterial.publicKey.hint`には`device_key_id`を格納する。

公開Rekorへの登録やFulcio証明書は、Artifact形式の必須条件にしない。

Sigstore Bundle v0.3はout-of-bandで配布した公開鍵の識別子と、任意のtransparency log entryを表現できる。

### 発行手順

1. IdPでPrincipalを認証する。
2. 最新のControl Stateを取得して署名とchainを検証する。
3. Control State上でPrincipalの書き込み権限とDevice Signing Keyの有効性を検証する。
4. Secret集合をage recipient群へ暗号化する。
5. 暗号化payloadのdigestを計算する。
6. generation、直前のManifest digest、Control State digestを含むin-toto Statementを生成する。
7. Device Signing KeyでDSSE署名し、Sigstore Bundle v0.3を生成する。
8. payloadとBundleを一つのOCI ManifestとしてRegistryへpushする。
9. push結果のManifest digestを、端末のhigh-water markへ保存する。

### 取得手順

1. RegistryからOCI Manifest、暗号化payload、Sigstore Bundleを取得する。
2. OCI descriptorと実データのdigestおよびsizeが一致することを検証する。
3. pin済みgenesisからControl Stateの署名とchainを検証する。
4. `device_key_id`に対応する公開鍵、Principal、権限、失効状態をControl Stateから解決する。
5. Sigstore BundleとDSSE署名を検証する。
6. Statementのpayload digest、project ID、environment ID、generationが取得対象と一致し、`control_digest`と`policy_digest`が検証済みの発行時stateを参照することを確認する。
7. generationと`previous_artifact_digest`を端末のhigh-water markと比較する。
8. 最新generationからhigh-water markまでに差がある場合は、`previous_artifact_digest`をたどって中間Manifestをdigestで取得し、各署名とchainを順番に検証する。
9. 中間revisionが保持されていない場合はhistory gapとして拒否し、high-water markを更新しない。
10. すべて成功した後にだけageで復号する。
11. `.env`を書き出した後、Access Audit Eventを生成する。

Registryには、検証対象になり得るimmutable revisionを保持する必要がある。

retention期間より長くofflineだった端末の回復手順は未決定事項とする。

署名検証に失敗したArtifactを復号してはならない。

監査Eventの送信失敗はArtifactの検証結果を変えない。

## 検知できる改変

| 事象 | 検知 | 根拠 |
|---|---|---|
| 暗号化payloadのbit改変 | できる | OCI digest、age認証、DSSE署名 |
| Bundle内Statementの改変 | できる | DSSE署名 |
| 未登録鍵によるArtifactの差し替え | できる | Control Stateによる鍵解決 |
| 別環境のArtifactへの差し替え | できる | 署名対象の`environment_id`照合 |
| 観測済みgenerationへの巻き戻し | できる | revision chainとlocal high-water mark |
| 初回端末への一貫した古い履歴の提示 | 完全にはできない | 外部checkpointがないため |
| 承認済み署名者による悪意ある更新 | できない | 有効な権限と署名を持つため |
| 生成後のローカル`.env`の変更 | できない | Artifact検証の境界外であるため |

## Audit Event v2

### Eventの情報源

| Event | 証拠の生成元 | 完全性 |
|---|---|---|
| `artifact.publish` | 署名済みSecret Artifactから導出 | Artifactが残る限り再構成可能 |
| `control.update` | 署名済みControl State statementから導出 | Control Stateが残る限り再構成可能 |
| `artifact.pull` | 復号成功後にクライアントが生成 | OSSではbest effort |

`artifact.publish`と`control.update`のために、同じ事実を表す独立Eventを必須にはしない。

検索用indexは署名済みArtifactとControl Stateから再構築できる派生データとする。

`artifact.pull`だけはArtifactから導出できないため、独立した署名済みAudit Eventとして生成する。

### ActorとTransport Principal

アクセス制御と監査上の本人は常に`actor`である。

`transport`はRegistryログとの相関に必要で、credential providerが安定した識別子を取得できる場合だけ記録する。

クライアント生成Eventの`transport`は自己申告である。

CloudのRegistry gatewayが生成したEventでは、gatewayが観測した値として扱える。

### pull Event

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "enbu:environment:01JENV...",
      "digest": {
        "sha256": "abc123..."
      }
    }
  ],
  "predicateType": "https://enbu.net/audit/v2",
  "predicate": {
    "event_id": "0198f8cf-53cb-7b9a-9fd6-4e89c0c7881f",
    "event": "artifact.pull",
    "source": "client",
    "actor": {
      "issuer": "https://example.okta.com/oauth2/default",
      "subject": "00uabc..."
    },
    "transport": {
      "provider": "aws",
      "subject": "arn:aws:iam::123456789012:role/enbu-developer"
    },
    "device_key_id": "sha256:KEY...",
    "project_id": "01JPROJECT...",
    "environment_id": "01JENV...",
    "generation": 42,
    "authorization_control_digest": "sha256:CONTROL...",
    "authorization_policy_digest": "sha256:POLICY...",
    "occurred_at": "2026-08-30T02:30:00Z"
  }
}
```

Audit Eventのsubject digestは、取得したOCI Manifest digestとする。

`authorization_control_digest`と`authorization_policy_digest`は、pull時の現在認可に使用したstateを表す。

Artifact発行時のstateは、subjectのSecret Artifact statementから取得する。

EventはDevice Signing KeyでDSSE署名し、Sigstore Bundle v0.3として保存または送信する。

`event_id`にはUUIDv7を用いる。

全Eventを直列化するためのグローバル連番は導入しない。

Artifactの順序は`environment_id`ごとのgenerationと`previous_artifact_digest`で表現する。

受信側が付与する`received_at`や保存先のobject keyは、署名対象Eventとは別のingestion metadataとする。

クライアントの`occurred_at`は署名者が申告した時刻であり、信頼できる時刻証明ではない。

Control State statementの`created_at`も署名者が申告した時刻であり、transparency logまたは信頼できるtimestampがなければ同じ制約を持つ。

### publish Eventの表示モデル

検索時はSecret Artifact statementから次の論理Eventを導出する。

```json
{
  "event": "artifact.publish",
  "operation": "secret.edit",
  "actor": {
    "issuer": "https://example.okta.com/oauth2/default",
    "subject": "00uabc..."
  },
  "project_id": "01JPROJECT...",
  "environment_id": "01JENV...",
  "generation": 42,
  "previous_artifact_digest": "sha256:AAA...",
  "result_artifact_digest": "sha256:BBB...",
  "changes": {
    "added": 0,
    "updated": 2,
    "deleted": 0
  },
  "occurred_at": "2026-08-30T02:30:00Z"
}
```

`operation`と`changes`はArtifact statementに署名し、Secret名は記録しない。

`changes`は復号後のSecret mapを比較して得た件数であり、値や名前を含まない。

### 永続化するfield

- Event type
- Principalの`issuer`と`subject`
- 任意のTransport Principal
- Device Signing Key ID
- project ID
- environment ID
- Artifact digest
- generation
- Control State digest
- Policy Artifact digest
- previous digestとresult digest
- 変更件数
- Event発生時刻
- Event ID

### 永続化しないfield

- Secret value
- Secret name
- IdPのusername、display name、email
- 環境の人間可読名
- OAuth token
- Registry credential
- 不要な完全Registry URL
- `.env`の平文digest

`secret_names = full | minimal`という設定は設けない。

Secret名は常に永続監査ログへ記録しない。

CLI表示時だけ、ローカル`enbu.toml`のenvironment ID mappingからopaque IDを人間可読名へ解決する。

mappingが存在しない端末ではopaque IDをそのまま表示する。

## OSSの保存と保証

enbu OSSは監査基盤をホストしない。

署名済み`artifact.pull` Eventは、設定されたsinkがあれば送信する。

sinkがなければ、組織全体のアクセス履歴が存在するとは主張しない。

送信失敗時はSecret操作自体を成功扱いとし、記録されなかったことを明示的に警告する。

```text
Warning: the operation succeeded, but the audit event was not recorded.
```

OSSで保証できるのはEvent一件の署名者と内容の非改変であり、Event集合の完全性ではない。

Public FulcioとPublic Rekorは既定の依存にしない。

必要な利用者は、Sigstore Bundleの任意のtransparency log entryとしてPublic Rekorや別のlogを使用できる。

ただし、公開logへ登録するdigest、署名、公開鍵、証明書identityが公開情報になる可能性を利用者へ明示する。

## Cloudで追加できる保証

Cloudの詳細設計は本Design Docの対象外とする。

同じEvent schemaと検証Coreを使い、将来次の保証を追加できるようにする。

- enbu Cloud IdPがPrincipalを認証する。
- 管理対象Registryまたはgatewayがpullとpushをサーバー側で観測する。
- 成功および拒否Eventをサーバー署名する。
- append-only object storageへ原本Bundleを保存する。
- transparency logまたは署名checkpointでEvent集合の削除とforkを検知する。
- 検索indexを原本から再構築できる派生データとして運用する。

Cloudであっても、検索DBを証拠の正本にしない。

採番だけを目的とするRDBは不要である。

Event IDはUUIDv7、Artifact順序はenvironment単位のgeneration、log順序はtransparency logの位置で表現できる。

## CLI

想定する操作は次のとおりとする。

```bash
enbu verify
enbu audit list
enbu audit export
enbu audit verify <bundle>
```

`enbu verify`は、取得済みSecret ArtifactのOCI digest、Sigstore Bundle、Control State binding、revision chainを検証する。

ローカル`.env`自体のbyte比較はMVPに含めない。

`enbu audit list`は利用可能なsinkまたはCloud APIを検索し、IDの表示名を権限確認後に解決する。

`enbu audit export`は署名済みBundleをそのまま出力する。

`enbu audit verify`は保存先を信頼せず、Bundle、署名鍵binding、必要なtransparency proofを検証する。

## 代替案

### 毎回Fulcioでkeyless署名する

採用しない。

任意のIdPがPublic Fulcioで受理されるとは限らず、通常操作とは別のOIDC flowが必要になる。

短命証明書を期限後に検証するには、署名時刻を裏付けるtransparency log entryまたはRFC 3161 timestampも必要になる。

enbuではPrincipalとDevice Signing KeyのbindingをControl Stateで管理し、ArtifactとEventの署名方式をIdPから分離する。

### すべてのEventをPublic Rekorへ送る

既定では採用しない。

外部から観測可能なmetadataが増え、公開サービスの可用性と利用規約へ依存するためである。

また、Public Rekorへ登録しても、改造クライアントがpull Eventを送信しない問題は解決しない。

### Registryアクセスログをbackstopにする

採用しない。

ログ内容、保持期間、契約plan、actor表現、耐改変性がRegistryごとに異なるためである。

利用できる場合だけ相関用の補助証拠として扱う。

### Secret名をHMAC化して記録する

採用しない。

辞書攻撃が可能で、鍵管理が増え、Artifact単位で調査する設計に不要だからである。

### OCI Referrersで署名を分離する

MVPでは採用しない。

Manifest digest自体を署名できる利点はあるが、Registry互換性、Artifactと署名の取得一貫性、push途中の状態管理が増えるためである。

## 懸念点

### Control Stateが新しい信頼の中心になる

Artifact署名が正しくても、攻撃者がControl Stateを差し替えられると不正な鍵を承認できる。

genesis pin、署名chain、失効、端末high-water markの実装と回復手順を先にPoCする必要がある。

### Registryの更新がatomic compare-and-swapではない

現在のdigest precheck後に競合pushが発生すると、二つの正当なrevisionがforkする可能性がある。

署名とgenerationだけではlost updateを防げないため、対象Registryごとの条件付き更新能力を確認する必要がある。

### Access Audit Eventの完全性はOSSで保証できない

改造クライアント、端末侵害、Event送信失敗によりpull Eventを欠落させられる。

この制約は暗号署名やPublic Rekorだけでは解消できない。

### 署名鍵の窃取

Device Signing Keyが盗まれると、失効が反映されるまで正当なPrincipalとしてArtifactやEventを署名できる。

OS keyring、hardware-backed key、失効伝播時間の要件を実装前に評価する。

### metadataの相関

opaque IDだけでも、時刻、頻度、Artifact size、digestの外部相関から利用状況を推測される可能性がある。

公開transparency logを有効にする場合は、この漏えいを明示的に許容する必要がある。

## 未決定事項

| 項目 | 今決めない理由 | 決定時期 |
|---|---|---|
| ローカル`.env`のmaterialization receipt | Artifact整合性とは別の脅威境界である | `enbu verify`実装前 |
| revision retention後の端末回復 | transparency logまたは信頼できるcheckpointの要件が未確定である | revision storage PoC後 |
| OSSの標準Audit sink protocol | Cloud以外の運用要件が未検証である | Access Audit実装前 |
| Public Rekorを利用するCLI option | privacyとRekor v2 client対応を実測していない | Artifact署名PoC後 |
| Cloudのobject formatと検索index | Cloudは現時点の主対象ではない | Cloud監査基盤設計時 |
| RFC 3161 timestampの必須化 | 永続Device Keyでは証明書期限の問題がなく、必要な時刻保証が未確定である | compliance要件確定時 |
| 鍵のhardware-backed化 | OSと企業要件ごとの互換性が未検証である | keystore PoC時 |

未決定事項はArtifact schemaを分岐させない。

追加の証明はSigstore Bundleのverification materialまたはCloudのassurance policyとして表現する。

## 実装順序

1. Principal、Device Signing Key、Control Stateのmodelと検証器を実装する。
2. 暗号化payloadとSigstore Bundleを同梱するOCI ArtifactをPoCする。
3. GHCR、ECR、Harbor、GitLab Registryでpush、pull、競合、未知layerの挙動を検証する。
4. 復号前のArtifact検証を必須化する。
5. 署名済み`artifact.pull` Eventとsink interfaceを実装する。
6. ArtifactとControl Stateから監査表示modelを導出する。
7. rollback、fork、失効、鍵窃取、欠落Eventのscenario testを追加する。
8. unsigned v1 Artifactからsigned v2 Artifactへの移行規則を実装する。

一度signed v2 Artifactを観測したenvironmentでは、unsigned v1 Artifactへのfallbackを拒否する。

## 参考資料

- [Sigstore Bundle Format](https://docs.sigstore.dev/about/bundle/)
- [sigstore-go signing](https://github.com/sigstore/sigstore-go/blob/main/docs/signing.md)
- [Rekor v2 client guidance](https://github.com/sigstore/rekor-tiles/blob/main/CLIENTS.md)
- [OpenID Connect Core 1.0, Subject Identifier Types](https://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes)
- [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- [OCI Image Manifest Specification](https://github.com/opencontainers/image-spec/blob/main/manifest.md)
