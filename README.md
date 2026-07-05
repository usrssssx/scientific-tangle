# R&D Knowledge Map MVP для горно-металлургических исследований

Это локальный MVP единой карты знаний R&D. Он создан для демонстрации логики решения на тестовых данных: документы, эксперименты, эксперты, извлечение сущностей и числовых ограничений, граф связей, поиск и структурированный ответ с источниками.

## Что уже есть в MVP

- тестовый корпус документов на русском и английском;
- тестовый каталог экспериментов и экспертов;
- словари материалов, процессов, оборудования, свойств, географии и синонимов;
- импорт `.md`, `.txt`, `.pdf`, `.docx`, `.docm`, `.pptx`, `.xlsx`, `.csv`, `.json`, `.zip`;
- capability-aware импорт legacy `.doc`, `.ppt` через LibreOffice/`soffice`, legacy `.xls` через `xlrd`/`soffice` fallback и `.rar` через `unrar`;
- magic-byte диагностика mislabeled image files независимо от расширения;
- reconstruction split ZIP архивов `.zip.001/.zip.002` с индексированием только первого тома;
- optional OCR hook для image-only PDF через OCRmyPDF sidecar, если `ocrmypdf` установлен;
- поддержка AES-encrypted PDF через `pypdf` + `cryptography`;
- SQLite-хранилище с FTS5-поиском и локальным hybrid retrieval: BM25/LIKE + deterministic hashed embeddings + metadata/ABAC filters;
- извлечение сущностей: Material, Process, Equipment, Property, Geography;
- извлечение числовых условий: диапазоны, ограничения `≤`, `<`, `≥`, единицы `мг/л`, `м/с`, `%`, `руб/м3`, `USD/m3`;
- строгая фильтрация числовых фактов в `/search` через `numeric_filters` + `strict_numeric_filters`, включая конвертацию совместимых единиц;
- графовые связи: `describes`, `uses_material`, `uses_equipment`, `validated_by`, `recommended_sequence_contains`;
- онтология классов/отношений, JSON-LD context, unit ontology и production storage target в `data/ontology/rd_ontology.json`;
- readiness-check `/ready`;
- manifest batch-ingest в таблице `ingest_files` с resume, checksum-dedupe, progress output и per-file commit;
- статусы и версии фактов, журнал экспертной проверки `fact_reviews`;
- evidence locator/span, `document_id`, `extractor_version`, validation status/warnings и `evidence_pack` в search response;
- answer modes для `/search`: `auto`, `review`, `comparison`, `protocol`, `gap_analysis`, `evidence_table`;
- сохранение простых XLS/XLSX/CSV таблиц в `document_tables`;
- extraction gold set и evaluator для entity/numeric/relation precision/recall/F1;
- API и UI для verify/reject/comment фактов и merge/split сущностей;
- API на FastAPI;
- Streamlit-интерфейс с поиском, answer modes, numeric filters, manager dashboard, graph view и curation panel;
- RBAC/ABAC-заготовка через заголовки `X-Role`, `X-Department`, `X-Project`, `X-Clearance`, `X-Subject` и opt-in OIDC-compatible Bearer JWT mode с HS256 dev mode, RS256 JWKS/discovery validation, AD/IdP group-to-role mapping и SCIM-compatible directory lifecycle с Bulk operations;
- optional API key через `RD_KG_API_KEY`;
- централизованная in-app action policy для endpoint-level RBAC с admin endpoints `/security/policy` и `/security/policy/decisions`, optional external policy engine hook, service auth/mTLS и policy decision audit;
- internal security review gate с local/production profiles через `scripts/security_review.py`, внешним sign-off/evidence metadata validator и admin endpoint `/security/review`;
- role-aware DLP для search/export/ready/audit без маскирования технических диапазонов как телефонов;
- export DLP content inspection rule engine для Markdown/CSV/PDF/ZIP/JSON-LD/RDF: regex rules могут flag, require approval или block, findings пишутся в audit без сырого совпадения;
- classification-aware export policy для `public/internal/confidential/secret`: `secret` можно просматривать с роли `manager`, но выгрузка через export endpoints требует роль `admin` либо одноразовый approved export approval; policy decision, DLP findings и approval flow пишутся в audit;
- optional AES-GCM field-level encryption at rest для source path/abstract, audit details/object ids, export approval justification/review comments и expert contacts через `RD_KG_FIELD_ENCRYPTION_KEY`, плюс production storage-encryption gate `/security/storage-encryption`;
- in-process request metrics на `/metrics` и Prometheus text endpoint `/metrics/prometheus` для роли `admin`;
- OpenTelemetry-compatible HTTP tracing: `traceparent` propagation, `X-Trace-Id`, structured span logs, optional OTLP/HTTP JSON export и Prometheus counters по spans/export;
- deployable observability bundle: Prometheus, OpenTelemetry Collector, Tempo, Loki/Promtail и Grafana dashboard;
- structured JSON request logs;
- readiness cache и SQLite performance indexes для рабочих search/curation endpoint’ов на текущей БД;
- backfill локальных document embeddings через `scripts/build_document_embeddings.py` для hybrid retrieval на уже загруженном корпусе;
- SQLite backup/restore helper с SHA-256 sidecar, AES-GCM encrypted `.sqlite.enc` backups, scheduled backup plan, retention и restore-drill;
- аудит поисковых запросов, загрузок и экспортов;
- экспорт ответа в Markdown, графа в JSON-LD и RDF/Turtle с role-aware фильтрацией доступа.

## Быстрый старт без Docker

```bash
cd rd_knowledge_mvp
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
python3 -m app.seed_data
uvicorn app.main:app --reload --port 8000
```

UI во втором терминале:

```bash
cd rd_knowledge_mvp
source .venv/bin/activate
streamlit run ui/streamlit_app.py --server.port 8501
```

Откройте:

- API: `http://localhost:8000/docs`
- Ready-check: `http://localhost:8000/ready`
- UI: `http://localhost:8501`

## Быстрый старт через Docker Compose

```bash
docker compose up --build
```

После запуска:

- API: `http://localhost:8000/docs`
- UI: `http://localhost:8501`

## Примеры API-запросов

```bash
curl -X POST http://localhost:8000/search \
  -H "Content-Type: application/json" \
  -H "X-Role: researcher" \
  -d '{
    "query": "Какие методы обессоливания воды подходят для обогатительной фабрики, если сульфаты 200-300 мг/л и сухой остаток ≤1000 мг/дм³?",
    "top_k": 5
  }'
```

Строгая числовая фильтрация оставляет в блоке `facts` только факты, пересекающиеся с заданными числовыми условиями:

```bash
curl -X POST http://localhost:8000/search \
  -H "Content-Type: application/json" \
  -H "X-Role: researcher" \
  -d '{
    "query": "сухой остаток tds для воды",
    "answer_mode": "evidence_table",
    "numeric_filters": [
      {"property": "tds", "comparator": "<=", "value": 1.0, "unit": "g_l"}
    ],
    "strict_numeric_filters": true,
    "top_k": 5
  }'
```

Для `answer_mode` можно передать `auto`, `review`, `comparison`, `protocol`, `gap_analysis` или `evidence_table`. В режиме `auto` система выбирает формат по intent запроса и найденным пробелам.

```bash
curl -X POST http://localhost:8000/graph \
  -H "Content-Type: application/json" \
  -H "X-Role: researcher" \
  -d '{"entity":"catholyte_circulation", "depth":2, "limit":80}'
```

```bash
curl http://localhost:8000/ontology
```

```bash
curl http://localhost:8000/metrics \
  -H "X-Role: admin"
```

```bash
curl http://localhost:8000/metrics/prometheus \
  -H "X-Role: admin"
```

OpenTelemetry-compatible tracing:

```bash
export RD_KG_OTEL_EXPORTER_OTLP_ENDPOINT="http://otel-collector:4318/v1/traces"
export RD_KG_OTEL_SERVICE_NAME="rd-knowledge-mvp"
export RD_KG_OTEL_EXPORT_TIMEOUT_SECONDS=2
```

Middleware принимает входящий `traceparent`, возвращает `X-Trace-Id` и новый `traceparent`, пишет `trace_id/span_id/parent_span_id` в JSON request log, считает `rdkg_trace_spans_total` и `rdkg_trace_export_total` в `/metrics/prometheus`, а при указанном endpoint отправляет OTLP/HTTP JSON traces.

Production-style observability bundle:

```bash
export RD_KG_OIDC_HS256_SECRET="change-me-observability-secret"
python3 scripts/generate_metrics_jwt.py --output ops/observability/secrets/rdkg_metrics.jwt
python3 scripts/validate_observability_bundle.py
docker compose -f ops/observability/docker-compose.yml up -d
```

Для app process:

```bash
mkdir -p logs
export RD_KG_OTEL_EXPORTER_OTLP_ENDPOINT="http://127.0.0.1:4318/v1/traces"
export RD_KG_OTEL_SERVICE_NAME="rd-knowledge-mvp"
uvicorn app.main:app --port 8000 2>&1 | tee -a logs/rdkg-api.jsonl
```

Prometheus читает `/metrics/prometheus` через Bearer JWT из `ops/observability/secrets/rdkg_metrics.jwt`; Grafana доступна на `http://localhost:3000` и provisioned dashboard называется `RD Knowledge Overview`.

```bash
curl http://localhost:8000/security/policy \
  -H "X-Role: admin"
```

```bash
curl "http://localhost:8000/curation/facts/pending?limit=10" \
  -H "X-Role: analyst"
```

```bash
curl -X POST http://localhost:8000/curation/facts/1/review \
  -H "Content-Type: application/json" \
  -H "X-Role: analyst" \
  -d '{"action":"verify","comment":"Проверено экспертом","reviewer":"expert-name"}'
```

```bash
curl -X POST http://localhost:8000/curation/facts/bulk-review \
  -H "Content-Type: application/json" \
  -H "X-Role: analyst" \
  -d '{"fact_ids":[1,2,3],"action":"verify","comment":"Пакетная проверка","reviewer":"expert-name"}'
```

```bash
curl -X POST http://localhost:8000/curation/facts/assign \
  -H "Content-Type: application/json" \
  -H "X-Role: analyst" \
  -d '{"fact_ids":[1,2,3],"assignee":"expert-a","reviewer":"lead","due_at":"2026-07-10"}'
```

```bash
curl "http://localhost:8000/curation/facts/pending?limit=10&assignee=expert-a" \
  -H "X-Role: analyst"
```

```bash
curl "http://localhost:8000/dashboard" \
  -H "X-Role: manager"
```

```bash
curl "http://localhost:8000/curation/facts/1/history" \
  -H "X-Role: analyst"
```

```bash
curl -X POST http://localhost:8000/curation/facts/1/dispute \
  -H "Content-Type: application/json" \
  -H "X-Role: analyst" \
  -d '{"reason":"Конфликтует с лабораторным протоколом","severity":"high","reviewer":"expert-name","assignee":"lead","due_at":"2026-07-10 18:00:00","comment":"Нужна повторная проверка evidence"}'
```

```bash
curl "http://localhost:8000/curation/disputes?limit=10" \
  -H "X-Role: analyst"
```

```bash
curl -X POST http://localhost:8000/curation/disputes/1/resolve \
  -H "Content-Type: application/json" \
  -H "X-Role: analyst" \
  -d '{"reviewer":"lead","resolution":"Факт отклонён после проверки источника","fact_status":"rejected"}'
```

```bash
curl -X POST http://localhost:8000/curation/facts/1/supersede \
  -H "Content-Type: application/json" \
  -H "X-Role: analyst" \
  -d '{"replacement_fact_id":2,"reviewer":"expert-name","comment":"Новая версия факта"}'
```

```bash
curl -X POST http://localhost:8000/curation/entities/merge \
  -H "Content-Type: application/json" \
  -H "X-Role: analyst" \
  -d '{"survivor_id":1,"duplicate_id":2,"reviewer":"expert-name","comment":"same entity"}'
```

```bash
curl -X POST http://localhost:8000/curation/entities/split \
  -H "Content-Type: application/json" \
  -H "X-Role: analyst" \
  -d '{"source_entity_id":1,"new_type":"Material","new_name":"nickel_ore","aliases":["никелевая руда"],"move_fact_ids":[],"move_edge_ids":[]}'
```

```bash
curl "http://localhost:8000/export/markdown?query=циркуляция%20католита%20никель"
```

```bash
curl "http://localhost:8000/export/table?query=циркуляция%20католита%20никель" \
  -H "X-Role: researcher"
```

```bash
curl "http://localhost:8000/export/pdf?query=циркуляция%20католита%20никель" \
  -H "X-Role: researcher" \
  -o rdkg-evidence-report.pdf
```

```bash
curl "http://localhost:8000/export/report-package?query=циркуляция%20католита%20никель" \
  -H "X-Role: researcher" \
  -o rdkg-report-package.zip
```

```bash
curl http://localhost:8000/export/rdf \
  -H "X-Role: researcher"
```

Sensitive export approval flow:

```bash
curl -X POST http://localhost:8000/export/approvals \
  -H "Content-Type: application/json" \
  -H "X-Role: manager" \
  -d '{"export_format":"pdf","query":"secret metallurgy protocol","justification":"One-time board pack export"}'

curl -X POST http://localhost:8000/export/approvals/1/approve \
  -H "Content-Type: application/json" \
  -H "X-Role: admin" \
  -d '{"reviewer":"security-admin","comment":"Approved for one-time export"}'

curl "http://localhost:8000/export/pdf?query=secret%20metallurgy%20protocol&approval_id=1" \
  -H "X-Role: manager" \
  -o rdkg-approved-export.pdf
```

## Загрузка своих данных

Для небольшого архива или отдельного файла:

```bash
curl -X POST http://localhost:8000/ingest/upload \
  -H "X-Role: analyst" \
  -F 'metadata_json={"source_type":"internal_report","confidentiality":"internal","reliability_score":0.7}' \
  -F "file=@your_archive.zip"
```

Для большого архива 4 ГБ лучше сначала распаковать его на сервере и запустить локальный ingest папки:

```bash
curl -X POST "http://localhost:8000/ingest/local-folder?folder_path=/data/real_corpus" \
  -H "X-Role: admin" \
  -H "Content-Type: application/json" \
  -d '{"source_type":"internal_report","confidentiality":"internal","reliability_score":0.6}'
```

Для production-версии большой архив не надо грузить синхронно через API: нужен объектный storage, очередь задач и асинхронный ETL.

## Доступ и DLP

Локальная модель доступа по умолчанию использует HTTP headers:

- `X-Role`: `external_partner`, `researcher`, `manager`, `analyst`, `admin`;
- `X-Department`: отдел пользователя;
- `X-Project`: проект пользователя;
- `X-Clearance`: дополнительный уровень допуска.
- `X-Subject`: stable subject/user id для локального directory lifecycle режима.

Для identity-backed режима можно включить OIDC-compatible Bearer JWT validation. В локальном dev-режиме поддержан HS256-подписанный JWT с `iss`, `aud`, `exp`/`nbf`/`iat` и claims роли/ABAC:

```bash
export RD_KG_OIDC_REQUIRED=true
export RD_KG_OIDC_HS256_SECRET="change-me"
export RD_KG_OIDC_ISSUER="https://issuer.example"
export RD_KG_OIDC_AUDIENCE="rdkg"
```

Для пилотного OIDC/SSO-режима используйте RS256 token validation через JWKS или discovery metadata:

```bash
export RD_KG_OIDC_REQUIRED=true
export RD_KG_OIDC_ISSUER="https://issuer.example"
export RD_KG_OIDC_AUDIENCE="rdkg"
export RD_KG_OIDC_JWKS_URL="https://issuer.example/.well-known/jwks.json"
# или:
export RD_KG_OIDC_DISCOVERY_URL="https://issuer.example/.well-known/openid-configuration"
```

JWKS кэшируется локально; TTL задаётся через `RD_KG_OIDC_JWKS_CACHE_TTL_SECONDS` (по умолчанию 300 секунд). Для офлайн-тестов можно передать `RD_KG_OIDC_JWKS_JSON`.

После этого protected endpoints требуют `Authorization: Bearer <jwt>`, а `role`, `roles`, `groups`, `memberOf`, `department`, `project`, `clearance` берутся из signed claims. Header-role не может повысить права, если Bearer JWT передан.

Для корпоративных IdP/AD claims можно мапить внешние группы в роли приложения без прямого LDAP sync:

```bash
export RD_KG_OIDC_GROUP_CLAIM="groups"
export RD_KG_OIDC_GROUP_ROLE_MAP_JSON='{"RDKG-Researchers":"researcher","RDKG-Analysts":"analyst","/corp/rdkg/managers":"manager","RDKG-Admins":"admin"}'
# или:
export RD_KG_OIDC_GROUP_ROLE_MAP_FILE="/etc/rd-knowledge/group-role-map.json"
```

Mapping принимает JSON object `external_group -> app_role`; допустимые app roles: `external_partner`, `researcher`, `analyst`, `manager`, `admin`. Для AD distinguished names используется `CN=...`, для IdP paths и domain-qualified groups также учитывается последний сегмент (`/corp/rdkg/managers`, `CORP\RDKG-Admins`).

Для SCIM-compatible lifecycle можно включить обязательную проверку локального directory state:

```bash
export RD_KG_DIRECTORY_REQUIRED=true
```

В этом режиме каждый protected request должен иметь `subject` из Bearer JWT (`sub`) или локальный `X-Subject`; пользователь обязан быть provisioned и `active` в directory tables. Directory user/group role становится авторитетной ролью, если она задана, поэтому деактивация или понижение роли срабатывает до бизнес-логики endpoint. Admin-only SCIM endpoints:

- `GET /scim/v2/ServiceProviderConfig`;
- `GET|POST /scim/v2/Users`, `GET|PUT|PATCH|DELETE /scim/v2/Users/{id}`;
- `GET|POST /scim/v2/Groups`, `GET|PUT|PATCH|DELETE /scim/v2/Groups/{id}`;
- `POST /scim/v2/Bulk` для enterprise provisioning batches до 100 операций с atomic rollback по умолчанию.

`DELETE /Users/{id}` деактивирует пользователя, а не удаляет audit-relevant identity. Group membership может повышать пользователя до роли группы, если роль группы входит в `external_partner/researcher/analyst/manager/admin`. Все SCIM read/write/bulk операции проходят через action policy `directory.read`/`directory.write` и пишутся в audit как `directory_*`.

Direct AD/LDAP sync использует тот же локальный directory model, что и SCIM. Примерный LDAP config можно проверить офлайн: `python3 scripts/sync_directory.py --config ops/directory_sync.example.json --validate-only`; dry-run включён по умолчанию для реального config, apply: `python3 scripts/sync_directory.py --config /secure/path/directory_sync.json --apply`. Конфиг требует LDAPS или StartTLS, bind secret через env/file, `user_base_dn`, `group_base_dn` и `group_role_map`.

Endpoint-level RBAC вынесен в централизованную action matrix в `app/policy.py`. Текущую матрицу действий можно посмотреть через `GET /security/policy` с ролью `admin`; чтение матрицы пишется в audit как `security_policy`. Последние allow/deny decisions доступны admin через `GET /security/policy/decisions` и хранятся в `policy_decisions`.

Для production-пилота можно включить внешний policy engine/PDP поверх локальных guardrails:

```bash
export RD_KG_POLICY_ENGINE_URL="https://policy.example/v1/data/rdkg/allow"
export RD_KG_POLICY_ENGINE_TIMEOUT_SECONDS=2
export RD_KG_POLICY_ENGINE_BEARER_TOKEN_FILE="/run/secrets/rdkg-pdp-token"
export RD_KG_POLICY_ENGINE_CA_FILE="/etc/rdkg/pdp-ca.pem"
export RD_KG_POLICY_ENGINE_CLIENT_CERT="/etc/rdkg/pdp-client.crt"
export RD_KG_POLICY_ENGINE_CLIENT_KEY="/etc/rdkg/pdp-client.key"
# По умолчанию fail-closed. Временный fail-open режим только для controlled degradation:
export RD_KG_POLICY_ENGINE_FAIL_OPEN=false
```

Сервис отправляет `POST {"input": {"action": "...", "subject": {...}, "resource": {...}, "local_policy": {...}}}` и принимает OPA-style `{"result": true}` или `{"result": {"allow": true, "reason": "..."}}`. Локальная матрица остаётся нижней границей: внешний engine может сузить доступ, но не повышает права, если локальная policy уже отказала. Для service auth поддержаны `RD_KG_POLICY_ENGINE_BEARER_TOKEN`/`_FILE`, `RD_KG_POLICY_ENGINE_AUTH_HEADER` и `RD_KG_POLICY_ENGINE_HEADERS_JSON`; для mTLS - `RD_KG_POLICY_ENGINE_CA_FILE`, `RD_KG_POLICY_ENGINE_CLIENT_CERT`, `RD_KG_POLICY_ENGINE_CLIENT_KEY`. Policy decision audit включён по умолчанию и отключается только через `RD_KG_POLICY_DECISION_AUDIT=false`.

Классификация источников: `public`, `internal`, `confidential`, `secret`. Просмотр `secret` доступен с роли `manager`, но экспорт `secret` payload через Markdown/CSV/PDF/ZIP/JSON-LD/RDF endpoints требует роль `admin` либо одноразовый `approval_id`, выданный через `/export/approvals`; отказ, approve/reject и consume записываются в audit вместе с `export_policy`.

Content-inspection DLP rules для экспорта лежат в `data/security/dlp_export_rules.json`. По умолчанию `secret_assignment` ищет `api_key=...`, `token=...`, `password=...`, `secret=...` и требует approval/admin; `personal_email` помечает export как finding без блокировки. Action `block` не обходится approval. Findings содержат имя правила, action/classification, count и JSON paths, но не содержат сырой секрет. Правила можно переопределить:

```bash
export RD_KG_DLP_RULES_PATH="/etc/rdkg/dlp_export_rules.json"
export RD_KG_DLP_RULES_JSON='{"rules":[{"name":"project_code","pattern":"PROJECT-[0-9]{3}","classification":"confidential","action":"approval_required","formats":["csv"]}]}'
```

Для field-level at-rest encryption чувствительных DB-полей:

```bash
python3 - <<'PY'
from app.field_encryption import generate_field_encryption_key
print(generate_field_encryption_key())
PY
export RD_KG_FIELD_ENCRYPTION_KEY="paste-generated-key"
```

При включённом ключе новые значения `sources.path`, `sources.abstract`, `experts.contact`, `audit_log.object_id`, `audit_log.details_json`, `export_approvals.reason`, `export_approvals.justification`, `export_approvals.review_comment`, `policy_decisions.reason`, `policy_decisions.resource_json` и `policy_decisions.external_json` пишутся как AES-GCM ciphertext с префиксом `rdkg:v1:aesgcm:`. Чтение через API остаётся прозрачным при наличии ключа.

Для production-gate at-rest encryption включите обязательную проверку:

```bash
export RD_KG_REQUIRE_STORAGE_ENCRYPTION=true
export RD_KG_FIELD_ENCRYPTION_KEY="paste-generated-key"
export RD_KG_STORAGE_ENCRYPTION_PROVIDER="managed_encrypted_db" # или encrypted_volume/sqlcipher
export RD_KG_STORAGE_ENCRYPTION_EVIDENCE="rds:storageEncrypted=true:kmsKeyId=alias/rdkg"
# для SQLCipher:
export RD_KG_SQLCIPHER_KEY_FILE="/run/secrets/rdkg-sqlcipher-key"
```

При `RD_KG_REQUIRE_STORAGE_ENCRYPTION=true` startup падает, если нет валидного field-level key и подтверждённого full-storage provider (`managed_encrypted_db`, `encrypted_volume` или `sqlcipher`). Admin может проверить состояние через `GET /security/storage-encryption`; отчет не раскрывает ключи, только fingerprints и evidence metadata.

Internal security review gate:

```bash
python3 scripts/security_review.py --profile local --no-fail
python3 scripts/validate_security_review_evidence.py ops/security_review_evidence.example.json
python3 scripts/security_review.py --profile production --evidence-file /secure/path/security_review_evidence.json
curl http://localhost:8000/security/review?profile=local -H "X-Role: admin"
```

Production profile проверяет OIDC/JWKS, SCIM directory enforcement, SCIM Bulk, direct AD/LDAP sync config, action matrix, external PDP service auth/HA/bundle evidence, policy decision audit, DLP rules, storage encryption gate, observability bundle, SIEM/alerting/retention evidence, encrypted backup/restore-drill plan, independent DR evidence, synthetic 1M SLA profile и redacted external security review sign-off metadata. Реальный evidence-файл передаётся через `RD_KG_SECURITY_REVIEW_EVIDENCE_FILE` или `--evidence-file`; пример формата лежит в `ops/security_review_evidence.example.json`.

Для источников можно передавать metadata-поля `department`, `allowed_departments`, `project`, `allowed_projects`, `min_clearance`. Они применяются к search documents/facts, graph traversal, dashboard aggregates и graph export. Для ролей ниже `analyst` DLP редактирует пути, контакты, email и телефоны в API/export ответах; secrets (`api_key`, `token`, `password`, `secret`) маскируются для всех ролей.

## Инвентаризация и batch ingest корпуса

Инвентаризация не читает содержимое документов, а только классифицирует файлы:

```bash
python3 scripts/inventory_corpus.py "data/Задача 2. Научный клубок/Источники информации" --json
```

Углублённая инвентаризация может считать checksum-дубли с ограничением размера:

```bash
python3 scripts/inventory_corpus.py "data/Задача 2. Научный клубок/Источники информации" \
  --json \
  --checksums \
  --max-checksum-mb 1
```

Batch ingest папки с manifest, checksum, resume, checksum-dedupe, per-file commit и диагностикой unsupported форматов:

```bash
python3 scripts/batch_ingest.py "data/Задача 2. Научный клубок/Источники информации" \
  --limit 150 \
  --source-type real_corpus \
  --confidentiality internal
```

Progress печатается построчно в `stderr`, итоговый JSON summary - в `stdout`. Для машинного тихого режима используйте `--no-progress`.

По умолчанию resume пропускает уже известные `indexed`, `duplicate_skipped`, `failed` и `skipped_unsupported`, чтобы они не расходовали `--limit`. Для повторной попытки известных ошибок есть явные флаги:

```bash
python3 scripts/batch_ingest.py "data/Задача 2. Научный клубок/Источники информации" \
  --limit 100 \
  --retry-failed \
  --retry-unsupported
```

Отчёт покрытия корпуса по inventory + manifest:

```bash
python3 scripts/corpus_progress.py "data/Задача 2. Научный клубок/Источники информации" --json
```

В отчёте есть блок `remediation`: найденные утилиты (`soffice`, `unrar`, `tesseract`, `ocrmypdf`, `7z`) и действия по хвостам корпуса: продолжить batch, конвертировать legacy Office, распаковать RAR, добавить OCR или split-archive pipeline.

Backfill evidence locator/span и простых таблиц для уже загруженной БД:

```bash
python3 scripts/backfill_evidence_metadata.py --table-limit 2000
```

Проверка качества extraction на маленьком gold set: entity/numeric/relation precision/recall/F1.

```bash
python3 scripts/evaluate_extraction.py --json
```

Проверка качества query/retrieval/answer на gold queries: retrieval recall@k, evidence trace coverage, source snippet coverage, answer citation coverage.

```bash
python3 scripts/evaluate_quality.py --json
```

Локальный benchmark search latency по gold queries:

```bash
python3 scripts/benchmark_search.py --iterations 3 --json
```

Synthetic 1M+ graph load test для проверки 4-hop traversal и fact lookup SLA:

```bash
python3 scripts/load_test_synthetic_graph.py --profile pilot-1m --database /tmp/rdkg_synthetic_1m.sqlite --delete-after --json
```

Текущая инвентаризация предоставленного корпуса:

- 1453 файла;
- 5.22 GB;
- 1163 PDF, 115 DOCX, 79 ZIP, 46 XLS, 18 DOC, 16 RAR, 5 PPTX, 3 DOCM, 3 XLSX, 4 split archive parts, 1 GIF;
- 1352 файла маршрутизируются как поддержанные для текущего MVP-парсинга, 93 архива - как supported archive, 8 - unsupported;
- в текущем окружении найдены `soffice` и `unrar`; `tesseract`, `ocrmypdf` и `7z/7zz` отсутствуют;
- реальная smoke-проверка legacy-конвертации дала `26900` символов из DOC и `91551` символов из XLS без записи в БД;
- реальная smoke-проверка `Армировка.rar` распаковала 3 файла через `unrar`;
- реальная smoke-проверка `.zip.001/.zip.002` восстановила валидный ZIP с `CM_05_09.pdf`;
- unsupported/explicit formats фиксируются в manifest и не ломают batch;
- доменные папки: `Материалы конференций: 879`, `Журналы: 394`, `Обзоры: 104`, `Статьи: 60`, `Доклады: 16`;
- size buckets: `<1MB: 705`, `1-10MB: 650`, `10-50MB: 93`, `50-100MB: 3`, `>=100MB: 2`;
- checksum scan до 1MB нашёл реальные content-дубли, включая 3 одинаковых PDF Mitsui annual forecast.

Проверенное состояние после seed, batch `--limit 150`, нескольких batch `--limit 100`, targeted XLSX ingest, evidence backfill, retry batch `--limit 25 --retry-unsupported`, targeted AES PDF retry, targeted segment ingest и полного root-level batch `--limit 300`:

- `sources: 1884`, `documents/FTS chunks: 251744`, `entities: 1826`, `facts: 409980`, `graph_edges: 48268`, `document_tables: 40285`;
- trace coverage: `409980/409980` facts linked to `document_id` and evidence span;
- manifest: `1878 indexed`, `93 archive_indexed`, `103 duplicate_skipped`, `8 failed` OCR-only/no-text documents, `8 skipped_unsupported`;
- corpus progress: `1453/1453` root files manifested, `1437/1453` indexed-like, `0` pending;
- remaining remediation: `8` OCR/no-text failed documents, `4` auxiliary RAR volumes to skip, `2` auxiliary split parts to skip, `2` image/OCR files;
- latest full-root batch added `253 indexed`, `10 archive_indexed`, `2 duplicate_skipped`, `1 skipped_unsupported`, `4 failed`; mislabeled BMP `.xls` reclassified to image/OCR remediation.
- local backup artifacts were removed after verification to recover disk space; recreate with `python3 scripts/backup_db.py backup`.
- AES retry: `ALTA Ni-Co-Cu 2013 Proceedings.pdf` now indexed after installing `cryptography==49.0.0` (`797` chunks, `1182` facts).
- strict numeric smoke на текущей БД: фильтр `tds <= 1 g_l` вернул только `numeric_match=true` факты, сохранённые в `mg_l`.
- answer mode smoke покрыт тестами: `comparison` добавляет таблицу сравнения, `evidence_table` - таблицу фактов, `auto` выбирает `gap_analysis` для запросов про пробелы.
- curation bulk review покрыт тестом: duplicate IDs обрабатываются один раз, факты получают статус `verified`, review log получает отдельную запись на каждый факт.
- queue assignment покрыт тестом: assign/release работают, review action закрывает активное назначение как `completed`, рабочая БД мигрирована с `fact_assignments`.
- fact history/superseding покрыт тестом: replacement fact получает `supersedes_fact_id`, старый факт становится `superseded`, history показывает обе стороны цепочки.
- disputed workflow покрыт тестом: open/comment/SLA overdue/escalate/resolve меняют dispute state, пишут reviews/audit и отображаются в `fact_history`.
- manager dashboard покрыт тестом и smoke на рабочей БД: coverage, freshness, risk topics, fact/dispute quality и team/audit activity доступны через `/dashboard`.
- table export покрыт тестом: `/export/table` отдаёт evidence pack в CSV с `source`, `locator`, `span`, value и validation fields, а handler пишет audit action `export_table`.
- PDF/report package export покрыт тестом: `/export/pdf` отдаёт валидный PDF, `/export/report-package` содержит `answer.md`, `evidence.csv`, `payload.json`, `report.pdf`; sample PDF отрендерен через Poppler и визуально проверен.
- export DLP policy покрыта тестом: `secret` payload блокируется для `manager`, разрешается для `admin`, а audit получает `export_policy.allowed`, `max_confidentiality` и причину решения.
- export DLP content inspection покрыт тестом: `token=...` в export payload повышает classification до `secret`, требует approval/admin, audit получает `dlp_findings` без сырого секрета; flag-only email rule не блокирует export.
- export approval flow покрыт тестом: blocked sensitive export создаёт pending approval, `admin` approve переводит его в `approved`, первый export с `approval_id` помечает approval как `used`, повторное использование отклоняется.
- search benchmark smoke: после structured FTS + local hybrid rerank одна итерация по 5 gold queries на текущей БД дала overall p50 `162.27 ms`, p95 `2258.35 ms`, max `2586.04 ms`.
- locator backfill: документы без page/sheet marker получают fallback `chunk N`; рабочая БД теперь имеет `251744/251744` document locators и `409980/409980` fact locators.
- document embeddings backfill: рабочая БД теперь имеет `251744/251744` embeddings для hybrid retrieval.
- central action policy покрыта тестом: `metrics.read` доступен только `admin`, `curation.write` только `analyst/admin`, а `manager` не получает curation write автоматически по числовому уровню роли.
- external policy engine hook покрыт тестом: локально разрешённый action может быть denied внешним PDP по `action/subject/resource`, недоступность engine работает fail-closed по умолчанию и fail-open только при явном `RD_KG_POLICY_ENGINE_FAIL_OPEN=true`; service bearer/custom headers, mTLS context и `policy_decisions` allow/deny audit также покрыты тестами.
- SCIM-compatible directory lifecycle покрыт тестом: `RD_KG_DIRECTORY_REQUIRED=true` требует active provisioned subject, directory/group role ограничивает JWT/header role, `/scim/v2/Users`, `/scim/v2/Groups` и `/scim/v2/Bulk` provision/update/deactivate users и membership с audit events; atomic bulk failure откатывает уже применённые операции и пишет `directory_bulk_failed`.
- Direct AD/LDAP directory sync покрыт тестом: `ops/directory_sync.example.json` валидируется только при LDAPS/StartTLS и bind secret env/file, JSON-source dry-run ничего не пишет, apply upsert users/groups, replaces membership, deactivates missing users и пишет summary audit `directory_sync`.
- field-level encryption покрыта тестом: при `RD_KG_FIELD_ENCRYPTION_KEY` sensitive source/audit/export-approval поля хранятся как AES-GCM ciphertext и прозрачно расшифровываются через `row_to_dict`.
- storage encryption production gate покрыт тестом: `RD_KG_REQUIRE_STORAGE_ENCRYPTION=true` блокирует запуск без full-storage provider evidence и field-level key, managed encrypted DB config проходит, `/security/storage-encryption` доступен только `admin` и пишет audit.
- internal security review gate покрыт тестом: local profile не падает без production env, production profile проходит при полной evidence-конфигурации и attached external sign-off metadata, fail-closed при отсутствующей evidence, `/security/review` доступен только `admin` и пишет audit.
- OpenTelemetry-compatible tracing покрыт тестом: middleware propagates `traceparent`, отдаёт `X-Trace-Id`, считает spans, а OTLP exporter формирует `resourceSpans` payload без реального collector.
- synthetic 1M graph load test: временная БД `/tmp/rdkg_synthetic_1m.sqlite` с `1,000,000` entities, `1,000,000` facts и `2,000,000` graph_edges прошла 4-hop traversal p50 `1.80 ms`, p95 `5.12 ms`, max `5.28 ms`; fact lookup p50 `1.55 ms`, p95 `3.01 ms`, max `6.62 ms`; target `5s` выполнен, БД удалена после прогона.
- quality gate smoke: `scripts/evaluate_quality.py --json` проходит `5/5`; retrieval recall@k `1.0`, evidence trace coverage `1.0`, answer citation coverage `1.0`, locator coverage `1.0`.
- extraction gate smoke: `scripts/evaluate_extraction.py --json` проходит `5/5`; entity F1 `1.0`, numeric F1 `1.0`, relation F1 `1.0`.

## Структура проекта

```text
app/
  main.py          FastAPI endpoints
  converters.py    optional soffice/unrar capability wrappers
  db.py            SQLite schema and helpers
  dlp.py           export content-inspection DLP rules
  extract.py       entity/numeric extraction
  ingest.py        file/folder/archive ingestion
  policy.py        centralized endpoint action policy
  search.py        query parser, retrieval, graph traversal
  security.py      access context, ABAC helpers, DLP sanitization
  synthesize.py    structured answer generation
  seed_data.py     demo database creation
ui/
  streamlit_app.py simple UI
data/
  sample_docs/     demo documents
  dictionaries/    terms, units, taxonomy
  security/        DLP export content-inspection rules
  ontology/         classes, relations, JSON-LD context, units, storage target
  evaluation/       gold queries for quality checks
  experiments.csv  demo experiments
  experts.json     demo experts
scripts/
  batch_ingest.py
  corpus_progress.py
  evaluate_extraction.py
  inventory_corpus.py
  evaluate_quality.py
  benchmark_search.py
  load_test_synthetic_graph.py
  backfill_evidence_metadata.py
  backup_db.py
  sync_directory.py
  generate_metrics_jwt.py
  validate_observability_bundle.py
  validate_security_review_evidence.py
  rebuild_demo.sh
  run_api.sh
  run_ui.sh
ops/
  backup_plan.example.json
  directory_sync.example.json
  security_review_evidence.example.json
  observability/  Prometheus, OTEL Collector, Tempo, Loki/Promtail, Grafana
tests/
  pytest smoke tests
```

## Backup/restore локальной БД

```bash
python3 scripts/backup_db.py backup
```

Для одновременного копирования артефактов в отдельную директорию:

```bash
python3 scripts/backup_db.py backup --offsite-dir /secure/offsite/rdkg
```

Для encrypted backup сначала создайте ключ и положите его в защищённое окружение:

```bash
python3 scripts/backup_db.py generate-key
export RD_KG_BACKUP_KEY="..."
python3 scripts/backup_db.py backup --encrypted --offsite-dir /secure/offsite/rdkg
```

Restore намеренно требует явного подтверждения:

```bash
python3 scripts/backup_db.py restore data/backups/rd_knowledge_YYYYMMDDTHHMMSSZ.sqlite --force
python3 scripts/backup_db.py restore data/backups/rd_knowledge_YYYYMMDDTHHMMSSZ.sqlite.enc --force
```

Перед restore скрипт создаёт `pre_restore_*` backup текущей БД. Encrypted backup по умолчанию удаляет временный plaintext-файл и оставляет `.sha256` для ciphertext плюс `.manifest.json` с SHA-256 plaintext.

Restore drill проверяет backup в одноразовой временной БД и не перезаписывает активную `data/rd_knowledge.sqlite`:

```bash
python3 scripts/backup_db.py restore-drill data/backups/rd_knowledge_YYYYMMDDTHHMMSSZ.sqlite
python3 scripts/backup_db.py restore-drill data/backups/rd_knowledge_YYYYMMDDTHHMMSSZ.sqlite.enc
```

По умолчанию drill проверяет `PRAGMA integrity_check` и ненулевые `sources`, `documents`, `facts`; можно добавить `--require-embeddings` или переопределить минимум через повторяемый `--min-count TABLE=N`.

Для production-style расписания используйте единый backup plan: encrypted backup, optional offsite copy, restore drill и retention применяются одной командой.

```bash
cp ops/backup_plan.example.json /etc/rdkg/backup_plan.json
python3 scripts/backup_db.py run-plan --config /etc/rdkg/backup_plan.json --dry-run
python3 scripts/backup_db.py run-plan --config /etc/rdkg/backup_plan.json
```

`offsite_dir` должен указывать на независимое хранилище: отдельный volume, NFS/SFTP mount или смонтированный object-storage prefix. Локальные и offsite retention policies задаются отдельно:

```bash
python3 scripts/backup_db.py prune --directory data/backups --keep-latest 14 --max-age-days 30 --dry-run
```

Шаблоны `ops/systemd/rdkg-backup.service.example` и `ops/systemd/rdkg-backup.timer.example` запускают `run-plan` ежедневно. Секрет `RD_KG_BACKUP_KEY` храните в root-readable `EnvironmentFile`, например `/etc/rdkg/backup.env`, а не в JSON-конфиге.

## Hybrid retrieval embeddings

Новые chunks получают локальные deterministic embeddings автоматически. Для уже загруженной БД выполните backfill:

```bash
python3 scripts/build_document_embeddings.py
```

`/search` смешивает source reliability, BM25/LIKE, entity/alias matches и `vector_score`; в ответе источников доступны `bm25_score`, `vector_score` и `retrieval_method`.

## Ограничения MVP

- Извлечение сущностей и связей детерминированное, словарно-регулярное. Для production нужна модельная NER/RE-экстракция и человек-в-контуре.
- SQLite с добавленными graph/fact lookup indexes проходит локальный synthetic 1M graph traversal smoke, но для production-конкурентности, HA и managed scaling всё равно нужен целевой PostgreSQL + graph/search/vector stack.
- OCR hook для PDF есть, но в текущем окружении `ocrmypdf` не установлен; полноценный OCR/image pipeline для GIF/сканов ещё не закрыт.
- Нет generic non-ZIP split archive pipeline, PDF-table extraction и production-grade entity resolution.
- Strict numeric filtering сейчас использует interval-overlap и покрывает базовые совместимые единицы (`g_l`/`mg_l`, `t_day`/`kg_day`, `m3_day`/`m3_h`, `l_s`/`m3_h`); для production нужна расширенная онтология единиц и доменные правила сравнения.
- Legacy Office и RAR зависят от установленных внешних утилит `soffice` и `unrar`.
- Checksum-dedupe включён для новых batch-прогонов, но уже созданные до него дубли требуют отдельной ретро-чистки.
- Есть OIDC-compatible JWT-проверка с RS256 JWKS/discovery cache, AD/IdP group-to-role mapping, локальный SCIM-compatible user/group lifecycle с Bulk operations и direct AD/LDAP sync adapter; для production остаются live LDAP connectivity validation в целевой сети, service-account rotation/run scheduling и SIEM-интеграция.
- RBAC/ABAC/DLP сейчас локальные по данным, content-inspection rules и approval state, но endpoint actions можно дополнительно проверять внешним policy engine/PDP с service auth/mTLS и decision audit; field-level encryption, storage-encryption gate и security-review evidence metadata validator закрывают local production guardrails, но для production ещё нужны managed KMS rotation, реальное развертывание encrypted volume/SQLCipher/managed DB, managed policy bundles/HA PDP, external enterprise DLP/SIEM connectors, alert routing, long-term retention и фактическое прохождение enterprise review workflow с реальными signed evidence artifacts.
- Backup helper покрывает encrypted local backups, offsite artifact copy, retention, scheduled `run-plan` и non-destructive restore drills; отдельное managed object storage, immutable retention, мониторинг DR jobs и независимая DR-инфраструктура остаются deployment-задачами.
- Локальный hybrid retrieval есть, но production-векторный индекс и полноценный neural reranker ещё вынесены в roadmap.
- RDF/Turtle export и JSON-LD context есть, но полноценная OWL/SHACL-валидация вынесена в roadmap.

## Проверка

```bash
.venv/bin/python -m app.seed_data
.venv/bin/pytest -q
.venv/bin/python scripts/evaluate_quality.py
.venv/bin/python scripts/evaluate_extraction.py
.venv/bin/python scripts/benchmark_search.py --iterations 1 --json
.venv/bin/python scripts/load_test_synthetic_graph.py --profile smoke --database /tmp/rdkg_synthetic_smoke.sqlite --delete-after --json
.venv/bin/python scripts/validate_observability_bundle.py
.venv/bin/python scripts/validate_security_review_evidence.py ops/security_review_evidence.example.json
RD_KG_LDAP_BIND_PASSWORD=placeholder .venv/bin/python scripts/sync_directory.py --config ops/directory_sync.example.json --validate-only
```

Подробный статус реализации: `docs/IMPLEMENTATION_STATUS.md`.
