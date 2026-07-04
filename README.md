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
- RBAC/ABAC-заготовка через заголовки `X-Role`, `X-Department`, `X-Project`, `X-Clearance`;
- optional API key через `RD_KG_API_KEY`;
- role-aware DLP для search/export/ready/audit без маскирования технических диапазонов как телефонов;
- classification-aware export policy для `public/internal/confidential/secret`: `secret` можно просматривать с роли `manager`, но выгрузка через export endpoints разрешена только `admin` и всегда попадает в audit с policy decision;
- in-process request metrics на `/metrics` и Prometheus text endpoint `/metrics/prometheus` для роли `admin`;
- structured JSON request logs;
- readiness cache и SQLite performance indexes для рабочих search/curation endpoint’ов на текущей БД;
- backfill локальных document embeddings через `scripts/build_document_embeddings.py` для hybrid retrieval на уже загруженном корпусе;
- SQLite backup/restore helper с SHA-256 sidecar и AES-GCM encrypted `.sqlite.enc` backups;
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

Локальная модель доступа использует HTTP headers:

- `X-Role`: `external_partner`, `researcher`, `manager`, `analyst`, `admin`;
- `X-Department`: отдел пользователя;
- `X-Project`: проект пользователя;
- `X-Clearance`: дополнительный уровень допуска.

Классификация источников: `public`, `internal`, `confidential`, `secret`. Просмотр `secret` доступен с роли `manager`, но экспорт `secret` payload через Markdown/CSV/PDF/ZIP/JSON-LD/RDF endpoints требует роль `admin`; отказ возвращает `403` и записывается в audit вместе с `export_policy`.

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
- latest backup: `data/backups/rd_knowledge_20260704T171726Z.sqlite`, SHA-256 `fe823fb8c0ac3cf4b09681e15abe6f9d925d0742843c981303b0a7477e07162c`.
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
- search benchmark smoke: после structured FTS + local hybrid rerank три итерации по 5 gold queries на текущей БД дали overall p50 `170.62 ms`, p95 `2317.85 ms`, max `2437.10 ms`.
- locator backfill: документы без page/sheet marker получают fallback `chunk N`; рабочая БД теперь имеет `251744/251744` document locators и `409980/409980` fact locators.
- document embeddings backfill: рабочая БД теперь имеет `251744/251744` embeddings для hybrid retrieval.
- quality gate smoke: `scripts/evaluate_quality.py --json` проходит `5/5`; retrieval recall@k `1.0`, evidence trace coverage `1.0`, answer citation coverage `1.0`, locator coverage `1.0`.
- extraction gate smoke: `scripts/evaluate_extraction.py --json` проходит `5/5`; entity F1 `1.0`, numeric F1 `1.0`, relation F1 `1.0`.

## Структура проекта

```text
app/
  main.py          FastAPI endpoints
  converters.py    optional soffice/unrar capability wrappers
  db.py            SQLite schema and helpers
  extract.py       entity/numeric extraction
  ingest.py        file/folder/archive ingestion
  search.py        query parser, retrieval, graph traversal
  security.py      access context, ABAC helpers, DLP sanitization
  synthesize.py    structured answer generation
  seed_data.py     demo database creation
ui/
  streamlit_app.py simple UI
data/
  sample_docs/     demo documents
  dictionaries/    terms, units, taxonomy
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
  backfill_evidence_metadata.py
  backup_db.py
  rebuild_demo.sh
  run_api.sh
  run_ui.sh
tests/
  pytest smoke tests
```

## Backup/restore локальной БД

```bash
python3 scripts/backup_db.py backup
```

Для encrypted backup сначала создайте ключ и положите его в защищённое окружение:

```bash
python3 scripts/backup_db.py generate-key
export RD_KG_BACKUP_KEY="..."
python3 scripts/backup_db.py backup --encrypted
```

Restore намеренно требует явного подтверждения:

```bash
python3 scripts/backup_db.py restore data/backups/rd_knowledge_YYYYMMDDTHHMMSSZ.sqlite --force
python3 scripts/backup_db.py restore data/backups/rd_knowledge_YYYYMMDDTHHMMSSZ.sqlite.enc --force
```

Перед restore скрипт создаёт `pre_restore_*` backup текущей БД. Encrypted backup по умолчанию удаляет временный plaintext-файл и оставляет `.sha256` для ciphertext плюс `.manifest.json` с SHA-256 plaintext.

## Hybrid retrieval embeddings

Новые chunks получают локальные deterministic embeddings автоматически. Для уже загруженной БД выполните backfill:

```bash
python3 scripts/build_document_embeddings.py
```

`/search` смешивает source reliability, BM25/LIKE, entity/alias matches и `vector_score`; в ответе источников доступны `bm25_score`, `vector_score` и `retrieval_method`.

## Ограничения MVP

- Извлечение сущностей и связей детерминированное, словарно-регулярное. Для production нужна модельная NER/RE-экстракция и человек-в-контуре.
- SQLite подходит для прототипа, но не для цели `1 млн сущностей / 3-5 секунд / 4 уровня графа`.
- OCR hook для PDF есть, но в текущем окружении `ocrmypdf` не установлен; полноценный OCR/image pipeline для GIF/сканов ещё не закрыт.
- Нет generic non-ZIP split archive pipeline, PDF-table extraction и production-grade entity resolution.
- Strict numeric filtering сейчас использует interval-overlap и покрывает базовые совместимые единицы (`g_l`/`mg_l`, `t_day`/`kg_day`, `m3_day`/`m3_h`, `l_s`/`m3_h`); для production нужна расширенная онтология единиц и доменные правила сравнения.
- Legacy Office и RAR зависят от установленных внешних утилит `soffice` и `unrar`.
- Checksum-dedupe включён для новых batch-прогонов, но уже созданные до него дубли требуют отдельной ретро-чистки.
- Нет SSO/LDAP/AD, шифрования на уровне основной инфраструктуры/storage, SIEM-интеграции.
- ABAC/DLP сейчас локальные и header-based; для production нужен identity-backed policy engine и полноценный approve flow для чувствительных экспортов.
- Backup helper есть для MVP, включая encrypted local backups, но production backup policy, offsite storage и restore drills не настроены.
- Локальный hybrid retrieval есть, но production-векторный индекс и полноценный neural reranker ещё вынесены в roadmap.
- RDF/Turtle export и JSON-LD context есть, но полноценная OWL/SHACL-валидация вынесена в roadmap.

## Проверка

```bash
.venv/bin/python -m app.seed_data
.venv/bin/pytest -q
.venv/bin/python scripts/evaluate_quality.py
.venv/bin/python scripts/evaluate_extraction.py
.venv/bin/python scripts/benchmark_search.py --iterations 1 --json
```

Подробный статус реализации: `docs/IMPLEMENTATION_STATUS.md`.
