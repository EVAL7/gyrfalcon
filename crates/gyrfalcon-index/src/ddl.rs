//! DDL таблиц индекса — вехи 2 (код) и 3 (метаданные).
//!
//! # Откуда взято
//!
//! Снято с живого индекса прежнего инструмента (`sqlite_master`) 28.08.2026, а не
//! спроектировано заново (решение Р-003). Столбцы, их имена и типы совпадают
//! один-в-один — иначе сверка «поимённо» превращается в сверку с переводом.
//!
//! # Что добавлено сверх прежнего инструмента
//!
//! Два столбца в `calls`: `resolution` (класс резолвинга) и `confidence`.
//! Решение Р-005: неразрешимое ребро обязано помечаться классом, а не пустым
//! `callee_key` — иначе «не сумели разрешить» неотличимо от «разрешать нечего».

/// Версия **схемы индекса** — не версия программы.
///
/// Разведены намеренно: правка кода без правки таблиц не делает старый индекс
/// несовместимым, и объявлять его таковым было бы ложной тревогой. Растёт
/// только при изменении состава или смысла столбцов.
///
/// # Зачем это вообще
///
/// Урок прежнего инструмента: у него по полю `builder_version` видно, что индекс собран
/// старой сборкой и неполон — без такого признака «метод не найден» читается
/// как факт о конфигурации, хотя это дефект сборки. Индекс, не знающий своей
/// версии, молча отдаёт неверное новому коду.
///
/// | Версия | Что появилось |
/// |---|---|
/// | 1 | веха 2: шесть таблиц кода, граф вызовов с классом резолвинга |
/// | 2 | веха 3: ядро метаданных; в `object_attributes` добавлены квалификаторы |
/// | 3 | веха 7: `index_meta.git_commit`, индекс `idx_calls_caller` |
/// | 4 | Р-022: расширения целиком — `extensions`, `extension_objects`; строки расширений во всех таблицах с адресом `../ext/<Имя>/…` |
/// | 5 | MCP-06: `common_modules` — флаги контекста общих модулей для проверки `check_bsl` |
///
/// Версия 3 совместима со 2 по чтению: столбцов не убавилось, а новый
/// индекс лишь ускоряет. Поэтому `MIN_READABLE_SCHEMA` не поднят —
/// прежние индексы продолжают работать, просто медленнее на исходящих
/// рёбрах и без сверки коммита.
///
/// Версия 4 совместима с 3 по чтению: таблицы только добавлены. Индекс
/// версии 3 читается, но кода расширений в нём нет — это видно по
/// `schema_version`, и пересборка его возвращает.
///
/// Версия 5 совместима с 4 по чтению: добавлена одна таблица. На индексе
/// версии 4 проверка контекста общих модулей в `check_bsl` не делается и
/// говорит об этом в ответе, а не молчит.
pub const SCHEMA_VERSION: u32 = 5;

/// Минимальная версия схемы, которую умеет читать этот код.
///
/// Индекс версией ниже читать нельзя: столбцов, на которые рассчитывает код,
/// в нём просто нет. Отказ здесь честнее пустого ответа.
pub const MIN_READABLE_SCHEMA: u32 = 1;

/// Схема шести таблиц кода. Порядок важен: `methods` ссылается на `modules`,
/// `calls` — на `methods`.
pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS modules (
    id INTEGER PRIMARY KEY,
    rel_path TEXT UNIQUE NOT NULL,
    category TEXT,
    object_name TEXT,
    module_type TEXT,
    form_name TEXT,
    is_form INTEGER DEFAULT 0,
    mtime REAL,
    size INTEGER
);

CREATE TABLE IF NOT EXISTS module_headers (
    module_id INTEGER PRIMARY KEY REFERENCES modules(id),
    header_comment TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS methods (
    id INTEGER PRIMARY KEY,
    module_id INTEGER NOT NULL REFERENCES modules(id),
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    is_export INTEGER DEFAULT 0,
    params TEXT,
    line INTEGER,
    end_line INTEGER,
    loc INTEGER
);

CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY,
    caller_id INTEGER NOT NULL REFERENCES methods(id),
    callee_name TEXT NOT NULL,
    line INTEGER,
    callee_key TEXT,
    resolution TEXT NOT NULL,
    confidence REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS regions (
    id INTEGER PRIMARY KEY,
    module_id INTEGER REFERENCES modules(id),
    name TEXT NOT NULL,
    line INTEGER NOT NULL,
    end_line INTEGER
);

CREATE TABLE IF NOT EXISTS file_paths (
    id INTEGER PRIMARY KEY,
    rel_path TEXT NOT NULL UNIQUE,
    extension TEXT NOT NULL,
    dir_path TEXT NOT NULL,
    filename TEXT NOT NULL,
    depth INTEGER NOT NULL,
    size INTEGER,
    mtime REAL
);

CREATE TABLE IF NOT EXISTS index_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"#;

/// Индексы. Создаются **после** наполнения: строить их по ходу вставки
/// значит переупорядочивать B-дерево на каждой строке.
///
/// Список снят с прежнего инструмента; выражение `idx_calls_callee_short` тоже — оно даёт
/// поиск по короткому имени в квалифицированном вызове (`Модуль.Метод` → `Метод`).
pub const INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_mod_category ON modules(category);
CREATE INDEX IF NOT EXISTS idx_mod_object ON modules(object_name);
CREATE INDEX IF NOT EXISTS idx_meth_module ON methods(module_id);
CREATE INDEX IF NOT EXISTS idx_meth_name ON methods(name COLLATE NOCASE);
-- Исходящие рёбра метода: `caller_id` — направление, которого в списке
-- прежнего инструмента не было, и его отсутствие обошлось дорого. Без него любой вопрос
-- «что вызывает этот метод» и любая чистка рёбер модуля идут ПОЛНЫМ
-- перебором `calls` (5,6 млн строк на ЕРП.УХ).
--
-- Замер 29.08.2026: выборка рёбер одного модуля 7,69 с → 0,000 с.
-- Цена: +3 с к сборке и +65 МБ к индексу. Найдено не чтением схемы,
-- а планом запроса (`EXPLAIN QUERY PLAN` показал `SCAN calls`), когда
-- инкремент на ЕРП.УХ занял 45 с вместо ожидаемых секунд.
CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller_id);
CREATE INDEX IF NOT EXISTS idx_calls_callee ON calls(callee_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_calls_callee_key ON calls(callee_key);
CREATE INDEX IF NOT EXISTS idx_calls_resolution ON calls(resolution);
CREATE INDEX IF NOT EXISTS idx_calls_callee_short ON calls(
    (CASE WHEN instr(callee_name,'.')>0
          THEN substr(callee_name, instr(callee_name,'.')+1)
          ELSE callee_name END) COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_regions_module ON regions(module_id);
CREATE INDEX IF NOT EXISTS idx_regions_name ON regions(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_fp_depth ON file_paths(depth);
CREATE INDEX IF NOT EXISTS idx_fp_dir ON file_paths(dir_path);
CREATE INDEX IF NOT EXISTS idx_fp_ext ON file_paths(extension);
CREATE INDEX IF NOT EXISTS idx_fp_filename ON file_paths(filename COLLATE NOCASE);
"#;

/// PRAGMA на время сборки.
///
/// `synchronous = OFF` и журнал в памяти уместны именно здесь: индекс —
/// артефакт, который при сбое пересобирается с нуля за минуты. Ради этого
/// рисковать целостностью чужих данных было бы нельзя, своих — можно.
pub const BUILD_PRAGMAS: &str = "
PRAGMA journal_mode = OFF;
PRAGMA synchronous = OFF;
PRAGMA cache_size = -262144;
PRAGMA temp_store = MEMORY;
";

/// Схема таблиц метаданных — веха 3, ядро.
///
/// # Столбцы совпадают с прежним инструментом, кроме явно добавленных
///
/// Имена и типы сняты с его живого индекса (решение Р-003). Сверх прежнего инструмента —
/// только квалификаторы в `object_attributes`: `length`, `precision`, `scale`,
/// `date_fractions`. Замер 28.08.2026 по индексу БП: у прежнего инструмента 1706 уникальных
/// обозначений типа и **ни одного** с длиной или точностью, то есть 10 891
/// строковый и 7 200 числовых реквизитов лежат без них. Столбец `attr_type`
/// при этом сохраняет его формат (JSON-массив имён) — иначе сверка поимённо
/// превращается в сверку с переводом.
pub const SCHEMA_META: &str = r#"
CREATE TABLE IF NOT EXISTS object_attributes (
    id INTEGER PRIMARY KEY,
    object_name TEXT NOT NULL,
    category TEXT NOT NULL,
    attr_name TEXT NOT NULL,
    attr_synonym TEXT,
    attr_type TEXT,
    attr_kind TEXT NOT NULL,
    ts_name TEXT,
    source_file TEXT NOT NULL,
    length INTEGER,
    precision INTEGER,
    scale INTEGER,
    date_fractions TEXT
);

CREATE TABLE IF NOT EXISTS object_synonyms (
    id INTEGER PRIMARY KEY,
    object_name TEXT NOT NULL,
    category TEXT NOT NULL,
    synonym TEXT NOT NULL,
    file TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enum_values (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    synonym TEXT,
    values_json TEXT NOT NULL,
    source_file TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS predefined_items (
    id INTEGER PRIMARY KEY,
    object_name TEXT NOT NULL,
    category TEXT NOT NULL,
    item_name TEXT NOT NULL,
    item_synonym TEXT,
    item_code TEXT,
    types_json TEXT,
    is_folder INTEGER DEFAULT 0,
    source_file TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS defined_types (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    type_refs_json TEXT NOT NULL,
    path TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS characteristic_types (
    id INTEGER PRIMARY KEY,
    pvh_name TEXT NOT NULL,
    type_refs_json TEXT NOT NULL,
    path TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subsystem_content (
    id INTEGER PRIMARY KEY,
    subsystem_name TEXT NOT NULL,
    subsystem_synonym TEXT,
    object_ref TEXT NOT NULL,
    file TEXT NOT NULL
);
"#;

/// Схема таблиц метаданных — веха 3, часть вторая: подписки, регламентные
/// задания, функциональные опции, права ролей, состав планов обмена.
///
/// Столбцы сняты с прежнего инструмента один-в-один, включая его решения, которые я бы принял
/// иначе: `use` и `predefined` у заданий хранятся числом, а не логическим типом,
/// `source_types` подписки — JSON-строкой, а не отдельной таблицей связей.
/// Расхождение в форме хранения превратило бы сверку поимённо в сверку
/// с переводом, а спорить о вкусе формата дешевле после доказанного паритета.
pub const SCHEMA_META2: &str = r#"
CREATE TABLE IF NOT EXISTS event_subscriptions (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    synonym TEXT,
    event TEXT,
    handler_module TEXT,
    handler_procedure TEXT,
    source_types TEXT,
    source_count INTEGER,
    file TEXT
);

CREATE TABLE IF NOT EXISTS scheduled_jobs (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    synonym TEXT,
    method_name TEXT,
    handler_module TEXT,
    handler_procedure TEXT,
    use INTEGER DEFAULT 1,
    predefined INTEGER DEFAULT 0,
    restart_count INTEGER DEFAULT 0,
    restart_interval INTEGER DEFAULT 0,
    file TEXT
);

CREATE TABLE IF NOT EXISTS functional_options (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    synonym TEXT,
    location TEXT,
    content TEXT,
    file TEXT
);

CREATE TABLE IF NOT EXISTS role_rights (
    id INTEGER PRIMARY KEY,
    role_name TEXT NOT NULL,
    object_name TEXT NOT NULL,
    right_name TEXT NOT NULL,
    file TEXT
);

CREATE TABLE IF NOT EXISTS exchange_plan_content (
    id INTEGER PRIMARY KEY,
    plan_name TEXT NOT NULL,
    object_ref TEXT NOT NULL,
    auto_record INTEGER NOT NULL,
    path TEXT NOT NULL
);

-- Флаги общих модулей (схема 5, MCP-06). У прежнего инструмента такой таблицы
-- нет: флаги живут только в XML, а без них проверка «клиент зовёт серверный
-- модуль» невозможна. Флаги хранятся числом 0/1, как `use` у заданий.
CREATE TABLE IF NOT EXISTS common_modules (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    global INTEGER NOT NULL,
    client_managed INTEGER NOT NULL,
    client_ordinary INTEGER NOT NULL,
    server INTEGER NOT NULL,
    server_call INTEGER NOT NULL,
    external_connection INTEGER NOT NULL,
    privileged INTEGER NOT NULL,
    file TEXT NOT NULL
);
"#;

/// Ссылки между объектами метаданных.
///
/// Столбцы прежнего инструмента один-в-один. `line` у него заполнен лишь у четырёх видов
/// из четырнадцати (типы реквизитов, ввод на основании, владельцы, формы
/// по умолчанию) — там, где он читает XML построчно; у остальных `NULL`.
/// Ставить свои номера строк там, где у него их нет, значило бы разойтись
/// в данных ради мнимой полноты.
pub const SCHEMA_REFS: &str = r#"
CREATE TABLE IF NOT EXISTS metadata_references (
    id INTEGER PRIMARY KEY,
    source_object TEXT NOT NULL,
    source_category TEXT NOT NULL,
    ref_object TEXT NOT NULL,
    ref_kind TEXT NOT NULL,
    used_in TEXT NOT NULL,
    path TEXT NOT NULL,
    line INTEGER
);
"#;

/// Индексы таблицы ссылок.
pub const INDEXES_REFS: &str = r#"
CREATE INDEX IF NOT EXISTS idx_mr_source ON metadata_references(source_object COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_mr_ref ON metadata_references(ref_object COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_mr_kind ON metadata_references(ref_kind);
"#;

/// Индексы второй части метаданных.
pub const INDEXES_META2: &str = r#"
CREATE INDEX IF NOT EXISTS idx_es_name ON event_subscriptions(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_es_handler ON event_subscriptions(handler_module COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_sj_name ON scheduled_jobs(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_sj_handler ON scheduled_jobs(handler_module COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_fo_name ON functional_options(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_rr_role ON role_rights(role_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_rr_object ON role_rights(object_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_epc_plan ON exchange_plan_content(plan_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_epc_object ON exchange_plan_content(object_ref COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_cm_name ON common_modules(name COLLATE NOCASE);
"#;

/// Индексы таблиц метаданных. Как и у кода — строго после наполнения.
pub const INDEXES_META: &str = r#"
CREATE INDEX IF NOT EXISTS idx_oa_object ON object_attributes(object_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_oa_name ON object_attributes(attr_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_oa_kind ON object_attributes(attr_kind);
CREATE INDEX IF NOT EXISTS idx_os_object ON object_synonyms(object_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_os_syn ON object_synonyms(synonym COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_pi_object ON predefined_items(object_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_pi_item ON predefined_items(item_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_ev_name ON enum_values(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_sc_subsystem ON subsystem_content(subsystem_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_sc_object ON subsystem_content(object_ref COLLATE NOCASE);
"#;

/// Интеграция и движения: XDTO, web- и HTTP-сервисы, движения регистров.
///
/// # Где мы расходимся с прежним инструментом — намеренно, и почему
///
/// **`register_movements.source`.** У прежнего инструмента движения собраны ТОЛЬКО из кода
/// (`code` 184, `manager_table` 117, `manager_code` 56, `adapted` 7 = 364 строки
/// на БП), а объявленный состав `<RegisterRecords>` в XML документа он не
/// читает вовсе. Замер 28.08.2026: объявлено 2 108 движений у 236 документов
/// против 245 пар у 135 документов у прежнего инструмента; объявленного, но не найденного им —
/// 1 958. Мы пишем ОБЪЕДИНЕНИЕ и помечаем источник: `declared` — объявление в
/// метаданных документа, остальные классы — найденное в коде. Паритет по числу
/// строк здесь брать нельзя: он означал бы воспроизвести дыру.
///
/// **`xdto_packages.types_json`.** У прежнего инструмента он пуст во ВСЕХ 434 строках — имя и
/// пространство имён есть, типов ноль. Причина найдена: схема пакета лежит не в
/// `XDTOPackages/<Имя>.xml`, а в спутнике `<Имя>/Ext/Package.bin` — файл с
/// расширением `.bin`, внутри которого обычный XML (UTF-8 BOM, корень
/// `<package targetNamespace=…>`). Замер 28.08.2026 по всем 434 пакетам:
/// 16 389 `objectType`, 6 749 `valueType`, 110 988 `property`. Мы его читаем.
///
/// Столбцы у всех четырёх — прежний инструментские один-в-один; `source` в
/// `register_movements` у него тоже есть, мы лишь расширяем набор значений.
pub const SCHEMA_INTEGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS register_movements (
    id INTEGER PRIMARY KEY,
    document_name TEXT NOT NULL,
    register_name TEXT NOT NULL,
    source TEXT DEFAULT 'code',
    file TEXT
);

CREATE TABLE IF NOT EXISTS xdto_packages (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    namespace TEXT NOT NULL,
    types_json TEXT NOT NULL,
    file TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS web_services (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    namespace TEXT NOT NULL,
    operations_json TEXT NOT NULL,
    file TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS http_services (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    root_url TEXT NOT NULL,
    templates_json TEXT NOT NULL,
    file TEXT NOT NULL
);
"#;

/// Индексы таблиц интеграции.
pub const INDEXES_INTEGRATION: &str = r#"
CREATE INDEX IF NOT EXISTS idx_rm_document ON register_movements(document_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_rm_register ON register_movements(register_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_xp_name ON xdto_packages(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_xp_ns ON xdto_packages(namespace);
CREATE INDEX IF NOT EXISTS idx_ws_name ON web_services(name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_hs_name ON http_services(name COLLATE NOCASE);
"#;

/// Упоминания объектов метаданных в коде.
///
/// Столбцы прежнего инструмента один-в-один. Отличие в СОДЕРЖИМОМ, а не в форме: мы
/// фильтруем строки по списку существующих объектов конфигурации.
///
/// # Почему фильтр — это улучшение, а не потеря
///
/// Замер 28.08.2026: **1,41% строк прежнего инструмента (3 663 из 259 401) указывают на
/// объекты, которых в конфигурации нет вовсе**. Причины систематические,
/// а не случайные:
///
/// | Что попало | Пример | Строк |
/// |---|---|---|
/// | методы платформы на менеджере | `Документы.ТипВсеСсылки()` | 305 |
/// | методы плана обмена | `ПланыОбмена.ЗарегистрироватьИзменения` | 166 |
/// | псевдонимы таблиц в запросах | `ВЫБРАТЬ Документ.Дата` — `Документ` тут алиас | 40+ |
/// | JavaScript внутри строк BSL | `document.location.href`, `document.body` | — |
/// | узлы XML электронных документов | `Document.СвСчФакт`, `Document.СвПродПер` | 204 |
/// | `НСтр("ru='…")` | принято за `Report.ru` | — |
///
/// Такая строка не просто бесполезна: на вопрос «где используется документ X»
/// она отвечает выдумкой, неотличимой от факта. Тот же класс дефекта, за
/// который забракован сторонний индексатор при замере 25.08.2026.
///
/// Фильтр возможен потому, что список объектов у нас уже есть — веха 3 его
/// собрала и сверила поимённо. Прежний инструмент его при сборке этой таблицы не смотрит.
pub const SCHEMA_USAGES: &str = r#"
CREATE TABLE IF NOT EXISTS metadata_code_usages (
    id             INTEGER PRIMARY KEY,
    module_id      INTEGER NOT NULL REFERENCES modules(id),
    object_ref     TEXT NOT NULL,
    object_ref_key TEXT NOT NULL,
    member_path    TEXT,
    usage_kind     TEXT NOT NULL,
    line           INTEGER
);
"#;

/// Индексы таблицы упоминаний.
pub const INDEXES_USAGES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_mcu_key ON metadata_code_usages(object_ref_key);
CREATE INDEX IF NOT EXISTS idx_mcu_module ON metadata_code_usages(module_id);
CREATE INDEX IF NOT EXISTS idx_mcu_kind ON metadata_code_usages(usage_kind);
"#;

/// Элементы управляемых форм: реквизиты, обработчики событий, команды.
///
/// Столбцы прежнего инструмента один-в-один. Три вида в одной таблице (`kind`), потому что
/// вопрос к ней один и тот же — «что есть на этой форме»; разносить по трём
/// таблицам значило бы заставлять читателя склеивать их обратно.
///
/// `scope` осмыслен только у обработчиков: `form` — событие самой формы,
/// `element` — событие элемента (тогда заполнены `element_name`/`element_type`/
/// `data_path`), `ext_info` — служебные разделы формы (командная панель,
/// контекстное меню, расширенная подсказка).
pub const SCHEMA_FORMS: &str = r#"
CREATE TABLE IF NOT EXISTS form_elements (
    id INTEGER PRIMARY KEY,
    object_name TEXT NOT NULL,
    category TEXT NOT NULL,
    form_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    element_name TEXT NOT NULL DEFAULT '',
    element_type TEXT NOT NULL DEFAULT '',
    event TEXT NOT NULL DEFAULT '',
    handler TEXT NOT NULL DEFAULT '',
    data_path TEXT NOT NULL DEFAULT '',
    main_table TEXT NOT NULL DEFAULT '',
    attribute_is_main INTEGER DEFAULT 0,
    extra_json TEXT NOT NULL DEFAULT '',
    file TEXT NOT NULL
);
"#;

/// Индексы таблицы форм.
pub const INDEXES_FORMS: &str = r#"
CREATE INDEX IF NOT EXISTS idx_fe_object ON form_elements(object_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_fe_form ON form_elements(form_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_fe_kind ON form_elements(kind);
CREATE INDEX IF NOT EXISTS idx_fe_handler ON form_elements(handler COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_fe_element ON form_elements(element_name COLLATE NOCASE);
"#;

/// Перехваты расширений с адресом — `extension_overrides`.
///
/// Столбцы повторяют прежний инструментские: сверка идёт поимённо, и переименование
/// на ровном месте дало бы расхождение там, где данные совпадают.
///
/// Два адреса, и они разные по смыслу:
/// `target_method_line` — строка объявления перехватываемого метода в ОСНОВНОЙ
/// конфигурации; `ext_line` — строка САМОЙ АННОТАЦИИ в расширении (не строка
/// объявления процедуры-перехватчика: проверено на корпусе ДО, прежний инструмент пишет
/// именно её). `target_method_line` пуст, когда цель не разрешилась — модуль
/// основной конфигурации отсутствует или метод в нём не найден.
pub const SCHEMA_EXTENSIONS: &str = r#"
CREATE TABLE IF NOT EXISTS extension_overrides (
    id INTEGER PRIMARY KEY,
    object_name TEXT NOT NULL,
    source_path TEXT NOT NULL DEFAULT '',
    source_module_id INTEGER,
    target_method TEXT NOT NULL,
    target_method_line INTEGER,
    annotation TEXT NOT NULL,
    extension_name TEXT NOT NULL,
    extension_purpose TEXT,
    extension_method TEXT,
    extension_root TEXT NOT NULL,
    ext_module_path TEXT NOT NULL,
    ext_line INTEGER
);

-- Реестр расширений: все найденные, с перехватами или без (Р-022).
-- rel_root — адрес корня от source_path: `../ext/<Имя>` либо `../cfe` (одно\n-- расширение прямо в каталоге, Р-024). Им же начинаются
-- адреса всех строк расширения в остальных таблицах.
CREATE TABLE IF NOT EXISTS extensions (
    name TEXT NOT NULL,
    purpose TEXT,
    name_prefix TEXT,
    rel_root TEXT NOT NULL
);

-- Состав расширений: объект и его принадлежность.
-- belonging: `own` — объект расширения; `adopted` — заимствован из основной
-- конфигурации, его собственные свойства берутся оттуда, а здесь записано
-- лишь то, что расширение добавило.
CREATE TABLE IF NOT EXISTS extension_objects (
    extension_name TEXT NOT NULL,
    category TEXT NOT NULL,
    object_name TEXT NOT NULL,
    belonging TEXT NOT NULL,
    source_file TEXT NOT NULL
);
"#;

/// Индексы перехватов: спрашивают их «кто перехватил этот метод»
/// и «что делает вот это расширение».
pub const INDEXES_EXTENSIONS: &str = r#"
CREATE INDEX IF NOT EXISTS idx_eo_object ON extension_overrides(object_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_eo_target ON extension_overrides(target_method COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_eo_ext ON extension_overrides(extension_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_eo_annot ON extension_overrides(annotation);
CREATE INDEX IF NOT EXISTS idx_extobj_obj ON extension_objects(object_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_extobj_ext ON extension_objects(extension_name COLLATE NOCASE);
"#;

/// Семантический слой (веха 4).
///
/// # Почему это отдельная схема, а не «ещё три таблицы описи»
///
/// Опись `schema::TABLES` — чек-лист **переноса** от прежнего инструмента: 27 из 27. У прежнего инструмента
/// семантики нет вовсе (у него FTS5 по именам), поэтому здешние таблицы в опись
/// не входят и счётчик переноса не портят. Это первое, что сервер делает сверх
/// прежнего инструмента, а не догоняя его.
///
/// # Устройство (решение Р-006)
///
/// `semantic_dictionary` — предпосчитанные ОФЛАЙН векторы токенов. Пустая
/// таблица штатна: тогда всё считается random indexing по строке токена.
/// Инференса при сборке индекса нет ни при каком состоянии словаря.
///
/// `semantic_tokens` — словарь корпуса с частотами. Нужен не для поиска,
/// а для IDF: вес токена в векторе сущности обратен его распространённости,
/// иначе `Заполнить` (8 302 имени) перевесит `Себестоимость`.
///
/// `semantic_vectors` — вектор сущности (метода, объекта метаданных) как
/// взвешенная IDF-сумма векторов его токенов, квантованная в int8.
pub const SCHEMA_SEMANTIC: &str = r#"
CREATE TABLE IF NOT EXISTS semantic_dictionary (
    token TEXT PRIMARY KEY,
    vector BLOB NOT NULL,
    source TEXT NOT NULL DEFAULT 'offline'
);

CREATE TABLE IF NOT EXISTS semantic_tokens (
    token TEXT PRIMARY KEY,
    df INTEGER NOT NULL,
    idf REAL NOT NULL,
    from_dictionary INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS semantic_vectors (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    ref_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    vector BLOB NOT NULL,
    dict_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0
);
"#;

/// Индексы семантики.
///
/// По `kind` спрашивают «искать только среди методов»; `ref_id` связывает
/// вектор с исходной строкой, иначе выдача поиска — это имена без адреса.
pub const INDEXES_SEMANTIC: &str = r#"
CREATE INDEX IF NOT EXISTS idx_sv_kind ON semantic_vectors(kind);
CREATE INDEX IF NOT EXISTS idx_sv_ref ON semantic_vectors(kind, ref_id);
CREATE INDEX IF NOT EXISTS idx_st_df ON semantic_tokens(df DESC);
"#;

/// Полнотекстовый поиск по именам (лексическая половина выдачи, Р-016).
///
/// # Зачем он рядом с семантикой
///
/// Решение Р-016: лексика и семантика отдаются раздельно, без общей формулы.
/// Значит лексический проход должен существовать — иначе «раздельная выдача»
/// это один список и одно пустое поле.
///
/// # Токенизатор — trigram, как у прежнего инструмента
///
/// `unicode61` режет по словам и не найдёт `Себестоимост` в
/// `РассчитатьСебестоимостьПартий`: имена 1С пишутся слитно, границы слов
/// внутри идентификатора для FTS не существует. Триграммы дают поиск по
/// подстроке — то, чем лексический проход и полезен: точное вхождение куска
/// имени он находит там, где семантика только «похоже».
///
/// # `detail` менять нельзя — проверено отказом
///
/// Первая редакция ставила `detail=none` ради экономии места. Таблица
/// заполнилась (530 886 строк) и **перестала отвечать на любой запрос**:
/// `fts5: phrase queries are not supported (detail!=full)`. Триграммный
/// поиск и есть фразовый по построению — каждое слово раскладывается
/// в последовательность триграмм.
///
/// Дефект стоил бы дорого, если бы не всплыл сразу: заполненная таблица
/// с молчащим поиском выглядит как «по такому слову ничего нет» — отказ
/// инструмента, неотличимый от факта о конфигурации.
pub const SCHEMA_FTS: &str = r#"
CREATE VIRTUAL TABLE IF NOT EXISTS methods_fts USING fts5(
    name,
    tokenize = 'trigram'
);

CREATE VIRTUAL TABLE IF NOT EXISTS objects_fts USING fts5(
    name,
    tokenize = 'trigram'
);
"#;
