//! Инструменты сервера — то, что агент реально вызывает.
//!
//! # Устройство (решение Р-101)
//!
//! Инструментов мало и каждый широкий. Экономию токенов даёт **ширина одного
//! вызова**, а не исполнение кода на стороне сервера: `find` за один заход
//! ищет тремя способами, `callers` отдаёт транзитивное замыкание, `object`
//! собирает карточку объекта из четырёх таблиц. Песочницы нет.
//!
//! `sql` — предохранитель: множество вопросов, которые я предвидел, конечно,
//! а вопросы агента — нет.
//!
//! # Тела модулей наружу не уходят
//!
//! Контрольная точка вехи 5 требует этого прямо. `read` отдаёт **одну
//! процедуру** по адресу из индекса, а не файл; никакой инструмент не
//! возвращает модуль целиком.

use crate::sql;
use rusqlite::Connection;
use serde_json::{json, Value};

/// Профиль набора: какие инструменты видит роль (решение Р-104).
///
/// Лекарство от капкана «инструмент без правила, когда его звать»: если роли
/// он не нужен — его у неё нет вовсе, а не лежит мёртвым весом.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Всё, включая `sql`.
    All,
    /// Чтение и навигация без произвольного SQL — для ролей, которым нужен
    /// ответ, а не доступ к схеме.
    Analysis,
    /// Минимум для разведки: найти, посмотреть, оценить полноту.
    Scout,
}

impl Profile {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "all" => Some(Profile::All),
            "analysis" => Some(Profile::Analysis),
            "scout" => Some(Profile::Scout),
            _ => None,
        }
    }

    fn allows(self, name: &str) -> bool {
        // `delete_project` ЗДЕСЬ НЕТ намеренно: это единственная
        // разрушающая операция сервера, и она доступна только профилю
        // `all`. Роль, чьё дело — читать, стирать индексы не должна.
        const ANALYSIS: &[&str] = &[
            "list_projects",
            "kb_1c",
            "project_practices",
            "standards_1c",
            "find",
            "object",
            "assist_bsl",
            "callers",
            "read",
            "overrides",
            "movements",
            "detect_changes",
            "impact",
            "schema",
            "coverage",
            "grep",
            "check_bsl",
        ];
        // Добор — в ОБОИХ профилях: он нужен ровно там, где структурный поиск
        // промахнулся, а это случается у разведчика чаще, чем у аналитика.
        //
        // `check_bsl` — в обоих профилях: роль, которая пишет код, без него
        // пишет вслепую, а какая именно роль пишет — решается заданием, не
        // профилем. Индекс ему нужен (имена сверяются по нему), поэтому под
        // общее стоп-условие «нет индекса — нет работы» он попадает сам.
        const SCOUT: &[&str] = &[
            "list_projects",
            "kb_1c",
            "project_practices",
            "standards_1c",
            "find",
            "object",
            "assist_bsl",
            "read",
            "schema",
            "coverage",
            "grep",
            "check_bsl",
        ];
        match self {
            Profile::All => true,
            Profile::Analysis => ANALYSIS.contains(&name),
            Profile::Scout => SCOUT.contains(&name),
        }
    }
}

/// Описание инструмента для `tools/list`.
pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    pub schema: fn() -> Value,
}

/// Все инструменты сервера.
///
/// Порядок — от частого к редкому: он же порядок в выдаче `tools/list`.
pub const TOOLS: &[Tool] = &[
    Tool {
        name: "list_projects",
        description: "Какие конфигурации 1С обслуживает этот сервер: имя, каталог              исходников, число модулей и методов, время сборки индекса. Спрашивать              ПЕРВЫМ, когда неизвестно, что подставлять в параметр project.              Отвечает про реестр сервера, а не про содержимое конфигураций.",
        schema: schema_projects,
    },
    Tool {
        name: "delete_project",
        description: "Удалить ИНДЕКС конфигурации: закрыть его, снять слежение              за исходниками, убрать файл. Исходники 1С не трогает. Нужен потому,              что удалить файл снаружи при работающем сервере нельзя — он его              держит. Отвечает исходом словом: deleted / not_found / delete_failed.",
        schema: schema_delete_project,
    },
    Tool { name: "kb_1c", description: "Найти пользовательскую встроенную справку Ext/Help в индексе выбранного проекта. Требует одно явное имя project из list_projects; справка другого проекта не смешивается. Источник обновляется при сборке индекса. Это не API платформы и не проектные правила.", schema: schema_kb_1c },
    Tool { name: "project_practices", description: "Единый базовый слой стандартов 1С плюс принятые практики одного проекта. Пустой профиль автоматически получает быстрый проход по индексу BSL-модулей: пары областей учитываются как свидетельства к общему стандарту, а проверяемые API-сценарии попадают в кандидаты с выборкой тел методов; непустой профиль не перезаполняется. Полный поиск AST и вызовов пока исследовательский. view=candidates показывает локальные кандидаты и конфликты с базисом.", schema: schema_project_practices },
    Tool { name: "standards_1c", description: "Единый локальный корпус официальных стандартов 1С: view=search ищет пункты, catalog перечисляет статьи, article и clause читают источник, practices отдаёт принятые общие правила с поиском и пагинацией. Корпус общий для всех проектов; принятые исключения показываются отдельно.", schema: schema_standards_1c },
    Tool {
        name: "find",
        description: "Найти объект метаданных, модуль или метод. Три способа поиска за один \
             вызов: точное имя, подстрока и поиск ПО СМЫСЛУ (находит «склад» по запросу \
             «где лежат товары»). Возвращает адреса, а не тела. Начинать поиск отсюда, \
             а не с чтения файлов.",
        schema: schema_find,
    },
    Tool {
        name: "object",
        description: "Карточка объекта метаданных: реквизиты с ТИПАМИ и квалификаторами, \
             табличные части, синонимы, предопределённые, формы, движения по регистрам. \
             Собирается из нескольких таблиц за один вызов — не нужно спрашивать по частям.",
        schema: schema_object,
    },
    Tool {
        name: "assist_bsl",
        description: "Помочь НАПИСАТЬ BSL, а не только проверить готовое: по задаче              подобрать реальные методы, объекты и реквизиты конфигурации, показать              короткие места вызова, дать дополнения в позиции курсора и безопасный              каркас. Непустой черновик заодно проходит check_bsl. Выдача строгая:              слабые совпадения отбрасываются, reference_only нельзя копировать как              внешний вызов. Текст запросов 1С проверяется отдельно.",
        schema: crate::assist_bsl::schema,
    },
    Tool {
        name: "callers",
        description: "Кто вызывает метод и кого вызывает он — транзитивно, на заданную глубину. \
             У каждого ребра класс разрешения и confidence: «не сумели разрешить» отличимо \
             от «разрешать нечего». Заменяет поиск по тексту при анализе влияния правки.",
        schema: schema_callers,
    },
    Tool {
        name: "read",
        description: "Прочитать ТЕЛО ОДНОГО метода по адресу из индекса. Не файл и не модуль: \
             сначала find, потом read по найденному адресу.",
        schema: schema_read,
    },
    Tool {
        name: "overrides",
        description: "Расширения конфигурации. Без параметров — все расширения: перехватов, \
             своих объектов, заимствовано, модулей. По extension — перехваты И состав расширения \
             (свои и заимствованные объекты). По object — перехваты с АДРЕСОМ: аннотация \
             (Перед/После/Вместо/ИзменениеИКонтроль), модуль расширения, строка. Отвечает на \
             «почему типовой код ведёт себя не как типовой». Код и объекты расширений \
             ищутся обычными find/object/read/callers, путь — ../ext/<Имя>/… \
             (одно расширение в каталоге cfe — ../cfe/…; корень каждого — rel_root).",
        schema: schema_overrides,
    },
    Tool {
        name: "movements",
        description: "Движения документов по регистрам: кто по каким регистрам пишет. \
             Берётся из ОБЪЯВЛЕННЫХ движений метаданных, а не только из кода — поэтому \
             видит и то, что пишется подписками и общими модулями.",
        schema: schema_movements,
    },
    Tool {
        name: "detect_changes",
        description: "Что сломает эта правка: git diff → изменённые методы → радиус поражения \
             с оценкой риска по расстоянию (hop 1 — CRITICAL, дальше убывает). Видит и \
             закоммиченное против базы, и рабочее дерево, и новые файлы. Отвечает на вопрос \
             ревьюера одним вызовом вместо обхода вызывающих руками.",
        schema: schema_detect_changes,
    },
    Tool {
        name: "impact",
        description: "Оценить последствия планируемой правки до появления diff: кто вызывает метод, какие подписки и задания его запускают, а для объекта — формы, права и метаданные, которые на него ссылаются. Каждая строка содержит вид связи и адрес из индекса.",
        schema: schema_impact,
    },
    Tool {
        name: "schema",
        description: "Устройство индекса: таблицы, колонки, число строк. Спрашивать ПЕРЕД sql, \
             чтобы запрос писался по фактической схеме, а не по памяти о ней.",
        schema: schema_schema,
    },
    Tool {
        name: "coverage",
        description: "Чего в индексе НЕТ: файлы с ошибкой разбора, нерешённые рёбра графа, \
             доля разрешённого. ВАЖНО: отсутствие записи об ошибке не гарантирует полноту. \
             Спрашивать, когда ответ «не найдено» выглядит подозрительно — он может означать \
             «не проиндексировано», а не «в конфигурации нет».",
        schema: schema_coverage,
    },
    Tool {
        name: "grep",
        description: "Полнотекстовый ДОБОР по телу модулей — то, чего нет ни в одном имени:              GUID, текст сообщения пользователю, кусок запроса, магическая строка.              Звать, когда find вернул пусто, а объект наверняка есть: «промах поиска              не равен отсутствию». Сужать параметром module — на 30 тыс. модулей это              разница между секундой и минутой.",
        schema: schema_grep,
    },
    Tool {
        name: "check_bsl",
        description: "Проверить модуль BSL ДО записи в файл — ОДНИМ вызовом: структуру              (незакрытые блоки, скобки, Если без Тогда), ИМЕНА по индексу конфигурации              (есть ли такой метод, столько ли аргументов), НЕОПРЕДЕЛЁННЫЕ ПЕРЕМЕННЫЕ и              НЕДОСТУПНОЕ НА КЛИЕНТЕ в &НаКлиенте (Новый Запрос, серверные методы платформы,              серверный общий модуль без «Вызов сервера»). Отдаёт строку, колонку,              фрагмент и подсказку. Передайте module — путь правимого модуля в выгрузке:              тогда реквизиты формы и объекта сверяются точно. Что не проверено — в              not_checked. Текст ЗАПРОСА проверяется не здесь, а в канале данных (query_check).",
        schema: crate::check_bsl::schema,
    },
    Tool {
        name: "sql",
        description: "Read-only SQL к индексу — для вопросов, которых нет в наборе выше. \
             Разрешены только SELECT/WITH, один оператор. Сначала вызвать schema.",
        schema: schema_sql,
    },
];

/// Собрать схему инструмента, добавив к ней общий параметр `project`.
///
/// Добавляется ЗДЕСЬ, а не в каждой схеме отдельно, ровно по той причине,
/// по которой заведён этот слой: параметр, который надо не забыть повторить
/// в десяти местах, однажды забудут в одиннадцатом. Новый инструмент
/// получает `project` тем, что вообще пользуется этой функцией.
///
/// В `required` он НЕ входит: сервер, поднятый с одним `--db`, обязан
/// работать без него — иначе мультипроектность сломала бы прежние вызовы
/// ради возможности, которая тому пользователю не нужна. Требование
/// назвать проект накладывает реестр (`registry::Источник`), и только
/// когда проектов действительно несколько.
fn обяз(prop: Value, required: &[&str]) -> Value {
    let mut props = prop;
    if let Some(o) = props.as_object_mut() {
        o.insert(
            "project".into(),
            json!({
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}}
                ],
                "description":
                "Конфигурация 1С, к которой вопрос. Обязателен, когда сервер                  обслуживает несколько (см. list_projects); при одном индексе не нужен.                  Массив имён или \"*\" — спросить несколько конфигураций сразу:                  ответ придёт разделённым по проектам, а не склеенным"
            }),
        );
    }
    json!({"type": "object", "properties": props, "required": required})
}

/// У `projects` параметров нет: он отвечает про сам сервер.
///
/// Схема собирается НЕ через `обяз()` намеренно — иначе инструмент,
/// перечисляющий проекты, сам требовал бы указать проект.
fn schema_projects() -> Value {
    json!({"type": "object", "properties": {}})
}

fn schema_kb_1c() -> Value {
    json!({"type":"object","properties":{"project":{"type":"string","description":"Ровно один проект из list_projects; обязателен и для сервера с одним индексом"},"query":{"type":"string","description":"Вопрос пользователя о работе в конфигурации этого проекта"},"source_id":{"type":"string","description":"Ограничить поиск одним подключённым источником справки"},"config_version":{"type":"string","description":"Точная версия справки конфигурации"},"limit":{"type":"integer","default":8},"full":{"type":"boolean","default":false,"description":"Вернуть текст найденных страниц до 8000 символов"}},"required":["project","query"]})
}

fn schema_project_practices() -> Value {
    json!({"type":"object","properties":{"project":{"type":"string","description":"Ровно один проект из list_projects; практики разных конфигураций не смешиваются"},"view":{"type":"string","enum":["verified","candidates"],"default":"verified","description":"candidates добавляет не принятые практики для просмотра"}},"required":["project"]})
}

fn schema_standards_1c() -> Value {
    json!({"type":"object","properties":{
        "project":{"type":"string","description":"Ровно один проект из list_projects; корпус стандартов общий"},
        "view":{"type":"string","enum":["search","catalog","article","clause","practices"],"default":"search"},
        "query":{"type":"string","description":"Тема для view=search или фильтр принятых практик"},
        "rule_id":{"type":"string","description":"Точный ID общего правила для view=practices"},
        "article_id":{"type":"string","description":"ID статьи для view=article"},
        "clause_id":{"type":"string","description":"Адрес пункта для view=clause"},
        "offset":{"type":"integer","default":0,"minimum":0,"description":"Смещение каталога или текста пункта"},
        "max_chars":{"type":"integer","default":4000,"minimum":1,"maximum":8000,"description":"Длина фрагмента для view=clause"},
        "limit":{"type":"integer","default":8,"minimum":1,"maximum":50}},
        "required":["project"]})
}

/// У `delete_project` проект ОБЯЗАТЕЛЕН и ровно один.
///
/// Ни массива, ни `"*"`: массовое удаление одним вызовом — это операция,
/// в которой опечатка стоит пересборки всех индексов. Пусть зовут по разу.
fn schema_delete_project() -> Value {
    json!({
        "type": "object",
        "properties": {
            "project": {"type": "string", "description":
                "Имя проекта из list_projects. Удаляется файл индекса, исходники остаются"}
        },
        "required": ["project"]
    })
}

fn schema_find() -> Value {
    обяз(
        json!({
            "query": {"type": "string", "description":
                "Что ищем: имя объекта/метода или описание смысла на естественном языке"},
            "kind": {"type": "string", "enum": ["any", "object", "method", "module"],
                "default": "any", "description": "Ограничить род искомого"},
            "semantic": {"type": "boolean", "default": true, "description":
                "Искать и по смыслу (Р-017: одним ранжированным списком, не отдельным разделом). \n                 false — только лексика: дешевле и достаточно, когда имя известно точно"},
            "limit": {"type": "integer", "default": 20}
        }),
        &["query"],
    )
}

fn schema_object() -> Value {
    обяз(
        json!({
            "name": {"type": "string", "description": "Имя объекта, например ЗаказКлиента"},
            "category": {"type": "string", "description":
                "Категория (Catalogs/Documents/…), если имя неоднозначно"},
            "parts": {"type": "array", "items": {"type": "string"}, "description":
                "Что включить: attributes, synonyms, predefined, enum_values, movements, forms, rights, options, subscriptions, scheduled_jobs. \
                 По умолчанию — всё, кроме forms (их бывает много)"}
        }),
        &["name"],
    )
}

fn schema_impact() -> Value {
    обяз(
        json!({
            "symbol": {"type": "string", "description": "Метод или объект, который планируется изменить"},
            "kind": {"type": "string", "enum": ["auto", "method", "object"], "default": "auto",
                "description": "auto сначала ищет метод, затем объект"},
            "depth": {"type": "integer", "default": 2, "description": "Глубина входящего графа вызовов, 1-5"},
            "limit": {"type": "integer", "default": 100}
        }),
        &["symbol"],
    )
}

fn schema_callers() -> Value {
    обяз(
        json!({
            "method": {"type": "string", "description": "Имя метода"},
            "module": {"type": "string", "description":
                "Модуль, если метод одноимённый в нескольких (подстрока пути)"},
            "direction": {"type": "string", "enum": ["in", "out", "both"], "default": "in",
                "description": "in — кто вызывает; out — кого вызывает"},
            "depth": {"type": "integer", "default": 2, "description":
                "Глубина обхода. 1 — прямые связи"},
            "limit": {"type": "integer", "default": 100}
        }),
        &["method"],
    )
}

fn schema_detect_changes() -> Value {
    обяз(
        json!({
            "base_branch": {"type": "string", "default": "main", "description":
                "Ветка сравнения. Диапазон трёхточечный (base...HEAD) — от точки \
                 расхождения, поэтому чужие правки, приехавшие в base после ветвления, \
                 в выдачу не попадают"},
            "since": {"type": "string", "description":
                "Ссылка вместо ветки: HEAD~10, тег, коммит. Имеет приоритет над base_branch"},
            "direction": {"type": "string", "enum": ["inbound", "outbound", "both"],
                "default": "inbound", "description":
                "inbound — радиус поражения (кого заденет правка); outbound — от чего она зависит"},
            "depth": {"type": "integer", "default": 2, "description": "Глубина обхода, 1-5"},
            "scope": {"type": "string", "enum": ["files", "symbols"], "default": "symbols",
                "description": "files — только перечень изменённых файлов, без обхода графа"},
            "limit": {"type": "integer", "default": 200}
        }),
        &[],
    )
}

fn schema_read() -> Value {
    обяз(
        json!({
            "method": {"type": "string"},
            "module": {"type": "string", "description": "Подстрока пути модуля"}
        }),
        &["method"],
    )
}

fn schema_overrides() -> Value {
    обяз(
        json!({
            "object": {"type": "string", "description": "Перехваты этого объекта"},
            "extension": {"type": "string", "description": "Всё, что делает это расширение"}
        }),
        &[],
    )
}

fn schema_movements() -> Value {
    обяз(
        json!({
            "document": {"type": "string", "description": "Движения этого документа"},
            "register": {"type": "string", "description": "Кто пишет в этот регистр"}
        }),
        &[],
    )
}

fn schema_schema() -> Value {
    обяз(
        json!({"table": {"type": "string", "description":
            "Подробности по одной таблице; без него — список всех"}}),
        &[],
    )
}

fn schema_coverage() -> Value {
    обяз(json!({}), &[])
}

fn schema_grep() -> Value {
    обяз(
        json!({
            "pattern": {"type": "string", "description": "литерал или регулярное выражение"},
            "module": {"type": "string", "description": "сузить до модулей, чей путь или объект содержит это"},
            "max_files": {"type": "integer", "default": 2000},
            "limit": {"type": "integer", "default": 50},
            "case_sensitive": {"type": "boolean", "default": false}
        }),
        &["pattern"],
    )
}

fn schema_sql() -> Value {
    обяз(
        json!({
            "query": {"type": "string", "description": "SELECT или WITH … SELECT, один оператор"},
            "limit": {"type": "integer", "default": 200}
        }),
        &["query"],
    )
}

/// Перечень инструментов, видимых профилю.
pub fn list(profile: Profile) -> Vec<&'static Tool> {
    TOOLS.iter().filter(|t| profile.allows(t.name)).collect()
}

/// Выполнить инструмент. `Err` — текст для агента, а не паника.
pub fn call(
    conn: &Connection,
    profile: Profile,
    name: &str,
    args: &Value,
) -> Result<Value, String> {
    if !profile.allows(name) {
        return Err(format!(
            "инструмент '{name}' недоступен в профиле {profile:?} — см. tools/list"
        ));
    }
    match name {
        "kb_1c" => crate::kb_1c::search(conn, args),
        "project_practices" => crate::project_practices::profile(conn, args),
        "standards_1c" => crate::standards_1c::search(conn, args),
        "find" => find(conn, args),
        "object" => object(conn, args),
        "assist_bsl" => crate::assist_bsl::assist_bsl(conn, args),
        "callers" => callers(conn, args),
        "impact" => impact(conn, args),
        "read" => read(conn, args),
        "overrides" => overrides(conn, args),
        "movements" => movements(conn, args),
        "schema" => схема(conn, args),
        "coverage" => coverage(conn),
        "grep" => crate::grep::grep(conn, args),
        "detect_changes" => crate::changes::detect_changes(conn, args),
        "check_bsl" => crate::check_bsl::check_bsl(conn, args),
        "sql" => {
            let q = строка(args, "query").ok_or("нужен параметр query")?;
            let lim = число(args, "limit").unwrap_or(sql::DEFAULT_LIMIT as i64) as usize;
            sql::run(conn, &q, lim).map_err(|e| e.to_string())
        }
        _ => Err(format!("нет такого инструмента: {name}")),
    }
}

fn строка(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(str::to_string)
}
fn число(v: &Value, k: &str) -> Option<i64> {
    v.get(k).and_then(Value::as_i64)
}

/// Выполнить запрос и вернуть строки массивами (форма дешевле по токенам).
///
/// Запрос без параметров передаётся как `[]`, а не как пустой срез
/// `&[&dyn ToSql]`: пустой срез rusqlite трактует иначе, и запрос молча
/// возвращал ноль строк при непустой таблице. Поймано живым вызовом
/// `coverage`, который отдал пустую `index_meta` при пятнадцати строках в ней.
fn выборка(
    conn: &Connection,
    sql_text: &str,
    params: &[&dyn rusqlite::ToSql],
) -> Result<Value, String> {
    let mut st = conn.prepare(sql_text).map_err(|e| e.to_string())?;
    let колонки: Vec<String> = st.column_names().iter().map(|s| s.to_string()).collect();
    let n = колонки.len();
    let mut rows = if params.is_empty() {
        st.query([]).map_err(|e| e.to_string())?
    } else {
        st.query(params).map_err(|e| e.to_string())?
    };
    let mut out = Vec::new();
    while let Some(r) = rows.next().map_err(|e| e.to_string())? {
        let mut стр = Vec::with_capacity(n);
        for i in 0..n {
            стр.push(значение(r, i));
        }
        // Хвостовые `null` не печатаются: `["Имя","String",null,null,null]`
        // и `["Имя","String"]` несут одно и то же, но первое стоит на 15
        // знаков дороже КАЖДОЙ строки. На 176 реквизитах это 2 640 знаков
        // из 16 114 — шестая часть ответа уходила на отсутствие данных.
        //
        // Обрезается только ХВОСТ: `null` в середине означает «этой колонки
        // у этой строки нет», и позиции остальных значений сдвигать нельзя —
        // читатель сопоставляет их с `columns` по номеру.
        while стр.last() == Some(&Value::Null) {
            стр.pop();
        }
        out.push(Value::Array(стр));
    }
    Ok(json!({"columns": колонки, "rows": out, "count": out.len()}))
}

fn значение(r: &rusqlite::Row<'_>, i: usize) -> Value {
    use rusqlite::types::ValueRef;
    match r.get_ref(i) {
        Ok(ValueRef::Null) => Value::Null,
        Ok(ValueRef::Integer(v)) => json!(v),
        Ok(ValueRef::Real(v)) => json!(v),
        Ok(ValueRef::Text(v)) => json!(String::from_utf8_lossy(v)),
        Ok(ValueRef::Blob(b)) => json!(format!("<blob {} байт>", b.len())),
        Err(e) => json!(format!("<ошибка: {e}>")),
    }
}

/// Поиск: ОДИН ранжированный список (решение Р-017).
///
/// # Что изменилось 29.08.2026 и почему
///
/// Прежнее устройство (Р-016) отдавало пять независимых разделов: объекты,
/// методы, модули — каждый своим `LIKE`, плюс `semantic` отдельным списком
/// со своей шкалой. Ранжирования между ними не было вовсе, и это стоило
/// дорого по обеим осям:
///
/// * **токены** — раздел `semantic` пришивался к КАЖДОМУ ответу
///   (умолчание `semantic=true`) и занимал 79–81% выдачи. На запросе
///   `ЗаказКлиента`, где имя известно точно: 2 047 знаков против 386 без
///   него. Это и есть причина, по которой на сценариях приёмки S01/S02 мы
///   вчетверо дороже прежнего инструмента ПРИ ТОМ ЖЕ результате — у прежнего инструмента семантики
///   нет вовсе, он отвечает чистой лексикой;
/// * **смысл** — одна сущность, найденная и точным совпадением, и
///   семантикой, выдавалась ДВАЖДЫ в разных разделах и читалась как две
///   находки.
///
/// Теперь: кандидаты собираются всеми путями, сводятся в один список и
/// ранжируются взвешенным баллом (`gyrfalcon_index::rank`). Семантика —
/// ОДИН сигнал из четырёх, а не отдельная выдача.
///
/// # Что осталось честным
///
/// `semantic=false` по-прежнему выключает семантический проход целиком —
/// он стоит дороже прочих, и на запросе с точным именем не нужен. Разница
/// с прошлым устройством в том, что теперь выключение НЕ меняет структуру
/// ответа: список один в обоих случаях.
fn find(conn: &Connection, args: &Value) -> Result<Value, String> {
    use gyrfalcon_index::rank::{rank, точность, Candidate, Signals};

    let q = строка(args, "query").ok_or("нужен параметр query")?;
    let kind = строка(args, "kind").unwrap_or_else(|| "any".into());
    let limit = число(args, "limit").unwrap_or(20).clamp(1, 500) as usize;
    let семантика = args
        .get("semantic")
        .and_then(Value::as_bool)
        .unwrap_or(true);

    // Кандидатов набираем шире запрошенного: ранжирование должно иметь из
    // чего выбирать, иначе сигнал, срабатывающий у редкой строки, не попадёт
    // в выборку вовсе и не сможет ничего перевесить.
    let широта = (limit * 3).clamp(30, 300) as i64;
    let шаблон = format!("%{q}%");
    let mut кандидаты: Vec<Candidate> = Vec::new();

    // Редкость слов запроса. Считается один раз: она свойство ЗАПРОСА,
    // а не кандидата, и служит множителем доверия к совпадению — попадание
    // по «Получить» стоит меньше попадания по «Контрагент».
    //
    // IDF лежал в индексе с вехи 4 и в ранжировании не использовался вовсе.
    let idf_запроса: f32 = {
        let токены = gyrfalcon_parser::tokens::tokenize(&q);
        if токены.is_empty() {
            0.0
        } else {
            let mut сумма = 0.0f32;
            if let Ok(mut st) = conn.prepare("SELECT idf FROM semantic_tokens WHERE token = ?1") {
                for t in &токены {
                    сумма += st.query_row([t], |r| r.get::<_, f32>(0)).unwrap_or(1.0);
                }
            }
            сумма / токены.len() as f32
        }
    };

    // 1. Объекты метаданных.
    //
    // Перечень берётся из `object_synonyms` (одна строка на объект), а не из
    // `object_attributes` (таблицы РЕКВИЗИТОВ): объект без реквизитов в ней
    // не существует вовсе, и поиск молча не находил общие модули, константы,
    // функциональные опции, определяемые типы, общие команды. На запросе
    // «РеализацияТоваровУслуг» это давало 2 объекта вместо 13 — дефект
    // найден корпусом приёмки вехи 6, тестами не ловился (на фикстурах
    // реквизиты есть всегда).
    if kind == "any" || kind == "object" {
        // Ищем И ПО СИНОНИМУ — русскому названию объекта. Запрос «адресная
        // книга» обязан находить `АдреснаяКнига`: пользователь 1С видит в
        // интерфейсе синоним, а не имя метаданных. Сигнала с таким смыслом
        // у прежнего инструмента нет — в его 158 языках у сущности одно имя.
        // Сигнал «использование в коде» — НЕОБЯЗАТЕЛЬНЫЙ, но только в одном
        // смысле: индекс, собранный до вехи 3, таблицы `metadata_code_usages`
        // не содержит, и поиск обязан работать на нём без неё. Любая другая
        // ошибка — громкая. Прежде запасной путь срабатывал на ЛЮБОЙ сбой
        // prepare, и подзапрос по несуществующей колонке `metadata_name`
        // с 0.1.0 молча обнулял сигнал на всех индексах.
        let есть_упоминания: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master
                                WHERE type='table' AND name='metadata_code_usages')",
                [],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        // Счёт — отдельным запросом по ключу, а не подзапросом в SQL: ключ в
        // нижнем регистре, а `lower()` SQLite кириллицу не понижает.
        let mut st_упоминания = if есть_упоминания {
            Some(
                conn.prepare("SELECT COUNT(*) FROM metadata_code_usages WHERE object_ref_key = ?1")
                    .map_err(|e| e.to_string())?,
            )
        } else {
            None
        };
        // Порядок ДО лимита. Без него `LIMIT` брал первые строки в порядке
        // таблицы, и главный объект отсекался раньше, чем доходил до
        // ранжирования: на ЕРП.УХ запросу «Сотрудник» отвечают 539 объектов,
        // справочник `Сотрудники` в первые 30 не попадал, и никакой сигнал
        // не мог его поднять. Ключ дешёвый и грубый — точное имя, точный
        // синоним, префикс, длина, — тонкую работу делает `rank`; задача
        // ключа только не выбросить очевидного кандидата. `UNION` обёрнут
        // в подзапрос: выражения в ORDER BY составного SELECT SQLite не берёт.
        let mut st = conn
            .prepare(
                "SELECT object_name, category, synonym FROM (
                     SELECT s.object_name, s.category, COALESCE(s.synonym,'') AS synonym
                     FROM object_synonyms s
                     WHERE s.object_name LIKE ?1 COLLATE NOCASE
                        OR s.synonym LIKE ?1 COLLATE NOCASE
                     UNION
                     SELECT a.object_name, a.category, '' FROM object_attributes a
                     WHERE a.object_name LIKE ?1 COLLATE NOCASE)
                 ORDER BY object_name = ?3 COLLATE NOCASE DESC,
                          synonym = ?3 COLLATE NOCASE DESC,
                          object_name LIKE ?3 || '%' DESC,
                          synonym LIKE ?3 || '%' DESC,
                          length(object_name)
                 LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let rows: Vec<(String, String, String)> = st
            .query_map(rusqlite::params![&шаблон, широта, &q], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1).unwrap_or_default(),
                    r.get::<_, String>(2).unwrap_or_default(),
                ))
            })
            .map_err(|e| e.to_string())?
            .flatten()
            .collect();
        for (имя, кат, синоним) in rows {
            let usages: i64 = match (
                st_упоминания.as_mut(),
                gyrfalcon_index::build::ключ_упоминания(&кат, &имя),
            ) {
                (Some(st_u), Some(ключ)) => st_u
                    .query_row([&ключ], |r| r.get(0))
                    .map_err(|e| e.to_string())?,
                // Категория, на которую в коде не ссылаются (общий модуль,
                // функциональная опция), — ноль по существу, а не по сбою.
                _ => 0,
            };
            кандидаты.push(Candidate {
                kind: "object".into(),
                name: имя.clone(),
                payload: vec![кат, синоним.clone()],
                signals: Signals {
                    exact: точность(&имя, &q),
                    synonym: точность(&синоним, &q),
                    usage: (usages as f32 + 1.0).ln(),
                    idf: idf_запроса,
                    ..Default::default()
                },
            });
        }
    }

    // 2. Методы. Степень связности берём из графа вызовов тем же запросом:
    //    часто вызываемый метод при прочих равных релевантнее одиночного.
    if kind == "any" || kind == "method" {
        // Точное имя — отдельным добором по индексу `idx_meth_name`, а не
        // порядком в общей выборке. Порядок до лимита здесь пробовали
        // (06.10.2026) и отвергли замером: на 750 тыс. методов ЕРП.УХ он
        // убивает раннюю остановку `LIMIT` (+0,3 с на запрос), а ключ
        // «короче — выше» вытесняет сигнал степени: на «При» наверх лезли
        // `Принять` вместо `ПриСозданииНаСервере`. Добор стоит 1–10 мс и
        // гарантирует ровно то, что терялось, — метод с названным именем.
        //
        // Добор идёт ВТОРЫМ запросом и дописывается в конец: при равных
        // баллах `rank` сохраняет порядок поступления, и прежняя выборка
        // обязана прийти первой и в прежнем порядке — иначе на частых словах
        // менялась бы выдача, которую эта правка менять не собиралась
        // (проверено A/B: объединение в одном запросе переставляло «При»).
        const ВЫБОРКА: &str = "SELECT m.name, m.type, m.is_export, mo.rel_path, m.line,
                    (SELECT COUNT(*) FROM calls c
                      WHERE c.callee_key = mo.rel_path || '::' || lower(m.name)) AS deg
             FROM methods m JOIN modules mo ON mo.id = m.module_id";
        let mut строки: Vec<(String, String, i64, String, i64, i64)> = Vec::new();
        let mut уже: std::collections::HashSet<(String, i64)> = std::collections::HashSet::new();
        for (условие, образец) in [
            ("WHERE m.name LIKE ?1 COLLATE NOCASE LIMIT ?2", &шаблон),
            ("WHERE m.name = ?1 COLLATE NOCASE LIMIT ?2", &q),
        ] {
            let mut st = conn
                .prepare(&format!("{ВЫБОРКА} {условие}"))
                .map_err(|e| e.to_string())?;
            let rows = st
                .query_map(rusqlite::params![образец, широта], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1).unwrap_or_default(),
                        r.get::<_, i64>(2).unwrap_or(0),
                        r.get::<_, String>(3).unwrap_or_default(),
                        r.get::<_, i64>(4).unwrap_or(0),
                        r.get::<_, i64>(5).unwrap_or(0),
                    ))
                })
                .map_err(|e| e.to_string())?;
            for строка in rows.flatten() {
                if уже.insert((строка.3.clone(), строка.4)) {
                    строки.push(строка);
                }
            }
        }
        for (name, typ, exp, path, line, deg) in строки {
            кандидаты.push(Candidate {
                kind: "method".into(),
                name: name.clone(),
                payload: vec![typ, exp.to_string(), path, line.to_string()],
                signals: Signals {
                    exact: точность(&name, &q),
                    // Логарифм, а не сырое число: разница между 0 и 10
                    // вызовами содержательна, между 1000 и 1010 — нет.
                    degree: (deg as f32 + 1.0).ln(),
                    idf: idf_запроса,
                    ..Default::default()
                },
            });
        }
    }

    // 3. Модули.
    if kind == "any" || kind == "module" {
        let mut st = conn
            .prepare(
                "SELECT rel_path, category, object_name, module_type FROM modules
                 WHERE rel_path LIKE ?1 COLLATE NOCASE OR object_name LIKE ?1 COLLATE NOCASE
                 ORDER BY object_name = ?3 COLLATE NOCASE DESC,
                          object_name LIKE ?3 || '%' DESC,
                          length(rel_path)
                 LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let rows = st
            .query_map(rusqlite::params![&шаблон, широта, &q], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1).unwrap_or_default(),
                    r.get::<_, String>(2).unwrap_or_default(),
                    r.get::<_, String>(3).unwrap_or_default(),
                ))
            })
            .map_err(|e| e.to_string())?;
        for (path, cat, obj, mt) in rows.flatten() {
            кандидаты.push(Candidate {
                kind: "module".into(),
                name: path.clone(),
                payload: vec![cat, obj.clone(), mt],
                signals: Signals {
                    exact: точность(&obj, &q).max(точность(&path, &q)),
                    ..Default::default()
                },
            });
        }
    }

    // 4. Семантика — СИГНАЛ, а не раздел. Ошибку прохода не глотаем:
    //    пустая выдача сломанного поиска неотличима от честного «не нашлось».
    let mut ошибка_семантики: Option<String> = None;
    // На запрос-перечисление (`kind` задан, большой лимит) семантика не
    // подмешивается: вопрос «какие объекты называются так» — про ИМЯ, и
    // близкое по смыслу в ответе на него лишнее. Поймано приёмкой 29.08:
    // на S01 семантика добавляла `ВыпускПродукцииУслуг` и
    // `АктОбОказанииПроизводственныхУслуг` — по смыслу родня, по вопросу мусор.
    if семантика && !(kind != "any" && limit > 25) {
        match gyrfalcon_index::semantic::search(conn, &q, None, широта as usize) {
            Ok(hits) => {
                for h in hits {
                    // `Hit::name` у объектов приходит СКЛЕЕННЫМ с синонимом
                    // («Контрагенты Контрагенты») — так удобно человеку,
                    // читающему выдачу семантики отдельным списком. В общем
                    // ранжированном списке это ломает и склейку дубликатов
                    // (одна сущность в двух написаниях = две строки), и
                    // сверку с прежним инструментом, который отдаёт голое имя.
                    // Синоним — отдельный сигнал, а не часть имени.
                    let чистое = h
                        .name
                        .split_once(' ')
                        .filter(|(и, _)| !и.is_empty())
                        .map(|(и, _)| и.to_string())
                        .unwrap_or_else(|| h.name.clone());
                    кандидаты.push(Candidate {
                        kind: h.kind.clone(),
                        name: чистое.clone(),
                        payload: vec![],
                        signals: Signals {
                            exact: точность(&чистое, &q),
                            synonym: точность(&h.name, &q),
                            semantic: h.raw,
                            ..Default::default()
                        },
                    });
                }
            }
            Err(e) => ошибка_семантики = Some(e.to_string()),
        }
    }

    // 5. BM25 из FTS5 (триграммы) — текстовый сигнал поверх точного совпадения.
    //    Отдельная выборка: FTS находит и то, что `LIKE` пропускает при
    //    перестановке частей имени.
    if семантика || kind == "any" {
        for (табл, вид) in [("methods_fts", "method"), ("objects_fts", "object")] {
            let sql =
                // Без `ORDER BY rank` FTS5 отдаёт первые строки по rowid,
                // а `bm25()` лишь подписан к ним — лучшие по баллу могут не
                // войти в выборку. У объектов порядок почти бесплатен; у
                // методов на коротком частом слове стоит до +0,16 с (ЕРП.УХ,
                // замер 06.10.2026), а главное, что терялось, — точное имя —
                // там уже гарантирует добор. Компромисс записан в задаче.
                if вид == "object" {
                    format!(
                        "SELECT name, bm25({табл}) FROM {табл} WHERE {табл} MATCH ?1
                         ORDER BY rank LIMIT ?2"
                    )
                } else {
                    format!("SELECT name, bm25({табл}) FROM {табл} WHERE {табл} MATCH ?1 LIMIT ?2")
                };
            if let Ok(mut st) = conn.prepare(&sql) {
                let rows = st.query_map(rusqlite::params![&q, широта], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, f64>(1).unwrap_or(0.0)))
                });
                if let Ok(rows) = rows {
                    for (name, bm) in rows.flatten() {
                        // В `objects_fts` имя проиндексировано ВМЕСТЕ с
                        // синонимом («РеализацияТоваровУслуг Реализация
                        // (акты, накладные, УПД)») — это нужно поиску, чтобы
                        // находить по русскому названию. Но в выдаче имя
                        // должно быть голым, иначе одна сущность приходит
                        // дважды: из точной выборки без синонима и отсюда
                        // с ним, и склейка дубликатов их не узнаёт.
                        let чистое = name
                            .split_once(' ')
                            .filter(|(и, _)| !и.is_empty())
                            .map(|(и, _)| и.to_string())
                            .unwrap_or_else(|| name.clone());
                        кандидаты.push(Candidate {
                            kind: вид.into(),
                            name: чистое.clone(),
                            payload: vec![],
                            signals: Signals {
                                exact: точность(&чистое, &q),
                                synonym: точность(&name, &q),
                                // bm25() в SQLite отдаёт МЕНЬШЕ для лучшего
                                // совпадения. Разворачиваем, иначе сигнал
                                // будет тянуть список в обратную сторону.
                                bm25: -(bm as f32),
                                ..Default::default()
                            },
                        });
                    }
                }
            }
        }
    }

    // `kind` обязан фильтровать ВЫДАЧУ, а не только выбор источников.
    //
    // Поймано приёмкой 29.08: семантический и BM25-проходы добавляют
    // кандидатов независимо от `kind`, и на запросе `kind=object, limit=50`
    // в списке оказалось 43 метода из 50 мест — четыре законных объекта
    // вытеснены за предел лимита. Снаружи это выглядело как «мы находим
    // 7 объектов против 11 у прежнего инструмента», то есть как дефект ПОИСКА, хотя
    // объекты лежали в кандидатах и были вытеснены чужим видом.
    if kind != "any" {
        кандидаты.retain(|c| c.kind == kind);
    }

    let mut ранжированные = rank(кандидаты, limit);

    // Отсечка слабых.
    //
    // Балл ниже 0,25 — это строка, которую не поддержал ни один сигнал,
    // кроме нормированного смысла: она не «менее релевантная», а найденная
    // потому, что список надо было чем-то заполнить. Раньше такие занимали
    // 18 строк из 20 в каждом ответе и составляли до 90% выдачи в знаках.
    //
    // Отсечка НЕ применяется, когда не набралось трёх строк вообще: пустой
    // ответ на существующий объект хуже слабого, а отличить их можно по
    // самому баллу — он в выдаче есть.
    // Отсечка НЕ применяется, когда спрошен конкретный вид (`kind`) или
    // задан большой лимит: это запрос «перечисли всё, что подходит», и
    // урезать его по релевантности значит молча потерять законные находки.
    //
    // Поймано приёмкой 29.08: на `kind=object, limit=50` отсечка съедала
    // объекты вроде `ОсуществляетсяРеализацияТоваровУслугКомитентов` —
    // совпадение по подстроке с низким баллом, но это ОТВЕТ на вопрос
    // «какие объекты содержат такое имя», а не мусор. Стало 8 против 11
    // у прежнего инструмента. Ранжирование обязано менять ПОРЯДОК, а не состав.
    let перечисление = kind != "any" || limit > 25;
    if !перечисление && ранжированные.len() > 3 {
        let сильных = ранжированные.iter().filter(|r| r.score >= 0.25).count();
        if сильных >= 3 {
            ранжированные.retain(|r| r.score >= 0.25);
        } else {
            ранжированные.truncate(сильных.max(3));
        }
    }

    let rows: Vec<Value> = ранжированные
        .iter()
        .map(|r| {
            json!([
                r.name,
                r.kind,
                // Округление ЧЕРЕЗ f64: `(f32 * 1000).round()/1000` в JSON
                // печатается как 0.949999988079071 — двоичный хвост f32.
                ((r.score as f64) * 1000.0).round() / 1000.0,
                r.reason,
                r.payload
            ])
        })
        .collect();

    let mut out = json!({
        "query": q,
        "columns": ["name", "kind", "score", "reason", "details"],
        "rows": rows,
        "found": ранжированные.len(),
    });
    if let Some(e) = ошибка_семантики {
        out["semantic_error"] = json!(e);
    }
    Ok(out)
}

fn object(conn: &Connection, args: &Value) -> Result<Value, String> {
    let name = строка(args, "name").ok_or("нужен параметр name")?;
    let parts: Vec<String> = args
        .get("parts")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_else(|| {
            [
                "attributes",
                "synonyms",
                "predefined",
                "enum_values",
                "movements",
                "rights",
                "options",
                "subscriptions",
                "scheduled_jobs",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect()
        });
    let есть = |p: &str| parts.iter().any(|x| x == p);

    let mut out = json!({"object": name});

    if есть("attributes") {
        // Три сжатия, ни одно не теряет данных (замер 29.08.2026:
        // 16 114 знаков на 176 реквизитах, из них ПОЛОВИНА служебная).
        //
        // 1. Тип: одиночный отдаётся строкой, а не массивом в строке.
        //    Было `"[\"String\"]"` — 13 знаков, экранирование удваивает
        //    кавычки. Стало `"String"` — 8. Составные (1 525 штук на БП,
        //    вида `["CatalogRef.А", "CatalogRef.Б"]`) остаются массивом:
        //    их сворачивать нельзя, это разные типы, а не форматирование.
        // 2. Пустые числовые квалификаторы (`length`/`precision`/`scale`)
        //    не печатаются вовсе. У ссылочного реквизита длины нет —
        //    и `null` об этом говорит не больше, чем отсутствие поля,
        //    зато стоит 15 знаков на строку.
        // 3. `attr_kind` опускается для `attribute` — это умолчание
        //    (22 632 из 47 915 строк на БП). Названо в `note`, чтобы
        //    пропуск читался как умолчание, а не как потеря.
        out["attributes"] = выборка(
            conn,
            "SELECT attr_name,
                    CASE WHEN attr_type LIKE '[%' AND attr_type NOT LIKE '%,%'
                         THEN trim(replace(replace(attr_type,'[\"',''),'\"]',''))
                         ELSE attr_type END AS attr_type,
                    CASE WHEN attr_kind = 'attribute' THEN NULL ELSE attr_kind END AS attr_kind,
                    ts_name, length, precision, scale
             FROM object_attributes WHERE object_name = ?1 COLLATE NOCASE
             ORDER BY attr_kind, ts_name, attr_name",
            &[&name],
        )?;
        out["attributes"]["note"] =
            json!("пустой attr_kind = attribute (умолчание); отсутствующий квалификатор = неприменим к типу");
    }
    if есть("synonyms") {
        out["synonyms"] = выборка(
            conn,
            "SELECT category, synonym FROM object_synonyms
             WHERE object_name = ?1 COLLATE NOCASE",
            &[&name],
        )?;
    }
    if есть("predefined") {
        out["predefined"] = выборка(
            conn,
            "SELECT item_name, item_code, is_folder FROM predefined_items
             WHERE object_name = ?1 COLLATE NOCASE",
            &[&name],
        )?;
    }
    if есть("enum_values") {
        out["enum_values"] = выборка(
            conn,
            "SELECT name, values_json FROM enum_values WHERE name = ?1 COLLATE NOCASE",
            &[&name],
        )?;
    }
    if есть("movements") {
        out["movements"] = выборка(
            conn,
            "SELECT register_name, source, file FROM register_movements
             WHERE document_name = ?1 COLLATE NOCASE",
            &[&name],
        )?;
    }
    if есть("forms") {
        out["forms"] = выборка(
            conn,
            "SELECT DISTINCT form_name FROM modules
             WHERE object_name = ?1 COLLATE NOCASE AND is_form = 1",
            &[&name],
        )?;
    }
    if есть("rights") {
        out["rights"] = выборка(
            conn,
            "SELECT role_name, right_name, file FROM role_rights
             WHERE object_name = ?1 COLLATE NOCASE
             ORDER BY role_name, right_name",
            &[&name],
        )?;
    }
    if есть("options") {
        out["options"] = выборка(
            conn,
            "SELECT name, synonym, location, file FROM functional_options
             WHERE content LIKE '%' || ?1 || '%' COLLATE NOCASE
             ORDER BY name",
            &[&name],
        )?;
    }
    if есть("subscriptions") {
        out["subscriptions"] = выборка(
            conn,
            "SELECT name, event, handler_module, handler_procedure, source_types, file
             FROM event_subscriptions
             WHERE source_types LIKE '%' || ?1 || '%' COLLATE NOCASE
             ORDER BY name",
            &[&name],
        )?;
    }
    if есть("scheduled_jobs") {
        out["scheduled_jobs"] = выборка(
            conn,
            "SELECT name, method_name, handler_module, handler_procedure, use, file
             FROM scheduled_jobs
             WHERE handler_module LIKE '%' || ?1 || '%' COLLATE NOCASE
             ORDER BY name",
            &[&name],
        )?;
    }
    Ok(out)
}

fn callers(conn: &Connection, args: &Value) -> Result<Value, String> {
    let method = строка(args, "method").ok_or("нужен параметр method")?;
    let dir = строка(args, "direction").unwrap_or_else(|| "in".into());
    let depth = число(args, "depth").unwrap_or(2).clamp(1, 5);
    let limit = число(args, "limit").unwrap_or(100).clamp(1, 2000) as usize;

    let mut out = json!({"method": method, "direction": dir, "depth": depth});

    if dir == "in" || dir == "both" {
        // Транзитивное замыкание считает SQLite рекурсивным CTE: за один вызов,
        // а не циклом на стороне агента (Р-101 — ширина вызова вместо песочницы).
        let v = выборка(
            conn,
            "WITH RECURSIVE вверх(name, hop) AS (
                 SELECT ?1, 0
                 UNION
                 SELECT m.name, в.hop + 1
                 FROM вверх в
                 JOIN calls c ON c.callee_name = в.name COLLATE NOCASE
                 JOIN methods m ON m.id = c.caller_id
                 WHERE в.hop < ?2
             )
             SELECT в.name, в.hop, mo.rel_path, m.line
             FROM вверх в
             JOIN methods m ON m.name = в.name COLLATE NOCASE
             JOIN modules mo ON mo.id = m.module_id
             WHERE в.hop > 0 ORDER BY в.hop, в.name LIMIT ?3",
            &[&method, &depth, &(limit as i64)],
        )?;
        out["callers"] = v;
        // Вызовы в модульном коде — не единственная точка входа. Подписки и
        // регламентные задания запускаются платформой, поэтому в таблице calls
        // их принципиально нет; без этого раздела «никто не вызывает» было бы
        // ложным отрицанием.
        out["platform_entrypoints"] = platform_entrypoints(conn, &method)?;
    }
    if dir == "out" || dir == "both" {
        let v = выборка(
            conn,
            "SELECT c.callee_name, c.resolution, c.confidence, c.line
             FROM calls c JOIN methods m ON m.id = c.caller_id
             WHERE m.name = ?1 COLLATE NOCASE ORDER BY c.line LIMIT ?2",
            &[&method, &(limit as i64)],
        )?;
        out["callees"] = v;
    }
    Ok(out)
}

fn platform_entrypoints(conn: &Connection, method: &str) -> Result<Value, String> {
    выборка(
        conn,
        "SELECT 'event_subscription' AS kind, name, event AS trigger,
                handler_module, handler_procedure, file
         FROM event_subscriptions
         WHERE handler_procedure = ?1 COLLATE NOCASE
         UNION ALL
         SELECT 'scheduled_job' AS kind, name, method_name AS trigger,
                handler_module, handler_procedure, file
         FROM scheduled_jobs
         WHERE handler_procedure = ?1 COLLATE NOCASE
            OR method_name = ?1 COLLATE NOCASE
         ORDER BY kind, name",
        &[&method],
    )
}

fn impact(conn: &Connection, args: &Value) -> Result<Value, String> {
    let symbol = строка(args, "symbol").ok_or("нужен параметр symbol")?;
    let kind = строка(args, "kind").unwrap_or_else(|| "auto".into());
    let depth = число(args, "depth").unwrap_or(2).clamp(1, 5);
    let limit = число(args, "limit").unwrap_or(100).clamp(1, 2000);
    let method_exists: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM methods WHERE name = ?1 COLLATE NOCASE",
            rusqlite::params![&symbol],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    let use_method = kind == "method" || (kind == "auto" && method_exists > 0);
    if kind != "auto" && kind != "method" && kind != "object" {
        return Err("kind должен быть auto, method или object".into());
    }

    if use_method {
        if method_exists == 0 {
            return Err(format!("метод '{symbol}' не найден в индексе"));
        }
        let graph = callers(
            conn,
            &json!({"method": symbol, "direction": "in", "depth": depth, "limit": limit}),
        )?;
        let direct = graph["callers"]["count"].as_u64().unwrap_or(0);
        let entry = graph["platform_entrypoints"]["count"].as_u64().unwrap_or(0);
        return Ok(json!({
            "symbol": symbol, "kind": "method", "depth": depth,
            "callers": graph["callers"], "platform_entrypoints": graph["platform_entrypoints"],
            "risk": if entry + direct > 10 { "high" } else if entry + direct > 0 { "medium" } else { "unknown" },
            "note": "unknown означает, что индекс не нашёл входов; перед выводом об отсутствии проверьте coverage()."
        }));
    }

    let card = object(
        conn,
        &json!({"name": symbol, "parts": ["forms", "rights", "options", "subscriptions", "scheduled_jobs"]}),
    )?;
    let dependents = выборка(
        conn,
        "SELECT source_object, source_category, ref_kind, used_in, path, line
         FROM metadata_references WHERE ref_object LIKE '%' || ?1 || '%' COLLATE NOCASE
         ORDER BY source_category, source_object LIMIT ?2",
        &[&symbol, &limit],
    )?;
    Ok(json!({
        "symbol": symbol, "kind": "object", "card": card,
        "metadata_dependents": dependents,
        "note": "Для оценки конкретной процедуры вызовите impact(kind='method'); для объекта показаны адресные метаданные и платформенные связи."
    }))
}

fn read(conn: &Connection, args: &Value) -> Result<Value, String> {
    let method = строка(args, "method").ok_or("нужен параметр method")?;
    let module = строка(args, "module").unwrap_or_default();

    let mut st = conn
        .prepare(
            "SELECT mo.rel_path, m.line, m.end_line, m.type, m.params, m.is_export
             FROM methods m JOIN modules mo ON mo.id = m.module_id
             WHERE m.name = ?1 COLLATE NOCASE AND mo.rel_path LIKE ?2
             ORDER BY length(mo.rel_path) LIMIT 5",
        )
        .map_err(|e| e.to_string())?;
    let шаблон = if module.is_empty() {
        "%".to_string()
    } else {
        format!("%{module}%")
    };
    let найдено: Vec<(String, i64, i64, String, String, i64)> = st
        .query_map(rusqlite::params![&method, &шаблон], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get::<_, Option<String>>(4)?.unwrap_or_default(),
                r.get(5)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .filter_map(std::result::Result::ok)
        .collect();

    if найдено.is_empty() {
        // Не «пусто», а отказ с причиной: пустой ответ читается как факт
        // об отсутствии метода, и это ровно та ошибка, ради которой заведён
        // инструмент coverage.
        return Err(format!(
            "метод '{method}' не найден в индексе{}. Это может значить и то, что он \
             не проиндексирован — проверьте инструментом coverage",
            if module.is_empty() {
                String::new()
            } else {
                format!(" (модуль ~ '{module}')")
            }
        ));
    }
    if найдено.len() > 1 {
        return Ok(json!({
            "ambiguous": true,
            "note": "метод найден в нескольких модулях — уточните параметр module",
            "candidates": найдено.iter().map(|f| json!([f.0, f.1])).collect::<Vec<_>>()
        }));
    }

    let (путь, line, end_line, тип, params, экспорт) = найдено.into_iter().next().unwrap();
    // Корень выгрузки известен индексу — тело читается на сервере и наружу
    // уходит ОДНА процедура, а не файл.
    // Ключ называется source_path — проверено на живом индексе, а не взято
    // из памяти о схеме. Первая редакция читала `base_path` и молча не
    // находила корень: `read` отвечал бы отказом на каждый вызов.
    let корень: Option<String> = conn
        .query_row(
            "SELECT value FROM index_meta WHERE key = 'source_path'",
            [],
            |r| r.get(0),
        )
        .ok();
    let корень = корень.ok_or("в индексе нет source_path — пересоберите индекс")?;
    let полный = std::path::Path::new(&корень).join(&путь);
    let текст = std::fs::read(&полный)
        .map_err(|e| format!("модуль {} недоступен: {e}", полный.display()))?;
    let текст = String::from_utf8_lossy(
        текст
            .strip_prefix(&[0xEF, 0xBB, 0xBF])
            .unwrap_or(текст.as_slice()),
    );
    let строки: Vec<&str> = текст.lines().collect();
    let a = (line.max(1) as usize) - 1;
    let b = (end_line.max(line) as usize).min(строки.len());
    let тело = строки[a.min(строки.len())..b].join("\n");

    Ok(json!({
        "method": method, "module": путь, "type": тип,
        "params": params, "is_export": экспорт == 1,
        "line": line, "end_line": end_line,
        "body": тело
    }))
}

fn overrides(conn: &Connection, args: &Value) -> Result<Value, String> {
    let object = строка(args, "object");
    let extension = строка(args, "extension");
    match (object, extension) {
        (Some(o), _) => выборка(
            conn,
            "SELECT object_name, target_method, annotation, extension_name, extension_purpose,
                    ext_module_path, ext_line, target_method_line
             FROM extension_overrides WHERE object_name LIKE ?1 COLLATE NOCASE",
            &[&format!("%{o}%")],
        ),
        (None, Some(e)) => {
            let перехваты = выборка(
                conn,
                "SELECT object_name, target_method, annotation, extension_name, extension_purpose,
                        ext_module_path, ext_line
                 FROM extension_overrides WHERE extension_name LIKE ?1 COLLATE NOCASE",
                &[&format!("%{e}%")],
            )?;
            // «Всё, что делает расширение» — это и его собственные объекты, а
            // не только перехваты (Р-022). На индексе схемы 3 состава нет —
            // так и говорим, а не отдаём перехваты за полный ответ.
            if !есть_таблица(conn, "extension_objects") {
                return Ok(json!({
                    "overrides": перехваты,
                    "objects": null,
                    "note": "индекс собран до Р-022 (схема < 4): собственные объекты и код \
                             расширений в нём не индексированы — пересоберите индекс"
                }));
            }
            let объекты = выборка(
                conn,
                "SELECT extension_name, category, object_name, belonging, source_file
                 FROM extension_objects WHERE extension_name LIKE ?1 COLLATE NOCASE
                 ORDER BY extension_name, belonging DESC, category, object_name",
                &[&format!("%{e}%")],
            )?;
            Ok(json!({
                "overrides": перехваты,
                "objects": объекты,
                "note": "belonging: own — объект расширения; adopted — заимствован, его \
                         свойства в индексе от основной конфигурации плюс добавленное расширением. \
                         Код расширения адресуется путём от rel_root (../ext/<Имя>/… или ../cfe/…) в find/read/callers"
            }))
        }
        (None, None) => {
            if !есть_таблица(conn, "extensions") {
                return выборка(
                    conn,
                    "SELECT extension_name, extension_purpose, count(*) AS перехватов
                     FROM extension_overrides GROUP BY extension_name, extension_purpose",
                    &[],
                );
            }
            // Все расширения, а не только с перехватами: прежняя выборка шла
            // по `extension_overrides`, и расширение без перехвата в списке
            // отсутствовало — на ДО два из девяти.
            выборка(
                conn,
                "SELECT e.name, e.purpose,
                        (SELECT count(*) FROM extension_overrides o WHERE o.extension_name = e.name) AS перехватов,
                        (SELECT count(*) FROM extension_objects x
                          WHERE x.extension_name = e.name AND x.belonging = 'own') AS своих_объектов,
                        (SELECT count(*) FROM extension_objects x
                          WHERE x.extension_name = e.name AND x.belonging = 'adopted') AS заимствовано,
                        (SELECT count(*) FROM modules m WHERE m.rel_path LIKE e.rel_root || '/%') AS модулей
                 FROM extensions e ORDER BY e.name",
                &[],
            )
        }
    }
}

/// Есть ли таблица в индексе: новые таблицы появляются с версией схемы,
/// а читать приходится и индексы, собранные раньше.
fn есть_таблица(conn: &Connection, имя: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [имя],
        |r| r.get::<_, bool>(0),
    )
    .unwrap_or(false)
}

fn movements(conn: &Connection, args: &Value) -> Result<Value, String> {
    let doc = строка(args, "document");
    let reg = строка(args, "register");
    match (doc, reg) {
        (Some(d), _) => выборка(
            conn,
            "SELECT register_name, source, file FROM register_movements
             WHERE document_name LIKE ?1 COLLATE NOCASE",
            &[&format!("%{d}%")],
        ),
        (None, Some(r)) => выборка(
            conn,
            "SELECT document_name, source, file FROM register_movements
             WHERE register_name LIKE ?1 COLLATE NOCASE",
            &[&format!("%{r}%")],
        ),
        (None, None) => Err("нужен document или register".into()),
    }
}

fn схема(conn: &Connection, args: &Value) -> Result<Value, String> {
    if let Some(t) = строка(args, "table") {
        let cols = выборка(
            conn,
            "SELECT name, type, \"notnull\", pk FROM pragma_table_info(?1)",
            &[&t],
        )?;
        let строк: i64 = conn
            .query_row(
                &format!("SELECT count(*) FROM \"{}\"", t.replace('"', "")),
                [],
                |r| r.get(0),
            )
            .unwrap_or(-1);
        return Ok(json!({"table": t, "columns": cols, "rows": строк}));
    }
    // Список таблиц с назначением: назначение берётся из описи схемы, а не
    // выдумывается по имени.
    let mut список = Vec::new();
    for t in gyrfalcon_index::schema::TABLES
        .iter()
        .chain(gyrfalcon_index::schema::OWN_TABLES)
    {
        let n: i64 = conn
            .query_row(&format!("SELECT count(*) FROM \"{}\"", t.name), [], |r| {
                r.get(0)
            })
            .unwrap_or(-1);
        список.push(json!([t.name, n, t.purpose]));
    }
    Ok(json!({
        "columns": ["table", "rows", "purpose"],
        "rows": список,
        "note": "число -1 значит, что таблицы нет в этом индексе"
    }))
}

/// Чего в индексе нет (решение Р-104).
///
/// Оговорка про неполноту стоит в самом ответе, а не в документации: её
/// читает агент, а документацию — нет.
fn coverage(conn: &Connection) -> Result<Value, String> {
    let мета = выборка(conn, "SELECT key, value FROM index_meta ORDER BY key", &[])?;
    let рёбра: (i64, i64) = conn
        .query_row(
            "SELECT count(*), sum(callee_key IS NOT NULL) FROM calls",
            [],
            |r| Ok((r.get(0)?, r.get::<_, Option<i64>>(1)?.unwrap_or(0))),
        )
        .map_err(|e| e.to_string())?;
    let по_классам = выборка(
        conn,
        "SELECT resolution, count(*) FROM calls GROUP BY resolution ORDER BY 2 DESC",
        &[],
    )?;
    let доля = if рёбра.0 > 0 {
        (рёбра.1 as f64 / рёбра.0 as f64 * 1000.0).round() / 10.0
    } else {
        0.0
    };
    Ok(json!({
        "meta": мета,
        "calls_total": рёбра.0,
        "calls_resolved": рёбра.1,
        "calls_resolved_pct": доля,
        "resolution_classes": по_классам,
        "warning": "Отсутствие записи об ошибке НЕ гарантирует полноту. Если ответ \
                    «не найдено» выглядит подозрительно — он может означать «не \
                    проиндексировано», а не «в конфигурации нет»."
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Расширение без перехватов обязано быть в списке (Р-022).
    ///
    /// Прежде список шёл по `extension_overrides`, и на ДО два расширения
    /// из девяти в нём отсутствовали — их собственный код был невидим.
    #[test]
    fn список_расширений_включает_расширение_без_перехватов() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(gyrfalcon_index::ddl::SCHEMA).unwrap();
        c.execute_batch(gyrfalcon_index::ddl::SCHEMA_EXTENSIONS)
            .unwrap();
        c.execute_batch(
            "INSERT INTO extensions (name, purpose, name_prefix, rel_root) VALUES
               ('Перехватчик','Patch',NULL,'../ext/Перехватчик'),
               ('СвойКод','Customization','Св_','../ext/СвойКод');
             INSERT INTO extension_overrides (object_name, target_method, annotation,
                 extension_name, extension_root, ext_module_path, ext_line)
               VALUES ('Товар','ПриЗаписи','После','Перехватчик','x','Catalogs/Товар/Ext/ObjectModule.bsl',1);
             INSERT INTO extension_objects VALUES
               ('СвойКод','CommonModules','Св_Сервис','own','../ext/СвойКод/CommonModules/Св_Сервис.xml'),
               ('СвойКод','Catalogs','Товар','adopted','../ext/СвойКод/Catalogs/Товар.xml');
             INSERT INTO modules (id, rel_path, category, object_name, module_type, is_form, size)
               VALUES (1,'../ext/СвойКод/CommonModules/Св_Сервис/Ext/Module.bsl',
                       'CommonModules','Св_Сервис','Module',0,10);",
        )
        .unwrap();

        let r = call(&c, Profile::All, "overrides", &json!({})).unwrap();
        let строки = r["rows"].as_array().unwrap();
        assert_eq!(строки.len(), 2, "{r}");
        let свой = строки
            .iter()
            .find(|s| s[0] == "СвойКод")
            .expect("расширение без перехватов пропало из списка");
        // перехватов, своих объектов, заимствовано, модулей
        assert_eq!(
            (&свой[2], &свой[3], &свой[4], &свой[5]),
            (&json!(0), &json!(1), &json!(1), &json!(1))
        );

        let r = call(
            &c,
            Profile::All,
            "overrides",
            &json!({"extension": "СвойКод"}),
        )
        .unwrap();
        assert_eq!(r["objects"]["rows"].as_array().unwrap().len(), 2, "{r}");
    }

    /// Индекс до Р-022: таблиц реестра нет — прежний ответ, а не падение,
    /// и честная пометка, что состава расширения в индексе нет.
    #[test]
    fn расширения_на_индексе_старой_схемы() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE extension_overrides (object_name TEXT, target_method TEXT,
               annotation TEXT, extension_name TEXT, extension_purpose TEXT,
               ext_module_path TEXT, ext_line INTEGER, target_method_line INTEGER);
             INSERT INTO extension_overrides VALUES ('Товар','ПриЗаписи','После','Старое',NULL,'m',1,2);",
        )
        .unwrap();
        let r = call(&c, Profile::All, "overrides", &json!({})).unwrap();
        assert_eq!(r["rows"].as_array().unwrap().len(), 1, "{r}");
        let r = call(
            &c,
            Profile::All,
            "overrides",
            &json!({"extension": "Старое"}),
        )
        .unwrap();
        assert!(r["objects"].is_null(), "{r}");
        assert!(r["note"].as_str().unwrap().contains("пересоберите"), "{r}");
    }

    /// База с объектом БЕЗ реквизитов — тот случай, на котором ломался поиск.
    ///
    /// Общий модуль, константа, функциональная опция реквизитов не имеют
    /// вовсе, и пока `find` искал объекты в таблице РЕКВИЗИТОВ, они были
    /// невидимы. Фикстура строится настоящим DDL индексатора: выдуманная
    /// схема уже один раз позволила дефекту дожить до живого индекса.
    fn база_с_безреквизитным() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(gyrfalcon_index::ddl::SCHEMA_META).unwrap();
        c.execute_batch(
            "INSERT INTO object_synonyms (object_name, category, synonym, file) VALUES
               ('РеализацияТоваровУслуг','Documents','Реализация','Documents/Р.xml'),
               ('РеализацияТоваровУслугФормы','CommonModules','','CommonModules/Р.xml'),
               ('ОсуществляетсяРеализация','FunctionalOptions','','FO/О.xml');
             INSERT INTO object_attributes
                 (object_name, category, attr_name, attr_type, attr_kind, source_file)
               VALUES ('РеализацияТоваровУслуг','Documents','Контрагент',
                       'CatalogRef.Контрагенты','attribute','Documents/Р.xml');",
        )
        .unwrap();
        c
    }

    /// Поиск объекта не должен зависеть от того, есть ли у объекта реквизиты.
    ///
    /// Дефект найден корпусом приёмки вехи 6: на живой БП запрос
    /// «РеализацияТоваровУслуг» давал 2 объекта вместо 13, потому что
    /// одиннадцать не имели реквизитов. Эталон на тот же вопрос отвечал
    /// полным списком — расхождение и вскрыло причину.
    #[test]
    fn поиск_находит_объект_без_реквизитов() {
        let c = база_с_безреквизитным();
        let r = call(
            &c,
            Profile::All,
            "find",
            &json!({"query": "Реализация", "kind": "object", "semantic": false}),
        )
        .unwrap();
        // Р-017: выдача — ОДИН ранжированный список `rows`, а не разделы
        // по видам. Проверка та же: объект без реквизитов обязан найтись.
        let имена: Vec<String> = r["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s[0].as_str().unwrap().to_string())
            .collect();
        assert!(
            имена.iter().any(|x| x == "РеализацияТоваровУслугФормы"),
            "общий модуль без реквизитов не найден: {имена:?}"
        );
        assert!(
            имена.iter().any(|x| x == "ОсуществляетсяРеализация"),
            "функциональная опция не найдена: {имена:?}"
        );
        assert!(
            имена.iter().any(|x| x == "РеализацияТоваровУслуг"),
            "объект С реквизитами потерян — добор из object_attributes сломан: {имена:?}"
        );
    }

    /// Сигнал «использование в коде» обязан доходить до ранжирования.
    ///
    /// С 0.1.0 подзапрос обращался к колонке `metadata_name`, которой в
    /// схеме нет; prepare падал, запасной путь отдавал `usage = 0`, и выдача
    /// выглядела нормальной. Два документа с равным совпадением по имени —
    /// упоминаемый в коде обязан стоять выше. Кириллица в имени нарочно:
    /// `lower()` SQLite её не понижает.
    #[test]
    fn использование_в_коде_поднимает_объект() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(gyrfalcon_index::ddl::SCHEMA).unwrap();
        c.execute_batch(gyrfalcon_index::ddl::SCHEMA_META).unwrap();
        c.execute_batch(gyrfalcon_index::ddl::SCHEMA_USAGES)
            .unwrap();
        c.execute_batch(
            "INSERT INTO object_synonyms (object_name, category, synonym, file) VALUES
               ('ЗаказА','Documents','','Documents/А.xml'),
               ('ЗаказБ','Documents','','Documents/Б.xml');
             INSERT INTO modules(id, rel_path, object_name, is_form) VALUES
               (1, 'CommonModules/М/Module.bsl', 'М', 0);",
        )
        .unwrap();
        for i in 0..5 {
            c.execute(
                "INSERT INTO metadata_code_usages
                   (module_id, object_ref, object_ref_key, member_path, usage_kind, line)
                 VALUES (1, 'Document.ЗаказБ', ?1, NULL, 'manager', ?2)",
                rusqlite::params![
                    gyrfalcon_index::build::ключ_упоминания("Documents", "ЗаказБ").unwrap(),
                    i
                ],
            )
            .unwrap();
        }
        let r = call(
            &c,
            Profile::All,
            "find",
            &json!({"query": "Заказ", "kind": "object", "semantic": false}),
        )
        .unwrap();
        let имена: Vec<String> = r["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s[0].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            имена.first().map(String::as_str),
            Some("ЗаказБ"),
            "упоминаемый в коде объект не поднялся — сигнал usage не дошёл: {имена:?}"
        );
    }

    /// Главный кандидат не должен отсекаться лимитом выборки ДО ранжирования.
    ///
    /// На ЕРП.УХ запросу «Сотрудник» отвечают 539 объектов; выборка брала
    /// первые 30 в порядке таблицы, и справочника `Сотрудники` в выдаче не
    /// было вовсе — ни один сигнал не поднимет кандидата, которого нет.
    /// Здесь 40 однокоренных имён стоят в таблице раньше главного, и оно
    /// обязано найтись — и среди объектов, и среди методов.
    #[test]
    fn главный_кандидат_не_отсекается_до_ранжирования() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(gyrfalcon_index::ddl::SCHEMA).unwrap();
        c.execute_batch(gyrfalcon_index::ddl::SCHEMA_META).unwrap();
        c.execute_batch("INSERT INTO modules(id, rel_path, object_name, is_form) VALUES (1, 'CommonModules/М/Module.bsl', 'М', 0);")
            .unwrap();
        for i in 0..40 {
            c.execute(
                "INSERT INTO object_synonyms (object_name, category, synonym, file)
                 VALUES (?1, 'Catalogs', '', 'Catalogs/x.xml')",
                [format!("СотрудникА{i:02}")],
            )
            .unwrap();
            c.execute(
                "INSERT INTO methods(module_id, name, type, line) VALUES (1, ?1, 'Procedure', ?2)",
                rusqlite::params![format!("ПолучитьДанныеА{i:02}"), i],
            )
            .unwrap();
        }
        c.execute_batch(
            "INSERT INTO object_synonyms (object_name, category, synonym, file)
               VALUES ('Сотрудники', 'Catalogs', '', 'Catalogs/Сотрудники.xml');
             INSERT INTO methods(module_id, name, type, line)
               VALUES (1, 'ПолучитьДанные', 'Function', 100);",
        )
        .unwrap();

        for (запрос, вид, главный) in [
            ("Сотрудник", "object", "Сотрудники"),
            ("ПолучитьДанные", "method", "ПолучитьДанные"),
        ] {
            let r = call(
                &c,
                Profile::All,
                "find",
                &json!({"query": запрос, "kind": вид, "limit": 10, "semantic": false}),
            )
            .unwrap();
            let имена: Vec<String> = r["rows"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s[0].as_str().unwrap().to_string())
                .collect();
            assert!(
                имена.iter().any(|x| x == главный),
                "{вид} «{главный}» отсечён до ранжирования: {имена:?}"
            );
        }
    }

    #[test]
    fn профили_режут_набор() {
        assert!(Profile::All.allows("sql"));
        assert!(
            !Profile::Analysis.allows("sql"),
            "аналитику SQL не выдаётся"
        );
        assert!(!Profile::Scout.allows("callers"));
        assert!(Profile::Scout.allows("find"));
        assert!(Profile::Scout.allows("coverage"), "разведке нужна полнота");
    }

    #[test]
    fn карточка_и_impact_видят_метаданные_и_платформенные_входы() {
        // Фикстура создаётся тем же DDL, что и рабочий индекс: иначе тест
        // проверял бы выдуманную схему и не поймал бы несовпадение колонок.
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(gyrfalcon_index::ddl::SCHEMA).unwrap();
        c.execute_batch(gyrfalcon_index::ddl::SCHEMA_META).unwrap();
        c.execute_batch(gyrfalcon_index::ddl::SCHEMA_META2).unwrap();
        c.execute_batch(gyrfalcon_index::ddl::SCHEMA_REFS).unwrap();
        c.execute_batch(
            "INSERT INTO modules(id, rel_path, object_name, is_form) VALUES
               (1, 'Documents/Заказ/ObjectModule.bsl', 'Заказ', 0),
               (2, 'Documents/Заказ/Form.xml', 'Заказ', 1);
             INSERT INTO methods(id, module_id, name, type, line) VALUES
               (1, 1, 'Провести', 'Procedure', 10),
               (2, 1, 'Запустить', 'Procedure', 20);
             INSERT INTO calls(id, caller_id, callee_name, line, resolution, confidence) VALUES
               (1, 2, 'Провести', 21, 'exact', 1.0);
             INSERT INTO role_rights(role_name, object_name, right_name, file) VALUES
               ('Менеджер', 'Заказ', 'Read', 'Roles/Менеджер.xml');
             INSERT INTO functional_options(name, content, file) VALUES
               ('ИспользоватьЗаказы', 'Document.Заказ', 'FunctionalOptions/Заказы.xml');
             INSERT INTO event_subscriptions(name, event, handler_module, handler_procedure, source_types, file) VALUES
               ('ПередПроведениемЗаказа', 'BeforeWrite', 'Заказ', 'Провести', '[\"Document.Заказ\"]', 'EventSubscriptions/Заказ.xml');
             INSERT INTO scheduled_jobs(name, method_name, handler_module, handler_procedure, file) VALUES
               ('НочнойЗаказ', 'Провести', 'Заказ', 'Провести', 'ScheduledJobs/Заказ.xml');
             INSERT INTO metadata_references(source_object, source_category, ref_object, ref_kind, used_in, path) VALUES
               ('Продажа', 'Documents', 'Заказ', 'attribute_type', 'Document.Продажа.Заказ', 'Documents/Продажа.xml');",
        ).unwrap();

        let card = object(&c, &json!({"name": "Заказ", "parts": ["forms", "rights", "options", "subscriptions", "scheduled_jobs"]})).unwrap();
        assert_eq!(card["forms"]["rows"].as_array().unwrap().len(), 1);
        assert_eq!(card["rights"]["rows"].as_array().unwrap().len(), 1);
        assert_eq!(card["subscriptions"]["rows"].as_array().unwrap().len(), 1);

        let method = impact(&c, &json!({"symbol": "Провести", "kind": "method"})).unwrap();
        assert_eq!(
            method["platform_entrypoints"]["rows"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(method["risk"], json!("medium"));
        let object = impact(&c, &json!({"symbol": "Заказ", "kind": "object"})).unwrap();
        assert_eq!(
            object["metadata_dependents"]["rows"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn список_инструментов_зависит_от_профиля() {
        assert_eq!(list(Profile::All).len(), TOOLS.len());
        assert!(list(Profile::Scout).len() < list(Profile::Analysis).len());
    }

    #[test]
    fn имена_инструментов_уникальны() {
        let mut n: Vec<&str> = TOOLS.iter().map(|t| t.name).collect();
        n.sort_unstable();
        let было = n.len();
        n.dedup();
        assert_eq!(было, n.len(), "дубли имён инструментов");
    }

    #[test]
    fn у_каждого_инструмента_есть_схема_и_описание() {
        for t in TOOLS {
            let s = (t.schema)();
            assert_eq!(s["type"], "object", "{}: схема не объект", t.name);
            assert!(
                t.description.len() > 40,
                "{}: описание короче, чем нужно агенту, чтобы понять, когда звать",
                t.name
            );
        }
    }

    #[test]
    fn недоступный_профилю_инструмент_отказывает_а_не_молчит() {
        let c = Connection::open_in_memory().unwrap();
        let e = call(&c, Profile::Scout, "sql", &json!({"query": "SELECT 1"})).unwrap_err();
        assert!(e.contains("недоступен"), "получено: {e}");
    }
}
