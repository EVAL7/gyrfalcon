//! Третий слой `check_bsl`: неопределённые переменные и контекст исполнения (MCP-06).
//!
//! # Зачем
//!
//! Платформенный `/CheckConfig` ловит оба класса, но по типовой конфигурации
//! идёт десятки минут (замер на ERP 09.10.2026 — 21 мин 19 с), и гонять его на
//! каждой задаче нельзя. Калибровка 09.10.2026 на модуле формы расширения:
//!
//! | подлог | `/CheckConfig` | `check_bsl` 0.1.9 |
//! |---|---|---|
//! | неопределённая переменная на сервере | (4,14) «Переменная не определена» | `ok: true` |
//! | `Новый Запрос` в `&НаКлиенте` | (9,17) «Тип не определен (Запрос)» | `ok: true` |
//!
//! # Источники правды — три, и у каждого своя часть
//!
//! * **дерево разбора** — что объявлено и что прочитано (`gyrfalcon_parser::scope`);
//! * **справка платформы** — глобальные имена, свойства типов и раздел
//!   «Доступность» у типов и методов (`platform_help::context`);
//! * **индекс конфигурации** — реквизиты формы и объекта, общие модули и их
//!   флаги (`common_modules`, схема 5).
//!
//! Без любого из них соответствующая часть проверки НЕ делается и говорит об
//! этом в ответе. Половинный зелёный ответ читается как полный.
//!
//! # Правило молчания
//!
//! Ложная тревога здесь дороже пропуска: инструмент, который врёт на верном
//! коде, перестают читать вместе с тем, где он прав. Поэтому везде, где
//! неизвестно, — молчим: метод под `#Если`, раздел «Доступность» пуст, тип
//! справке не известен, модуль не найден в индексе.

use crate::platform_help::{OnThinClient, PlatformContext};
use gyrfalcon_parser::scope::{self, Context, ModuleScope};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

/// Имена, которые компилятор принимает, а справка платформы 8.3.27 не знает.
///
/// Не догадка, а факт о поставляемом коде: каждое имя стоит в типовых
/// конфигурациях, которые компилируются, — адрес рядом. Из справки их не
/// вывести, и без списка каждое давало бы ложное «Переменная не определена»
/// (84 раза на 22,8 млн имён трёх корпусов, 13.10.2026).
///
/// Пополняется только по калибровке на корпусе с адресом, не «по памяти».
/// Тест `исключения_справке_неизвестны` падает, когда справка начинает
/// имя знать, — тогда запись удаляется.
pub const ПРИНИМАЕТ_КОМПИЛЯТОР: &[(&str, &str)] = &[
    (
        "РежимОткрытияОкна",
        "свойство формы; в справке — `РежимОткрытияОкнаФормы`. \
         ДО: Catalogs/ПравилаОбработки/Forms/ФормаЭлемента/Ext/Form/Module.bsl:189; \
         БП: Catalogs/СтраныМира/Forms/ФормаСписка/Ext/Form/Module.bsl:95",
    ),
    (
        "ТипЭлементаФорматированногоДокумента",
        "системное перечисление, страницы в справке нет. \
         ДО: Catalogs/РассылкиОтчетов/Forms/ФормаЭлемента/Ext/Form/Module.bsl:2082; \
         БП: Catalogs/РассылкиОтчетов/Forms/НастройкаРассылкиБП/Ext/Form/Module.bsl:448",
    ),
];

fn принимает_компилятор(name: &str) -> bool {
    let низ = name.to_lowercase();
    ПРИНИМАЕТ_КОМПИЛЯТОР
        .iter()
        .any(|(n, _)| n.to_lowercase() == низ)
}

/// Итог слоя: замечания и то, что проверено и что нет.
pub struct ScopeReport {
    pub issues: Vec<Value>,
    pub checked_names: usize,
    pub checked_client_methods: usize,
    /// Чего этот слой НЕ проверил и почему — едет в ответ как есть.
    pub skipped: Vec<String>,
    /// Как определён набор реквизитов: `module` — точно по модулю,
    /// `union` — объединение по конфигурации, `none` — не определялся.
    pub attributes_from: &'static str,
}

/// Флаги общего модуля, нужные проверке.
#[derive(Clone, Copy)]
struct Флаги {
    global: bool,
    client: bool,
    server: bool,
    server_call: bool,
}

pub fn check(
    conn: &Connection,
    source: &str,
    module: Option<&str>,
    platform: Result<&PlatformContext, String>,
) -> Result<ScopeReport, String> {
    let mut r = ScopeReport {
        issues: Vec::new(),
        checked_names: 0,
        checked_client_methods: 0,
        skipped: Vec::new(),
        attributes_from: "none",
    };
    let platform = match platform {
        Ok(p) if !p.is_empty() => p,
        Ok(_) => {
            r.skipped
                .push("переменные и контекст исполнения: справка платформы пуста".into());
            return Ok(r);
        }
        Err(e) => {
            r.skipped.push(format!(
                "переменные и контекст исполнения: справка платформы недоступна ({e})"
            ));
            return Ok(r);
        }
    };
    let s = scope::parse(source).map_err(|e| format!("разбор не состоялся: {e}"))?;
    if s.has_errors {
        // На битом дереве и объявления, и чтения — мусор: сначала структура.
        r.skipped
            .push("переменные и контекст исполнения: сначала исправьте структуру модуля".into());
        return Ok(r);
    }

    let к = конфигурация(conn)?;
    r.skipped.extend(к.skipped.iter().cloned());
    // С module — свой набор модуля; без него — объединение из кэша. Строить
    // объединение на каждый вызов стоило втрое: 16 модулей/с против 48 на ДО
    // (13.10.2026), при том что между вызовами оно не меняется.
    let свои = реквизиты_модуля(conn, module)?;
    let mut свои_с_приложением;
    let реквизиты: &HashSet<String> = match свои {
        Some(набор) => {
            свои_с_приложением = набор;
            свои_с_приложением.extend(к.переменные_приложения.iter().cloned());
            r.attributes_from = "module";
            &свои_с_приложением
        }
        None => {
            r.attributes_from = "union";
            &к.объединение
        }
    };
    let модуль_клиентский = клиентский_общий_модуль(conn, module, &к.общие)?;

    переменные(&s, platform, &к.общие, реквизиты, &mut r);
    контекст(
        &s,
        platform,
        &к.общие,
        &к.глобальные_методы,
        реквизиты,
        модуль_клиентский,
        &mut r,
    );
    Ok(r)
}

/// Сведения о конфигурации, общие для всех вызовов по одному индексу.
struct Конфигурация {
    общие: Option<HashMap<String, Флаги>>,
    глобальные_методы: HashSet<String>,
    /// Имена уровня конфигурации, законные голыми: переменные модулей
    /// приложения (экспортные видны на клиенте глобально — `ПараметрыПриложения`
    /// БСП; берутся все, лишнее имя стоит пропуска, недостающее — ложной
    /// тревоги) и общие реквизиты.
    переменные_приложения: HashSet<String>,
    /// Объединение имён по конфигурации для вызова без `module`
    /// (см. `объединение`); переменные приложения уже внутри.
    объединение: HashSet<String>,
    skipped: Vec<String>,
}

/// Кэш по (источник индекса, время сборки).
///
/// Флаги общих модулей меняются только полной пересборкой, а она меняет
/// `built_at`. Перечитывать их на каждый вызов — замер 13.10.2026 на БП:
/// 10 модулей/с вместо прежних 69. Методы глобальных модулей инкремент
/// обновить может; кэш их не догонит до пересборки, и это осознанно:
/// промах возможен, только если новый метод глобального модуля назван как
/// серверный метод платформы.
fn конфигурация(
    conn: &Connection,
) -> Result<std::sync::Arc<Конфигурация>, String> {
    use std::sync::{Arc, Mutex, OnceLock};
    static КЭШ: OnceLock<Mutex<HashMap<String, Arc<Конфигурация>>>> = OnceLock::new();
    let мета = |k: &str| -> String {
        conn.query_row("SELECT value FROM index_meta WHERE key = ?1", [k], |r| {
            r.get::<_, Option<String>>(0)
        })
        .ok()
        .flatten()
        .unwrap_or_default()
    };
    let источник = мета("source_path");
    // Без метаданных индекса (тестовая база в памяти) кэшировать нечем:
    // одинаковый пустой ключ склеил бы разные индексы.
    let ключ = (!источник.is_empty()).then(|| format!("{источник}|{}", мета("built_at")));
    if let Some(k) = &ключ {
        if let Some(c) = КЭШ.get_or_init(Default::default).lock().unwrap().get(k) {
            return Ok(c.clone());
        }
    }
    let mut skipped = Vec::new();
    let общие = общие_модули(conn, &mut skipped)?;
    let глобальные_методы = методы_глобальных_модулей(conn, &общие)?;
    let mut переменные_приложения = переменные_приложения(conn, &источник)?;
    // Общие реквизиты видны в модулях объектов как собственные реквизиты
    // (`ОбластьДанныхОсновныеДанные`, `НаименованиеЯзык1` — ДО 13.10.2026).
    // В `object_attributes` их нет: они не принадлежат ни одному объекту.
    собрать(
        conn,
        "SELECT DISTINCT object_name FROM object_synonyms WHERE category = 'CommonAttributes'",
        &[],
        &mut переменные_приложения,
    )
    .ok();
    let mut объединение = объединение(conn)?;
    объединение.extend(переменные_приложения.iter().cloned());
    let c = Arc::new(Конфигурация {
        общие,
        глобальные_методы,
        переменные_приложения,
        объединение,
        skipped,
    });
    if let Some(k) = ключ {
        КЭШ
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .insert(k, c.clone());
    }
    Ok(c)
}

/// Переменные модулей приложения — читаются с диска: тела модулей индекс
/// не хранит. Нет файла — нет и имён, это не ошибка.
fn переменные_приложения(
    conn: &Connection,
    источник: &str,
) -> Result<HashSet<String>, String> {
    let mut out = HashSet::new();
    if источник.is_empty() {
        return Ok(out);
    }
    let есть_module_type: bool = conn
        .query_row(
            "SELECT count(*) FROM pragma_table_info('modules') WHERE name = 'module_type'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map_err(|e| e.to_string())?
        > 0;
    if !есть_module_type {
        return Ok(out);
    }
    let mut st = conn
        .prepare(
            "SELECT rel_path FROM modules
             WHERE module_type IN ('ManagedApplicationModule', 'OrdinaryApplicationModule')",
        )
        .map_err(|e| e.to_string())?;
    let пути: Vec<String> = st
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    for rel in пути {
        let путь = std::path::Path::new(источник).join(&rel);
        let Ok(raw) = std::fs::read(&путь) else {
            continue;
        };
        let raw = raw.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&raw);
        if let Ok(s) = scope::parse(&String::from_utf8_lossy(raw)) {
            out.extend(s.module_vars);
        }
    }
    Ok(out)
}

/// Неопределённые переменные: голое имя, которое не объявлено в методе и
/// модуле, не известно платформе и не является объектом конфигурации.
fn переменные(
    s: &ModuleScope,
    platform: &PlatformContext,
    общие: &Option<HashMap<String, Флаги>>,
    реквизиты: &HashSet<String>,
    r: &mut ScopeReport,
) {
    let модульные: HashSet<&str> = s
        .module_vars
        .iter()
        .chain(&s.method_names)
        .map(String::as_str)
        .collect();
    for m in &s.methods {
        let свои: HashSet<&str> = m.declared.iter().map(String::as_str).collect();
        let mut сказано: HashSet<String> = HashSet::new();
        for u in &m.reads {
            let низ = u.name.to_lowercase();
            r.checked_names += 1;
            if свои.contains(низ.as_str())
                || модульные.contains(низ.as_str())
                || реквизиты.contains(&низ)
                || platform.is_known_name(&u.name)
                || принимает_компилятор(&u.name)
                || общие.as_ref().is_some_and(|o| o.contains_key(&низ))
            {
                continue;
            }
            // Одно имя — одно замечание на метод: опечатка, повторённая
            // пять раз, — одна ошибка, а не пять.
            if !сказано.insert(низ) {
                continue;
            }
            r.issues.push(json!({
                "line": u.line,
                "column": u.column,
                "kind": "undefined_variable",
                "message": format!("Переменная не определена ({})", u.name),
                "method": m.name,
            }));
        }
    }
}

/// Контекст исполнения: в клиентском методе — то, чего на тонком клиенте нет.
fn контекст(
    s: &ModuleScope,
    platform: &PlatformContext,
    общие: &Option<HashMap<String, Флаги>>,
    глобальные_методы: &HashSet<String>,
    реквизиты: &HashSet<String>,
    модуль_клиентский: bool,
    r: &mut ScopeReport,
) {
    let свои_методы: HashSet<&str> = s.method_names.iter().map(String::as_str).collect();
    let модульные: HashSet<&str> = s.module_vars.iter().map(String::as_str).collect();
    for m in &s.methods {
        let на_клиенте = match m.context {
            Context::Client => true,
            Context::Unspecified => модуль_клиентский,
            Context::Server | Context::Both => false,
        };
        if !на_клиенте || m.under_preprocessor_if {
            continue;
        }
        r.checked_client_methods += 1;
        let под_если = |line: u32| {
            m.guarded_lines
                .iter()
                .any(|(a, b)| line >= *a && line <= *b)
        };

        for n in &m.news {
            if под_если(n.line) {
                continue;
            }
            if let Some((title, OnThinClient::No)) = platform.new_type(&n.type_name) {
                r.issues.push(json!({
                    "line": n.line,
                    "column": n.column,
                    "kind": "client_context",
                    "message": format!(
                        "Тип не определен ({}): «{title}» недоступен на клиенте",
                        n.type_name
                    ),
                    "method": m.name,
                    "hint": "перенесите работу в серверную процедуру (&НаСервере / &НаСервереБезКонтекста) и вызовите её",
                }));
            }
        }

        for c in &m.calls {
            if под_если(c.line) {
                continue;
            }
            let низ = c.name.to_lowercase();
            if c.qualifier.is_empty() {
                // Свой метод модуля и метод глобального общего модуля
                // затеняют одноимённый глобальный метод платформы.
                if свои_методы.contains(низ.as_str()) || глобальные_методы.contains(&низ)
                {
                    continue;
                }
                if let Some((_, OnThinClient::No)) = platform.global_method(&c.name) {
                    r.issues.push(json!({
                        "line": c.line,
                        "column": c.column,
                        "kind": "client_context",
                        "message": format!(
                            "Метод «{}» глобального контекста недоступен на клиенте",
                            c.name
                        ),
                        "method": m.name,
                    }));
                }
                continue;
            }
            // `ОбщийМодуль.Метод()` — только однословный квалификатор: у
            // цепочки `А.Б.Метод()` голова — не общий модуль.
            let Some(общие) = общие else {
                continue;
            };
            if c.qualifier.contains('.') {
                continue;
            }
            // Квалификатор — локальная переменная, переменная модуля или
            // реквизит, совпавший именем с общим модулем: `Пользователи.Очистить()`
            // по реквизиту-списку (9 ложных тревог на ДО 13.10.2026).
            let кв = c.qualifier.to_lowercase();
            if m.declared.contains(&кв)
                || модульные.contains(кв.as_str())
                || реквизиты.contains(&кв)
            {
                continue;
            }
            if let Some(f) = общие.get(&c.qualifier.to_lowercase()) {
                if !f.client && !f.server_call && f.server {
                    r.issues.push(json!({
                        "line": c.line,
                        "column": c.column,
                        "kind": "client_context",
                        "message": format!(
                            "Общий модуль «{}» серверный и без флага «Вызов сервера»: с клиента его метод «{}» недоступен",
                            c.qualifier, c.name
                        ),
                        "method": m.name,
                        "hint": "вызовите через модуль с флагом «Вызов сервера» или через серверную процедуру формы",
                    }));
                }
            }
        }

        for u in &m.reads {
            if под_если(u.line) {
                continue;
            }
            // Локальное имя, переменная модуля и реквизит затеняют глобальное
            // свойство: реквизит формы `РабочаяДата` — не `РабочаяДата`
            // платформы (ложная тревога первого прогона на БП 13.10.2026).
            let низ = u.name.to_lowercase();
            if m.declared.contains(&низ)
                || модульные.contains(низ.as_str())
                || реквизиты.contains(&низ)
            {
                continue;
            }
            if let Some((_, OnThinClient::No)) = platform.global_property(&u.name) {
                r.issues.push(json!({
                    "line": u.line,
                    "column": u.column,
                    "kind": "client_context",
                    "message": format!(
                        "«{}» недоступно на клиенте (свойство глобального контекста)",
                        u.name
                    ),
                    "method": m.name,
                }));
            }
        }
    }
}

/// Флаги общих модулей. `None` — таблицы нет (индекс схемы ниже 5).
fn общие_модули(
    conn: &Connection,
    skipped: &mut Vec<String>,
) -> Result<Option<HashMap<String, Флаги>>, String> {
    let есть: bool = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='common_modules'",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map_err(|e| e.to_string())?
        > 0;
    if !есть {
        skipped.push(
            "вызовы общих модулей с клиента: в индексе нет флагов общих модулей \
             (схема ниже 5) — пересоберите индекс"
                .into(),
        );
        return Ok(None);
    }
    let mut st = conn
        .prepare("SELECT name, global, client_managed, server, server_call FROM common_modules")
        .map_err(|e| e.to_string())?;
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                Флаги {
                    global: r.get::<_, i64>(1)? != 0,
                    client: r.get::<_, i64>(2)? != 0,
                    server: r.get::<_, i64>(3)? != 0,
                    server_call: r.get::<_, i64>(4)? != 0,
                },
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut out = HashMap::new();
    for row in rows {
        let (name, f) = row.map_err(|e| e.to_string())?;
        out.insert(name.to_lowercase(), f);
    }
    Ok(Some(out))
}

/// Методы глобальных общих модулей: их зовут без имени модуля, и они
/// затеняют одноимённые методы платформы.
fn методы_глобальных_модулей(
    conn: &Connection,
    общие: &Option<HashMap<String, Флаги>>,
) -> Result<HashSet<String>, String> {
    let Some(общие) = общие else {
        return Ok(HashSet::new());
    };
    let глобальные: Vec<&String> = общие
        .iter()
        .filter(|(_, f)| f.global)
        .map(|(n, _)| n)
        .collect();
    let mut out = HashSet::new();
    let mut st = conn
        .prepare(
            "SELECT me.name FROM methods me JOIN modules mo ON mo.id = me.module_id
             WHERE mo.category = 'CommonModules' AND mo.object_name = ?1 COLLATE NOCASE",
        )
        .map_err(|e| e.to_string())?;
    for g in глобальные {
        let rows = st
            .query_map([g], |r| r.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        for n in rows {
            out.insert(n.map_err(|e| e.to_string())?.to_lowercase());
        }
    }
    Ok(out)
}

/// Проверяемый модуль — клиентский общий модуль? Тогда методы без директивы
/// исполняются на клиенте.
fn клиентский_общий_модуль(
    conn: &Connection,
    module: Option<&str>,
    общие: &Option<HashMap<String, Флаги>>,
) -> Result<bool, String> {
    let (Some(module), Some(общие)) = (module, общие) else {
        return Ok(false);
    };
    let Some((категория, объект, _)) = строка_модуля(conn, module)?
    else {
        return Ok(false);
    };
    if категория != "CommonModules" {
        return Ok(false);
    }
    Ok(общие
        .get(&объект.to_lowercase())
        .is_some_and(|f| f.client && !f.server))
}

/// Нормализованный адрес модуля: прямые слэши, без `./`.
fn адрес(module: &str) -> String {
    module
        .replace('\\', "/")
        .trim_start_matches("./")
        .to_string()
}

/// (категория, объект, путь) модуля из индекса. Сначала точный адрес, затем
/// по хвосту — агент может прислать абсолютный путь.
fn строка_модуля(
    conn: &Connection,
    module: &str,
) -> Result<Option<(String, String, String)>, String> {
    let a = адрес(module);
    let q = |sql: &str, p: &str| {
        conn.query_row(sql, [p], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, String>(2)?,
            ))
        })
        .optional()
        .map_err(|e| e.to_string())
    };
    if let Some(x) = q(
        "SELECT category, object_name, rel_path FROM modules WHERE rel_path = ?1",
        &a,
    )? {
        return Ok(Some(x));
    }
    // По хвосту — только однозначно: два кандидата хуже, чем ни одного.
    let mut st = conn
        .prepare(
            "SELECT category, object_name, rel_path FROM modules
             WHERE ?1 LIKE '%' || rel_path LIMIT 2",
        )
        .map_err(|e| e.to_string())?;
    let rows: Vec<(String, String, String)> = st
        .query_map([&a], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, String>(2)?,
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    Ok(if rows.len() == 1 {
        rows.into_iter().next()
    } else {
        None
    })
}

/// Значения перечислений: одного (`Some(имя)`) или всех (`None`).
fn значения_перечислений(
    conn: &Connection,
    перечисление: Option<&str>,
    out: &mut HashSet<String>,
) -> Result<(), String> {
    let (sql, params): (&str, Vec<&dyn rusqlite::ToSql>) = match &перечисление {
        Some(имя) => (
            "SELECT values_json FROM enum_values WHERE name = ?1 COLLATE NOCASE",
            vec![имя as &dyn rusqlite::ToSql],
        ),
        None => ("SELECT values_json FROM enum_values", vec![]),
    };
    let mut st = conn.prepare(sql).map_err(|e| e.to_string())?;
    let строки = st
        .query_map(params.as_slice(), |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    for s in строки {
        let s = s.map_err(|e| e.to_string())?;
        if let Ok(Value::Array(значения)) = serde_json::from_str::<Value>(&s) {
            for з in значения {
                if let Some(имя) = з.as_str().or_else(|| з["name"].as_str()) {
                    out.insert(имя.to_lowercase());
                }
            }
        }
    }
    Ok(())
}

/// Объединение по всей конфигурации — для вызова без `module` (или с
/// модулем, которого нет в индексе): реквизиты объектов и форм, табличные
/// части, предопределённые, значения перечислений. Опечатку, совпавшую с
/// чужим именем, так не поймать, зато верный код не даст ложной тревоги.
/// Считается один раз на индекс (кэш `конфигурация`).
fn объединение(conn: &Connection) -> Result<HashSet<String>, String> {
    let mut out = HashSet::new();
    for sql in [
        "SELECT DISTINCT element_name FROM form_elements WHERE kind = 'attribute'",
        "SELECT DISTINCT attr_name FROM object_attributes",
        "SELECT DISTINCT item_name FROM predefined_items",
        "SELECT DISTINCT ts_name FROM object_attributes WHERE ts_name IS NOT NULL",
    ] {
        собрать(conn, sql, &[], &mut out)?;
    }
    // Значения перечислений в модуле менеджера перечисления — голые имена;
    // без них режим объединения давал 420 ложных тревог на ДО (13.10.2026).
    значения_перечислений(conn, None, &mut out)?;
    Ok(out)
}

/// Реквизиты, законные как голые имена в проверяемом модуле, — точно по
/// модулю: реквизиты формы этого модуля формы либо реквизиты и табличные
/// части объекта этого модуля объекта. `None` — модуль не передан или не
/// найден в индексе: тогда проверка берёт объединение.
fn реквизиты_модуля(
    conn: &Connection,
    module: Option<&str>,
) -> Result<Option<HashSet<String>>, String> {
    if let Some(m) = module {
        if let Some((категория, объект, путь)) = строка_модуля(conn, m)?
        {
            let mut out = HashSet::new();
            if let Some(форма) = путь.strip_suffix("/Ext/Form/Module.bsl") {
                let файл = format!("{форма}/Ext/Form.xml");
                // COLLATE NOCASE во всех запросах ниже — не вкус: индексы
                // `idx_*_object` построены с ним, и без него SQLite перебирает
                // таблицу целиком на каждый вызов (план запроса 13.10.2026:
                // `SCAN object_attributes` против `SEARCH USING INDEX`).
                собрать(
                    conn,
                    "SELECT element_name FROM form_elements
                     WHERE object_name = ?1 COLLATE NOCASE AND kind = 'attribute' AND file = ?2",
                    &[&объект, &файл],
                    &mut out,
                )?;
            } else if путь.ends_with("/Ext/ManagerModule.bsl") && категория == "Enums"
            {
                // Значения своего перечисления в модуле его менеджера — голые
                // имена. Замер на ДО 13.10.2026: 595 из 616 ложных тревог.
                значения_перечислений(conn, Some(&объект), &mut out)?;
            } else if путь.ends_with("/Ext/ManagerModule.bsl") {
                // В модуле менеджера предопределённые элементы своего объекта —
                // голые имена: `Ссылка = ПрочиеНалогиИСборы;`. Замер на БП
                // 13.10.2026: 10 из 11 ложных тревог первого прогона — они.
                собрать(
                    conn,
                    "SELECT item_name FROM predefined_items
                     WHERE object_name = ?1 COLLATE NOCASE AND category = ?2",
                    &[&объект, &категория],
                    &mut out,
                )?;
            } else {
                собрать(
                    conn,
                    "SELECT attr_name FROM object_attributes
                     WHERE object_name = ?1 COLLATE NOCASE AND category = ?2
                       AND attr_kind <> 'ts_attribute'",
                    &[&объект, &категория],
                    &mut out,
                )?;
                собрать(
                    conn,
                    "SELECT DISTINCT ts_name FROM object_attributes
                     WHERE object_name = ?1 COLLATE NOCASE AND category = ?2 AND ts_name IS NOT NULL",
                    &[&объект, &категория],
                    &mut out,
                )?;
            }
            return Ok(Some(out));
        }
    }
    Ok(None)
}

fn собрать(
    conn: &Connection,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
    out: &mut HashSet<String>,
) -> Result<(), String> {
    let mut st = conn.prepare(sql).map_err(|e| e.to_string())?;
    let rows = st
        .query_map(params, |r| r.get::<_, Option<String>>(0))
        .map_err(|e| e.to_string())?;
    for row in rows {
        if let Some(v) = row.map_err(|e| e.to_string())? {
            if !v.is_empty() {
                out.insert(v.to_lowercase());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Сторож списка: имя, которое справка начала знать, из списка удаляется.
    /// Без установленной 1С (CI) проверять не с чем — тест молчит, а не врёт.
    #[test]
    fn исключения_справке_неизвестны() {
        let Ok(p) = crate::platform_help::context() else {
            return;
        };
        for (имя, _) in ПРИНИМАЕТ_КОМПИЛЯТОР {
            assert!(
                !p.is_known_name(имя),
                "справка знает «{имя}» — удалите его из ПРИНИМАЕТ_КОМПИЛЯТОР"
            );
        }
    }

    #[test]
    fn исключение_без_учёта_регистра() {
        assert!(принимает_компилятор("режимоткрытияокна"));
        assert!(!принимает_компилятор("РежимОткрытия"));
    }
}
