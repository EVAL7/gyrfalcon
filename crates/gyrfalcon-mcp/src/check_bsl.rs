//! Проверка модуля BSL перед записью — структура и имена ОДНИМ вызовом.
//!
//! # Почему один инструмент, а не два
//!
//! Проверок внутри действительно две, и они разной природы: структуру видит
//! разбор текста, имена — только индекс конфигурации. Разделить их на два
//! вызова было бы честнее по устройству и **хуже по делу**: слабая модель
//! не зовёт и один разведочный инструмент, а два не позовёт тем более.
//! Замер 31.08.2026 по языку запросов это показал числом — `query_check`
//! был назван в ОДНОЙ методике из сорока, и модель его не звала.
//!
//! Поэтому наружу — один `check_bsl`, а обе проверки внутри.
//!
//! # Без индекса не работает
//!
//! Не «деградирует до структурной проверки», а отказывает. Причина не
//! техническая: разработка по конфигурации 1С без индекса не ведётся вовсе
//! (стоп-условие контура), и инструмент, отвечающий половину правды на
//! неготовом окружении, эту границу размывал бы. Половинный зелёный ответ
//! читается как полный — ровно та ошибка, что уже стоила вечера на зелёном
//! `ibcmd config check` при несобирающемся модуле.
//!
//! # Что здесь НЕ проверяется
//!
//! Текст запроса. Его проверяет канал данных (`gt-data-1c`: `query_check`,
//! `query_build`, `syntax` по справке вендора) — там источник правды живая
//! база и справка платформы, здесь выгрузка и индекс.

use gyrfalcon_parser::{bsl, module};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

/// Сколько замечаний показывать по умолчанию.
///
/// При каскаде tree-sitter выдаёт десятки узлов, из которых осмысленны первые.
/// Длинная простыня не помогает исправить, а мешает выбрать, с чего начать.
const DEFAULT_LIMIT: usize = 20;
const MAX_LIMIT: usize = 200;

/// Длина показываемого фрагмента строки, символов.
const FRAGMENT_CHARS: usize = 120;

/// Сколько похожих имён предлагать взамен ненайденного.
///
/// Подсказка обязательна, а не украшение: замер по языку запросов (31.08.2026)
/// показал, что на внятный отказ с позицией модель отвечает ПОВТОРЕНИЕМ той же
/// ошибки — шесть раз подряд. Выбор из готового списка она делает уверенно,
/// сочинение замены — нет.
const SUGGEST: usize = 3;

/// Проверить модуль: структура по AST + имена по индексу + переменные и
/// контекст исполнения по справке платформы.
pub fn check_bsl(conn: &Connection, args: &Value) -> Result<Value, String> {
    check_bsl_with(conn, args, crate::platform_help::context())
}

/// То же с явно переданной справкой платформы. Отдельно ради тестов: на CI
/// установленной 1С нет, и проверка не должна зависеть от машины, на
/// которой её гоняют.
pub fn check_bsl_with(
    conn: &Connection,
    args: &Value,
    platform: Result<&crate::platform_help::PlatformContext, String>,
) -> Result<Value, String> {
    let source = args
        .get("source")
        .and_then(Value::as_str)
        .ok_or("нужен параметр source — текст модуля BSL")?;
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map(|n| (n as usize).clamp(1, MAX_LIMIT))
        .unwrap_or(DEFAULT_LIMIT);
    let deep = args.get("deep").and_then(Value::as_bool).unwrap_or(false);
    let module = args.get("module").and_then(Value::as_str);

    let mut issues = Vec::new();

    // --- Слой 1: структура. Разбор текста, индекс не нужен. ---
    let lines: Vec<&str> = source.lines().collect();
    for e in bsl::check_syntax(source).map_err(|e| format!("разбор не состоялся: {e}"))?
    {
        let mut item = json!({
            "line": e.line,
            "kind": "syntax",
            "message": e.message,
        });
        // Фрагмент строки: без него ответ называет координату, а модель всё
        // равно перечитывает файл, чтобы понять, о чём речь.
        if let Some(text) = lines.get(e.line as usize - 1) {
            item["column"] = json!(e.column);
            item["fragment"] = json!(text
                .trim_end()
                .chars()
                .take(FRAGMENT_CHARS)
                .collect::<String>());
            // Подозрительные символы — частая причина на реальных выгрузках:
            // U+2003 и прочие юникодные пробелы 1С глотает, а глазами они
            // неотличимы от обычных (замер 27.08.2026, единственный сбой корпуса A).
            let odd: Vec<String> = text
                .chars()
                .filter(|c| !c.is_ascii() && !('А'..='я').contains(c) && *c != 'ё' && *c != 'Ё')
                .map(|c| format!("U+{:04X}", c as u32))
                .collect();
            if !odd.is_empty() {
                item["suspicious_chars"] = json!(odd);
            }
        }
        issues.push(item);
    }

    // --- Слой 2: имена. Только по индексу конфигурации. ---
    let parsed = module::parse(source).map_err(|e| format!("разбор не состоялся: {e}"))?;
    let (проверено, пропущено) = проверить_имена(conn, &parsed, &mut issues)?;

    // --- Слой 3: переменные и контекст исполнения (MCP-06). ---
    let область = crate::check_scope::check(conn, source, module, platform)?;
    issues.extend(область.issues);

    issues.sort_by_key(|i| {
        (
            i["line"].as_u64().unwrap_or(0),
            i["column"].as_u64().unwrap_or(0),
        )
    });
    let всего = issues.len();
    issues.truncate(limit);

    let mut out = json!({
        "ok": всего == 0,
        "issues": issues,
        "total": всего,
        "checked_calls": проверено,
        "skipped_calls": пропущено,
        "checked_names": область.checked_names,
        "checked_client_methods": область.checked_client_methods,
        "attributes_from": область.attributes_from,
    });
    if !область.skipped.is_empty() {
        out["not_checked"] = json!(область.skipped);
    }
    if всего > issues.len() {
        out["truncated"] = json!(всего - issues.len());
    }
    // Оговорка едет в КАЖДОМ ответе, а не только в описании инструмента:
    // описание модель читает один раз при загрузке, ответ — каждый раз.
    out["note"] = json!(format!(
        "Проверены структура кода и имена в вызовах «Модуль.Метод», где Модуль — объект этой \
         конфигурации: {проверено} шт. Пропущено {пропущено} вызовов — встроенные функции \
         платформы, методы её типов и обращения через переменные: индекс о них не знает, и \
         «не найдено» про них было бы ложью. Неопределённые переменные и недоступное на \
         клиенте проверены по справке платформы, кроме кода под #Если; что не проверено — \
         в not_checked. Реквизиты формы и объекта сверяются точно, только если передан \
         module (attributes_from=module). Текст ЗАПРОСА здесь не проверяется — это \
         query_check канала данных."
    ));
    if deep {
        out["complexity"] = json!(метрики_сложности(source));
    }
    Ok(out)
}

/// Недорогая метрика для выбора очередности ручной проверки. Это не заменяет
/// статический анализатор: она намеренно прозрачна и считается по тем же
/// словам, которые разработчик видит в BSL. Глубину считаем по парным блокам,
/// а не по отступам — отступ в выгрузках не является синтаксисом.
fn метрики_сложности(source: &str) -> Value {
    let mut decisions = 0u64;
    let mut nesting = 0u64;
    let mut max_nesting = 0u64;
    let mut procedures = 0u64;
    let mut executable = 0u64;
    for raw in source.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        executable += 1;
        let upper = line.to_uppercase();
        if upper.starts_with("ПРОЦЕДУРА ") || upper.starts_with("ФУНКЦИЯ ") {
            procedures += 1;
        }
        if upper.starts_with("ЕСЛИ ")
            || upper.starts_with("ИНАЧЕЕСЛИ ")
            || upper.starts_with("ПОКА ")
            || upper.starts_with("ДЛЯ ")
            || upper.starts_with("ПОПЫТКА")
        {
            decisions += 1;
        }
        if upper.starts_with("ЕСЛИ ")
            || upper.starts_with("ДЛЯ ")
            || upper.starts_with("ПОКА ")
            || upper.starts_with("ПОПЫТКА")
        {
            nesting += 1;
            max_nesting = max_nesting.max(nesting);
        }
        if upper.starts_with("КОНЕЦЕСЛИ")
            || upper.starts_with("КОНЕЦЦИКЛА")
            || upper.starts_with("КОНЕЦПОПЫТКИ")
        {
            nesting = nesting.saturating_sub(1);
        }
    }
    json!({
        "cyclomatic": decisions + 1,
        "decisions": decisions,
        "max_nesting": max_nesting,
        "procedures": procedures,
        "executable_lines": executable,
        "note": "Приближённая прозрачная метрика BSL: решения = Если/ИначеЕсли/Для/Пока/Попытка. Для углублённого аудита применяйте профильный анализатор."
    })
}

/// Слой имён. Возвращает (проверено, пропущено).
///
/// # Почему проверяются НЕ ВСЕ вызовы
///
/// Замер 05.09.2026 на Документообороте, 187 234 вызова заведомо ПРАВИЛЬНОГО
/// кода конфигурации:
///
/// | что сверяем | ложных тревог |
/// |---|---|
/// | все имена подряд | 88 880 = **47,5%** |
/// | только квалифицированные известным модулем | 1,14% |
/// | + локальные имена модуля | 0,50% |
/// | + предопределённые элементы | **0,26%** |
///
/// Причина разрыва видна в хвосте частот первого варианта: `НСтр` (11 596),
/// `ЗначениеЗаполнено` (10 230), `ТипЗнч`, `СтрШаблон` — встроенные функции
/// платформы; `Вставить` (14 308), `Найти`, `Следующий`, `ПолучитьОбъект` —
/// методы её типов (Структура, Массив, Выборка). Ни того, ни другого в индексе
/// КОНФИГУРАЦИИ нет и быть не может.
///
/// Отсюда правило: **проверяем только то, про что индекс вправе иметь мнение.**
/// Инструмент, врущий в половине случаев, хуже отсутствующего — его перестают
/// читать вместе с той половиной, где он прав.
fn проверить_имена(
    conn: &Connection,
    parsed: &module::ParsedModule,
    issues: &mut Vec<Value>,
) -> Result<(usize, usize), String> {
    let модули = объекты_с_модулями(conn)?;
    let предопр = предопределённые(conn)?;
    // Имена, объявленные в самом тексте: переменные, параметры, счётчики.
    // Без них `Контрагенты.Количество()` по локальному массиву читается как
    // обращение к справочнику.
    let локальные: HashSet<String> = parsed.locals.iter().map(|s| s.to_lowercase()).collect();
    // Методы самого проверяемого текста: они законны и в индексе отсутствуют —
    // модуль ещё не записан и не проиндексирован.
    let свои: HashSet<String> = parsed
        .methods
        .iter()
        .map(|m| m.name.to_lowercase())
        .collect();

    let mut кэш: HashMap<String, HashMap<String, String>> = HashMap::new();
    let (mut проверено, mut пропущено) = (0usize, 0usize);

    for call in &parsed.calls {
        let Some((qual, name)) = call.name.rsplit_once('.') else {
            пропущено += 1;
            continue;
        };
        let низ = qual.to_lowercase();
        if локальные.contains(&низ) || предопр.contains(&низ) || !модули.contains(&низ)
        {
            пропущено += 1;
            continue;
        }
        проверено += 1;
        if свои.contains(&name.to_lowercase()) {
            continue;
        }

        // Кэш на объект: у модуля десятки вызовов к одному общему модулю,
        // и спрашивать индекс о каждом — то же, что перечитывать словарь
        // на каждое слово.
        if !кэш.contains_key(&низ) {
            кэш.insert(низ.clone(), методы_объекта(conn, qual)?);
        }
        let имена = &кэш[&низ];

        match имена.get(&name.to_lowercase()) {
            None => issues.push(json!({
                "line": call.line,
                "kind": "name_not_found",
                "call": call.name,
                "message": format!("метод «{name}» не найден в модуле «{qual}»"),
                "suggest": похожие(имена, name),
            })),
            Some(params) => {
                if let Some((мин, макс)) = границы_аргументов(params) {
                    let n = call.arg_count;
                    if n < мин || n > макс {
                        issues.push(json!({
                            "line": call.line,
                            "kind": "arg_count",
                            "call": call.name,
                            "message": format!(
                                "передано аргументов: {n}, объявлено: {}{}",
                                if мин == макс { мин.to_string() } else { format!("{мин}..{макс}") },
                                if мин == макс { "" } else { " (часть со значением по умолчанию)" }
                            ),
                            "signature": params,
                        }));
                    }
                }
            }
        }
    }
    Ok((проверено, пропущено))
}

/// Объекты конфигурации, у которых есть модули.
///
/// Фильтр «только с экспортными методами» пробован и отвергнут замером
/// 05.09.2026: точность выросла с 1,25% до 1,12%, а скорость упала вчетверо
/// (GROUP BY по 103 тысячам методов).
fn объекты_с_модулями(conn: &Connection) -> Result<HashSet<String>, String> {
    собрать(
        conn,
        "SELECT DISTINCT object_name FROM modules WHERE object_name <> ''",
    )
}

/// Имена предопределённых элементов справочников, планов видов и перечислений.
///
/// Ловят класс ложных тревог, который не снимается ни локальными именами, ни
/// фильтром по модулям. Пример из корпуса
/// (`Catalogs/АдреснаяКнига/Ext/ManagerModule.bsl:919`):
///
/// ```text
/// РазделАдреснойКниги = Организации.ПолучитьОбъект();
/// ```
///
/// `Организации` здесь — ПРЕДОПРЕДЕЛЁННЫЙ ЭЛЕМЕНТ справочника, а
/// `ПолучитьОбъект` — метод платформы у ссылки. Но в конфигурации есть и
/// справочник `Организации` с собственным модулем, поэтому квалификатор
/// проходил фильтр, а метод в модуле, конечно, не находился.
fn предопределённые(conn: &Connection) -> Result<HashSet<String>, String> {
    собрать(
        conn,
        "SELECT DISTINCT item_name FROM predefined_items WHERE item_name <> ''",
    )
}

fn собрать(conn: &Connection, sql: &str) -> Result<HashSet<String>, String> {
    let mut st = conn.prepare(sql).map_err(|e| e.to_string())?;
    let rows = st
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?;
    let mut out = HashSet::new();
    for r in rows {
        out.insert(r.map_err(|e| e.to_string())?.to_lowercase());
    }
    Ok(out)
}

/// Все методы названного объекта: имя -> сигнатура.
///
/// ОДИН запрос на объект вместо запроса на каждый вызов. Так было не сразу:
/// первая версия спрашивала индекс дважды за промах (существование + похожие),
/// и живой прогон дал **1 модуль в секунду**. Разница не в SQLite, а в числе
/// обращений: у модуля с сотней вызовов их было двести.
fn методы_объекта(
    conn: &Connection,
    qual: &str,
) -> Result<HashMap<String, String>, String> {
    let mut st = conn
        .prepare(
            // COLLATE NOCASE, а не LOWER(): к результату функции SQLite не
            // применяет индекс, и idx_mod_object простаивал. Замер 05.09.2026:
            // 8 модулей/с до этой правки, 91 после.
            "SELECT m.name, m.params FROM methods m
             JOIN modules mo ON mo.id = m.module_id
             WHERE mo.object_name = ?1 COLLATE NOCASE",
        )
        .map_err(|e| e.to_string())?;
    let rows = st
        .query_map([qual], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1).unwrap_or_default(),
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut out = HashMap::new();
    for r in rows {
        let (имя, params) = r.map_err(|e| e.to_string())?;
        out.insert(имя.to_lowercase(), params);
    }
    Ok(out)
}

/// Похожие имена — подсказка вместо голого отказа.
///
/// Схожесть считается по общему префиксу и вхождению подстроки, а не полным
/// расстоянием Левенштейна: у выдуманных имён 1С промах обычно в хвосте
/// («ПересчитатьСуммыДокумента» вместо «ПересчитатьИтогиДокумента»), и дешёвый
/// признак ловит ровно этот случай.
fn похожие(имена: &HashMap<String, String>, name: &str) -> Vec<String> {
    let искомое = name.to_lowercase();
    let mut кандидаты: Vec<(usize, &String)> = Vec::new();
    for низ in имена.keys() {
        let общий = низ
            .chars()
            .zip(искомое.chars())
            .take_while(|(a, b)| a == b)
            .count();
        let вес = if низ.contains(&искомое) || искомое.contains(низ.as_str()) {
            общий + 100
        } else {
            общий
        };
        // Меньше четырёх общих букв — это не подсказка, а шум.
        if вес >= 4 {
            кандидаты.push((вес, низ));
        }
    }
    кандидаты.sort_by_key(|(вес, _)| std::cmp::Reverse(*вес));
    кандидаты
        .into_iter()
        .take(SUGGEST)
        .map(|(_, имя)| имя.clone())
        .collect()
}

/// Сколько аргументов допускает сигнатура: (минимум, максимум).
///
/// `params` лежит в индексе строкой ровно как в объявлении:
/// `(Задача, КэшДанных = Неопределено)`. Параметры со значением по умолчанию
/// необязательны — отсюда диапазон, а не число. `None` — сигнатуру разобрать
/// не удалось, и тогда проверка молчит: выдумывать границы хуже, чем не
/// проверять.
fn границы_аргументов(params: &str) -> Option<(usize, usize)> {
    let s = params.trim().strip_prefix('(')?.strip_suffix(')')?;
    if s.trim().is_empty() {
        return Some((0, 0));
    }
    let части = разбить_верхнего_уровня(s);
    let максимум = части.len();
    let минимум = части.iter().filter(|p| !p.contains('=')).count();
    Some((минимум, максимум))
}

/// Разбить список параметров по запятым верхнего уровня.
///
/// Значением по умолчанию бывает конструктор или литерал с запятой внутри —
/// `Новый Структура("А, Б")`, — поэтому наивный `split(',')` даёт лишние
/// параметры и ложное «передано меньше, чем объявлено».
fn разбить_верхнего_уровня(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut in_str, mut start) = (0i32, false, 0usize);
    for (i, ch) in s.char_indices() {
        match ch {
            '"' => in_str = !in_str,
            _ if in_str => {}
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push(&s[start..i]);
                start = i + ch.len_utf8();
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

/// Схема параметров для `tools/list`.
pub fn schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "source": {
                "type": "string",
                "description": "Текст модуля BSL целиком — тот, который собираешься записать"
            },
            "project": {
                "oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}],
                "description":
                "Конфигурация 1С, по которой сверять имена. Обязателен, когда сервер \
                 обслуживает несколько (см. list_projects)"
            },
            "module": {
                "type": "string",
                "description": "Путь модуля в выгрузке (например Documents/Заказ/Forms/ФормаДокумента/Ext/Form/Module.bsl). \
                 С ним реквизиты формы или объекта сверяются точно, а методы клиентского общего \
                 модуля проверяются как клиентские. Без него — сверка с реквизитами всей конфигурации"
            },
            "limit": {
                "type": "integer",
                "default": DEFAULT_LIMIT,
                "description": "Сколько замечаний показать; остальные посчитаны в truncated"
            },
            "deep": {
                "type": "boolean",
                "default": false,
                "description": "Добавить прозрачные метрики сложности: ветвления, максимальная вложенность и объём"
            }
        },
        "required": ["source"]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Индекс с минимумом таблиц: слой имён без него не проверить.
    fn индекс() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "CREATE TABLE modules(id INTEGER PRIMARY KEY, object_name TEXT);
             CREATE TABLE methods(id INTEGER PRIMARY KEY, module_id INTEGER, name TEXT, params TEXT);
             CREATE TABLE predefined_items(id INTEGER PRIMARY KEY, item_name TEXT);
             INSERT INTO modules VALUES (1, 'ОбщегоНазначения');
             INSERT INTO methods VALUES
               (1, 1, 'СообщитьПользователю', '(Знач Текст, Знач Ключ = Неопределено)'),
               (2, 1, 'ЗначениеРеквизитаОбъекта', '(Ссылка, ИмяРеквизита)'),
               (3, 1, 'ПересчитатьИтогиДокумента', '(Документ)');
             INSERT INTO predefined_items VALUES (1, 'Организации');",
        )
        .unwrap();
        c
    }

    /// Слои 1–2 без справки платформы: так тесты не зависят от того,
    /// установлена ли 1С на машине, где их гоняют.
    fn проверить(src: &str) -> Value {
        check_bsl_with(
            &индекс(),
            &json!({ "source": src }),
            Err("нет справки в тесте".into()),
        )
        .unwrap()
    }

    // --- слой 3: переменные и контекст исполнения (MCP-06) ---

    /// Индекс схемы 5: общие модули с флагами, реквизиты формы и объекта.
    fn индекс5() -> Connection {
        let c = индекс();
        c.execute_batch(
            "ALTER TABLE modules ADD COLUMN rel_path TEXT;
             ALTER TABLE modules ADD COLUMN category TEXT;
             UPDATE modules SET rel_path='CommonModules/ОбщегоНазначения/Ext/Module.bsl', category='CommonModules' WHERE id=1;
             INSERT INTO modules VALUES (2, 'СерверныйМодуль', 'CommonModules/СерверныйМодуль/Ext/Module.bsl', 'CommonModules');
             INSERT INTO modules VALUES (3, 'МодульВызовСервера', 'CommonModules/МодульВызовСервера/Ext/Module.bsl', 'CommonModules');
             INSERT INTO modules VALUES (4, 'Заказ', 'Documents/Заказ/Forms/ФормаДокумента/Ext/Form/Module.bsl', 'Documents');
             INSERT INTO methods VALUES (10, 2, 'Посчитать', '()'), (11, 3, 'Посчитать', '()');
             CREATE TABLE common_modules(id INTEGER PRIMARY KEY, name TEXT, global INTEGER, client_managed INTEGER,
               client_ordinary INTEGER, server INTEGER, server_call INTEGER, external_connection INTEGER,
               privileged INTEGER, file TEXT);
             INSERT INTO common_modules VALUES
               (1, 'ОбщегоНазначения', 0, 1, 1, 1, 0, 1, 0, ''),
               (2, 'СерверныйМодуль', 0, 0, 0, 1, 0, 1, 0, ''),
               (3, 'МодульВызовСервера', 0, 0, 0, 1, 1, 0, 0, '');
             CREATE TABLE form_elements(object_name TEXT, form_name TEXT, kind TEXT, element_name TEXT, file TEXT);
             INSERT INTO form_elements VALUES
               ('Заказ', 'ФормаДокумента', 'attribute', 'Объект', 'Documents/Заказ/Forms/ФормаДокумента/Ext/Form.xml'),
               ('Заказ', 'ФормаДокумента', 'attribute', 'ВыбранныйСклад', 'Documents/Заказ/Forms/ФормаДокумента/Ext/Form.xml');
             CREATE TABLE object_attributes(object_name TEXT, category TEXT, attr_name TEXT, attr_kind TEXT, ts_name TEXT);
             INSERT INTO object_attributes VALUES ('Заказ', 'Documents', 'Контрагент', 'attribute', NULL);
             CREATE TABLE enum_values(name TEXT, values_json TEXT);
             INSERT INTO enum_values VALUES ('Важность', '[\"Высокая\", \"Низкая\"]');",
        )
        .unwrap();
        c
    }

    /// Справка платформы в миниатюре: разметка страниц — как в 8.3.27.
    fn справка() -> crate::platform_help::PlatformContext {
        let стр = |заголовок: &str, доступность: &str| {
            format!(
                "<h1 class=\"V8SH_pagetitle\">{заголовок}</h1><p class=\"V8SH_chapter\">Доступность:</p><p>{доступность}</p>"
            )
        };
        let запрос = стр(
            "Запрос (Query)",
            "Сервер, толстый клиент, внешнее соединение.",
        );
        let массив = стр(
            "Массив (Array)",
            "Тонкий клиент, веб-клиент, сервер, толстый клиент.",
        );
        let тдс = стр(
            "Глобальный контекст.ТекущаяДатаСеанса (CurrentSessionDate)",
            "Сервер, толстый клиент, внешнее соединение.",
        );
        let сообщить = стр(
            "Глобальный контекст.Сообщить (Message)",
            "Тонкий клиент, веб-клиент, сервер, толстый клиент.",
        );
        let справочники = стр(
            "Глобальный контекст.Справочники (Catalogs)",
            "Сервер, толстый клиент, внешнее соединение.",
        );
        let элементы = стр(
            "ФормаКлиентскогоПриложения.Элементы (Items)",
            "Тонкий клиент, веб-клиент, сервер, толстый клиент.",
        );
        crate::platform_help::context_from_pages(&[
            ("objects/c1/Query.html", запрос.as_str()),
            ("objects/c1/Array.html", массив.as_str()),
            (
                "objects/Global context/methods/CurrentSessionDate.html",
                тдс.as_str(),
            ),
            (
                "objects/Global context/methods/Message.html",
                сообщить.as_str(),
            ),
            (
                "objects/Global context/properties/Catalogs.html",
                справочники.as_str(),
            ),
            (
                "objects/ManagedForm/properties/Items.html",
                элементы.as_str(),
            ),
        ])
    }

    fn проверить3(src: &str, module: Option<&str>) -> Value {
        let п = справка();
        let mut args = json!({ "source": src });
        if let Some(m) = module {
            args["module"] = json!(m);
        }
        check_bsl_with(&индекс5(), &args, Ok(&п)).unwrap()
    }

    fn замечания(v: &Value, kind: &str) -> Vec<Value> {
        v["issues"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["kind"] == json!(kind))
            .cloned()
            .collect()
    }

    /// Калибровка 09.10.2026 дословно (без первой строки модуля).
    const КАЛИБРОВКА: &str = "&НаСервере
Процедура КалибровкаНаСервере()
\tРезультат = НеОпределённаяПеременнаяКалибровки + 1;
КонецПроцедуры

&НаКлиенте
Процедура КалибровкаНаКлиенте(Команда)
\tЗапрос = Новый Запрос(\"ВЫБРАТЬ 1\");
\tКалибровкаНаСервере();
КонецПроцедуры
";

    #[test]
    fn калибровка_неопределённая_переменная_с_позицией() {
        let v = проверить3(КАЛИБРОВКА, None);
        let u = замечания(&v, "undefined_variable");
        assert_eq!(u.len(), 1, "{v}");
        assert_eq!(
            (u[0]["line"].as_u64(), u[0]["column"].as_u64()),
            (Some(3), Some(14))
        );
        assert!(u[0]["message"]
            .as_str()
            .unwrap()
            .contains("НеОпределённаяПеременнаяКалибровки"));
    }

    #[test]
    fn калибровка_серверный_тип_на_клиенте_с_позицией() {
        let v = проверить3(КАЛИБРОВКА, None);
        let c = замечания(&v, "client_context");
        assert_eq!(c.len(), 1, "{v}");
        assert_eq!(
            (c[0]["line"].as_u64(), c[0]["column"].as_u64()),
            (Some(8), Some(17))
        );
        assert!(c[0]["message"].as_str().unwrap().contains("Запрос"));
        assert_eq!(v["ok"], json!(false));
    }

    #[test]
    fn клиентский_тип_на_клиенте_не_ошибка() {
        let v = проверить3(
            "&НаКлиенте\nПроцедура П()\n\tМ = Новый Массив;\n\tСообщить(\"х\");\nКонецПроцедуры\n",
            None,
        );
        assert_eq!(v["ok"], json!(true), "{v}");
    }

    #[test]
    fn серверный_модуль_с_клиента_ловится_а_вызов_сервера_нет() {
        // Класс живой задачи: клиентский вызов серверного прошёл все проверки агента.
        let v = проверить3(
            "&НаКлиенте\nПроцедура П()\n\tСерверныйМодуль.Посчитать();\n\tМодульВызовСервера.Посчитать();\n\tОбщегоНазначения.СообщитьПользователю(\"х\");\nКонецПроцедуры\n",
            None,
        );
        let c = замечания(&v, "client_context");
        assert_eq!(c.len(), 1, "{v}");
        assert!(c[0]["message"]
            .as_str()
            .unwrap()
            .contains("СерверныйМодуль"));
    }

    #[test]
    fn серверный_глобальный_метод_и_свойство_на_клиенте() {
        let v = проверить3(
            "&НаКлиенте\nПроцедура П()\n\tД = ТекущаяДатаСеанса();\n\tС = Справочники.Номенклатура;\nКонецПроцедуры\n",
            None,
        );
        assert_eq!(замечания(&v, "client_context").len(), 2, "{v}");
    }

    #[test]
    fn реквизит_формы_затеняет_глобальное_свойство() {
        // Живой случай БП: реквизит формы `РабочаяДата` на клиенте — не
        // серверное свойство глобального контекста. Здесь в роли
        // «серверного свойства» — `Справочники`, в роли реквизита — оно же.
        let c = индекс5();
        c.execute_batch(
            "INSERT INTO form_elements VALUES ('Заказ', 'ФормаДокумента', 'attribute', 'Справочники',
               'Documents/Заказ/Forms/ФормаДокумента/Ext/Form.xml');",
        )
        .unwrap();
        let п = справка();
        let v = check_bsl_with(
            &c,
            &json!({"source": "&НаКлиенте\nПроцедура П()\n\tХ = Справочники;\nКонецПроцедуры\n",
                    "module": "Documents/Заказ/Forms/ФормаДокумента/Ext/Form/Module.bsl"}),
            Ok(&п),
        )
        .unwrap();
        assert_eq!(v["ok"], json!(true), "{v}");
    }

    #[test]
    fn предопределённое_голым_именем_в_модуле_менеджера() {
        let c = индекс5();
        c.execute_batch(
            "ALTER TABLE predefined_items ADD COLUMN object_name TEXT;
             ALTER TABLE predefined_items ADD COLUMN category TEXT;
             INSERT INTO predefined_items VALUES (2, 'ПрочиеНалоги', 'ВидыНалогов', 'Catalogs');
             INSERT INTO modules VALUES (5, 'ВидыНалогов', 'Catalogs/ВидыНалогов/Ext/ManagerModule.bsl', 'Catalogs');",
        )
        .unwrap();
        let п = справка();
        let v = check_bsl_with(
            &c,
            &json!({"source": "Функция Ф()\n\tВозврат ПрочиеНалоги;\nКонецФункции\n",
                    "module": "Catalogs/ВидыНалогов/Ext/ManagerModule.bsl"}),
            Ok(&п),
        )
        .unwrap();
        assert_eq!(v["ok"], json!(true), "{v}");
    }

    #[test]
    fn значение_перечисления_голым_именем_и_без_модуля() {
        // Режим объединения обязан знать значения перечислений: в модуле
        // менеджера перечисления они — голые имена (420 ложных на ДО 13.10.2026).
        let v = проверить3("Функция Ф()\n\tВозврат Высокая;\nКонецФункции\n", None);
        assert_eq!(v["ok"], json!(true), "{v}");
        assert_eq!(v["attributes_from"], json!("union"));
    }

    #[test]
    fn тот_же_код_на_сервере_молчит() {
        let v = проверить3(
            "&НаСервере\nПроцедура П()\n\tД = ТекущаяДатаСеанса();\n\tЗ = Новый Запрос;\n\tСерверныйМодуль.Посчитать();\nКонецПроцедуры\n",
            None,
        );
        assert_eq!(v["ok"], json!(true), "{v}");
    }

    #[test]
    fn код_под_если_не_проверяется_на_контекст() {
        let v = проверить3(
            "&НаКлиенте\nПроцедура П()\n#Если ТолстыйКлиентОбычноеПриложение Тогда\n\tЗ = Новый Запрос;\n#КонецЕсли\nКонецПроцедуры\n",
            None,
        );
        assert!(замечания(&v, "client_context").is_empty(), "{v}");
    }

    #[test]
    fn реквизиты_формы_точно_по_модулю() {
        let src = "&НаКлиенте\nПроцедура П()\n\tЭлементы.Склад.Видимость = ЗначениеЗаполнено(ВыбранныйСклад);\n\tХ = Объект.Ссылка;\nКонецПроцедуры\n";
        let v = проверить3(
            src,
            Some("Documents/Заказ/Forms/ФормаДокумента/Ext/Form/Module.bsl"),
        );
        assert_eq!(v["ok"], json!(true), "{v}");
        assert_eq!(v["attributes_from"], json!("module"));
        // Реквизит чужого объекта в форме — неопределённая переменная.
        let v = проверить3(
            "&НаКлиенте\nПроцедура П()\n\tХ = Контрагент;\nКонецПроцедуры\n",
            Some("Documents/Заказ/Forms/ФормаДокумента/Ext/Form/Module.bsl"),
        );
        assert_eq!(замечания(&v, "undefined_variable").len(), 1, "{v}");
    }

    #[test]
    fn без_модуля_сверка_с_объединением_реквизитов() {
        // Без module тот же код молчит: Контрагент есть в конфигурации.
        let v = проверить3(
            "&НаКлиенте\nПроцедура П()\n\tХ = Контрагент;\nКонецПроцедуры\n",
            None,
        );
        assert_eq!(v["ok"], json!(true), "{v}");
        assert_eq!(v["attributes_from"], json!("union"));
    }

    #[test]
    fn объявленное_и_модульное_не_ошибка() {
        let src = "Перем МодульнаяПеременная;\n\nФункция Ф(П1, П2 = 5)\n\tПерем Л;\n\tДля Сч = 1 По 3 Цикл\n\t\tЛ = Сч;\n\tКонецЦикла;\n\tВозврат П1 + П2 + Л + МодульнаяПеременная + ОбщегоНазначения.ЗначениеРеквизитаОбъекта(1, 2);\nКонецФункции\n";
        let v = проверить3(src, None);
        assert_eq!(v["ok"], json!(true), "{v}");
    }

    #[test]
    fn без_справки_слой_честно_не_проверяет() {
        let v = проверить("Процедура П()\n\tХ = НетТакой;\nКонецПроцедуры\n");
        assert_eq!(v["ok"], json!(true));
        let nc = v["not_checked"].as_array().unwrap();
        assert!(nc[0].as_str().unwrap().contains("справка платформы"), "{v}");
    }

    #[test]
    fn старый_индекс_без_флагов_говорит_об_этом() {
        let п = справка();
        let v = check_bsl_with(
            &индекс_без_флагов(),
            &json!({"source": "&НаКлиенте\nПроцедура П()\n\tСерверныйМодуль.Посчитать();\nКонецПроцедуры\n"}),
            Ok(&п),
        )
        .unwrap();
        let nc = v["not_checked"].as_array().unwrap();
        assert!(
            nc.iter()
                .any(|x| x.as_str().unwrap().contains("схема ниже 5")),
            "{v}"
        );
    }

    fn индекс_без_флагов() -> Connection {
        let c = индекс5();
        c.execute_batch("DROP TABLE common_modules;").unwrap();
        c
    }

    #[test]
    fn битая_структура_глушит_слой_3() {
        let v = проверить3(
            "Процедура П()\n\tЕсли А = 1\n\tХ = НетТакой;\nКонецПроцедуры\n",
            None,
        );
        assert!(замечания(&v, "undefined_variable").is_empty(), "{v}");
        assert!(!замечания(&v, "syntax").is_empty(), "{v}");
    }

    fn виды(v: &Value) -> Vec<String> {
        v["issues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["kind"].as_str().unwrap_or("?").to_string())
            .collect()
    }

    #[test]
    fn чистый_модуль_молчит() {
        let v = проверить(
            "Процедура Т()\n\tОбщегоНазначения.СообщитьПользователю(\"привет\");\nКонецПроцедуры\n",
        );
        assert_eq!(v["ok"], json!(true), "ложная тревога на верном коде: {v}");
        assert_eq!(v["total"], json!(0));
    }

    #[test]
    fn глубокий_режим_выдаёт_метрики_сложности() {
        let v = check_bsl_with(&индекс(), &json!({"source": "Процедура Т()\nЕсли Истина Тогда\nДля Н = 1 По 2 Цикл\nКонецЦикла;\nКонецЕсли;\nКонецПроцедуры", "deep": true}), Err("нет справки в тесте".into())).unwrap();
        assert_eq!(v["complexity"]["cyclomatic"], json!(3));
        assert_eq!(v["complexity"]["max_nesting"], json!(2));
    }

    #[test]
    fn один_вызов_ловит_оба_класса_ошибок() {
        // Главное свойство слияния: структура и имена приходят одним ответом.
        // Пока это были два инструмента, второй класс требовал второго вызова —
        // а слабая модель не делает и первого.
        let v = проверить(
            "Процедура Т()\n\tОбщегоНазначения.ВыдуманныйМетод(А);\n\tЕсли А = 1\nКонецПроцедуры\n",
        );
        let k = виды(&v);
        assert!(
            k.contains(&"syntax".to_string()),
            "структура не поймана: {v}"
        );
        assert!(
            k.contains(&"name_not_found".to_string()),
            "имя не поймано: {v}"
        );
    }

    #[test]
    fn замечания_идут_по_порядку_строк() {
        // Два слоя пишут в один список — он обязан быть отсортирован, иначе
        // ошибка со строки 9 стоит перед ошибкой со строки 2.
        let v = проверить(
            "Процедура Т()\n\tОбщегоНазначения.НетТакого(А);\n\tБ = (1));\nКонецПроцедуры\n",
        );
        let строки: Vec<u64> = v["issues"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["line"].as_u64().unwrap())
            .collect();
        let mut отсортированы = строки.clone();
        отсортированы.sort_unstable();
        assert_eq!(строки, отсортированы, "порядок строк нарушен: {строки:?}");
    }

    #[test]
    fn платформенные_вызовы_не_трогаются() {
        // 47,5% ложных тревог начинались ровно здесь.
        let v = проверить(
            "Процедура Т()\n\tЗначениеЗаполнено(А);\n\tСписок = Новый Массив;\n\tСписок.Добавить(1);\nКонецПроцедуры\n",
        );
        assert_eq!(v["ok"], json!(true), "платформа принята за ошибку: {v}");
        assert!(
            v["skipped_calls"].as_u64().unwrap() >= 2,
            "не пропущено: {v}"
        );
    }

    #[test]
    fn предопределённый_элемент_не_ошибка() {
        let v = проверить(
            "Процедура Т()\n\tХ = Организации.ПолучитьОбъект();\nКонецПроцедуры\n",
        );
        assert_eq!(
            v["ok"],
            json!(true),
            "предопределённый принят за модуль: {v}"
        );
    }

    #[test]
    fn лишний_аргумент_ловится_с_сигнатурой() {
        let v = проверить(
            "Процедура Т()\n\tОбщегоНазначения.ЗначениеРеквизитаОбъекта(А, Б, В, Г);\nКонецПроцедуры\n",
        );
        let i = &v["issues"][0];
        assert_eq!(i["kind"], json!("arg_count"));
        assert!(i["signature"].is_string(), "сигнатура не приложена: {v}");
    }

    #[test]
    fn строковый_литерал_считается_аргументом() {
        // Поймано живым прогоном 05.09.2026: `СообщитьПользователю("привет")`
        // считался нулём аргументов и давал ложное «передано 0, объявлено 1..2».
        let v = проверить(
            "Процедура Т()\n\tОбщегоНазначения.СообщитьПользователю(\"привет\");\nКонецПроцедуры\n",
        );
        assert_eq!(v["ok"], json!(true), "строка не посчитана аргументом: {v}");
    }

    #[test]
    fn подсказка_похожего_имени() {
        let v = проверить(
            "Процедура Т()\n\tОбщегоНазначения.ПересчитатьСуммыДокумента(Д);\nКонецПроцедуры\n",
        );
        let s = v["issues"][0]["suggest"].as_array().unwrap();
        assert!(!s.is_empty(), "подсказки нет: {v}");
    }

    #[test]
    fn свой_метод_модуля_не_считается_чужим() {
        // Модуль ещё не записан и не проиндексирован — его методы законны.
        let v = проверить(
            "Процедура Т()\n\tОбщегоНазначения.СообщитьПользователю(\"х\");\nКонецПроцедуры\n\nПроцедура Другая()\nКонецПроцедуры\n",
        );
        assert_eq!(v["ok"], json!(true));
    }

    #[test]
    fn оговорка_о_неполноте_всегда_в_ответе() {
        let v = проверить("Процедура Т()\nКонецПроцедуры\n");
        let note = v["note"].as_str().unwrap();
        assert!(note.contains("Пропущено"), "оговорка потеряна: {note}");
        assert!(
            note.contains("query_check"),
            "не сказано про запросы: {note}"
        );
    }

    #[test]
    fn без_source_внятный_отказ() {
        let e = check_bsl(&индекс(), &json!({})).unwrap_err();
        assert!(e.contains("source"), "отказ не называет параметр: {e}");
    }

    #[test]
    fn пропуск_точки_с_запятой_не_ошибка() {
        // В BSL перевод строки разделяет операторы — парсер прав, и инструмент
        // не должен изобретать строгость, которой нет в языке.
        let v = проверить("Процедура Т()\n\tА = 1\n\tБ = 2\nКонецПроцедуры\n");
        assert_eq!(v["ok"], json!(true), "ложная тревога на пропуске ;");
    }

    #[test]
    fn лимит_режет_и_считает_остаток() {
        let битый =
            "Процедура Т()\n\tА = (1));\n\tБ = (2));\n\tВ = (3));\n\tГ = (4));\nКонецПроцедуры\n";
        let v = check_bsl_with(
            &индекс(),
            &json!({ "source": битый, "limit": 2 }),
            Err("нет справки в тесте".into()),
        )
        .unwrap();
        assert_eq!(v["total"], json!(4));
        assert_eq!(v["issues"].as_array().unwrap().len(), 2);
        assert_eq!(v["truncated"], json!(2));
    }
}
