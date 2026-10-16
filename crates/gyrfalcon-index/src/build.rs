//! Сборка индекса: конвейер «воркеры парсят → канал → один писатель».
//!
//! # Почему конвейер, а не просто параллельный разбор (решение Р-004)
//!
//! SQLite на запись однопоточен. Если воркеры пишут сами, они выстраиваются
//! в очередь на блокировке, и выигрыш вехи 1 (6,11× по ядрам) съедается
//! целиком. Поэтому разбор и запись разведены каналом: воркеры считают,
//! писатель пишет, и они работают одновременно, а не по очереди.
//!
//! # Два прохода, и почему их именно два
//!
//! Разрешение имён требует знать **все** методы всех модулей: вызов из первого
//! разобранного модуля может указывать в последний. Значит:
//!
//! 1. **проход 1** — разбор и запись модулей, методов, областей; попутно
//!    строятся таблицы разрешения;
//! 2. **проход 2** — разрешение собранных вызовов и запись рёбер.
//!
//! Тексты модулей между проходами не хранятся: вызовы копятся сырыми
//! (имя + строка + владелец), это на порядок меньше исходников.

use crate::classify::{self, ModuleInfo};
use crate::ddl;
use crate::extensions;
use crate::forms;
use crate::help;
use crate::integration;
use crate::meta;
use crate::meta2;
use crate::refs;
use crate::resolve::{self, MethodRef, ResolutionStats, ResolveTables};
use crate::{IndexError, Result};
use gyrfalcon_parser::module::{self, ParsedModule};
use rayon::prelude::*;
use rusqlite::{Connection, OptionalExtension};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Отчёт о сборке. Числа нужны для главного критерия — скорости индексации.
#[derive(Debug, Clone, Default)]
pub struct BuildReport {
    /// Встроенная пользовательская справка проекта из Ext/Help.
    pub help: help::HelpReport,
    /// Ошибка справки не останавливает построение навигации по коду.
    pub help_error: Option<String>,
    pub modules: u64,
    pub methods: u64,
    pub regions: u64,
    pub calls: u64,
    /// Объекты метаданных, разобранные из XML (веха 3).
    pub meta_objects: u64,
    /// Реквизиты: свои, табличных частей, измерения и ресурсы регистров.
    pub attributes: u64,
    pub predefined: u64,
    pub enum_values: u64,
    pub subsystem_content: u64,
    /// Вторая часть вехи 3 — по одному счётчику на таблицу.
    pub event_subscriptions: u64,
    pub scheduled_jobs: u64,
    pub functional_options: u64,
    pub role_rights: u64,
    pub exchange_plan_content: u64,
    /// Флаги общих модулей (схема 5): сверх таблиц прежнего инструмента.
    pub common_modules: u64,
    /// Ссылки между объектами метаданных — надстройка над таблицами выше.
    pub metadata_references: u64,
    /// Интеграция и движения. `register_movements` считает объединение
    /// объявленных и найденных в коде — сравнивать его с числом прежнего инструмента нельзя,
    /// см. `integration.rs`.
    pub register_movements: u64,
    pub xdto_packages: u64,
    /// Типы внутри пакетов XDTO — то, чего у прежнего инструмента нет вовсе (у него 0).
    pub xdto_types: u64,
    pub web_services: u64,
    pub http_services: u64,
    /// Упоминания объектов метаданных в коде — записанные.
    pub metadata_code_usages: u64,
    /// Отброшено фильтром: ссылка на объект, которого в конфигурации нет.
    /// Считается отдельно, чтобы «мы полнее» и «мы чище» не смешивались.
    pub usages_filtered: u64,
    /// Элементы управляемых форм: реквизиты, обработчики, команды.
    pub form_elements: u64,
    /// Разобрано файлов форм — знаменатель для form_elements.
    pub forms: u64,
    /// Перехваты расширений — записанные строки `extension_overrides`.
    pub extension_overrides: u64,
    /// Перехваты, у которых цель НЕ разрешилась (нет модуля или метода
    /// в основной конфигурации). Считается отдельно: неразрешённая цель —
    /// это факт о корпусе, а не потеря разбора, и прятать её в общем числе
    /// значит выдать дыру за полноту.
    pub extension_unresolved: u64,
    /// Найдено расширений — знаменатель для перехватов.
    pub extensions: u64,
    /// Модули расширений, записанные в `modules` наравне с основными (Р-022).
    pub extension_modules: u64,
    /// Объекты в составе расширений — свои и заимствованные (`extension_objects`).
    pub extension_objects: u64,
    /// Строки расширений, отброшенные как повтор основной конфигурации:
    /// заимствованные реквизиты, элементы заимствованных форм, права.
    /// Считается отдельно, чтобы «записали меньше» читалось как «не задвоили»,
    /// а не как потеря.
    pub extension_duplicates: u64,
    /// XML, которые не удалось разобрать. Отдельно от модулей: это разные корпуса.
    pub meta_unreadable: u64,
    pub meta_ms: u64,
    pub files_unreadable: u64,
    pub files_with_parse_errors: u64,
    pub walk_ms: u64,
    pub parse_ms: u64,
    pub resolve_ms: u64,
    pub index_ms: u64,
    pub total_ms: u64,
    pub stats: ResolutionStats,
    /// Семантика (веха 4): словарь корпуса и векторы сущностей.
    pub semantic: crate::semantic::SemanticStats,
}

/// Разобранный модуль вместе с тем, что о нём знает индекс.
pub(crate) struct ModuleData {
    pub(crate) rel_path: String,
    pub(crate) info: ModuleInfo,
    pub(crate) size: u64,
    pub(crate) parsed: ParsedModule,
}

/// Собрать индекс кода по каталогу выгрузки.
/// Собрать индекс. `dict` — путь к готовому словарю векторов (Р-015):
/// он строится ОДИН раз по всем конфигурациям и переносится между ними,
/// поэтому берётся снаружи, а не пересчитывается на каждую сборку.
/// `None` — словаря нет, семантика уйдёт целиком в random indexing.
pub fn build(src: &Path, out: &Path, dict: Option<&Path>) -> Result<BuildReport> {
    let started = Instant::now();
    let mut report = BuildReport::default();
    let old_help = help::snapshot(out).map_err(IndexError::Unsupported)?;
    if let Some(previous) = old_help.primary_root() {
        let canonical = src.canonicalize()?;
        if Path::new(previous) != canonical {
            return Err(IndexError::Unsupported(format!(
                "индекс Help принадлежит другому проекту: {previous}; новый источник {}",
                canonical.display()
            )));
        }
    }
    let extra_help_sources = old_help.extra_sources();

    // --- обход ---
    //
    // Корни — основная конфигурация и каждое расширение (Р-022). Основная
    // идёт первой: при совпадении имён адресатом вызова остаётся её объект.
    let t = Instant::now();
    // Без манифеста у корня это не выгрузка: не тот каталог или недовыгрузка.
    // Собранный по нему индекс отвечал бы нулями, неотличимыми от «нет такого».
    if !src.join("Configuration.xml").is_file() {
        return Err(IndexError::NoConfiguration(src.display().to_string()));
    }
    let корни = extensions::корни(src);
    let mut paths = gyrfalcon_parser::scan::collect_modules(src);
    if paths.is_empty() {
        return Err(IndexError::NoModules(src.display().to_string()));
    }
    for к in корни.iter().filter(|к| к.extension.is_some()) {
        paths.extend(gyrfalcon_parser::scan::collect_modules(&к.dir));
    }
    report.walk_ms = t.elapsed().as_millis() as u64;

    // --- проход 1: разбор параллельно по ядрам ---
    let t = Instant::now();
    let parsed: Vec<ModuleData> = paths
        .par_iter()
        .filter_map(|path| read_and_parse(src, path))
        .collect();
    report.parse_ms = t.elapsed().as_millis() as u64;

    report.files_unreadable = paths.len() as u64 - parsed.len() as u64;
    report.extension_modules = parsed.iter().filter(|m| из_расширения(&m.rel_path)).count() as u64;
    report.files_with_parse_errors = parsed.iter().filter(|m| m.parsed.has_errors).count() as u64;

    // --- запись модулей, методов, областей ---
    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(out);
    let mut conn = Connection::open(out)?;
    conn.execute_batch(ddl::BUILD_PRAGMAS)?;
    conn.execute_batch(ddl::SCHEMA)?;
    help::restore(&mut conn, old_help).map_err(IndexError::Unsupported)?;

    let tables = write_modules(&mut conn, &parsed, &mut report)?;

    // --- проход 2: разрешение имён и запись рёбер ---
    let t = Instant::now();
    write_calls(&mut conn, &parsed, &tables, &mut report)?;
    report.resolve_ms = t.elapsed().as_millis() as u64;

    // --- метаданные: разбор XML параллельно, запись одним потоком ---
    let t = Instant::now();
    conn.execute_batch(ddl::SCHEMA_META)?;
    // Таблицы расширений заводятся ДО метаданных: состав каждого расширения
    // (`extension_objects`) пишется тем же проходом, что и сами объекты.
    conn.execute_batch(ddl::SCHEMA_EXTENSIONS)?;
    let из_разбора = write_metadata(&mut conn, src, &корни, &mut report)?;
    conn.execute_batch(ddl::SCHEMA_META2)?;
    write_metadata2(&mut conn, src, &корни, &mut report)?;
    conn.execute_batch(ddl::SCHEMA_INTEGRATION)?;
    write_integration(&mut conn, src, &корни, &mut report)?;
    // Упоминания пишутся ПОСЛЕ метаданных: они фильтруются по списку
    // существующих объектов, а он берётся из уже заполненных таблиц.
    conn.execute_batch(ddl::SCHEMA_USAGES)?;
    write_usages(&mut conn, &parsed, &mut report)?;
    conn.execute_batch(ddl::SCHEMA_FORMS)?;
    write_forms(&mut conn, src, &корни, &mut report)?;
    // Ссылки строятся ПОСЛЕ всех таблиц-источников: они читают их, а не файлы.
    // Перехваты расширений: читают уже записанные модули и методы основной
    // конфигурации, поэтому идут ПОСЛЕ них — резолвинг цели это SQL по
    // `modules`/`methods`, а не вторая карта в памяти.
    write_extensions(&mut conn, src, &mut report)?;
    conn.execute_batch(ddl::SCHEMA_REFS)?;
    write_references(&mut conn, из_разбора, &mut report)?;
    report.meta_ms = t.elapsed().as_millis() as u64;

    // --- семантика: ПОСЛЕ всех имён, потому что IDF считается по корпусу ---
    //
    // Стоит здесь, а не раньше: векторам нужны имена и методов, и объектов
    // метаданных. Считать семантику по одним модулям значит выбросить
    // половину корпуса имён.
    conn.execute_batch(ddl::SCHEMA_SEMANTIC)?;
    if let Some(d) = dict {
        // Словарь копируется В индекс: собранный артефакт обязан быть
        // самодостаточным. Индекс, ссылающийся на внешний файл, при переносе
        // молча теряет семантику и продолжает отвечать — хуже, чем не иметь её.
        let n = скопировать_словарь(&conn, d)?;
        tracing::info!("словарь: {n} векторов из {}", d.display());
    }
    write_semantic(&mut conn, &mut report)?;

    // Справка живёт в этом же проектном индексе: соседний проект физически
    // не может попасть в ответ. Полная пересборка перечитывает его источник.
    match help::sync(&mut conn, "primary", src) {
        Ok(help_report) => report.help = help_report,
        Err(error) => report.help_error = Some(error),
    }
    for (id, root) in extra_help_sources {
        if !root.is_dir() {
            match help::remove(&mut conn, &id) {
                Ok(removed) => report.help.removed += removed,
                Err(error) => report.help_error = Some(format!("{id}: {error}")),
            }
            continue;
        }
        let extra = match help::sync(&mut conn, &id, &root) {
            Ok(report) => report,
            Err(error) => {
                report.help_error = Some(match report.help_error {
                    Some(previous) => format!("{previous}; {id}: {error}"),
                    None => format!("{id}: {error}"),
                });
                continue;
            }
        };
        report.help.html_files += extra.html_files;
        report.help.raw_html_bytes += extra.raw_html_bytes;
        report.help.hashed += extra.hashed;
        report.help.parsed += extra.parsed;
        report.help.added += extra.added;
        report.help.updated += extra.updated;
        report.help.unchanged += extra.unchanged;
        report.help.removed += extra.removed;
        report.help.skipped_short += extra.skipped_short;
        report.help.unreadable += extra.unreadable;
        report.help.title_only += extra.title_only;
        report.help.duplicate_texts += extra.duplicate_texts;
        report.help.text_bytes += extra.text_bytes;
    }

    // --- лексический поиск: вторая половина раздельной выдачи (Р-016) ---
    //
    // `rowid` FTS-таблицы держится равным `id` исходной строки, поэтому
    // найденное лексикой адресуется тем же ключом, что и найденное
    // семантикой — иначе два списка невозможно сопоставить между собой.
    conn.execute_batch(ddl::SCHEMA_FTS)?;
    conn.execute_batch(
        "INSERT INTO methods_fts(rowid, name) SELECT id, name FROM methods;
         INSERT INTO objects_fts(rowid, name) SELECT id, object_name || ' ' || synonym
             FROM object_synonyms;",
    )?;

    // --- индексы: строго после наполнения ---
    let t = Instant::now();
    conn.execute_batch(ddl::INDEXES)?;
    conn.execute_batch(ddl::INDEXES_META)?;
    conn.execute_batch(ddl::INDEXES_META2)?;
    conn.execute_batch(ddl::INDEXES_INTEGRATION)?;
    conn.execute_batch(ddl::INDEXES_USAGES)?;
    conn.execute_batch(ddl::INDEXES_FORMS)?;
    conn.execute_batch(ddl::INDEXES_EXTENSIONS)?;
    conn.execute_batch(ddl::INDEXES_REFS)?;
    conn.execute_batch(ddl::INDEXES_SEMANTIC)?;
    report.index_ms = t.elapsed().as_millis() as u64;

    write_meta(&conn, src, &report)?;
    conn.execute_batch("PRAGMA optimize;")?;

    report.total_ms = started.elapsed().as_millis() as u64;
    Ok(report)
}

/// Прочитать и разобрать модуль. `src` — корень ОСНОВНОЙ конфигурации.
///
/// Файл расширения лежит соседом `src` (Р-022): адрес у него `../ext/<Имя>/…`,
/// а классифицируется он по пути внутри СВОЕЙ выгрузки — иначе `classify`
/// принял бы `..` за категорию, и общий модуль расширения не стал бы общим.
pub(crate) fn read_and_parse(src: &Path, path: &PathBuf) -> Option<ModuleData> {
    let raw = std::fs::read(path).ok()?;
    let raw = raw.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&raw);
    let source =
        нормализовать_переводы_строк(&String::from_utf8_lossy(raw));

    let корень = extensions::корень_файла(src, path).unwrap_or_else(|| src.to_path_buf());
    let внутри = rel_of(&корень, path);
    let rel_path = rel_of(src, path);

    Some(ModuleData {
        info: classify::classify(&внутри),
        size: raw.len() as u64,
        parsed: module::parse(&source).ok()?,
        rel_path,
    })
}

/// Привести одиночный `CR` к `LF`, не трогая `CRLF`.
///
/// # Зачем, если это выглядит косметикой
///
/// tree-sitter считает одиночный `CR` переводом строки (стандарт Unicode
/// это допускает, и сама 1С такой файл компилирует). Редакторы, `git diff`
/// и конфигуратор — не считают. Номер строки нужен человеку, чтобы ОТКРЫТЬ
/// её и увидеть, поэтому побеждает нумерация редактора, а не формальная
/// правота парсера (решение владельца 28.08.2026).
///
/// Случай не гипотетический: на корпусе БП такой символ нашёлся в одном
/// модуле из 18 230 — и сдвинул на единицу номера ВСЕХ упоминаний ниже
/// него. 16 строк расхождения с прежним инструментом из 256 709 объяснялись только этим.
/// Найдено сверкой, а не тестом: синтетика такого не порождает.
fn нормализовать_переводы_строк(s: &str) -> String {
    if !s.contains('\r') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            // CRLF оставляем как есть: он и так один перевод строки
            // для обеих сторон. Одиночный CR заменяем на LF.
            if chars.peek() == Some(&'\n') {
                out.push('\r');
            } else {
                out.push('\n');
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Записать модули, методы, области, пути файлов. Вернуть таблицы разрешения.
fn write_modules(
    conn: &mut Connection,
    parsed: &[ModuleData],
    report: &mut BuildReport,
) -> Result<ResolveTables> {
    let mut tables = ResolveTables::default();
    let tx = conn.transaction()?;

    {
        let mut ins_mod = tx.prepare(
            "INSERT INTO modules (id, rel_path, category, object_name, module_type, form_name, is_form, size)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        )?;
        let mut ins_hdr =
            tx.prepare("INSERT INTO module_headers (module_id, header_comment) VALUES (?1,?2)")?;
        let mut ins_meth = tx.prepare(
            "INSERT INTO methods (id, module_id, name, type, is_export, params, line, end_line, loc)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        )?;
        let mut ins_reg = tx.prepare(
            "INSERT INTO regions (module_id, name, line, end_line) VALUES (?1,?2,?3,?4)",
        )?;
        let mut ins_fp = tx.prepare(
            "INSERT INTO file_paths (rel_path, extension, dir_path, filename, depth, size)
             VALUES (?1,?2,?3,?4,?5,?6)",
        )?;

        let mut method_id: i64 = 0;
        for (i, m) in parsed.iter().enumerate() {
            let module_id = i as i64 + 1;
            ins_mod.execute(rusqlite::params![
                module_id,
                m.rel_path,
                m.info.category,
                m.info.object_name,
                m.info.module_type,
                m.info.form_name,
                i32::from(m.info.is_form),
                m.size as i64,
            ])?;

            if let Some(h) = &m.parsed.header_comment {
                ins_hdr.execute(rusqlite::params![module_id, h])?;
            }

            let (dir, file) = split_path(&m.rel_path);
            ins_fp.execute(rusqlite::params![
                m.rel_path,
                "bsl",
                dir,
                file,
                m.rel_path.matches('/').count() as i64,
                m.size as i64,
            ])?;

            let mut own: HashMap<String, MethodRef> = HashMap::new();
            for meth in &m.parsed.methods {
                method_id += 1;
                ins_meth.execute(rusqlite::params![
                    method_id,
                    module_id,
                    meth.name,
                    meth.kind,
                    i32::from(meth.is_export),
                    meth.params,
                    meth.line_start as i64,
                    meth.line_end as i64,
                    meth.loc() as i64,
                ])?;
                own.insert(
                    meth.name.to_lowercase(),
                    MethodRef {
                        method_id,
                        is_export: meth.is_export,
                    },
                );
            }
            report.methods += m.parsed.methods.len() as u64;

            for r in &m.parsed.regions {
                ins_reg.execute(rusqlite::params![
                    module_id,
                    r.name,
                    r.line as i64,
                    r.end_line.map(i64::from),
                ])?;
            }
            report.regions += m.parsed.regions.len() as u64;

            // Таблицы разрешения: адресуемые снаружи модули.
            //
            // Модуль расширения занимает имя, только если оно свободно:
            // заимствованный общий модуль лежит в расширении под тем же
            // именем, но адресат `ОбщийМодуль.Метод` — модуль основной
            // конфигурации, а в расширении только его перехватчики. Основная
            // записана раньше (порядок корней), поэтому «свободно» и значит
            // «собственный объект расширения».
            let из_расширения = из_расширения(&m.rel_path);
            if classify::is_common_module(&m.info) {
                if let Some(name) = &m.info.object_name {
                    let запись = (m.rel_path.clone(), own.clone());
                    if из_расширения {
                        tables
                            .common_modules
                            .entry(name.to_lowercase())
                            .or_insert(запись);
                    } else {
                        tables.common_modules.insert(name.to_lowercase(), запись);
                    }
                }
            }
            if classify::is_manager_module(&m.info) {
                if let Some(name) = &m.info.object_name {
                    let запись = (m.rel_path.clone(), own.clone());
                    if из_расширения {
                        tables.managers.entry(name.to_lowercase()).or_insert(запись);
                    } else {
                        tables.managers.insert(name.to_lowercase(), запись);
                    }
                }
            }
            for meth in &m.parsed.methods {
                tables.defined_anywhere.insert(meth.name.to_lowercase());
            }
            tables.by_module.insert(m.rel_path.clone(), own);
        }
        report.modules = parsed.len() as u64;
    }

    tx.commit()?;
    Ok(tables)
}

/// Разрешить вызовы и записать рёбра.
///
/// Разрешение считается **параллельно** (это чистая функция от таблиц),
/// а запись идёт одним потоком в транзакции.
fn write_calls(
    conn: &mut Connection,
    parsed: &[ModuleData],
    tables: &ResolveTables,
    report: &mut BuildReport,
) -> Result<()> {
    // id методов раздавались подряд по модулям — восстанавливаем базу отсчёта.
    let mut base = Vec::with_capacity(parsed.len());
    let mut acc: i64 = 0;
    for m in parsed {
        base.push(acc);
        acc += m.parsed.methods.len() as i64;
    }

    let resolved: Vec<(i64, resolve::ResolvedCall)> = parsed
        .par_iter()
        .enumerate()
        .flat_map(|(i, m)| {
            let base_id = base[i];
            m.parsed
                .calls
                .par_iter()
                .filter_map(move |c| {
                    // Вызовы вне метода в граф не идут: у ребра нет источника.
                    let caller = c.caller?;
                    let caller_id = base_id + caller as i64 + 1;
                    Some((caller_id, resolve::resolve(&c.name, &m.rel_path, tables)))
                })
                .collect::<Vec<_>>()
        })
        .collect();

    let tx = conn.transaction()?;
    {
        let mut ins = tx.prepare(
            "INSERT INTO calls (caller_id, callee_name, callee_key, resolution, confidence)
             VALUES (?1,?2,?3,?4,?5)",
        )?;
        for (caller_id, r) in &resolved {
            ins.execute(rusqlite::params![
                caller_id,
                r.callee_name,
                r.callee_key,
                r.resolution.as_str(),
                r.confidence,
            ])?;
            report.stats.add(r);
        }
    }
    tx.commit()?;

    report.calls = resolved.len() as u64;
    Ok(())
}

/// Разобрать XML метаданных и записать таблицы ядра вехи 3.
///
/// Устройство то же, что у кода (решение Р-004): разбор идёт параллельно по
/// ядрам, запись — одним потоком в транзакции. XML читается по одному файлу
/// и не накапливается: держать 65 тысяч разобранных документов разом незачем.
/// Записать метаданные и вернуть ссылки, которые видны только при разборе.
///
/// Четыре вида ссылок (`based_on`, `owner`, формы по умолчанию, тип параметра
/// команды) не выводятся из таблиц индекса: этих свойств там просто нет.
/// Заводить ради них таблицу-источник было бы честно, но лишне — прежний инструмент тоже
/// хранит их только в ссылках. Поэтому они отдаются наверх прямо из разбора.
fn write_metadata(
    conn: &mut Connection,
    src: &Path,
    корни: &[extensions::Корень],
    report: &mut BuildReport,
) -> Result<Vec<refs::MetaRef>> {
    let objects: Vec<(String, PathBuf)> = корни
        .iter()
        .flat_map(|к| meta::collect_objects(&к.dir))
        .collect();
    if objects.is_empty() {
        // Выгрузка без единого объекта метаданных — не поломка: индекс могли
        // собрать по каталогу с одними модулями. Молчаливого нуля тут нет:
        // счётчики в `index_meta` покажут ноль явно.
        return Ok(Vec::new());
    }

    let parsed: Vec<(meta::MetaObject, Vec<meta::PredefinedItem>)> = objects
        .par_iter()
        .filter_map(|(cat, path)| {
            let rel = rel_of(src, path);
            let obj = meta::parse_object(path, cat, &rel)?;
            // Предопределённые лежат отдельным файлом рядом с объектом.
            // У плоского XML каталога-спутника нет — тогда их просто нет.
            let pre_path = path.with_extension("").join("Ext").join("Predefined.xml");
            let pre = meta::parse_predefined(&pre_path);
            Some((obj, pre))
        })
        .collect();

    report.meta_unreadable = objects.len() as u64 - parsed.len() as u64;

    // Ключи основной конфигурации — чтобы строка расширения, повторяющая
    // оригинал, не легла второй (см. `без_повторов`). Пометка `Adopted`
    // отсекает заимствованное по факту; ключ страхует случай, где выгрузка
    // пометку не поставила.
    let ключ_реквизита = |o: &meta::MetaObject, a: &meta::Attribute| {
        format!(
            "{}|{}|{}|{}|{}",
            o.category,
            o.name.to_lowercase(),
            a.ts_name.as_deref().unwrap_or("").to_lowercase(),
            a.name.to_lowercase(),
            a.kind
        )
    };
    let основные_реквизиты: std::collections::HashSet<String> = parsed
        .iter()
        .filter(|(o, _)| !из_расширения(&o.source_file))
        .flat_map(|(o, _)| o.attributes.iter().map(move |a| ключ_реквизита(o, a)))
        .collect();
    let основной_состав: std::collections::HashSet<(String, String)> = parsed
        .iter()
        .filter(|(o, _)| !из_расширения(&o.source_file) && o.category == "Subsystems")
        .flat_map(|(o, _)| o.content.iter().map(move |r| (o.name.clone(), r.clone())))
        .collect();

    let tx = conn.transaction()?;
    {
        let mut ins_attr = tx.prepare(
            "INSERT INTO object_attributes
             (object_name, category, attr_name, attr_synonym, attr_type, attr_kind,
              ts_name, source_file, length, precision, scale, date_fractions)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        )?;
        let mut ins_syn = tx.prepare(
            "INSERT INTO object_synonyms (object_name, category, synonym, file)
             VALUES (?1,?2,?3,?4)",
        )?;
        let mut ins_enum = tx.prepare(
            "INSERT INTO enum_values (name, synonym, values_json, source_file)
             VALUES (?1,?2,?3,?4)",
        )?;
        let mut ins_pre = tx.prepare(
            "INSERT INTO predefined_items
             (object_name, category, item_name, item_synonym, item_code,
              types_json, is_folder, source_file)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        )?;
        let mut ins_dt =
            tx.prepare("INSERT INTO defined_types (name, type_refs_json, path) VALUES (?1,?2,?3)")?;
        let mut ins_ct = tx.prepare(
            "INSERT INTO characteristic_types (pvh_name, type_refs_json, path) VALUES (?1,?2,?3)",
        )?;
        let mut ins_sc = tx.prepare(
            "INSERT INTO subsystem_content (subsystem_name, subsystem_synonym, object_ref, file)
             VALUES (?1,?2,?3,?4)",
        )?;
        let mut ins_eo = tx.prepare(
            "INSERT INTO extension_objects
             (extension_name, category, object_name, belonging, source_file)
             VALUES (?1,?2,?3,?4,?5)",
        )?;

        let раскладка = extensions::Раскладка::из_корней(src, корни);
        let mut объектов: u64 = 0;
        for (obj, pre) in &parsed {
            // Заимствованный объект — не новый объект: его синоним, состав
            // перечисления и предопределённые уже записаны из основной
            // конфигурации. От него в индекс идёт только добавленное.
            let заимствован = из_расширения(&obj.source_file) && obj.adopted;
            if let Some(расширение) = раскладка.расширение(&obj.source_file)
            {
                ins_eo.execute(rusqlite::params![
                    расширение,
                    obj.category,
                    obj.name,
                    if obj.adopted { "adopted" } else { "own" },
                    obj.source_file,
                ])?;
                report.extension_objects += 1;
            }
            if !заимствован {
                объектов += 1;
            }

            for a in &obj.attributes {
                if из_расширения(&obj.source_file)
                    && (a.adopted
                        || основные_реквизиты.contains(&ключ_реквизита(obj, a)))
                {
                    report.extension_duplicates += 1;
                    continue;
                }
                report.attributes += 1;
                ins_attr.execute(rusqlite::params![
                    obj.name,
                    obj.category,
                    a.name,
                    a.synonym,
                    json_array(&a.types),
                    a.kind,
                    a.ts_name,
                    obj.source_file,
                    a.length,
                    a.precision,
                    a.scale,
                    a.date_fractions,
                ])?;
            }

            if заимствован {
                // Подсистема и перечисление могут нести добавленное
                // расширением — его записываем; остальное у оригинала.
                if obj.category == "Subsystems" {
                    for r in &obj.content {
                        if основной_состав.contains(&(obj.name.clone(), r.clone())) {
                            report.extension_duplicates += 1;
                            continue;
                        }
                        ins_sc.execute(rusqlite::params![
                            obj.name,
                            obj.synonym,
                            r,
                            obj.source_file
                        ])?;
                        report.subsystem_content += 1;
                    }
                }
                if obj.category == "Enums" && !obj.enum_values.is_empty() {
                    ins_enum.execute(rusqlite::params![
                        obj.name,
                        obj.synonym,
                        json_array(&obj.enum_values),
                        obj.source_file,
                    ])?;
                    report.enum_values += obj.enum_values.len() as u64;
                }
                continue;
            }

            if let Some(syn) = &obj.synonym {
                ins_syn.execute(rusqlite::params![
                    obj.name,
                    obj.category,
                    syn,
                    obj.source_file
                ])?;
            }

            // Пустое перечисление записывается СТРОКОЙ с пустым списком,
            // а не пропускается. На БП таких два, и они существуют: молчание
            // о них неотличимо от «такого перечисления нет», а это разные
            // ответы на вопрос агента. Так же поступает прежний инструмент.
            if obj.category == "Enums" {
                ins_enum.execute(rusqlite::params![
                    obj.name,
                    obj.synonym,
                    json_array(&obj.enum_values),
                    obj.source_file,
                ])?;
                report.enum_values += obj.enum_values.len() as u64;
            }

            if obj.category == "DefinedTypes" && !obj.type_refs.is_empty() {
                ins_dt.execute(rusqlite::params![
                    obj.name,
                    json_array(&obj.type_refs),
                    obj.source_file
                ])?;
            }
            if obj.category == "ChartsOfCharacteristicTypes" && !obj.type_refs.is_empty() {
                ins_ct.execute(rusqlite::params![
                    obj.name,
                    json_array(&obj.type_refs),
                    obj.source_file
                ])?;
            }

            // Только подсистемы. Тег `<Content>` есть и у критериев отбора
            // (`FilterCriteria`), и его состав — не состав подсистемы:
            // 28.08.2026 так натекло 489 лишних строк, среди них ссылки на
            // реквизиты (`Document.X.Attribute.Y`), которых в подсистеме
            // не бывает. Таблица, куда попадает «всё похожее», перестаёт
            // отвечать на вопрос, ради которого заведена.
            if obj.category == "Subsystems" {
                for r in &obj.content {
                    ins_sc.execute(rusqlite::params![obj.name, obj.synonym, r, obj.source_file])?;
                }
                report.subsystem_content += obj.content.len() as u64;
            }

            for it in pre {
                ins_pre.execute(rusqlite::params![
                    obj.name,
                    obj.category,
                    it.name,
                    it.description,
                    it.code,
                    json_array(&it.types),
                    i32::from(it.is_folder),
                    obj.source_file,
                ])?;
            }
            report.predefined += pre.len() as u64;
        }
        // Объектов — без заимствованных: они уже посчитаны в основной.
        // На конфигурации без расширений число то же, что прежде.
        report.meta_objects = объектов;
    }
    tx.commit()?;

    // Ссылки из разбора (ввод на основании, владельцы, формы по умолчанию)
    // у заимствованного объекта повторяют ссылки оригинала.
    let свои: Vec<(meta::MetaObject, Vec<meta::PredefinedItem>)> = parsed
        .into_iter()
        .filter(|(o, _)| !(из_расширения(&o.source_file) && o.adopted))
        .collect();
    Ok(refs::из_разбора(&свои))
}

/// Собрать пути объектов одной категории первого уровня: `<Категория>/<Имя>.xml`.
///
/// Возвращает пары (имя объекта, путь). Отсутствие каталога — штатный случай:
/// не во всякой конфигурации есть планы обмена или регламентные задания.
fn category_files(src: &Path, category: &str) -> Vec<(String, PathBuf)> {
    let dir = src.join(category);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) == Some("xml") {
            if let Some(name) = p.file_stem().and_then(|x| x.to_str()) {
                out.push((name.to_string(), p));
            }
        }
    }
    out
}

/// Собрать пути файлов-спутников: `<Категория>/<Имя>/Ext/<файл>`.
///
/// Обход идёт по каталогам категории, а не по всем файлам дерева: у роли и
/// плана обмена нужный файл лежит на фиксированной глубине, и рекурсия сюда
/// притащила бы формы и макеты.
fn companion_files(src: &Path, category: &str, rel_tail: &str) -> Vec<(String, PathBuf)> {
    let dir = src.join(category);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let target = p.join(rel_tail);
        if target.is_file() {
            if let Some(name) = p.file_name().and_then(|x| x.to_str()) {
                out.push((name.to_string(), target));
            }
        }
    }
    out
}

/// Путь относительно корня выгрузки, разделителем `/` — формат прежнего инструмента.
///
/// Файл расширения получает адрес `../ext/<Имя>/…` (см. `extensions::rel_from`).
fn rel_of(src: &Path, path: &Path) -> String {
    extensions::rel_from(src, path)
}

/// Строка пришла из расширения — по адресу её файла.
fn из_расширения(file: &str) -> bool {
    file.starts_with("../")
}

/// Убрать из строк расширений те, что повторяют строку основной конфигурации.
///
/// Заимствованный объект лежит в выгрузке расширения вместе с тем, что
/// расширению понадобилось от оригинала: роль — с правами, форма — со всеми
/// элементами, подписка — целиком. Записать их ещё раз значит раздвоить
/// каждый такой реквизит и элемент в выдаче, и раздвоение читалось бы как
/// «их два». Остаётся только добавленное расширением. Сравнение — по ключу
/// содержания, без файла: файл у копии другой по определению.
fn без_повторов<T>(
    rows: Vec<T>,
    file: impl Fn(&T) -> &str,
    key: impl Fn(&T) -> String,
    отброшено: &mut u64,
) -> Vec<T> {
    let основные: std::collections::HashSet<String> = rows
        .iter()
        .filter(|r| !из_расширения(file(r)))
        .map(&key)
        .collect();
    let до = rows.len();
    let out: Vec<T> = rows
        .into_iter()
        .filter(|r| !из_расширения(file(r)) || !основные.contains(&key(r)))
        .collect();
    *отброшено += (до - out.len()) as u64;
    out
}

/// Записать вторую часть метаданных вехи 3.
///
/// Разбор параллельный, запись одним потоком — как в первой части (решение
/// Р-004): пять корпусов независимы, и ждать друг друга им незачем.
fn write_metadata2(
    conn: &mut Connection,
    src: &Path,
    корни: &[extensions::Корень],
    report: &mut BuildReport,
) -> Result<()> {
    // Файлы — по всем корням; адрес — от `src` (у расширения `../ext/…`).
    let файлы = |кат: &str| -> Vec<(String, PathBuf)> {
        корни
            .iter()
            .flat_map(|к| category_files(&к.dir, кат))
            .collect()
    };
    let спутники = |кат: &str, хвост: &str| -> Vec<(String, PathBuf)> {
        корни
            .iter()
            .flat_map(|к| companion_files(&к.dir, кат, хвост))
            .collect()
    };
    let mut повторы = 0u64;

    let subs: Vec<meta2::EventSubscription> = файлы("EventSubscriptions")
        .par_iter()
        .filter_map(|(_, p)| meta2::parse_event_subscription(p, &rel_of(src, p)))
        .collect();
    let subs = без_повторов(subs, |s| &s.file, |s| s.name.to_lowercase(), &mut повторы);

    let jobs: Vec<meta2::ScheduledJob> = файлы("ScheduledJobs")
        .par_iter()
        .filter_map(|(_, p)| meta2::parse_scheduled_job(p, &rel_of(src, p)))
        .collect();
    let jobs = без_повторов(jobs, |j| &j.file, |j| j.name.to_lowercase(), &mut повторы);

    let opts: Vec<meta2::FunctionalOption> = файлы("FunctionalOptions")
        .par_iter()
        .filter_map(|(_, p)| meta2::parse_functional_option(p, &rel_of(src, p)))
        .collect();
    let opts = без_повторов(opts, |o| &o.file, |o| o.name.to_lowercase(), &mut повторы);

    // Флаги общего модуля задаёт основная конфигурация. Заимствованный в
    // расширение модуль их не меняет, поэтому повтор по имени отбрасывается
    // тем же правилом, что у остальных таблиц, — первым идёт основной корень.
    let common: Vec<meta2::CommonModuleFlags> = файлы("CommonModules")
        .par_iter()
        .filter_map(|(_, p)| meta2::parse_common_module(p, &rel_of(src, p)))
        .collect();
    let common =
        без_повторов(common, |m| &m.file, |m| m.name.to_lowercase(), &mut повторы);

    let rights: Vec<meta2::RoleRight> = спутники("Roles", "Ext/Rights.xml")
        .par_iter()
        .flat_map(|(role, p)| meta2::parse_role_rights(p, role, &rel_of(src, p)))
        .collect();
    let rights = без_повторов(
        rights,
        |r| &r.file,
        |r| format!("{}|{}|{}", r.role_name, r.object_name, r.right_name).to_lowercase(),
        &mut повторы,
    );

    let content: Vec<meta2::ExchangeContentItem> =
        спутники("ExchangePlans", "Ext/Content.xml")
            .par_iter()
            .flat_map(|(plan, p)| meta2::parse_exchange_content(p, plan, &rel_of(src, p)))
            .collect();
    let content = без_повторов(
        content,
        |c| &c.path,
        |c| format!("{}|{}", c.plan_name, c.object_ref).to_lowercase(),
        &mut повторы,
    );
    report.extension_duplicates += повторы;

    let tx = conn.transaction()?;
    {
        let mut ins_es = tx.prepare(
            "INSERT INTO event_subscriptions
             (name, synonym, event, handler_module, handler_procedure,
              source_types, source_count, file)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        )?;
        for s in &subs {
            ins_es.execute(rusqlite::params![
                s.name,
                s.synonym,
                s.event,
                s.handler_module,
                s.handler_procedure,
                json_array(&s.source_types),
                s.source_types.len() as i64,
                s.file,
            ])?;
        }

        let mut ins_sj = tx.prepare(
            "INSERT INTO scheduled_jobs
             (name, synonym, method_name, handler_module, handler_procedure,
              use, predefined, restart_count, restart_interval, file)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        )?;
        for j in &jobs {
            ins_sj.execute(rusqlite::params![
                j.name,
                j.synonym,
                j.method_name,
                j.handler_module,
                j.handler_procedure,
                i32::from(j.use_),
                i32::from(j.predefined),
                j.restart_count,
                j.restart_interval,
                j.file,
            ])?;
        }

        let mut ins_fo = tx.prepare(
            "INSERT INTO functional_options (name, synonym, location, content, file)
             VALUES (?1,?2,?3,?4,?5)",
        )?;
        for o in &opts {
            ins_fo.execute(rusqlite::params![
                o.name,
                o.synonym,
                o.location,
                json_array(&o.content),
                o.file,
            ])?;
        }

        let mut ins_cm = tx.prepare(
            "INSERT INTO common_modules
             (name, global, client_managed, client_ordinary, server, server_call,
              external_connection, privileged, file)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        )?;
        for m in &common {
            ins_cm.execute(rusqlite::params![
                m.name,
                i32::from(m.global),
                i32::from(m.client_managed),
                i32::from(m.client_ordinary),
                i32::from(m.server),
                i32::from(m.server_call),
                i32::from(m.external_connection),
                i32::from(m.privileged),
                m.file,
            ])?;
        }

        let mut ins_rr = tx.prepare(
            "INSERT INTO role_rights (role_name, object_name, right_name, file)
             VALUES (?1,?2,?3,?4)",
        )?;
        for r in &rights {
            ins_rr.execute(rusqlite::params![
                r.role_name,
                r.object_name,
                r.right_name,
                r.file
            ])?;
        }

        let mut ins_ec = tx.prepare(
            "INSERT INTO exchange_plan_content (plan_name, object_ref, auto_record, path)
             VALUES (?1,?2,?3,?4)",
        )?;
        for c in &content {
            ins_ec.execute(rusqlite::params![
                c.plan_name,
                c.object_ref,
                c.auto_record,
                c.path
            ])?;
        }
    }
    tx.commit()?;

    report.event_subscriptions = subs.len() as u64;
    report.scheduled_jobs = jobs.len() as u64;
    report.functional_options = opts.len() as u64;
    report.common_modules = common.len() as u64;
    report.role_rights = rights.len() as u64;
    report.exchange_plan_content = content.len() as u64;
    Ok(())
}

/// Записать интеграцию и движения: движения регистров, XDTO, web- и HTTP-сервисы.
///
/// Разбор параллельный, запись одним потоком — как в остальных стадиях (Р-004).
///
/// Движения берутся из объявленного состава `<RegisterRecords>` документов.
/// Кодовый источник прежнего инструмента (`code`/`manager_code`/`manager_table`) сюда пока не
/// добавлен: он требует прохода по телам модулей и приедет вместе с
/// `metadata_code_usages`, где модули и так читаются. Столбец `source` заведён
/// сразу, чтобы дописать классы, а не менять схему.
fn write_integration(
    conn: &mut Connection,
    src: &Path,
    корни: &[extensions::Корень],
    report: &mut BuildReport,
) -> Result<()> {
    let файлы = |кат: &str| -> Vec<(String, PathBuf)> {
        корни
            .iter()
            .flat_map(|к| category_files(&к.dir, кат))
            .collect()
    };
    let mut повторы = 0u64;

    // Документ расширения пишет в регистры — это его движения, и без них
    // вопрос «кто пишет в регистр» на доработанной базе отвечает неполно.
    let movements: Vec<integration::RegisterMovement> = файлы("Documents")
        .par_iter()
        .flat_map(|(name, p)| integration::parse_declared_movements(p, name, &rel_of(src, p)))
        .collect();
    let movements = без_повторов(
        movements,
        |m| &m.file,
        |m| format!("{}|{}|{}", m.document_name, m.register_name, m.source).to_lowercase(),
        &mut повторы,
    );

    let packages: Vec<integration::XdtoPackage> = файлы("XDTOPackages")
        .par_iter()
        .filter_map(|(_, p)| {
            // Пакет лежит каталогом-спутником рядом со своим XML — в том же
            // корне, где найден, а не обязательно в основной конфигурации.
            let bin = p.with_extension("").join("Ext").join("Package.bin");
            integration::parse_xdto_package(p, &bin, &rel_of(src, p))
        })
        .collect();
    let packages = без_повторов(
        packages,
        |p| &p.file,
        |p| p.name.to_lowercase(),
        &mut повторы,
    );

    let webs: Vec<integration::WebService> = файлы("WebServices")
        .par_iter()
        .filter_map(|(_, p)| integration::parse_web_service(p, &rel_of(src, p)))
        .collect();
    let webs = без_повторов(webs, |s| &s.file, |s| s.name.to_lowercase(), &mut повторы);

    let https: Vec<integration::HttpService> = файлы("HTTPServices")
        .par_iter()
        .filter_map(|(_, p)| integration::parse_http_service(p, &rel_of(src, p)))
        .collect();
    let https =
        без_повторов(https, |s| &s.file, |s| s.name.to_lowercase(), &mut повторы);
    report.extension_duplicates += повторы;

    let tx = conn.transaction()?;
    {
        let mut ins_rm = tx.prepare(
            "INSERT INTO register_movements (document_name, register_name, source, file)
             VALUES (?1,?2,?3,?4)",
        )?;
        for m in &movements {
            ins_rm.execute(rusqlite::params![
                m.document_name,
                m.register_name,
                m.source,
                m.file
            ])?;
        }

        let mut ins_xp = tx.prepare(
            "INSERT INTO xdto_packages (name, namespace, types_json, file)
             VALUES (?1,?2,?3,?4)",
        )?;
        for p in &packages {
            ins_xp.execute(rusqlite::params![
                p.name,
                p.namespace,
                xdto_types_json(&p.types),
                p.file,
            ])?;
        }

        let mut ins_ws = tx.prepare(
            "INSERT INTO web_services (name, namespace, operations_json, file)
             VALUES (?1,?2,?3,?4)",
        )?;
        for s in &webs {
            ins_ws.execute(rusqlite::params![
                s.name,
                s.namespace,
                web_operations_json(&s.operations),
                s.file,
            ])?;
        }

        let mut ins_hs = tx.prepare(
            "INSERT INTO http_services (name, root_url, templates_json, file)
             VALUES (?1,?2,?3,?4)",
        )?;
        for s in &https {
            ins_hs.execute(rusqlite::params![
                s.name,
                s.root_url,
                http_templates_json(&s.templates),
                s.file,
            ])?;
        }
    }
    tx.commit()?;

    report.register_movements = movements.len() as u64;
    report.xdto_packages = packages.len() as u64;
    report.xdto_types = packages.iter().map(|p| p.types.len() as u64).sum();
    report.web_services = webs.len() as u64;
    report.http_services = https.len() as u64;
    Ok(())
}

/// Типы пакета XDTO в JSON. Форма своя: у прежнего инструмента здесь всегда `[]`,
/// воспроизводить нечего.
fn xdto_types_json(types: &[integration::XdtoType]) -> String {
    let v: Vec<serde_json::Value> = types
        .iter()
        .map(|t| {
            let props: Vec<serde_json::Value> = t
                .properties
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.name,
                        "type": p.type_ref,
                        "lower_bound": p.lower_bound,
                        "upper_bound": p.upper_bound,
                    })
                })
                .collect();
            serde_json::json!({
                "kind": t.kind,
                "name": t.name,
                "base": t.base,
                "properties": props,
            })
        })
        .collect();
    serde_json::Value::Array(v).to_string()
}

/// Операции web-сервиса в JSON. Ключи — прежний инструментские (`return_type`,
/// `procedure_name`, `params`), чтобы читатель индекса не переучивался.
fn web_operations_json(ops: &[integration::WebOperation]) -> String {
    let v: Vec<serde_json::Value> = ops
        .iter()
        .map(|o| {
            serde_json::json!({
                "name": o.name,
                "return_type": o.return_type,
                "procedure_name": o.procedure_name,
                "params": o.params,
            })
        })
        .collect();
    serde_json::Value::Array(v).to_string()
}

/// Шаблоны HTTP-сервиса в JSON. Ключи прежний инструментские.
fn http_templates_json(tpls: &[integration::HttpTemplate]) -> String {
    let v: Vec<serde_json::Value> = tpls
        .iter()
        .map(|t| {
            let methods: Vec<serde_json::Value> = t
                .methods
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "name": m.name,
                        "http_method": m.http_method,
                        "handler": m.handler,
                    })
                })
                .collect();
            serde_json::json!({
                "name": t.name,
                "template": t.template,
                "methods": methods,
            })
        })
        .collect();
    serde_json::Value::Array(v).to_string()
}

/// Записать упоминания объектов метаданных в коде.
///
/// Разбор уже сделан проходом 1 — здесь только фильтрация и запись.
/// Фильтр по списку существующих объектов обязателен: без него в таблицу
/// попадают методы платформы (`Документы.ТипВсеСсылки`), псевдонимы таблиц
/// в запросах (`ВЫБРАТЬ Документ.Дата`), JavaScript и XML внутри строковых
/// литералов. У прежнего инструмента таких строк 1,41% — см. `ddl::SCHEMA_USAGES`.
fn write_usages(
    conn: &mut Connection,
    parsed: &[ModuleData],
    report: &mut BuildReport,
) -> Result<()> {
    let существующие = существующие_объекты(conn)?;
    // Пустой список объектов — законное состояние (индекс по каталогу с одними
    // модулями). Фильтровать в этом случае нечем, и отбрасывать всё было бы
    // подменой «не с чем сверить» на «ничего не найдено».
    let фильтровать = !существующие.is_empty();

    let tx = conn.transaction()?;
    let mut записано: u64 = 0;
    let mut отброшено: u64 = 0;
    {
        let mut ins = tx.prepare(
            "INSERT INTO metadata_code_usages
             (module_id, object_ref, object_ref_key, member_path, usage_kind, line)
             VALUES (?1,?2,?3,?4,?5,?6)",
        )?;
        for (i, m) in parsed.iter().enumerate() {
            let module_id = i as i64 + 1;
            for u in &m.parsed.usages {
                if фильтровать && !существующие.contains(&u.object_ref_key) {
                    отброшено += 1;
                    continue;
                }
                ins.execute(rusqlite::params![
                    module_id,
                    u.object_ref,
                    u.object_ref_key,
                    u.member_path,
                    u.kind.as_str(),
                    u.line,
                ])?;
                записано += 1;
            }
        }
    }
    tx.commit()?;

    report.metadata_code_usages = записано;
    report.usages_filtered = отброшено;
    Ok(())
}

/// Ключи существующих объектов метаданных: `document.операциябух`.
///
/// Источник — уже заполненные таблицы этого же индекса, а не файлы: к моменту
/// вызова метаданные разобраны. Категория выгрузки (`Catalogs`) приводится к
/// категории ссылки (`Catalog`) — форма, в которой упоминания и записываются.
fn существующие_объекты(
    conn: &Connection,
) -> Result<std::collections::HashSet<String>> {
    let mut out = std::collections::HashSet::new();
    for sql in [
        "SELECT DISTINCT object_name, category FROM object_synonyms",
        "SELECT DISTINCT object_name, category FROM object_attributes",
    ] {
        let mut st = conn.prepare(sql)?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (name, cat) = row?;
            if let Some(k) = ключ_упоминания(&cat, &name) {
                out.insert(k);
            }
        }
    }
    Ok(out)
}

/// Ключ объекта в `metadata_code_usages.object_ref_key`: `document.операциябух`.
///
/// Единственное место, где ключ строится из категории выгрузки и имени: им
/// пишет сборщик и им же ищет `find`. Две копии формулы однажды разойдутся,
/// и счётчик молча станет нулём — так уже было с колонкой `metadata_name`,
/// которой в схеме не было никогда.
///
/// Нижний регистр — Rust-овый, а не `lower()` SQLite: тот понижает только
/// ASCII и кириллическое имя оставил бы как есть.
pub fn ключ_упоминания(категория: &str, имя: &str) -> Option<String> {
    категория_ссылки(категория).map(|k| format!("{k}.{имя}").to_lowercase())
}

/// Категория каталога выгрузки → категория в ссылке.
///
/// Список закрытый и покрывает те виды, что вообще бывают в упоминаниях
/// (проверено по прежнему инструменту: 15 категорий на 259 401 строке).
fn категория_ссылки(каталог: &str) -> Option<&'static str> {
    Some(match каталог {
        "Catalogs" => "Catalog",
        "Documents" => "Document",
        "Enums" => "Enum",
        "InformationRegisters" => "InformationRegister",
        "AccumulationRegisters" => "AccumulationRegister",
        "AccountingRegisters" => "AccountingRegister",
        "CalculationRegisters" => "CalculationRegister",
        "ChartsOfAccounts" => "ChartOfAccounts",
        "ChartsOfCharacteristicTypes" => "ChartOfCharacteristicTypes",
        "ChartsOfCalculationTypes" => "ChartOfCalculationTypes",
        "ExchangePlans" => "ExchangePlan",
        "BusinessProcesses" => "BusinessProcess",
        "Tasks" => "Task",
        "Constants" => "Constant",
        "DataProcessors" => "DataProcessor",
        "Reports" => "Report",
        "DocumentJournals" => "DocumentJournal",
        _ => return None,
    })
}

/// Собрать пути всех форм выгрузки.
///
/// Формы лежат в двух раскладках, и обе нужны:
///
/// ```text
/// <Категория>/<Объект>/Forms/<Форма>/Ext/Form.xml   — форма объекта
/// CommonForms/<Имя>/Ext/Form.xml                    — общая форма
/// ```
///
/// Замер 28.08.2026 на БП: 7 463 формы объектов + 427 общих = 7 890
/// против 7 874 уникальных форм у прежнего инструмента.
fn form_files(src: &Path) -> Vec<(String, String, String, PathBuf)> {
    let mut out = Vec::new();

    // Общие формы: у них нет объекта-владельца.
    if let Ok(rd) = std::fs::read_dir(src.join("CommonForms")) {
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_dir() {
                continue;
            }
            let target = p.join("Ext").join("Form.xml");
            if target.is_file() {
                if let Some(name) = p.file_name().and_then(|x| x.to_str()) {
                    out.push((
                        name.to_string(),
                        "CommonForms".to_string(),
                        name.to_string(),
                        target,
                    ));
                }
            }
        }
    }

    // Формы объектов по всем категориям.
    let Ok(корень) = std::fs::read_dir(src) else {
        return out;
    };
    for кат in корень.flatten() {
        let кат_путь = кат.path();
        if !кат_путь.is_dir() {
            continue;
        }
        let Some(категория) = кат.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if категория == "CommonForms" {
            continue;
        }
        let Ok(объекты) = std::fs::read_dir(&кат_путь) else {
            continue;
        };
        for об in объекты.flatten() {
            let об_путь = об.path();
            if !об_путь.is_dir() {
                continue;
            }
            let Some(объект) = об.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Ok(формы) = std::fs::read_dir(об_путь.join("Forms")) else {
                continue;
            };
            for ф in формы.flatten() {
                let ф_путь = ф.path();
                if !ф_путь.is_dir() {
                    continue;
                }
                let target = ф_путь.join("Ext").join("Form.xml");
                if target.is_file() {
                    if let Some(форма) = ф.file_name().to_str() {
                        out.push((объект.clone(), категория.clone(), форма.to_string(), target));
                    }
                }
            }
        }
    }
    out
}

/// Записать элементы управляемых форм.
///
/// Разбор параллельный, запись одним потоком (Р-004). Формы — самый крупный
/// корпус XML после модулей: 7 890 файлов, и разбирать их последовательно
/// значило бы отдать выигрыш по ядрам даром.
fn write_forms(
    conn: &mut Connection,
    src: &Path,
    корни: &[extensions::Корень],
    report: &mut BuildReport,
) -> Result<()> {
    let файлы: Vec<(String, String, String, PathBuf)> =
        корни.iter().flat_map(|к| form_files(&к.dir)).collect();
    let элементы: Vec<forms::FormElement> = файлы
        .par_iter()
        .flat_map(|(объект, категория, форма, путь)| {
            forms::parse_form(путь, объект, категория, форма, &rel_of(src, путь))
        })
        .collect();
    // Заимствованная форма выгружается в расширение целиком, с элементами
    // оригинала. Остаются только добавленные расширением элементы.
    let mut повторы = 0u64;
    let элементы = без_повторов(
        элементы,
        |e| &e.file,
        |e| {
            format!(
                "{}|{}|{}|{}|{}|{}|{:?}|{:?}|{:?}",
                e.category,
                e.object_name,
                e.form_name,
                e.kind,
                e.scope,
                e.element_name,
                e.event,
                e.handler,
                e.data_path
            )
            .to_lowercase()
        },
        &mut повторы,
    );
    report.extension_duplicates += повторы;

    let tx = conn.transaction()?;
    {
        let mut ins = tx.prepare(
            "INSERT INTO form_elements
             (object_name, category, form_name, kind, scope, element_name,
              element_type, event, handler, data_path, main_table,
              attribute_is_main, extra_json, file)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
        )?;
        for e in &элементы {
            ins.execute(rusqlite::params![
                e.object_name,
                e.category,
                e.form_name,
                e.kind,
                e.scope,
                e.element_name,
                e.element_type,
                e.event,
                e.handler,
                e.data_path,
                e.main_table,
                i32::from(e.attribute_is_main),
                "",
                e.file,
            ])?;
        }
    }
    tx.commit()?;

    report.form_elements = элементы.len() as u64;
    report.forms = файлы.len() as u64;
    Ok(())
}

/// Записать ссылки между объектами метаданных.
///
/// Источник — уже заполненные таблицы этого же индекса, а не файлы выгрузки.
/// Поэтому вызывается последней: до неё разбор должен быть завершён.
fn write_references(
    conn: &mut Connection,
    из_разбора: Vec<refs::MetaRef>,
    report: &mut BuildReport,
) -> Result<()> {
    let mut links = refs::собрать(conn)?;
    links.extend(из_разбора);
    let tx = conn.transaction()?;
    {
        let mut ins = tx.prepare(
            "INSERT INTO metadata_references
             (source_object, source_category, ref_object, ref_kind, used_in, path, line)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
        )?;
        for l in &links {
            ins.execute(rusqlite::params![
                l.source_object,
                l.source_category,
                l.ref_object,
                l.ref_kind,
                l.used_in,
                l.path,
                l.line,
            ])?;
        }
    }
    tx.commit()?;
    report.metadata_references = links.len() as u64;
    Ok(())
}

/// Список строк как JSON-массив — формат прежнего инструмента для типов и значений.
///
/// Своя сборка вместо `serde_json`: значения здесь всегда строки, а экранировать
/// нужно кавычку и обратный слэш. Тащить сериализатор ради этого незачем,
/// а вот молча получить неэкранированную кавычку в JSON — можно.
fn json_array(items: &[String]) -> String {
    let mut s = String::from("[");
    for (i, x) in items.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push('"');
        for c in x.chars() {
            match c {
                '"' => s.push_str("\\\""),
                '\\' => s.push_str("\\\\"),
                _ => s.push(c),
            }
        }
        s.push('"');
    }
    s.push(']');
    s
}

fn write_meta(conn: &Connection, src: &Path, report: &BuildReport) -> Result<()> {
    let pairs: [(&str, String); 19] = [
        ("builder", "gyrfalcon".into()),
        // Версия ПРОГРАММЫ и версия СХЕМЫ — разные вещи, и пишутся обе.
        // Правка кода без правки таблиц не делает индекс несовместимым.
        ("builder_version", env!("CARGO_PKG_VERSION").into()),
        ("schema_version", ddl::SCHEMA_VERSION.to_string()),
        ("built_at", built_at()),
        ("source_path", src.display().to_string()),
        // Коммит рабочей копии на момент сборки (веха 7). Пусто — выгрузка
        // лежит вне git; тогда единственный признак отставания это mtime.
        //
        // Признак нужен ВТОРЫМ, потому что mtime слеп к `git checkout`:
        // git восстанавливает прежнее содержимое, ставя своё время правки,
        // и файл, вернувшийся к старому виду, выглядит нетронутым.
        ("git_commit", crate::git::head(src).unwrap_or_default()),
        ("modules", report.modules.to_string()),
        ("methods", report.methods.to_string()),
        ("calls_total", report.stats.total.to_string()),
        ("calls_resolved", report.stats.resolved.to_string()),
        ("calls_resolvable", report.stats.resolvable().to_string()),
        // Веха 3: счётчики метаданных названы теми же именами, что у прежнего инструмента,
        // чтобы паритет считался сравнением значений, а не переводом ключей.
        ("meta_objects", report.meta_objects.to_string()),
        ("object_attributes_count", report.attributes.to_string()),
        ("predefined_items_count", report.predefined.to_string()),
        ("enum_values_count", report.enum_values.to_string()),
        (
            "subsystem_content_count",
            report.subsystem_content.to_string(),
        ),
        // Р-022: расширения в индексе целиком. Ноль модулей при ненулевом
        // числе расширений — признак, что их код не попал, и он виден здесь,
        // а не только по пустому ответу на поиск.
        ("extensions", report.extensions.to_string()),
        ("extension_modules", report.extension_modules.to_string()),
        ("extension_objects", report.extension_objects.to_string()),
    ];
    for (k, v) in pairs {
        conn.execute(
            "INSERT OR REPLACE INTO index_meta (key, value) VALUES (?1,?2)",
            rusqlite::params![k, v],
        )?;
    }
    Ok(())
}

/// Время сборки в секундах эпохи.
///
/// Не форматированная дата: у неё есть часовой пояс и локаль, а у индекса,
/// который переносится между машинами, их быть не должно.
fn built_at() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())
}

/// Что индекс говорит о себе. Читается **до** запросов к нему.
#[derive(Debug, Clone)]
pub struct IndexInfo {
    pub schema_version: u32,
    pub builder: String,
    pub builder_version: String,
    pub source_path: String,
    pub built_at: u64,
    /// Коммит выгрузки на момент сборки. Пусто — не git или не записан.
    pub git_commit: String,
}

impl IndexInfo {
    /// Отстал ли индекс от исходников (веха 7).
    ///
    /// Живёт здесь, а не в вызывающем коде, потому что все три аргумента —
    /// собственные записи индекса. Собери их снаружи — и появится
    /// возможность сверить индекс не с тем каталогом, получив складный
    /// неверный ответ.
    pub fn freshness(&self) -> crate::freshness::Freshness {
        crate::freshness::check(self.built_at, &self.source_path, &self.git_commit)
    }

    /// Умеет ли текущий код читать этот индекс.
    pub fn is_readable(&self) -> bool {
        self.schema_version >= ddl::MIN_READABLE_SCHEMA
            && self.schema_version <= ddl::SCHEMA_VERSION
    }
}

/// Прочитать сведения об индексе.
///
/// Отдельная функция, потому что вызывать её надо **первой**, до содержательных
/// запросов: индекс несовместимой версии отвечает не ошибкой, а неверными
/// данными — столбца нет, значение пустое, вывод «ничего не найдено».
pub fn info(path: &Path) -> Result<IndexInfo> {
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let get = |k: &str| -> String {
        conn.query_row(
            "SELECT value FROM index_meta WHERE key = ?1",
            rusqlite::params![k],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_default()
    };
    Ok(IndexInfo {
        // Индекс без записанной версии считается нулевым, а не текущим:
        // «версии нет» значит «собран до того, как версии появились».
        schema_version: get("schema_version").parse().unwrap_or(0),
        builder: get("builder"),
        builder_version: get("builder_version"),
        source_path: get("source_path"),
        built_at: get("built_at").parse().unwrap_or(0),
        git_commit: get("git_commit"),
    })
}

fn split_path(rel: &str) -> (String, String) {
    match rel.rfind('/') {
        Some(i) => (rel[..i].to_string(), rel[i + 1..].to_string()),
        None => (String::new(), rel.to_string()),
    }
}

/// Записать перехваты расширений.
///
/// Три шага: найти расширения соседями от `src`, разобрать их модули (тем же
/// парсером, что и основную конфигурацию — перехватчик это обычный BSL),
/// разрешить цель по уже записанным `modules`/`methods`.
///
/// Резолвинг ищет метод в том же по имени модуле основной конфигурации:
/// расширение выгружается зеркально, `CommonModules/X/Ext/Module.bsl` в
/// расширении отвечает такому же пути в `src`. Не нашлось — пишем строку
/// с пустым `target_method_line`: перехват в расширении есть, а цели нет,
/// и это факт о корпусе, который прятать нельзя.
fn write_extensions(conn: &mut Connection, src: &Path, report: &mut BuildReport) -> Result<()> {
    let расширения: Vec<extensions::Extension> = extensions::extension_dirs(src)
        .iter()
        .flat_map(|d| extensions::collect_extensions(d))
        .collect();
    report.extensions = расширения.len() as u64;
    if расширения.is_empty() {
        return Ok(());
    }

    // Реестр расширений — ВСЕ, а не только те, у кого есть перехваты.
    // Прежде расширение без перехвата не существовало для индекса вовсе:
    // на ДО два из девяти, и «что делает это расширение» отвечало пустотой.
    {
        let tx = conn.transaction()?;
        {
            let mut ins = tx.prepare(
                "INSERT INTO extensions (name, purpose, name_prefix, rel_root)
                 VALUES (?1,?2,?3,?4)",
            )?;
            for e in &расширения {
                ins.execute(rusqlite::params![
                    e.name,
                    e.purpose,
                    e.name_prefix,
                    rel_of(src, &e.root),
                ])?;
            }
        }
        tx.commit()?;
    }

    // Разбор по расширениям параллельно: их немного, но модулей внутри
    // бывает много, и последовательный проход тут даром отдаёт ядра.
    let найдено: Vec<extensions::Override> = расширения
        .par_iter()
        .flat_map(перехваты_расширения)
        .collect();

    // Резолвинг цели по уже записанным таблицам основной конфигурации.
    let mut строки = найдено;
    {
        let mut sel = conn.prepare(
            "SELECT m.id, mt.line
               FROM modules m
               JOIN methods mt ON mt.module_id = m.id
              WHERE m.rel_path = ?1 COLLATE NOCASE
                AND mt.name = ?2 COLLATE NOCASE
              LIMIT 1",
        )?;
        for перехват in &mut строки {
            let найдено: Option<(i64, i64)> = sel
                .query_row(
                    rusqlite::params![&перехват.source_path, &перехват.target_method],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match найдено {
                Some((_, line)) => перехват.target_method_line = Some(line as u32),
                None => report.extension_unresolved += 1,
            }
        }
    }

    let tx = conn.transaction()?;
    {
        let mut ins = tx.prepare(
            "INSERT INTO extension_overrides
             (object_name, source_path, source_module_id, target_method,
              target_method_line, annotation, extension_name, extension_purpose,
              extension_method, extension_root, ext_module_path, ext_line)
             VALUES (?1,?2,
                     (SELECT id FROM modules WHERE rel_path = ?2 COLLATE NOCASE),
                     ?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        )?;
        for перехват in &строки {
            ins.execute(rusqlite::params![
                перехват.object_name,
                перехват.source_path,
                перехват.target_method,
                перехват.target_method_line,
                перехват.annotation,
                перехват.extension_name,
                перехват.extension_purpose,
                перехват.extension_method,
                перехват.extension_root,
                перехват.ext_module_path,
                перехват.ext_line,
            ])?;
        }
    }
    tx.commit()?;
    report.extension_overrides = строки.len() as u64;
    Ok(())
}

/// Перехваты одного расширения: обходим его модули и разбираем аннотации.
fn перехваты_расширения(
    ext: &extensions::Extension,
) -> Vec<extensions::Override> {
    let пути = gyrfalcon_parser::scan::collect_modules(&ext.root);
    let mut out = Vec::new();

    for путь in &пути {
        let Ok(raw) = std::fs::read(путь) else {
            continue;
        };
        let raw = raw.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&raw);
        let Ok(source) = std::str::from_utf8(raw) else {
            continue;
        };
        let Ok(разобран) = gyrfalcon_parser::module::parse(source) else {
            continue;
        };
        if разобран.overrides.is_empty() {
            continue;
        }

        let отн = rel_of(&ext.root, путь);
        for перехват in &разобран.overrides {
            out.push(extensions::Override {
                object_name: extensions::object_of_path(&отн),
                // Путь модуля-цели в основной конфигурации совпадает с путём
                // модуля в расширении: выгрузка зеркальная.
                source_path: отн.clone(),
                target_method: перехват.target_method.clone(),
                target_method_line: None,
                annotation: перехват.annotation.clone(),
                extension_name: ext.name.clone(),
                extension_purpose: ext.purpose.clone(),
                extension_method: перехват.method_name.clone(),
                extension_root: ext.root.display().to_string(),
                ext_module_path: отн.clone(),
                ext_line: перехват.line,
            });
        }
    }
    out
}

/// Семантический этап: словарь корпуса, IDF и векторы сущностей.
///
/// # Барьер по корпусу — явный, и это требование вехи
///
/// Разбор и запись метаданных идут по одному файлу за раз, поэтому их можно
/// лить конвейером. Семантика так не умеет: IDF токена — это его
/// распространённость **по всему корпусу**, и посчитать её можно только когда
/// собраны все имена. Барьер здесь не побочный эффект ожидания на общем
/// ресурсе, а объявленная граница фаз:
///
/// 1. собрать имена (уже в базе — методы и объекты метаданных);
/// 2. **барьер**: посчитать частоты и IDF по всему корпусу;
/// 3. посчитать векторы сущностей — снова параллельно.
///
/// Если бы веха стояла последней, этот барьер вскрылся бы на финальном
/// замере скорости. Ровно поэтому её подняли выше.
///
/// # Инференса нет
///
/// Ни на одном пути (решение Р-006). Словарь либо предпосчитан офлайн и лежит
/// в `semantic_dictionary`, либо пуст — тогда всё считается random indexing.
/// Модель во время сборки не зовётся никогда.
fn write_semantic(conn: &mut Connection, report: &mut BuildReport) -> Result<()> {
    use crate::semantic::{Dictionary, VectorSource, DIM};
    use std::collections::HashMap;

    let t = Instant::now();
    let dict = Dictionary::load(conn)?;

    // --- фаза 1: имена сущностей из уже заполненных таблиц ---
    //
    // Читаем из базы, а не из `parsed`: объекты метаданных живут только там,
    // а искать по одним методам значит выбросить половину корпуса имён.
    struct Entity {
        kind: &'static str,
        ref_id: i64,
        name: String,
    }
    let mut entities: Vec<Entity> = Vec::new();
    {
        let mut st = conn.prepare("SELECT id, name FROM methods")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (id, name) = row?;
            entities.push(Entity {
                kind: "method",
                ref_id: id,
                name,
            });
        }
    }
    {
        // Объекты метаданных берутся из `object_synonyms`, и вместе с именем
        // индексируется СИНОНИМ: `ЗаказКлиента` — машинное имя, а «Заказ
        // клиента» — то, как объект называет человек. Вопрос задаётся
        // человеческими словами, поэтому синоним для семантики ценнее имени.
        //
        // Имя таблицы взято из `ddl.rs`, а не по памяти: первый заход искал
        // выдуманную `metadata_objects` и упал на сборке. П. 12 правил
        // в чистом виде — имя объекта без вызова инструмента это гипотеза.
        let mut st = conn.prepare("SELECT id, object_name, synonym FROM object_synonyms")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (id, name, synonym) = row?;
            // Синоним склеивается с именем в одну строку: у вектора сущности
            // тогда есть и машинная форма, и человеческая, а искать можно
            // любой из них. Пустой синоним не портит — токенизация его
            // просто не даст.
            let combined = if synonym.is_empty() {
                name
            } else {
                format!("{name} {synonym}")
            };
            entities.push(Entity {
                kind: "object",
                ref_id: id,
                name: combined,
            });
        }
    }
    report.semantic.names = entities.len() as u64;

    // Токенизация — параллельно, она независима по именам.
    let tokenized: Vec<Vec<String>> = entities
        .par_iter()
        .map(|e| gyrfalcon_parser::tokens::tokenize(&e.name))
        .collect();

    // --- ФАЗА 2: БАРЬЕР. Частоты по всему корпусу ---
    //
    // Здесь нельзя ничего считать по одному имени: df токена — это число
    // имён, где он встретился, то есть свойство корпуса целиком.
    let mut df: HashMap<&str, u64> = HashMap::new();
    for toks in &tokenized {
        let mut уникальные: Vec<&str> = toks.iter().map(|s| s.as_str()).collect();
        уникальные.sort_unstable();
        уникальные.dedup();
        for t in уникальные {
            *df.entry(t).or_default() += 1;
        }
    }
    report.semantic.tokens = df.len() as u64;

    let n = entities.len().max(1) as f64;
    let idf: HashMap<&str, f32> = df
        .iter()
        .map(|(t, d)| {
            // Сглаженный IDF: без сглаживания токен, встреченный во всех
            // именах, дал бы ln(1) = 0 и вектор схлопнулся бы в ноль.
            (*t, ((n + 1.0) / (*d as f64 + 1.0)).ln() as f32)
        })
        .collect();

    // Сколько токенов корпуса накрыл словарь — прямое требование
    // контрольной точки 4. При пустом словаре это честный ноль.
    report.semantic.dict_hits = df
        .keys()
        .filter(|t| matches!(dict.vector(t).1, VectorSource::Dictionary))
        .count() as u64;

    // --- фаза 3: векторы сущностей, снова параллельно ---
    //
    // Вектор имени = взвешенная IDF-сумма векторов его токенов. Взвешивание
    // обязательно: без него `Заполнить` (8 302 имени) весил бы столько же,
    // сколько `Себестоимость`, и все имена сползлись бы к общему центру.
    let vectors: Vec<(usize, Vec<u8>, u64, u64)> = tokenized
        .par_iter()
        .enumerate()
        .filter_map(|(i, toks)| {
            if toks.is_empty() {
                return None;
            }
            // Пути НЕ смешиваются внутри одного вектора (решение Р-014).
            //
            // Замер 28.08.2026: на частично заполненном словаре сложение
            // dense-векторов модели с sparse-хэшами даёт выдачу хуже любого
            // из путей по отдельности — они лежат в разных геометриях, и
            // сумма получается шумом. Поэтому: есть хоть один токен в
            // словаре — имя считается ТОЛЬКО по словарным токенам, остальные
            // пропускаются; нет ни одного — имя целиком уходит в sparse.
            let есть_словарные = toks
                .iter()
                .any(|t| dict.vector(t).1 == VectorSource::Dictionary);

            let mut acc = vec![0f32; DIM];
            let mut из_словаря = 0u64;
            for t in toks {
                let (v, src) = dict.vector(t);
                let словарный = src == VectorSource::Dictionary;
                if словарный {
                    из_словаря += 1;
                } else if есть_словарные {
                    // Незнакомый токен в dense-имени пропускается: подмешать
                    // его значит испортить весь вектор ради одной части.
                    continue;
                }
                let w = idf.get(t.as_str()).copied().unwrap_or(1.0);
                for (k, slot) in acc.iter_mut().enumerate() {
                    *slot += v[k] as f32 * w;
                }
            }
            // Нормируем перед квантованием: без этого длинные имена дали бы
            // большие числа и упёрлись бы в потолок int8, а короткие — в ноль.
            let norm = acc.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm <= f32::EPSILON {
                return None;
            }
            let blob: Vec<u8> = acc
                .iter()
                .map(|x| ((x / norm * 127.0).round().clamp(-127.0, 127.0) as i8) as u8)
                .collect();
            Some((i, blob, из_словаря, toks.len() as u64))
        })
        .collect();

    // --- запись: один поток, как и всё остальное в SQLite ---
    let tx = conn.transaction()?;
    {
        let mut st = tx.prepare(
            "INSERT INTO semantic_tokens(token, df, idf, from_dictionary) VALUES (?1,?2,?3,?4)",
        )?;
        for (t, d) in &df {
            let есть = matches!(dict.vector(t).1, VectorSource::Dictionary) as i64;
            st.execute(rusqlite::params![t, *d as i64, idf[t] as f64, есть])?;
        }
    }
    {
        let mut st = tx.prepare(
            "INSERT INTO semantic_vectors(kind, ref_id, name, vector, dict_tokens, total_tokens)
             VALUES (?1,?2,?3,?4,?5,?6)",
        )?;
        for (i, blob, из_словаря, всего) in &vectors {
            let e = &entities[*i];
            st.execute(rusqlite::params![
                e.kind,
                e.ref_id,
                e.name,
                blob,
                *из_словаря as i64,
                *всего as i64
            ])?;
        }
    }
    tx.commit()?;

    report.semantic.ms = t.elapsed().as_millis() as u64;
    Ok(())
}

/// Скопировать готовый словарь векторов в собираемый индекс.
///
/// Через `ATTACH`, а не построчным чтением: словарь это 25 тысяч блобов
/// по килобайту, и гонять их через прикладной код незачем.
fn скопировать_словарь(conn: &Connection, dict: &Path) -> Result<u64> {
    if !dict.is_file() {
        return Err(IndexError::NoModules(format!(
            "словарь не найден: {}",
            dict.display()
        )));
    }
    conn.execute("ATTACH DATABASE ?1 AS dict", [dict.to_string_lossy()])?;
    let n = conn.execute(
        "INSERT OR REPLACE INTO semantic_dictionary(token, vector, source)
         SELECT token, vector, source FROM dict.semantic_dictionary",
        [],
    )?;
    conn.execute("DETACH DATABASE dict", [])?;
    Ok(n as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Манифест основной конфигурации — без него сборка отказывает.
    pub(crate) fn манифест_основной(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(
            dir.join("Configuration.xml"),
            "<MetaDataObject xmlns=\"http://v8.1c.ru/8.3/MDClasses\"><Configuration>\
             <Properties><Name>Тест</Name></Properties></Configuration></MetaDataObject>",
        )
        .unwrap();
    }

    fn корпус(dir: &Path) {
        манифест_основной(dir);
        let common = dir.join("CommonModules/ОбщегоНазначения/Ext");
        std::fs::create_dir_all(&common).unwrap();
        std::fs::write(
            common.join("Module.bsl"),
            "// Общий модуль.\nФункция ЗначениеРеквизита(С) Экспорт\n\tВозврат С;\nКонецФункции\n",
        )
        .unwrap();

        let obj = dir.join("Catalogs/Товар/Ext");
        std::fs::create_dir_all(&obj).unwrap();
        std::fs::write(
            obj.join("ObjectModule.bsl"),
            "#Область Обработчики\n\
             Процедура ПередЗаписью(Отказ)\n\
             \tОбщегоНазначения.ЗначениеРеквизита(Ссылка);\n\
             \tСвояПроцедура();\n\
             \tЗаголовки.Вставить(\"а\", 1);\n\
             КонецПроцедуры\n\
             Процедура СвояПроцедура()\n\
             КонецПроцедуры\n\
             #КонецОбласти\n",
        )
        .unwrap();
    }

    #[test]
    fn сборка_наполняет_шесть_таблиц() {
        let dir = std::env::temp_dir().join("gyrfalcon-build-test");
        let _ = std::fs::remove_dir_all(&dir);
        корпус(&dir);
        let db = dir.join("index.db");

        let r = build(&dir, &db, None).unwrap();
        assert_eq!(r.modules, 2);
        assert_eq!(r.methods, 3, "два в объекте, один в общем модуле");
        assert_eq!(r.regions, 1);
        assert!(r.calls >= 3, "рёбра: {}", r.calls);

        let conn = Connection::open(&db).unwrap();
        for t in [
            "modules",
            "module_headers",
            "methods",
            "calls",
            "regions",
            "file_paths",
        ] {
            let n: i64 = conn
                .query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
                .unwrap();
            assert!(n > 0, "таблица {t} пуста");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn классы_резолвинга_проставлены() {
        let dir = std::env::temp_dir().join("gyrfalcon-build-res");
        let _ = std::fs::remove_dir_all(&dir);
        корпус(&dir);
        let db = dir.join("index.db");
        let r = build(&dir, &db, None).unwrap();

        // Все три класса встретились: общий модуль, локальный, платформенный.
        assert!(r.stats.common_module >= 1, "{:?}", r.stats);
        assert!(r.stats.local >= 1, "{:?}", r.stats);
        assert!(r.stats.platform_var >= 1, "{:?}", r.stats);

        // Ни одно ребро не осталось без класса.
        let conn = Connection::open(&db).unwrap();
        let без: i64 = conn
            .query_row(
                "SELECT count(*) FROM calls WHERE resolution IS NULL OR resolution=''",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(без, 0, "есть рёбра без класса резолвинга");

        // Доля внутри разрешимого выше голой доли — ровно то, ради чего Р-005.
        assert!(
            r.stats.resolved_share_of_resolvable() > r.stats.resolved_share_raw(),
            "{:?}",
            r.stats
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn записать(p: &Path, текст: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, текст).unwrap();
    }

    /// Справочник в форме выгрузки. `заимствован` — пометки расширения:
    /// у объекта и у каждого реквизита из `чужие`; реквизиты из `свои` — без неё.
    fn справочник(
        имя: &str, заимствован: bool, чужие: &[&str], свои: &[&str]
    ) -> String {
        let метка = |да: bool| {
            if да {
                "<ObjectBelonging>Adopted</ObjectBelonging>"
            } else {
                ""
            }
        };
        let mut реквизиты = String::new();
        for (r, да) in чужие
            .iter()
            .map(|r| (r, true))
            .chain(свои.iter().map(|r| (r, false)))
        {
            реквизиты.push_str(&format!(
                "<Attribute uuid=\"1\"><Properties>{}<Name>{r}</Name></Properties></Attribute>",
                метка(заимствован && да)
            ));
        }
        format!(
            "<MetaDataObject xmlns=\"http://v8.1c.ru/8.3/MDClasses\"><Catalog uuid=\"0\">\
             <Properties>{}<Name>{имя}</Name></Properties>\
             <ChildObjects>{реквизиты}</ChildObjects></Catalog></MetaDataObject>",
            метка(заимствован)
        )
    }

    /// Проект с расширениями соседями `src`: `<проект>/src` и `<проект>/ext/<Имя>`.
    fn проект_с_расширениями(dir: &Path) -> PathBuf {
        let src = dir.join("src");
        корпус(&src);
        записать(
            &src.join("Catalogs/Товар.xml"),
            &справочник("Товар", false, &[], &["Артикул", "Цена"]),
        );

        // Расширение с собственным кодом и заимствованиями, БЕЗ перехватов:
        // до Р-022 его для индекса не существовало вовсе.
        let ext = dir.join("ext/Доработка");
        записать(
            &ext.join("Configuration.xml"),
            "<MetaDataObject xmlns=\"http://v8.1c.ru/8.3/MDClasses\"><Configuration>\
             <Properties><ConfigurationExtensionPurpose>Customization</ConfigurationExtensionPurpose>\
             <NamePrefix>Дор_</NamePrefix></Properties></Configuration></MetaDataObject>",
        );
        // Собственный общий модуль, вызывающий общий модуль основной конфигурации.
        записать(
            &ext.join("CommonModules/Дор_Сервис/Ext/Module.bsl"),
            "Процедура Выполнить() Экспорт\n\tОбщегоНазначения.ЗначениеРеквизита(1);\nКонецПроцедуры\n",
        );
        // Заимствованный общий модуль с тем же именем, что в основной.
        записать(
            &ext.join("CommonModules/ОбщегоНазначения/Ext/Module.bsl"),
            "Процедура Дор_Вспомогательная()\nКонецПроцедуры\n",
        );
        // Заимствованный справочник: один реквизит оригинала + один свой.
        записать(
            &ext.join("Catalogs/Товар.xml"),
            &справочник("Товар", true, &["Артикул"], &["Дор_Поставщик"]),
        );
        src
    }

    #[test]
    fn расширение_индексируется_целиком_без_задвоений() {
        let dir = std::env::temp_dir().join("gyrfalcon-build-ext");
        let _ = std::fs::remove_dir_all(&dir);
        let src = проект_с_расширениями(&dir);
        let db = dir.join("index.db");
        let r = build(&src, &db, None).unwrap();
        let conn = Connection::open(&db).unwrap();
        let число = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };

        // Код расширения — в modules, адрес от src через `../`.
        assert_eq!(r.extension_modules, 2);
        assert_eq!(
            число(
                "SELECT count(*) FROM modules WHERE category='CommonModules'
                   AND rel_path='../ext/Доработка/CommonModules/Дор_Сервис/Ext/Module.bsl'"
            ),
            1,
            "собственный модуль расширения классифицирован по пути внутри своей выгрузки"
        );

        // Вызов из расширения ушёл в модуль ОСНОВНОЙ конфигурации, а не
        // в одноимённый заимствованный.
        let адресат: String = conn
            .query_row(
                "SELECT c.callee_key FROM calls c JOIN methods m ON m.id=c.caller_id
                  WHERE m.name='Выполнить'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            адресат,
            "CommonModules/ОбщегоНазначения/Ext/Module.bsl::значениереквизита"
        );

        // Заимствованный реквизит не задвоен, свой — добавлен.
        let реквизиты = |имя: &str| {
            число(&format!(
                "SELECT count(*) FROM object_attributes WHERE object_name='Товар' AND attr_name='{имя}'"
            ))
        };
        assert_eq!(
            реквизиты("Артикул"),
            1,
            "заимствованный реквизит раздвоился"
        );
        assert_eq!(
            реквизиты("Дор_Поставщик"),
            1,
            "свой реквизит расширения потерян"
        );
        assert_eq!(
            число("SELECT count(*) FROM object_synonyms WHERE object_name='Товар'"),
            число("SELECT count(*) FROM object_synonyms WHERE object_name='Товар' AND file NOT LIKE '../%'"),
            "заимствованный объект не должен давать второй строки синонима"
        );

        // Расширение без перехватов — в реестре; состав с принадлежностью.
        assert_eq!(
            число("SELECT count(*) FROM extensions WHERE name='Доработка'"),
            1
        );
        assert_eq!(
            число(
                "SELECT count(*) FROM extension_objects
                  WHERE object_name='Товар' AND belonging='adopted'"
            ),
            1
        );
        assert!(r.extension_duplicates >= 1, "{r:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn без_расширений_сборка_прежняя() {
        // Конфигурация без `ext/` обязана собираться ровно как до Р-022:
        // ни лишних модулей, ни строк в таблицах расширений.
        let dir = std::env::temp_dir().join("gyrfalcon-build-noext");
        let _ = std::fs::remove_dir_all(&dir);
        корпус(&dir);
        let db = dir.join("index.db");
        let r = build(&dir, &db, None).unwrap();
        assert_eq!((r.modules, r.extension_modules, r.extensions), (2, 0, 0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn пустой_каталог_даёт_отказ_а_не_пустой_индекс() {
        // Правило заглушек: пустой результат неотличим от «нечего индексировать».
        let dir = std::env::temp_dir().join("gyrfalcon-build-empty");
        let _ = std::fs::remove_dir_all(&dir);
        манифест_основной(&dir);
        let e = build(&dir, &dir.join("i.db"), None);
        assert!(matches!(e, Err(IndexError::NoModules(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn каталог_без_манифеста_даёт_отказ_даже_с_модулями() {
        // Не тот каталог (родитель выгрузки, недовыгрузка) — отказ сразу:
        // индекс из нулей неотличим от ответа «такого нет».
        let dir = std::env::temp_dir().join("gyrfalcon-build-nomanifest");
        let _ = std::fs::remove_dir_all(&dir);
        корпус(&dir);
        std::fs::remove_file(dir.join("Configuration.xml")).unwrap();
        let e = build(&dir, &dir.join("i.db"), None);
        assert!(matches!(e, Err(IndexError::NoConfiguration(_))), "{e:?}");
        assert!(!dir.join("i.db").exists(), "индекс не создан");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Проект с ОДНИМ расширением в `cfe/`: каталог сам и есть его выгрузка.
    #[test]
    fn одно_расширение_в_cfe_индексируется() {
        let dir = std::env::temp_dir().join("gyrfalcon-build-cfe-single");
        let _ = std::fs::remove_dir_all(&dir);
        let src = dir.join("src");
        корпус(&src);
        записать(
            &src.join("Catalogs/Товар.xml"),
            &справочник("Товар", false, &[], &["Артикул"]),
        );
        let ext = dir.join("cfe");
        записать(
            &ext.join("Configuration.xml"),
            "<MetaDataObject xmlns=\"http://v8.1c.ru/8.3/MDClasses\"><Configuration>\
             <Properties><Name>СвоёРасширение</Name>\
             <ConfigurationExtensionPurpose>Customization</ConfigurationExtensionPurpose>\
             <NamePrefix>Св_</NamePrefix></Properties></Configuration></MetaDataObject>",
        );
        записать(
            &ext.join("CommonModules/Св_Сервис/Ext/Module.bsl"),
            "Процедура Выполнить() Экспорт\n\tОбщегоНазначения.ЗначениеРеквизита(1);\nКонецПроцедуры\n",
        );
        записать(
            &ext.join("CommonModules/ОбщегоНазначения/Ext/Module.bsl"),
            "&После(\"ЗначениеРеквизита\")\nПроцедура Св_ЗначениеРеквизита(С)\nКонецПроцедуры\n",
        );
        записать(
            &ext.join("Catalogs/Товар.xml"),
            &справочник("Товар", true, &["Артикул"], &["Св_Поставщик"]),
        );

        let db = dir.join("index.db");
        let r = build(&src, &db, None).unwrap();
        let conn = Connection::open(&db).unwrap();
        let число = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        let строка = |sql: &str| -> String { conn.query_row(sql, [], |r| r.get(0)).unwrap() };

        assert_eq!((r.extensions, r.extension_modules), (1, 2));
        assert_eq!(
            строка("SELECT name || '|' || rel_root FROM extensions"),
            "СвоёРасширение|../cfe"
        );
        assert_eq!(
            число(
                "SELECT count(*) FROM modules WHERE category='CommonModules'
                   AND rel_path='../cfe/CommonModules/Св_Сервис/Ext/Module.bsl'"
            ),
            1,
            "модуль классифицирован по пути внутри `cfe`, а не как категория `..`"
        );
        assert_eq!(
            строка(
                "SELECT group_concat(extension_name || ':' || object_name || ':' || belonging, ',')
                 FROM (SELECT * FROM extension_objects ORDER BY object_name)"
            ),
            "СвоёРасширение:Товар:adopted",
            "состав расширения записан под его именем"
        );
        assert_eq!(
            строка(
                "SELECT extension_name || ':' || target_method || ':' || annotation
                 FROM extension_overrides"
            ),
            "СвоёРасширение:ЗначениеРеквизита:После"
        );
        assert_eq!(
            число("SELECT count(*) FROM extension_overrides WHERE target_method_line IS NOT NULL"),
            1,
            "цель перехвата разрешена в основной конфигурации"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn повторная_сборка_справки_инкрементальна_и_не_блокирует_код() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "gyrfalcon-build-help-incremental-{}-{nonce}",
            std::process::id()
        ));
        корпус(&dir);
        let help_dir = dir.join("Catalogs/Товар/Ext/Help");
        std::fs::create_dir_all(&help_dir).unwrap();
        let first = help_dir.join("ru.html");
        let second = help_dir.join("en.html");
        std::fs::write(
            &first,
            "<h1>Товар</h1><p>Исходная инструкция по заполнению карточки товара.</p>",
        )
        .unwrap();
        let db = dir.join("index.db");
        let r = build(&dir, &db, None).unwrap();
        assert_eq!((r.help.added, r.help.parsed), (1, 1));
        let r = build(&dir, &db, None).unwrap();
        assert_eq!((r.help.unchanged, r.help.parsed, r.help.added), (1, 0, 0));
        std::fs::write(
            &first,
            "<h1>Товар</h1><p>Изменённая инструкция по заполнению карточки товара.</p>",
        )
        .unwrap();
        std::fs::write(
            &second,
            "<h1>Product</h1><p>Additional instructions for filling in a product card.</p>",
        )
        .unwrap();
        let r = build(&dir, &db, None).unwrap();
        assert_eq!((r.help.parsed, r.help.updated, r.help.added), (2, 1, 1));
        std::fs::remove_file(&second).unwrap();
        let r = build(&dir, &db, None).unwrap();
        assert_eq!((r.help.parsed, r.help.removed, r.help.unchanged), (0, 1, 1));
        // Ошибка необязательной справки не делает индекс кода непригодным.
        std::fs::write(&first, [0xff, 0xfe, 0xfd]).unwrap();
        let r = build(&dir, &db, None).unwrap();
        assert_eq!(r.modules, 2);
        assert!(r.help_error.is_some());
        let conn = Connection::open(&db).unwrap();
        let modules: i64 = conn
            .query_row("SELECT count(*) FROM modules", [], |r| r.get(0))
            .unwrap();
        assert_eq!(modules, 2);
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
