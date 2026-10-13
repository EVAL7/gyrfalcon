//! Узкий индекс официального синтакс-помощника платформы 1С.
//!
//! Источник — локальный `shcntx_ru.hbk` той версии платформы, которая
//! установлена на машине. Наружу выходят только точные страницы API:
//! синтаксис, краткое описание, доступность и короткий пример. Полные HTML
//! и слабые «лучшие из плохих» совпадения не возвращаются.

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const MAX_SECTION: usize = 800;
const MIN_TERM_MATCHES: usize = 2;
const TARGET_SCORE_WINDOW: usize = 20;
/// 3 — страницы типов и английские имена (MCP-06). Кэш младшей схемы их не
/// знает, а без смены схемы считался бы актуальным для неизменной справки:
/// `name_en` прочитался бы пустым через `serde(default)` — молча.
const CACHE_SCHEMA: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Item {
    title: String,
    owner: String,
    name: String,
    kind: String,
    syntax: String,
    description: String,
    availability: String,
    example: String,
    path: String,
    /// Английское имя из заголовка: «Запрос (Query)» → `Query`,
    /// «Структура.Вставить (Structure.Insert)» → `Insert`. Код на английском
    /// встречается в типовых (ERP 13.10.2026: `QueryResultIteration`,
    /// `Metadata`, `ThisForm` — 37 ложных тревог без этого поля).
    #[serde(default)]
    name_en: String,
}

#[derive(Debug)]
struct Catalog {
    source: PathBuf,
    version: String,
    items: Vec<Item>,
    cache_path: PathBuf,
    cache_hit: bool,
    cache_bytes: u64,
    source_bytes: u64,
    load_ms: u128,
    cache_warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SourceIdentity {
    schema: u32,
    path: String,
    version: String,
    size: u64,
    modified_ns: u128,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CachePayload {
    identity: SourceIdentity,
    items: Vec<Item>,
}

static CATALOG: OnceLock<Result<Catalog, String>> = OnceLock::new();

/// Подсказки из официальной локальной справки платформы.
pub fn suggest(task: &str, source: &str, cursor: Option<&Value>, limit: usize) -> Value {
    let catalog = match CATALOG.get_or_init(load_catalog) {
        Ok(c) => c,
        Err(e) => {
            return json!({
                "available": false,
                "items": [],
                "completions": [],
                "reason": e,
            })
        }
    };

    let terms = stems(task);
    let task_low = task.to_lowercase();
    // Страницы типов нужны проверке контекста (`check_bsl`), а не подсказке:
    // синтаксиса у них нет, и в выдаче они вытеснили бы методы описаниями.
    let api = || catalog.items.iter().filter(|i| i.kind != "type");
    let has_exact_title = api().any(|item| {
        let title = item.title.to_lowercase();
        task_low.contains(&title) || title.contains(&task_low)
    });
    let owners: HashSet<String> = api().map(|item| item.owner.clone()).collect();
    let target_owners = select_target_owners(owners.iter().map(String::as_str), task, &terms);
    let mut ranked: Vec<(usize, &Item)> = api()
        .filter_map(|item| {
            if !target_owners.is_empty() && !target_owners.contains(&item.owner.to_lowercase()) {
                return None;
            }
            let title = item.title.to_lowercase();
            let exact = task_low.contains(&title) || title.contains(&task_low);
            if has_exact_title && !exact {
                return None;
            }
            let content = format!(
                "{} {} {}",
                item.name.to_lowercase(),
                item.description.to_lowercase(),
                item.syntax.to_lowercase()
            );
            let hay = format!("{} {}", title, content);
            let matched = terms.iter().filter(|t| hay.contains(t.as_str())).count();
            let owner_terms = camel_stems(&item.owner);
            let intent_terms: Vec<_> = terms.iter().filter(|t| !owner_terms.contains(t)).collect();
            let intent_matched = intent_terms
                .iter()
                .filter(|t| content.contains(t.as_str()))
                .count();
            let intent_required = intent_terms.len().min(MIN_TERM_MATCHES);
            if !exact
                && (matched < MIN_TERM_MATCHES
                    || (!target_owners.is_empty() && intent_matched < intent_required))
            {
                return None;
            }
            let title_hits = terms.iter().filter(|t| title.contains(t.as_str())).count();
            // Короткое имя типа, названное пользователем, важнее длинного
            // составного типа, случайно вобравшего те же слова. Например,
            // «добавить элемент в структуру» должно вести к `Структура`, а
            // не к `КоллекцияЭлементовСтруктурыДиаграммыКомпоновкиДанных`.
            let exact_owner = target_owners.contains(&item.owner.to_lowercase());
            let length_penalty = item.title.chars().count().min(200);
            Some((
                usize::from(exact) * 10_000
                    + usize::from(exact_owner) * 2_000
                    + matched * 100
                    + title_hits * 50
                    - length_penalty,
                item,
            ))
        })
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.title.cmp(&b.1.title)));
    if !target_owners.is_empty() {
        let best = ranked.first().map(|(score, _)| *score).unwrap_or(0);
        ranked.retain(|(score, _)| score.saturating_add(TARGET_SCORE_WINDOW) >= best);
    }

    let mut seen = HashSet::new();
    let items: Vec<Value> = ranked
        .into_iter()
        .filter(|(_, i)| seen.insert(i.title.to_lowercase()))
        .take(limit)
        .map(|(score, i)| {
            json!({
                "title": i.title,
                "kind": i.kind,
                "syntax": i.syntax,
                "description": i.description,
                "availability": i.availability,
                "example": i.example,
                "score": score,
                "source_page": i.path,
            })
        })
        .collect();

    let prefix = cursor_prefix(source, cursor);
    let completions: Vec<Value> = prefix
        .as_deref()
        .and_then(|p| p.rsplit_once('.').map(|(owner, name)| (p, owner, name)))
        .map(|(whole, owner, name)| {
            let owner = owner.to_lowercase();
            let name = name.to_lowercase();
            api()
                .filter(|i| {
                    i.owner.to_lowercase() == owner && i.name.to_lowercase().starts_with(&name)
                })
                .take(limit)
                .map(|i| {
                    json!({
                        "replace": whole,
                        "with": i.title,
                        "syntax": i.syntax,
                        "kind": i.kind,
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let methods = catalog.items.iter().filter(|i| i.kind == "method").count();
    let properties = catalog
        .items
        .iter()
        .filter(|i| i.kind == "property")
        .count();
    let constructors = catalog
        .items
        .iter()
        .filter(|i| i.kind == "constructor")
        .count();
    let events = catalog.items.iter().filter(|i| i.kind == "event").count();
    let types = catalog.items.iter().filter(|i| i.kind == "type").count();
    let mut target_owner_list: Vec<&str> = target_owners.iter().map(String::as_str).collect();
    target_owner_list.sort();
    json!({
        "available": true,
        "version": catalog.version,
        "source": catalog.source,
        "cache": {
            "hit": catalog.cache_hit,
            "path": catalog.cache_path,
            "source_bytes": catalog.source_bytes,
            "compressed_bytes": catalog.cache_bytes,
            "load_ms": catalog.load_ms,
            "warning": catalog.cache_warning,
        },
        "target_owners": target_owner_list,
        "catalog_items": catalog.items.len(),
        "catalog_by_kind": {
            "methods": methods,
            "properties": properties,
            "constructors": constructors,
            "events": events,
            "types": types,
        },
        "items": items,
        "completions": completions,
        "no_reliable_suggestions": items.is_empty() && completions.is_empty(),
        "note": "Источник — локальный официальный shcntx_ru.hbk. Возвращаются только точное имя либо совпадение минимум по двум значимым основам слов; слабые результаты скрыты."
    })
}

/// Доступен ли элемент платформы на тонком клиенте — по разделу «Доступность».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnThinClient {
    Yes,
    No,
    /// Раздел пуст: справка молчит, и проверка обязана молчать вместе с ней.
    Unknown,
}

impl OnThinClient {
    fn of(availability: &str) -> Self {
        if availability.trim().is_empty() {
            OnThinClient::Unknown
        } else if availability.to_lowercase().contains("тонкий клиент") {
            OnThinClient::Yes
        } else {
            OnThinClient::No
        }
    }
}

/// Сведения справки, нужные проверке контекста исполнения (`check_bsl`).
///
/// Отдельно от подсказок: тем нужен поиск по смыслу, здесь — точный ответ
/// по имени. Имена хранятся в нижнем регистре: BSL к регистру безразличен.
#[derive(Debug, Default)]
pub struct PlatformContext {
    types: HashMap<String, (String, OnThinClient)>,
    global_methods: HashMap<String, (String, OnThinClient)>,
    global_props: HashMap<String, (String, OnThinClient)>,
    /// Имена свойств ВСЕХ типов платформы. В модуле формы или объекта
    /// свойства владельца — голые имена (`Элементы`, `Ссылка`, `Модифицированность`),
    /// и без этого множества каждое из них выглядело бы неопределённой переменной.
    member_props: HashSet<String>,
}

/// Владелец глобальных методов и свойств в справке 8.3.
const GLOBAL_OWNER: &str = "глобальный контекст";

impl PlatformContext {
    fn from_items(items: &[Item]) -> Self {
        let mut c = PlatformContext::default();
        // Каждая страница регистрируется под обоими именами: код на английском
        // законен так же, как на русском.
        let имена = |i: &Item| {
            let mut v = vec![i.name.to_lowercase()];
            if !i.name_en.is_empty() {
                v.push(i.name_en.to_lowercase());
            }
            v
        };
        for i in items {
            for name in имена(i) {
                c.add(i, name);
            }
        }
        c
    }

    fn add(&mut self, i: &Item, name: String) {
        let entry = (i.title.clone(), OnThinClient::of(&i.availability));
        match i.kind.as_str() {
            "type" => {
                // Тип с двумя одноимёнными страницами (редкость) — берём
                // более строгую: ложное «доступно» хуже ложного молчания.
                self.types
                    .entry(name)
                    .and_modify(|e| {
                        if entry.1 == OnThinClient::No {
                            *e = entry.clone();
                        }
                    })
                    .or_insert(entry);
            }
            "method" if i.owner.to_lowercase() == GLOBAL_OWNER => {
                self.global_methods.insert(name, entry);
            }
            "property" if i.owner.to_lowercase() == GLOBAL_OWNER => {
                self.global_props.insert(name, entry);
            }
            "property" => {
                self.member_props.insert(name);
            }
            _ => {}
        }
    }

    /// Тип для `Новый X`: (заголовок страницы, доступность). `None` — такого
    /// типа справка не знает (например, тип конфигурации).
    pub fn new_type(&self, name: &str) -> Option<&(String, OnThinClient)> {
        self.types.get(&name.to_lowercase())
    }

    pub fn global_method(&self, name: &str) -> Option<&(String, OnThinClient)> {
        self.global_methods.get(&name.to_lowercase())
    }

    pub fn global_property(&self, name: &str) -> Option<&(String, OnThinClient)> {
        self.global_props.get(&name.to_lowercase())
    }

    /// Законно ли имя как голый идентификатор с точки зрения платформы:
    /// глобальное свойство, имя типа (системные перечисления пишутся так —
    /// `РежимДиалогаВопрос.ДаНет`) или свойство владельца модуля.
    pub fn is_known_name(&self, name: &str) -> bool {
        let n = name.to_lowercase();
        self.global_props.contains_key(&n)
            || self.types.contains_key(&n)
            || self.member_props.contains(&n)
    }

    pub fn is_empty(&self) -> bool {
        self.types.is_empty() && self.global_methods.is_empty()
    }
}

static CONTEXT: OnceLock<Result<PlatformContext, String>> = OnceLock::new();

/// Сведения о контексте из локальной справки платформы — один раз на процесс.
pub fn context() -> Result<&'static PlatformContext, String> {
    CONTEXT
        .get_or_init(|| {
            let catalog = CATALOG
                .get_or_init(load_catalog)
                .as_ref()
                .map_err(Clone::clone)?;
            Ok(PlatformContext::from_items(&catalog.items))
        })
        .as_ref()
        .map_err(Clone::clone)
}

#[cfg(test)]
pub(crate) fn context_from_pages(pages: &[(&str, &str)]) -> PlatformContext {
    let items: Vec<Item> = pages
        .iter()
        .filter_map(|(path, html)| parse_page(path, html))
        .collect();
    PlatformContext::from_items(&items)
}

fn select_target_owners<'a>(
    owners: impl Iterator<Item = &'a str>,
    task: &str,
    terms: &[String],
) -> HashSet<String> {
    let owners: Vec<&str> = owners.collect();
    let task_compact = compact_name(task);
    let exact: Vec<(usize, String)> = if task.contains('.') {
        owners
            .iter()
            .filter_map(|owner| {
                let compact = compact_name(owner);
                (compact.chars().count() >= 4 && task_compact.contains(&compact))
                    .then(|| (compact.chars().count(), owner.to_lowercase()))
            })
            .collect()
    } else {
        Vec::new()
    };
    if let Some(longest) = exact.iter().map(|(length, _)| *length).max() {
        return exact
            .into_iter()
            .filter_map(|(length, owner)| (length == longest).then_some(owner))
            .collect();
    }

    // В вопросе о событии слова «поле» и «форма» описывают контекст, но не
    // обязательно точный тип-владелец. Сужение по ним прячет специализации.
    if terms.iter().any(|term| term == "событ") {
        return HashSet::new();
    }

    let fuzzy: Vec<(usize, usize, String)> = owners
        .iter()
        .filter_map(|owner| {
            let owner_terms = camel_stems(owner);
            if owner_terms.is_empty() || !owner_terms.iter().all(|term| terms.contains(term)) {
                return None;
            }
            let last_position = owner_terms
                .iter()
                .filter_map(|owner_term| terms.iter().position(|term| term == owner_term))
                .max()?;
            Some((owner_terms.len(), last_position, owner.to_lowercase()))
        })
        .collect();
    let shortest = fuzzy.iter().map(|(count, _, _)| *count).min();
    let latest = fuzzy
        .iter()
        .filter(|(count, _, _)| Some(*count) == shortest)
        .map(|(_, position, _)| *position)
        .max();
    fuzzy
        .into_iter()
        .filter_map(|(count, position, owner)| {
            (Some(count) == shortest && Some(position) == latest).then_some(owner)
        })
        .collect()
}

fn load_catalog() -> Result<Catalog, String> {
    let started = Instant::now();
    let source = locate_hbk().ok_or(
        "не найден shcntx_ru.hbk; задайте GYRFALCON_PLATFORM_BIN каталогом bin установленной платформы 1С",
    )?;
    let version = source
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(|s| s.to_str())
        .unwrap_or("unknown")
        .to_string();
    let bytes = fs::read(&source).map_err(|e| format!("не прочитан {}: {e}", source.display()))?;
    let identity = source_identity(&source, &version, &bytes)?;
    let cache_path = cache_file_path(&identity);
    let (items, cache_hit, cache_warning) = load_or_create_cache(&cache_path, &identity, || {
        let storage = extract_entity(&bytes, "FileStorage")?;
        let mut zip = zip::ZipArchive::new(Cursor::new(storage))
            .map_err(|e| format!("FileStorage в {} не является ZIP: {e}", source.display()))?;
        let mut items = Vec::new();
        for index in 0..zip.len() {
            let mut file = zip.by_index(index).map_err(|e| e.to_string())?;
            let path = file.name().replace('\\', "/");
            if !path.ends_with(".html") || !interesting_path(&path) {
                continue;
            }
            let mut html = String::new();
            file.read_to_string(&mut html)
                .map_err(|e| format!("не прочитана страница {path}: {e}"))?;
            if let Some(item) = parse_page(&path, &html) {
                items.push(item);
            }
        }
        if items.is_empty() {
            return Err(format!(
                "в {} не найдено ни одной страницы API",
                source.display()
            ));
        }
        Ok(items)
    })?;
    Ok(Catalog {
        source,
        version,
        items,
        cache_bytes: fs::metadata(&cache_path).map(|m| m.len()).unwrap_or(0),
        cache_path,
        cache_hit,
        source_bytes: bytes.len() as u64,
        load_ms: started.elapsed().as_millis(),
        cache_warning,
    })
}

fn source_identity(source: &Path, version: &str, bytes: &[u8]) -> Result<SourceIdentity, String> {
    let metadata = fs::metadata(source)
        .map_err(|e| format!("не прочитаны свойства {}: {e}", source.display()))?;
    let canonical = source
        .canonicalize()
        .unwrap_or_else(|_| source.to_path_buf());
    let modified_ns = metadata
        .modified()
        .unwrap_or(SystemTime::UNIX_EPOCH)
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    Ok(SourceIdentity {
        schema: CACHE_SCHEMA,
        path: canonical.to_string_lossy().to_string(),
        version: version.to_string(),
        size: metadata.len(),
        modified_ns,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    })
}

fn cache_file_path(identity: &SourceIdentity) -> PathBuf {
    let path_hash = format!("{:x}", Sha256::digest(identity.path.as_bytes()));
    let name = format!(
        "platform-help-v{}-{}-{}.zip",
        CACHE_SCHEMA,
        &path_hash[..16],
        &identity.sha256[..16]
    );
    cache_dir().join(name)
}

fn cache_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("GYRFALCON_CACHE_DIR") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(path).join("Gyrfalcon").join("cache");
    }
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(path).join("gyrfalcon");
    }
    if let Some(path) = std::env::var_os("HOME") {
        return PathBuf::from(path).join(".cache").join("gyrfalcon");
    }
    std::env::temp_dir().join("gyrfalcon-cache")
}

fn read_cache(path: &Path, identity: &SourceIdentity) -> Result<Vec<Item>, String> {
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    let entry = zip.by_name("catalog.json").map_err(|e| e.to_string())?;
    let payload: CachePayload = serde_json::from_reader(entry).map_err(|e| e.to_string())?;
    if payload.identity != *identity {
        return Err("отпечаток справки изменился".to_string());
    }
    if payload.items.is_empty() {
        return Err("кэш справки пуст".to_string());
    }
    Ok(payload.items)
}

fn load_or_create_cache<F>(
    path: &Path,
    identity: &SourceIdentity,
    create: F,
) -> Result<(Vec<Item>, bool, Option<String>), String>
where
    F: FnOnce() -> Result<Vec<Item>, String>,
{
    if let Ok(items) = read_cache(path, identity) {
        return Ok((items, true, None));
    }
    let items = create()?;
    let warning = write_cache(path, identity, &items).err();
    Ok((items, false, warning))
}

fn write_cache(path: &Path, identity: &SourceIdentity, items: &[Item]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or("у пути кэша нет родительского каталога")?;
    fs::create_dir_all(parent).map_err(|e| format!("не создан каталог кэша: {e}"))?;
    let cursor = Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("catalog.json", options)
        .map_err(|e| format!("не начат кэш справки: {e}"))?;
    let payload = CachePayload {
        identity: identity.clone(),
        items: items.to_vec(),
    };
    serde_json::to_writer(&mut zip, &payload)
        .map_err(|e| format!("не записан кэш справки: {e}"))?;
    zip.flush()
        .map_err(|e| format!("не сброшен кэш справки: {e}"))?;
    let data = zip
        .finish()
        .map_err(|e| format!("не завершён кэш справки: {e}"))?
        .into_inner();
    let temporary = path.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&temporary, data).map_err(|e| format!("не записан временный кэш: {e}"))?;
    match fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(_) if read_cache(path, identity).is_ok() => {
            let _ = fs::remove_file(&temporary);
            Ok(())
        }
        Err(first) => {
            let _ = fs::remove_file(path);
            fs::rename(&temporary, path)
                .map_err(|second| format!("не установлен кэш справки: {first}; повтор: {second}"))
        }
    }
}

fn interesting_path(path: &str) -> bool {
    path.contains("/methods/")
        || path.contains("/properties/")
        || path.contains("/ctors/")
        || path.contains("/events/")
        || is_type_page(path)
}

/// Страница самого типа: `objects/…/Query.html`.
///
/// Доступность ТИПА записана только здесь, а не на странице конструктора:
/// замер по 8.3.27 (13.10.2026) — у всех 444 конструкторов раздел пуст, у
/// 2417 страниц-типов заполнен. Без этих страниц `Новый Запрос` на клиенте
/// не отличить от `Новый Массив`. Страницы-оглавления (`…/catalog393.html`)
/// и служебные разделы (`formparams`) отсекаются в `parse_page` отсутствием
/// раздела «Доступность».
fn is_type_page(path: &str) -> bool {
    if !path.starts_with("objects/") {
        return false;
    }
    let stem = path
        .rsplit('/')
        .next()
        .and_then(|f| f.strip_suffix(".html"))
        .unwrap_or("");
    let catalog = stem
        .strip_prefix("catalog")
        .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
    !catalog && !path.contains("/formparams/")
}

/// Английское имя из заголовка «Русское (English.Name)» — последний сегмент.
fn english_name(title: &str) -> String {
    title
        .rsplit_once(" (")
        .and_then(|(_, en)| en.strip_suffix(')'))
        .map(|en| en.rsplit('.').next().unwrap_or(en).trim().to_string())
        .unwrap_or_default()
}

fn parse_page(path: &str, html: &str) -> Option<Item> {
    let title = tag_text(html, "<h1 class=\"V8SH_pagetitle\">")?;
    let name_en = english_name(&title);
    let russian_title = title
        .split_once(" (")
        .map(|(ru, _)| ru)
        .unwrap_or(&title)
        .trim()
        .to_string();
    // Тип не делится на владельца и имя: `ДокументОбъект.<Имя документа>` —
    // это одно имя типа, а не член `ДокументОбъект`.
    if !path.contains("/methods/")
        && !path.contains("/properties/")
        && !path.contains("/ctors/")
        && !path.contains("/events/")
    {
        let availability = section(html, "Доступность");
        if availability.is_empty() {
            return None;
        }
        return Some(Item {
            title: russian_title.clone(),
            owner: String::new(),
            name: russian_title,
            kind: "type".to_string(),
            syntax: String::new(),
            description: section(html, "Описание"),
            availability,
            example: String::new(),
            path: path.to_string(),
            name_en,
        });
    }
    let (owner, name) = russian_title
        .rsplit_once('.')
        .map(|(o, n)| (o.to_string(), n.to_string()))
        .unwrap_or_else(|| (String::new(), russian_title.clone()));
    let kind = if path.contains("/methods/") {
        "method"
    } else if path.contains("/properties/") {
        "property"
    } else if path.contains("/ctors/") {
        "constructor"
    } else {
        "event"
    };
    Some(Item {
        title: russian_title,
        owner,
        name,
        kind: kind.to_string(),
        syntax: section(html, "Синтаксис"),
        description: section(html, "Описание"),
        availability: section(html, "Доступность"),
        example: section(html, "Пример"),
        path: path.to_string(),
        name_en,
    })
}

fn tag_text(html: &str, marker: &str) -> Option<String> {
    let tail = html.split_once(marker)?.1;
    let raw = tail.split_once("</h1>")?.0;
    Some(clean_html(raw))
}

fn section(html: &str, name: &str) -> String {
    let marker = "<p class=\"V8SH_chapter\">";
    for block in html.split(marker).skip(1) {
        let Some((heading, tail)) = block.split_once("</p>") else {
            continue;
        };
        if clean_html(heading).trim().trim_end_matches(':').trim() != name {
            continue;
        }
        let raw = tail.split(marker).next().unwrap_or(tail);
        return clean_html(raw).chars().take(MAX_SECTION).collect();
    }
    String::new()
}

fn clean_html(raw: &str) -> String {
    static BREAKS: OnceLock<Regex> = OnceLock::new();
    static TAGS: OnceLock<Regex> = OnceLock::new();
    static SPACES: OnceLock<Regex> = OnceLock::new();
    let breaks = BREAKS.get_or_init(|| Regex::new("(?i)<br\\s*/?>|</p>|</li>|</tr>").unwrap());
    let tags = TAGS.get_or_init(|| Regex::new("(?s)<[^>]+>").unwrap());
    let spaces = SPACES.get_or_init(|| Regex::new(r"[ \t\r\n]+").unwrap());
    let with_breaks = breaks.replace_all(raw, "\n");
    let no_tags = tags.replace_all(&with_breaks, "");
    let decoded = no_tags
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .replace("&quot;", "\"")
        .replace("&amp;", "&");
    // Отдельные строки справки не нужны: компактная выдача полезнее верстки.
    spaces.replace_all(decoded.trim(), " ").to_string()
}

fn extract_entity(bytes: &[u8], wanted: &str) -> Result<Vec<u8>, String> {
    let mut pos = 18usize;
    let payload = hex_len(bytes, &mut pos)?;
    let block = hex_len(bytes, &mut pos)?;
    pos = pos.checked_add(11).ok_or("переполнение позиции HBK")?;
    let end = pos.checked_add(payload).ok_or("переполнение таблицы HBK")?;
    let infos = bytes.get(pos..end).ok_or("обрезана таблица файлов HBK")?;
    // `block` читается для проверки заголовка: таблица должна умещаться в блок.
    if block < payload {
        return Err("некорректный HBK: блок таблицы меньше полезных данных".into());
    }
    for info in infos.chunks_exact(12) {
        let header = u32::from_le_bytes(info[0..4].try_into().unwrap()) as usize;
        let body = u32::from_le_bytes(info[4..8].try_into().unwrap()) as usize;
        let reserved = u32::from_le_bytes(info[8..12].try_into().unwrap());
        if reserved != i32::MAX as u32 {
            continue;
        }
        let mut hp = header.checked_add(2).ok_or("переполнение адреса HBK")?;
        let name_payload = hex_len(bytes, &mut hp)?;
        hp = hp.checked_add(40).ok_or("переполнение заголовка HBK")?;
        let name_len = name_payload
            .checked_sub(24)
            .ok_or("некорректная длина имени HBK")?;
        let name_bytes = bytes
            .get(hp..hp + name_len)
            .ok_or("обрезано имя файла HBK")?;
        let utf16: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        let name = String::from_utf16_lossy(&utf16);
        if name != wanted {
            continue;
        }
        let mut bp = body.checked_add(2).ok_or("переполнение тела HBK")?;
        let body_len = hex_len(bytes, &mut bp)?;
        bp = bp
            .checked_add(20)
            .ok_or("переполнение заголовка тела HBK")?;
        return bytes
            .get(bp..bp + body_len)
            .map(|b| b.to_vec())
            .ok_or_else(|| "обрезано тело FileStorage в HBK".to_string());
    }
    Err(format!("в HBK не найден {wanted}"))
}

fn hex_len(bytes: &[u8], pos: &mut usize) -> Result<usize, String> {
    let text = bytes
        .get(*pos..*pos + 8)
        .ok_or("обрезано шестнадцатеричное поле HBK")?;
    *pos += 9; // восемь цифр и разделитель
    let text = std::str::from_utf8(text).map_err(|_| "длина HBK не ASCII")?;
    usize::from_str_radix(text, 16).map_err(|_| format!("неверная длина HBK: {text}"))
}

fn locate_hbk() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("GYRFALCON_PLATFORM_BIN") {
        let path = PathBuf::from(path);
        let file = if path.is_file() {
            path
        } else {
            path.join("shcntx_ru.hbk")
        };
        if file.is_file() {
            return Some(file);
        }
    }

    let mut candidates = Vec::new();
    for env_name in ["ProgramFiles", "ProgramFiles(x86)"] {
        let Some(base) = std::env::var_os(env_name) else {
            continue;
        };
        let root = PathBuf::from(base).join("1cv8");
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path().join("bin").join("shcntx_ru.hbk");
            if path.is_file() {
                candidates.push(path);
            }
        }
    }
    candidates.sort_by_key(|p| {
        p.parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .map(|s| version_key(&s.to_string_lossy()))
            .unwrap_or_default()
    });
    candidates.pop()
}

fn version_key(version: &str) -> Vec<u32> {
    version
        .split('.')
        .map(|p| p.parse::<u32>().unwrap_or(0))
        .collect()
}

fn stems(text: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "для",
        "как",
        "при",
        "или",
        "это",
        "что",
        "код",
        "нужно",
        "надо",
        "через",
        "получить",
    ];
    let mut out = Vec::new();
    for word in text.split(|c: char| !c.is_alphanumeric() && c != '_') {
        let lower = word.to_lowercase();
        if lower.chars().count() < 4 || STOP.contains(&lower.as_str()) {
            continue;
        }
        let has_internal_upper = word.chars().skip(1).any(char::is_uppercase);
        let word_stems = if has_internal_upper || word.contains('_') {
            camel_stems(word)
        } else {
            vec![lower.chars().take(5).collect()]
        };
        for stem in word_stems {
            if !out.contains(&stem) {
                out.push(stem);
            }
        }
    }
    out
}

fn compact_name(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn camel_stems(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = text.chars().collect();
    for (index, ch) in chars.iter().copied().enumerate() {
        if !ch.is_alphanumeric() && ch != '_' {
            if !current.is_empty() {
                words.push(current);
                current = String::new();
            }
            continue;
        }
        let prev = index.checked_sub(1).and_then(|i| chars.get(i)).copied();
        let next = chars.get(index + 1).copied();
        let boundary = ch.is_uppercase()
            && !current.is_empty()
            && (prev.is_some_and(char::is_lowercase)
                || (prev.is_some_and(char::is_uppercase) && next.is_some_and(char::is_lowercase)));
        if boundary {
            words.push(current);
            current = String::new();
        }
        current.extend(ch.to_lowercase());
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
        .into_iter()
        // Короткие акронимы тоже являются частью имени владельца. Если
        // отбросить `DOM`, тип `ЭлементDOM` ложно выглядит как `Элемент`.
        .filter(|w| w.chars().count() >= 3)
        .map(|w| w.chars().take(5).collect())
        .collect()
}

fn cursor_prefix(source: &str, cursor: Option<&Value>) -> Option<String> {
    if source.is_empty() {
        return None;
    }
    let total = source.chars().count();
    let at = cursor
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .unwrap_or(total)
        .min(total);
    let before: String = source.chars().take(at).collect();
    let prefix: String = before
        .chars()
        .rev()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    (prefix.chars().count() >= 2).then_some(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_platform_page_without_html_noise() {
        let html = r#"<h1 class="V8SH_pagetitle">Структура.Вставить (Structure.Insert)</h1>
          <p class="V8SH_chapter">Синтаксис:</p>Вставить(&lt;Ключ&gt;, &lt;Значение&gt;)
          <p class="V8SH_chapter">Описание:</p><p>Добавляет <b>элемент</b>.</p>
          <p class="V8SH_chapter">Доступность:</p>Сервер.<BR>Тонкий клиент.
          <p class="V8SH_chapter">Пример:</p>С.Вставить("А", 1);"#;
        let item = parse_page("objects/Structure/methods/Insert.html", html).unwrap();
        assert_eq!(item.title, "Структура.Вставить");
        assert_eq!(item.owner, "Структура");
        assert_eq!(item.name, "Вставить");
        assert_eq!(item.syntax, "Вставить(<Ключ>, <Значение>)");
        assert_eq!(item.description, "Добавляет элемент.");
        assert!(!item.availability.contains('<'));
    }

    /// Разметка снята с настоящей `Query.html` справки 8.3.27.
    const ЗАПРОС: &str = r#"<h1 class="V8SH_pagetitle">Запрос (Query)</h1><p class="V8SH_title">Запрос (Query)</p><p class="V8SH_chapter">Описание:</p><p>Предназначен для выполнения запросов к базе данных.</p><p class="V8SH_chapter">Доступность: </p><p>Сервер, толстый клиент, внешнее соединение, мобильное приложение (сервер), мобильный автономный сервер.</p><p class="V8SH_chapter">См. также:</p>"#;

    #[test]
    fn страница_типа_даёт_доступность_типа() {
        let item = parse_page("objects/catalog213/catalog393/Query.html", ЗАПРОС).unwrap();
        assert_eq!(item.kind, "type");
        assert_eq!(item.name, "Запрос");
        assert!(
            item.availability.starts_with("Сервер"),
            "{}",
            item.availability
        );
        assert_eq!(OnThinClient::of(&item.availability), OnThinClient::No);
    }

    #[test]
    fn оглавление_и_служебные_страницы_не_типы() {
        assert!(!is_type_page("objects/catalog213/catalog393.html"));
        assert!(!is_type_page("objects/catalog125.html"));
        assert!(!is_type_page("objects/x/formparams/Key97.html"));
        assert!(is_type_page("objects/catalog213/catalog393/Query.html"));
        // Страница без раздела «Доступность» — не тип, даже если путь похож.
        let html = r#"<h1 class="V8SH_pagetitle">Глобальный контекст</h1>"#;
        assert!(parse_page("objects/Global context.html", html).is_none());
    }

    #[test]
    fn контекст_различает_клиент_и_сервер() {
        let c = context_from_pages(&[
            ("objects/catalog213/catalog393/Query.html", ЗАПРОС),
            (
                "objects/Global context/methods/CurrentSessionDate.html",
                r#"<h1 class="V8SH_pagetitle">Глобальный контекст.ТекущаяДатаСеанса (CurrentSessionDate)</h1><p class="V8SH_chapter">Доступность:</p><p>Сервер, толстый клиент, внешнее соединение.</p>"#,
            ),
            (
                "objects/Global context/methods/CurrentDate.html",
                r#"<h1 class="V8SH_pagetitle">Глобальный контекст.ТекущаяДата (CurrentDate)</h1><p class="V8SH_chapter">Доступность:</p><p>Тонкий клиент, веб-клиент, сервер.</p>"#,
            ),
        ]);
        assert_eq!(c.new_type("запрос").unwrap().1, OnThinClient::No);
        // Английское имя из заголовка — то же значение.
        assert_eq!(c.new_type("Query").unwrap().1, OnThinClient::No);
        assert_eq!(
            c.global_method("CurrentSessionDate").unwrap().1,
            OnThinClient::No
        );
        assert_eq!(
            c.global_method("ТекущаяДатаСеанса").unwrap().1,
            OnThinClient::No
        );
        assert_eq!(c.global_method("ТекущаяДата").unwrap().1, OnThinClient::Yes);
        assert!(c.global_method("НетТакого").is_none());
    }

    #[test]
    fn camel_stems_do_not_hide_unmatched_acronyms() {
        assert_eq!(camel_stems("Структура"), vec!["струк"]);
        assert_eq!(camel_stems("ЭлементDOM"), vec!["элеме", "dom"]);
        assert_eq!(camel_stems("Табличная часть"), vec!["табли", "часть"]);
        assert_eq!(
            camel_stems("КоллекцияЭлементовСтруктуры"),
            vec!["колле", "элеме", "струк"]
        );
        assert_eq!(
            stems("КоллекцияЭлементовСтруктуры.Добавить"),
            vec!["колле", "элеме", "струк", "добав"]
        );
        assert_eq!(compact_name("Таблица значений"), "таблицазначений");
    }

    #[test]
    fn natural_task_selects_short_owner_at_the_last_noun() {
        let owners = [
            "Элемент",
            "ЭлементDOM",
            "Структура",
            "КоллекцияЭлементовСтруктурыТаблицыКомпоновкиДанных",
        ];
        let task = "как добавить элемент в структуру";
        let selected = select_target_owners(owners.iter().copied(), task, &stems(task));
        assert_eq!(selected, HashSet::from(["структура".to_string()]));
    }

    #[test]
    fn exact_long_owner_wins_over_nested_short_owner() {
        let owners = [
            "Структура",
            "КоллекцияЭлементовСтруктурыДиаграммыКомпоновкиДанных",
        ];
        let task = "КоллекцияЭлементовСтруктурыДиаграммыКомпоновкиДанных.Добавить";
        let selected = select_target_owners(owners.iter().copied(), task, &stems(task));
        assert_eq!(
            selected,
            HashSet::from(["коллекцияэлементовструктурыдиаграммыкомпоновкиданных".to_string()])
        );
    }

    fn cache_fixture(name: &str) -> (PathBuf, SourceIdentity, Item) {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "gyrfalcon-cache-test-{}-{name}-{unique}",
            std::process::id(),
        ));
        let path = directory.join("catalog.zip");
        let identity = SourceIdentity {
            schema: CACHE_SCHEMA,
            path: "C:/Program Files/1cv8/8.3.27/bin/shcntx_ru.hbk".to_string(),
            version: "8.3.27".to_string(),
            size: 40_000_000,
            modified_ns: 123,
            sha256: "a".repeat(64),
        };
        let item = parse_page(
            "objects/Structure/methods/Insert.html",
            r#"<h1 class="V8SH_pagetitle">Структура.Вставить</h1>
               <p class="V8SH_chapter">Синтаксис:</p>Вставить(&lt;Ключ&gt;)"#,
        )
        .unwrap();
        (path, identity, item)
    }

    #[test]
    fn cold_cache_is_created() {
        let (path, identity, item) = cache_fixture("cold");
        let (items, hit, warning) =
            load_or_create_cache(&path, &identity, || Ok(vec![item])).unwrap();

        assert!(!hit);
        assert!(warning.is_none());
        assert_eq!(items.len(), 1);
        assert!(path.is_file());
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn warm_cache_is_loaded_without_rebuilding() {
        let (path, identity, item) = cache_fixture("warm");
        write_cache(&path, &identity, &[item]).unwrap();
        let (items, hit, warning) = load_or_create_cache(&path, &identity, || {
            Err("тёплый кэш не должен вызывать сборщик".to_string())
        })
        .unwrap();

        assert!(hit);
        assert!(warning.is_none());
        assert_eq!(items.len(), 1);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn changed_source_identity_invalidates_cache() {
        let (path, identity, item) = cache_fixture("invalidate");
        write_cache(&path, &identity, std::slice::from_ref(&item)).unwrap();

        let mut changed = identity.clone();
        changed.version = "8.3.28".to_string();
        let (_, hit, warning) = load_or_create_cache(&path, &changed, || Ok(vec![item])).unwrap();
        assert!(!hit);
        assert!(warning.is_none());
        assert!(read_cache(&path, &identity).is_err());
        assert_eq!(read_cache(&path, &changed).unwrap().len(), 1);

        let mut changed_contents = changed.clone();
        changed_contents.sha256 = "b".repeat(64);
        assert_ne!(
            cache_file_path(&changed),
            cache_file_path(&changed_contents)
        );

        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn version_sort_is_numeric() {
        assert!(version_key("8.3.27.2130") > version_key("8.3.9.9999"));
    }

    #[test]
    fn cursor_is_unicode_offset() {
        let s = "Структура.Вст\nКонец";
        let at = "Структура.Вст".chars().count();
        assert_eq!(cursor_prefix(s, Some(&json!(at))).unwrap(), "Структура.Вст");
    }
}
