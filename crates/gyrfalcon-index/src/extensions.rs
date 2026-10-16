//! Перехваты расширений с адресом — таблица `extension_overrides`.
//!
//! Это место, где адрес перехвата — наше преимущество, и терять здесь
//! нельзя ничего:
//! перехвата — модуль, строка, вид — то, ради чего сервер вообще спрашивают
//! про расширения.
//!
//! # Где лежат расширения
//!
//! Не внутри `src`, а СОСЕДЯМИ от него, и в двух раскладках:
//!
//! * контейнер — `<проект>/ext/<Имя расширения>/Configuration.xml`, по
//!   подкаталогу на расширение;
//! * одно расширение — `<проект>/cfe/Configuration.xml`: каталог сам и есть
//!   выгрузка расширения. Имя тогда берётся из манифеста, а не из каталога —
//!   иначе расширение звалось бы `cfe`.
//!
//! Каталог зовётся `ext` или `cfe` — в обеих раскладках. Внутри — обычная
//! выгрузка со своим `Configuration.xml`, поэтому разбор модуля тот же, что у
//! основной конфигурации; отличается только связывание с целью.
//!
//! До 0.1.19 вторая раскладка не была видна вовсе: искался только контейнер,
//! и проект с одним расширением собирался с `extensions = 0` без единого
//! предупреждения.
//!
//! # Два адреса, и они про разное
//!
//! * `ext_line` — строка САМОЙ АННОТАЦИИ в расширении. Проверено на корпусе ДО
//!   поимённо: прежний инструмент пишет строку `&После(...)`, а не строку следующего за ней
//!   `Процедура`. Разница в одну строку на всех 13 перехватах — ровно тот
//!   случай, где паритет разошёлся бы целиком.
//! * `target_method_line` — строка объявления перехватываемого метода в
//!   ОСНОВНОЙ конфигурации. Пусто, когда цель не разрешилась: модуля нет
//!   или метод в нём не найден. Пустое поле здесь — честный признак
//!   неразрешённого, а не «перехвата без адреса».
//!
//! # Как отличается перехват от директивы компиляции
//!
//! По ФОРМЕ, а не по списку имён (см. `module::override_of`): у перехвата есть
//! строковый аргумент, у `&НаСервере` его нет. Список видов не зашит —
//! `Вместо`, `Перед`, `После`, `ИзменениеИКонтроль` и то, что платформа
//! добавит завтра, разбираются одинаково.
//!
//! # Оговорка о корпусе
//!
//! Сверка сделана на ДО (9 расширений, 13 перехватов): там встречаются только
//! `ИзменениеИКонтроль` (10) и `После` (3). `Вместо` и `Перед` разбираются тем
//! же кодом, но НА ЖИВОМ КОРПУСЕ НЕ ПРОВЕРЕНЫ — сказано прямо, чтобы разбор
//! этих двух не считался подтверждённым.

use quick_xml::events::Event;
use quick_xml::Reader;
use std::path::{Path, PathBuf};

/// Расширение как целое: манифест плюс корень на диске.
#[derive(Debug, Clone)]
pub struct Extension {
    pub name: String,
    /// `Customization` / `Patch` из `<ConfigurationExtensionPurpose>`.
    ///
    /// Тег зовётся именно так, а не `Purpose`: имя проверено в выгрузке.
    pub purpose: Option<String>,
    /// Префикс имён (`Расш1_`) — не нужен для адреса, но объясняет,
    /// почему перехватчик называется не как цель.
    pub name_prefix: Option<String>,
    pub root: PathBuf,
}

/// Один перехват — строка таблицы.
#[derive(Debug, Clone)]
pub struct Override {
    /// Объект основной конфигурации, чей модуль перехвачен:
    /// имя общего модуля либо имя справочника/документа.
    pub object_name: String,
    /// Путь модуля-цели относительно `src`.
    pub source_path: String,
    pub target_method: String,
    /// Строка объявления цели; `None` — цель не разрешилась.
    pub target_method_line: Option<u32>,
    pub annotation: String,
    pub extension_name: String,
    pub extension_purpose: Option<String>,
    pub extension_method: String,
    pub extension_root: String,
    /// Путь модуля расширения относительно корня расширения.
    pub ext_module_path: String,
    pub ext_line: u32,
}

/// Каталоги расширений рядом с `src`.
///
/// Ищем соседей: `<родитель src>/ext` и `<родитель src>/cfe` — обе раскладки
/// встречаются, и какая именно, зависит от конфигурации, а не от нашего выбора.
pub fn extension_dirs(src: &Path) -> Vec<PathBuf> {
    let Some(parent) = src.parent() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for name in ["ext", "cfe"] {
        let dir = parent.join(name);
        if dir.is_dir() {
            out.push(dir);
        }
    }
    out
}

/// Каталог сам является выгрузкой расширения, а не контейнером.
fn одно_расширение(dir: &Path) -> bool {
    dir.join("Configuration.xml").is_file()
}

/// Расширения в каталоге `ext`/`cfe`: сам каталог, если в нём лежит
/// `Configuration.xml`, иначе — по одному подкаталогу на расширение.
pub fn collect_extensions(dir: &Path) -> Vec<Extension> {
    if одно_расширение(dir) {
        let m = parse_manifest(&dir.join("Configuration.xml"));
        let name = m.name.unwrap_or_else(|| имя_каталога(dir));
        return vec![Extension {
            name,
            purpose: m.purpose,
            name_prefix: m.prefix,
            root: dir.to_path_buf(),
        }];
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in rd.flatten() {
        let root = e.path();
        if !root.is_dir() {
            continue;
        }
        let manifest = root.join("Configuration.xml");
        if !manifest.is_file() {
            continue;
        }
        // Имя — по каталогу, как до 0.1.19: на нём держатся адреса уже
        // собранных индексов, а в выгрузке каталог и так назван по расширению.
        let name = имя_каталога(&root);
        let m = parse_manifest(&manifest);
        out.push(Extension {
            name,
            purpose: m.purpose,
            name_prefix: m.prefix,
            root,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn имя_каталога(dir: &Path) -> String {
    dir.file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_string()
}

/// Корень разбора: основная конфигурация или одно расширение.
///
/// # Почему расширение — такой же корень, а не таблица перехватов
///
/// До 06.10.2026 из расширений бралось только `extension_overrides`: модуль
/// без перехвата отбрасывался целиком, метаданные не читались вовсе. На ДО
/// это значило, что новые общие модули, регистры, обработки и роли девяти
/// расширений в индексе отсутствовали, а два расширения без перехватов не
/// существовали для индекса совсем. Ответ «такого нет» на живой код —
/// худший вид отказа. Решение владельца 06.10.2026: расширение индексируется
/// полностью, тем же разбором, что и основная конфигурация (Р-022).
#[derive(Debug, Clone)]
pub struct Корень {
    pub dir: PathBuf,
    /// `None` — основная конфигурация.
    pub extension: Option<Extension>,
}

/// Все корни проекта: сначала основная конфигурация, потом расширения по имени.
///
/// Порядок не косметический: при совпадении имён (заимствованный общий модуль
/// лежит в расширении под тем же именем, что в основной) адресатом вызова
/// остаётся объект основной конфигурации, а он должен быть записан первым.
pub fn корни(src: &Path) -> Vec<Корень> {
    let mut out = vec![Корень {
        dir: src.to_path_buf(),
        extension: None,
    }];
    for d in extension_dirs(src) {
        for ext in collect_extensions(&d) {
            out.push(Корень {
                dir: ext.root.clone(),
                extension: Some(ext),
            });
        }
    }
    out
}

/// Путь файла относительно `src`, разделителем `/`.
///
/// Файл расширения лежит соседом `src`, поэтому его адрес начинается с `../`:
/// `../ext/Доработка/CommonModules/X/Ext/Module.bsl`. Это рабочий путь —
/// `src.join(rel)` открывает файл, — и та же форма, что отдаёт прежний
/// инструмент, так что агенту не нужно переучиваться. Признак «это расширение»
/// читается по префиксу, отдельного столбца в каждой таблице не требуется.
pub fn rel_from(src: &Path, path: &Path) -> String {
    if let Ok(r) = path.strip_prefix(src) {
        return r.to_string_lossy().replace('\\', "/");
    }
    if let Some(parent) = src.parent() {
        if let Ok(r) = path.strip_prefix(parent) {
            return format!("../{}", r.to_string_lossy().replace('\\', "/"));
        }
    }
    path.to_string_lossy().replace('\\', "/")
}

/// Корень, внутри которого лежит файл: `src`, `<родитель>/ext|cfe/<Имя>`
/// либо сам `<родитель>/cfe`, когда это одно расширение.
///
/// Нужен там, где файл приходит по одному (инкремент, сторож свежести):
/// классификация модуля идёт по пути ВНУТРИ его выгрузки, а не от `src`.
pub fn корень_файла(src: &Path, path: &Path) -> Option<PathBuf> {
    if path.starts_with(src) {
        return Some(src.to_path_buf());
    }
    for d in extension_dirs(src) {
        if let Ok(r) = path.strip_prefix(&d) {
            if одно_расширение(&d) {
                return Some(d);
            }
            let имя = r.components().next()?;
            return Some(d.join(имя.as_os_str()));
        }
    }
    None
}

/// Где в адресах лежит каждое расширение: `rel_root` → имя.
///
/// # Зачем отдельная структура, а не разбор адреса
///
/// До 0.1.19 имя расширения вынималось из адреса строкой: `../ext/<Имя>/…`,
/// третий сегмент. У одного расширения в `cfe/` адрес `../cfe/CommonModules/…`,
/// и тот же разбор назвал бы расширением `CommonModules`. Форма адреса сама по
/// себе раскладку не выдаёт — её знает только тот, кто видел диск (сборка) или
/// записанный реестр `extensions` (инкремент). Отсюда два конструктора.
#[derive(Debug, Clone, Default)]
pub struct Раскладка {
    /// `(rel_root, имя)`; `rel_root` — без завершающего `/`.
    корни: Vec<(String, String)>,
}

impl Раскладка {
    /// По корням, найденным на диске.
    pub fn из_корней(src: &Path, корни: &[Корень]) -> Self {
        Self {
            корни: корни
                .iter()
                .filter_map(|к| {
                    let e = к.extension.as_ref()?;
                    Some((rel_from(src, &к.dir), e.name.clone()))
                })
                .collect(),
        }
    }

    /// По записанному реестру `extensions` — для инкремента, где диска
    /// целиком не видно.
    pub fn из_индекса(conn: &rusqlite::Connection) -> rusqlite::Result<Self> {
        let mut st = conn.prepare("SELECT rel_root, name FROM extensions")?;
        let корни = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Self { корни })
    }

    fn найти<'a>(&self, rel: &'a str) -> Option<(&str, &'a str)> {
        self.корни.iter().find_map(|(корень, имя)| {
            let хвост = rel.strip_prefix(корень.as_str())?.strip_prefix('/')?;
            Some((имя.as_str(), хвост))
        })
    }

    /// Имя расширения, которому принадлежит адрес; `None` — основная конфигурация.
    pub fn расширение(&self, rel: &str) -> Option<&str> {
        self.найти(rel).map(|(имя, _)| имя)
    }

    /// Путь внутри выгрузки, которой принадлежит файл: `../ext/<Имя>/X/Y` → `X/Y`,
    /// `../cfe/X/Y` → `X/Y`. Путь основной конфигурации возвращается как есть.
    pub fn внутри<'a>(&self, rel: &'a str) -> &'a str {
        self.найти(rel).map_or(rel, |(_, хвост)| хвост)
    }
}

/// Что берётся из манифеста расширения.
#[derive(Debug, Default)]
struct Манифест {
    name: Option<String>,
    purpose: Option<String>,
    prefix: Option<String>,
}

/// Имя, назначение и префикс из манифеста расширения.
///
/// Имя — только `Properties/Name` верхнего уровня: `Name` встречается и глубже
/// (в описаниях языков), и первое попавшееся было бы не тем.
fn parse_manifest(path: &Path) -> Манифест {
    let mut out = Манифест::default();
    let Ok(text) = std::fs::read_to_string(path) else {
        return out;
    };
    let mut reader = Reader::from_str(&text);
    reader.config_mut().trim_text(true);

    let mut стек: Vec<Vec<u8>> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => стек.push(local_name(e.name().as_ref()).to_vec()),
            Ok(Event::Text(t)) => {
                let Some(тег) = стек.last() else {
                    buf.clear();
                    continue;
                };
                // MetaDataObject / Configuration / Properties / <поле>
                let в_свойствах = стек.len() == 4 && стек[2].as_slice() == b"Properties";
                let поле = match тег.as_slice() {
                    b"ConfigurationExtensionPurpose" => Some(&mut out.purpose),
                    b"NamePrefix" => Some(&mut out.prefix),
                    b"Name" if в_свойствах => Some(&mut out.name),
                    _ => None,
                };
                if let (Some(поле), Ok(v)) = (поле, t.unescape()) {
                    let v = v.trim();
                    if !v.is_empty() && поле.is_none() {
                        *поле = Some(v.to_string());
                    }
                }
            }
            Ok(Event::End(_)) => {
                стек.pop();
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

/// Локальное имя тега без префикса пространства имён.
fn local_name(raw: &[u8]) -> &[u8] {
    match raw.iter().rposition(|b| *b == b':') {
        Some(i) => &raw[i + 1..],
        None => raw,
    }
}

/// Объект-владелец модуля по пути внутри выгрузки.
///
/// `CommonModules/ОбзорДокумента/Ext/Module.bsl` → `ОбзорДокумента`;
/// `Catalogs/ДокументыПредприятия/Forms/ФормаЭлемента/Ext/Form/Module.bsl`
/// → `ДокументыПредприятия`. Второй сегмент — имя объекта в обеих раскладках.
pub fn object_of_path(rel: &str) -> String {
    rel.replace('\\', "/")
        .split('/')
        .nth(1)
        .unwrap_or_default()
        .to_string()
}

#[cfg(test)]
mod тесты_адреса {
    use super::*;

    #[test]
    fn адрес_расширения_от_src() {
        let src = Path::new("C:/p/src");
        assert_eq!(
            rel_from(src, Path::new("C:/p/src/CommonModules/А/Ext/Module.bsl")),
            "CommonModules/А/Ext/Module.bsl"
        );
        let r = rel_from(
            src,
            Path::new("C:/p/ext/Доработка/CommonModules/Б/Ext/Module.bsl"),
        );
        assert_eq!(r, "../ext/Доработка/CommonModules/Б/Ext/Module.bsl");
    }

    /// Обе раскладки на диске: контейнер `ext/<Имя>` и одно расширение `cfe/`.
    fn проект(метка: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("gyrfalcon-ext-layout-{метка}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("src")).unwrap();
        d
    }

    fn манифест(dir: &Path, имя: Option<&str>) {
        std::fs::create_dir_all(dir).unwrap();
        let имя = имя.map(|и| format!("<Name>{и}</Name>")).unwrap_or_default();
        std::fs::write(
            dir.join("Configuration.xml"),
            format!(
                "<MetaDataObject xmlns=\"http://v8.1c.ru/8.3/MDClasses\"><Configuration>\
                 <InternalInfo><Name>ЛожноеИмя</Name></InternalInfo>\
                 <Properties>{имя}<ConfigurationExtensionPurpose>Customization</ConfigurationExtensionPurpose>\
                 <NamePrefix>Св_</NamePrefix><Synonym><v8:item><v8:lang>ru</v8:lang>\
                 <v8:content>Не имя</v8:content></v8:item></Synonym></Properties>\
                 </Configuration></MetaDataObject>"
            ),
        )
        .unwrap();
    }

    #[test]
    fn одно_расширение_в_cfe_видно_под_именем_из_манифеста() {
        let d = проект("single");
        манифест(&d.join("cfe"), Some("СвоёРасширение"));
        let src = d.join("src");

        let к = корни(&src);
        assert_eq!(к.len(), 2, "основная + одно расширение");
        let e = к[1].extension.as_ref().unwrap();
        assert_eq!(e.name, "СвоёРасширение", "имя из манифеста, а не `cfe`");
        assert_eq!(e.purpose.as_deref(), Some("Customization"));
        assert_eq!(e.name_prefix.as_deref(), Some("Св_"));
        assert_eq!(к[1].dir, d.join("cfe"));

        let файл = d.join("cfe/CommonModules/Св_Сервис/Ext/Module.bsl");
        assert_eq!(корень_файла(&src, &файл), Some(d.join("cfe")));

        let раскл = Раскладка::из_корней(&src, &к);
        let rel = rel_from(&src, &файл);
        assert_eq!(rel, "../cfe/CommonModules/Св_Сервис/Ext/Module.bsl");
        assert_eq!(раскл.расширение(&rel), Some("СвоёРасширение"));
        assert_eq!(раскл.внутри(&rel), "CommonModules/Св_Сервис/Ext/Module.bsl");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn контейнер_ext_прежний() {
        let d = проект("container");
        манифест(&d.join("ext/Доработка"), Some("ИмяИзМанифеста"));
        манифест(&d.join("ext/Второе"), None);
        let src = d.join("src");

        let к = корни(&src);
        let имена: Vec<&str> = к
            .iter()
            .filter_map(|к| к.extension.as_ref().map(|e| e.name.as_str()))
            .collect();
        assert_eq!(
            имена,
            ["Второе", "Доработка"],
            "в контейнере имя — по каталогу"
        );

        let файл = d.join("ext/Доработка/Catalogs/Товар.xml");
        assert_eq!(корень_файла(&src, &файл), Some(d.join("ext/Доработка")));
        let раскл = Раскладка::из_корней(&src, &к);
        let rel = rel_from(&src, &файл);
        assert_eq!(раскл.расширение(&rel), Some("Доработка"));
        assert_eq!(раскл.внутри(&rel), "Catalogs/Товар.xml");
        assert_eq!(раскл.расширение("CommonModules/А/Ext/Module.bsl"), None);
        assert_eq!(раскл.внутри("CommonModules/А"), "CommonModules/А");
        // Префикс без разделителя — не принадлежность: `../ext/Доработка2`
        // не лежит в `../ext/Доработка`.
        assert_eq!(раскл.расширение("../ext/Доработка2/X.xml"), None);
        let _ = std::fs::remove_dir_all(&d);
    }
}
