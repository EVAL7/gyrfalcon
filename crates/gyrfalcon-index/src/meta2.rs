//! Разбор метаданных вехи 3, часть вторая: подписки, регламентные задания,
//! функциональные опции, права ролей, состав планов обмена.
//!
//! # Почему отдельным модулем, а не внутри `meta.rs`
//!
//! У объектов из `meta.rs` общая форма: `Properties` + `ChildObjects`, и один
//! проход разбирает их все. Здесь форма у каждого своя — `Rights.xml` вообще не
//! `MetaDataObject`, а `Content.xml` плана обмена лежит в каталоге-спутнике.
//! Втискивание их в общий проход дало бы разбор с пятью ветками «а если это…».
//!
//! # Откуда взяты поля
//!
//! Схема снята с индекса прежнего инструмента (`sqlite_master`), значения сверены с живой
//! выгрузкой БП 28.08.2026 — не по памяти о том, как устроена 1С. В частности:
//!
//! - **права пишутся только со значением `true`**. Проверено числом: у роли
//!   `АдминистраторСистемы` в XML 3 956 тегов `<right>`, из них 3 615 со
//!   значением `true` — и ровно 3 615 строк у прежнего инструмента. Писать отказы значило бы
//!   разойтись с ним на 341 строку и назвать это «мы полнее»;
//! - **`AutoRecord`**: `Deny` → 0, `Allow` → 1 (12 239 и 21 на БП — сходится
//!   с прежним инструментом поштучно).

use quick_xml::events::Event;
use quick_xml::Reader;
use std::path::Path;

/// Подписка на событие.
#[derive(Debug, Clone, Default)]
pub struct EventSubscription {
    pub name: String,
    pub synonym: Option<String>,
    pub event: Option<String>,
    /// Модуль-обработчик: из `CommonModule.X.Метод` — это `X`.
    pub handler_module: Option<String>,
    pub handler_procedure: Option<String>,
    /// Типы источника, как в XML: `DocumentObject.X`.
    pub source_types: Vec<String>,
    pub file: String,
}

/// Регламентное задание.
#[derive(Debug, Clone, Default)]
pub struct ScheduledJob {
    pub name: String,
    pub synonym: Option<String>,
    pub method_name: Option<String>,
    pub handler_module: Option<String>,
    pub handler_procedure: Option<String>,
    pub use_: bool,
    pub predefined: bool,
    pub restart_count: i64,
    pub restart_interval: i64,
    pub file: String,
}

/// Функциональная опция.
#[derive(Debug, Clone, Default)]
pub struct FunctionalOption {
    pub name: String,
    pub synonym: Option<String>,
    /// Где хранится значение: `InformationRegister.X.Resource.Y` или `Constant.X`.
    pub location: Option<String>,
    /// Состав опции — объекты, которыми она управляет.
    pub content: Vec<String>,
    pub file: String,
}

/// Одно право роли на один объект.
#[derive(Debug, Clone, Default)]
pub struct RoleRight {
    pub role_name: String,
    pub object_name: String,
    pub right_name: String,
    pub file: String,
}

/// Строка состава плана обмена.
#[derive(Debug, Clone, Default)]
pub struct ExchangeContentItem {
    pub plan_name: String,
    pub object_ref: String,
    /// `Allow` → 1, `Deny` → 0. Хранится числом — формат прежнего инструмента.
    pub auto_record: i64,
    pub path: String,
}

/// Флаги общего модуля: где его код существует и откуда его можно звать.
///
/// Нужны проверке контекста исполнения (`check_bsl`, MCP-06): вызов из
/// `&НаКлиенте` в модуль без клиентского флага и без `ServerCall` платформа
/// не компилирует, а по одному тексту модуля это не видно — флаги живут
/// только в XML. Класс ошибки из живой задачи: клиентский вызов серверного
/// метода прошёл все проверки агента и вылез у пользователя при запуске.
///
/// Имена полей — имена тегов выгрузки (сверено с `CommonModules/*.xml` БП
/// 13.10.2026), без перевода.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommonModuleFlags {
    pub name: String,
    pub global: bool,
    pub client_managed: bool,
    pub client_ordinary: bool,
    pub server: bool,
    pub server_call: bool,
    pub external_connection: bool,
    pub privileged: bool,
    pub file: String,
}

/// Прочитать файл, сняв BOM. `None` — файла нет или он нечитаем.
fn read_text(path: &Path) -> Option<String> {
    let raw = std::fs::read(path).ok()?;
    let raw = raw.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&raw);
    Some(String::from_utf8_lossy(raw).into_owned())
}

fn reader_for(text: &str) -> Reader<&[u8]> {
    let mut reader = Reader::from_reader(text.as_bytes());
    let cfg = reader.config_mut();
    cfg.trim_text(true);
    cfg.check_end_names = false;
    reader
}

fn local_name(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    s.rsplit(':').next().unwrap_or("").to_string()
}

/// Убрать префикс пространства имён у ссылки на тип:
/// `cfg:DocumentObject.X` → `DocumentObject.X`.
fn strip_cfg(t: &str) -> &str {
    t.split_once(':').map(|(_, r)| r).unwrap_or(t)
}

/// Разделить `CommonModule.Модуль.Метод` на модуль и метод.
///
/// Форма ровно такая у обоих мест, где встречается (обработчик подписки, метод
/// задания). Иное не разбираем и оставляем `None`: выдумывать разбор формы,
/// которой не видели, значит наполнить таблицу правдоподобным мусором.
fn split_handler(h: &str) -> (Option<String>, Option<String>) {
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() == 3 && parts[0] == "CommonModule" {
        (Some(parts[1].to_string()), Some(parts[2].to_string()))
    } else {
        (None, None)
    }
}

/// Пары (путь тегов от корня, текст) — общий разбор объекта с `Properties`.
///
/// Путь нужен потому, что `<Name>` встречается и у объекта, и внутри
/// `Synonym`, и вложенным в состав: различать их по одному имени тега нельзя.
fn properties_pairs(text: &str) -> Vec<(Vec<String>, String)> {
    let mut out = Vec::new();
    let mut reader = reader_for(text);
    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => stack.push(local_name(e.name().as_ref())),
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Text(t)) => {
                let s = t.unescape().map(|c| c.into_owned()).unwrap_or_default();
                if !s.trim().is_empty() {
                    out.push((stack.clone(), s));
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

/// Синоним первого языка: `Synonym/item/content`.
fn take_synonym(pairs: &[(Vec<String>, String)]) -> Option<String> {
    pairs
        .iter()
        .find(|(p, _)| {
            p.iter().any(|t| t == "Synonym") && p.last().map(String::as_str) == Some("content")
        })
        .map(|(_, v)| v.clone())
}

/// Значение прямого свойства — тега непосредственно внутри `Properties`,
/// а не вложенного глубже.
fn direct_prop(pairs: &[(Vec<String>, String)], tag: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(p, _)| {
            p.len() >= 2
                && p.last().map(String::as_str) == Some(tag)
                && p[p.len() - 2] == "Properties"
        })
        .map(|(_, v)| v.clone())
}

/// Разобрать подписку на событие.
pub fn parse_event_subscription(path: &Path, rel: &str) -> Option<EventSubscription> {
    let text = read_text(path)?;
    let pairs = properties_pairs(&text);
    let name = direct_prop(&pairs, "Name")?;

    let handler = direct_prop(&pairs, "Handler");
    let (hm, hp) = handler
        .as_deref()
        .map(split_handler)
        .unwrap_or((None, None));

    // Источник — один или несколько `<v8:Type>` внутри `<Source>`, либо
    // определяемый тип `<v8:TypeSet>cfg:DefinedType.X`. Второй до 0.1.19
    // отбрасывался: на типовой УТ так у 121 подписки из 300, и у них
    // источников не было вовсе. Пишется в исходной форме `DefinedType.X` —
    // развёртывает её читающий (`defined_types`), а не сборка: состав
    // определяемого типа хранится без суффикса (`Document.X`), а источники
    // подписок — с ним (`DocumentObject.X`), и смешивать формы в одном
    // столбце нельзя (см. `meta::strip_suffix`).
    let source_types: Vec<String> = pairs
        .iter()
        .filter(|(p, _)| {
            p.iter().any(|t| t == "Source")
                && matches!(p.last().map(String::as_str), Some("Type" | "TypeSet"))
        })
        .map(|(_, v)| strip_cfg(v).to_string())
        .collect();

    Some(EventSubscription {
        name,
        synonym: take_synonym(&pairs),
        event: direct_prop(&pairs, "Event"),
        handler_module: hm,
        handler_procedure: hp,
        source_types,
        file: rel.to_string(),
    })
}

/// Разобрать регламентное задание.
pub fn parse_scheduled_job(path: &Path, rel: &str) -> Option<ScheduledJob> {
    let text = read_text(path)?;
    let pairs = properties_pairs(&text);
    let name = direct_prop(&pairs, "Name")?;

    let method = direct_prop(&pairs, "MethodName");
    let (hm, hp) = method.as_deref().map(split_handler).unwrap_or((None, None));

    Some(ScheduledJob {
        name,
        synonym: take_synonym(&pairs),
        method_name: method,
        handler_module: hm,
        handler_procedure: hp,
        use_: direct_prop(&pairs, "Use").as_deref() == Some("true"),
        predefined: direct_prop(&pairs, "Predefined").as_deref() == Some("true"),
        restart_count: direct_prop(&pairs, "RestartCountOnFailure")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        restart_interval: direct_prop(&pairs, "RestartIntervalOnFailure")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        file: rel.to_string(),
    })
}

/// Разобрать флаги общего модуля.
///
/// Отсутствующий флаг читается как `false` — так платформа и выгружает
/// умолчание. Но объект без `<Name>` отвергается: модуль без имени в таблице
/// был бы строкой, на которую нельзя сослаться.
pub fn parse_common_module(path: &Path, rel: &str) -> Option<CommonModuleFlags> {
    let text = read_text(path)?;
    let pairs = properties_pairs(&text);
    let name = direct_prop(&pairs, "Name")?;
    let flag = |tag: &str| direct_prop(&pairs, tag).as_deref() == Some("true");
    Some(CommonModuleFlags {
        name,
        global: flag("Global"),
        client_managed: flag("ClientManagedApplication"),
        client_ordinary: flag("ClientOrdinaryApplication"),
        server: flag("Server"),
        server_call: flag("ServerCall"),
        external_connection: flag("ExternalConnection"),
        privileged: flag("Privileged"),
        file: rel.to_string(),
    })
}

/// Разобрать функциональную опцию.
pub fn parse_functional_option(path: &Path, rel: &str) -> Option<FunctionalOption> {
    let text = read_text(path)?;
    let pairs = properties_pairs(&text);
    let name = direct_prop(&pairs, "Name")?;

    // Состав — ссылки внутри `<Content>`, тегами `<xr:Object>`.
    //
    // Тег именно `Object`, а не `Field`: на `Field` разбор молчал у ВСЕХ 496
    // опций, и таблица при этом выглядела заполненной — сверка по ключу
    // «имя + место хранения» давала паритет, потому что состав в этот ключ
    // не входил. Поймано только сверкой `metadata_references` с прежним инструментом
    // (28.08.2026): у него 6 472 строки состава против наших нулей.
    //
    // Ссылка бывает составной: `Document.X.TabularSection.Y.Attribute.Z` —
    // опция управляет отдельным реквизитом, а не объектом целиком. Такие
    // не укорачиваются: 3 867 строк из 6 472 у прежнего инструмента именно такие, и
    // «упрощение» до объекта потеряло бы, ЧЕМ опция управляет.
    let content: Vec<String> = pairs
        .iter()
        .filter(|(p, _)| {
            p.iter().any(|t| t == "Content") && p.last().map(String::as_str) == Some("Object")
        })
        .map(|(_, v)| strip_cfg(v).to_string())
        .collect();

    Some(FunctionalOption {
        name,
        synonym: take_synonym(&pairs),
        location: direct_prop(&pairs, "Location"),
        content,
        file: rel.to_string(),
    })
}

/// Разобрать `Roles/<Роль>/Ext/Rights.xml`.
///
/// Пишутся только права со значением `true` — так делает прежний инструмент, и так же
/// читается смысл: право, выключенное явно, не отличается от невыданного.
pub fn parse_role_rights(path: &Path, role: &str, rel: &str) -> Vec<RoleRight> {
    let Some(text) = read_text(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut reader = reader_for(&text);
    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    // `<name>` встречается и у объекта, и у права: различает их не имя тега,
    // а родитель — `object/name` против `object/right/name`.
    let mut object_name: Option<String> = None;
    let mut right_name: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let n = local_name(e.name().as_ref());
                if n == "right" {
                    right_name = None;
                }
                stack.push(n);
            }
            Ok(Event::End(e)) => {
                if local_name(e.name().as_ref()) == "object" {
                    object_name = None;
                }
                stack.pop();
            }
            Ok(Event::Text(t)) => {
                let s = t.unescape().map(|c| c.into_owned()).unwrap_or_default();
                let depth = stack.len();
                match stack.last().map(String::as_str) {
                    Some("name") if depth >= 2 && stack[depth - 2] == "object" => {
                        object_name = Some(s);
                    }
                    Some("name") if depth >= 2 && stack[depth - 2] == "right" => {
                        right_name = Some(s);
                    }
                    Some("value") if depth >= 2 && stack[depth - 2] == "right" && s == "true" => {
                        if let (Some(o), Some(r)) = (&object_name, &right_name) {
                            out.push(RoleRight {
                                role_name: role.to_string(),
                                object_name: o.clone(),
                                right_name: r.clone(),
                                file: rel.to_string(),
                            });
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

/// Разобрать `ExchangePlans/<План>/Ext/Content.xml`.
pub fn parse_exchange_content(path: &Path, plan: &str, rel: &str) -> Vec<ExchangeContentItem> {
    let Some(text) = read_text(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut reader = reader_for(&text);
    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut metadata: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let n = local_name(e.name().as_ref());
                if n == "Item" {
                    metadata = None;
                }
                stack.push(n);
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Text(t)) => {
                let s = t.unescape().map(|c| c.into_owned()).unwrap_or_default();
                match stack.last().map(String::as_str) {
                    Some("Metadata") => metadata = Some(strip_cfg(&s).to_string()),
                    Some("AutoRecord") => {
                        if let Some(m) = metadata.take() {
                            out.push(ExchangeContentItem {
                                plan_name: plan.to_string(),
                                object_ref: m,
                                auto_record: i64::from(s == "Allow"),
                                path: rel.to_string(),
                            });
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Записать XML во временный файл. Тесты читают с диска, а не из строки:
    /// разбор начинается со снятия BOM, и проверять его в обход файла значило
    /// бы проверить не тот путь, которым идут настоящие данные.
    fn во_временный(имя: &str, xml: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("gyrfalcon-meta2-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(имя);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(&[0xEF, 0xBB, 0xBF]).unwrap();
        f.write_all(xml.as_bytes()).unwrap();
        p
    }

    const ПОДПИСКА: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<MetaDataObject xmlns:v8="http://v8.1c.ru/8.1/data/core">
  <EventSubscription uuid="ca17">
    <Properties>
      <Name>ПриПроведении</Name>
      <Synonym><v8:item><v8:lang>ru</v8:lang><v8:content>При проведении</v8:content></v8:item></Synonym>
      <Comment/>
      <Source><v8:Type>cfg:DocumentObject.РасходТовара</v8:Type></Source>
      <Event>Posting</Event>
      <Handler>CommonModule.УчетЗарплаты.ПриПроведенииДокумента</Handler>
    </Properties>
  </EventSubscription>
</MetaDataObject>"#;

    #[test]
    fn подписка_разбирает_обработчик_и_источник() {
        let p = во_временный("sub.xml", ПОДПИСКА);
        let s = parse_event_subscription(&p, "EventSubscriptions/ПриПроведении.xml").unwrap();
        assert_eq!(s.name, "ПриПроведении");
        assert_eq!(s.event.as_deref(), Some("Posting"));
        // Модуль и процедура разделены, а не оставлены одной строкой:
        // вопрос агента «кто обрабатывает событие» — про модуль.
        assert_eq!(s.handler_module.as_deref(), Some("УчетЗарплаты"));
        assert_eq!(
            s.handler_procedure.as_deref(),
            Some("ПриПроведенииДокумента")
        );
        // Префикс `cfg:` снят — иначе тип не сходится с тем, как объект
        // называется во всех остальных таблицах индекса.
        assert_eq!(s.source_types, vec!["DocumentObject.РасходТовара"]);
        assert_eq!(s.synonym.as_deref(), Some("При проведении"));
    }

    #[test]
    fn подписка_с_несколькими_источниками_не_теряет_ни_одного() {
        let xml = ПОДПИСКА.replace(
            "<Source><v8:Type>cfg:DocumentObject.РасходТовара</v8:Type></Source>",
            "<Source><v8:Type>cfg:DocumentObject.А</v8:Type>\
             <v8:Type>cfg:DocumentObject.Б</v8:Type>\
             <v8:Type>cfg:CatalogObject.В</v8:Type></Source>",
        );
        let p = во_временный("sub-multi.xml", &xml);
        let s = parse_event_subscription(&p, "x.xml").unwrap();
        assert_eq!(s.source_types.len(), 3);
    }

    /// Источник через определяемый тип — `TypeSet`, а не `Type`; до 0.1.19
    /// такая подписка оставалась без источников.
    #[test]
    fn подписка_с_определяемым_типом_не_теряет_источник() {
        let xml = ПОДПИСКА.replace(
            "<Source><v8:Type>cfg:DocumentObject.РасходТовара</v8:Type></Source>",
            "<Source><v8:TypeSet>cfg:DefinedType.ВерсионируемыеДанные</v8:TypeSet></Source>",
        );
        let p = во_временный("sub-typeset.xml", &xml);
        let s = parse_event_subscription(&p, "x.xml").unwrap();
        assert_eq!(s.source_types, vec!["DefinedType.ВерсионируемыеДанные"]);
    }

    #[test]
    fn общий_модуль_читает_флаги_контекста() {
        // Форма снята с `CommonModules/ОбщегоНазначенияВызовСервера.xml` БП.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<MetaDataObject xmlns:v8="http://v8.1c.ru/8.1/data/core">
  <CommonModule uuid="1c0d">
    <Properties>
      <Name>ОбщегоНазначенияВызовСервера</Name>
      <Synonym/>
      <Comment/>
      <Global>false</Global>
      <ClientManagedApplication>false</ClientManagedApplication>
      <Server>true</Server>
      <ExternalConnection>false</ExternalConnection>
      <ClientOrdinaryApplication>false</ClientOrdinaryApplication>
      <ServerCall>true</ServerCall>
      <Privileged>false</Privileged>
      <ReturnValuesReuse>DontUse</ReturnValuesReuse>
    </Properties>
  </CommonModule>
</MetaDataObject>"#;
        let p = во_временный("cm.xml", xml);
        let m = parse_common_module(&p, "CommonModules/ОбщегоНазначенияВызовСервера.xml").unwrap();
        assert_eq!(m.name, "ОбщегоНазначенияВызовСервера");
        assert!(m.server && m.server_call, "серверные флаги потеряны: {m:?}");
        assert!(!m.client_managed && !m.global && !m.privileged);
    }

    #[test]
    fn общий_модуль_без_флага_читается_как_ложь() {
        // Отсутствующий тег — умолчание платформы `false`, а не «неизвестно».
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<MetaDataObject><CommonModule uuid="1"><Properties>
<Name>Клиентский</Name><ClientManagedApplication>true</ClientManagedApplication>
</Properties></CommonModule></MetaDataObject>"#;
        let p = во_временный("cm-short.xml", xml);
        let m = parse_common_module(&p, "x.xml").unwrap();
        assert!(m.client_managed);
        assert!(!m.server && !m.server_call);
    }

    #[test]
    fn задание_читает_флаги_и_числа() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<MetaDataObject xmlns:v8="http://v8.1c.ru/8.1/data/core">
  <ScheduledJob uuid="3331">
    <Properties>
      <Name>ЗагрузкаКурсов</Name>
      <MethodName>CommonModule.РаботаСКурсами.ЗагрузитьКурсы</MethodName>
      <Use>false</Use>
      <Predefined>true</Predefined>
      <RestartCountOnFailure>3</RestartCountOnFailure>
      <RestartIntervalOnFailure>10</RestartIntervalOnFailure>
    </Properties>
  </ScheduledJob>
</MetaDataObject>"#;
        let p = во_временный("job.xml", xml);
        let j = parse_scheduled_job(&p, "ScheduledJobs/ЗагрузкаКурсов.xml").unwrap();
        assert!(!j.use_, "Use=false обязано читаться как выключено");
        assert!(j.predefined);
        assert_eq!(j.restart_count, 3);
        assert_eq!(j.restart_interval, 10);
        assert_eq!(j.handler_module.as_deref(), Some("РаботаСКурсами"));
    }

    #[test]
    fn права_берутся_только_разрешённые() {
        // Ровно тот случай, что на живой роли: у объекта есть и выданные
        // права, и явно запрещённые. Запрещённое не пишется — так у прежнего инструмента,
        // и так же читается смысл: запрет неотличим от невыдачи.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Rights xmlns="http://v8.1c.ru/8.2/roles">
  <setForNewObjects>false</setForNewObjects>
  <object>
    <name>Constant.Организация</name>
    <right><name>Read</name><value>true</value></right>
    <right><name>Update</name><value>false</value></right>
  </object>
  <object>
    <name>Catalog.Номенклатура</name>
    <right><name>View</name><value>true</value></right>
  </object>
</Rights>"#;
        let p = во_временный("rights.xml", xml);
        let r = parse_role_rights(&p, "Роль", "Roles/Роль/Ext/Rights.xml");
        assert_eq!(r.len(), 2, "запрещённое право попало в индекс: {r:?}");
        assert!(r
            .iter()
            .any(|x| x.object_name == "Constant.Организация" && x.right_name == "Read"));
        assert!(r.iter().all(|x| x.right_name != "Update"));
        // Права не «слипаются» между объектами: имя объекта сбрасывается
        // на закрытии `</object>`, иначе последнее имя протекло бы дальше.
        assert!(r.iter().any(|x| x.object_name == "Catalog.Номенклатура"));
    }

    #[test]
    fn состав_обмена_кодирует_авторегистрацию_числом() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ExchangePlanContent xmlns="http://v8.1c.ru/8.3/xcf/extrnprops">
  <Item><Metadata>Constant.А</Metadata><AutoRecord>Deny</AutoRecord></Item>
  <Item><Metadata>Catalog.Б</Metadata><AutoRecord>Allow</AutoRecord></Item>
</ExchangePlanContent>"#;
        let p = во_временный("content.xml", xml);
        let c = parse_exchange_content(&p, "План", "ExchangePlans/План/Ext/Content.xml");
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].auto_record, 0, "Deny обязан быть нулём");
        assert_eq!(c[1].auto_record, 1, "Allow обязан быть единицей");
    }

    #[test]
    fn опция_читает_место_хранения() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<MetaDataObject xmlns:v8="http://v8.1c.ru/8.1/data/core">
  <FunctionalOption uuid="9091">
    <Properties>
      <Name>ВестиУчетПоСкладам</Name>
      <Location>InformationRegister.Настройки.Resource.ВестиУчетПоСкладам</Location>
      <Content/>
    </Properties>
  </FunctionalOption>
</MetaDataObject>"#;
        let p = во_временный("fo.xml", xml);
        let o = parse_functional_option(&p, "FunctionalOptions/ВестиУчетПоСкладам.xml").unwrap();
        assert_eq!(
            o.location.as_deref(),
            Some("InformationRegister.Настройки.Resource.ВестиУчетПоСкладам")
        );
        // Пустой состав — штатный случай, а не признак недоразбора.
        assert!(o.content.is_empty());
    }

    #[test]
    fn отсутствующий_файл_даёт_пустоту_а_не_панику() {
        // Не во всякой конфигурации есть планы обмена и роли: отсутствие
        // файла обязано быть штатным исходом, иначе сборка падает на
        // конфигурации, где просто нет такой категории.
        let нет = std::path::Path::new("нет-такого-файла.xml");
        assert!(parse_event_subscription(нет, "x").is_none());
        assert!(parse_role_rights(нет, "Роль", "x").is_empty());
        assert!(parse_exchange_content(нет, "План", "x").is_empty());
    }
}
