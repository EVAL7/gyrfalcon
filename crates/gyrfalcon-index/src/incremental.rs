//! Инкрементальная пересборка: переиндексировать изменившееся, а не всё.
//!
//! # Что инкремент даёт, а что нет (замер 29.08.2026)
//!
//! Разбивка полной сборки ЕРП.УХ (132,5 с) по этапам:
//!
//! | этап | время | ускоряется инкрементом |
//! |---|---|---|
//! | индексы SQLite | 48,4 с (37%) | **нет** — строятся по итоговым таблицам |
//! | разбор модулей | 25,1 с (19%) | да, пропорционально числу правок |
//! | метаданные (XML) | 18,5 с (14%) | да |
//! | разрешение имён | 10,4 с (8%) | **нет** — резолвинг видит весь корпус |
//! | обход дерева | 10,2 с (8%) | частично |
//! | семантика | 7,9 с (6%) | **нет** — IDF считается по корпусу |
//!
//! Отсюда честная оценка: инкремент снимает около 43% времени, а не «почти
//! всё». Обещать разы было бы враньём — платятся 57% при любой правке.
//! Выигрыш здесь берётся не с индексов, а с того, что при правке ОДНОГО
//! модуля не перечитываются и не переразбираются остальные 18 тысяч.
//!
//! # Почему индексы SQLite не пересобираются
//!
//! Они уже построены в индексе и переживают точечные `INSERT`/`DELETE`:
//! B-дерево обновляется на изменённых строках, а не строится заново. Это
//! ровно та причина, по которой полная сборка строит их ПОСЛЕ наполнения,
//! а инкремент — не трогает вовсе. Те самые 48 секунд платит только
//! сборка с нуля.
//!
//! # Что переписывается при правке одного модуля
//!
//! К модулю привязаны шесть таблиц (сверено по живому индексу ДО, а не по
//! памяти о схеме): `modules`, `methods`, `methods_fts`, `calls`, `regions`,
//! `module_headers`, плюс `metadata_code_usages` и строка в `file_paths`.
//! Остальные двадцать таблиц наполняются из XML метаданных и правкой `.bsl`
//! не затрагиваются.
//!
//! # Чего инкремент НЕ делает — и почему это сказано вслух
//!
//! * **не пересчитывает семантику.** Векторы имён считаются по IDF всего
//!   корпуса; правка одного модуля сдвигает частоты на доли процента, но
//!   пересчёт стоит 8 секунд. Новый метод в поиске по смыслу появится
//!   после следующей полной сборки — это цена, и она названа;
//! * **не переиндексирует XML метаданных.** Изменение `.xml` в инкремент
//!   не принимается вовсе: правка одного файла метаданных задевает
//!   `metadata_references`, `subsystem_content`, `object_synonyms` и ещё
//!   десяток таблиц перекрёстными ссылками, и выборочная чистка там даёт
//!   не ускорение, а тихо расходящийся индекс. Такая правка честно требует
//!   полной сборки, и функция говорит об этом отказом;
//! * **не перерешает рёбра, ведущие В изменённый модуль.** Если в модуле
//!   появился экспортный метод, вызовы к нему из ДРУГИХ модулей остались
//!   в классе `unknown`. Пересчёт их — это резолвинг всего корпуса,
//!   те самые 10 секунд. Счётчик расхождения возвращается в отчёте, чтобы
//!   решение принималось по числу, а не на ощупь.
//!
//! Это не оговорки для документации, а условия применимости: инкремент
//! годится для «поправил модуль — хочу видеть новый метод», и не годится
//! как замена полной сборке.

use crate::resolve::{self, MethodRef, ResolveTables};
use crate::IndexError;
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

type Result<T> = std::result::Result<T, IndexError>;

/// Что сделал инкремент. Числа, а не «готово».
#[derive(Debug, Clone, Default)]
pub struct IncrementReport {
    /// Модулей переиндексировано.
    pub modules: usize,
    /// Модулей добавлено (в индексе их не было).
    pub added: usize,
    /// Модулей удалено (файла больше нет).
    pub removed: usize,
    /// Методов после пересборки этих модулей.
    pub methods: usize,
    /// Рёбер вызовов, переписанных заново.
    pub calls: usize,
    /// Рёбер класса `unknown`, ведущих в переиндексированные модули.
    ///
    /// Это ЦЕНА инкремента, названная числом: вызовы из других модулей
    /// к новым экспортным методам остались неразрешёнными и станут
    /// разрешёнными только после полной сборки. Ноль — цены нет.
    pub stale_edges: usize,
    pub elapsed_ms: u64,
}

/// Переиндексировать заданные модули в существующем индексе.
///
/// `files` — абсолютные пути к `.bsl`. Файл, которого больше нет на диске,
/// удаляется из индекса; которого не было в индексе — добавляется.
///
/// # Отказы
///
/// * индекс не открывается или несовместим по версии схемы;
/// * среди путей есть не-`.bsl` — инкремент по метаданным не поддержан
///   намеренно (см. обзор модуля), и молчаливо пропустить такой файл
///   значит оставить индекс расходящимся с исходниками, о чём никто
///   не узнает.
pub fn update(db: &Path, src: &Path, files: &[std::path::PathBuf]) -> Result<IncrementReport> {
    let started = Instant::now();
    let mut report = IncrementReport::default();

    if let Some(чужой) = files.iter().find(|p| {
        !p.extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| x.eq_ignore_ascii_case("bsl"))
    }) {
        return Err(IndexError::Unsupported(format!(
            "инкремент принимает только .bsl, получен {}. Правка метаданных \
             требует полной сборки: она задевает таблицы перекрёстными ссылками, \
             и выборочная чистка даёт расходящийся индекс",
            чужой.display()
        )));
    }

    let mut conn = Connection::open(db)?;

    // Совместимость проверяется ДО правок: писать в индекс чужой версии
    // значит смешать две схемы в одном файле и получить состояние, из
    // которого нет выхода, кроме полной пересборки.
    let info = crate::build::info(db)?;
    if !info.is_readable() {
        return Err(IndexError::Unsupported(format!(
            "индекс версии схемы {} не обновляется этим кодом (нужна {}..={})",
            info.schema_version,
            crate::ddl::MIN_READABLE_SCHEMA,
            crate::ddl::SCHEMA_VERSION
        )));
    }

    // --- разбор изменившихся ---
    let mut разобранные = Vec::new();
    let mut удаляемые = Vec::new();
    for path in files {
        // Тот же адрес, что пишет полная сборка: файл расширения — `../ext/…`.
        let rel = crate::extensions::rel_from(src, path);
        if !path.is_file() {
            удаляемые.push(rel);
            continue;
        }
        match crate::build::read_and_parse(src, path) {
            Some(d) => разобранные.push(d),
            // Нечитаемый файл НЕ удаляется из индекса: «не смог прочитать»
            // и «файла нет» — разные вещи, и первое не повод забыть о нём.
            None => continue,
        }
    }

    // --- карта резолвинга: из ИНДЕКСА, а не повторным разбором корпуса ---
    //
    // Здесь и живёт выигрыш. Резолверу нужны все методы конфигурации, но
    // они уже лежат в `methods` — читать их SQL-запросом на порядок дешевле,
    // чем заново разобрать 18 тысяч модулей ради той же карты.
    let tables = собрать_таблицы(&conn)?;

    // Индекс по `caller_id` мог не существовать: базы, собранные до вехи 7,
    // его не имеют, а без него КАЖДАЯ чистка рёбер модуля идёт полным
    // перебором `calls` (7,69 с на 5,6 млн строк ЕРП.УХ против 0,000 с).
    // Создаём молча: `IF NOT EXISTS` на уже существующем стоит ноль,
    // а один раз построить его дешевле (3 с), чем платить перебором.
    conn.execute_batch("CREATE INDEX IF NOT EXISTS idx_calls_caller ON calls(caller_id);")?;

    let tx = conn.transaction()?;
    {
        // --- следующие свободные id: считаются ДО удаления ---
        //
        // Порядок не косметика, а суть. Посчитай их после — и `MAX(id)+1`
        // вернёт значение, только что освободившееся удалением; новый метод
        // получил бы id старого, а чужие рёбра `calls`, ссылающиеся на
        // прежний, молча привязались бы к нему. Поймано тестом
        // `id_не_переиспользуются`: было max 2, стало min 2.
        let mut след_модуль: i64 =
            tx.query_row("SELECT IFNULL(MAX(id),0) + 1 FROM modules", [], |r| {
                r.get(0)
            })?;
        let mut след_метод: i64 =
            tx.query_row("SELECT IFNULL(MAX(id),0) + 1 FROM methods", [], |r| {
                r.get(0)
            })?;

        // --- удаление старых строк ---
        //
        // Порядок важен: `calls` ссылается на `methods`, `methods` — на
        // `modules`. Чистим от листьев к корню.
        for rel in разобранные
            .iter()
            .map(|d| d.rel_path.clone())
            .chain(удаляемые.iter().cloned())
        {
            let id: Option<i64> = tx
                .query_row(
                    "SELECT id FROM modules WHERE rel_path = ?1",
                    rusqlite::params![rel],
                    |r| r.get(0),
                )
                .ok();
            let Some(id) = id else {
                continue;
            };
            tx.execute(
                "DELETE FROM calls WHERE caller_id IN (SELECT id FROM methods WHERE module_id = ?1)",
                rusqlite::params![id],
            )?;
            // FTS чистится ОТДЕЛЬНО: это виртуальная таблица, каскада по
            // внешнему ключу у неё нет, и осиротевшая строка в ней
            // отвечает на поиск именем удалённого метода.
            tx.execute(
                "DELETE FROM methods_fts WHERE rowid IN (SELECT id FROM methods WHERE module_id = ?1)",
                rusqlite::params![id],
            )?;
            tx.execute(
                "DELETE FROM methods WHERE module_id = ?1",
                rusqlite::params![id],
            )?;
            tx.execute(
                "DELETE FROM regions WHERE module_id = ?1",
                rusqlite::params![id],
            )?;
            tx.execute(
                "DELETE FROM module_headers WHERE module_id = ?1",
                rusqlite::params![id],
            )?;
            let _ = tx.execute(
                "DELETE FROM metadata_code_usages WHERE module_id = ?1",
                rusqlite::params![id],
            );
            tx.execute(
                "DELETE FROM file_paths WHERE rel_path = ?1",
                rusqlite::params![rel],
            )?;
            tx.execute("DELETE FROM modules WHERE id = ?1", rusqlite::params![id])?;
        }
        report.removed = удаляемые.len();

        // --- вставка заново ---
        //
        // id раздаются продолжением существующих, а не с единицы: чужие
        // рёбра ссылаются на прежние значения, и переиспользование
        // освободившегося id молча привязало бы старый вызов к новому методу.
        for d in &разобранные {
            let module_id = след_модуль;
            след_модуль += 1;
            report.added += 1;

            tx.execute(
                "INSERT INTO modules (id, rel_path, category, object_name, module_type,
                                      form_name, is_form, size)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                rusqlite::params![
                    module_id,
                    d.rel_path,
                    d.info.category,
                    d.info.object_name,
                    d.info.module_type,
                    d.info.form_name,
                    i32::from(d.info.is_form),
                    d.size as i64,
                ],
            )?;
            if let Some(h) = &d.parsed.header_comment {
                tx.execute(
                    "INSERT INTO module_headers (module_id, header_comment) VALUES (?1,?2)",
                    rusqlite::params![module_id, h],
                )?;
            }
            let (dir, file) = раздел_пути(&d.rel_path);
            tx.execute(
                "INSERT INTO file_paths (rel_path, extension, dir_path, filename, depth, size)
                 VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![
                    d.rel_path,
                    "bsl",
                    dir,
                    file,
                    d.rel_path.matches('/').count() as i64,
                    d.size as i64
                ],
            )?;

            let первый_метод = след_метод;
            for m in &d.parsed.methods {
                tx.execute(
                    "INSERT INTO methods (id, module_id, name, type, is_export, params,
                                          line, end_line, loc)
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    rusqlite::params![
                        след_метод,
                        module_id,
                        m.name,
                        m.kind,
                        i32::from(m.is_export),
                        m.params,
                        m.line_start as i64,
                        m.line_end as i64,
                        m.loc() as i64,
                    ],
                )?;
                tx.execute(
                    "INSERT INTO methods_fts (rowid, name) VALUES (?1,?2)",
                    rusqlite::params![след_метод, m.name],
                )?;
                след_метод += 1;
                report.methods += 1;
            }
            for r in &d.parsed.regions {
                tx.execute(
                    "INSERT INTO regions (module_id, name, line, end_line) VALUES (?1,?2,?3,?4)",
                    rusqlite::params![module_id, r.name, r.line as i64, r.end_line.map(i64::from)],
                )?;
            }

            // --- рёбра исходящие ---
            for c in &d.parsed.calls {
                let Some(caller) = c.caller else { continue };
                let caller_id = первый_метод + caller as i64;
                let r = resolve::resolve(&c.name, &d.rel_path, &tables);
                tx.execute(
                    "INSERT INTO calls (caller_id, callee_name, callee_key, resolution, confidence)
                     VALUES (?1,?2,?3,?4,?5)",
                    rusqlite::params![
                        caller_id,
                        r.callee_name,
                        r.callee_key,
                        r.resolution.as_str(),
                        r.confidence
                    ],
                )?;
                report.calls += 1;
            }
        }

        // --- цена инкремента, названная числом ---
        //
        // Рёбра из ДРУГИХ модулей, чьё имя совпадает с методом только что
        // переиндексированного модуля, но класс остался `unknown`. Они
        // разрешатся лишь при полной сборке; молчать об этом нельзя —
        // «не найдено» тогда читалось бы как факт о конфигурации.
        let имена: HashSet<&str> = разобранные
            .iter()
            .flat_map(|d| d.parsed.methods.iter().map(|m| m.name.as_str()))
            .collect();
        if !имена.is_empty() {
            let список: Vec<String> = имена.iter().map(|s| s.to_lowercase()).collect();
            let подстановки = vec!["?"; список.len()].join(",");
            let sql = format!(
                "SELECT count(*) FROM calls WHERE resolution = 'unknown'
                 AND lower(callee_name) IN ({подстановки})"
            );
            let params: Vec<&dyn rusqlite::ToSql> =
                список.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
            report.stale_edges = tx
                .query_row(&sql, params.as_slice(), |r| r.get::<_, i64>(0))
                .unwrap_or(0) as usize;
        }
    }
    tx.commit()?;

    report.modules = разобранные.len();
    // Индекс перестал соответствовать своему `built_at`: часть его собрана
    // сейчас, часть — раньше. Отметка обновляется, иначе сторож свежести
    // будет вечно показывать отставание по только что учтённым файлам.
    отметить_обновление(&conn, src)?;

    report.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(report)
}

/// Записать, что индекс обновлён: время и коммит.
fn отметить_обновление(conn: &Connection, src: &Path) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    conn.execute(
        "INSERT OR REPLACE INTO index_meta (key, value) VALUES ('built_at', ?1)",
        rusqlite::params![now.to_string()],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO index_meta (key, value) VALUES ('git_commit', ?1)",
        rusqlite::params![crate::git::head(src).unwrap_or_default()],
    )?;
    // Отдельная отметка: индекс собран не одним заходом. Полезна, когда
    // «должно было найтись, а не нашлось» — инкремент не пересчитывает
    // семантику и не перерешает входящие рёбра.
    conn.execute(
        "INSERT OR REPLACE INTO index_meta (key, value) VALUES ('incremental', '1')",
        [],
    )?;
    Ok(())
}

/// Восстановить карту резолвинга из индекса.
///
/// Дешёвая замена повторному разбору корпуса: те же данные лежат в
/// `modules`+`methods`, и SQL отдаёт их за доли секунды против десятков
/// секунд на разбор.
fn собрать_таблицы(conn: &Connection) -> Result<ResolveTables> {
    let mut t = ResolveTables::default();

    // Классификация берётся тем же `classify`, что и в полной сборке, а не
    // сравнением категории со строкой: строку я бы угадывал, а функция —
    // единственный источник правды о том, что считается общим модулем.
    let mut st = conn.prepare(
        "SELECT m.rel_path, me.name, me.is_export, me.id
         FROM modules m JOIN methods me ON me.module_id = m.id
         ORDER BY m.id",
    )?;
    let mut rows = st.query([])?;
    let mut по_модулю: HashMap<String, HashMap<String, MethodRef>> = HashMap::new();
    while let Some(r) = rows.next()? {
        let rel: String = r.get(0)?;
        let имя: String = r.get(1)?;
        let экспорт: i64 = r.get(2)?;
        let method_id: i64 = r.get(3)?;

        // `MethodRef` несёт только id и признак экспорта — ровно то, что
        // лежит в `methods`. Резолвер отвечает «какой метод», а не «где он».
        t.defined_anywhere.insert(имя.to_lowercase());
        по_модулю.entry(rel).or_default().insert(
            имя.to_lowercase(),
            MethodRef {
                method_id,
                is_export: экспорт != 0,
            },
        );
    }

    // Порядок как в полной сборке: сначала основная конфигурация, потом
    // расширения, и модуль расширения занимает имя, только если оно свободно
    // (Р-022). Обход `HashMap` в произвольном порядке отдал бы имя заимствованного
    // общего модуля то основной конфигурации, то расширению — от запуска к запуску.
    let mut модули: Vec<(String, HashMap<String, MethodRef>)> = по_модулю.into_iter().collect();
    // Раскладка — по записанному реестру: здесь виден индекс, а не диск, и
    // имя расширения по одной форме адреса не определить (см. `Раскладка`).
    let раскладка = crate::extensions::Раскладка::из_индекса(conn)?;
    модули.sort_by_key(|(rel, _)| rel.starts_with("../"));
    for (rel, методы) in модули {
        let из_расширения = rel.starts_with("../");
        let info = crate::classify::classify(раскладка.внутри(&rel));
        let занять = |карта: &mut HashMap<String, (String, HashMap<String, MethodRef>)>,
                      имя: &str| {
            let запись = (rel.clone(), методы.clone());
            if из_расширения {
                карта.entry(имя.to_lowercase()).or_insert(запись);
            } else {
                карта.insert(имя.to_lowercase(), запись);
            }
        };
        if crate::classify::is_common_module(&info) {
            if let Some(имя) = &info.object_name {
                занять(&mut t.common_modules, имя);
            }
        }
        if crate::classify::is_manager_module(&info) {
            if let Some(имя) = &info.object_name {
                занять(&mut t.managers, имя);
            }
        }
        t.by_module.insert(rel, методы);
    }
    Ok(t)
}

fn раздел_пути(rel: &str) -> (String, String) {
    match rel.rsplit_once('/') {
        Some((d, f)) => (d.to_string(), f.to_string()),
        None => (String::new(), rel.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    /// Корпус из двух модулей: общий и объектный, со связью между ними.
    struct Корпус(PathBuf);

    impl Корпус {
        fn новый(метка: &str) -> Self {
            let d = std::env::temp_dir().join(format!("gyrfalcon-incr-{метка}"));
            let _ = fs::remove_dir_all(&d);
            let общий = d.join("CommonModules/Расчёты/Ext");
            fs::create_dir_all(&общий).unwrap();
            fs::write(
                d.join("Configuration.xml"),
                "<MetaDataObject><Configuration><Properties><Name>Тест</Name>\
                 </Properties></Configuration></MetaDataObject>",
            )
            .unwrap();
            fs::write(
                общий.join("Module.bsl"),
                "Функция Посчитать(А) Экспорт\n\tВозврат А;\nКонецФункции\n",
            )
            .unwrap();
            let объект = d.join("Catalogs/Номенклатура/Ext/ObjectModule");
            fs::create_dir_all(&объект).unwrap();
            fs::write(
                объект.join("Module.bsl"),
                "Процедура ПередЗаписью(Отказ)\n\tРасчёты.Посчитать(1);\nКонецПроцедуры\n",
            )
            .unwrap();
            Self(d)
        }
        fn путь(&self) -> &Path {
            &self.0
        }
        fn общий(&self) -> PathBuf {
            self.0.join("CommonModules/Расчёты/Ext/Module.bsl")
        }
        fn индекс(&self) -> PathBuf {
            self.0.join("index.db")
        }
        fn собрать(&self) {
            crate::build::build(self.путь(), &self.индекс(), None).unwrap();
        }
    }

    impl Drop for Корпус {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn счёт(db: &Path, sql: &str) -> i64 {
        let c = Connection::open(db).unwrap();
        c.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn новый_метод_появляется_после_инкремента() {
        let к = Корпус::новый("новый-метод");
        к.собрать();
        assert_eq!(
            счёт(
                &к.индекс(),
                "SELECT count(*) FROM methods WHERE name='Проверить'"
            ),
            0
        );

        fs::write(
            к.общий(),
            "Функция Посчитать(А) Экспорт\n\tВозврат А;\nКонецФункции\n\
             Функция Проверить() Экспорт\n\tВозврат Истина;\nКонецФункции\n",
        )
        .unwrap();
        let r = update(&к.индекс(), к.путь(), &[к.общий()]).unwrap();

        assert_eq!(r.modules, 1);
        assert_eq!(r.methods, 2);
        assert_eq!(
            счёт(
                &к.индекс(),
                "SELECT count(*) FROM methods WHERE name='Проверить'"
            ),
            1,
            "новый метод обязан появиться"
        );
    }

    #[test]
    fn удалённый_метод_исчезает_и_из_поиска() {
        // Осиротевшая строка в FTS — тот дефект, что не виден в `methods`,
        // но отвечает на поиск именем, которого больше нет.
        let к = Корпус::новый("удаление");
        к.собрать();
        assert_eq!(
            счёт(
                &к.индекс(),
                "SELECT count(*) FROM methods_fts WHERE name MATCH 'Посчитать'"
            ),
            1
        );

        fs::write(
            к.общий(),
            "Функция Иная() Экспорт\n\tВозврат 0;\nКонецФункции\n",
        )
        .unwrap();
        update(&к.индекс(), к.путь(), &[к.общий()]).unwrap();

        assert_eq!(
            счёт(
                &к.индекс(),
                "SELECT count(*) FROM methods WHERE name='Посчитать'"
            ),
            0
        );
        assert_eq!(
            счёт(
                &к.индекс(),
                "SELECT count(*) FROM methods_fts WHERE name MATCH 'Посчитать'"
            ),
            0,
            "FTS обязана чиститься вместе с methods"
        );
    }

    #[test]
    fn пропавший_файл_убирается_из_индекса() {
        let к = Корпус::новый("пропажа");
        к.собрать();
        let было = счёт(&к.индекс(), "SELECT count(*) FROM modules");

        fs::remove_file(к.общий()).unwrap();
        let r = update(&к.индекс(), к.путь(), &[к.общий()]).unwrap();

        assert_eq!(r.removed, 1);
        assert_eq!(счёт(&к.индекс(), "SELECT count(*) FROM modules"), было - 1);
    }

    #[test]
    fn рёбра_старого_модуля_не_остаются_сиротами() {
        let к = Корпус::новый("сироты");
        к.собрать();
        let было = счёт(&к.индекс(), "SELECT count(*) FROM calls");
        assert!(
            было > 0,
            "корпус обязан давать рёбра, иначе тест ничего не проверяет"
        );

        update(&к.индекс(), к.путь(), &[к.общий()]).unwrap();
        let осиротевшие = счёт(
            &к.индекс(),
            "SELECT count(*) FROM calls c
             WHERE NOT EXISTS (SELECT 1 FROM methods m WHERE m.id = c.caller_id)",
        );
        assert_eq!(осиротевшие, 0, "ребро без источника — сломанный граф");
    }

    #[test]
    fn метаданные_в_инкремент_не_принимаются() {
        // Отказ, а не тихий пропуск: пропущенный .xml оставил бы индекс
        // расходящимся с исходниками, и никто бы об этом не узнал.
        let к = Корпус::новый("xml");
        к.собрать();
        let ошибка = update(
            &к.индекс(),
            к.путь(),
            &[к.путь().join("Catalogs/Номенклатура.xml")],
        )
        .unwrap_err();
        let текст = ошибка.to_string();
        assert!(текст.contains("только .bsl"), "{текст}");
        assert!(
            текст.contains("полной сборки"),
            "отказ обязан говорить, что делать: {текст}"
        );
    }

    #[test]
    fn отметка_свежести_обновляется_после_инкремента() {
        // Иначе сторож свежести вечно показывал бы отставание по файлам,
        // которые инкремент только что учёл.
        let к = Корпус::новый("свежесть");
        к.собрать();
        fs::write(
            к.общий(),
            "Функция Посчитать(А) Экспорт\n\tВозврат А + 1;\nКонецФункции\n",
        )
        .unwrap();
        update(&к.индекс(), к.путь(), &[к.общий()]).unwrap();

        let info = crate::build::info(&к.индекс()).unwrap();
        let f = info.freshness();
        assert!(
            !f.stale,
            "после инкремента индекс не отстал: {:?}",
            f.note()
        );
    }

    #[test]
    fn id_не_переиспользуются() {
        // Освободившийся id, отданный новому методу, молча привязал бы к нему
        // чужие старые рёбра.
        let к = Корпус::новый("иды");
        к.собрать();
        let макс_до: i64 = счёт(&к.индекс(), "SELECT MAX(id) FROM methods");

        fs::write(
            к.общий(),
            "Функция Посчитать(А) Экспорт\n\tВозврат А;\nКонецФункции\n",
        )
        .unwrap();
        update(&к.индекс(), к.путь(), &[к.общий()]).unwrap();

        let мин_после: i64 = счёт(
            &к.индекс(),
            "SELECT MIN(me.id) FROM methods me JOIN modules m ON m.id = me.module_id
             WHERE m.rel_path LIKE 'CommonModules%'",
        );
        assert!(
            мин_после > макс_до,
            "id переиспользован: было max {макс_до}, стало min {мин_после}"
        );
    }
}
