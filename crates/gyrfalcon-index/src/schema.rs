//! Опись таблиц индекса.
//!
//! # Откуда взято
//!
//! Снято с **живого индекса** работающего Python-сервера (`sqlite_master`),
//! а не выведено из его исходников и не спроектировано заново.
//!
//! Эталонный корпус — крупнейшая из доступных конфигураций: 91 830 файлов
//! выгрузки, 6,2 ГБ, 18 230 модулей BSL; индекс весит 1,7 ГБ. Числа строк
//! фактические и стоят здесь как свидетельство масштаба, а не как норматив:
//! на другой конфигурации они будут другими, а вот СОСТАВ таблиц — тот же.
//!
//! Служебные таблицы SQLite (`sqlite_sequence`, `sqlite_stat1`) и обвязка FTS5
//! (`methods_fts_*` — шесть таблиц одной виртуальной) в опись не входят:
//! они появятся сами при создании индексов и полнотекстового поиска.
//!
//! # Зачем опись отдельным списком
//!
//! Схема переносится **как есть**. Это накопленное знание о частностях 1С —
//! права ролей, движения регистров, перехваты расширений, функциональные опции,
//! предопределённые элементы. Опись служит чек-листом переноса: пока таблица
//! не реализована, видно, что её нет.

/// Таблица индекса: имя, назначение и порядок величины на крупной конфигурации.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Table {
    /// Имя таблицы в SQLite.
    pub name: &'static str,
    /// Что хранит.
    pub purpose: &'static str,
    /// Строк в прежний инструментном индексе (замер 28.08.2026).
    pub reference_rows: u64,
    /// Реализована ли в этом сервере.
    pub implemented: bool,
}

/// Полная опись содержательных таблиц — 27 штук.
pub const TABLES: &[Table] = &[
    // --- код ---
    Table {
        name: "modules",
        purpose: "модули конфигурации и расширений",
        reference_rows: 18_230,
        implemented: true,
    },
    Table {
        name: "module_headers",
        purpose: "шапки модулей: директивы компиляции",
        reference_rows: 1_188,
        implemented: true,
    },
    Table {
        name: "methods",
        purpose: "процедуры и функции с границами строк",
        reference_rows: 530_879,
        implemented: true,
    },
    Table {
        name: "calls",
        purpose: "рёбра графа вызовов",
        reference_rows: 2_929_197,
        implemented: true,
    },
    Table {
        name: "regions",
        purpose: "области #Область внутри модулей",
        reference_rows: 70_725,
        implemented: true,
    },
    Table {
        name: "file_paths",
        purpose: "файлы выгрузки: путь, хэш, размер",
        reference_rows: 83_795,
        implemented: true,
    },
    // --- метаданные ---
    Table {
        name: "object_attributes",
        purpose: "реквизиты объектов с типами и квалификаторами",
        reference_rows: 43_157,
        implemented: true,
    },
    Table {
        name: "object_synonyms",
        purpose: "синонимы объектов и полей",
        reference_rows: 13_636,
        implemented: true,
    },
    Table {
        name: "predefined_items",
        purpose: "предопределённые элементы справочников",
        reference_rows: 3_468,
        implemented: true,
    },
    Table {
        name: "enum_values",
        purpose: "значения перечислений",
        reference_rows: 1_132,
        implemented: true,
    },
    Table {
        name: "defined_types",
        purpose: "определяемые типы",
        reference_rows: 481,
        implemented: true,
    },
    Table {
        name: "characteristic_types",
        purpose: "планы видов характеристик",
        reference_rows: 8,
        implemented: true,
    },
    Table {
        name: "subsystem_content",
        purpose: "состав подсистем",
        reference_rows: 18_463,
        implemented: true,
    },
    Table {
        name: "form_elements",
        purpose: "элементы управляемых форм",
        reference_rows: 223_291,
        implemented: true,
    },
    // --- связи и поведение ---
    Table {
        name: "metadata_references",
        purpose: "ссылки между объектами метаданных",
        reference_rows: 88_186,
        implemented: true,
    },
    Table {
        name: "metadata_code_usages",
        purpose: "упоминания объектов метаданных в коде",
        reference_rows: 259_401,
        implemented: true,
    },
    Table {
        name: "register_movements",
        purpose: "какой документ пишет в какой регистр",
        reference_rows: 364,
        implemented: true,
    },
    Table {
        name: "event_subscriptions",
        purpose: "подписки на события и их обработчики",
        reference_rows: 447,
        implemented: true,
    },
    Table {
        name: "scheduled_jobs",
        purpose: "регламентные задания",
        reference_rows: 168,
        implemented: true,
    },
    Table {
        name: "functional_options",
        purpose: "функциональные опции и их состав",
        reference_rows: 496,
        implemented: true,
    },
    // --- права ---
    Table {
        name: "role_rights",
        purpose: "права ролей по объектам, включая RLS",
        reference_rows: 48_458,
        implemented: true,
    },
    // --- расширения ---
    Table {
        name: "extension_overrides",
        purpose: "перехваты расширений с адресом: модуль+строка",
        // У прежнего инструмента по БП 0 строк — расширений там нет вовсе. Эталон взят
        // на ДО: 9 расширений, 13 перехватов, паритет поимённо по всем
        // 11 содержательным колонкам (28.08.2026).
        reference_rows: 13,
        implemented: true,
    },
    // --- интеграция ---
    Table {
        name: "xdto_packages",
        purpose: "пакеты XDTO",
        reference_rows: 434,
        implemented: true,
    },
    Table {
        name: "web_services",
        purpose: "web-сервисы",
        reference_rows: 17,
        implemented: true,
    },
    Table {
        name: "http_services",
        purpose: "HTTP-сервисы",
        reference_rows: 9,
        implemented: true,
    },
    Table {
        name: "exchange_plan_content",
        purpose: "состав планов обмена",
        reference_rows: 12_260,
        implemented: true,
    },
    // --- служебное для самого индекса ---
    Table {
        name: "index_meta",
        purpose: "версия индекса, источник, время сборки",
        reference_rows: 30,
        implemented: true,
    },
];

/// Таблицы сверх описи переноса — то, чего у прежнего инструмента нет.
///
/// Отдельным списком, а не дописаны в [`TABLES`]: та опись — чек-лист
/// переноса, и её счётчик «27 из 27» говорит о паритете. Но инструмент
/// `schema` строит по описи список таблиц для агента, и таблица вне всякой
/// описи для него не существует — спросить её через `sql` он не догадается.
/// `reference_rows` здесь — замер на БП (сборка 13.10.2026), а не на
/// индексе предшественника.
pub const OWN_TABLES: &[Table] = &[Table {
    name: "common_modules",
    purpose: "флаги общих модулей: клиент, сервер, вызов сервера, глобальный",
    reference_rows: 3_437,
    implemented: true,
}];

/// Сколько таблиц уже реализовано.
pub fn implemented_count() -> usize {
    TABLES.iter().filter(|t| t.implemented).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn опись_содержит_27_таблиц() {
        assert_eq!(TABLES.len(), 27);
    }

    #[test]
    fn имена_таблиц_уникальны() {
        let mut names: Vec<_> = TABLES.iter().map(|t| t.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "в описи есть повторяющиеся имена");
    }

    #[test]
    fn реализовано_ядро_вехи_3() {
        // Веха 2: шесть таблиц кода плюс index_meta. Веха 3, ядро: семь
        // таблиц метаданных. Тест падает при любом изменении числа и
        // заставляет обновить README вместе с кодом.
        assert_eq!(implemented_count(), 27);
    }

    #[test]
    fn таблицы_ядра_метаданных_реализованы_поимённо() {
        for name in [
            "object_attributes",
            "object_synonyms",
            "predefined_items",
            "enum_values",
            "defined_types",
            "characteristic_types",
            "subsystem_content",
        ] {
            let t = TABLES.iter().find(|t| t.name == name).expect(name);
            assert!(t.implemented, "таблица {name} ядра вехи 3 не отмечена");
        }
    }

    #[test]
    fn таблицы_второй_части_метаданных_реализованы_поимённо() {
        for name in [
            "event_subscriptions",
            "scheduled_jobs",
            "functional_options",
            "role_rights",
            "exchange_plan_content",
        ] {
            let t = TABLES.iter().find(|t| t.name == name).expect(name);
            assert!(
                t.implemented,
                "таблица {name} второй части вехи 3 не отмечена"
            );
        }
    }

    #[test]
    fn нереализованное_видно_поимённо() {
        // Смысл описи: пока таблицы нет, это ВИДНО, а не выглядит как
        // «данных в конфигурации нет». Веха 3 закрыта 28.08.2026 —
        // остаток пуст, и тест сторожит именно это: новая таблица без
        // реализации обязана здесь всплыть.
        let остаток: Vec<_> = TABLES
            .iter()
            .filter(|t| !t.implemented)
            .map(|t| t.name)
            .collect();
        assert!(остаток.is_empty(), "остаток описи: {остаток:?}");
    }

    #[test]
    fn перехваты_расширений_реализованы() {
        let t = TABLES
            .iter()
            .find(|t| t.name == "extension_overrides")
            .expect("extension_overrides");
        assert!(t.implemented, "таблица перехватов не отмечена");
        // Эталон — ДО, а не БП: у прежнего инструмента по БП здесь ноль строк,
        // и «паритет» с нулём ничего не проверяет.
        assert_eq!(t.reference_rows, 13);
    }

    #[test]
    fn таблицы_интеграции_реализованы_поимённо() {
        for name in [
            "register_movements",
            "xdto_packages",
            "web_services",
            "http_services",
        ] {
            let t = TABLES.iter().find(|t| t.name == name).expect(name);
            assert!(t.implemented, "таблица {name} интеграции не отмечена");
        }
    }

    #[test]
    fn таблицы_кода_реализованы_поимённо() {
        for name in [
            "modules",
            "module_headers",
            "methods",
            "calls",
            "regions",
            "file_paths",
        ] {
            let t = TABLES.iter().find(|t| t.name == name).expect(name);
            assert!(t.implemented, "таблица {name} вехи 2 не отмечена");
        }
    }
}
