//! Детерминированный SQLite-индекс конфигурации 1С.
//!
//! Ядро замысла: агент не читает файлы конфигурации, а спрашивает индекс.
//! Тела модулей остаются на сервере — наружу идут выжимки.
//!
//! # Состояние
//!
//! Вехи 1-3 закрыты: разбор, граф вызовов и **27 содержательных таблиц
//! метаданных из 27** — паритет с прежним инструментом поимённо, включая перехваты
//! расширений с адресом.
//!
//! Веха 4 закрыта: **семантический поиск**. Его таблицы (`semantic_*`,
//! `*_fts`) в опись переноса `schema::TABLES` не входят намеренно — у прежнего инструмента
//! семантики нет вовсе, и счётчик «27 из 27» означает перенос, а не общий
//! объём. Это первое, что сервер делает сверх прежнего инструмента.
//!
//! Дальше — веха 5: MCP-сервер и развилка о батчинге.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("не реализовано: {0}")]
    NotImplemented(&'static str),
    #[error("модулей .bsl не найдено: {0}")]
    NoModules(String),
    /// В корне нет `Configuration.xml` — это не выгрузка конфигурации
    /// (не тот каталог, недовыгрузка). Отказ, а не индекс из нулей.
    #[error(
        "в корне нет Configuration.xml: {0} — это не выгрузка конфигурации в файлы; \
         укажите каталог, где лежит Configuration.xml основной конфигурации"
    )]
    NoConfiguration(String),
    #[error("ошибка ввода-вывода: {0}")]
    Io(#[from] std::io::Error),
    #[error("ошибка SQLite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Операция неприменима к этим данным — с объяснением, что делать вместо.
    /// Не «сломалось», а «так нельзя»: инкремент по XML метаданных,
    /// индекс несовместимой версии схемы.
    #[error("{0}")]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, IndexError>;

pub mod build;
pub mod classify;
pub mod ddl;
pub mod extensions;
pub mod forms;
pub mod freshness;
pub mod git;
pub mod help;
pub mod incremental;
pub mod integration;
pub mod meta;
pub mod meta2;
pub mod rank;
pub mod refs;
pub mod resolve;
pub mod schema;
pub mod semantic;

pub use build::{build, BuildReport};
