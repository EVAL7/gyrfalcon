//! Разбор исходников 1С:Предприятие.
//!
//! Два разных предмета под одной крышей:
//!
//! * **BSL** — код модулей. Разбор через tree-sitter, грамматика vendored
//!   (см. `vendor/tree-sitter-bsl/PROVENANCE.md`).
//! * **XML-выгрузка** — метаданные: объекты, реквизиты с типами, формы, роли,
//!   движения регистров, подписки на события. Пока не реализовано.
//!
//! # Правило заглушек
//!
//! Нереализованное возвращает [`ParseError::NotImplemented`], а не пустой результат.
//! Пустой `Vec` от ненаписанного разбора неотличим от честного «в модуле нет методов».

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("не реализовано: {0}")]
    NotImplemented(&'static str),
    #[error("не удалось загрузить грамматику: {0}")]
    Language(String),
    #[error("разбор не дал дерева")]
    NoTree,
    #[error("ошибка ввода-вывода: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ParseError>;

pub mod bsl;
pub mod module;
pub mod scan;
pub mod scope;
pub mod tokens;
pub mod usages;

/// Разбор XML-выгрузки: метаданные конфигурации.
pub mod metadata {
    use super::{ParseError, Result};

    /// Объект метаданных: справочник, документ, регистр и т.д.
    #[derive(Debug, Clone)]
    pub struct MetadataObject {
        pub kind: String,
        pub name: String,
        pub synonym: Option<String>,
        pub uuid: Option<String>,
    }

    /// Разобрать XML объекта метаданных.
    ///
    /// Должен учитывать, что объект бывает выгружен **плоским XML** — файлом
    /// `Catalogs/Имя.xml` без каталога-спутника `Catalogs/Имя/`. Так выгружаются
    /// объекты без форм и модулей, и обход только по каталогам их теряет.
    pub fn parse_object(_xml: &str) -> Result<MetadataObject> {
        Err(ParseError::NotImplemented("metadata::parse_object"))
    }
}
