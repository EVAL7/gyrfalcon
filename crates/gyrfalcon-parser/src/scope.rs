//! Область видимости и контекст исполнения — сырьё для `check_bsl` (MCP-06).
//!
//! Здесь только то, что видно по ДЕРЕВУ: какие имена объявлены, какие голые
//! имена прочитаны, где стоит `Новый X`, какой директивой помечен метод.
//! Решение «это ошибка» принимает проверка, у которой есть справка платформы
//! и индекс конфигурации; разбор о них не знает и знать не должен.
//!
//! # Как в дереве выглядит то, что нам нужно
//!
//! Снято дампом на калибровочном модуле 13.10.2026, а не по `node-types.json`:
//!
//! ```text
//! preprocessor                 &НаКлиенте        ← директива — СОСЕД перед методом
//!   annotation
//! procedure_definition
//!   parameters / parameter / identifier          ← параметр
//!   assignment_statement / identifier            ← объявление присваиванием
//!   var_statement / identifier                   ← Перем внутри метода
//!   for_statement / identifier                   ← счётчик Для
//!   expression / identifier                      ← ЧТЕНИЕ голого имени
//!   access / identifier                          ← голова цепочки `Элементы.Поле`
//!   new_expression / identifier                  ← тип в `Новый Запрос(...)`
//! var_definition / variable_spec / identifier    ← Перем модуля
//! preprocessor                                   ← `#Если Сервер Тогда` ОБЪЕМЛЕТ код
//!   PREPROC_IF_KEYWORD
//!   expression / identifier   Сервер             ← не переменная
//! ```
//!
//! Колонка у tree-sitter — в БАЙТАХ. Наружу отдаём в символах, как
//! конфигуратор: в кириллице байт на символ два, и «(4,27)» вместо «(4,14)»
//! указывало бы в середину соседнего слова.

use crate::{ParseError, Result};
use tree_sitter::{Node, Parser};

/// Где исполняется метод — по директиве компиляции.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    /// `&НаКлиенте`: тонкий/веб-клиент, серверного API нет.
    Client,
    /// `&НаСервере`, `&НаСервереБезКонтекста`.
    Server,
    /// `&НаКлиентеНаСервереБезКонтекста`, `&НаКлиентеНаСервере`: код обязан
    /// компилироваться в обоих — но проверять «клиентскую» половину мы
    /// не берёмся: такой код обычно разведён `#Если`.
    Both,
    /// Директивы нет: контекст задаёт модуль, а не текст.
    Unspecified,
}

/// Голое имя, прочитанное в выражении.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameUse {
    pub name: String,
    pub line: u32,
    /// В символах, с единицы.
    pub column: u32,
}

/// `Новый X(...)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewUse {
    pub type_name: String,
    pub line: u32,
    pub column: u32,
}

/// Вызов: голый `Метод()` или квалифицированный `Модуль.Метод()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallUse {
    /// Квалификатор целиком (`ОбщегоНазначения`), пусто у голого вызова.
    pub qualifier: String,
    pub name: String,
    pub line: u32,
    pub column: u32,
}

/// Метод с тем, что объявлено и использовано внутри.
#[derive(Debug, Clone)]
pub struct MethodScope {
    pub name: String,
    pub context: Context,
    pub line_start: u32,
    /// Метод лежит внутри `#Если …` — его реальный контекст задаёт условие
    /// препроцессора, а не директива. Проверка контекста такие методы
    /// пропускает: молчание здесь дешевле ложной тревоги.
    pub under_preprocessor_if: bool,
    /// Имена, объявленные в методе: параметры, присваивания, `Перем`, счётчики.
    /// В нижнем регистре. BSL не знает блочной области — имя, присвоенное
    /// где угодно в методе, видно во всём методе.
    pub declared: Vec<String>,
    pub reads: Vec<NameUse>,
    pub news: Vec<NewUse>,
    pub calls: Vec<CallUse>,
    /// Строки внутри `#Если … #КонецЕсли` В ТЕЛЕ метода — их контекст
    /// задан условием, а не директивой.
    pub guarded_lines: Vec<(u32, u32)>,
}

/// Разобранная область видимости модуля.
#[derive(Debug, Clone, Default)]
pub struct ModuleScope {
    /// `Перем` модуля и имена, присвоенные в теле модуля (основная программа).
    /// Второе — уступка в сторону молчания: такие имена методам не видны,
    /// но лишнее имя здесь стоит пропуска, а недостающее — ложной тревоги.
    pub module_vars: Vec<String>,
    /// Имена методов модуля: голое имя метода законно как значение
    /// (`ОписаниеОповещения` его не требует, но `Выполнить` и подобное — да).
    pub method_names: Vec<String>,
    pub methods: Vec<MethodScope>,
    pub has_errors: bool,
}

/// Разобрать модуль.
pub fn parse(source: &str) -> Result<ModuleScope> {
    let mut parser = Parser::new();
    parser
        .set_language(&crate::bsl::language())
        .map_err(|e| ParseError::Language(e.to_string()))?;
    let tree = parser.parse(source, None).ok_or(ParseError::NoTree)?;
    Ok(разобрать(tree.root_node(), source))
}

fn разобрать(root: Node, source: &str) -> ModuleScope {
    let b = source.as_bytes();
    let mut out = ModuleScope {
        has_errors: root.has_error(),
        ..Default::default()
    };
    let mut контекст = Context::Unspecified;
    обойти_уровень(root, source, b, false, &mut контекст, &mut out);
    out.module_vars.sort();
    out.module_vars.dedup();
    out.method_names.sort();
    out.method_names.dedup();
    out
}

/// Обойти детей узла верхнего уровня (модуль или объемлющий `#Если`/`#Область`).
///
/// Директива `&НаКлиенте` — отдельный узел ПЕРЕД объявлением и относится к
/// следующему объявлению ПО ТЕКСТУ. Отсюда два правила, оба проверены тестами:
///
/// * объемлющий препроцессор прозрачен — `&НаКлиенте` перед `#Область`
///   достаётся первому методу внутри неё; поэтому `контекст` один на весь
///   обход, а не свой у каждого уровня;
/// * любой другой узел, кроме комментария, директиву гасит. Без этого
///   невостребованная директива доживала до первого метода ПОСЛЕ области:
///   ложное «клиентский метод» на ERP 13.10.2026 (модуль формы документа).
fn обойти_уровень(
    node: Node,
    source: &str,
    b: &[u8],
    под_если: bool,
    контекст: &mut Context,
    out: &mut ModuleScope,
) {
    let mut c = node.walk();
    for ch in node.children(&mut c) {
        match ch.kind() {
            "preprocessor" => {
                if let Some(к) = директива(ch, b) {
                    *контекст = к;
                    continue;
                }
                // Аннотация перехвата (`&После("Метод")`) стоит между
                // директивой и объявлением и директиву не гасит.
                if ребёнок(ch, "annotation").is_some() {
                    continue;
                }
                // `#Область` прозрачна; `#Если` — тоже по тексту, но под ним
                // контекст задаёт условие, и проверка такие методы пропускает.
                let это_если = первый_ребёнок(ch) == Some("PREPROC_IF_KEYWORD");
                обойти_уровень(ch, source, b, под_если || это_если, контекст, out);
            }
            "procedure_definition" | "function_definition" => {
                if let Some(m) = метод(ch, source, b, *контекст, под_если) {
                    out.method_names.push(m.name.to_lowercase());
                    out.methods.push(m);
                }
                *контекст = Context::Unspecified;
            }
            "line_comment" => {}
            // Служебные узлы самого препроцессора (ключевые слова, имя области,
            // условие `#Если`) директиву не гасят: это разметка, не код.
            k if node.kind() == "preprocessor"
                && (k.starts_with("PREPROC_")
                    || k == "THEN_KEYWORD"
                    || k == "identifier"
                    || k == "expression") => {}
            "var_definition" => {
                собрать_объявления(ch, b, &mut out.module_vars);
                *контекст = Context::Unspecified;
            }
            // Основная программа модуля.
            _ => {
                let mut объявлено = Vec::new();
                собрать_объявления(ch, b, &mut объявлено);
                out.module_vars.extend(объявлено);
                *контекст = Context::Unspecified;
            }
        }
    }
}

/// Первый ребёнок нужного вида. Дети собираются в `Vec`, потому что узел,
/// найденный прямо по итератору курсора, держит заём курсора дольше, чем
/// живёт сам курсор (тот же приём в `module::override_of`).
fn ребёнок<'t>(n: Node<'t>, kind: &str) -> Option<Node<'t>> {
    let mut c = n.walk();
    let дети: Vec<Node<'t>> = n.children(&mut c).collect();
    дети.into_iter().find(|d| d.kind() == kind)
}

fn первый_ребёнок(n: Node) -> Option<&'static str> {
    n.child(0).map(|c| c.kind())
}

/// Директива компиляции, если этот `preprocessor` — она.
///
/// Перехват расширения (`&Перед("Метод")`) имеет ту же форму, но со строкой;
/// он контекст не задаёт — директива при нём ставится отдельной строкой.
fn директива(n: Node, b: &[u8]) -> Option<Context> {
    let mut c = n.walk();
    let дети: Vec<Node> = n.children(&mut c).collect();
    let ann = дети.iter().find(|d| d.kind() == "annotation")?;
    if дети.iter().any(|d| d.kind() == "string") {
        // Перехват: контекст не трогаем, директива уже стоит строкой выше.
        return None;
    }
    let текст = ann
        .utf8_text(b)
        .ok()?
        .trim_start_matches('&')
        .trim()
        .to_lowercase();
    Some(match текст.as_str() {
        "наклиенте" | "atclient" => Context::Client,
        "насервере" | "насерверебезконтекста" | "atserver" | "atservernocontext" => {
            Context::Server
        }
        "наклиентенасерверебезконтекста"
        | "наклиентенасервере"
        | "atclientatservernocontext"
        | "atclientatserver" => Context::Both,
        _ => return None,
    })
}

fn метод(
    n: Node,
    source: &str,
    b: &[u8],
    context: Context,
    под_если: bool,
) -> Option<MethodScope> {
    let name = n
        .child_by_field_name("name")?
        .utf8_text(b)
        .ok()?
        .to_string();
    let mut m = MethodScope {
        name,
        context,
        line_start: n.start_position().row as u32 + 1,
        under_preprocessor_if: под_если,
        declared: Vec::new(),
        reads: Vec::new(),
        news: Vec::new(),
        calls: Vec::new(),
        guarded_lines: Vec::new(),
    };
    if let Some(params) = n.child_by_field_name("parameters") {
        let mut c = params.walk();
        for p in params.children(&mut c).filter(|p| p.kind() == "parameter") {
            if let Some(id) = ребёнок(p, "identifier") {
                if let Ok(t) = id.utf8_text(b) {
                    m.declared.push(t.to_lowercase());
                }
            }
        }
    }
    // Тело — всё, кроме имени и параметров.
    let mut c = n.walk();
    for ch in n.children(&mut c) {
        if ch.kind() == "parameters"
            || Some(ch.id()) == n.child_by_field_name("name").map(|x| x.id())
        {
            continue;
        }
        обойти_тело(ch, source, b, &mut m);
    }
    m.declared.sort();
    m.declared.dedup();
    Some(m)
}

/// Обход тела метода явным стеком: глубина чужого дерева неизвестна.
fn обойти_тело(start: Node, source: &str, b: &[u8], m: &mut MethodScope) {
    let mut stack = vec![start];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "preprocessor" => {
                if первый_ребёнок(n) == Some("PREPROC_IF_KEYWORD") {
                    m.guarded_lines.push((
                        n.start_position().row as u32 + 1,
                        n.end_position().row as u32 + 1,
                    ));
                }
                // Условие `#Если Сервер` — не чтение переменной: в тело
                // заходим, а выражение условия пропускаем.
                let mut c = n.walk();
                let мимо_условия = n.children(&mut c).filter(|d| d.kind() != "expression");
                stack.extend(мимо_условия);
                continue;
            }
            "assignment_statement" | "var_statement" | "for_statement" | "for_each_statement" => {
                объявленное_оператором(n, b, &mut m.declared);
            }
            // `Перем` внутри `#Область` в теле метода грамматика разбирает
            // формой уровня модуля (БП, `УчетНДСФормированиеОтчетности`:5468).
            "var_definition" => {
                собрать_объявления(n, b, &mut m.declared);
                continue;
            }
            "new_expression" => {
                if let Some(id) = ребёнок(n, "identifier") {
                    if let Ok(t) = id.utf8_text(b) {
                        let (line, column) = позиция(id, source);
                        m.news.push(NewUse {
                            type_name: t.to_string(),
                            line,
                            column,
                        });
                    }
                }
            }
            "method_call" => {
                if let Some(c) = вызов(n, source, b) {
                    m.calls.push(c);
                }
            }
            "identifier" if читается(n) => {
                if let Ok(t) = n.utf8_text(b) {
                    let (line, column) = позиция(n, source);
                    m.reads.push(NameUse {
                        name: t.to_string(),
                        line,
                        column,
                    });
                }
            }
            _ => {}
        }
        let mut c = n.walk();
        stack.extend(n.children(&mut c));
    }
}

/// Прочитано ли голое имя как значение.
///
/// Только два родителя дают чтение: `expression` (имя само по себе
/// значение) и `access` (голова цепочки `Элементы.Поле`). Остальные места
/// идентификатора — объявление, имя метода, тип в `Новый`, свойство после
/// точки, метка — переменными не являются.
fn читается(id: Node) -> bool {
    let Some(p) = id.parent() else { return false };
    match p.kind() {
        "expression" => true,
        // `access` с одним ребёнком — голова цепочки. У `А.Б` голова лежит
        // во вложенном `access`, сюда попадает именно он.
        "access" => p.named_child_count() == 1,
        _ => false,
    }
}

/// Имя, которое объявляет оператор: левая часть присваивания, `Перем`,
/// счётчик цикла. Присваивание полю (`А.Б = 1`) ничего не объявляет — это
/// чтение `А`, и обход тела его так и увидит.
fn объявленное_оператором(n: Node, b: &[u8], out: &mut Vec<String>) {
    let mut c = n.walk();
    for ch in n.children(&mut c) {
        match ch.kind() {
            "identifier" => {
                if let Ok(t) = ch.utf8_text(b) {
                    out.push(t.to_lowercase());
                }
                // У `Перем А, Б;` объявлений несколько — идём дальше,
                // у присваивания и цикла первый идентификатор единственный.
                if n.kind() != "var_statement" {
                    return;
                }
            }
            "access" | "property_access" | "expression" if n.kind() != "var_statement" => {
                return;
            }
            _ => {}
        }
    }
}

/// Объявления верхнего уровня: `Перем` модуля и присваивания основной программы.
fn собрать_объявления(n: Node, b: &[u8], out: &mut Vec<String>) {
    let mut stack = vec![n];
    while let Some(x) = stack.pop() {
        match x.kind() {
            "variable_spec" => {
                if let Some(id) = ребёнок(x, "identifier") {
                    if let Ok(t) = id.utf8_text(b) {
                        out.push(t.to_lowercase());
                    }
                }
            }
            "assignment_statement" | "var_statement" | "for_statement" | "for_each_statement" => {
                объявленное_оператором(x, b, out);
            }
            _ => {}
        }
        let mut c = x.walk();
        stack.extend(x.children(&mut c));
    }
}

fn вызов(n: Node, source: &str, b: &[u8]) -> Option<CallUse> {
    let name_node = n.child_by_field_name("name")?;
    let name = name_node.utf8_text(b).ok()?.to_string();
    let qualifier = n
        .parent()
        .filter(|p| p.kind() == "call_expression")
        .and_then(|p| p.child(0))
        .filter(|a| a.kind() == "access")
        .and_then(|a| a.utf8_text(b).ok())
        .map(|q| q.trim().to_string())
        .unwrap_or_default();
    let (line, column) = позиция(name_node, source);
    Some(CallUse {
        qualifier,
        name,
        line,
        column,
    })
}

/// Строка и колонка В СИМВОЛАХ, обе с единицы.
fn позиция(n: Node, source: &str) -> (u32, u32) {
    let p = n.start_position();
    let начало_строки = n.start_byte() - p.column;
    let column = source
        .get(начало_строки..n.start_byte())
        .map(|s| s.chars().count())
        .unwrap_or(p.column);
    (p.row as u32 + 1, column as u32 + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Калибровочный модуль 09.10.2026 — дословно, с отступами табуляцией.
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

    fn метод_по_имени<'a>(s: &'a ModuleScope, имя: &str) -> &'a MethodScope {
        s.methods.iter().find(|m| m.name == имя).unwrap()
    }

    #[test]
    fn директивы_привязаны_к_своим_методам() {
        let s = parse(КАЛИБРОВКА).unwrap();
        assert_eq!(
            метод_по_имени(&s, "КалибровкаНаСервере").context,
            Context::Server
        );
        assert_eq!(
            метод_по_имени(&s, "КалибровкаНаКлиенте").context,
            Context::Client
        );
    }

    #[test]
    fn позиция_как_у_конфигуратора() {
        // /CheckConfig: «Переменная не определена (НеОпределённаяПеременнаяКалибровки)», (3,14)
        // в модуле без строки `Перем` — у калибровки 09.10 было (4,14) из-за сдвига на строку.
        let s = parse(КАЛИБРОВКА).unwrap();
        let r = метод_по_имени(&s, "КалибровкаНаСервере")
            .reads
            .iter()
            .find(|r| r.name == "НеОпределённаяПеременнаяКалибровки")
            .unwrap();
        assert_eq!((r.line, r.column), (3, 14));
        // «Тип не определен (Запрос)», (9,17) у калибровки → (8,17) здесь.
        let n = &метод_по_имени(&s, "КалибровкаНаКлиенте").news[0];
        assert_eq!(n.type_name, "Запрос");
        assert_eq!((n.line, n.column), (8, 17));
    }

    #[test]
    fn объявленное_не_читается_как_неизвестное() {
        let s = parse(КАЛИБРОВКА).unwrap();
        let m = метод_по_имени(&s, "КалибровкаНаКлиенте");
        assert!(m.declared.contains(&"запрос".to_string()));
        assert!(m.declared.contains(&"команда".to_string()), "параметр");
        // Левая часть присваивания — объявление, а не чтение.
        assert!(!m.reads.iter().any(|r| r.name == "Запрос"));
    }

    #[test]
    fn тип_в_новый_и_имя_метода_не_чтение() {
        let s = parse(КАЛИБРОВКА).unwrap();
        let m = метод_по_имени(&s, "КалибровкаНаКлиенте");
        assert!(m.reads.is_empty(), "лишние чтения: {:?}", m.reads);
        assert_eq!(m.calls[0].name, "КалибровкаНаСервере");
        assert!(m.calls[0].qualifier.is_empty());
    }

    #[test]
    fn свойство_после_точки_не_чтение_а_голова_цепочки_да() {
        let s = parse("Процедура П()\n\tЭлементы.Поле.Видимость = Ложь;\n\tХ = Объект.Ссылка;\nКонецПроцедуры\n").unwrap();
        let имена: Vec<&str> = s.methods[0].reads.iter().map(|r| r.name.as_str()).collect();
        assert!(имена.contains(&"Элементы"), "{имена:?}");
        assert!(имена.contains(&"Объект"), "{имена:?}");
        assert!(
            !имена.contains(&"Поле") && !имена.contains(&"Видимость") && !имена.contains(&"Ссылка")
        );
    }

    #[test]
    fn переменные_модуля_и_перем_метода() {
        let src = "Перем МодульнаяА Экспорт, МодульнаяБ;\n\nФункция Ф(Знач П1, П2 = 5)\n\tПерем Л, М;\n\tДля Сч = 1 По 3 Цикл\n\tКонецЦикла;\n\tВозврат П1 + Л + МодульнаяА;\nКонецФункции\n";
        let s = parse(src).unwrap();
        assert!(s.module_vars.contains(&"модульнаяа".to_string()));
        assert!(s.module_vars.contains(&"модульнаяб".to_string()));
        let d = &s.methods[0].declared;
        for x in ["п1", "п2", "л", "м", "сч"] {
            assert!(d.contains(&x.to_string()), "не объявлено {x}: {d:?}");
        }
    }

    #[test]
    fn условие_препроцессора_не_переменная() {
        let src = "Процедура П()\n#Если Сервер Тогда\n\tА = 1;\n#КонецЕсли\nКонецПроцедуры\n";
        let s = parse(src).unwrap();
        assert!(s.methods[0].reads.iter().all(|r| r.name != "Сервер"));
        assert_eq!(s.methods[0].guarded_lines, vec![(2, 4)]);
    }

    #[test]
    fn метод_под_если_помечен() {
        let src = "#Если Сервер Или ТолстыйКлиентОбычноеПриложение Тогда\n&НаКлиенте\nПроцедура П()\nКонецПроцедуры\n#КонецЕсли\n";
        let s = parse(src).unwrap();
        assert!(s.methods[0].under_preprocessor_if);
        assert_eq!(s.methods[0].context, Context::Client);
    }

    #[test]
    fn область_прозрачна_для_директив() {
        let src =
            "#Область Обработчики\n&НаКлиенте\nПроцедура П()\nКонецПроцедуры\n#КонецОбласти\n";
        let s = parse(src).unwrap();
        assert_eq!(s.methods[0].context, Context::Client);
        assert!(!s.methods[0].under_preprocessor_if);
    }

    #[test]
    fn директива_не_протекает_из_области() {
        // Форма из ERP (модуль формы документа): последний
        // метод области помечен `&НаКлиенте`, после `#КонецОбласти` — функция
        // БЕЗ директивы. Её контекст — умолчание модуля, а не клиент.
        let src = "#Область А\n&НаСервере\nПроцедура П1()\nКонецПроцедуры\n&НаКлиенте\nПроцедура П2()\nКонецПроцедуры\n#КонецОбласти\n\n// комментарий\nФункция Ф() Экспорт\nКонецФункции\n";
        let s = parse(src).unwrap();
        let ф = s.methods.iter().find(|m| m.name == "Ф").unwrap();
        assert_eq!(
            ф.context,
            Context::Unspecified,
            "{:?}",
            s.methods
                .iter()
                .map(|m| (&m.name, m.context))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn директива_перед_областью_не_доживает_до_метода_после() {
        // Директива относится только к НЕПОСРЕДСТВЕННО следующему объявлению.
        // Невостребованная (перед `#Область`) не должна достаться первому
        // методу верхнего уровня после области.
        // Для компилятора `#Область` — разметка: директива перед ней достаётся
        // первому методу ВНУТРИ области, и после этого израсходована.
        let src = "&НаКлиенте\n#Область А\nПроцедура П1()\nКонецПроцедуры\n#КонецОбласти\n\nФункция Ф() Экспорт\nКонецФункции\n";
        let s = parse(src).unwrap();
        let к = |имя: &str| s.methods.iter().find(|m| m.name == имя).unwrap().context;
        assert_eq!(к("П1"), Context::Client);
        assert_eq!(к("Ф"), Context::Unspecified);
    }

    #[test]
    fn перем_внутри_области_в_теле_метода() {
        let src = "Процедура П()\n#Область Подготовка\n\tПерем ТаблицаРасшифровки;\n#КонецОбласти\n\tФ(ТаблицаРасшифровки);\nКонецПроцедуры\n";
        let s = parse(src).unwrap();
        assert!(
            s.methods[0]
                .declared
                .contains(&"таблицарасшифровки".to_string()),
            "{:?}",
            s.methods[0].declared
        );
    }

    #[test]
    fn перехват_расширения_не_директива() {
        let src = "&НаСервере\n&После(\"ПриСозданииНаСервере\")\nПроцедура Расш_П(Отказ)\nКонецПроцедуры\n";
        let s = parse(src).unwrap();
        assert_eq!(s.methods[0].context, Context::Server);
    }

    #[test]
    fn квалифицированный_вызов_несёт_модуль() {
        let s = parse("&НаКлиенте\nПроцедура П()\n\tОбщегоНазначения.Метод(1);\nКонецПроцедуры\n")
            .unwrap();
        let c = &s.methods[0].calls[0];
        assert_eq!(c.qualifier, "ОбщегоНазначения");
        assert_eq!(c.name, "Метод");
    }
}
