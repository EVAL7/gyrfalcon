//! Автосинхронизация с git: периодический `pull` выгрузки и обновление индекса.
//!
//! # Что здесь происходит
//!
//! Сервер, отвечающий по вчерашнему индексу, врёт аккуратно: каждая правка,
//! приехавшая из репозитория, невидима, пока индекс не пересобран. Раньше
//! обновление было рукопашным (`gyrfalcon build` / `gyrfalcon update`), а
//! автодосборка догоняла только `.bsl` и только по поводу — перед ответом
//! на вызов инструмента. Выгрузка, которую тянет кто-то другой (CI, коллега),
//! до этого повода не доходит вовсе.
//!
//! Этот модуль — первый в сервере фоновый поток ПО ТАЙМЕРУ (досборка
//! сознательно обошлась без него, см. `autoupdate`). Здесь таймер оправдан:
//! pull — это чужая работа, у которой нет нашего повода, и без таймера
//! узнавать о ней неоткуда.
//!
//! # Правила, продиктованные безопасностью
//!
//! 1. **`--ff-only`** — pull не создаёт коммитов слияния. Конфликт слияния
//!    в автоматическом режиме это правка чужой истории руками робота.
//! 2. **Грязная рабочая копия пропускается** — локальные правки человека
//!    важнее свежести индекса. Проверка ограничена поддеревом выгрузки:
//!    репозиторий часто шире её (`repo/src/cf/...`), и мусор в соседнем
//!    каталоге нашу выгрузку не касается.
//! 3. **Сбой pull не трогает индекс** — проект продолжает отвечать по тому,
//!    что есть; причина видна в `list_projects`.
//!
//! # Что здесь НЕ делается
//!
//! Не решается, ЧТО делать с приехавшими файлами — это решает сервер
//! (`Server::синхронизировать`): `.bsl` уходят инкременту, метаданные —
//! полной пересборке. Модуль отвечает только за разговор с git.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

/// Минимальный осмысленный интервал.
///
/// Ограничение снизу, а не сверху: интервал короче десяти секунд гонял бы
/// git по каждому проекту чаще, чем успевает доехать правка, и превращал
/// бы «автосинхронизацию» в шум статуса.
const МИНИМУМ_С: u64 = 10;

/// Разобрать интервал: `<N><s|m|h>`, суффикс обязателен.
///
/// «15» без суффикса — ошибка, а не догадка: угаданные минуты в одном
/// месте и секунды в другом расходятся молча, и человек узнаёт об этом
/// по частоте pull, а не по сообщению.
pub fn разобрать_интервал(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    // strip_suffix, а не срез по len-1: русский суффикс «м» двухбайтный,
    // и срез резал его посередине (поймано тестом на «15м»).
    let тело_и_множитель = s
        .strip_suffix('s')
        .or_else(|| s.strip_suffix('с'))
        .map(|т| (т, 1))
        .or_else(|| s.strip_suffix('m').map(|т| (т, 60)))
        .or_else(|| s.strip_suffix('м').map(|т| (т, 60)))
        .or_else(|| s.strip_suffix('h').map(|т| (т, 3600)))
        .or_else(|| s.strip_suffix('ч').map(|т| (т, 3600)));
    let Some((тело, множитель)) = тело_и_множитель else {
        return Err(format!(
            "интервал '{s}': нужен суффикс — секунды (30s), минуты (15m) или часы (2h)"
        ));
    };
    let секунды = parse_число(тело, множитель)?;
    if секунды < МИНИМУМ_С {
        return Err(format!(
            "интервал '{s}': меньше {МИНИМУМ_С} с — синхронизация чаще не имеет смысла"
        ));
    }
    Ok(Duration::from_secs(секунды))
}

fn parse_число(тело: &str, множитель: u64) -> Result<u64, String> {
    let n: u64 = тело
        .trim()
        .parse()
        .map_err(|_| format!("интервал '{тело}': число перед суффиксом не прочитано"))?;
    n.checked_mul(множитель)
        .ok_or_else(|| format!("интервал '{тело}': слишком большое число"))
}

/// Интервал словами — для статуса: «15м», «30с», «2ч».
pub fn описать_интервал(d: Duration) -> String {
    let сек = d.as_secs();
    if сек % 3600 == 0 {
        format!("{}ч", сек / 3600)
    } else if сек % 60 == 0 {
        format!("{}м", сек / 60)
    } else {
        format!("{}с", сек)
    }
}

/// Запустить git и вернуть stdout; НЕУДАЧА — ошибка.
///
/// В отличие от `changes::git`, где stderr глотается намеренно (там источников
/// три и один битый не должен топить остальные), здесь источник один и молчаливый
/// сбой pull значил бы вечное «синхронизировано» без синхронизации.
fn git(корень: &Path, аргументы: &[&str]) -> Result<String, String> {
    let вывод = Command::new("git")
        .arg("-c")
        .arg("core.quotepath=false")
        .arg("-C")
        .arg(корень)
        .args(аргументы)
        .output()
        .map_err(|e| {
            format!(
                "git не запустился: {e}. Автосинхронизация требует git в PATH \
                 (для одной проверки свежести он не нужен, для pull — обязателен)"
            )
        })?;
    if !вывод.status.success() {
        let stderr = String::from_utf8_lossy(&вывод.stderr);
        return Err(format!(
            "git {:?} отказал: {}",
            аргументы.first().unwrap_or(&""),
            stderr.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&вывод.stdout).into_owned())
}

/// Вывод `status --porcelain` пуст по содержательным строкам → можно тянуть.
///
/// Чистая функция ради теста: правило «untracked тоже грязь» — решение,
/// и проверять его надо без репозитория.
pub fn рабочая_копия_чистая(статус: &str) -> bool {
    !статус.lines().any(|l| !l.trim().is_empty())
}

/// Спека путей — поддерево выгрузки относительно корня репозитория.
///
/// Репозиторий может быть шире выгрузки (`repo/src/cf/...`): спека держит
/// и проверку грязи, и diff в её пределах, чтобы правка в соседнем каталоге
/// репозитория не блокировала синхронизацию и не попадала в индекс.
fn спека(верх: &Path, выгрузка: &Path) -> String {
    let выгрузка = std::fs::canonicalize(выгрузка).unwrap_or_else(|_| выгрузка.to_path_buf());
    let отн = выгрузка
        .strip_prefix(верх)
        .map(|p| p.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"))
        .unwrap_or_default();
    if отн.is_empty() {
        ".".into()
    } else {
        отн
    }
}

/// Путь из `diff --name-only` (от корня репо, через `/`) → путь ОТНОСИТЕЛЬНО
/// ВЫГРУЗКИ, как её помнит индекс.
///
/// Склеивать с корнем репо нельзя: git отдаёт (а мы канонизируем) физический
/// путь — на macOS `/private/var/…`, — а индекс помнит выгрузку так, как её
/// дали сборке, — `/var/…`. Разница в симлинке ломает `rel_from`, и инкремент
/// вставлял бы дубликат модуля вместо замены (поймано живым тестом:
/// модулей 3 вместо 2). Поэтому путь собирается от ВЫГРУЗКИ той же навигацией,
/// какой git ограничил diff.
fn в_выгрузке(выгрузка: &Path, спека: &str, файл: &str) -> PathBuf {
    let файл = файл.trim_start_matches("./");
    let внутри = if спека == "." {
        файл
    } else {
        файл
            .strip_prefix(&format!("{спека}/"))
            .unwrap_or(файл)
    };
    выгрузка.join(внутри.replace('/', std::path::MAIN_SEPARATOR_STR))
}

/// Состояние синхронизации одного проекта — своё у каждого, как сторож.
pub struct ГитСинк {
    /// Каталог выгрузки из `index_meta.source_path`.
    корень: PathBuf,
    /// Интервал синхронизации; `None` — выключена (флага не было).
    интервал: Option<Duration>,
    /// Идёт ли сейчас такт: второй поверх первого не нужен.
    занято: AtomicBool,
    /// Когда тянули в последний раз (unix, с) — 0, если ни разу.
    последняя_попытка: AtomicU64,
    /// Последний исход словами — для `list_projects`.
    последний_итог: Mutex<Option<String>>,
    /// Коммит, до которого дотянулись — для `list_projects`.
    последний_коммит: Mutex<Option<String>>,
}

impl ГитСинк {
    pub fn новый(корень: &Path, интервал: Option<Duration>) -> Self {
        Self {
            корень: корень.to_path_buf(),
            интервал,
            занято: AtomicBool::new(false),
            последняя_попытка: AtomicU64::new(0),
            последний_итог: Mutex::new(None),
            последний_коммит: Mutex::new(None),
        }
    }

    pub fn включена(&self) -> bool {
        self.интервал.is_some()
    }

    /// Каталог выгрузки — для полной пересборки.
    pub fn корень(&self) -> &Path {
        &self.корень
    }

    /// Попытаться занять такт; `false` — уже идёт.
    pub fn занять(&self) -> bool {
        !self.занято.swap(true, Ordering::AcqRel)
    }

    pub fn освободить(&self) {
        self.занято.store(false, Ordering::Release);
    }

    fn сейчас() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn записать(&self, итог: String) {
        *self.последний_итог.lock().unwrap() = Some(итог);
        self.последняя_попытка.store(Self::сейчас(), Ordering::Release);
    }

    /// Один такт: pull и список приехавших файлов ВНУТРИ выгрузки.
    ///
    /// `Ok(vec![])` — pull прошёл, изменений в выгрузке нет. `Err` — причина
    /// словами (уже с префиксом «ПРОПУЩЕНО»/«ОШИБКА»): она попадает в статус
    /// как есть. И сбой, и пропуск оставляют репозиторий нетронутым.
    pub fn тянуть(&self) -> Result<Vec<PathBuf>, String> {
        // Дешёвая проверка чтением .git/HEAD вверх по предкам — без неё
        // каждый такт платил бы порождением процесса за ответ «не репозиторий».
        if gyrfalcon_index::git::head(&self.корень).is_none() {
            self.записать("ПРОПУЩЕНО: исходники не в git".into());
            return Err("ПРОПУЩЕНО: исходники не в git".into());
        }
        let верх = match git(&self.корень, &["rev-parse", "--show-toplevel"]) {
            Ok(в) => {
                let в = в.trim();
                if в.is_empty() {
                    self.записать("ПРОПУЩЕНО: исходники не в git".into());
                    return Err("ПРОПУЩЕНО: исходники не в git".into());
                }
                let p = PathBuf::from(в);
                std::fs::canonicalize(&p).unwrap_or(p)
            }
            Err(e) => {
                self.записать(format!("ОШИБКА git: {e}"));
                return Err(format!("ОШИБКА git: {e}"));
            }
        };
        let спека = спека(&верх, &self.корень);

        let статус = match git(
            &верх,
            &[
                "--no-optional-locks",
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--",
                &спека,
            ],
        ) {
            Ok(s) => s,
            Err(e) => {
                self.записать(format!("ОШИБКА git: {e}"));
                return Err(format!("ОШИБКА git: {e}"));
            }
        };
        if !рабочая_копия_чистая(&статус) {
            let строк = статус.lines().filter(|l| !l.trim().is_empty()).count();
            let причина = format!("ПРОПУЩЕНО: грязная рабочая копия ({строк} строк status)");
            self.записать(причина.clone());
            return Err(причина);
        }

        let было = gyrfalcon_index::git::head(&self.корень);
        if let Err(e) = git(&верх, &["pull", "--ff-only"]) {
            self.записать(format!("ОШИБКА pull: {e}"));
            return Err(format!("ОШИБКА pull: {e}"));
        }
        self.последняя_попытка.store(Self::сейчас(), Ordering::Release);
        let стало = gyrfalcon_index::git::head(&self.корень);
        if стало == было {
            return Ok(vec![]);
        }
        *self.последний_коммит.lock().unwrap() = стало.clone();

        let диапазон = format!("{}..{}", было.unwrap_or_default(), стало.unwrap_or_default());
        let diff = git(&верх, &["diff", "--name-only", &диапазон, "--", &спека])
            .unwrap_or_default();
        Ok(diff
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .map(|ф| в_выгрузке(&self.корень, &спека, ф))
            .collect())
    }

    /// Записать исход такта, решённый сервером (инкремент/пересборка).
    pub fn записать_итог(&self, итог: String) {
        self.записать(итог);
    }

    /// Состояние словами — для `list_projects`.
    ///
    /// Выключенная синхронизация говорит об этом прямо — по той же причине,
    /// что и выключенная автодосборка: молчание читалось бы как «нечего тянуть».
    pub fn состояние(&self) -> serde_json::Value {
        let Some(интервал) = self.интервал else {
            return serde_json::json!({
                "git_sync": "выключена",
                "note": "включить: --git-sync 15m (или GYRFALCON_GIT_SYNC=15m). \
                         Pull --ff-only по чистой рабочей копии; .bsl — инкрементом, \
                         метаданные — полной пересборкой"
            });
        };
        let попытка = self.последняя_попытка.load(Ordering::Acquire);
        serde_json::json!({
            "git_sync": format!("включена (каждые {})", описать_интервал(интервал)),
            "last_pull": if попытка == 0 { serde_json::Value::Null }
                         else { serde_json::json!(попытка) },
            "last_result": *self.последний_итог.lock().unwrap(),
            "last_commit": *self.последний_коммит.lock().unwrap(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn интервал_читается_по_суффиксу() {
        assert_eq!(разобрать_интервал("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(разобрать_интервал("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(разобрать_интервал("2h").unwrap(), Duration::from_secs(7200));
        // Русские суффиксы: раскладка меняется чаще, чем память о ней.
        assert_eq!(разобрать_интервал("15м").unwrap(), Duration::from_secs(900));
    }

    #[test]
    fn интервал_без_суффикса_ошибка_а_не_догадка() {
        assert!(разобрать_интервал("15").is_err());
        assert!(разобрать_интервал("").is_err());
    }

    #[test]
    fn интервал_короче_минимума_отклоняется() {
        assert!(разобрать_интервал("1s").is_err());
        assert!(разобрать_интервал("0m").is_err());
        assert!(разобрать_интервал("9s").is_err());
        assert!(разобрать_интервал("10s").is_ok());
    }

    #[test]
    fn чистая_копия_это_пустой_статус() {
        assert!(рабочая_копия_чистая(""));
        assert!(рабочая_копия_чистая("\n \n"));
        assert!(!рабочая_копия_чистая(" M src/CommonModules/А/Ext/Module.bsl\n"));
        // Untracked — тоже грязь: новый файл в выгрузке не хуже изменённого.
        assert!(!рабочая_копия_чистая("?? src/новый-каталог/\n"));
    }

    #[test]
    fn спека_выгрузки_внутри_репозитория() {
        let верх = Path::new("/repo");
        assert_eq!(спека(верх, Path::new("/repo")), ".");
        assert_eq!(спека(верх, Path::new("/repo/src/cf")), "src/cf");
    }

    /// Живой git: bare-origin и два рабочих клона. Второй клон играет роль
    /// «того, кто пушит»: правки едут в origin, первый клон их тянет.
    struct Пара {
        _база: PathBuf,
        клон: PathBuf,
        второй: PathBuf,
    }

    impl Пара {
        fn новый(метка: &str) -> Self {
            let база = std::env::temp_dir().join(format!("gyrfalcon-gitsync-{метка}"));
            let _ = std::fs::remove_dir_all(&база);
            std::fs::create_dir_all(&база).unwrap();
            let п = Self {
                _база: база.clone(),
                клон: база.join("клон"),
                второй: база.join("второй"),
            };
            п.git(&база, &["init", "-q", "--bare", "origin.git"]);
            п.git(&база, &["init", "-q", "клон"]);
            п.w("src/семя.txt", "семя\n");
            п.git(&п.клон, &["add", "-A"]);
            п.git(&п.клон, &["commit", "-q", "-m", "init"]);
            п.git(
                &п.клон,
                &["remote", "add", "origin", "../origin.git"],
            );
            п.git(&п.клон, &["push", "-q", "-u", "origin", "HEAD"]);
            п.git(&база, &["clone", "-q", "origin.git", "второй"]);
            п
        }

        fn git(&self, корень: &Path, a: &[&str]) {
            let ok = Command::new("git")
                .args([
                    "-c",
                    "user.name=t",
                    "-c",
                    "user.email=t@t",
                    "-c",
                    "core.autocrlf=false",
                    "-c",
                    "commit.gpgsign=false",
                ])
                .arg("-C")
                .arg(корень)
                .args(a)
                .status()
                .unwrap()
                .success();
            assert!(ok, "git {a:?}");
        }

        fn w(&self, путь: &str, текст: &str) {
            let f = self.клон.join(путь);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, текст).unwrap();
        }

        /// Новый коммит в origin — через второй клон.
        fn перевалка(&self, путь: &str, текст: &str) {
            let f = self.второй.join(путь);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, текст).unwrap();
            self.git(&self.второй, &["add", "-A"]);
            self.git(&self.второй, &["commit", "-q", "-m", "правка"]);
            self.git(&self.второй, &["push", "-q"]);
        }
    }

    impl Drop for Пара {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self._база);
        }
    }

    fn синк(клон: &Path) -> ГитСинк {
        // Выгрузка — ВНУТРИ репозитория (клон/src): обычный случай 1С.
        ГитСинк::новый(&клон.join("src"), Some(Duration::from_secs(60)))
    }

    #[test]
    fn pull_привозит_bsl_и_xml_в_пределах_выгрузки() {
        let п = Пара::новый("pull");
        п.перевалка("src/CommonModules/А/Ext/Module.bsl", "Функция А() Экспорт\nКонецФункции\n");
        п.перевалка("src/Catalogs/Товары.xml", "<MetaDataObject/>\n");
        // Правка ВНЕ выгрузки: в diff попасть не обязана.
        п.перевалка("доки/README.md", "текст\n");
        let синхр = синк(&п.клон);
        let файлы = синхр.тянуть().expect("чистая копия — pull обязан пройти");
        assert_eq!(файлы.len(), 2, "в diff — только файлы выгрузки: {файлы:?}");
        assert!(файлы.iter().any(|f| f.extension().is_some_and(|x| x == "bsl")));
        assert!(файлы.iter().any(|f| f.extension().is_some_and(|x| x == "xml")));
        let st = синхр.состояние();
        assert!(st["last_commit"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[test]
    fn pull_без_нового_это_пустой_список() {
        let п = Пара::новый("пусто");
        let файлы = синк(&п.клон).тянуть().unwrap();
        assert!(файлы.is_empty(), "тянуть нечего — не ошибка");
    }

    #[test]
    fn грязная_выгрузка_пропускается_с_причиной() {
        let п = Пара::новый("грязно");
        п.перевалка("src/CommonModules/А/Ext/Module.bsl", "новое\n");
        // Локальная правка В ВЫГРУЗКЕ — блокирует.
        п.w("src/CommonModules/А/Ext/Module.bsl", "локальная правка\n");
        let синхр = синк(&п.клон);
        let err = синхр.тянуть().expect_err("грязная копия — пропуск");
        assert!(err.contains("грязная"), "{err}");
        let st = синхр.состояние();
        assert!(st["last_result"].as_str().unwrap().contains("ПРОПУЩЕНО"));
    }

    #[test]
    fn грязь_вне_выгрузки_не_блокирует() {
        let п = Пара::новый("сосед");
        п.перевалка("src/CommonModules/А/Ext/Module.bsl", "новое\n");
        // Локальная правка в СОСЕДНЕМ каталоге репозитория — не наша забота.
        п.w("доки/заметки.txt", "мусор\n");
        let файлы = синк(&п.клон).тянуть().expect("соседняя грязь не блокирует");
        assert_eq!(файлы.len(), 1);
    }

    #[test]
    fn не_в_git_называется_а_не_падает() {
        let д = std::env::temp_dir().join("gyrfalcon-gitsync-невgit");
        let _ = std::fs::remove_dir_all(&д);
        std::fs::create_dir_all(&д).unwrap();
        let синхр = ГитСинк::новый(&д, Some(Duration::from_secs(60)));
        let err = синхр.тянуть().expect_err("не репозиторий");
        assert!(err.contains("не в git"), "{err}");
        let _ = std::fs::remove_dir_all(&д);
    }

    #[test]
    fn выключенная_синхронизация_называет_себя() {
        let синхр = ГитСинк::новый(Path::new("."), None);
        let st = синхр.состояние();
        assert_eq!(st["git_sync"], "выключена");
        assert!(st["note"].as_str().unwrap().contains("--git-sync"));
    }
}
