//! Справочно-навигационный сервер по 1С: точка входа.
//!
//! # Состояние
//!
//! Веха 5: **MCP-сервер работает** — `serve` поднимает JSON-RPC на stdio с
//! девятью инструментами и профилями под роль (Р-101, Р-104). Плюс прежние
//! команды сборки и замера.

use gyrfalcon_mcp::{hooks, http, install, mcp_http, project_practices, registry, server, tools};

use gyrfalcon_index::schema;
use gyrfalcon_parser::scan;
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => {
            println!("gyrfalcon {}", env!("CARGO_PKG_VERSION"));
        }
        Some("status") => print_status(),
        // Скилл в том виде, в каком его кладёт `install`: с отметкой версии.
        // Так его забирает и CI выпуска — ассет рядом с бинарём.
        Some("skill") => print!("{}", install::skill_with_stamp()),
        Some("install") => {
            if let Err(e) = cmd_install(&args[1..]) {
                eprintln!("ошибка: {e}");
                std::process::exit(1);
            }
        }
        Some("hook-augment") => print!("{}", hooks::augment_text(индекс_доступен())),
        Some("hook-session") | Some("hook-subagent") => {
            print!("{}", hooks::session_text(индекс_из_окружения().as_deref()))
        }
        Some("ui") => {
            if let Err(e) = cmd_ui(&args[1..]) {
                eprintln!("ошибка: {e}");
                std::process::exit(1);
            }
        }
        Some("serve") => {
            if let Err(e) = cmd_serve(&args[1..]) {
                eprintln!("ошибка: {e}");
                std::process::exit(1);
            }
        }
        Some("build") => {
            if let Err(e) = cmd_build(&args[1..]) {
                eprintln!("ошибка: {e}");
                std::process::exit(1);
            }
        }
        Some("kb") => {
            if let Err(e) = cmd_kb(&args[1..]) {
                eprintln!("ошибка: {e}");
                std::process::exit(1);
            }
        }
        Some("practices") => {
            if let Err(e) = cmd_practices(&args[1..]) {
                eprintln!("ошибка: {e}");
                std::process::exit(1);
            }
        }
        Some("update") => {
            if let Err(e) = cmd_update(&args[1..]) {
                eprintln!("ошибка: {e}");
                std::process::exit(1);
            }
        }
        Some("scan") => {
            if let Err(e) = cmd_scan(&args[1..]) {
                eprintln!("ошибка: {e}");
                std::process::exit(1);
            }
        }
        Some("--help") | Some("-h") | None => print_help(),
        Some(other) => {
            eprintln!("неизвестная команда: {other}\n");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!(
        "gyrfalcon {} — справочно-навигационный сервер по 1С:Предприятие (BSL)

Команды:
  serve --db <файл.db> | --index-dir <каталог> [--profile all|analysis|scout]
                      [--auto-update]  догонять индекс по .bsl самому (по умолчанию нет)
                      [--semantic-cache-mb 1536]
                                       держать векторы смыслового поиска в памяти
                                       (потолок на все индексы; 0 — читать с диска каждый раз)
                      [--http [--port 8788] [--bind 127.0.0.1] [--workers 4]]
                                       транспорт Streamable HTTP вместо stdio;
                                       --workers — сколько запросов обслуживать одновременно
                      MCP-сервер (по умолчанию stdio — для клиента вроде Claude Code)
  ui --db <файл.db> [--port 8787]
                      визуальная карта: движения, подсистемы, расширения
  install [--harness claude|kilo|codex] [--db <файл>] [--plan] [--force]
                      разложить скилл (правило, когда звать инструменты) и роли;
                      файлы прежней версии, не правленные вручную, обновляются сами
  skill               напечатать скилл с отметкой версии (то же, что кладёт install)
  status              состояние переноса схемы индекса
  build <путь> --out <файл> [--dict <словарь.db>]  собрать индекс: код, метаданные, семантика
  kb sync --db <индекс> --source-id <id> --src <путь>  обновить дополнительный Ext/Help источник проекта
  kb refresh --db <индекс>  дополнить существующий индекс справкой из его source_path
  kb remove --db <индекс> --source-id <id>  отключить только этот источник
  kb audit --src <путь> [--out <новый.db>]  проверить извлечение; --out создаёт QA-снимок
  practices import --src <путь> --project <имя> --commit <sha> --document <.md>
                      загрузить заголовки документации как кандидаты практик
  practices add --src <путь> --project <имя> --commit <sha> --rule <rule.json>
                      вручную добавить правило из JSON; MCP выдаст его только после проверки
  practices discover --db <индекс> --project <имя> [--depth quick|full]
                      явно дополнить существующий профиль кандидатами из BSL-модулей
  practices preview --db <индекс> --project <имя> [--depth quick|full] [--out <report.json>]
                      проверить полный корпус и кандидатов без изменения профиля
  practices accept --db <индекс> --project <имя> --id <id> --sample <N> --matches <N>
                   --module <путь.bsl> --method <имя>
                      принять кандидата только после проверки адреса и метрик
  practices approve --db <индекс> --project <имя> --id <id> --authority customer|project
                    --reviewer <кто> --reason <основание>
                      принять нормативное правило по явному решению и источнику
  scan <путь> [опции] замерить разбор модулей BSL в каталоге выгрузки
      --serial          дополнительно прогнать в один поток и показать ускорение
      --runs <N>        повторить замер N раз (по умолчанию 1)
      --threads <N>     ограничить число потоков
  --version           версия
  --help              эта справка

Репозиторий: {}",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_REPOSITORY")
    );
}

fn cmd_practices(args: &[String]) -> Result<(), String> {
    let action = args
        .first()
        .map(String::as_str)
        .ok_or("нужна команда practices import|add|discover|accept|approve")?;
    let mut src = None;
    let mut project = None;
    let mut commit = None;
    let mut document = None;
    let mut rule = None;
    let mut db = None;
    let mut id = None;
    let mut sample = None;
    let mut matches = None;
    let mut module = None;
    let mut method = None;
    let mut authority = None;
    let mut out = None;
    let mut depth = None;
    let mut reviewer = None;
    let mut reason = None;
    let mut i = 1;
    while i < args.len() {
        let flag = &args[i];
        i += 1;
        let value = args
            .get(i)
            .ok_or_else(|| format!("{flag} без значения"))?
            .clone();
        i += 1;
        match flag.as_str() {
            "--src" => src = Some(value),
            "--project" => project = Some(value),
            "--commit" => commit = Some(value),
            "--document" => document = Some(value),
            "--rule" => rule = Some(value),
            "--db" => db = Some(value),
            "--id" => id = Some(value),
            "--sample" => sample = Some(value),
            "--matches" => matches = Some(value),
            "--module" => module = Some(value),
            "--method" => method = Some(value),
            "--authority" => authority = Some(value),
            "--out" => out = Some(value),
            "--depth" => depth = Some(value),
            "--reviewer" => reviewer = Some(value),
            "--reason" => reason = Some(value),
            _ => return Err(format!("неизвестная опция practices: {flag}")),
        }
    }
    let mining_depth = match depth.as_deref() {
        None | Some("quick") => gyrfalcon_mcp::practice_mining::MiningDepth::Quick,
        Some("full") => gyrfalcon_mcp::practice_mining::MiningDepth::Full,
        Some(_) => return Err("--depth: допустимо quick или full".into()),
    };
    match action {
        "import" => {
            let src = src.ok_or("нужен --src")?;
            let project = project.ok_or("нужен --project")?;
            let commit = commit.ok_or("нужен --commit")?;
            let document = document.ok_or("practices import требует --document")?;
            let added = project_practices::import_document(&src, &project, &commit, &document)?;
            println!("документация импортирована; добавлено кандидатов: {added}");
        }
        "add" => {
            let src = src.ok_or("нужен --src")?;
            let project = project.ok_or("нужен --project")?;
            let commit = commit.ok_or("нужен --commit")?;
            let file = rule.ok_or("practices add требует --rule <rule.json>")?;
            let value = serde_json::from_str(
                &std::fs::read_to_string(&file)
                    .map_err(|e| format!("не прочитан rule JSON: {e}"))?,
            )
            .map_err(|e| format!("некорректный rule JSON: {e}"))?;
            project_practices::add_manual(&src, &project, &commit, value)?;
            println!("ручной кандидат добавлен; до приёмки project_practices его не выдаст");
        }
        "discover" => {
            let project = project.ok_or("practices discover требует --project")?;
            let db = db.ok_or("practices discover требует --db")?;
            if std::path::Path::new(&db)
                .file_stem()
                .and_then(|s| s.to_str())
                != Some(project.as_str())
            {
                return Err("--project не совпадает с именем файла индекса --db".into());
            }
            let conn = rusqlite::Connection::open_with_flags(
                db,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(|e| format!("не открыт индекс: {e}"))?;
            let added = project_practices::discover_with_depth(&conn, &project, mining_depth)?;
            println!("добавлено кандидатов из модулей: {added}; существующие правила сохранены");
        }
        "preview" => {
            let project = project.ok_or("practices preview требует --project")?;
            let db = db.ok_or("practices preview требует --db")?;
            if std::path::Path::new(&db)
                .file_stem()
                .and_then(|s| s.to_str())
                != Some(project.as_str())
            {
                return Err("--project не совпадает с именем файла индекса --db".into());
            }
            let conn = rusqlite::Connection::open_with_flags(
                db,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(|e| format!("не открыт индекс: {e}"))?;
            let source: String = conn
                .query_row(
                    "SELECT value FROM index_meta WHERE key='source_path'",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| format!("не прочитан source_path: {e}"))?;
            let mined = gyrfalcon_mcp::practice_mining::mine(&conn, &source, mining_depth)?;
            let report = serde_json::json!({"project":project,"source_path":source,
                "coverage":mined.coverage,"candidates":mined.candidates});
            if let Some(path) = out {
                let encoded = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
                std::fs::write(&path, encoded)
                    .map_err(|e| format!("не записан отчёт {path}: {e}"))?;
                println!("отчёт: {path}");
            }
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "project":project,"coverage":report["coverage"],
                    "candidate_count":report["candidates"].as_array().map_or(0, Vec::len)
                }))
                .map_err(|e| e.to_string())?
            );
        }
        "accept" => {
            let project = project.ok_or("practices accept требует --project")?;
            let db = db.ok_or("practices accept требует --db")?;
            let sample: i64 = sample
                .ok_or("нужен --sample")?
                .parse()
                .map_err(|_| "--sample: не число")?;
            let matches: i64 = matches
                .ok_or("нужен --matches")?
                .parse()
                .map_err(|_| "--matches: не число")?;
            let conn = rusqlite::Connection::open_with_flags(
                db,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(|e| format!("не открыт индекс: {e}"))?;
            project_practices::accept(
                &conn,
                &project,
                &id.ok_or("нужен --id")?,
                sample,
                matches,
                &module.ok_or("нужен --module")?,
                &method.ok_or("нужен --method")?,
            )?;
            println!("кандидат принят; теперь его отдаст project_practices");
        }
        "approve" => {
            let project = project.ok_or("practices approve требует --project")?;
            let db = db.ok_or("practices approve требует --db")?;
            let conn = rusqlite::Connection::open_with_flags(
                db,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(|e| format!("не открыт индекс: {e}"))?;
            project_practices::approve(
                &conn,
                &project,
                &id.ok_or("нужен --id")?,
                &authority.ok_or("нужен --authority")?,
                &reviewer.ok_or("нужен --reviewer")?,
                &reason.ok_or("нужен --reason")?,
            )?;
            println!("нормативное правило принято; источник и решение записаны в профиль");
        }
        _ => return Err("practices: import, add, discover, accept или approve".into()),
    }
    Ok(())
}

fn print_status() {
    let total = schema::TABLES.len();
    let done = schema::implemented_count();

    println!("Схема индекса: {done} из {total} таблиц реализовано\n");

    for t in schema::TABLES {
        let mark = if t.implemented { "[x]" } else { "[ ]" };
        println!(
            "{mark} {:<22} {:>10}  {}",
            t.name, t.reference_rows, t.purpose
        );
    }

    println!(
        "\nЧисла — строки в прежний инструментном индексе (замер 28.08.2026),\n\
         ориентир масштаба, а не норматив."
    );
}

struct ScanOpts {
    root: PathBuf,
    serial: bool,
    runs: u32,
    threads: Option<usize>,
}

fn parse_scan_args(args: &[String]) -> Result<ScanOpts, String> {
    let mut root = None;
    let mut opts = ScanOpts {
        root: PathBuf::new(),
        serial: false,
        runs: 1,
        threads: None,
    };

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--serial" => opts.serial = true,
            "--runs" => {
                i += 1;
                opts.runs = args
                    .get(i)
                    .ok_or("--runs без значения")?
                    .parse()
                    .map_err(|_| "--runs: не число")?;
            }
            "--threads" => {
                i += 1;
                opts.threads = Some(
                    args.get(i)
                        .ok_or("--threads без значения")?
                        .parse()
                        .map_err(|_| "--threads: не число")?,
                );
            }
            other if other.starts_with("--") => return Err(format!("неизвестная опция: {other}")),
            path => root = Some(PathBuf::from(path)),
        }
        i += 1;
    }

    opts.root = root.ok_or("не указан путь к выгрузке")?;
    Ok(opts)
}

fn cmd_scan(args: &[String]) -> Result<(), String> {
    let opts = parse_scan_args(args)?;

    if !opts.root.is_dir() {
        return Err(format!("не каталог: {}", opts.root.display()));
    }

    if let Some(n) = opts.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .map_err(|e| format!("не удалось задать число потоков: {e}"))?;
    }

    println!("Корпус: {}", opts.root.display());

    // Обход меряется отдельно: он упирается в файловую систему, а не в процессор,
    // и смешивать его с разбором — значит не понять, что именно ускорилось.
    let t = Instant::now();
    let paths = scan::collect_modules(&opts.root);
    let walk_ms = t.elapsed().as_millis();
    println!("Обход: {} модулей .bsl за {} мс\n", paths.len(), walk_ms);

    if paths.is_empty() {
        return Err("модулей .bsl не найдено — тот ли каталог?".to_string());
    }

    let mut par_runs = Vec::new();
    for run in 1..=opts.runs {
        let r = scan::scan_parallel(&paths);
        if opts.runs > 1 {
            print!("прогон {run}/{}: ", opts.runs);
        }
        print_report("параллельно", &r);
        par_runs.push(r.elapsed_ms);
    }

    if opts.runs > 1 {
        let min = par_runs.iter().min().copied().unwrap_or(0);
        let max = par_runs.iter().max().copied().unwrap_or(0);
        let avg = par_runs.iter().sum::<u64>() / par_runs.len() as u64;
        println!(
            "\nразброс по {} прогонам: мин {:.2} c, сред {:.2} c, макс {:.2} c",
            par_runs.len(),
            min as f64 / 1000.0,
            avg as f64 / 1000.0,
            max as f64 / 1000.0
        );
    }

    if opts.serial {
        println!();
        let s = scan::scan_serial(&paths);
        print_report("в один поток", &s);

        let best_par = par_runs.iter().min().copied().unwrap_or(u64::MAX);
        if best_par > 0 {
            let speedup = s.elapsed_ms as f64 / best_par as f64;
            let threads = rayon::current_num_threads();
            println!(
                "\nУскорение: {speedup:.2}× на {threads} потоках \
                 (потолок по физическим ядрам, не по логическим)"
            );
        }
    }

    Ok(())
}

fn print_report(label: &str, r: &scan::ScanReport) {
    println!(
        "{label:>14}: {:.2} c | {:.0} файлов/с | {:.1} МБ/с | методов {} | потоков {}",
        r.elapsed_ms as f64 / 1000.0,
        r.files_per_sec(),
        r.mb_per_sec(),
        r.methods,
        r.threads
    );
    if r.unreadable > 0 {
        println!("{:>14}  не прочитано файлов: {}", "", r.unreadable);
    }
    if r.with_parse_errors > 0 {
        println!(
            "{:>14}  с ошибками разбора: {} ({:.2}%)",
            "",
            r.with_parse_errors,
            r.with_parse_errors as f64 * 100.0 / r.files.max(1) as f64
        );
    }
}

/// Индекс, о котором знает окружение. Хуки не ищут его сами: путь задаёт
/// тот, кто ставил сервер, а угадывание дало бы подсказку про чужой индекс.
fn индекс_из_окружения() -> Option<String> {
    std::env::var("GYRFALCON_DB").ok().filter(|s| !s.is_empty())
}

fn индекс_доступен() -> bool {
    индекс_из_окружения()
        .map(|p| std::path::Path::new(&p).exists())
        .unwrap_or(false)
}

/// Поднять визуальную часть.
fn cmd_ui(args: &[String]) -> Result<(), String> {
    let mut db: Option<PathBuf> = None;
    let mut port = 8787u16;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                i += 1;
                db = Some(PathBuf::from(args.get(i).ok_or("--db без значения")?));
            }
            "--port" => {
                i += 1;
                port = args
                    .get(i)
                    .ok_or("--port без значения")?
                    .parse()
                    .map_err(|_| "--port: не число")?;
            }
            other => return Err(format!("неизвестный параметр: {other}")),
        }
        i += 1;
    }
    http::serve(db.ok_or("нужен --db <файл индекса>")?, port)
}

/// Разложить скилл по харнесам.
fn cmd_install(args: &[String]) -> Result<(), String> {
    let mut харнесы: Vec<install::Harness> = Vec::new();
    let mut plan = false;
    let mut force = false;
    let mut db = String::from("<путь к индексу>");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--harness" => {
                i += 1;
                let v = args.get(i).ok_or("--harness без значения")?;
                харнесы.push(
                    install::Harness::parse(v).ok_or_else(|| {
                        format!("неизвестный харнес '{v}': claude | kilo | codex")
                    })?,
                );
            }
            "--db" => {
                i += 1;
                db = args.get(i).ok_or("--db без значения")?.clone();
            }
            "--plan" => plan = true,
            "--force" => force = true,
            other => return Err(format!("неизвестный параметр: {other}")),
        }
        i += 1;
    }
    if харнесы.is_empty() {
        харнесы = install::Harness::ALL.to_vec();
    }

    for д in install::install(&харнесы, plan, force) {
        println!("{:<12} {:<6} {}", д.харнес, д.что, д.итог);
        if !д.куда.as_os_str().is_empty() {
            println!("             {}", д.куда.display());
        }
    }
    println!("\nФрагменты конфигурации — вписать самостоятельно.");
    println!("Серверов ТРИ, по одному на профиль: урезание набора инструментов");
    println!("держится запуском сервера, а не текстом роли.");
    for h in харнесы {
        println!(
            "\n=== {} — MCP ===\n{}",
            h.name(),
            install::фрагмент(h, &db)
        );
        let хуки = install::фрагмент_хуков(h);
        if !хуки.is_empty() {
            println!(
                "=== {} — хуки (подсказки, не запреты) ===\n{}",
                h.name(),
                хуки
            );
        }
    }
    println!("Хукам нужен путь к индексу в переменной GYRFALCON_DB — без неё");
    println!("они молчат, а не гадают, какой индекс имелся в виду.");
    Ok(())
}

/// Поднять MCP-сервер на stdio.
///
/// Индекс обязателен параметром: базы «по умолчанию» у сервера нет намеренно —
/// молчаливый выбор чужого индекса даёт правдоподобные ответы про другую
/// конфигурацию, а это худший род ошибки.
fn cmd_serve(args: &[String]) -> Result<(), String> {
    let mut db: Option<PathBuf> = None;
    let mut index_dir: Option<PathBuf> = None;
    let mut profile = tools::Profile::All;
    // Выключена по умолчанию — как auto_index у образца: сборка трогает
    // файл, которым сервер отвечает, и включать её за человека нельзя.
    let mut auto_update = false;
    // Транспорт: stdio, пока не сказано иное. Порт отдельно от флага, чтобы
    // `--port` без `--http` не молчал, а был назван ошибкой.
    let mut http = false;
    let mut port: Option<u16> = None;
    let mut bind: Option<String> = None;
    let mut workers: Option<usize> = None;
    // Векторы смыслового поиска в памяти. Включено для сервера и только для
    // него: он живёт долго, и перечитывать 580 тысяч векторов на каждый
    // `find` (1,4 из 1,8 с, замер 01.10.2026) дороже, чем держать их.
    let mut semantic_cache_mb: usize = 1536;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                i += 1;
                db = Some(PathBuf::from(args.get(i).ok_or("--db без значения")?));
            }
            "--index-dir" => {
                i += 1;
                index_dir = Some(PathBuf::from(
                    args.get(i).ok_or("--index-dir без значения")?,
                ));
            }
            "--profile" => {
                i += 1;
                let v = args.get(i).ok_or("--profile без значения")?;
                profile = tools::Profile::parse(v)
                    .ok_or_else(|| format!("неизвестный профиль '{v}': all | analysis | scout"))?;
            }
            "--auto-update" => auto_update = true,
            "--http" => http = true,
            "--port" => {
                i += 1;
                port = Some(
                    args.get(i)
                        .ok_or("--port без значения")?
                        .parse()
                        .map_err(|_| "--port: не число")?,
                );
            }
            "--bind" => {
                i += 1;
                bind = Some(args.get(i).ok_or("--bind без значения")?.clone());
            }
            "--workers" => {
                i += 1;
                workers = Some(
                    args.get(i)
                        .ok_or("--workers без значения")?
                        .parse()
                        .map_err(|_| "--workers: не число")?,
                );
            }
            "--semantic-cache-mb" => {
                i += 1;
                semantic_cache_mb = args
                    .get(i)
                    .ok_or("--semantic-cache-mb без значения")?
                    .parse()
                    .map_err(|_| "--semantic-cache-mb: не число")?;
            }
            other => return Err(format!("неизвестный параметр: {other}")),
        }
        i += 1;
    }
    // Молча проглотить эти флаги значило бы соврать: человек их задал,
    // а слушать никто не начнёт.
    if port.is_some() && !http {
        return Err("--port без --http: транспорт stdio порта не слушает. \
             Нужен HTTP — добавьте --http"
            .into());
    }
    if bind.is_some() && !http {
        return Err(
            "--bind без --http: транспорт stdio интерфейсов не слушает. \
             Нужен HTTP — добавьте --http"
                .into(),
        );
    }
    if workers.is_some() && !http {
        return Err(
            "--workers без --http: транспорт stdio обслуживает одного клиента. \
             Нужен HTTP — добавьте --http"
                .into(),
        );
    }
    let источник = registry::Источник::из_аргументов(db, index_dir)?;
    gyrfalcon_index::semantic::set_cache_limit(semantic_cache_mb);
    let сервер = server::Server::new(источник, profile).с_автодосборкой(auto_update);
    if http {
        mcp_http::serve(
            сервер,
            bind.as_deref().unwrap_or(mcp_http::ПЕТЛЯ),
            port.unwrap_or(mcp_http::ПОРТ),
            workers.unwrap_or(mcp_http::ПОТОКОВ),
        )
    } else {
        сервер.run().map_err(|e| e.to_string())
    }
}

/// Инкрементальная пересборка: догнать индекс, не собирая заново.
///
/// Без списка файлов сам находит изменившиеся — тем же обходом по mtime,
/// каким сторож свежести определяет отставание. Со списком берёт названные:
/// так его зовёт тот, кто уже знает, что правил.
fn cmd_update(args: &[String]) -> Result<(), String> {
    let mut db: Option<PathBuf> = None;
    let mut файлы: Vec<PathBuf> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                i += 1;
                db = Some(PathBuf::from(args.get(i).ok_or("--db без значения")?));
            }
            other if other.starts_with("--") => return Err(format!("неизвестная опция: {other}")),
            path => файлы.push(PathBuf::from(path)),
        }
        i += 1;
    }
    let db = db.ok_or("не указан --db")?;

    // Каталог исходников берётся ИЗ ИНДЕКСА, а не аргументом: индекс сам
    // помнит, откуда собран, и подсунуть ему чужой корпус нельзя.
    let info = gyrfalcon_index::build::info(&db).map_err(|e| e.to_string())?;
    let src = PathBuf::from(&info.source_path);
    if !src.is_dir() {
        return Err(format!(
            "каталог исходников {} недоступен — индекс собран не на этой машине",
            info.source_path
        ));
    }

    if файлы.is_empty() {
        println!("Ищу изменившиеся файлы в {} …", src.display());
        let f =
            gyrfalcon_index::freshness::check(info.built_at, &info.source_path, &info.git_commit);
        if !f.stale {
            println!("Индекс не отстал — пересобирать нечего.");
            return Ok(());
        }
        // Обход считает и .xml, а инкремент их не берёт: показываем оба
        // числа, чтобы «учтено меньше, чем изменилось» не выглядело потерей.
        файлы = собрать_изменившиеся(&src, info.built_at);
        println!(
            "Изменилось файлов: {} (из них .bsl — {})",
            f.changed,
            файлы.len()
        );
        if файлы.is_empty() {
            return Err(
                "изменились только метаданные (.xml) — нужна полная сборка:                  gyrfalcon build <путь> --out <файл>"
                    .into(),
            );
        }
    }

    let r = gyrfalcon_index::incremental::update(&db, &src, &файлы).map_err(|e| e.to_string())?;
    println!(
        "
Переиндексировано модулей {} (удалено {}), методов {}, рёбер {} за {:.1} c",
        r.modules,
        r.removed,
        r.methods,
        r.calls,
        r.elapsed_ms as f64 / 1000.0
    );
    if r.stale_edges > 0 {
        // Цена инкремента называется числом, а не оговоркой в документации:
        // её читает тот, кто сейчас будет задавать вопросы этому индексу.
        println!(
            "ВНИМАНИЕ: {} вызовов из других модулей по этим именам остались              неразрешёнными (класс unknown). Разрешатся полной сборкой;              семантический поиск новых методов тоже ждёт её.",
            r.stale_edges
        );
    }
    Ok(())
}

fn cmd_kb(args: &[String]) -> Result<(), String> {
    use gyrfalcon_index::help;
    let action = args
        .first()
        .map(String::as_str)
        .ok_or("нужны kb sync, kb refresh, kb remove или kb audit")?;
    if action != "sync" && action != "refresh" && action != "remove" && action != "audit" {
        return Err(format!("неизвестная операция kb: {action}"));
    }
    let mut db: Option<PathBuf> = None;
    let mut source_id: Option<String> = None;
    let mut src: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                i += 1;
                db = Some(PathBuf::from(args.get(i).ok_or("--db без значения")?));
            }
            "--out" if action == "audit" => {
                i += 1;
                db = Some(PathBuf::from(args.get(i).ok_or("--out без значения")?));
            }
            "--source-id" => {
                i += 1;
                source_id = Some(args.get(i).ok_or("--source-id без значения")?.clone());
            }
            "--src" => {
                i += 1;
                src = Some(PathBuf::from(args.get(i).ok_or("--src без значения")?));
            }
            other => return Err(format!("неизвестный параметр kb: {other}")),
        }
        i += 1;
    }
    if action == "audit" {
        if source_id.is_some() {
            return Err("kb audit не принимает --source-id".into());
        }
        let src = src.ok_or("для kb audit нужен --src")?;
        let mut conn = if let Some(out) = db {
            if out.exists() {
                return Err(format!("QA-снимок уже существует: {}", out.display()));
            }
            rusqlite::Connection::open(out).map_err(|e| e.to_string())?
        } else {
            rusqlite::Connection::open_in_memory().map_err(|e| e.to_string())?
        };
        let r = help::sync(&mut conn, "audit", &src)?;
        println!("HTML {}, сырого HTML байт {}, добавлено {}, коротких {}, заголовочных {}, одинаковых текстов {}, текстовых байт {}",
            r.html_files, r.raw_html_bytes, r.added, r.skipped_short, r.title_only, r.duplicate_texts, r.text_bytes);
        return Ok(());
    }
    let db = db.ok_or("нужен --db с индексом конкретного проекта")?;
    if !db.is_file() {
        return Err(format!("индекс проекта не найден: {}", db.display()));
    }
    if action == "refresh" {
        if src.is_some() || source_id.is_some() {
            return Err("kb refresh принимает только --db; источник берётся из индекса".into());
        }
        let info = gyrfalcon_index::build::info(&db).map_err(|e| e.to_string())?;
        let mut conn = rusqlite::Connection::open(&db).map_err(|e| e.to_string())?;
        let r = help::sync(&mut conn, "primary", &PathBuf::from(info.source_path))?;
        println!("primary: HTML {}, хэшировано {}, разобрано {}, добавлено {}, обновлено {}, без изменений {}, удалено {}, текстовых байт {}",
            r.html_files, r.hashed, r.parsed, r.added, r.updated, r.unchanged, r.removed, r.text_bytes);
        return Ok(());
    }
    let source_id = source_id.ok_or("нужен --source-id")?;
    if source_id == "primary" {
        return Err(
            "источник primary управляется командами build/refresh; используйте другой source-id"
                .into(),
        );
    }
    let mut conn = rusqlite::Connection::open(&db).map_err(|e| e.to_string())?;
    match action {
        "sync" => {
            let src = src.ok_or("для kb sync нужен --src")?;
            let r = help::sync(&mut conn, &source_id, &src)?;
            println!("{source_id}: HTML {}, сырого HTML байт {}, хэшировано {}, разобрано {}, добавлено {}, обновлено {}, без изменений {}, удалено {}, коротких {}, заголовочных {}, одинаковых текстов {}, текстовых байт {}",
                r.html_files, r.raw_html_bytes, r.hashed, r.parsed, r.added, r.updated, r.unchanged, r.removed, r.skipped_short, r.title_only, r.duplicate_texts, r.text_bytes);
        }
        "remove" => {
            if src.is_some() {
                return Err("для kb remove --src не используется".into());
            }
            let n = help::remove(&mut conn, &source_id)?;
            println!("источник {source_id} отключён: удалено {n} страниц");
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// Файлы .bsl, изменившиеся после сборки индекса.
fn собрать_изменившиеся(src: &std::path::Path, built_at: u64) -> Vec<PathBuf> {
    walkdir::WalkDir::new(src)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("bsl"))
        })
        .filter(|e| {
            e.metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .is_some_and(|d| d.as_secs() > built_at + 1)
        })
        .map(walkdir::DirEntry::into_path)
        .collect()
}

fn cmd_build(args: &[String]) -> Result<(), String> {
    let mut src = None;
    let mut out = None;
    let mut dict: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out = Some(PathBuf::from(args.get(i).ok_or("--out без значения")?));
            }
            "--dict" => {
                i += 1;
                dict = Some(PathBuf::from(args.get(i).ok_or("--dict без значения")?));
            }
            other if other.starts_with("--") => return Err(format!("неизвестная опция: {other}")),
            path => src = Some(PathBuf::from(path)),
        }
        i += 1;
    }
    let src = src.ok_or("не указан путь к выгрузке")?;
    let out = out.ok_or("не указан --out")?;
    if !src.is_dir() {
        return Err(format!("не каталог: {}", src.display()));
    }

    println!("Корпус: {}", src.display());
    println!(
        "Индекс: {}
",
        out.display()
    );

    let r = gyrfalcon_index::build(&src, &out, dict.as_deref()).map_err(|e| e.to_string())?;

    println!("Модулей   {}", r.modules);
    println!("Методов   {}", r.methods);
    println!("Справка Ext/Help: HTML {}, сырого HTML байт {}, хэшировано {}, разобрано {}, добавлено {}, пропущено коротких {}, не прочитано {}, заголовочных {}, повторов текста {}, байт текста {}",
        r.help.html_files, r.help.raw_html_bytes, r.help.hashed, r.help.parsed, r.help.added, r.help.skipped_short, r.help.unreadable,
        r.help.title_only, r.help.duplicate_texts, r.help.text_bytes);
    if let Some(error) = &r.help_error {
        eprintln!("Предупреждение: справка Ext/Help не синхронизирована: {error}");
    }
    println!("Областей  {}", r.regions);
    println!("Рёбер     {}", r.calls);
    println!();

    println!("Метаданные (веха 3):");
    println!("  объектов      {:>9}", r.meta_objects);
    println!("  реквизитов    {:>9}", r.attributes);
    println!("  предопр.      {:>9}", r.predefined);
    println!("  знач. перечисл{:>9}", r.enum_values);
    println!("  состав подсист{:>9}", r.subsystem_content);
    println!("  подписки      {:>9}", r.event_subscriptions);
    println!("  регл. задания {:>9}", r.scheduled_jobs);
    println!("  функц. опции  {:>9}", r.functional_options);
    println!("  права ролей   {:>9}", r.role_rights);
    println!("  состав обмена {:>9}", r.exchange_plan_content);
    println!("  общие модули  {:>9}", r.common_modules);
    println!("  ссылки        {:>9}", r.metadata_references);
    println!(
        "  движения рег. {:>9}  (объявленные; кодовые — с вехой usages)",
        r.register_movements
    );
    println!(
        "  пакеты XDTO   {:>9}  (типов внутри: {})",
        r.xdto_packages, r.xdto_types
    );
    println!("  web-сервисы   {:>9}", r.web_services);
    println!("  HTTP-сервисы  {:>9}", r.http_services);
    println!(
        "  упоминания    {:>9}  (отброшено фильтром: {})",
        r.metadata_code_usages, r.usages_filtered
    );
    println!(
        "  элем. форм    {:>9}  (форм разобрано: {})",
        r.form_elements, r.forms
    );
    if r.extensions > 0 {
        // Расширений может не быть вовсе (на БП их нет) — тогда строки нет,
        // а не ноль: ноль перехватов и отсутствие расширений это разные факты.
        println!(
            "  перехваты рсш {:>9}  (расширений: {}{})",
            r.extension_overrides,
            r.extensions,
            if r.extension_unresolved > 0 {
                format!(", цель не найдена: {}", r.extension_unresolved)
            } else {
                String::new()
            }
        );
    }
    if r.meta_unreadable > 0 {
        // Названо отдельной строкой намеренно: неразобранный XML — это
        // потерянные данные, и молчать о них нельзя.
        println!("  НЕ РАЗОБРАНО  {:>9}  XML-файлов", r.meta_unreadable);
    }
    println!();

    let s = &r.stats;
    println!("Классы резолвинга:");
    println!("  local          {:>9}", s.local);
    println!("  common_module  {:>9}", s.common_module);
    println!("  object_manager {:>9}", s.object_manager);
    println!(
        "  platform_var   {:>9}  (неразрешимо: нужен вывод типов)",
        s.platform_var
    );
    println!(
        "  platform_global{:>9}  (неразрешимо: функция платформы)",
        s.platform_global
    );
    println!(
        "  unknown        {:>9}  (НЕ разрешили, хотя могли бы)",
        s.unknown
    );
    println!();
    println!(
        "Разрешено {} из {} разрешимых = {:.1}%   <- критерий вехи 2 (Р-005)",
        s.resolved,
        s.resolvable(),
        s.resolved_share_of_resolvable() * 100.0
    );
    println!(
        "Голая доля по всем рёбрам = {:.1}%   <- так считает прежний инструмент (у него 46,6%)",
        s.resolved_share_raw() * 100.0
    );
    println!();
    println!("Семантика (веха 4):");
    println!("  имён обработано  {:>8}", r.semantic.names);
    println!("  токенов корпуса  {:>8}", r.semantic.tokens);
    // Покрытие словарём — прямое требование контрольной точки 4.
    // Ноль здесь штатен: словарь наполняется отдельным офлайн-прогоном,
    // и до него весь корпус считается random indexing. Это НАДО видеть,
    // а не выводить по умолчанию как «всё хорошо»: качество поиска
    // на пустом словаре ниже, и молчать об этом нельзя.
    if r.semantic.dict_hits == 0 {
        println!("  покрытие словарём      0%   <- словарь ПУСТ, всё через random indexing");
    } else {
        println!(
            "  покрытие словарём  {:>6.1}%   ({} из {})",
            r.semantic.coverage() * 100.0,
            r.semantic.dict_hits,
            r.semantic.tokens
        );
    }

    println!();
    println!("Время:");
    println!("  обход      {:>7.1} c", r.walk_ms as f64 / 1000.0);
    println!("  разбор     {:>7.1} c", r.parse_ms as f64 / 1000.0);
    println!("  разрешение {:>7.1} c", r.resolve_ms as f64 / 1000.0);
    println!("  метаданные {:>7.1} c", r.meta_ms as f64 / 1000.0);
    println!("  индексы    {:>7.1} c", r.index_ms as f64 / 1000.0);
    println!("  семантика  {:>7.1} c", r.semantic.ms as f64 / 1000.0);
    println!(
        "  ИТОГО      {:>7.1} c   (порог прежнего инструмента: 605,0 c)",
        r.total_ms as f64 / 1000.0
    );

    if r.files_unreadable > 0 {
        println!(
            "
не прочитано файлов: {}",
            r.files_unreadable
        );
    }
    if r.files_with_parse_errors > 0 {
        println!(
            "с ошибками разбора: {} ({:.2}%)",
            r.files_with_parse_errors,
            r.files_with_parse_errors as f64 * 100.0 / r.modules.max(1) as f64
        );
    }
    Ok(())
}
