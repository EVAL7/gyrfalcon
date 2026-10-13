//! Прогон `check_bsl` по настоящей выгрузке: что он находит на ПРАВИЛЬНОМ
//! коде конфигурации — то есть какова доля ложных тревог.
//!
//! Служебный пример, не часть продукта. Отвечает на вопрос «инструмент
//! проверен или только собран»: юнит-тесты гоняют десяток строк, а
//! конфигурация — тысячи модулей, написанных не мной.
//!
//! ```text
//! check_bsl_corpus <индекс.db> <выгрузка> [лимит модулей] [module|union]
//! ```
//!
//! Режим `module` (по умолчанию) передаёт путь модуля — так зовёт агент,
//! знающий, какой файл правит; `union` — без него. Типовая конфигурация
//! компилируется, поэтому КАЖДОЕ замечание здесь — ложная тревога.
use gyrfalcon_mcp::check_bsl::check_bsl;
use gyrfalcon_parser::scan;
use serde_json::json;
use std::collections::HashMap;

fn main() {
    let db = std::env::args().nth(1).expect("путь к индексу");
    let срц = std::env::args().nth(2).expect("путь к выгрузке");
    let лимит: usize = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);
    let с_модулем = std::env::args().nth(4).as_deref() != Some("union");
    // Пятый аргумент — файл, куда выгрузить ВСЕ замечания слоя 3 строками
    // JSON: разбирать ложные тревоги по источникам, а не по сорока примерам.
    let mut выгрузка = std::env::args()
        .nth(5)
        .map(|p| std::io::BufWriter::new(std::fs::File::create(p).unwrap()));
    let conn =
        rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();

    let корень = std::path::Path::new(&срц);
    let paths = scan::collect_modules(корень);
    let t0 = std::time::Instant::now();
    let (mut модулей, mut проверено, mut пропущено, mut замечаний) = (0usize, 0u64, 0u64, 0usize);
    let (mut имён, mut клиентских) = (0u64, 0u64);
    let mut по_видам: HashMap<String, usize> = HashMap::new();
    let mut частоты: HashMap<String, usize> = HashMap::new();
    let mut без_оговорки = 0usize;
    let mut не_проверено: HashMap<String, usize> = HashMap::new();
    let mut откуда: HashMap<String, usize> = HashMap::new();
    let mut примеры: Vec<String> = Vec::new();
    let mut самый_долгий = (0u128, String::new());

    for p in paths.iter().take(лимит) {
        let Ok(raw) = std::fs::read(p) else { continue };
        let raw = raw.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&raw);
        let s = String::from_utf8_lossy(raw).to_string();
        let rel = p
            .strip_prefix(корень)
            .map(|r| r.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        let mut args = json!({"source": s, "limit": 200});
        if с_модулем {
            args["module"] = json!(rel);
        }
        let t = std::time::Instant::now();
        let Ok(v) = check_bsl(&conn, &args) else {
            continue;
        };
        let мс = t.elapsed().as_millis();
        if мс > самый_долгий.0 {
            самый_долгий = (мс, rel.clone());
        }
        модулей += 1;
        // Ход в stderr: прогон по ERP идёт полчаса, и «когда закончится»
        // должно быть замером, а не оценкой.
        if модулей % 1000 == 0 {
            let прошло = t0.elapsed().as_secs_f64();
            let всего = paths.len().min(лимит);
            eprintln!(
                "{модулей}/{всего}, {:.0} модулей/с, осталось ~{:.0} с",
                модулей as f64 / прошло,
                (всего - модулей) as f64 * прошло / модулей as f64
            );
        }
        проверено += v["checked_calls"].as_u64().unwrap_or(0);
        пропущено += v["skipped_calls"].as_u64().unwrap_or(0);
        имён += v["checked_names"].as_u64().unwrap_or(0);
        клиентских += v["checked_client_methods"].as_u64().unwrap_or(0);
        замечаний += v["total"].as_u64().unwrap_or(0) as usize;
        *откуда
            .entry(v["attributes_from"].as_str().unwrap_or("?").to_string())
            .or_default() += 1;
        for x in v["not_checked"].as_array().into_iter().flatten() {
            *не_проверено
                .entry(x.as_str().unwrap_or("?").chars().take(60).collect())
                .or_default() += 1;
        }
        // Оговорка обязана быть в КАЖДОМ ответе — она и есть защита от того,
        // что зелёный вердикт прочитают как «код верный».
        if !v["note"]
            .as_str()
            .map(|s| s.contains("Пропущено"))
            .unwrap_or(false)
        {
            без_оговорки += 1;
        }
        for i in v["issues"].as_array().unwrap() {
            let вид = i["kind"].as_str().unwrap_or("?").to_string();
            if let Some(w) = выгрузка.as_mut() {
                if вид == "undefined_variable" || вид == "client_context" {
                    use std::io::Write;
                    let mut x = i.clone();
                    x["module"] = json!(rel);
                    writeln!(w, "{x}").unwrap();
                }
            }
            *по_видам.entry(вид.clone()).or_default() += 1;
            let msg = i["message"].as_str().unwrap_or("?").to_string();
            *частоты.entry(format!("{вид} | {msg}")).or_default() += 1;
            if примеры.len() < 40 {
                примеры.push(format!(
                    "{rel}:{}:{} | {вид} | {msg}",
                    i["line"], i["column"]
                ));
            }
        }
    }
    let сек = t0.elapsed().as_secs_f64();
    println!(
        "режим:              {}",
        if с_модулем { "module" } else { "union" }
    );
    println!("модулей:            {модулей}");
    println!("вызовов проверено:  {проверено}");
    println!("вызовов пропущено:  {пропущено}");
    println!("имён проверено:     {имён}");
    println!("клиентских методов: {клиентских}");
    println!(
        "ЗАМЕЧАНИЙ:          {замечаний} ({:.2}% от проверенных вызовов)",
        100.0 * замечаний as f64 / проверено.max(1) as f64
    );
    println!("по видам:           {по_видам:?}");
    println!("реквизиты из:       {откуда:?}");
    println!("не проверено:       {не_проверено:?}");
    println!("ответ без оговорки: {без_оговорки}   <- обязан быть 0");
    println!(
        "время:              {сек:.1} с ({:.0} модулей/с), самый долгий {} мс: {}",
        модулей as f64 / сек.max(0.001),
        самый_долгий.0,
        самый_долгий.1
    );
    let mut топ: Vec<_> = частоты.into_iter().collect();
    топ.sort_by_key(|x| std::cmp::Reverse(x.1));
    println!("\n=== частые замечания (на правильном коде это ЛОЖНЫЕ тревоги) ===");
    for (k, n) in топ.iter().take(60) {
        println!("  {n:>6}  {k}");
    }
    println!("\n=== примеры с адресом ===");
    for s in &примеры {
        println!("  {s}");
    }
}
