use clap::Parser;
use configparser::ini::Ini;
use duration_string::DurationString;
use filenamify::filenamify;
use filetime::FileTime;
use sorted_vec::SortedSet;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
struct Args {
    /// Path of the config file
    #[arg(short, long)]
    conf: String,

    /// Whether to ignore any other running copies
    #[arg(long)]
    ignore_others: Option<bool>,
}

trait FsTraits: Send {
    fn read_to_string(&self, path: &Path) -> std::io::Result<String>;
    fn mtime(&self, path: &Path) -> std::io::Result<FileTime>;
    fn write(&self, path: &Path, data: &str) -> std::io::Result<()>;
    fn rsync(&self, source: &Path, dest: &Path) -> std::io::Result<()>;
    fn touch(&self, path: &Path) -> std::io::Result<()>;
    fn cp_al(&self, source: &Path, dest: &Path) -> std::io::Result<()>;
    fn mv(&self, source: &Path, dest: &Path) -> std::io::Result<()>;
    fn path_exists(&self, path: &Path) -> bool;
    fn is_dir(&self, path: &Path) -> Result<bool, String>;
    fn create_dir_all(&self, path: &Path) -> std::io::Result<()>;
    fn remove_file(&self, path: &Path) -> std::io::Result<()>;
    fn remove_dir_all(&self, path: &Path) -> std::io::Result<()>;
    fn sleep(&self, duration: Duration);
}

#[derive(Clone)]
struct FsImpl {}

unsafe impl Send for FsImpl {}

#[mutants::skip]
impl FsTraits for FsImpl {
    fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
        fs::read_to_string(path)
    }

    fn mtime(&self, path: &Path) -> std::io::Result<FileTime> {
        let metadata = fs::metadata(path);
        match metadata {
            Ok(metadata) => Ok(FileTime::from_last_modification_time(&metadata)),
            Err(error) => Err(error),
        }
    }

    fn write(&self, path: &Path, data: &str) -> std::io::Result<()> {
        fs::write(path, data)
    }

    fn rsync(&self, source: &Path, dest: &Path) -> std::io::Result<()> {
        if Path::exists(Path::new(dest)) {
            let metadata = fs::metadata(Path::new(dest))?;
            if !metadata.is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "{} exists but is not a directory",
                ));
            }
        } else {
            fs::create_dir_all(dest)?;
        }

        let command = format!(
            "/usr/bin/rsync -v -a --delete --numeric-ids --relative --delete-excluded {:?} {:?}",
            source, dest
        );

        self.exec_command(&command, "rsync")
    }

    fn touch(&self, path: &Path) -> std::io::Result<()> {
        let command = format!("touch {}", path.to_str().unwrap());
        self.exec_command(&command, "touch")
    }

    fn path_exists(&self, path: &Path) -> bool {
        Path::exists(path)
    }

    fn is_dir(&self, path: &Path) -> Result<bool, String> {
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return Err(format!(
                    "Could not get metadata for {:?}: {:?}",
                    path, error
                ))
            }
        };
        Ok(metadata.is_dir())
    }

    fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        fs::create_dir_all(path)
    }

    fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        println!("Executing rm {:?}", path);
        fs::remove_file(path)
    }

    fn cp_al(&self, source: &Path, dest: &Path) -> std::io::Result<()> {
        let command = format!(
            "cp -al {} {}",
            source.to_str().unwrap(),
            dest.to_str().unwrap()
        );
        self.exec_command(&command, "cp")
    }

    fn mv(&self, source: &Path, dest: &Path) -> std::io::Result<()> {
        println!("Executing mv {:?} {:?}", source, dest);
        fs::rename(source, dest)
    }

    fn remove_dir_all(&self, path: &Path) -> std::io::Result<()> {
        println!("Executing rm -rf {:?}", path);
        fs::remove_dir_all(path)
    }

    fn sleep(&self, duration: Duration) {
        thread::sleep(duration);
    }
}

impl FsImpl {
    fn exec_command(&self, command: &str, verb: &str) -> std::io::Result<()> {
        println!("Executing {}", command);

        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .output()
            .expect("failed to execute process");
        std::io::stdout().write_all(&output.stdout).unwrap();
        std::io::stderr().write_all(&output.stderr).unwrap();
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{} failed", verb),
            ));
        }
        Ok(())
    }
}

struct Settings {
    config: HashMap<std::string::String, HashMap<std::string::String, Option<std::string::String>>>,

    ignore_others: bool,
}

use std::cmp::Ordering;

#[derive(Clone, Debug)]
struct PeriodInfo {
    name: String,
    count: u32,
    interval: Duration,
}

impl Ord for PeriodInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.interval.cmp(&other.interval)
    }
}

#[mutants::skip]
impl PartialOrd for PeriodInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PeriodInfo {
    fn eq(&self, other: &Self) -> bool {
        self.interval == other.interval
    }
}

impl Eq for PeriodInfo {}

struct SourceInfo {
    path: String,
    order: u32,
}

impl Ord for SourceInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.order.cmp(&other.order)
    }
}

#[mutants::skip]
impl PartialOrd for SourceInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SourceInfo {
    fn eq(&self, other: &Self) -> bool {
        self.order == other.order
    }
}

impl Eq for SourceInfo {}

#[mutants::skip]
fn main() -> Result<(), String> {
    let args = Args::parse();
    let settings = Settings {
        config: load_config(args.conf)?,
        ignore_others: args.ignore_others.unwrap_or(false),
    };

    let result = body(FsImpl {}, settings)?;
    println!("RESULT {:?}", result);

    println!("Success");
    Ok(())
}

#[mutants::skip]
fn load_config(
    conf_path: String,
) -> Result<
    HashMap<std::string::String, HashMap<std::string::String, Option<std::string::String>>>,
    String,
> {
    let mut ini = Ini::new_cs();
    ini.load(conf_path)
}

fn body(fsimpl: impl FsTraits + Clone + 'static, settings: Settings) -> Result<(), String> {
    let fsimpl_pid_thread = fsimpl.clone();

    let context = Context {
        fsimpl: Box::new(fsimpl),
    };

    let pid_path = get_conf_key(&settings.config, "main", "pid_file", Option::None)?;

    if !settings.ignore_others {
        // exit if pid file exists and pid exists
        let other_pid = get_other_pid(&context, Path::new(&pid_path))?;
        match other_pid {
            Some(pid) => return Err(format!("Already running with PID: {:?}", pid)),
            None => (),
        }
    }

    match context
        .fsimpl
        .write(Path::new(&pid_path), &format!("{}", std::process::id()))
    {
        Ok(()) => (),
        Err(error) => {
            return Err(format!(
                "Could not write PID file {:?}: {:?}",
                pid_path, error
            ))
        }
    }

    let (stop_pid_thread_tx, stop_pid_thread_rx) = mpsc::channel();

    let pid_thread = move |path: String| loop {
        for _ in 1..600 {
            fsimpl_pid_thread.sleep(Duration::from_millis(100));
            let received = stop_pid_thread_rx.try_recv();
            match received {
                Ok(_) => return,
                Err(_) => (),
            }
        }
        fsimpl_pid_thread
            .write(Path::new(&path), &format!("{}", std::process::id()))
            .unwrap();
    };

    let pid_thread_pid_path = pid_path.clone();
    let pid_handle = thread::spawn(move || pid_thread(pid_thread_pid_path));

    let result = do_work(settings, &context);

    // del pid file
    let _ = stop_pid_thread_tx.send("done");
    let _ = pid_handle.join();

    match context.fsimpl.remove_file(Path::new(&pid_path)) {
        Ok(()) => (),
        Err(error) => {
            return Err(format!(
                "Main result: {:?} Could not remove PID file {:?}: {:?}",
                result, pid_path, error
            ))
        }
    }

    result
}

fn do_work(settings: Settings, context: &Context) -> Result<(), String> {
    let target_root = get_conf_key(&settings.config, "main", "target_root", Option::None)?;

    ensure_target_root_exists(&target_root, context, &settings)?;

    rsync_sources(&settings, &target_root, context)?;

    rotate_periods(settings, target_root, context)?;

    Ok(())
}

fn rotate_periods(
    settings: Settings,
    target_root: String,
    context: &Context,
) -> Result<(), String> {
    let periods_set = match parse_periods(settings) {
        Ok(value) => value,
        Err(value) => return Err(value),
    };

    let mut optional_last_period: Option<PeriodInfo> = None;

    for period in periods_set.iter() {
        if period == periods_set.first().unwrap() {
            //   shortest period
            //     if most recent is old enough then
            //       rm extra folders
            //       rm period.oldest if already full
            //       mv period.n-1 period.n if period.n-1 exists
            //       cp -al .sync period.0
            let newest_path_this_period =
                Path::new(&target_root).join(format!("{}.0", period.name));

            let age_secs = if context
                .fsimpl
                .path_exists(newest_path_this_period.as_path())
            {
                get_path_age_secs(context, newest_path_this_period.as_path())?
            } else {
                u64::MAX
            };

            println!(
                "Most recent period {:?} age {}s, comparing with {}s",
                newest_path_this_period,
                age_secs,
                period.interval.as_secs()
            );

            if age_secs >= period.interval.as_secs() {
                println!("Most recent period {} is old enough, rotating", period.name);

                remove_extra_period_folders(period, &target_root, context)?;

                let temp_sync_target_this_period =
                    Path::new(&target_root).join(format!("{}.new", period.name));

                cp_sync_to_period(
                    context,
                    Path::new(&target_root).join(".sync"),
                    temp_sync_target_this_period.clone(),
                )?;

                rotate_period_folders(period, &target_root, context)?;

                match context
                    .fsimpl
                    .mv(&temp_sync_target_this_period, &newest_path_this_period)
                {
                    Ok(()) => (),
                    Err(error) => {
                        return Err(format!(
                            "Could not mv {:?} to {:?}: {:?}",
                            temp_sync_target_this_period, newest_path_this_period, error
                        ))
                    }
                }
            } else {
                println!(
                    "Most recent period {} is not old enough, not rotating",
                    period.name
                );
            }
        } else {
            //   not shortest period
            //     if shorter period is full && most_recent(this period) - oldest(shorter period) >= interval
            //       rm extra folders
            //       rm period.oldest if already full
            //       mv period.n-1 period.n if period.n-1 exists
            //       mv oldest(shorter period) period.0
            let last_period = optional_last_period.unwrap();
            let newest_path_this_period =
                Path::new(&target_root).join(format!("{}.0", period.name));
            let oldest_path_last_period = Path::new(&target_root).join(format!(
                "{}.{}",
                last_period.name,
                last_period.count - 1
            ));

            let this_period_age_secs = if context
                .fsimpl
                .path_exists(newest_path_this_period.as_path())
            {
                get_path_age_secs(context, newest_path_this_period.as_path())?
            } else {
                u64::MAX
            };

            let last_period_age_secs = if context
                .fsimpl
                .path_exists(oldest_path_last_period.as_path())
            {
                get_path_age_secs(context, oldest_path_last_period.as_path())?
            } else {
                u64::MAX
            };

            let diff_secs = if this_period_age_secs >= last_period_age_secs {
                Some(this_period_age_secs - last_period_age_secs)
            } else {
                Option::None
            };

            println!(
                "Most recent period {:?} age {}s, prev period {:?} age {}s, diff {}s, comparing with {}s",
                newest_path_this_period,
                this_period_age_secs,
                oldest_path_last_period,
                last_period_age_secs,
                match diff_secs { Some(number) => number.to_string(), None => "?".to_string()},
                period.interval.as_secs()
            );

            if diff_secs.is_some() && diff_secs.unwrap() >= period.interval.as_secs() {
                println!("Other period {} is old enough, rotating", period.name);

                remove_extra_period_folders(period, &target_root, context)?;

                rotate_period_folders(period, &target_root, context)?;

                mv_periods(context, oldest_path_last_period, newest_path_this_period)?;
            } else {
                println!(
                    "Other period {} is not old enough, not rotating",
                    period.name
                );
            }
        }

        optional_last_period = Some(period.clone());
    }

    Ok(())
}

fn mv_periods(
    context: &Context,
    source: std::path::PathBuf,
    dest: std::path::PathBuf,
) -> Result<(), String> {
    match context.fsimpl.mv(&source, &dest) {
        Ok(()) => (),
        Err(error) => {
            return Err(format!(
                "Could not mv {:?} to {:?}: {:?}",
                source, dest, error
            ))
        }
    }

    Ok(())
}

fn cp_sync_to_period(
    context: &Context,
    source: std::path::PathBuf,
    destination: std::path::PathBuf,
) -> Result<(), String> {
    match context.fsimpl.cp_al(&source, &destination) {
        Ok(()) => (),
        Err(error) => {
            return Err(format!(
                "Could not cp {:?} to {:?}: {:?}",
                source, destination, error
            ))
        }
    }

    Ok(())
}

fn rotate_period_folders(
    period: &PeriodInfo,
    target_root: &String,
    context: &Context,
) -> Result<(), String> {
    for suffix in 0..period.count {
        let path = Path::new(target_root).join(format!("{}.{}", period.name, suffix));
        if suffix == period.count - 1 && context.fsimpl.path_exists(&path) {
            match context.fsimpl.remove_dir_all(path.as_path()) {
                Ok(()) => (),
                Err(error) => return Err(format!("Could not remove {:?}: {:?}", path, error)),
            }
            cycle_period_folders(suffix, target_root, period, context)?;
            break;
        }
        if !context.fsimpl.path_exists(&path) {
            cycle_period_folders(suffix, target_root, period, context)?;
            break;
        }
    }

    Ok(())
}

fn cycle_period_folders(
    suffix: u32,
    target_root: &String,
    period: &PeriodInfo,
    context: &Context,
) -> Result<(), String> {
    for mv_suffix in (0..suffix).rev() {
        let from_path = Path::new(target_root).join(format!("{}.{}", period.name, mv_suffix));
        let to_path = Path::new(target_root).join(format!("{}.{}", period.name, mv_suffix + 1));
        match context.fsimpl.mv(&from_path.as_path(), &to_path.as_path()) {
            Ok(()) => (),
            Err(error) => {
                return Err(format!(
                    "Could not move {:?} to {:?}: {:?}",
                    from_path, to_path, error
                ))
            }
        }
    }

    Ok(())
}

fn remove_extra_period_folders(
    period: &PeriodInfo,
    target_root: &String,
    context: &Context,
) -> Result<(), String> {
    for suffix in period.count..102 {
        let path = Path::new(target_root).join(format!("{}.{}", period.name, suffix));
        if context.fsimpl.path_exists(&path) {
            println!("Removing period {:?}", path);
            match context.fsimpl.remove_file(path.as_path()) {
                Ok(()) => (),
                Err(error) => {
                    return Err(format!("Could not remove period {:?}: {:?}", path, error))
                }
            }
        }
    }

    Ok(())
}

fn rsync_sources(
    settings: &Settings,
    target_root: &String,
    context: &Context,
) -> Result<(), String> {
    let sources = match settings.config.get("sources") {
        Some(main) => main,
        None => return Err(String::from("No sources section in config")),
    };

    let mut sources_set: SortedSet<SourceInfo> = SortedSet::new();
    for (source_order, path_option) in sources {
        let path = match path_option {
            Some(path) => path,
            None => return Err(format!("No path for source {:?}", source_order)),
        };

        let order = match source_order.parse::<u32>() {
            Ok(count) => count,
            Err(_) => {
                return Err(format!(
                    "Could not parse order for source: {}={}",
                    source_order, path
                ))
            }
        };

        sources_set.push(SourceInfo {
            path: path.to_string(),
            order: order,
        });
    }

    let sync_pathbuf = Path::new(&target_root).join(".sync");
    let sync_path = sync_pathbuf.as_path();

    for source in sources_set.iter() {
        println!("SOURCE {:?}", source.path);

        if !context.fsimpl.path_exists(sync_path) {
            match context.fsimpl.create_dir_all(sync_path) {
                Ok(()) => (),
                Err(error) => {
                    return Err(format!(
                        "Could not create .sync dir {:?}: {:?}",
                        sync_path, error
                    ));
                }
            }
        }

        match context.fsimpl.rsync(Path::new(&source.path), sync_path) {
            Ok(_) => (),
            Err(error) => {
                return Err(format!(
                    "Could not rsync {} to {:?}: {:?}",
                    source.path, sync_path, error
                ))
            }
        }
    }

    match context.fsimpl.touch(sync_path) {
        Ok(_) => (),
        Err(error) => return Err(format!("Could not touch {:?}: {:?}", sync_path, error)),
    }

    Ok(())
}

fn ensure_target_root_exists(
    target_root: &String,
    context: &Context,
    settings: &Settings,
) -> Result<(), String> {
    let target_path = Path::new(target_root);
    Ok(if context.fsimpl.path_exists(&target_path) {
        if !context.fsimpl.is_dir(&target_path)? {
            return Err(format!("{} is not a directory", target_root));
        }
    } else {
        if get_conf_key(
            &settings.config,
            "main",
            "can_create_target_root",
            Some("false".to_string()),
        )? == "true"
        {
            match context.fsimpl.create_dir_all(&target_path) {
                Ok(()) => (),
                Err(error) => {
                    return Err(format!(
                        "Could not create target root dir {:?}: {:?}",
                        target_root, error
                    ))
                }
            }
        } else {
            return Err(format!("Target root {:?} does not exist", target_root));
        }
    })
}

fn parse_periods(settings: Settings) -> Result<SortedSet<PeriodInfo>, String> {
    let periods = match settings.config.get("periods") {
        Some(main) => main,
        None => return Err(String::from("No periods section in config")),
    };
    let mut periods_set = SortedSet::new();
    for (period_name, details) in periods {
        if period_name.len() == 0 {
            return Err(String::from("An empty period name was found"));
        }
        if filenamify(&period_name).ne(period_name) {
            return Err(format!("Invalid period name: {}", period_name));
        }

        let details_str = details.clone().unwrap_or("".to_string());
        let parts = details_str.split("@").collect::<Vec<&str>>();
        if parts.len() != 2 {
            return Err(format!(
                "Invalid period details (should be <count>@<interval>) for {}: {}",
                period_name, details_str
            ));
        }
        let count = match parts[0].parse::<u32>() {
            Ok(count) => count,
            Err(_) => {
                return Err(format!(
                    "Could not parse count (should be 1-100) for {}: {}",
                    period_name, details_str
                ))
            }
        };
        if count < 1 || count > 100 {
            return Err(format!(
                "Count should be 1-100 for {}: {}",
                period_name, details_str
            ));
        }
        let duration = DurationString::from_string(parts[1].to_string());
        let interval: Duration = match duration {
            Ok(duration) => duration.into(),
            Err(_) => {
                return Err(format!(
                    "Could not parse interval (should be 1s-1y) for {}: {}",
                    period_name, details_str
                ))
            }
        };
        if interval < Duration::from_secs(60 * 60)
            || interval
                > DurationString::from_string(String::from("5y"))
                    .unwrap()
                    .into()
        {
            return Err(format!(
                "Interval should be 1h-5y for {}: {}",
                period_name, details_str
            ));
        }

        periods_set.push(PeriodInfo {
            name: period_name.clone(),
            count: count,
            interval: interval,
        });
    }
    Ok(periods_set)
}

fn get_conf_key(
    config: &HashMap<
        std::string::String,
        HashMap<std::string::String, Option<std::string::String>>,
    >,
    section: &str,
    key: &str,
    default: Option<String>,
) -> Result<String, String> {
    let section_hash = match config.get(section) {
        Some(main) => main,
        None => return Err(format!("No {} section in config", section)),
    };

    let value = match section_hash.get(key) {
        Some(value) => value.clone().unwrap(),
        None => {
            if default.is_none() {
                return Err(format!("No {} in {} section of config", key, section));
            } else {
                return Ok(default.unwrap());
            }
        }
    };

    Ok(value)
}

struct Context {
    fsimpl: Box<dyn FsTraits>,
}

fn get_other_pid(context: &Context, pid_path: &Path) -> Result<Option<String>, String> {
    println!("Checking PID file {:?}", pid_path);

    let pid = match context.fsimpl.read_to_string(pid_path) {
        Ok(pid) => pid,
        Err(ref error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("PID file {:?} not found", pid_path);
            return Ok(None);
        }
        Err(error) => {
            return Err(format!(
                "Could not read PID file {:?}: {:?} {:?}",
                pid_path,
                error.kind(),
                error.to_string()
            ))
        }
    };

    let age_secs = get_path_age_secs(context, pid_path)?;

    if age_secs > 300 {
        println!("PID file {:?} written more than 5 minutes ago", pid_path);
        return Ok(None);
    }

    println!("PID file {:?} written recently by PID {:?}", pid_path, pid);
    Ok(Some(pid))
}

fn get_path_age_secs(context: &Context, path: &Path) -> Result<u64, String> {
    let mtime = match context.fsimpl.mtime(path) {
        Ok(mtime) => mtime,
        Err(error) => {
            return Err(format!(
                "Could not get mtime of {:?}: {:?} {:?}",
                path,
                error.kind(),
                error.to_string()
            ))
        }
    };
    let now = SystemTime::now();
    let age_secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs()
        - <i64 as TryInto<u64>>::try_into(mtime.unix_seconds()).unwrap();
    println!(
        "Path {:?} mtime {:?} vs now {:?} = age {:?} secs",
        path, mtime, now, age_secs
    );
    Ok(age_secs)
}

#[cfg(test)]
mod tests {

    use super::*;
    use mockall::*;
    use std::{
        ops::Sub,
        sync::{Arc, Mutex},
    };

    mock! {
        pub FsImpl {
        }
        impl FsTraits for FsImpl {
            fn read_to_string(&self, path: &Path) -> std::io::Result<String>;
            fn mtime(&self, path: &Path) -> std::io::Result<FileTime>;
            fn write(&self, path: &Path, data: &str) -> std::io::Result<()>;
            fn rsync(&self, source: &Path, dest: &Path) -> std::io::Result<()>;
            fn touch(&self, path: &Path) -> std::io::Result<()>;
            fn path_exists(&self, path: &Path) -> bool;
            fn is_dir(&self, path: &Path) -> Result<bool, String>;
            fn create_dir_all(&self, path: &Path) -> std::io::Result<()>;
            fn remove_file(&self, path: &Path) -> std::io::Result<()>;
            fn cp_al(&self, source: &Path, dest: &Path) -> std::io::Result<()>;
            fn mv(&self, source: &Path, dest: &Path) -> std::io::Result<()>;
            fn remove_dir_all(&self, path: &Path) -> std::io::Result<()>;
            fn sleep(&self, duration: Duration);
        }
        impl Clone for FsImpl {
            fn clone(&self) -> Self;
        }
    }

    #[test]
    fn if_pid_file_does_not_exist_then_should_run() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=\n[sources]\n[periods]",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let (sleep_signal_tx, sleep_signal_rx) = mpsc::channel();
        let sleep_signal_rx = Arc::new(Mutex::new(sleep_signal_rx));
        let mut mock = MockFsImpl::new();
        let mut mock2 = MockFsImpl::new();
        mock2.expect_sleep().times(1).return_once(move |_| {
            let _ = sleep_signal_rx.lock().unwrap().try_recv();
        });
        mock.expect_write().times(1).return_once(|_, _| Ok(()));
        mock.expect_clone().times(1).return_once(move || mock2);
        mock.expect_read_to_string().times(1).return_once(move |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File Not Found",
            ))
        });
        mock.expect_path_exists().times(1).return_once(|_| true);
        mock.expect_is_dir().times(1).return_once(|_| Ok(true));
        mock.expect_touch().times(1).return_once(|_| Ok(()));
        mock.expect_remove_file().times(1).return_once(|_| Ok(()));

        let result = body(mock, settings).unwrap();
        assert_eq!(result, ());
        let _ = sleep_signal_tx.send("wake-up");
    }

    #[test]
    fn if_pid_file_read_error_then_should_exit() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from("[main]\npid_file=/var/run/safersync.pid"))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        let mock2 = MockFsImpl::new();
        mock.expect_clone().times(1).return_once(move || mock2);
        mock.expect_read_to_string().times(1).return_once(move |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "Connection Reset",
            ))
        });

        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from(
                "Could not read PID file \"/var/run/safersync.pid\": ConnectionReset \"Connection Reset\""
            ))
        );
    }

    #[test]
    fn if_pid_file_write_error_then_should_exit() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from("[main]\npid_file=/var/run/safersync.pid"))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        let mock2 = MockFsImpl::new();
        mock.expect_write().times(1).return_once(|_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Permission Denied",
            ))
        });
        mock.expect_clone().times(1).return_once(move || mock2);
        mock.expect_read_to_string().times(1).return_once(move |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File Not Found",
            ))
        });

        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from(
                "Could not write PID file \"/var/run/safersync.pid\": Custom { kind: PermissionDenied, error: \"Permission Denied\" }"
            ))
        );
    }

    #[test]
    fn if_running_then_should_keep_writing_pid_file() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=\n[sources]\n[periods]",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let (write_signal_tx, write_signal_rx) = mpsc::channel();
        let write_signal_rx = Arc::new(Mutex::new(write_signal_rx));
        let write_signal_rx2 = write_signal_rx.clone();
        let write_signal_rx3 = write_signal_rx.clone();
        let write_signal_tx = Arc::new(Mutex::new(write_signal_tx));
        let write_signal_tx2 = write_signal_tx.clone();
        let mut mock = MockFsImpl::new();
        let mut mock2 = MockFsImpl::new();
        mock2.expect_sleep().returning(|_| {});
        mock2.expect_write().times(2).returning(move |_, _| {
            let _ = write_signal_tx.lock().unwrap().send("written");
            Ok(())
        });
        mock.expect_write().times(1).return_once(move |_, _| {
            let _ = write_signal_tx2.lock().unwrap().send("written");
            Ok(())
        });
        mock.expect_clone().times(1).return_once(move || mock2);
        mock.expect_read_to_string().times(1).return_once(move |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File Not Found",
            ))
        });
        mock.expect_path_exists().times(1).return_once(move |_| {
            let _ = write_signal_rx.lock().unwrap().recv().unwrap();
            true
        });
        mock.expect_is_dir().times(1).return_once(move |_| {
            let _ = write_signal_rx2.lock().unwrap().recv().unwrap();
            Ok(true)
        });
        mock.expect_touch().times(1).return_once(move |_| {
            let _ = write_signal_rx3.lock().unwrap().recv().unwrap();
            Ok(())
        });
        mock.expect_remove_file().times(1).return_once(|_| Ok(()));

        let result = body(mock, settings).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_ignoring_others_then_should_run() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=\n[sources]\n[periods]",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: true,
        };

        let (sleep_signal_tx, sleep_signal_rx) = mpsc::channel();
        let sleep_signal_rx = Arc::new(Mutex::new(sleep_signal_rx));
        let mut mock = MockFsImpl::new();
        let mut mock2 = MockFsImpl::new();
        mock2.expect_sleep().times(1).return_once(move |_| {
            let _ = sleep_signal_rx.lock().unwrap().try_recv();
        });
        mock.expect_write().times(1).return_once(move |_, _| Ok(()));
        mock.expect_clone().times(1).return_once(move || mock2);
        mock.expect_path_exists().times(1).return_once(|_| true);
        mock.expect_is_dir().times(1).return_once(|_| Ok(true));
        mock.expect_touch().times(1).return_once(|_| Ok(()));
        mock.expect_remove_file().times(1).return_once(|_| Ok(()));

        let result = body(mock, settings).unwrap();
        assert_eq!(result, ());
        let _ = sleep_signal_tx.send("wake-up");
    }

    #[test]
    fn if_pid_file_was_written_within_five_minutes_then_should_exit() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from("[main]\npid_file=/var/run/safersync.pid"))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        let mock2 = MockFsImpl::new();
        mock.expect_clone().times(1).return_once(move || mock2);
        mock.expect_read_to_string()
            .times(1)
            .return_once(move |_| Ok(String::from("1")));
        mock.expect_mtime().times(1).return_once(move |_| {
            Ok(FileTime::from_system_time(
                std::time::SystemTime::now().sub(std::time::Duration::from_secs(290)),
            ))
        });

        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(error, Err(String::from("Already running with PID: \"1\"")));
    }

    #[test]
    fn if_pid_file_was_written_over_five_minutes_ago_then_should_run() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=\n[sources]\n[periods]",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let (sleep_signal_tx, sleep_signal_rx) = mpsc::channel();
        let sleep_signal_rx = Arc::new(Mutex::new(sleep_signal_rx));
        let mut mock = MockFsImpl::new();
        let mut mock2 = MockFsImpl::new();
        mock2.expect_sleep().times(1).return_once(move |_| {
            let _ = sleep_signal_rx.lock().unwrap().try_recv();
        });
        mock.expect_write().times(1).return_once(move |_, _| Ok(()));
        mock.expect_clone().times(1).return_once(move || mock2);
        mock.expect_read_to_string()
            .times(1)
            .return_once(move |_| Ok(String::from("1")));
        mock.expect_mtime().times(1).return_once(move |_| {
            Ok(FileTime::from_system_time(
                std::time::SystemTime::now().sub(std::time::Duration::from_secs(301)),
            ))
        });
        mock.expect_path_exists().times(1).return_once(|_| true);
        mock.expect_is_dir().times(1).return_once(|_| Ok(true));
        mock.expect_touch().times(1).return_once(|_| Ok(()));
        mock.expect_remove_file().times(1).return_once(|_| Ok(()));

        let result = body(mock, settings).unwrap();
        assert_eq!(result, ());
        let _ = sleep_signal_tx.send("wake-up");
    }

    #[test]
    fn if_rsync_source_has_no_source_then_should_fail() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=\n[sources]\n1",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mock = MockFsImpl::new();
        let target_root = String::from("");
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = rsync_sources(&settings, &target_root, &context).map_err(|e| e);
        assert_eq!(error, Err(String::from("No path for source \"1\"")));
    }

    #[test]
    fn if_rsync_source_has_something_other_than_a_number_then_should_fail() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=\n[sources]\nA=B",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mock = MockFsImpl::new();
        let target_root = String::from("");
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = rsync_sources(&settings, &target_root, &context).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from("Could not parse order for source: A=B"))
        );
    }

    #[test]
    fn if_target_root_does_not_exist_and_creation_allowed_then_create_it() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=/a\ncan_create_target_root=true\n[sources]\n1=/A\n[periods]",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(1).returning(|_| false);
        mock.expect_create_dir_all()
            .times(1)
            .return_once(|_| Ok(()));

        let target_root = String::from("/a");
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let result = ensure_target_root_exists(&target_root, &context, &settings).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_target_root_does_not_exist_and_creation_forbidden_then_error() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=/a\ncan_create_target_root=false\n[sources]\n1=/A\n[periods]",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(1).returning(|_| false);

        let target_root = String::from("/a");
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = ensure_target_root_exists(&target_root, &context, &settings).unwrap_err();
        let exp_error = format!("Target root {:?} does not exist", Path::new("/a"));
        assert_eq!(error, exp_error);
    }

    #[test]
    fn if_target_root_does_not_exist_and_creation_not_specified_then_error() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=/a\n[sources]\n1=/A\n[periods]",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(1).returning(|_| false);

        let target_root = String::from("/a");
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = ensure_target_root_exists(&target_root, &context, &settings).unwrap_err();
        let exp_error = format!("Target root {:?} does not exist", Path::new("/a"));
        assert_eq!(error, exp_error);
    }

    #[test]
    fn if_target_root_cannot_be_created_then_error() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=/a\ncan_create_target_root=true\n[sources]\n1=/A\n[periods]",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(1).returning(|_| false);
        mock.expect_create_dir_all()
            .times(1)
            .return_once(|_| Err(std::io::Error::new(std::io::ErrorKind::Other, "error")));

        let target_root = String::from("/a");
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = ensure_target_root_exists(&target_root, &context, &settings).unwrap_err();
        let exp_error = format!(
            "Could not create target root dir {:?}: Custom {{ kind: Other, error: \"error\" }}",
            Path::new("/a")
        );
        assert_eq!(error, exp_error);
    }

    #[test]
    fn rsync_multiple_sources() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=\n[sources]\n1=/A\n2=/C\n[periods]",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let (sleep_signal_tx, sleep_signal_rx) = mpsc::channel();
        let sleep_signal_rx = Arc::new(Mutex::new(sleep_signal_rx));
        let mut mock = MockFsImpl::new();
        let mut mock2 = MockFsImpl::new();
        mock2.expect_sleep().times(1).return_once(move |_| {
            let _ = sleep_signal_rx.lock().unwrap().try_recv();
        });
        mock.expect_write().times(1).return_once(move |_, _| Ok(()));
        mock.expect_clone().times(1).return_once(move || mock2);
        mock.expect_read_to_string().times(1).return_once(move |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File Not Found",
            ))
        });
        mock.expect_path_exists().times(3).return_const(true);
        mock.expect_is_dir().times(1).return_once(|_| Ok(true));
        mock.expect_rsync().times(2).returning(move |_, _| Ok(()));
        mock.expect_touch().times(1).return_once(|_| Ok(()));
        mock.expect_remove_file().times(1).return_once(|_| Ok(()));

        let result = body(mock, settings).unwrap();
        assert_eq!(result, ());
        let _ = sleep_signal_tx.send("wake-up");
    }

    #[test]
    fn if_rsync_fails_then_exits() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=\n[sources]\n1=/A\n2=/C",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(1).return_const(true);
        mock.expect_rsync().times(1).return_once(move |_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "rsync failed",
            ))
        });

        let target_root = String::from("");
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = rsync_sources(&settings, &target_root, &context).map_err(|e| e);
        assert_eq!(
            error,
            Err(format!(
                "Could not rsync /A to {:?}: Custom {{ kind: Other, error: \"rsync failed\" }}",
                ".sync"
            ))
        );
    }

    #[test]
    fn if_multiple_sources_then_obey_source_order() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=\n[sources]\n10=/A\n9=/C",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(1).return_const(true);
        mock.expect_rsync().times(1).return_once(move |_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "rsync failed",
            ))
        });

        let target_root = String::from("");
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = rsync_sources(&settings, &target_root, &context).map_err(|e| e);
        assert_eq!(
            error,
            Err(format!(
                "Could not rsync /C to {:?}: Custom {{ kind: Other, error: \"rsync failed\" }}",
                ".sync"
            ))
        );
    }

    fn arrange_periods_test(periods: &str) -> Settings {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(format!(
                "[main]
                pid_file=/var/run/safersync.pid
                target_root=
                [sources]
                1=/A
                2=/C
                [periods]
                {}",
                periods
            )))
            .unwrap();
        Settings {
            config: config,
            ignore_others: false,
        }
    }

    #[test]
    fn if_period_is_shortest_allowed_then_ok() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(format!(
                "[main]
                pid_file=/var/run/safersync.pid
                target_root=
                [sources]
                1=/A
                2=/C
                [periods]
                a=1@1h",
            )))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let result = parse_periods(settings).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn if_period_is_longest_allowed_then_ok() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(format!(
                "[main]
                pid_file=/var/run/safersync.pid
                target_root=
                [sources]
                1=/A
                2=/C
                [periods]
                a=1@5y",
            )))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let result = parse_periods(settings).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn if_multiple_periods_then_check_sorted() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[periods]
                a=1@1w
                b=1@1y
                c=1@1d
                d=1@1h",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let result = parse_periods(settings).unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(
            result
                .iter()
                .map(|x| x.name.clone())
                .collect::<Vec<String>>(),
            vec!["d", "c", "a", "b"]
        );
    }

    #[test]
    fn if_invalid_period_name_then_error() {
        let settings = arrange_periods_test("/=1@1d");
        let error = parse_periods(settings).map_err(|e| e);
        assert_eq!(error, Err(String::from("Invalid period name: /")));
    }

    #[test]
    fn if_invalid_period_details_format_then_error() {
        let settings = arrange_periods_test("a=1");
        let error = parse_periods(settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from(
                "Invalid period details (should be <count>@<interval>) for a: 1"
            ))
        );
    }

    #[test]
    fn if_invalid_period_count_then_error() {
        let settings = arrange_periods_test("a=a@1h");
        let error = parse_periods(settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from(
                "Could not parse count (should be 1-100) for a: a@1h"
            ))
        );
    }

    #[test]
    fn if_period_count_too_few_then_error() {
        let settings = arrange_periods_test("a=0@1h");
        let error = parse_periods(settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from("Count should be 1-100 for a: 0@1h"))
        );
    }

    #[test]
    fn if_period_count_too_many_then_error() {
        let settings = arrange_periods_test("a=101@1h");
        let error = parse_periods(settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from("Count should be 1-100 for a: 101@1h"))
        );
    }

    #[test]
    fn if_invalid_period_length_then_error() {
        let settings = arrange_periods_test("a=1@xyz");
        let error = parse_periods(settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from(
                "Could not parse interval (should be 1s-1y) for a: 1@xyz"
            ))
        );
    }

    #[test]
    fn if_period_too_short_then_error() {
        let settings = arrange_periods_test("a=1@59m");
        let error = parse_periods(settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from("Interval should be 1h-5y for a: 1@59m"))
        );
    }

    #[test]
    fn if_period_too_long_then_error() {
        let settings = arrange_periods_test("a=1@5y1d");
        let error = parse_periods(settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from("Interval should be 1h-5y for a: 1@5y1d"))
        );
    }

    #[test]
    fn if_shortest_period_does_not_exist_then_create_it() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=tr\n[sources]\n1=/A\n[periods]\nhourly=1@1h",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists()
            .times(1 + 101 + 2)
            .returning(|path| {
                if path == Path::new("tr") || path == Path::new("tr").join(".sync") {
                    true
                } else if path == Path::new("tr").join("hourly.0") {
                    false
                } else {
                    false
                }
            });
        mock.expect_cp_al().times(1).return_once(|_, _| Ok(()));
        mock.expect_mv()
            .times(1)
            .withf(|source, dest| {
                source == Path::new("tr").join("hourly.new")
                    && dest == Path::new("tr").join("hourly.0")
            })
            .return_once(|_, _| Ok(()));

        let context = Context {
            fsimpl: Box::new(mock),
        };

        let result = rotate_periods(settings, String::from("tr"), &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_cannot_create_shortest_period_then_error() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=tr\n[sources]\n1=/A\n[periods]\nhourly=1@1h",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(1 + 101).returning(|path| {
            if path == Path::new("tr") || path == Path::new("tr").join(".sync") {
                true
            } else if path == Path::new("tr").join("hourly.0") {
                false
            } else {
                false
            }
        });
        mock.expect_cp_al().times(1).return_once(|_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File Not Found",
            ))
        });

        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = rotate_periods(settings, "tr".to_string(), &context).map_err(|e| e);
        assert_eq!(
            error,
            Err(format!(
                "Could not cp {:?} to {:?}: Custom {{ kind: NotFound, error: \"File Not Found\" }}",
                Path::new("tr").join(".sync"),
                Path::new("tr").join("hourly.new")
            ))
        );
    }

    #[test]
    fn if_shortest_period_is_new_then_do_nothing() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=tr\n[sources]\n1=/A\n[periods]\nhourly=1@1h",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(1).return_const(true);
        mock.expect_mtime()
            .times(1)
            .return_once(move |_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));

        let context = Context {
            fsimpl: Box::new(mock),
        };

        let result = rotate_periods(settings, "tr".to_string(), &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_shortest_period_is_old_then_remove_old_copies() {
        let period = PeriodInfo {
            name: String::from("hourly"),
            count: 3,
            interval: Duration::from_secs(3600),
        };
        let target_root = String::from(".");
        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(99).returning(|path| {
            if path == Path::new(".").join("hourly.10") {
                false
            } else {
                true
            }
        });
        mock.expect_remove_file().times(98).returning(|path| {
            assert!(path != Path::new(".").join("hourly.10"));
            Ok(())
        });
        let context = Context {
            fsimpl: Box::new(mock),
        };
        let result = remove_extra_period_folders(&period, &target_root, &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_cannot_remove_old_shortest_period_then_error() {
        let period = PeriodInfo {
            name: String::from("hourly"),
            count: 3,
            interval: Duration::from_secs(3600),
        };
        let target_root = String::from(".");
        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(8).return_const(true);
        mock.expect_remove_file().times(8).returning(|path| {
            if path == Path::new(".").join("hourly.10") {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "File Not Found",
                ))
            } else {
                Ok(())
            }
        });
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = remove_extra_period_folders(&period, &target_root, &context);
        assert_eq!(
            error,
            Err(format!(
                "Could not remove period {:?}: Custom {{ kind: NotFound, error: \"File Not Found\" }}",
                Path::new(".").join("hourly.10")
            ))
        );
    }

    #[test]
    fn if_shortest_period_is_old_then_rotate_folders() {
        let period = PeriodInfo {
            name: String::from("hourly"),
            count: 3,
            interval: Duration::from_secs(3600),
        };
        let target_root = String::from(".");
        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(4).returning(|path| {
            if path == Path::new(".").join("hourly.2") {
                false
            } else {
                true
            }
        });
        mock.expect_mv()
            .withf(|f, t| {
                f == Path::new(".").join("hourly.1") && t == Path::new(".").join("hourly.2")
            })
            .times(1)
            .return_once(|_, _| Ok(()));
        mock.expect_mv()
            .withf(|f, t| {
                f == Path::new(".").join("hourly.0") && t == Path::new(".").join("hourly.1")
            })
            .times(1)
            .return_once(|_, _| Ok(()));
        let context = Context {
            fsimpl: Box::new(mock),
        };
        let result = rotate_period_folders(&period, &target_root, &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_cannot_rotate_shortest_period_then_error() {
        let period = PeriodInfo {
            name: String::from("hourly"),
            count: 3,
            interval: Duration::from_secs(3600),
        };
        let target_root = String::from(".");
        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(4).returning(|path| {
            if path == Path::new(".").join("hourly.2") {
                false
            } else {
                true
            }
        });
        mock.expect_mv()
            .withf(|f, t| {
                f == Path::new(".").join("hourly.1") && t == Path::new(".").join("hourly.2")
            })
            .times(1)
            .return_once(|_, _| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "File Not Found",
                ))
            });
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = rotate_period_folders(&period, &target_root, &context);
        assert_eq!(
            error,
            Err(format!(
                "Could not move {:?} to {:?}: Custom {{ kind: NotFound, error: \"File Not Found\" }}",
                Path::new(".").join("hourly.1"),
                Path::new(".").join("hourly.2")
            ))
        );
    }

    #[test]
    fn if_shortest_period_is_old_and_folders_full_then_remove_oldest() {
        let period = PeriodInfo {
            name: String::from("hourly"),
            count: 3,
            interval: Duration::from_secs(3600),
        };
        let target_root = String::from(".");
        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(3).return_const(true);
        mock.expect_remove_dir_all()
            .withf(|path| path == Path::new(".").join("hourly.2"))
            .times(1)
            .return_once(|_| Ok(()));
        mock.expect_mv()
            .withf(|f, t| {
                f == Path::new(".").join("hourly.1") && t == Path::new(".").join("hourly.2")
            })
            .times(1)
            .return_once(|_, _| Ok(()));
        mock.expect_mv()
            .withf(|f, t| {
                f == Path::new(".").join("hourly.0") && t == Path::new(".").join("hourly.1")
            })
            .times(1)
            .return_once(|_, _| Ok(()));
        let context = Context {
            fsimpl: Box::new(mock),
        };
        let result = rotate_period_folders(&period, &target_root, &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_shortest_period_is_old_and_folders_full_and_remove_fails_then_error() {
        let period = PeriodInfo {
            name: String::from("hourly"),
            count: 3,
            interval: Duration::from_secs(3600),
        };
        let target_root = String::from(".");
        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(3).return_const(true);
        mock.expect_remove_dir_all()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.2"))
            .return_once(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "File Not Found",
                ))
            });
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = rotate_period_folders(&period, &target_root, &context);
        assert_eq!(
            error,
            Err(format!(
                "Could not remove {:?}: Custom {{ kind: NotFound, error: \"File Not Found\" }}",
                Path::new(".").join("hourly.2")
            ))
        );
    }

    #[test]
    fn if_shortest_period_is_old_then_cp_sync_folder() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=tr\n[sources]\n1=/A\n[periods]\nhourly=1@1h",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");
        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(103).returning(|path| {
            if path == Path::new(".").join("hourly.0") {
                true
            } else {
                false
            }
        });
        mock.expect_remove_dir_all()
            .withf(|path| path == Path::new(".").join("hourly.0"))
            .times(1)
            .return_once(|_| Ok(()));
        mock.expect_mtime().times(1).return_once(move |_| {
            Ok(FileTime::from_system_time(
                std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600)),
            ))
        });
        mock.expect_cp_al().times(1).return_once(|_, _| Ok(()));
        mock.expect_mv()
            .times(1)
            .withf(|source, dest| {
                source == Path::new(".").join("hourly.new")
                    && dest == Path::new(".").join("hourly.0")
            })
            .return_once(|_, _| Ok(()));
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let result = rotate_periods(settings, target_root, &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_cannot_cp_sync_to_shortest_period_then_error() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=tr\n[sources]\n1=/A\n[periods]\nhourly=1@1h",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");
        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(102).returning(|path| {
            if path == Path::new(".").join("hourly.0") {
                true
            } else {
                false
            }
        });
        mock.expect_mtime().times(1).return_once(move |_| {
            Ok(FileTime::from_system_time(
                std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600)),
            ))
        });
        mock.expect_cp_al().times(1).return_once(|_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File Not Found",
            ))
        });
        let context = Context {
            fsimpl: Box::new(mock),
        };
        let error = rotate_periods(settings, target_root, &context);
        assert_eq!(
            error,
            Err(format!(
                "Could not cp {:?} to {:?}: Custom {{ kind: NotFound, error: \"File Not Found\" }}",
                Path::new(".").join(".sync"),
                Path::new(".").join("hourly.new")
            ))
        );
    }

    #[test]
    fn if_shortest_period_is_not_full_then_do_not_create_other_period() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=.\n[sources]\n1=/A\n[periods]\nhourly=2@1h\ndaily=1@1d",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(3).returning(|path| {
            if path == Path::new(".").join("hourly.1") {
                false
            } else if path == Path::new(".").join("daily.0") {
                false
            } else {
                true
            }
        });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.0"))
            .returning(|_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let result = rotate_periods(settings, target_root, &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_shortest_period_is_full_and_other_period_does_not_exist_then_mv() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=.\n[sources]\n1=/A\n[periods]\nhourly=2@1h\ndaily=1@1d",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists()
            .times(4 + 101 + 1)
            .returning(|path| {
                if path == Path::new(".").join("hourly.0")
                    || path == Path::new(".").join("hourly.1")
                {
                    true
                } else {
                    false
                }
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.0"))
            .returning(|_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.1"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600 * 24)),
                ))
            });
        mock.expect_mv().times(1).return_once(|_, _| Ok(()));
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let result = rotate_periods(settings, target_root, &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_shortest_period_is_full_and_other_period_is_new_then_do_nothing() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=.\n[sources]\n1=/A\n[periods]\nhourly=2@1h\ndaily=1@1d",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(3).returning(|path| {
            if path == Path::new(".").join("hourly.0")
                || path == Path::new(".").join("hourly.1")
                || path == Path::new(".").join("daily.0")
            {
                true
            } else {
                false
            }
        });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.0"))
            .returning(|_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.1"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600 * 24)),
                ))
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("daily.0"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600 * 24)),
                ))
            });
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let result = rotate_periods(settings, target_root, &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_shortest_period_is_older_than_other_period_then_do_nothing() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=.\n[sources]\n1=/A\n[periods]\nhourly=2@1h\ndaily=1@1d",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(3).returning(|path| {
            if path == Path::new(".").join("hourly.0")
                || path == Path::new(".").join("hourly.1")
                || path == Path::new(".").join("daily.0")
            {
                true
            } else {
                false
            }
        });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.0"))
            .returning(|_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.1"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600 * 24)),
                ))
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("daily.0"))
            .returning(|_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let result = rotate_periods(settings, target_root, &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_shortest_period_is_full_and_other_period_is_old_then_mv() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=.\n[sources]\n1=/A\n[periods]\nhourly=2@1h\ndaily=1@1d",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists()
            .times(3 + 101 + 1)
            .returning(|path| {
                if path == Path::new(".").join("hourly.0")
                    || path == Path::new(".").join("hourly.1")
                    || path == Path::new(".").join("daily.0")
                {
                    true
                } else {
                    false
                }
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.0"))
            .returning(|_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.1"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600)),
                ))
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("daily.0"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600 * 25)),
                ))
            });
        mock.expect_remove_dir_all()
            .times(1)
            .return_once(|_| Ok(()));
        mock.expect_mv().times(1).return_once(|_, _| Ok(()));
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let result = rotate_periods(settings, target_root, &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_cannot_mv_to_other_period_then_error() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=.\n[sources]\n1=/A\n[periods]\nhourly=2@1h\ndaily=1@1d",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists()
            .times(3 + 101 + 1)
            .returning(|path| {
                if path == Path::new(".").join("hourly.0")
                    || path == Path::new(".").join("hourly.1")
                    || path == Path::new(".").join("daily.0")
                {
                    true
                } else {
                    false
                }
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.0"))
            .returning(|_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.1"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600)),
                ))
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("daily.0"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600 * 25)),
                ))
            });
        mock.expect_remove_dir_all()
            .times(1)
            .return_once(|_| Ok(()));
        mock.expect_mv()
            .times(1)
            .return_once(|_, _| Err(std::io::Error::new(std::io::ErrorKind::Other, "error")));
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = rotate_periods(settings, target_root, &context).map_err(|e| e);
        let exp_error = Err(format!(
            "Could not mv {:?} to {:?}: Custom {{ kind: Other, error: \"error\" }}",
            Path::new(".").join("hourly.1"),
            Path::new(".").join("daily.0")
        ));
        assert_eq!(error, exp_error);
    }

    #[test]
    fn if_cannot_remove_old_other_period_then_error() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=.\n[sources]\n1=/A\n[periods]\nhourly=2@1h\ndaily=1@1d",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists()
            .times(3 + 101 + 1)
            .returning(|path| {
                if path == Path::new(".").join("hourly.0")
                    || path == Path::new(".").join("hourly.1")
                    || path == Path::new(".").join("daily.0")
                {
                    true
                } else {
                    false
                }
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.0"))
            .returning(|_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.1"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600)),
                ))
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("daily.0"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600 * 25)),
                ))
            });
        mock.expect_remove_dir_all()
            .times(1)
            .return_once(|_| Err(std::io::Error::new(std::io::ErrorKind::Other, "error")));
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = rotate_periods(settings, target_root, &context).map_err(|e| e);
        let exp_error = Err(format!(
            "Could not remove {:?}: Custom {{ kind: Other, error: \"error\" }}",
            Path::new(".").join("daily.0")
        ));
        assert_eq!(error, exp_error);
    }

    #[test]
    fn if_other_period_is_old_then_rotate_folders() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=.\n[sources]\n1=/A\n[periods]\nhourly=2@1h\ndaily=2@1d",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists()
            .times(3 + 101 + 2)
            .returning(|path| {
                if path == Path::new(".").join("hourly.0")
                    || path == Path::new(".").join("hourly.1")
                    || path == Path::new(".").join("daily.0")
                {
                    true
                } else {
                    false
                }
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.0"))
            .returning(|_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.1"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600)),
                ))
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("daily.0"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600 * 25)),
                ))
            });
        mock.expect_mv().times(2).returning(|_, _| Ok(()));
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let result = rotate_periods(settings, target_root, &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_cannot_rotate_other_period_then_error() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=.\n[sources]\n1=/A\n[periods]\nhourly=2@1h\ndaily=2@1d",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists()
            .times(3 + 101 + 2)
            .returning(|path| {
                if path == Path::new(".").join("hourly.0")
                    || path == Path::new(".").join("hourly.1")
                    || path == Path::new(".").join("daily.0")
                {
                    true
                } else {
                    false
                }
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.0"))
            .returning(|_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.1"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600)),
                ))
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("daily.0"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600 * 25)),
                ))
            });
        mock.expect_mv()
            .times(1)
            .returning(|_, _| Err(std::io::Error::new(std::io::ErrorKind::Other, "error")));
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = rotate_periods(settings, target_root, &context).map_err(|e| e);
        let exp_error = Err(format!(
            "Could not move {:?} to {:?}: Custom {{ kind: Other, error: \"error\" }}",
            Path::new(".").join("daily.0"),
            Path::new(".").join("daily.1")
        ));
        assert_eq!(error, exp_error);
    }

    #[test]
    fn if_other_period_is_old_and_folders_full_then_remove_oldest() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=.\n[sources]\n1=/A\n[periods]\nhourly=2@1h\ndaily=2@1d",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists()
            .times(3 + 101 + 1)
            .returning(|path| {
                if path == Path::new(".").join("hourly.0")
                    || path == Path::new(".").join("hourly.1")
                    || path == Path::new(".").join("daily.0")
                    || path == Path::new(".").join("daily.1")
                {
                    true
                } else {
                    false
                }
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.0"))
            .returning(|_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.1"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600)),
                ))
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("daily.0"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600 * 25)),
                ))
            });
        mock.expect_remove_dir_all()
            .times(1)
            .return_once(|_| Ok(()));
        mock.expect_mv().times(2).returning(|_, _| Ok(()));
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let result = rotate_periods(settings, target_root, &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_other_period_is_old_and_folders_not_full_then_do_nothing() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=.\n[sources]\n1=/A\n[periods]\nhourly=3@1h\ndaily=2@1d",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists().times(3).returning(|path| {
            if path == Path::new(".").join("hourly.0")
                || path == Path::new(".").join("hourly.1")
                || path == Path::new(".").join("daily.0")
                || path == Path::new(".").join("daily.1")
            {
                true
            } else {
                false
            }
        });

        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.0"))
            .returning(|_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("daily.0"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600 * 25)),
                ))
            });
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let result = rotate_periods(settings, target_root, &context).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_other_period_is_old_and_folders_full_and_remove_fails_then_error() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=.\n[sources]\n1=/A\n[periods]\nhourly=2@1h\ndaily=2@1d",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };
        let target_root = String::from(".");

        let mut mock = MockFsImpl::new();
        mock.expect_path_exists()
            .times(3 + 101 + 1)
            .returning(|path| {
                if path == Path::new(".").join("hourly.0")
                    || path == Path::new(".").join("hourly.1")
                    || path == Path::new(".").join("daily.0")
                    || path == Path::new(".").join("daily.1")
                {
                    true
                } else {
                    false
                }
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.0"))
            .returning(|_| Ok(FileTime::from_system_time(std::time::SystemTime::now())));
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("hourly.1"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600)),
                ))
            });
        mock.expect_mtime()
            .times(1)
            .withf(|path| path == Path::new(".").join("daily.0"))
            .returning(|_| {
                Ok(FileTime::from_system_time(
                    std::time::SystemTime::now().sub(std::time::Duration::from_secs(3600 * 25)),
                ))
            });
        mock.expect_remove_dir_all()
            .times(1)
            .return_once(|_| Err(std::io::Error::new(std::io::ErrorKind::Other, "error")));
        let context = Context {
            fsimpl: Box::new(mock),
        };

        let error = rotate_periods(settings, target_root, &context).unwrap_err();
        let exp_error = format!(
            "Could not remove {:?}: Custom {{ kind: Other, error: \"error\" }}",
            Path::new(".").join("daily.1")
        );
        assert_eq!(error, exp_error);
    }
}
