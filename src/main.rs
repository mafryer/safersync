use clap::Parser;
use configparser::ini::Ini;
use duration_string::DurationString;
use filenamify::filenamify;
use filetime::FileTime;
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
    fn read_to_string(&self, path: &str) -> std::io::Result<String>;
    fn mtime(&self, path: &str) -> std::io::Result<FileTime>;
    fn write(&self, path: &str, data: &str) -> std::io::Result<()>;
    fn rsync(&self, source: &str, dest: &str) -> std::io::Result<()>;
    fn path_exists(&self, path: &Path) -> bool;
    fn is_dir(&self, path: &Path) -> Result<bool, String>;
    fn create_dir_all(&self, path: &Path) -> std::io::Result<()>;
    fn remove_file(&self, path: &str) -> std::io::Result<()>;
}

#[derive(Clone)]
struct FsImpl {}

unsafe impl Send for FsImpl {}

impl FsTraits for FsImpl {
    fn read_to_string(&self, path: &str) -> std::io::Result<String> {
        fs::read_to_string(path)
    }

    fn mtime(&self, path: &str) -> std::io::Result<FileTime> {
        let metadata = fs::metadata(path);
        match metadata {
            Ok(metadata) => Ok(FileTime::from_last_modification_time(&metadata)),
            Err(error) => Err(error),
        }
    }

    fn write(&self, path: &str, data: &str) -> std::io::Result<()> {
        fs::write(path, data)
    }

    fn rsync(&self, source: &str, dest: &str) -> std::io::Result<()> {
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

        let output = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "/usr/bin/rsync -a --delete --numeric-ids --relative --delete-excluded {:?} {:?}",
                source, dest
            ))
            .output()
            .expect("failed to execute process");
        std::io::stdout().write_all(&output.stdout).unwrap();
        std::io::stderr().write_all(&output.stderr).unwrap();
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "rsync failed",
            ));
        }
        Ok(())
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

    fn remove_file(&self, path: &str) -> std::io::Result<()> {
        fs::remove_file(path)
    }
}

struct Settings {
    config: HashMap<std::string::String, HashMap<std::string::String, Option<std::string::String>>>,

    ignore_others: bool,
}

struct PeriodInfo {
    name: String,
    count: u32,
    interval: Duration,
}

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

    let pid_path = get_conf_key(&settings.config, "main", "pid_file")?;

    if !settings.ignore_others {
        // exit if pid file exists and pid exists
        let other_pid = get_other_pid(&context, &pid_path)?;
        match other_pid {
            Some(pid) => return Err(format!("Already running with PID: {:?}", pid)),
            None => (),
        }
    }

    let (stop_pid_thread_tx, stop_pid_thread_rx) = mpsc::channel();

    let pid_thread = move |path: String| {
        fsimpl_pid_thread
            .write(&path, &format!("{}", std::process::id()))
            .unwrap();
        for _ in 1..600 {
            thread::sleep(Duration::from_millis(100));
            let received = stop_pid_thread_rx.try_recv();
            match received {
                Ok(_) => return,
                Err(_) => (),
            }
        }
    };

    let pid_thread_pid_path = pid_path.clone();
    let pid_handle = thread::spawn(move || pid_thread(pid_thread_pid_path));

    let result = do_work(settings, &context);

    // del pid file
    let _ = stop_pid_thread_tx.send("done");
    let _ = pid_handle.join();

    match context.fsimpl.remove_file(&pid_path) {
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
    let target_root = get_conf_key(&settings.config, "main", "target_root")?;
    let target_path = Path::new(&target_root);
    if context.fsimpl.path_exists(&target_path) {
        if !context.fsimpl.is_dir(&target_path)? {
            return Err(format!("{} is not a directory", target_root));
        }
    } else {
        if get_conf_key(&settings.config, "main", "can_create_target_root")? == "true" {
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
    }
    let sources = match settings.config.get("sources") {
        Some(main) => main,
        None => return Err(String::from("No sources section in config")),
    };
    for (source, dest) in sources {
        match dest {
            Some(_) => (),
            None => return Err(format!("No destination for source {:?}", source)),
        }

        println!("SOURCE {:?} DEST {:?}", source, dest.clone().unwrap());

        let dest_path = Path::new(&target_root)
            .join(dest.clone().unwrap())
            .join(".sync");

        match context.fsimpl.rsync(source, dest_path.to_str().unwrap()) {
            Ok(_) => (),
            Err(error) => {
                return Err(format!(
                    "Could not rsync {} to {:?}: {:?}",
                    source, dest_path, error
                ))
            }
        }
    }
    let periods = match settings.config.get("periods") {
        Some(main) => main,
        None => return Err(String::from("No periods section in config")),
    };

    let mut periods_vec = Vec::new();

    for (period_name, details) in periods {
        if period_name.len() == 0 {
            return Err(String::from("An empty period name was found"));
        }
        if filenamify(&period_name).ne(period_name) {
            return Err(format!("Invalid period name: {}", period_name));
        }
        /*
        if periods_vec
            .iter()
            .any(|other: &PeriodInfo| other.name.eq(period_name))
        {
            return Err(format!("Duplicate period name: {}", period_name));
        }
        */
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
            || interval > Duration::from_secs(60 * 60 * 24 * 365 * 5)
        {
            return Err(format!(
                "Interval should be 1h-5y for {}: {}",
                period_name, details_str
            ));
        }

        periods_vec.push(PeriodInfo {
            name: period_name.clone(),
            count: count,
            interval: interval,
        });
    }

    for period in periods_vec {
        //   if shortest period
        //     if most recent is old enough then
        //       rm period.oldest if too many
        //       mv period.n-1 period.n if period.n-1 exists
        //       cp -al .sync period.0
        //   else
        //     if most_recent(this period) - oldest(shorter period) >= interval
        //       rm period.oldest if too many
        //       mv period.n-1 period.n if period.n-1 exists
        //       mv oldest(shorter period) period.0
    }
    Ok(())
}

fn get_conf_key(
    config: &HashMap<
        std::string::String,
        HashMap<std::string::String, Option<std::string::String>>,
    >,
    section: &str,
    key: &str,
) -> Result<String, String> {
    let section_hash = match config.get(section) {
        Some(main) => main,
        None => return Err(format!("No {} section in config", section)),
    };

    let value = match section_hash.get(key) {
        Some(value) => value.clone().unwrap(),
        None => return Err(format!("No {} in {} section of config", key, section)),
    };

    Ok(value)
}

struct Context {
    fsimpl: Box<dyn FsTraits>,
}

fn get_other_pid(context: &Context, pid_path: &str) -> Result<Option<String>, String> {
    println!("Checking PID file {:?}", pid_path);
    let result = context.fsimpl.read_to_string(pid_path);
    let pid = match result {
        Ok(pid) => pid,
        Err(ref error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("PID file {:?} not found", pid_path);
            return Ok(None);
        }
        Err(error) => {
            return Err(format!(
                "Could not read {:?}: {:?} {:?}",
                pid_path,
                error.kind(),
                error.to_string()
            ))
        }
    };

    let result = context.fsimpl.mtime(pid_path);
    let mtime = match result {
        Ok(mtime) => mtime,
        Err(error) => {
            return Err(format!(
                "Could not get mtime of {:?}: {:?} {:?}",
                pid_path,
                error.kind(),
                error.to_string()
            ))
        }
    };

    let age_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - <i64 as TryInto<u64>>::try_into(mtime.unix_seconds()).unwrap();

    println!("PID file written at {:?}", mtime);
    println!("Time now {:?}", SystemTime::now());
    println!("Age {:?} secs", age_secs);

    if age_secs > 300 {
        println!("PID file {:?} written more than 5 minutes ago", pid_path);
        return Ok(None);
    }

    println!("PID file {:?} written recently by PID {:?}", pid_path, pid);
    Ok(Some(pid))
}

#[cfg(test)]
mod tests {

    use super::*;
    use mockall::*;
    use std::ops::Sub;

    mock! {
        pub FsImpl {
        }
        impl FsTraits for FsImpl {
            fn read_to_string(&self, path: &str) -> std::io::Result<String>;
            fn mtime(&self, path: &str) -> std::io::Result<FileTime>;
            fn write(&self, path: &str, data: &str) -> std::io::Result<()>;
            fn rsync(&self, source: &str, dest: &str) -> std::io::Result<()>;
            fn path_exists(&self, path: &Path) -> bool;
            fn is_dir(&self, path: &Path) -> Result<bool, String>;
            fn create_dir_all(&self, path: &Path) -> std::io::Result<()>;
            fn remove_file(&self, path: &str) -> std::io::Result<()>;
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

        let mut mock = MockFsImpl::new();
        let mut mock2 = MockFsImpl::new();
        mock2.expect_write().return_once(|_, _| Ok(()));
        mock.expect_clone().return_once(move || mock2);
        mock.expect_read_to_string().return_once(move |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File Not Found",
            ))
        });
        mock.expect_path_exists().return_once(|_| true);
        mock.expect_is_dir().return_once(|_| Ok(true));
        mock.expect_remove_file().return_once(|_| Ok(()));

        let result = body(mock, settings).unwrap();
        assert_eq!(result, ());
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
        mock.expect_clone().return_once(move || mock2);
        mock.expect_read_to_string().return_once(move |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "Connection Reset",
            ))
        });

        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from(
                "Could not read \"/var/run/safersync.pid\": ConnectionReset \"Connection Reset\""
            ))
        );
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

        let mut mock = MockFsImpl::new();
        let mut mock2 = MockFsImpl::new();
        mock2.expect_write().return_once(move |_, _| Ok(()));
        mock.expect_clone().return_once(move || mock2);
        mock.expect_read_to_string().return_once(move |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "Connection Reset",
            ))
        });
        mock.expect_path_exists().return_once(|_| true);
        mock.expect_is_dir().return_once(|_| Ok(true));
        mock.expect_remove_file().return_once(|_| Ok(()));

        let result = body(mock, settings).unwrap();
        assert_eq!(result, ());
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
        mock.expect_clone().return_once(move || mock2);
        mock.expect_read_to_string()
            .return_once(move |_| Ok(String::from("1")));
        mock.expect_mtime().return_once(move |_| {
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

        let mut mock = MockFsImpl::new();
        let mut mock2 = MockFsImpl::new();
        mock2.expect_write().return_once(move |_, _| Ok(()));
        mock.expect_clone().return_once(move || mock2);
        mock.expect_read_to_string()
            .return_once(move |_| Ok(String::from("1")));
        mock.expect_mtime().return_once(move |_| {
            Ok(FileTime::from_system_time(
                std::time::SystemTime::now().sub(std::time::Duration::from_secs(301)),
            ))
        });
        mock.expect_path_exists().return_once(|_| true);
        mock.expect_is_dir().return_once(|_| Ok(true));
        mock.expect_remove_file().return_once(|_| Ok(()));

        let result = body(mock, settings).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_rsync_source_has_no_dest_then_should_fail() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=\n[sources]\n/A",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        let mut mock2 = MockFsImpl::new();
        mock2.expect_write().return_once(move |_, _| Ok(()));
        mock.expect_clone().return_once(move || mock2);
        mock.expect_read_to_string().return_once(move |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File Not Found",
            ))
        });
        mock.expect_path_exists().return_once(|_| true);
        mock.expect_is_dir().return_once(|_| Ok(true));
        mock.expect_remove_file().return_once(|_| Ok(()));

        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(error, Err(String::from("No destination for source \"/A\"")));
    }

    #[test]
    fn rsync_multiple_sources() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=\n[sources]\n/A=/B\n/C=/D\n[periods]",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        let mut mock2 = MockFsImpl::new();
        mock2.expect_write().return_once(move |_, _| Ok(()));
        mock.expect_clone().return_once(move || mock2);
        mock.expect_read_to_string().return_once(move |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File Not Found",
            ))
        });
        mock.expect_path_exists().return_once(|_| true);
        mock.expect_is_dir().return_once(|_| Ok(true));
        mock.expect_rsync().times(2).returning(move |_, _| Ok(()));
        mock.expect_remove_file().return_once(|_| Ok(()));

        let result = body(mock, settings).unwrap();
        assert_eq!(result, ());
    }

    #[test]
    fn if_rsync_fails_then_exits() {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(
                "[main]\npid_file=/var/run/safersync.pid\ntarget_root=\n[sources]\n/A=/B\n/C=/D",
            ))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        let mut mock2 = MockFsImpl::new();
        mock2.expect_write().return_once(move |_, _| Ok(()));
        mock.expect_clone().return_once(move || mock2);
        mock.expect_read_to_string().return_once(move |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File Not Found",
            ))
        });
        mock.expect_path_exists().return_once(|_| true);
        mock.expect_is_dir().return_once(|_| Ok(true));
        mock.expect_rsync().return_once(move |_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "rsync failed",
            ))
        });
        mock.expect_remove_file().return_once(|_| Ok(()));

        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(format!(
                "Could not rsync /A to {:?}: Custom {{ kind: Other, error: \"rsync failed\" }}",
                Path::new("/B").join(".sync")
            ))
        );
    }

    fn arrange_periods_test(periods: &str) -> (Settings, MockFsImpl) {
        let mut ini = Ini::new_cs();
        let config = ini
            .read(String::from(format!(
                "[main]
                pid_file=/var/run/safersync.pid
                target_root=
                [sources]
                /A=/B
                /C=/D
                [periods]
                {}",
                periods
            )))
            .unwrap();
        let settings = Settings {
            config: config,
            ignore_others: false,
        };

        let mut mock = MockFsImpl::new();
        let mut mock2 = MockFsImpl::new();
        mock2.expect_write().return_once(move |_, _| Ok(()));
        mock.expect_clone().return_once(move || mock2);
        mock.expect_read_to_string().return_once(move |_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "File Not Found",
            ))
        });
        mock.expect_path_exists().return_once(|_| true);
        mock.expect_is_dir().return_once(|_| Ok(true));
        mock.expect_rsync().times(2).returning(move |_, _| Ok(()));
        mock.expect_remove_file().return_once(|_| Ok(()));

        (settings, mock)
    }

    #[test]
    fn if_invalid_period_name_then_error() {
        let (settings, mock) = arrange_periods_test("/=1@1d");
        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(error, Err(String::from("Invalid period name: /")));
    }

    #[test]
    fn if_invalid_period_details_format_then_error() {
        let (settings, mock) = arrange_periods_test("a=1");
        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from(
                "Invalid period details (should be <count>@<interval>) for a: 1"
            ))
        );
    }

    #[test]
    fn if_invalid_period_count_then_error() {
        let (settings, mock) = arrange_periods_test("a=a@1h");
        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from(
                "Could not parse count (should be 1-100) for a: a@1h"
            ))
        );
    }

    #[test]
    fn if_period_count_too_few_then_error() {
        let (settings, mock) = arrange_periods_test("a=0@1h");
        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from("Count should be 1-100 for a: 0@1h"))
        );
    }

    #[test]
    fn if_period_count_too_many_then_error() {
        let (settings, mock) = arrange_periods_test("a=101@1h");
        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from("Count should be 1-100 for a: 101@1h"))
        );
    }

    #[test]
    fn if_invalid_period_length_then_error() {
        let (settings, mock) = arrange_periods_test("a=1@xyz");
        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from(
                "Could not parse interval (should be 1s-1y) for a: 1@xyz"
            ))
        );
    }

    #[test]
    fn if_period_too_short_then_error() {
        let (settings, mock) = arrange_periods_test("a=1@1s");
        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from("Interval should be 1h-5y for a: 1@1s"))
        );
    }

    #[test]
    fn if_period_too_long_then_error() {
        let (settings, mock) = arrange_periods_test("a=1@5y1d");
        let error = body(mock, settings).map_err(|e| e);
        assert_eq!(
            error,
            Err(String::from("Interval should be 1h-5y for a: 1@5y1d"))
        );
    }
}
