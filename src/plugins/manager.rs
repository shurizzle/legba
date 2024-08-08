use std::collections::BTreeMap;
use std::sync::{Mutex, RwLock};
use std::time;

use ahash::HashSet;
use ansi_term::Style;
use lazy_static::lazy_static;
use rand::Rng;
use std::sync::Arc;
use tokio::task;

use crate::session::{Error, Session};
use crate::Plugin;
use crate::{report, Options};

use super::plugin::{BoxPlugin, PayloadStrategy};

type Inventory = BTreeMap<&'static str, BoxPlugin>;

lazy_static! {
    pub(crate) static ref INVENTORY: Mutex<Inventory> = Mutex::new(Inventory::new());
}

pub(crate) fn register<T: Plugin + 'static>(name: &'static str, plugin: T) {
    INVENTORY
        .lock()
        .unwrap()
        .insert(name, BoxPlugin::new(plugin));
}

pub(crate) fn list() {
    let bold = Style::new().bold();

    println!("{}\n", bold.paint("Available plugins:"));

    let max_len = INVENTORY
        .lock()
        .unwrap()
        .keys()
        .map(|k| k.len())
        .max()
        .unwrap_or(0);

    for (key, plugin) in &*INVENTORY.lock().unwrap() {
        println!(
            "  {}{} : {}",
            bold.paint(*key),
            " ".repeat(max_len - key.len()), // padding
            plugin.description()
        );
    }
}

pub(crate) fn setup(options: &Options) -> Result<BoxPlugin, Error> {
    let plugin_name = if let Some(value) = options.plugin.as_ref() {
        value.to_string()
    } else {
        return Err("no plugin selected".to_owned());
    };

    let Some(mut plugin) = INVENTORY.lock().unwrap().remove(plugin_name.as_str()) else {
        return Err(format!("{} is not a valid plugin name, run with --list-plugins to see the list of available plugins", plugin_name));
    };

    plugin.setup(options)?;

    Ok(plugin)
}

pub(crate) async fn run(
    plugin: &'static mut BoxPlugin,
    session: Arc<Session>,
) -> Result<(), Error> {
    let single = matches!(plugin.payload_strategy(), PayloadStrategy::Single);
    let override_payload = plugin.override_payload();
    let combinations = session.combinations(override_payload, single)?;
    let unreachables: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::default()));

    // spawn worker threads
    for _ in 0..session.options.concurrency {
        task::spawn(worker(plugin, unreachables.clone(), session.clone()));
    }

    if !session.options.quiet {
        // start statistics reporting
        let stat_sess = session.clone();
        std::thread::spawn(move || {
            report::statistics(stat_sess);
        });
    }

    // loop credentials for this session
    for creds in combinations {
        // exit on ctrl-c if we have to, otherwise send the new credentials to the workers
        if session.is_stop() {
            log::debug!("exiting loop");
            return Ok(());
        } else if let Err(e) = session.send_credentials(creds).await {
            log::error!("{}", e.to_string());
        }
    }

    Ok(())
}

async fn worker(
    plugin: &BoxPlugin,
    unreachables: Arc<RwLock<HashSet<String>>>,
    session: Arc<Session>,
) {
    log::debug!("worker started");

    let timeout = time::Duration::from_millis(session.options.timeout);
    let retry_time: time::Duration = time::Duration::from_millis(session.options.retry_time);

    while let Ok(creds) = session.recv_credentials().await {
        if session.is_stop() {
            log::debug!("exiting worker");
            break;
        }

        let mut errors = 0;
        let mut attempt = 0;

        while attempt < session.options.retries && !session.is_stop() {
            // perform random jitter if needed
            if session.options.jitter_max > 0 {
                let ms = rand::thread_rng()
                    .gen_range(session.options.jitter_min..=session.options.jitter_max);
                if ms > 0 {
                    log::debug!("jitter of {} ms", ms);
                    tokio::time::sleep(time::Duration::from_millis(ms)).await;
                }
            }

            attempt += 1;

            // skip attempt if we had enough failures from this specific target
            if !unreachables.read().unwrap().contains(&creds.target) {
                match plugin.attempt(&creds, timeout).await {
                    Err(err) => {
                        errors += 1;
                        if attempt < session.options.retries {
                            log::debug!(
                                "[{}] attempt {}/{}: {}",
                                &creds.target,
                                attempt,
                                session.options.retries,
                                err
                            );
                            tokio::time::sleep(retry_time).await;
                            continue;
                        } else {
                            // add this target to the list of unreachable in order to avoi
                            // pointless attempts
                            unreachables.write().unwrap().insert(creds.target.clone());

                            log::error!(
                                "[{}] attempt {}/{}: {}",
                                &creds.target,
                                attempt,
                                session.options.retries,
                                err
                            );
                        }
                    }
                    Ok(loot) => {
                        // do we have new loot?
                        if let Some(loots) = loot {
                            for loot in loots {
                                session.add_loot(loot).await.unwrap();
                            }
                        }
                    }
                };
            }

            break;
        }

        session.inc_done();
        if errors == session.options.retries {
            session.inc_errors();
            log::debug!("retries={} errors={}", session.options.retries, errors);
        }
    }

    log::debug!("worker exit");
}
