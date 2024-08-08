use std::future::Future;
use std::mem::{self, ManuallyDrop};
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::Arc;
use std::time::Duration;

use crate::creds::{Credentials, Expression};
use crate::session::{Error, Loot};
use crate::Options;

/// What type of payload is consumed by a plugin.
pub(crate) enum PayloadStrategy {
    /// Single payload like for dns, tcp.port, etc
    Single,
    /// Standard double payload.
    UsernamePassword,
}

impl std::fmt::Display for PayloadStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                PayloadStrategy::Single => "single",
                PayloadStrategy::UsernamePassword => "username_and_password",
            }
        )
    }
}

pub(crate) trait Plugin: Sync + Send {
    // return the description for this plugin
    fn description(&self) -> &'static str;

    // plugin payload strategy
    fn payload_strategy(&self) -> PayloadStrategy {
        PayloadStrategy::UsernamePassword
    }

    // single credential plugins can override this method to return their own payload expression
    fn override_payload(&self) -> Option<Expression> {
        None
    }

    // configure the plugin initial state
    fn setup(&mut self, options: &Options) -> Result<(), Error>;

    // perform a plugin step with the given credentials and timeout
    async fn attempt(
        &self,
        creds: &Credentials,
        timeout: Duration,
    ) -> Result<Option<Vec<Loot>>, Error>;
}

struct PluginVTable {
    description: unsafe fn(*const ()) -> &'static str,
    payload_strategy: unsafe fn(*const ()) -> PayloadStrategy,
    override_payload: unsafe fn(*const ()) -> Option<Expression>,
    setup: unsafe fn(*mut (), options: &Options) -> Result<(), Error>,
    attempt: unsafe fn(
        *const (),
        creds: *const Credentials,
        timeout: Duration,
    )
        -> Pin<Box<dyn Future<Output = Result<Option<Vec<Loot>>, Error>> + Send>>,
    clone: unsafe fn(*mut ()) -> *mut (),
    drop: unsafe fn(*mut ()),
}

unsafe fn plugin_description<T: Plugin>(this: *const ()) -> &'static str {
    (*(this as *const T)).description()
}

unsafe fn plugin_payload_strategy<T: Plugin>(this: *const ()) -> PayloadStrategy {
    (*(this as *const T)).payload_strategy()
}

unsafe fn plugin_override_payload<T: Plugin>(this: *const ()) -> Option<Expression> {
    (*(this as *const T)).override_payload()
}

unsafe fn plugin_setup<T: Plugin>(this: *mut (), options: &Options) -> Result<(), Error> {
    (*(this as *mut T)).setup(options)
}

unsafe fn plugin_clone<T: Plugin>(this: *mut ()) -> *mut () {
    if core::mem::size_of::<T>() == 0 {
        core::ptr::null_mut()
    } else {
        let this = &mut *(this as *mut T);
        let this = ManuallyDrop::new(Arc::from_raw(this));
        Arc::into_raw(Arc::clone(&this)) as *mut _
    }
}

unsafe fn plugin_drop<T: Plugin>(this: *mut ()) {
    if core::mem::size_of::<T>() != 0 {
        let this = &mut *(this as *mut T);
        core::ptr::drop_in_place(this);
        drop(Arc::from_raw(this));
    }
}

unsafe fn plugin_attempt<T: Plugin>(
    this: *const (),
    creds: *const Credentials,
    timeout: Duration,
) -> Pin<Box<dyn Future<Output = Result<Option<Vec<Loot>>, Error>> + Send>> {
    let f: Pin<Box<dyn Future<Output = Result<Option<Vec<Loot>>, Error>>>> =
        Box::pin((*(this as *mut T)).attempt(&*creds, timeout));
    core::mem::transmute(f)
}

const fn plugin_vtable<T: Plugin>() -> &'static PluginVTable {
    &PluginVTable {
        description: plugin_description::<T>,
        payload_strategy: plugin_payload_strategy::<T>,
        override_payload: plugin_override_payload::<T>,
        setup: plugin_setup::<T>,
        attempt: plugin_attempt::<T>,
        clone: plugin_clone::<T>,
        drop: plugin_drop::<T>,
    }
}

pub(crate) struct BoxPlugin {
    inner: *mut (),
    vtable: &'static PluginVTable,
}

impl BoxPlugin {
    pub(crate) fn new<T: Plugin + 'static>(inner: T) -> Self {
        Self {
            inner: if core::mem::size_of::<T>() == 0 {
                core::ptr::null_mut()
            } else {
                Arc::into_raw(Arc::new(inner)) as *mut T as *mut ()
            },
            vtable: plugin_vtable::<T>(),
        }
    }

    #[inline(always)]
    pub fn description(&self) -> &'static str {
        unsafe { (self.vtable.description)(self.inner) }
    }

    #[inline(always)]
    pub fn payload_strategy(&self) -> PayloadStrategy {
        unsafe { (self.vtable.payload_strategy)(self.inner) }
    }

    #[inline(always)]
    pub fn override_payload(&self) -> Option<Expression> {
        unsafe { (self.vtable.override_payload)(self.inner) }
    }

    #[inline(always)]
    pub fn setup(&mut self, options: &Options) -> Result<(), Error> {
        unsafe { (self.vtable.setup)(self.inner, options) }
    }

    #[inline(always)]
    pub fn attempt<'a>(
        &'a self,
        creds: &'a Credentials,
        timeout: Duration,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<Loot>>, Error>> + Send + 'a>> {
        unsafe { mem::transmute((self.vtable.attempt)(self.inner, creds, timeout)) }
    }
}

impl Clone for BoxPlugin {
    fn clone(&self) -> Self {
        Self {
            inner: unsafe { (self.vtable.clone)(self.inner) },
            vtable: self.vtable,
        }
    }
}

impl Drop for BoxPlugin {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe { (self.vtable.drop)(self.inner) };
    }
}

unsafe impl Send for BoxPlugin {}
unsafe impl Sync for BoxPlugin {}
