#![feature(trace_macros)]
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate mopa;

use std::arch::x86_64::{self, CpuidResult};
use std::io;
use std::rc::Rc;

use failure::Error;
use yansi::Paint;

use aesm_client::AesmClient;
use sgxs_loaders::isgx::{Device as IsgxDevice, DEFAULT_DEVICE_PATH};
use sgxs_loaders::sgx_enclave_common::Library as EnclCommonLib;

mod interpret;
mod linux;
mod tests;

use crate::interpret::*;
use crate::tests::Tests;

#[derive(Debug, Fail)]
enum DetectError {
    #[fail(display = "CPUID leaf {:x}h is not valid", leaf)]
    CpuidLeafInvalid { leaf: u32 },
    #[fail(display = "Failed access EFI variables: {}", _0)]
    EfiFsError(io::Error),
    #[fail(display = "Failed to read EFI variable: {}", _0)]
    EfiVariableError(io::Error),
}

fn cpuid(eax: u32, ecx: u32) -> Result<CpuidResult, Error> {
    unsafe {
        if eax <= x86_64::__get_cpuid_max(0).0 {
            Ok(x86_64::__cpuid_count(eax, ecx))
        } else {
            bail!(DetectError::CpuidLeafInvalid { leaf: eax })
        }
    }
}

#[derive(Debug)]
pub struct SgxSupport {
    cpuid_7h: Result<Cpuid7h, Error>,
    cpuid_12h_0: Result<Cpuid12h0, Error>,
    cpuid_12h_1: Result<Cpuid12h1, Error>,
    cpuid_12h_epc: Result<Vec<Cpuid12hEnum>, Error>,
    msr_3ah: Result<Msr3ah, Error>,
    efi_epcbios: Result<EfiEpcbios, Error>,
    efi_epcsw: Result<EfiEpcsw, Error>,
    efi_softwareguardstatus: Result<EfiSoftwareguardstatus, Error>,
    aesm_service: Result<AesmClient, Error>,
    dcap_library: bool,
    loader_sgxdev: Result<IsgxDevice, Error>,
    loader_encllib: Result<EnclCommonLib, Error>,
}

impl SgxSupport {
    fn detect() -> Self {
        let cpuid_7h = cpuid(0x7, 0).map(Cpuid7h::from);
        let cpuid_12h_0 = cpuid(0x12, 0).map(Cpuid12h0::from);
        let cpuid_12h_1 = cpuid(0x12, 1).map(Cpuid12h1::from);
        let cpuid_12h_epc = (2..)
            .into_iter()
            .map(|n| cpuid(0x12, n).map(|v| Cpuid12hEnum::from((n, v))))
            .take_while(|v| match v {
                Err(_) | Ok(Cpuid12hEnum::Invalid) => false,
                _ => true,
            })
            .collect();
        let msr_3ah = linux::rdmsr(0x3a).map(Msr3ah::from);
        let efi_epcbios = linux::read_efi_var("EPCBIOS", "c60aa7f6-e8d6-4956-8ba1-fe26298f5e87")
            .map(EfiEpcbios::from);
        let efi_epcsw = linux::read_efi_var("EPCSW", "d69a279b-58eb-45d1-a148-771bb9eb5251")
            .map(EfiEpcsw::from);
        let efi_softwareguardstatus = linux::read_efi_var(
            "SOFTWAREGUARDSTATUS",
            "9cb2e73f-7325-40f4-a484-659bb344c3cd",
        )
        .map(EfiSoftwareguardstatus::from);
        let aesm_service = (|| {
            let client = AesmClient::new();
            client.try_connect()?;
            Ok(client)
        })();
        let dcap_library = dcap_ql::is_loaded();
        let loader_sgxdev = (|| {
            let mut dev = IsgxDevice::open(DEFAULT_DEVICE_PATH)?;
            if let Ok(ref aesm) = aesm_service {
                dev = dev.einittoken_provider(aesm.clone());
            }
            Ok(dev.build())
        })();
        let loader_encllib = (|| {
            let mut lib = EnclCommonLib::load(None)?;
            if let Ok(ref aesm) = aesm_service {
                lib = lib.einittoken_provider(aesm.clone());
            }
            Ok(lib.build())
        })();

        SgxSupport {
            cpuid_7h,
            cpuid_12h_0,
            cpuid_12h_1,
            cpuid_12h_epc,
            msr_3ah,
            efi_epcbios,
            efi_epcsw,
            efi_softwareguardstatus,
            aesm_service,
            dcap_library,
            loader_sgxdev,
            loader_encllib,
        }
    }
}

fn main() {
    if atty::isnt(atty::Stream::Stdout) {
        Paint::disable()
    }
    env_logger::init();
    let support = Rc::new(SgxSupport::detect());

    let mut tests = Tests::default();
    tests.check_support(&support);
    tests.print();
}
