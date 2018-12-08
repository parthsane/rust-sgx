use std::cell::Cell;
use std::rc::Rc;

use petgraph::visit::{EdgeRef, VisitMap};

use sgx_isa::{AttributesFlags, Miscselect};

#[macro_use]
mod scaffold;

pub use self::scaffold::*;
use crate::interpret::*;
use crate::SgxSupport;
use sgxs_tools::*;

#[derive(Default, DebugSupport, Print, Update)]
struct Root;

#[derive(Default, DebugSupport, Update)]
struct Isa {
    cpu: Status,
    cpu_cfg: Status,
    attr: Status,
    epc: Status,
}

impl Print for Isa {
    fn supported(&self) -> Status {
        self.cpu & self.cpu_cfg & self.attr & self.epc
    }
}

#[optional_inner]
#[derive(Copy, Clone, Default, DebugSupport)]
struct SgxCpuSupport {
    sgx: bool,
}

impl Update for SgxCpuSupport {
    fn update(&mut self, support: &Rc<SgxSupport>) {
        self.inner = Some(SgxCpuSupportInner {
            sgx: support.cpuid_7h.as_ref().ok().map_or(false, |c| c.sgx),
        });
    }
}

impl Print for SgxCpuSupport {
    fn supported(&self) -> Status {
        self.inner.map(|inner| inner.sgx).as_req()
    }
}

#[optional_inner]
#[derive(Copy, Clone, Default, DebugSupport, Update)]
struct SgxCpuConfiguration {
    sgx1: bool,
    sgx2: bool,
    exinfo: bool,
    enclv: bool,
    oversub: bool,
    kss: bool,
}

#[dependency]
impl Dependency<SgxCpuSupport> for SgxCpuConfiguration {
    const CONTROL_VISIBILITY: bool = true;

    fn update_dependency(&mut self, dependency: &SgxCpuSupport, support: &Rc<SgxSupport>) {
        self.inner = match (dependency.inner, &support.cpuid_12h_0) {
            (Some(SgxCpuSupportInner { sgx: true }), Ok(c)) => Some(SgxCpuConfigurationInner {
                sgx1: c.sgx1 && c.max_enclave_size_32 > 0 && c.max_enclave_size_64 > 0,
                sgx2: c.sgx2,
                exinfo: c.miscselect_valid.contains(Miscselect::EXINFO),
                enclv: c.enclv,
                oversub: c.oversub,
                kss: c.kss,
            }),
            (Some(_), _) => Some(SgxCpuConfigurationInner {
                sgx1: false,
                sgx2: false,
                exinfo: false,
                enclv: false,
                oversub: false,
                kss: false,
            }),
            (None, _) => None,
        };
    }
}

impl Print for SgxCpuConfiguration {
    fn supported(&self) -> Status {
        self.inner.map(|inner| inner.sgx1).as_req()
    }
}

#[optional_inner]
#[derive(Copy, Clone, Default, DebugSupport, Update)]
struct EnclaveAttributes {
    standard_attributes: bool,
}

#[dependency]
impl Dependency<SgxCpuSupport> for EnclaveAttributes {
    const CONTROL_VISIBILITY: bool = true;

    fn update_dependency(&mut self, dependency: &SgxCpuSupport, support: &Rc<SgxSupport>) {
        self.inner = match (dependency.inner, &support.cpuid_12h_1) {
            (Some(SgxCpuSupportInner { sgx: true }), Ok(c)) => Some(EnclaveAttributesInner {
                standard_attributes: c.attributes_flags_valid.contains(
                    AttributesFlags::DEBUG
                        | AttributesFlags::MODE64BIT
                        | AttributesFlags::PROVISIONKEY
                        | AttributesFlags::EINITTOKENKEY,
                ) && (c.attributes_xfrm_valid & 0x3) == 0x3,
            }),
            (Some(_), _) => Some(EnclaveAttributesInner {
                standard_attributes: false,
            }),
            (None, _) => None,
        };
    }
}

impl Print for EnclaveAttributes {
    fn supported(&self) -> Status {
        self.inner.map(|inner| inner.standard_attributes).as_req()
    }
}

#[optional_inner]
#[derive(Copy, Clone, Default, DebugSupport, Update)]
struct EnclavePageCache {
    total_size: u64,
    any_unknown: bool,
}

#[dependency]
impl Dependency<SgxCpuSupport> for EnclavePageCache {
    const CONTROL_VISIBILITY: bool = true;

    fn update_dependency(&mut self, dependency: &SgxCpuSupport, support: &Rc<SgxSupport>) {
        self.inner = match (dependency.inner, &support.cpuid_12h_epc) {
            (Some(SgxCpuSupportInner { sgx: true }), Ok(c)) => {
                let mut total_size = 0;
                let mut any_unknown = false;
                for section in c {
                    match section {
                        Cpuid12hEnum::Epc {
                            ty: EpcType::ConfidentialityIntegrityProtected,
                            phys_size,
                            ..
                        } => total_size += phys_size,
                        Cpuid12hEnum::Invalid => unreachable!(),
                        _ => any_unknown = true,
                    }
                }

                Some(EnclavePageCacheInner {
                    total_size,
                    any_unknown,
                })
            }
            _ => None,
        };
    }
}

impl Print for EnclavePageCache {
    fn supported(&self) -> Status {
        match self.inner {
            // Minimum useful EPC size: 1 VA + 1 SECS + 2 REG + 1 TCS
            Some(EnclavePageCacheInner { total_size, .. }) if total_size >= 0x5000 => {
                Status::Supported
            }
            Some(EnclavePageCacheInner {
                any_unknown: true, ..
            }) => Status::Unknown,
            Some(_) => Status::Fatal,
            _ => Status::Unknown,
        }
    }
}

#[derive(Default, DebugSupport, Print, Update)]
struct SgxFeaturesCat;

#[derive(Default, DebugSupport, Update)]
struct SgxFeatures {
    cpu_cfg: Option<SgxCpuConfigurationInner>,
}

#[dependency]
impl Dependency<SgxCpuConfiguration> for SgxFeatures {
    const CONTROL_VISIBILITY: bool = true;

    fn update_dependency(&mut self, dependency: &SgxCpuConfiguration, _support: &Rc<SgxSupport>) {
        self.cpu_cfg = dependency.inner;
    }
}

#[dependency]
impl Dependency<EnclaveAttributes> for SgxFeatures {
    fn update_dependency(&mut self, _dependency: &EnclaveAttributes, _support: &Rc<SgxSupport>) {
        // TODO: check KSS against CPUID
    }
}

impl Print for SgxFeatures {
    // used for visibility control
    fn try_supported(&self) -> Option<Status> {
        Some(self.cpu_cfg.map(|c| c.sgx1).as_req())
    }

    fn print(&self, level: usize) {
        print!(
            "{:width$}{}SGX2  ",
            "",
            self.cpu_cfg.map(|c| c.sgx2).as_opt().paint(),
            width = level * 2
        );
        print!(
            "{}EXINFO  ",
            self.cpu_cfg.map(|c| c.exinfo).as_opt().paint()
        );
        print!("{}ENCLV  ", self.cpu_cfg.map(|c| c.enclv).as_opt().paint());
        print!(
            "{}OVERSUB  ",
            self.cpu_cfg.map(|c| c.oversub).as_opt().paint()
        );
        println!("{}KSS", self.cpu_cfg.map(|c| c.kss).as_opt().paint());
    }
}

#[derive(Copy, Clone, Default, DebugSupport, Update)]
struct EpcSize {
    epc: Option<EnclavePageCacheInner>,
}

#[dependency]
impl Dependency<EnclavePageCache> for EpcSize {
    const CONTROL_VISIBILITY: bool = true;

    fn update_dependency(&mut self, dependency: &EnclavePageCache, _support: &Rc<SgxSupport>) {
        self.epc = dependency.inner;
    }
}

impl Print for EpcSize {
    fn print(&self, level: usize) {
        if let Some(epc) = self.epc {
            println!(
                "{:width$}{}: {:.1}MiB",
                "",
                self.name(),
                epc.total_size as f64 / (1048576.),
                width = level * 2
            );
        }
    }
}

#[derive(Default, DebugSupport, Update)]
struct Flc {
    cpu: Status,
    cpu_cfg: Status,
}

impl Print for Flc {
    fn supported(&self) -> Status {
        (self.cpu & self.cpu_cfg).downgrade_fatal()
    }
}

#[dependency]
impl Dependency<SgxCpuSupport> for Flc {
    const CONTROL_VISIBILITY: bool = true;
}

#[optional_inner]
#[derive(Copy, Clone, Default, DebugSupport, Update)]
struct FlcCpuSupport {
    sgx_lc: bool,
}

#[dependency]
impl Dependency<SgxCpuSupport> for FlcCpuSupport {
    fn update_dependency(&mut self, dependency: &SgxCpuSupport, support: &Rc<SgxSupport>) {
        self.inner = match (dependency.inner, &support.cpuid_7h) {
            (Some(SgxCpuSupportInner { sgx: true }), Ok(c)) => {
                Some(FlcCpuSupportInner { sgx_lc: c.sgx_lc })
            }
            _ => None,
        };
    }
}

impl Print for FlcCpuSupport {
    fn supported(&self) -> Status {
        self.inner.map(|inner| inner.sgx_lc).as_req()
    }
}

#[optional_inner]
#[derive(Default, DebugSupport, Update)]
struct FlcCpuConfiguration {
    msr_locked: bool,
    msr_sgx_lc: bool,
}

#[dependency]
impl Dependency<FlcCpuSupport> for FlcCpuConfiguration {
    const CONTROL_VISIBILITY: bool = true;

    fn update_dependency(&mut self, dependency: &FlcCpuSupport, support: &Rc<SgxSupport>) {
        self.inner = match dependency.inner {
            Some(FlcCpuSupportInner { sgx_lc: true }) => {
                support
                    .msr_3ah
                    .as_ref()
                    .ok()
                    .map(|msr| FlcCpuConfigurationInner {
                        msr_locked: msr.locked,
                        msr_sgx_lc: msr.sgx_lc,
                    })
            }
            _ => None,
        };
    }
}

impl Print for FlcCpuConfiguration {
    fn supported(&self) -> Status {
        match self.inner {
            None => Status::Unknown,
            Some(FlcCpuConfigurationInner {
                msr_locked: true,
                msr_sgx_lc: true,
            }) => Status::Supported,
            Some(_) => Status::Fatal,
        }
    }
}

#[optional_inner]
#[derive(Copy, Clone, Default, DebugSupport)]
struct AesmService {
    service_ok: bool,
}

impl Update for AesmService {
    fn update(&mut self, support: &Rc<SgxSupport>) {
        self.inner = Some(AesmServiceInner {
            service_ok: support.aesm_service.is_ok(),
        });
    }
}

impl Print for AesmService {
    fn supported(&self) -> Status {
        self.inner.map(|inner| inner.service_ok).as_req()
    }
}

#[optional_inner]
#[derive(Copy, Clone, Default, DebugSupport)]
struct DeviceLoader {
    loader_ok: bool,
}

impl Update for DeviceLoader {
    fn update(&mut self, support: &Rc<SgxSupport>) {
        self.inner = Some(DeviceLoaderInner {
            loader_ok: support.loader_sgxdev.is_ok(),
        });
    }
}

impl Print for DeviceLoader {
    fn supported(&self) -> Status {
        self.inner.map(|inner| inner.loader_ok).as_req()
    }
}

#[optional_inner]
#[derive(Copy, Clone, Default, DebugSupport)]
struct EncllibLoader {
    loader_ok: bool,
}

impl Update for EncllibLoader {
    fn update(&mut self, support: &Rc<SgxSupport>) {
        self.inner = Some(EncllibLoaderInner {
            loader_ok: support.loader_encllib.is_ok(),
        });
    }
}

impl Print for EncllibLoader {
    fn supported(&self) -> Status {
        self.inner.map(|inner| inner.loader_ok).as_req()
    }
}

#[derive(Default, DebugSupport, Update)]
struct Psw {
    flc: Status,
    aesm: Status,
    driver: Status,
    encllib: Status,
}

#[dependency]
impl Dependency<Flc> for Psw {
    fn update_dependency(&mut self, dependency: &Flc, _support: &Rc<SgxSupport>) {
        self.flc = dependency.supported();
    }
}

impl Print for Psw {
    fn supported(&self) -> Status {
        let einittoken_provider = self.flc | self.aesm;
        let loader = self.driver | self.encllib;
        einittoken_provider & loader
    }
}

impl Tests {
    fn print_recurse(&self, test: TypeIdIdx, level: usize) {
        if self
            .dependencies
            .edges_directed(test.into(), petgraph::Direction::Incoming)
            .any(|edge| edge.weight().hidden.get())
        {
            return;
        }
        if let Some(adj_level) = level.checked_sub(1) {
            self.functions[test as usize].print(adj_level);
        }
        for child in self
            .ui_children
            .get(test as usize)
            .cloned()
            .unwrap_or_default()
        {
            self.print_recurse(child, level + 1);
        }
    }

    pub fn print(&self) {
        self.print_recurse(self.ui_root, 0);
    }

    pub fn check_support(&mut self, support: &Rc<SgxSupport>) {
        fn slice_dual_access<T>(slice: &mut [T], idx1: usize, idx2: usize) -> (&mut T, &mut T) {
            assert_ne!(idx1, idx2);
            if idx1 < idx2 {
                let (a, b) = slice.split_at_mut(idx1 + 1);
                (&mut a[idx1], &mut b[idx2 - idx1 - 1])
            } else {
                let (a, b) = slice.split_at_mut(idx2 + 1);
                (&mut b[idx1 - idx2 - 1], &mut a[idx2])
            }
        }

        let mut bfs = None;

        // setup breadth-first search of dependency graph, starting with all nodes
        // without dependencies
        for root in self.dependencies.externals(petgraph::Direction::Incoming) {
            self.functions[root.index()].update(support);
            match bfs {
                None => bfs = Some(petgraph::visit::Bfs::new(&self.dependencies, root)),
                Some(ref mut bfs) => {
                    bfs.stack.push_back(root);
                    bfs.discovered.visit(root);
                }
            }
        }
        let mut bfs = bfs.expect("at least one root");

        while let Some(node) = bfs.next(&self.dependencies) {
            for edge in self
                .dependencies
                .edges_directed(node, petgraph::Direction::Outgoing)
            {
                assert_eq!(edge.source(), node);
                let dependency_idx = edge.source().index();
                let dependent_idx = edge.target().index();
                let depinfo = edge.weight();

                let (dependency, dependent) =
                    slice_dual_access(&mut self.functions, dependency_idx, dependent_idx);

                (depinfo.update_fn)(&**dependency, &mut **dependent, support, &depinfo.hidden);
            }
        }
    }
}

impl Default for Tests {
    fn default() -> Tests {
        let mut tests = tests! {
            "SGX instruction set" => Category(Isa, tests: {
                @[update_supported = cpu]
                "CPU support" => Test(SgxCpuSupport),
                @[update_supported = cpu_cfg]
                "CPU configuration" => Test(SgxCpuConfiguration),
                @[update_supported = attr]
                "Enclave attributes" => Test(EnclaveAttributes),
                @[update_supported = epc]
                "Enclave Page Cache" => Test(EnclavePageCache),
                "SGX features" => Category(SgxFeaturesCat, tests: {
                    @[control_visibility]
                    "SGX features" => Test(SgxFeatures),
                    "Total EPC size" => Test(EpcSize),
                }),
            }),
            "Flexible launch control" => Category(Flc, tests: {
                @[update_supported = cpu]
                "CPU support" => Test(FlcCpuSupport),
                @[update_supported = cpu_cfg]
                "CPU configuration" => Test(FlcCpuConfiguration),
                //FlcAnyProdEnclave.into(),
            }),
            "SGX system software" => Category(Psw, tests: {
                @[update_supported = aesm]
                "AESM service" => Test(AesmService),
                @[update_supported = driver]
                "SGX kernel device" => Test(DeviceLoader),
                @[update_supported = encllib]
                "libsgx_enclave_common" => Test(EncllibLoader),
            }),
            //Category {
            //    name: "SGX remote attestation",
            //    items: vec![
            //        AttestationEpid.into(),
            //        AttestationDcap.into(),
            //    ],
            //    post: None
            //},
        };

        let tidmap = &mut tests.type_id_map;
        tests
            .dependencies
            .extend_with_edges(DEPENDENCIES.iter().map(|&(n1, n2, update_fn)| {
                (
                    tidmap.get(n1()),
                    tidmap.get(n2()),
                    DependencyInfo {
                        update_fn,
                        hidden: Cell::new(false),
                    },
                )
            }));

        assert!(!petgraph::algo::is_cyclic_directed(&tests.dependencies));
        assert_eq!(petgraph::algo::connected_components(&tests.dependencies), 1);

        tests
    }
}

fn update<T: DetectItem, U: Dependency<T>>(
    dependency: &dyn DetectItem,
    dependent: &mut dyn DetectItem,
    support: &Rc<SgxSupport>,
    hidden: &Cell<bool>,
) {
    let dependent = dependent.downcast_mut::<U>().unwrap();
    let dependency = dependency.downcast_ref::<T>().unwrap();
    dependent.update_dependency(dependency, support);

    let hiddenval = if U::CONTROL_VISIBILITY {
        match dependency.try_supported() {
            Some(Status::Supported) | Some(Status::Unsupported) | None => false,
            Some(Status::Fatal) | Some(Status::Unknown) => true,
        }
    } else {
        false
    };
    hidden.set(hiddenval);
}

define_dependencies!(update, DependencyUpdateFn);
