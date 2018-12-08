use std::any::{Any, TypeId};
use std::cell::Cell;
use std::rc::Rc;

use fnv::{FnvHashMap, FnvHashSet};
use petgraph::graph::DiGraph;
use yansi::Paint;

use crate::SgxSupport;

pub trait DetectItem: Print + DebugSupport + Update + mopa::Any {}
mopafy!(DetectItem);

pub trait Update {
    fn update(&mut self, _support: &Rc<SgxSupport>) {}
}

pub trait Name {
    fn name(&self) -> &'static str;
}

pub trait Print: Name {
    fn try_supported(&self) -> Option<Status> {
        Some(self.supported())
    }

    fn supported(&self) -> Status {
        unimplemented!()
    }

    fn print(&self, level: usize) {
        println!(
            "{:width$}{}{}",
            "",
            self.try_supported().map_or(Paint::new(""), Status::paint),
            self.name(),
            width = level * 2
        );
    }
}

pub trait DebugSupport {
    /// # Panics
    /// May panic if `supported` returns `Status::Supported`.
    fn debug(&self) {}
}

impl<T: Print + DebugSupport + Update + 'static> DetectItem for T {}

#[allow(non_camel_case_types)]
pub trait __missing_dependency_attribute__<T> {}

pub trait Dependency<T: DetectItem>: DetectItem + __missing_dependency_attribute__<T> {
    const CONTROL_VISIBILITY: bool = false;

    fn update_dependency(&mut self, dependency: &T, support: &Rc<SgxSupport>) {
        let _ = dependency;
        self.update(support)
    }
}

pub type DependencyUpdateFn =
    fn(&dyn DetectItem, &mut dyn DetectItem, &Rc<SgxSupport>, &Cell<bool>);

#[allow(unused)]
struct Category;
#[allow(unused)]
struct Test;

pub type TypeIdIdx = u8;

#[derive(Default)]
pub struct TypeIdMap {
    next: TypeIdIdx,
    map: FnvHashMap<TypeId, TypeIdIdx>,
}

impl TypeIdMap {
    pub fn get(&mut self, v: TypeId) -> TypeIdIdx {
        let next = &mut self.next;
        *self.map.entry(v).or_insert_with(|| {
            let this = *next;
            *next = this
                .checked_add(1)
                .expect("Too many nodes, increase index type size");
            this
        })
    }

    pub fn get_typed<T: 'static + ?Sized>(&mut self) -> TypeIdIdx {
        self.get(TypeId::of::<T>())
    }
}

pub struct DependencyInfo {
    pub update_fn: DependencyUpdateFn,
    pub hidden: Cell<bool>,
}

pub struct Tests {
    pub type_id_map: TypeIdMap,
    pub functions: Vec<Box<dyn DetectItem>>,
    pub values: Vec<Option<Box<dyn Any>>>,
    pub dependencies: DiGraph<(), DependencyInfo, TypeIdIdx>,
    pub ui_hidden: FnvHashSet<TypeIdIdx>,
    pub ui_children: Vec<Vec<TypeIdIdx>>,
    pub ui_root: TypeIdIdx,
}

pub fn set_at_index<T: Default>(v: &mut Vec<T>, index: usize, value: T) {
    if v.len() <= index {
        if let Some(additional) = (index + 1).checked_sub(v.capacity()) {
            v.reserve(additional)
        }
        while v.len() <= index {
            v.push(T::default());
        }
    }
    v[index] = value;
}

macro_rules! tests_inner {
    ( node $tests:ident $(@$meta:tt)* $name:expr => Category($test:ident, tests: { $($(@$cmeta:tt)* $cname:expr => $cty:ident $cparam:tt, )* } ) ) => {
        {
            let idx = tests_inner!( node_common $tests $test $name );

            let ui_children = vec![ $(tests_inner!( node $tests $(@$cmeta)* $cname => $cty $cparam ),)* ];

            $(
                #[dependency]
                impl Dependency<tests_inner!( typename $cparam )> for $test {
                    tests_inner!( meta_foreach control_visibility $($cmeta)* );
                    tests_inner!( meta_foreach [update_supported($cparam)] $($cmeta)* );
                }
            )*

            $crate::tests::scaffold::set_at_index(&mut $tests.ui_children, idx as usize, ui_children);

            idx
        }
    };
    ( node $tests:ident $(@$meta:tt)* $name:expr => Test($test:ident) ) => {
        tests_inner!( node_common $tests $test $name )
    };

    ( node_common $tests:ident $test:ident $name:expr ) => {
        {
            impl $crate::tests::Name for $test {
                fn name(&self) -> &'static str {
                    $name
                }
            }

            let idx = $tests.type_id_map.get_typed::<$test>();

            assert_eq!($tests.functions.len(), idx as usize);
            $tests.functions.push(Box::new($test::default()));
            $crate::tests::scaffold::set_at_index(&mut $tests.values, idx as usize, None);

            idx
        }
    };
    ( typename ( $name:ident $($rest:tt)* ) ) => {
        $name
    };

    ( meta_foreach $search:tt $meta:tt $($rest:tt)* ) => {
        tests_inner!( meta_check $meta );
        tests_inner!( meta_impl $search $meta );
        tests_inner!( meta_foreach $search $($rest)* );
    };
    ( meta_foreach $search:tt ) => {};
    ( meta_check [control_visibility $($rest:tt)*] ) => {};
    ( meta_check [update_supported $($rest:tt)*] ) => {};
    ( meta_check [$name:tt $($rest:tt)*] ) => {
        compile_error!(concat!("Unknown attribute: ", stringify!($name $($rest)*)));
    };

    ( meta_impl control_visibility [control_visibility] ) => {
        const CONTROL_VISIBILITY: bool = true;
    };
    ( meta_impl control_visibility [control_visibility $($rest:tt)*] ) => {
        compile_error!(concat!("Invalid control_visibility attribute: ", stringify!(control_visibility $($rest)*)));
    };
    ( meta_impl control_visibility $($rest:tt)* ) => {};

    ( meta_impl [update_supported($cparam:tt)] [update_supported = $var:ident] ) => {
        fn update_dependency(&mut self, dependency: &tests_inner!( typename $cparam ), support: &Rc<SgxSupport>) {
            self.$var = dependency.supported();
            self.update(support)
        }
    };
    ( meta_impl [update_supported($cparam:tt)] [update_supported $($rest:tt)*] ) => {
        compile_error!(concat!("Invalid update_supported attribute: ", stringify!(update_supported $($rest)*)));
    };
    ( meta_impl [update_supported($cparam:tt)] $($rest:tt)* ) => {};
}

macro_rules! tests {
    ($($rest:tt)*) => {{
        let mut type_id_map = TypeIdMap::default();
        let mut tests = crate::tests::Tests {
            ui_root: type_id_map.get_typed::<Root>(),
            type_id_map,
            functions: Default::default(),
            values: Default::default(),
            dependencies: Default::default(),
            ui_hidden: Default::default(),
            ui_children: Default::default(),
        };

        let ui_root = tests_inner!( node tests "root" => Category(Root, tests: { $($rest)* } ) );
        assert_eq!(tests.ui_root, ui_root);

        tests
    }};
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Status {
    Supported,
    Unsupported,
    Fatal,
    Unknown,
}

impl Status {
    pub fn paint(self) -> Paint<&'static str> {
        use yansi::{Color, Style};
        match self {
            Status::Supported => paintalt("✔  ", "yes ").with_style(Style::new(Color::Green)),
            Status::Unsupported => paintalt("✘  ", "no  ").with_style(Style::new(Color::Yellow)),
            Status::Fatal => paintalt("✘  ", "no  ").with_style(Style::new(Color::Red)),
            Status::Unknown => {
                paintalt("？ ", "??? ").with_style(Style::new(Color::Magenta).bold())
            }
        }
    }

    pub fn downgrade_fatal(self) -> Self {
        match self {
            Status::Fatal => Status::Unsupported,
            v => v,
        }
    }
}

impl Default for Status {
    fn default() -> Status {
        Status::Unknown
    }
}

impl std::ops::BitAnd for Status {
    type Output = Status;

    fn bitand(self, other: Status) -> Status {
        match (self, other) {
            (_, Status::Fatal) => Status::Fatal,
            (Status::Fatal, _) => Status::Fatal,
            (_, Status::Unknown) => Status::Unknown,
            (Status::Unknown, _) => Status::Unknown,
            (_, Status::Supported) => Status::Supported,
            (Status::Supported, _) => Status::Supported,
            (Status::Unsupported, Status::Unsupported) => Status::Unsupported,
        }
    }
}

impl std::ops::BitOr for Status {
    type Output = Status;

    fn bitor(self, other: Status) -> Status {
        match (self, other) {
            (_, Status::Supported) => Status::Supported,
            (Status::Supported, _) => Status::Supported,
            (_, Status::Unknown) => Status::Unknown,
            (Status::Unknown, _) => Status::Unknown,
            _ => Status::Fatal,
        }
    }
}

/*
impl std::iter::Product for Status {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut any = false;
        let ret = iter.fold(Status::Unsupported, |a, b| {
            any = true;
            a & b
        });
        if any { ret } else { Status::Supported }
    }
}
*/

pub trait StatusConv {
    fn as_opt(self) -> Status;
    fn as_req(self) -> Status;
}

impl StatusConv for bool {
    fn as_opt(self) -> Status {
        if self {
            Status::Supported
        } else {
            Status::Unsupported
        }
    }

    fn as_req(self) -> Status {
        if self {
            Status::Supported
        } else {
            Status::Fatal
        }
    }
}

impl StatusConv for Option<bool> {
    fn as_opt(self) -> Status {
        match self {
            Some(true) => Status::Supported,
            Some(false) => Status::Unsupported,
            None => Status::Unknown,
        }
    }

    fn as_req(self) -> Status {
        match self {
            Some(true) => Status::Supported,
            Some(false) => Status::Fatal,
            None => Status::Unknown,
        }
    }
}

fn paintalt(enabled: &'static str, disabled: &'static str) -> Paint<&'static str> {
    if Paint::is_enabled() {
        Paint::new(enabled)
    } else {
        Paint::new(disabled)
    }
}
