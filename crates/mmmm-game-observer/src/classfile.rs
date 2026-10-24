// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors

//! Bounded description of a narrow hidden-class forwarding recipe.
//!
//! This module does not establish that caller-supplied bytes were loaded, issue
//! definition receipts, or turn a symbolic constant-pool reference into a VM
//! identity. The native definition owner must bind the recipe and snapshot to
//! one actual returned/prepared class and resolve every reference through its
//! issuer-held class registry before admitting a declaring-method closure.
//!
//! Format: JVMS 25, chapter 4. GetBytecodes/GetConstantPool describe executable
//! instructions and a corresponding reconstituted pool, not a full classfile.

use std::collections::BTreeSet;
use std::fmt;

use crate::definitions::{ExecutableSnapshot, HiddenRecipe, MethodCode, MethodSnapshot};

pub(crate) const MAX_CLASSFILE_BYTES: usize = 8 * 1024 * 1024;
const MAX_POOL_ENTRIES: usize = 65_535;
const MAX_MEMBERS: usize = 256;
const MAX_ATTRIBUTES: usize = 256;
const MAX_ATTRIBUTE_NAME_BYTES: usize = 128;
const MAX_SYMBOLIC_TEXT_BYTES: usize = 4096;
const MAX_CODE_BYTES: usize = 65_535;
const MAX_FORWARDER_PARAMETERS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ClassfileError {
    Malformed(&'static str),
    Unsupported(&'static str),
    Bounds(&'static str),
    SnapshotMismatch(&'static str),
}

impl fmt::Display for ClassfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, message) = match self {
            Self::Malformed(message) => ("malformed classfile", message),
            Self::Unsupported(message) => ("unsupported forwarding recipe", message),
            Self::Bounds(message) => ("classfile bound exceeded", message),
            Self::SnapshotMismatch(message) => ("VM snapshot mismatch", message),
        };
        write!(formatter, "{kind}: {message}")
    }
}

impl std::error::Error for ClassfileError {}

/// A symbolic request for the native owner, never an actual jmethodID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MethodSymbol {
    owner: String,
    name: String,
    descriptor: String,
    interface: bool,
}

impl MethodSymbol {
    pub(crate) fn owner(&self) -> &str {
        &self.owner
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn descriptor(&self) -> &str {
        &self.descriptor
    }

    pub(crate) fn is_interface(&self) -> bool {
        self.interface
    }
}

/// Descriptive semantic match; deliberately has no verified/receipt fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HiddenForwarder {
    class_name: String,
    interface_name: String,
    sam_name: String,
    sam_descriptor: String,
    target: MethodSymbol,
    reference_classes: Vec<String>,
}

impl HiddenForwarder {
    pub(crate) fn class_name(&self) -> &str {
        &self.class_name
    }

    pub(crate) fn interface_name(&self) -> &str {
        &self.interface_name
    }

    pub(crate) fn sam_name(&self) -> &str {
        &self.sam_name
    }

    pub(crate) fn sam_descriptor(&self) -> &str {
        &self.sam_descriptor
    }

    pub(crate) fn target(&self) -> &MethodSymbol {
        &self.target
    }

    /// Includes Object, the SAM interface, target owner, descriptor references,
    /// and casts. Each needs the actual source loader's identity interpretation.
    pub(crate) fn reference_classes(&self) -> &[String] {
        &self.reference_classes
    }
}

/// Only the two PACK queue closures below have a supported captured shape.
/// This enum selects a parser policy, never an execution or source permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PackCapturedRecipeKind {
    TaskProvider,
    EntryAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CaptureField {
    name: String,
    descriptor: String,
}

impl CaptureField {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn descriptor(&self) -> &str {
        &self.descriptor
    }
}

/// A supported semantic shape from an authenticated recipe and VM snapshot.
/// Actual receiver, captured objects and declaring method still need native joins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PackCapturedForwarder {
    kind: PackCapturedRecipeKind,
    target: MethodSymbol,
    captures: Vec<CaptureField>,
}

impl PackCapturedForwarder {
    pub(crate) fn kind(&self) -> PackCapturedRecipeKind {
        self.kind
    }

    pub(crate) fn target(&self) -> &MethodSymbol {
        &self.target
    }

    /// In actual constructor parameter order, independent of field names/order.
    pub(crate) fn captures(&self) -> &[CaptureField] {
        &self.captures
    }
}

#[derive(Clone, Debug)]
enum PoolEntry {
    Unusable,
    Utf8(Vec<u16>),
    Integer,
    Float,
    Long,
    Double,
    Class(u16),
    String(u16),
    Field(u16, u16),
    Method(u16, u16),
    InterfaceMethod(u16, u16),
    NameAndType(u16, u16),
    MethodHandle(u8, u16),
    MethodType(u16),
    Dynamic(u16),
    InvokeDynamic(u16),
    Module(u16),
    Package(u16),
}

#[derive(Clone, Debug)]
struct Pool {
    entries: Vec<PoolEntry>,
}

impl Pool {
    fn entry(&self, index: u16) -> Result<&PoolEntry, ClassfileError> {
        if index == 0 {
            return Err(ClassfileError::Malformed("zero constant-pool reference"));
        }
        self.entries
            .get(usize::from(index))
            .filter(|entry| !matches!(entry, PoolEntry::Unusable))
            .ok_or(ClassfileError::Malformed("invalid constant-pool reference"))
    }

    fn utf8(&self, index: u16) -> Result<&[u16], ClassfileError> {
        match self.entry(index)? {
            PoolEntry::Utf8(value) => Ok(value),
            _ => Err(ClassfileError::Malformed(
                "constant-pool reference is not Utf8",
            )),
        }
    }

    fn text(&self, index: u16) -> Result<String, ClassfileError> {
        let units = self.utf8(index)?;
        if units.len() > MAX_SYMBOLIC_TEXT_BYTES {
            return Err(ClassfileError::Bounds("symbolic text length"));
        }
        if units.iter().any(|unit| *unit == 0 || *unit > 0x7f) {
            return Err(ClassfileError::Unsupported("non-ASCII symbolic text"));
        }
        Ok(units.iter().map(|unit| char::from(*unit as u8)).collect())
    }

    fn class(&self, index: u16) -> Result<String, ClassfileError> {
        match self.entry(index)? {
            PoolEntry::Class(name) => self.text(*name),
            _ => Err(ClassfileError::Malformed(
                "constant-pool reference is not Class",
            )),
        }
    }

    fn method(&self, index: u16) -> Result<MethodSymbol, ClassfileError> {
        let (owner, name_type, interface) = match self.entry(index)? {
            PoolEntry::Method(owner, name_type) => (*owner, *name_type, false),
            PoolEntry::InterfaceMethod(owner, name_type) => (*owner, *name_type, true),
            _ => {
                return Err(ClassfileError::Malformed(
                    "invoke reference is not a method",
                ));
            }
        };
        let (name, descriptor) = match self.entry(name_type)? {
            PoolEntry::NameAndType(name, descriptor) => (*name, *descriptor),
            _ => {
                return Err(ClassfileError::Malformed(
                    "method reference has no NameAndType",
                ));
            }
        };
        Ok(MethodSymbol {
            owner: self.class(owner)?,
            name: self.text(name)?,
            descriptor: self.text(descriptor)?,
            interface,
        })
    }

    fn field(&self, index: u16) -> Result<(String, CaptureField), ClassfileError> {
        let (owner, name_type) = match self.entry(index)? {
            PoolEntry::Field(owner, name_type) => (*owner, *name_type),
            _ => return Err(ClassfileError::Malformed("field reference is not Fieldref")),
        };
        let (name, descriptor) = match self.entry(name_type)? {
            PoolEntry::NameAndType(name, descriptor) => (*name, *descriptor),
            _ => return Err(ClassfileError::Malformed("field has no NameAndType")),
        };
        Ok((
            self.class(owner)?,
            CaptureField {
                name: self.text(name)?,
                descriptor: self.text(descriptor)?,
            },
        ))
    }

    fn validate(&self) -> Result<(), ClassfileError> {
        // Tag-checked edges form an acyclic graph: Class/String -> Utf8;
        // member -> Class/NameAndType -> Utf8; handle -> member. A self/cyclic
        // reference cannot pass these edge types. No recursive traversal occurs.
        for entry in &self.entries[1..] {
            match entry {
                PoolEntry::Class(index)
                | PoolEntry::String(index)
                | PoolEntry::MethodType(index)
                | PoolEntry::Module(index)
                | PoolEntry::Package(index) => {
                    self.utf8(*index)?;
                }
                PoolEntry::Field(owner, name_type)
                | PoolEntry::Method(owner, name_type)
                | PoolEntry::InterfaceMethod(owner, name_type) => {
                    if !matches!(self.entry(*owner)?, PoolEntry::Class(_))
                        || !matches!(self.entry(*name_type)?, PoolEntry::NameAndType(_, _))
                    {
                        return Err(ClassfileError::Malformed("member reference tag mismatch"));
                    }
                }
                PoolEntry::NameAndType(name, descriptor) => {
                    self.utf8(*name)?;
                    self.utf8(*descriptor)?;
                }
                PoolEntry::MethodHandle(kind, reference) => {
                    let target = self.entry(*reference)?;
                    let valid = match kind {
                        1..=4 => matches!(target, PoolEntry::Field(_, _)),
                        5 | 8 => matches!(target, PoolEntry::Method(_, _)),
                        6 | 7 => matches!(
                            target,
                            PoolEntry::Method(_, _) | PoolEntry::InterfaceMethod(_, _)
                        ),
                        9 => matches!(target, PoolEntry::InterfaceMethod(_, _)),
                        _ => false,
                    };
                    if !valid {
                        return Err(ClassfileError::Malformed(
                            "MethodHandle reference tag mismatch",
                        ));
                    }
                }
                PoolEntry::Dynamic(name_type) | PoolEntry::InvokeDynamic(name_type)
                    if !matches!(self.entry(*name_type)?, PoolEntry::NameAndType(_, _)) =>
                {
                    return Err(ClassfileError::Malformed("dynamic reference tag mismatch"));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn reject_dynamic_dispatch(&self) -> Result<(), ClassfileError> {
        if self.entries.iter().any(|entry| {
            matches!(
                entry,
                PoolEntry::MethodHandle(_, _)
                    | PoolEntry::MethodType(_)
                    | PoolEntry::Dynamic(_)
                    | PoolEntry::InvokeDynamic(_)
                    | PoolEntry::Module(_)
                    | PoolEntry::Package(_)
            )
        }) {
            return Err(ClassfileError::Unsupported(
                "dynamic or module constant-pool entry",
            ));
        }
        Ok(())
    }
}

struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn bytes(&mut self, count: usize) -> Result<&'a [u8], ClassfileError> {
        let end = self
            .offset
            .checked_add(count)
            .filter(|end| *end <= self.input.len())
            .ok_or(ClassfileError::Malformed("truncated structure"))?;
        let value = &self.input[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u1(&mut self) -> Result<u8, ClassfileError> {
        Ok(self.bytes(1)?[0])
    }

    fn u2(&mut self) -> Result<u16, ClassfileError> {
        let value = self.bytes(2)?;
        Ok(u16::from_be_bytes([value[0], value[1]]))
    }

    fn u4(&mut self) -> Result<u32, ClassfileError> {
        let value = self.bytes(4)?;
        Ok(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    }

    fn done(&self) -> Result<(), ClassfileError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(ClassfileError::Malformed("trailing structure bytes"))
        }
    }
}

/// Modified UTF-8 encodes UTF-16 code units, including separate surrogates.
/// Reject literal NUL, overlong forms except C0 80, and four-byte UTF-8.
fn decode_mutf8(input: &[u8]) -> Result<Vec<u16>, ClassfileError> {
    let mut units = Vec::with_capacity(input.len());
    let mut reader = Reader::new(input);
    while reader.offset < input.len() {
        let first = reader.u1()?;
        let unit = match first {
            1..=0x7f => u16::from(first),
            0xc0..=0xdf => {
                let second = reader.u1()?;
                if second & 0xc0 != 0x80 {
                    return Err(ClassfileError::Malformed(
                        "invalid modified UTF-8 continuation",
                    ));
                }
                let unit = (u16::from(first & 0x1f) << 6) | u16::from(second & 0x3f);
                if unit < 0x80 && !(first == 0xc0 && second == 0x80) {
                    return Err(ClassfileError::Malformed("overlong modified UTF-8"));
                }
                unit
            }
            0xe0..=0xef => {
                let second = reader.u1()?;
                let third = reader.u1()?;
                if second & 0xc0 != 0x80 || third & 0xc0 != 0x80 {
                    return Err(ClassfileError::Malformed(
                        "invalid modified UTF-8 continuation",
                    ));
                }
                let unit = (u16::from(first & 0x0f) << 12)
                    | (u16::from(second & 0x3f) << 6)
                    | u16::from(third & 0x3f);
                if unit < 0x800 {
                    return Err(ClassfileError::Malformed("overlong modified UTF-8"));
                }
                unit
            }
            _ => {
                return Err(ClassfileError::Malformed(
                    "invalid modified UTF-8 leading byte",
                ));
            }
        };
        units.push(unit);
    }
    Ok(units)
}

fn read_pool(reader: &mut Reader<'_>, count: usize) -> Result<Pool, ClassfileError> {
    if !(2..=MAX_POOL_ENTRIES).contains(&count) {
        return Err(ClassfileError::Bounds("constant-pool count"));
    }
    let mut entries = Vec::with_capacity(count);
    entries.push(PoolEntry::Unusable);
    while entries.len() < count {
        let entry = match reader.u1()? {
            1 => {
                let length = usize::from(reader.u2()?);
                PoolEntry::Utf8(decode_mutf8(reader.bytes(length)?)?)
            }
            3 => {
                reader.bytes(4)?;
                PoolEntry::Integer
            }
            4 => {
                reader.bytes(4)?;
                PoolEntry::Float
            }
            5 => {
                reader.bytes(8)?;
                PoolEntry::Long
            }
            6 => {
                reader.bytes(8)?;
                PoolEntry::Double
            }
            7 => PoolEntry::Class(reader.u2()?),
            8 => PoolEntry::String(reader.u2()?),
            9 => PoolEntry::Field(reader.u2()?, reader.u2()?),
            10 => PoolEntry::Method(reader.u2()?, reader.u2()?),
            11 => PoolEntry::InterfaceMethod(reader.u2()?, reader.u2()?),
            12 => PoolEntry::NameAndType(reader.u2()?, reader.u2()?),
            15 => PoolEntry::MethodHandle(reader.u1()?, reader.u2()?),
            16 => PoolEntry::MethodType(reader.u2()?),
            17 => {
                // Bootstrap indices are consumed, but dynamic dispatch is
                // always unsupported here. Keep the checked NameAndType edge.
                reader.u2()?;
                PoolEntry::Dynamic(reader.u2()?)
            }
            18 => {
                reader.u2()?;
                PoolEntry::InvokeDynamic(reader.u2()?)
            }
            19 => PoolEntry::Module(reader.u2()?),
            20 => PoolEntry::Package(reader.u2()?),
            _ => return Err(ClassfileError::Malformed("unknown constant-pool tag")),
        };
        let wide = matches!(entry, PoolEntry::Long | PoolEntry::Double);
        entries.push(entry);
        if wide {
            if entries.len() == count {
                return Err(ClassfileError::Malformed(
                    "wide constant at final pool slot",
                ));
            }
            entries.push(PoolEntry::Unusable);
        }
    }
    let pool = Pool { entries };
    pool.validate()?;
    Ok(pool)
}

#[derive(Clone, Debug)]
struct Attribute {
    name: String,
    bytes: Vec<u8>,
}

fn read_attributes(reader: &mut Reader<'_>, pool: &Pool) -> Result<Vec<Attribute>, ClassfileError> {
    let count = usize::from(reader.u2()?);
    if count > MAX_ATTRIBUTES {
        return Err(ClassfileError::Bounds("attribute count"));
    }
    let mut attributes = Vec::with_capacity(count);
    let mut singletons = BTreeSet::new();
    for _ in 0..count {
        let name = pool.text(reader.u2()?)?;
        if name.len() > MAX_ATTRIBUTE_NAME_BYTES {
            return Err(ClassfileError::Bounds("attribute name length"));
        }
        if matches!(name.as_str(), "Code" | "SourceFile" | "StackMapTable")
            && !singletons.insert(name.clone())
        {
            return Err(ClassfileError::Malformed("duplicate singleton attribute"));
        }
        let length = usize::try_from(reader.u4()?)
            .map_err(|_| ClassfileError::Bounds("attribute length"))?;
        if length > MAX_CLASSFILE_BYTES {
            return Err(ClassfileError::Bounds("attribute length"));
        }
        attributes.push(Attribute {
            name,
            bytes: reader.bytes(length)?.to_vec(),
        });
    }
    Ok(attributes)
}

#[derive(Clone, Debug)]
struct Code {
    max_stack: u16,
    max_locals: u16,
    bytes: Vec<u8>,
    exception_count: usize,
    attributes: Vec<Attribute>,
}

fn read_code(bytes: &[u8], pool: &Pool) -> Result<Code, ClassfileError> {
    let mut reader = Reader::new(bytes);
    let max_stack = reader.u2()?;
    let max_locals = reader.u2()?;
    let length =
        usize::try_from(reader.u4()?).map_err(|_| ClassfileError::Bounds("Code length"))?;
    if length == 0 || length > MAX_CODE_BYTES {
        return Err(ClassfileError::Bounds("Code length"));
    }
    let code = reader.bytes(length)?.to_vec();
    let exception_count = usize::from(reader.u2()?);
    for _ in 0..exception_count {
        let start = usize::from(reader.u2()?);
        let end = usize::from(reader.u2()?);
        let handler = usize::from(reader.u2()?);
        let catch_type = reader.u2()?;
        if start >= end || end > length || handler >= length {
            return Err(ClassfileError::Malformed(
                "invalid Code exception-table range",
            ));
        }
        if catch_type != 0 && !matches!(pool.entry(catch_type)?, PoolEntry::Class(_)) {
            return Err(ClassfileError::Malformed(
                "invalid Code exception catch type",
            ));
        }
    }
    let attributes = read_attributes(&mut reader, pool)?;
    reader.done()?;
    Ok(Code {
        max_stack,
        max_locals,
        bytes: code,
        exception_count,
        attributes,
    })
}

#[derive(Clone, Debug)]
struct Member {
    flags: u16,
    name: String,
    descriptor: String,
    attributes: Vec<Attribute>,
    code: Option<Code>,
}

fn read_members(
    reader: &mut Reader<'_>,
    pool: &Pool,
    methods: bool,
) -> Result<Vec<Member>, ClassfileError> {
    let count = usize::from(reader.u2()?);
    if count > MAX_MEMBERS {
        return Err(ClassfileError::Bounds("member count"));
    }
    let mut members = Vec::with_capacity(count);
    let mut signatures = BTreeSet::new();
    for _ in 0..count {
        let flags = reader.u2()?;
        let name = pool.text(reader.u2()?)?;
        let descriptor = pool.text(reader.u2()?)?;
        if !signatures.insert((name.clone(), descriptor.clone())) {
            return Err(ClassfileError::Malformed("duplicate member signature"));
        }
        let attributes = read_attributes(reader, pool)?;
        let mut code = None;
        for attribute in &attributes {
            if attribute.name == "Code" {
                if !methods || code.is_some() {
                    return Err(ClassfileError::Malformed(
                        "invalid or duplicate Code attribute",
                    ));
                }
                code = Some(read_code(&attribute.bytes, pool)?);
            }
        }
        if methods && (flags & (0x0100 | 0x0400) != 0) == code.is_some() {
            return Err(ClassfileError::Malformed(
                "Code and native/abstract flags disagree",
            ));
        }
        members.push(Member {
            flags,
            name,
            descriptor,
            attributes,
            code,
        });
    }
    Ok(members)
}

#[derive(Clone, Debug)]
pub(crate) struct ParsedClass {
    pool: Pool,
    flags: u16,
    class_name: String,
    super_name: Option<String>,
    interfaces: Vec<String>,
    fields: Vec<Member>,
    methods: Vec<Member>,
    attributes: Vec<Attribute>,
}

/// Complete bounded structural parse. Unknown attributes retain their bounded
/// body for the narrow semantic admission to reject; they are never executed.
pub(crate) fn parse_classfile(input: &[u8]) -> Result<ParsedClass, ClassfileError> {
    if input.len() > MAX_CLASSFILE_BYTES {
        return Err(ClassfileError::Bounds("input bytes"));
    }
    let mut reader = Reader::new(input);
    if reader.u4()? != 0xcafe_babe {
        return Err(ClassfileError::Malformed("classfile magic"));
    }
    let minor = reader.u2()?;
    let major = reader.u2()?;
    if !(45..=69).contains(&major) || (major >= 56 && minor != 0 && minor != 65_535) {
        return Err(ClassfileError::Malformed("classfile version"));
    }
    if minor == 65_535 {
        return Err(ClassfileError::Unsupported("preview classfile"));
    }
    let count = usize::from(reader.u2()?);
    let pool = read_pool(&mut reader, count)?;
    let flags = reader.u2()?;
    let class_name = pool.class(reader.u2()?)?;
    let super_index = reader.u2()?;
    let super_name = if super_index == 0 {
        None
    } else {
        Some(pool.class(super_index)?)
    };
    let interface_count = usize::from(reader.u2()?);
    if interface_count > MAX_MEMBERS {
        return Err(ClassfileError::Bounds("interface count"));
    }
    let mut interfaces = Vec::with_capacity(interface_count);
    let mut unique = BTreeSet::new();
    for _ in 0..interface_count {
        let interface = pool.class(reader.u2()?)?;
        if !unique.insert(interface.clone()) {
            return Err(ClassfileError::Malformed("duplicate interface"));
        }
        interfaces.push(interface);
    }
    let fields = read_members(&mut reader, &pool, false)?;
    let methods = read_members(&mut reader, &pool, true)?;
    let attributes = read_attributes(&mut reader, &pool)?;
    reader.done()?;
    Ok(ParsedClass {
        pool,
        flags,
        class_name,
        super_name,
        interfaces,
        fields,
        methods,
        attributes,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ValueType {
    Int(u8),
    Long,
    Float,
    Double,
    Reference(String),
    Void,
}

impl ValueType {
    fn slots(&self) -> usize {
        match self {
            Self::Long | Self::Double => 2,
            Self::Void => 0,
            _ => 1,
        }
    }

    fn load_opcode(&self) -> u8 {
        match self {
            Self::Int(_) => 0x15,
            Self::Long => 0x16,
            Self::Float => 0x17,
            Self::Double => 0x18,
            Self::Reference(_) => 0x19,
            Self::Void => 0,
        }
    }

    fn return_opcode(&self) -> u8 {
        match self {
            Self::Int(_) => 0xac,
            Self::Long => 0xad,
            Self::Float => 0xae,
            Self::Double => 0xaf,
            Self::Reference(_) => 0xb0,
            Self::Void => 0xb1,
        }
    }
}

fn field_type(reader: &mut Reader<'_>, allow_void: bool) -> Result<ValueType, ClassfileError> {
    let start = reader.offset;
    Ok(match reader.u1()? {
        tag @ (b'B' | b'C' | b'I' | b'S' | b'Z') => ValueType::Int(tag),
        b'J' => ValueType::Long,
        b'F' => ValueType::Float,
        b'D' => ValueType::Double,
        b'V' if allow_void => ValueType::Void,
        b'L' => {
            let begin = reader.offset;
            while reader.u1()? != b';' {}
            let name = std::str::from_utf8(&reader.input[begin..reader.offset - 1])
                .map_err(|_| ClassfileError::Malformed("non-ASCII descriptor"))?;
            validate_class_name(name)?;
            ValueType::Reference(name.to_owned())
        }
        b'[' => {
            let mut dimensions = 1;
            while reader.input.get(reader.offset) == Some(&b'[') {
                reader.u1()?;
                dimensions += 1;
                if dimensions > 255 {
                    return Err(ClassfileError::Bounds("array dimensions"));
                }
            }
            field_type(reader, false)?;
            let descriptor = std::str::from_utf8(&reader.input[start..reader.offset])
                .map_err(|_| ClassfileError::Malformed("non-ASCII descriptor"))?;
            ValueType::Reference(descriptor.to_owned())
        }
        _ => return Err(ClassfileError::Malformed("invalid descriptor type")),
    })
}

fn method_descriptor(descriptor: &str) -> Result<(Vec<ValueType>, ValueType), ClassfileError> {
    let mut reader = Reader::new(descriptor.as_bytes());
    if reader.u1()? != b'(' {
        return Err(ClassfileError::Malformed(
            "method descriptor has no argument list",
        ));
    }
    let mut parameters = Vec::new();
    let mut slots = 0;
    while reader.input.get(reader.offset) != Some(&b')') {
        if parameters.len() == MAX_FORWARDER_PARAMETERS {
            return Err(ClassfileError::Bounds("forwarder parameters"));
        }
        let parameter = field_type(&mut reader, false)?;
        slots += parameter.slots();
        if slots > 254 {
            return Err(ClassfileError::Bounds("instance parameter slots"));
        }
        parameters.push(parameter);
    }
    reader.u1()?;
    let result = field_type(&mut reader, true)?;
    reader.done()?;
    Ok((parameters, result))
}

fn validate_class_name(name: &str) -> Result<(), ClassfileError> {
    if name.is_empty()
        || name.starts_with('/')
        || name.ends_with('/')
        || name.contains("//")
        || name.bytes().any(|byte| {
            byte == 0 || byte > 0x7f || matches!(byte, b'.' | b';' | b'[' | b'(' | b')')
        })
    {
        return Err(ClassfileError::Malformed("invalid internal class name"));
    }
    Ok(())
}

fn validate_method_name(name: &str) -> Result<(), ClassfileError> {
    if name.is_empty()
        || name.bytes().any(|byte| {
            byte == 0
                || byte > 0x7f
                || matches!(byte, b'.' | b';' | b'[' | b'/' | b'<' | b'>' | b'(' | b')')
        })
    {
        return Err(ClassfileError::Malformed("invalid forwarding method name"));
    }
    Ok(())
}

fn expect_load(
    reader: &mut Reader<'_>,
    value_type: &ValueType,
    slot: usize,
) -> Result<(), ClassfileError> {
    let opcode = reader.u1()?;
    let base = value_type.load_opcode();
    let compact = 0x1a + (base - 0x15) * 4;
    let matches = if opcode == base {
        usize::from(reader.u1()?) == slot
    } else if slot <= 3 && opcode == compact + slot as u8 {
        true
    } else if opcode == 0xc4 && reader.u1()? == base {
        usize::from(reader.u2()?) == slot
    } else {
        false
    };
    if !matches {
        return Err(ClassfileError::Unsupported("argument load or order"));
    }
    Ok(())
}

fn passive_code_attributes(code: &Code) -> Result<(), ClassfileError> {
    for attribute in &code.attributes {
        let mut reader = Reader::new(&attribute.bytes);
        match attribute.name.as_str() {
            "LineNumberTable" => {
                let count = usize::from(reader.u2()?);
                for _ in 0..count {
                    if usize::from(reader.u2()?) >= code.bytes.len() {
                        return Err(ClassfileError::Malformed("line number start outside Code"));
                    }
                    reader.u2()?;
                }
            }
            "StackMapTable" => {
                if reader.u2()? != 0 {
                    return Err(ClassfileError::Unsupported("nonempty stack map"));
                }
            }
            _ => return Err(ClassfileError::Unsupported("unknown Code attribute")),
        }
        reader.done()?;
    }
    Ok(())
}

fn supported_code(member: &Member) -> Result<&Code, ClassfileError> {
    if member.flags & (0x0100 | 0x0400 | 0x0020) != 0 {
        return Err(ClassfileError::Unsupported(
            "native, abstract, or synchronized method",
        ));
    }
    if member
        .attributes
        .iter()
        .any(|attribute| attribute.name != "Code")
    {
        return Err(ClassfileError::Unsupported("unknown method attribute"));
    }
    let code = member
        .code
        .as_ref()
        .ok_or(ClassfileError::Malformed("concrete method has no Code"))?;
    if code.exception_count != 0 {
        return Err(ClassfileError::Unsupported("exception handlers"));
    }
    passive_code_attributes(code)?;
    Ok(code)
}

fn constructor_semantics(bytes: &[u8], pool: &Pool) -> Result<MethodSymbol, ClassfileError> {
    let mut reader = Reader::new(bytes);
    expect_load(
        &mut reader,
        &ValueType::Reference("java/lang/Object".to_owned()),
        0,
    )?;
    if reader.u1()? != 0xb7 {
        return Err(ClassfileError::Unsupported("constructor invocation"));
    }
    let target = pool.method(reader.u2()?)?;
    if target.owner != "java/lang/Object"
        || target.name != "<init>"
        || target.descriptor != "()V"
        || target.interface
        || reader.u1()? != 0xb1
    {
        return Err(ClassfileError::Unsupported("constructor has other effects"));
    }
    reader.done()?;
    Ok(target)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ForwardingSemantics {
    target: MethodSymbol,
    casts: Vec<Option<String>>,
}

fn forwarding_semantics(
    bytes: &[u8],
    descriptor: &str,
    pool: &Pool,
) -> Result<ForwardingSemantics, ClassfileError> {
    let (parameters, result) = method_descriptor(descriptor)?;
    let mut reader = Reader::new(bytes);
    let mut slot = 1;
    let mut casts = Vec::with_capacity(parameters.len());
    for parameter in &parameters {
        expect_load(&mut reader, parameter, slot)?;
        slot += parameter.slots();
        if reader.input.get(reader.offset) == Some(&0xc0) {
            if !matches!(parameter, ValueType::Reference(_)) {
                return Err(ClassfileError::Unsupported("cast of primitive argument"));
            }
            reader.u1()?;
            let cast = pool.class(reader.u2()?)?;
            if !cast.starts_with('[') {
                validate_class_name(&cast)?;
            } else {
                let mut descriptor_reader = Reader::new(cast.as_bytes());
                field_type(&mut descriptor_reader, false)?;
                descriptor_reader.done()?;
            }
            casts.push(Some(cast));
        } else {
            casts.push(None);
        }
    }
    if reader.u1()? != 0xb8 {
        return Err(ClassfileError::Unsupported(
            "SAM is not a direct invokestatic forwarder",
        ));
    }
    let target = pool.method(reader.u2()?)?;
    validate_class_name(&target.owner)?;
    validate_method_name(&target.name)?;
    if matches!(
        target.owner.as_str(),
        "java/lang/invoke/MethodHandle" | "java/lang/invoke/VarHandle"
    ) {
        return Err(ClassfileError::Unsupported(
            "MethodHandle or VarHandle dispatch",
        ));
    }
    let (target_parameters, target_result) = method_descriptor(&target.descriptor)?;
    if parameters.len() != target_parameters.len() || result != target_result {
        return Err(ClassfileError::Unsupported("argument or return adaptation"));
    }
    for ((source, target_type), cast) in parameters.iter().zip(&target_parameters).zip(&casts) {
        let adapted = match cast {
            Some(name) => ValueType::Reference(name.clone()),
            None => source.clone(),
        };
        if adapted != *target_type {
            return Err(ClassfileError::Unsupported(
                "unproved argument assignability",
            ));
        }
    }
    if reader.u1()? != result.return_opcode() {
        return Err(ClassfileError::Unsupported("SAM return instruction"));
    }
    reader.done()?;
    Ok(ForwardingSemantics { target, casts })
}

fn snapshot_pool(snapshot: &ExecutableSnapshot) -> Result<Pool, ClassfileError> {
    if snapshot.constant_pool.len() > MAX_CLASSFILE_BYTES || snapshot.methods.len() > MAX_MEMBERS {
        return Err(ClassfileError::Bounds("VM snapshot"));
    }
    let mut total = snapshot.constant_pool.len();
    for method in &snapshot.methods {
        total = total
            .checked_add(method.name_mutf8.len())
            .and_then(|sum| sum.checked_add(method.descriptor_mutf8.len()))
            .and_then(|sum| {
                sum.checked_add(match &method.code {
                    MethodCode::Bytecodes(bytes) => bytes.len(),
                    MethodCode::Native | MethodCode::Abstract => 0,
                })
            })
            .ok_or(ClassfileError::Bounds("VM snapshot bytes"))?;
        if total > MAX_CLASSFILE_BYTES {
            return Err(ClassfileError::Bounds("VM snapshot bytes"));
        }
    }
    let mut reader = Reader::new(&snapshot.constant_pool);
    let count = usize::try_from(snapshot.constant_pool_count)
        .map_err(|_| ClassfileError::Bounds("VM constant-pool count"))?;
    let pool = read_pool(&mut reader, count)?;
    reader.done()?;
    pool.reject_dynamic_dispatch()?;
    Ok(pool)
}

fn snapshot_method<'a>(
    snapshot: &'a ExecutableSnapshot,
    member: &Member,
) -> Result<&'a MethodSnapshot, ClassfileError> {
    let mut found = None;
    for method in &snapshot.methods {
        let name = decode_mutf8(&method.name_mutf8)?;
        let descriptor = decode_mutf8(&method.descriptor_mutf8)?;
        if name == member.name.encode_utf16().collect::<Vec<_>>()
            && descriptor == member.descriptor.encode_utf16().collect::<Vec<_>>()
        {
            if found.is_some() {
                return Err(ClassfileError::SnapshotMismatch("duplicate VM method"));
            }
            if method.modifiers < 0
                || method.modifiers > i32::from(u16::MAX)
                || method.modifiers != i32::from(member.flags)
            {
                return Err(ClassfileError::SnapshotMismatch("method modifiers"));
            }
            found = Some(method);
        }
    }
    found.ok_or(ClassfileError::SnapshotMismatch("method absent from VM"))
}

fn bytecodes(method: &MethodSnapshot) -> Result<&[u8], ClassfileError> {
    match &method.code {
        MethodCode::Bytecodes(bytes) if !bytes.is_empty() && bytes.len() <= MAX_CODE_BYTES => {
            Ok(bytes)
        }
        MethodCode::Bytecodes(_) => Err(ClassfileError::Bounds("VM Code length")),
        MethodCode::Native | MethodCode::Abstract => {
            Err(ClassfileError::Unsupported("VM native or abstract method"))
        }
    }
}

fn collect_references(value_type: &ValueType, classes: &mut BTreeSet<String>) {
    if let ValueType::Reference(name) = value_type {
        if name.starts_with('[') {
            if let Some(begin) = name.find('L') {
                classes.insert(name[begin + 1..name.len() - 1].to_owned());
            }
        } else {
            classes.insert(name.clone());
        }
    }
}

/// Matches a complete original zero-capture recipe against VM executable
/// semantics. Call only after the native owner has authenticated the pair;
/// accepting this result alone as source or execution authority is invalid.
pub(crate) fn match_hidden_forwarder(
    recipe: &HiddenRecipe,
    snapshot: &ExecutableSnapshot,
) -> Result<HiddenForwarder, ClassfileError> {
    if recipe.flags & 0x0002 == 0 || recipe.flags & !0x000f != 0 {
        return Err(ClassfileError::Unsupported("hidden definition flags"));
    }
    let parsed = parse_classfile(&recipe.input)?;
    parsed.pool.reject_dynamic_dispatch()?;
    if parsed.flags != 0x1030
        || parsed.super_name.as_deref() != Some("java/lang/Object")
        || parsed.interfaces.len() != 1
        || !parsed.fields.is_empty()
        || parsed.methods.len() != 2
    {
        return Err(ClassfileError::Unsupported("zero-capture class shape"));
    }
    validate_class_name(&parsed.class_name)?;
    validate_class_name(&parsed.interfaces[0])?;
    if recipe.requested_name_mutf8.len() > MAX_SYMBOLIC_TEXT_BYTES {
        return Err(ClassfileError::Bounds("requested hidden name length"));
    }
    if !recipe.requested_name_mutf8.is_empty() {
        let units = decode_mutf8(&recipe.requested_name_mutf8)?;
        if units.iter().any(|unit| *unit == 0 || *unit > 0x7f) {
            return Err(ClassfileError::Unsupported(
                "non-ASCII requested hidden name",
            ));
        }
        let requested: String = units
            .iter()
            .map(|unit| {
                if *unit == u16::from(b'.') {
                    '/'
                } else {
                    char::from(*unit as u8)
                }
            })
            .collect();
        if requested != parsed.class_name {
            return Err(ClassfileError::Malformed(
                "requested name and recipe class disagree",
            ));
        }
    }
    for attribute in &parsed.attributes {
        if attribute.name != "SourceFile" || attribute.bytes.len() != 2 {
            return Err(ClassfileError::Unsupported("unknown class attribute"));
        }
        parsed
            .pool
            .utf8(u16::from_be_bytes([attribute.bytes[0], attribute.bytes[1]]))?;
    }
    let constructor = parsed
        .methods
        .iter()
        .find(|member| member.name == "<init>")
        .ok_or(ClassfileError::Unsupported("missing constructor"))?;
    if constructor.descriptor != "()V" || constructor.flags != 0x0002 {
        return Err(ClassfileError::Unsupported(
            "capturing or nonprivate constructor",
        ));
    }
    let sam = parsed
        .methods
        .iter()
        .find(|member| member.name != "<init>")
        .ok_or(ClassfileError::Unsupported("missing SAM"))?;
    validate_method_name(&sam.name)?;
    if sam.flags != 0x0001 && sam.flags != 0x0011 {
        return Err(ClassfileError::Unsupported("SAM access flags"));
    }
    let constructor_code = supported_code(constructor)?;
    if constructor_code.max_stack < 1 || constructor_code.max_locals < 1 {
        return Err(ClassfileError::Malformed("constructor Code limits"));
    }
    let constructor_target = constructor_semantics(&constructor_code.bytes, &parsed.pool)?;
    let sam_code = supported_code(sam)?;
    let (parameters, result) = method_descriptor(&sam.descriptor)?;
    let slots = parameters.iter().map(ValueType::slots).sum::<usize>();
    if usize::from(sam_code.max_locals) < slots + 1
        || usize::from(sam_code.max_stack) < slots.max(result.slots())
    {
        return Err(ClassfileError::Malformed("SAM Code limits"));
    }
    let original = forwarding_semantics(&sam_code.bytes, &sam.descriptor, &parsed.pool)?;
    if original.target.owner == parsed.class_name {
        return Err(ClassfileError::Unsupported("self or hidden target method"));
    }
    if snapshot.methods.len() != parsed.methods.len() {
        return Err(ClassfileError::SnapshotMismatch("complete VM method set"));
    }
    let vm_pool = snapshot_pool(snapshot)?;
    let vm_constructor = snapshot_method(snapshot, constructor)?;
    let vm_sam = snapshot_method(snapshot, sam)?;
    if constructor_semantics(bytecodes(vm_constructor)?, &vm_pool)? != constructor_target
        || forwarding_semantics(bytecodes(vm_sam)?, &sam.descriptor, &vm_pool)? != original
    {
        return Err(ClassfileError::SnapshotMismatch("executable semantics"));
    }
    let mut references = BTreeSet::from([
        "java/lang/Object".to_owned(),
        parsed.interfaces[0].clone(),
        original.target.owner.clone(),
    ]);
    for value_type in parameters.iter().chain(std::iter::once(&result)) {
        collect_references(value_type, &mut references);
    }
    let (target_parameters, target_result) = method_descriptor(&original.target.descriptor)?;
    for value_type in target_parameters
        .iter()
        .chain(std::iter::once(&target_result))
    {
        collect_references(value_type, &mut references);
    }
    Ok(HiddenForwarder {
        class_name: parsed.class_name,
        interface_name: parsed.interfaces[0].clone(),
        sam_name: sam.name.clone(),
        sam_descriptor: sam.descriptor.clone(),
        target: original.target,
        reference_classes: references.into_iter().collect(),
    })
}

struct PackRecipeShape {
    interface: &'static str,
    sam_name: &'static str,
    sam_descriptor: &'static str,
    capture_descriptors: &'static [&'static str],
    target_owner: &'static str,
    target_name: &'static str,
    target_descriptor: &'static str,
}

impl PackCapturedRecipeKind {
    fn shape(self) -> PackRecipeShape {
        match self {
            Self::TaskProvider => PackRecipeShape {
                interface: "net/minecraft/commands/execution/tasks/ContinuationTask$TaskProvider",
                sam_name: "create",
                sam_descriptor: "(Lnet/minecraft/commands/execution/Frame;Ljava/lang/Object;)Lnet/minecraft/commands/execution/CommandQueueEntry;",
                capture_descriptors: &["Lnet/minecraft/commands/ExecutionCommandSource;"],
                target_owner: "net/minecraft/commands/execution/tasks/CallFunction",
                target_name: "lambda$execute$0",
                target_descriptor: "(Lnet/minecraft/commands/ExecutionCommandSource;Lnet/minecraft/commands/execution/Frame;Lnet/minecraft/commands/execution/UnboundEntryAction;)Lnet/minecraft/commands/execution/CommandQueueEntry;",
            },
            Self::EntryAction => PackRecipeShape {
                interface: "net/minecraft/commands/execution/EntryAction",
                sam_name: "execute",
                sam_descriptor: "(Lnet/minecraft/commands/execution/ExecutionContext;Lnet/minecraft/commands/execution/Frame;)V",
                capture_descriptors: &[
                    "Lnet/minecraft/commands/execution/UnboundEntryAction;",
                    "Ljava/lang/Object;",
                ],
                target_owner: "net/minecraft/commands/execution/UnboundEntryAction",
                target_name: "lambda$bind$0",
                target_descriptor: "(Ljava/lang/Object;Lnet/minecraft/commands/execution/ExecutionContext;Lnet/minecraft/commands/execution/Frame;)V",
            },
        }
    }
}

fn reference_field_type(descriptor: &str) -> Result<ValueType, ClassfileError> {
    let mut reader = Reader::new(descriptor.as_bytes());
    let value = field_type(&mut reader, false)?;
    reader.done()?;
    if !matches!(value, ValueType::Reference(_)) {
        return Err(ClassfileError::Unsupported("nonreference capture"));
    }
    Ok(value)
}

fn capture_field(
    reader: &mut Reader<'_>,
    pool: &Pool,
    opcode: u8,
    self_name: &str,
) -> Result<CaptureField, ClassfileError> {
    if reader.u1()? != opcode {
        return Err(ClassfileError::Unsupported("capture field instruction"));
    }
    let (owner, field) = pool.field(reader.u2()?)?;
    if owner != self_name {
        return Err(ClassfileError::Unsupported("capture field owner"));
    }
    validate_method_name(&field.name)?;
    reference_field_type(&field.descriptor)?;
    Ok(field)
}

fn captured_constructor_semantics(
    bytes: &[u8],
    pool: &Pool,
    self_name: &str,
    descriptors: &[&str],
) -> Result<Vec<CaptureField>, ClassfileError> {
    let mut reader = Reader::new(bytes);
    let reference = ValueType::Reference("java/lang/Object".to_owned());
    expect_load(&mut reader, &reference, 0)?;
    if reader.u1()? != 0xb7 {
        return Err(ClassfileError::Unsupported(
            "capture constructor invocation",
        ));
    }
    let object = pool.method(reader.u2()?)?;
    if object.owner != "java/lang/Object"
        || object.name != "<init>"
        || object.descriptor != "()V"
        || object.interface
    {
        return Err(ClassfileError::Unsupported(
            "capture constructor superclass",
        ));
    }
    let mut fields = Vec::with_capacity(descriptors.len());
    for (index, descriptor) in descriptors.iter().enumerate() {
        expect_load(&mut reader, &reference, 0)?;
        expect_load(&mut reader, &reference_field_type(descriptor)?, index + 1)?;
        let field = capture_field(&mut reader, pool, 0xb5, self_name)?;
        if field.descriptor != *descriptor || fields.contains(&field) {
            return Err(ClassfileError::Unsupported(
                "capture constructor assignment",
            ));
        }
        fields.push(field);
    }
    if reader.u1()? != 0xb1 {
        return Err(ClassfileError::Unsupported("capture constructor return"));
    }
    reader.done()?;
    Ok(fields)
}

fn captured_sam_semantics(
    bytes: &[u8],
    pool: &Pool,
    self_name: &str,
    kind: PackCapturedRecipeKind,
    captures: &[CaptureField],
) -> Result<MethodSymbol, ClassfileError> {
    let shape = kind.shape();
    let mut reader = Reader::new(bytes);
    let reference = ValueType::Reference("java/lang/Object".to_owned());
    for expected in captures {
        expect_load(&mut reader, &reference, 0)?;
        if capture_field(&mut reader, pool, 0xb4, self_name)? != *expected {
            return Err(ClassfileError::Unsupported("capture SAM field order"));
        }
    }
    expect_load(&mut reader, &reference, 1)?;
    expect_load(&mut reader, &reference, 2)?;
    if kind == PackCapturedRecipeKind::TaskProvider
        && (reader.u1()? != 0xc0
            || pool.class(reader.u2()?)? != "net/minecraft/commands/execution/UnboundEntryAction")
    {
        return Err(ClassfileError::Unsupported("PACK task argument cast"));
    }
    let expected_opcode = match kind {
        PackCapturedRecipeKind::TaskProvider => 0xb8,
        PackCapturedRecipeKind::EntryAction => 0xb9,
    };
    if reader.u1()? != expected_opcode {
        return Err(ClassfileError::Unsupported("PACK target invocation"));
    }
    let target = pool.method(reader.u2()?)?;
    if target.owner != shape.target_owner
        || target.name != shape.target_name
        || target.descriptor != shape.target_descriptor
        || target.interface != (kind == PackCapturedRecipeKind::EntryAction)
    {
        return Err(ClassfileError::Unsupported("PACK target method"));
    }
    if kind == PackCapturedRecipeKind::EntryAction && (reader.u1()? != 4 || reader.u1()? != 0) {
        return Err(ClassfileError::Unsupported("PACK interface argument slots"));
    }
    let expected_return = match kind {
        PackCapturedRecipeKind::TaskProvider => 0xb0,
        PackCapturedRecipeKind::EntryAction => 0xb1,
    };
    if reader.u1()? != expected_return {
        return Err(ClassfileError::Unsupported("PACK SAM return"));
    }
    reader.done()?;
    Ok(target)
}

/// Supports two closed captured shapes; these are parser policies, not claims
/// that a generated hidden layout has already been observed in a live game.
/// `actual_hidden_name` must come from the exact VM Class's current signature.
pub(crate) fn match_pack_captured_forwarder(
    recipe: &HiddenRecipe,
    snapshot: &ExecutableSnapshot,
    kind: PackCapturedRecipeKind,
    actual_hidden_name: &str,
) -> Result<PackCapturedForwarder, ClassfileError> {
    if recipe.flags & 0x0003 != 0x0003 || recipe.flags & !0x000f != 0 {
        return Err(ClassfileError::Unsupported("PACK hidden nestmate flags"));
    }
    let parsed = parse_classfile(&recipe.input)?;
    parsed.pool.reject_dynamic_dispatch()?;
    let shape = kind.shape();
    if parsed.flags & !0x1000 != 0x0030
        || parsed.super_name.as_deref() != Some("java/lang/Object")
        || parsed.interfaces.len() != 1
        || parsed.interfaces[0] != shape.interface
        || parsed.fields.len() != shape.capture_descriptors.len()
        || parsed.methods.len() != 2
    {
        return Err(ClassfileError::Unsupported("PACK captured class shape"));
    }
    validate_class_name(&parsed.class_name)?;
    if actual_hidden_name.len() > MAX_SYMBOLIC_TEXT_BYTES {
        return Err(ClassfileError::Bounds("actual PACK hidden name length"));
    }
    validate_class_name(actual_hidden_name)?;
    if recipe.requested_name_mutf8.len() > MAX_SYMBOLIC_TEXT_BYTES {
        return Err(ClassfileError::Bounds("requested PACK hidden name length"));
    }
    if !recipe.requested_name_mutf8.is_empty() {
        let requested = decode_mutf8(&recipe.requested_name_mutf8)?;
        if requested.iter().any(|unit| *unit == 0 || *unit > 0x7f) {
            return Err(ClassfileError::Unsupported("non-ASCII PACK hidden name"));
        }
        let requested: String = requested
            .iter()
            .map(|unit| {
                if *unit == u16::from(b'.') {
                    '/'
                } else {
                    char::from(*unit as u8)
                }
            })
            .collect();
        if requested != parsed.class_name {
            return Err(ClassfileError::Malformed(
                "PACK requested name and class disagree",
            ));
        }
    }
    for attribute in &parsed.attributes {
        if attribute.name != "SourceFile" || attribute.bytes.len() != 2 {
            return Err(ClassfileError::Unsupported("PACK class attribute"));
        }
        parsed
            .pool
            .utf8(u16::from_be_bytes([attribute.bytes[0], attribute.bytes[1]]))?;
    }
    for field in &parsed.fields {
        validate_method_name(&field.name)?;
        reference_field_type(&field.descriptor)?;
        if field.flags & !0x1000 != 0x0012 || !field.attributes.is_empty() {
            return Err(ClassfileError::Unsupported(
                "PACK private final capture field",
            ));
        }
    }
    let constructor = parsed
        .methods
        .iter()
        .find(|method| method.name == "<init>")
        .ok_or(ClassfileError::Unsupported("PACK constructor absent"))?;
    let (parameters, result) = method_descriptor(&constructor.descriptor)?;
    let expected_parameters = shape
        .capture_descriptors
        .iter()
        .map(|descriptor| reference_field_type(descriptor))
        .collect::<Result<Vec<_>, _>>()?;
    if constructor.flags & !0x1000 != 0x0002
        || parameters != expected_parameters
        || result != ValueType::Void
    {
        return Err(ClassfileError::Unsupported("PACK constructor parameters"));
    }
    let sam = parsed
        .methods
        .iter()
        .find(|method| method.name == shape.sam_name)
        .ok_or(ClassfileError::Unsupported("PACK SAM absent"))?;
    if sam.descriptor != shape.sam_descriptor || !matches!(sam.flags & !0x1000, 0x0001 | 0x0011) {
        return Err(ClassfileError::Unsupported("PACK SAM signature"));
    }
    let constructor_code = supported_code(constructor)?;
    let sam_code = supported_code(sam)?;
    let required_stack = match kind {
        PackCapturedRecipeKind::TaskProvider => 3,
        PackCapturedRecipeKind::EntryAction => 4,
    };
    if constructor_code.max_stack < 2
        || usize::from(constructor_code.max_locals) < parameters.len() + 1
        || sam_code.max_stack < required_stack
        || sam_code.max_locals < 3
    {
        return Err(ClassfileError::Malformed("PACK Code limits"));
    }
    let captures = captured_constructor_semantics(
        &constructor_code.bytes,
        &parsed.pool,
        &parsed.class_name,
        shape.capture_descriptors,
    )?;
    if captures.iter().any(|capture| {
        !parsed
            .fields
            .iter()
            .any(|field| field.name == capture.name && field.descriptor == capture.descriptor)
    }) {
        return Err(ClassfileError::Unsupported("PACK undeclared capture field"));
    }
    let target = captured_sam_semantics(
        &sam_code.bytes,
        &parsed.pool,
        &parsed.class_name,
        kind,
        &captures,
    )?;
    if snapshot.methods.len() != parsed.methods.len() {
        return Err(ClassfileError::SnapshotMismatch(
            "PACK complete VM method set",
        ));
    }
    let vm_pool = snapshot_pool(snapshot)?;
    let vm_constructor = snapshot_method(snapshot, constructor)?;
    let vm_sam = snapshot_method(snapshot, sam)?;
    let vm_captures = captured_constructor_semantics(
        bytecodes(vm_constructor)?,
        &vm_pool,
        actual_hidden_name,
        shape.capture_descriptors,
    )?;
    if vm_captures != captures
        || captured_sam_semantics(
            bytecodes(vm_sam)?,
            &vm_pool,
            actual_hidden_name,
            kind,
            &vm_captures,
        )? != target
    {
        return Err(ClassfileError::SnapshotMismatch(
            "PACK executable semantics",
        ));
    }
    Ok(PackCapturedForwarder {
        kind,
        target,
        captures,
    })
}

#[cfg(test)]
#[path = "classfile_tests.rs"]
mod tests;

#[cfg(test)]
mod pack_captured_tests {
    use super::*;

    struct FixturePool {
        count: u16,
        bytes: Vec<u8>,
    }
    impl FixturePool {
        fn entry(&mut self, tag: u8, body: &[u8]) -> u16 {
            let index = self.count;
            self.count += 1;
            self.bytes.push(tag);
            self.bytes.extend_from_slice(body);
            index
        }
        fn text(&mut self, value: &str) -> u16 {
            let mut body = (value.len() as u16).to_be_bytes().to_vec();
            body.extend_from_slice(value.as_bytes());
            self.entry(1, &body)
        }
        fn class(&mut self, name: &str) -> u16 {
            let name = self.text(name);
            self.entry(7, &name.to_be_bytes())
        }
        fn member(&mut self, tag: u8, owner: u16, name: &str, descriptor: &str) -> u16 {
            let name = self.text(name);
            let descriptor = self.text(descriptor);
            let mut body = name.to_be_bytes().to_vec();
            body.extend_from_slice(&descriptor.to_be_bytes());
            let name_type = self.entry(12, &body);
            let mut body = owner.to_be_bytes().to_vec();
            body.extend_from_slice(&name_type.to_be_bytes());
            self.entry(tag, &body)
        }
    }

    fn u2(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    fn u4(bytes: &mut Vec<u8>, value: usize) {
        bytes.extend_from_slice(&(value as u32).to_be_bytes());
    }
    fn instruction(bytes: &mut Vec<u8>, opcode: u8, reference: u16) {
        bytes.push(opcode);
        u2(bytes, reference);
    }
    fn method(
        bytes: &mut Vec<u8>,
        flags: u16,
        name: u16,
        descriptor: u16,
        code_name: u16,
        code: &[u8],
    ) {
        u2(bytes, flags);
        u2(bytes, name);
        u2(bytes, descriptor);
        u2(bytes, 1);
        u2(bytes, code_name);
        u4(bytes, code.len() + 12);
        u2(bytes, 4);
        u2(bytes, 3);
        u4(bytes, code.len());
        bytes.extend_from_slice(code);
        u2(bytes, 0);
        u2(bytes, 0);
    }

    /// Synthetic test data for a supported policy, never a live VM observation.
    fn fixture(
        kind: PackCapturedRecipeKind,
        self_name: &str,
        noise: bool,
    ) -> (HiddenRecipe, ExecutableSnapshot) {
        let shape = kind.shape();
        let mut pool = FixturePool {
            count: 1,
            bytes: Vec::new(),
        };
        if noise {
            pool.text("unused pool renumbering sentinel");
        }
        let this = pool.class(self_name);
        let object = pool.class("java/lang/Object");
        let interface = pool.class(shape.interface);
        let owner = pool.class(shape.target_owner);
        let object_init = pool.member(10, object, "<init>", "()V");
        let target = pool.member(
            if kind == PackCapturedRecipeKind::EntryAction {
                11
            } else {
                10
            },
            owner,
            shape.target_name,
            shape.target_descriptor,
        );
        let cast = pool.class("net/minecraft/commands/execution/UnboundEntryAction");
        let code_name = pool.text("Code");
        let ctor_name = pool.text("<init>");
        let ctor_descriptor = format!("({})V", shape.capture_descriptors.concat());
        let ctor_desc = pool.text(&ctor_descriptor);
        let sam_name = pool.text(shape.sam_name);
        let sam_desc = pool.text(shape.sam_descriptor);
        let mut declared = Vec::new();
        let mut references = Vec::new();
        for (index, descriptor) in shape.capture_descriptors.iter().enumerate() {
            let name = format!("retainedValue{index}");
            declared.push((pool.text(&name), pool.text(descriptor)));
            references.push(pool.member(9, this, &name, descriptor));
        }
        let mut constructor = vec![0x2a];
        instruction(&mut constructor, 0xb7, object_init);
        for (index, reference) in references.iter().enumerate() {
            constructor.push(0x2a);
            constructor.push(0x2b + index as u8);
            instruction(&mut constructor, 0xb5, *reference);
        }
        constructor.push(0xb1);
        let mut sam = Vec::new();
        for reference in references {
            sam.push(0x2a);
            instruction(&mut sam, 0xb4, reference);
        }
        sam.extend_from_slice(&[0x2b, 0x2c]);
        if kind == PackCapturedRecipeKind::TaskProvider {
            instruction(&mut sam, 0xc0, cast);
            instruction(&mut sam, 0xb8, target);
            sam.push(0xb0);
        } else {
            instruction(&mut sam, 0xb9, target);
            sam.extend_from_slice(&[4, 0, 0xb1]);
        }
        let mut bytes = vec![0xca, 0xfe, 0xba, 0xbe];
        u2(&mut bytes, 0);
        u2(&mut bytes, 69);
        u2(&mut bytes, pool.count);
        bytes.extend_from_slice(&pool.bytes);
        u2(&mut bytes, 0x1030);
        u2(&mut bytes, this);
        u2(&mut bytes, object);
        u2(&mut bytes, 1);
        u2(&mut bytes, interface);
        u2(&mut bytes, declared.len() as u16);
        for (name, descriptor) in declared {
            u2(&mut bytes, 0x0012);
            u2(&mut bytes, name);
            u2(&mut bytes, descriptor);
            u2(&mut bytes, 0);
        }
        u2(&mut bytes, 2);
        method(&mut bytes, 2, ctor_name, ctor_desc, code_name, &constructor);
        method(&mut bytes, 1, sam_name, sam_desc, code_name, &sam);
        u2(&mut bytes, 0);
        (
            HiddenRecipe {
                input: bytes,
                flags: 3,
                initialize: true,
                lookup_class_id: 1,
                defining_loader_id: 2,
                requested_name_mutf8: self_name.as_bytes().to_vec(),
            },
            ExecutableSnapshot {
                constant_pool_count: u32::from(pool.count),
                constant_pool: pool.bytes,
                methods: vec![
                    MethodSnapshot {
                        name_mutf8: b"<init>".to_vec(),
                        descriptor_mutf8: ctor_descriptor.into_bytes(),
                        modifiers: 2,
                        code: MethodCode::Bytecodes(constructor),
                    },
                    MethodSnapshot {
                        name_mutf8: shape.sam_name.as_bytes().to_vec(),
                        descriptor_mutf8: shape.sam_descriptor.as_bytes().to_vec(),
                        modifiers: 1,
                        code: MethodCode::Bytecodes(sam),
                    },
                ],
            },
        )
    }

    #[test]
    fn two_closed_shapes_preserve_capture_order_and_pool_semantics() {
        for kind in [
            PackCapturedRecipeKind::TaskProvider,
            PackCapturedRecipeKind::EntryAction,
        ] {
            let (recipe, _) = fixture(kind, "test/OriginalHidden", false);
            let (_, vm) = fixture(kind, "test/ActualHidden", true);
            let matched =
                match_pack_captured_forwarder(&recipe, &vm, kind, "test/ActualHidden").unwrap();
            assert_eq!(matched.kind(), kind);
            assert_eq!(
                matched.captures().len(),
                kind.shape().capture_descriptors.len()
            );
            for (index, field) in matched.captures().iter().enumerate() {
                assert_eq!(field.name(), format!("retainedValue{index}"));
                assert_eq!(field.descriptor(), kind.shape().capture_descriptors[index]);
            }
            assert!(match_hidden_forwarder(&recipe, &vm).is_err());
        }
    }

    #[test]
    fn wrong_kind_hidden_owner_and_incomplete_snapshot_are_unavailable() {
        let (recipe, snapshot) =
            fixture(PackCapturedRecipeKind::TaskProvider, "test/Hidden", false);
        assert!(
            match_pack_captured_forwarder(
                &recipe,
                &snapshot,
                PackCapturedRecipeKind::EntryAction,
                "test/Hidden"
            )
            .is_err()
        );
        assert!(
            match_pack_captured_forwarder(
                &recipe,
                &snapshot,
                PackCapturedRecipeKind::TaskProvider,
                "test/Other"
            )
            .is_err()
        );
        let mut missing = snapshot.clone();
        missing.methods.pop();
        assert!(
            match_pack_captured_forwarder(
                &recipe,
                &missing,
                PackCapturedRecipeKind::TaskProvider,
                "test/Hidden"
            )
            .is_err()
        );
    }

    #[test]
    fn changed_vm_dispatch_or_constructor_effects_are_not_recipe_matches() {
        let kind = PackCapturedRecipeKind::EntryAction;
        let (recipe, snapshot) = fixture(kind, "test/Hidden", false);
        for method_index in [0, 1] {
            let mut changed = snapshot.clone();
            let MethodCode::Bytecodes(code) = &mut changed.methods[method_index].code else {
                unreachable!();
            };
            code.insert(code.len() - 1, 0x00);
            assert!(match_pack_captured_forwarder(&recipe, &changed, kind, "test/Hidden").is_err());
        }
        let mut changed = snapshot;
        let MethodCode::Bytecodes(code) = &mut changed.methods[1].code else {
            unreachable!();
        };
        let count = code.len() - 3;
        code[count] = 3;
        assert!(match_pack_captured_forwarder(&recipe, &changed, kind, "test/Hidden").is_err());
    }
}
