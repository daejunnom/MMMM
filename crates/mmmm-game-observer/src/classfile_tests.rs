// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MMMM contributors

//! Authored classfile/snapshot pairs exercise the narrow forwarder matcher.
//! They are neither an observed VM definition nor lookup/loader authority.
//! Separate encoders remap source and VM CP references, including code operands;
//! parser-produced indices are never reused as the expected interpretation.

use super::{ClassfileError, MAX_CLASSFILE_BYTES, match_hidden_forwarder, parse_classfile};
use crate::definitions::{ExecutableSnapshot, HiddenRecipe, MethodCode, MethodSnapshot};

const SELF_NAME: usize = 0;
const SELF_CLASS: usize = 1;
const OBJECT_NAME: usize = 2;
const OBJECT_CLASS: usize = 3;
const INTERFACE_NAME: usize = 4;
const INTERFACE_CLASS: usize = 5;
const INIT_NAME: usize = 6;
const INIT_DESCRIPTOR: usize = 7;
const INIT_NAME_TYPE: usize = 8;
const OBJECT_INIT: usize = 9;
const SAM_NAME: usize = 10;
const SAM_DESCRIPTOR: usize = 11;
const CODE_NAME: usize = 12;
const TARGET_NAME: usize = 13;
const TARGET_CLASS: usize = 14;
const TARGET_METHOD: usize = 15;
const TARGET_NAME_TYPE: usize = 16;
const TARGET_REFERENCE: usize = 17;

#[derive(Clone)]
enum PoolEntry {
    Utf8(Vec<u8>),
    Class(usize),
    NameAndType(usize, usize),
    MethodReference {
        tag: u8,
        class: usize,
        name_type: usize,
    },
    MethodHandle(u8, usize),
    Dynamic(u16, usize),
    InvokeDynamic(u16, usize),
    MethodType(usize),
}

#[derive(Clone)]
enum Instruction {
    Bytes(Vec<u8>),
    PoolOperand(u8, usize),
}

fn bytes(value: &[u8]) -> Instruction {
    Instruction::Bytes(value.to_vec())
}

fn call() -> Instruction {
    Instruction::PoolOperand(0xb8, TARGET_REFERENCE)
}

#[derive(Clone)]
struct MethodSpec {
    access: u16,
    name: usize,
    descriptor: usize,
    instructions: Option<Vec<Instruction>>,
    handlers: Vec<[u16; 4]>,
}

struct Fixture {
    recipe: HiddenRecipe,
    snapshot: ExecutableSnapshot,
    pool: Vec<PoolEntry>,
    methods: Vec<MethodSpec>,
    class_access: u16,
    fields: Vec<(u16, usize, usize)>,
    interfaces: Vec<usize>,
    class_attributes: Vec<(usize, Vec<u8>)>,
    source_map: Vec<u16>,
    vm_map: Vec<u16>,
    code_length_offsets: Vec<usize>,
    attribute_length_offsets: Vec<usize>,
}

fn u16_bytes(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn u32_bytes(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn pool_encoding(pool: &[PoolEntry], order: &[usize]) -> (Vec<u8>, Vec<u16>) {
    assert_eq!(pool.len(), order.len());
    let mut mapping = vec![0u16; pool.len()];
    for (position, label) in order.iter().enumerate() {
        assert_eq!(mapping[*label], 0, "fixture permutation repeats a label");
        mapping[*label] = (position + 1) as u16;
    }
    let mut output = Vec::new();
    for label in order {
        match &pool[*label] {
            PoolEntry::Utf8(value) => {
                output.push(1);
                u16_bytes(&mut output, value.len() as u16);
                output.extend_from_slice(value);
            }
            PoolEntry::Class(name) => {
                output.push(7);
                u16_bytes(&mut output, mapping[*name]);
            }
            PoolEntry::NameAndType(name, descriptor) => {
                output.push(12);
                u16_bytes(&mut output, mapping[*name]);
                u16_bytes(&mut output, mapping[*descriptor]);
            }
            PoolEntry::MethodReference {
                tag,
                class,
                name_type,
            } => {
                output.push(*tag);
                u16_bytes(&mut output, mapping[*class]);
                u16_bytes(&mut output, mapping[*name_type]);
            }
            PoolEntry::MethodHandle(kind, reference) => {
                output.push(15);
                output.push(*kind);
                u16_bytes(&mut output, mapping[*reference]);
            }
            PoolEntry::Dynamic(bootstrap, name_type) => {
                output.push(17);
                u16_bytes(&mut output, *bootstrap);
                u16_bytes(&mut output, mapping[*name_type]);
            }
            PoolEntry::InvokeDynamic(bootstrap, name_type) => {
                output.push(18);
                u16_bytes(&mut output, *bootstrap);
                u16_bytes(&mut output, mapping[*name_type]);
            }
            PoolEntry::MethodType(descriptor) => {
                output.push(16);
                u16_bytes(&mut output, mapping[*descriptor]);
            }
        }
    }
    (output, mapping)
}

fn instructions_encoding(instructions: &[Instruction], mapping: &[u16]) -> Vec<u8> {
    let mut output = Vec::new();
    for instruction in instructions {
        match instruction {
            Instruction::Bytes(value) => output.extend_from_slice(value),
            Instruction::PoolOperand(opcode, label) => {
                output.push(*opcode);
                u16_bytes(&mut output, mapping[*label]);
            }
        }
    }
    output
}

impl Fixture {
    fn for_descriptor(descriptor: &str, sam: Vec<Instruction>) -> Self {
        let pool = vec![
            PoolEntry::Utf8(b"fixtures/Forwarder".to_vec()),
            PoolEntry::Class(SELF_NAME),
            PoolEntry::Utf8(b"java/lang/Object".to_vec()),
            PoolEntry::Class(OBJECT_NAME),
            PoolEntry::Utf8(b"fixtures/ForwarderFn".to_vec()),
            PoolEntry::Class(INTERFACE_NAME),
            PoolEntry::Utf8(b"<init>".to_vec()),
            PoolEntry::Utf8(b"()V".to_vec()),
            PoolEntry::NameAndType(INIT_NAME, INIT_DESCRIPTOR),
            PoolEntry::MethodReference {
                tag: 10,
                class: OBJECT_CLASS,
                name_type: INIT_NAME_TYPE,
            },
            PoolEntry::Utf8(b"apply".to_vec()),
            PoolEntry::Utf8(descriptor.as_bytes().to_vec()),
            PoolEntry::Utf8(b"Code".to_vec()),
            PoolEntry::Utf8(b"fixtures/Target".to_vec()),
            PoolEntry::Class(TARGET_NAME),
            PoolEntry::Utf8(b"forward".to_vec()),
            PoolEntry::NameAndType(TARGET_METHOD, SAM_DESCRIPTOR),
            PoolEntry::MethodReference {
                tag: 10,
                class: TARGET_CLASS,
                name_type: TARGET_NAME_TYPE,
            },
        ];
        let methods = vec![
            MethodSpec {
                access: 2,
                name: INIT_NAME,
                descriptor: INIT_DESCRIPTOR,
                instructions: Some(vec![
                    bytes(&[0x2a]),
                    Instruction::PoolOperand(0xb7, OBJECT_INIT),
                    bytes(&[0xb1]),
                ]),
                handlers: Vec::new(),
            },
            MethodSpec {
                access: 0x11,
                name: SAM_NAME,
                descriptor: SAM_DESCRIPTOR,
                instructions: Some(sam),
                handlers: Vec::new(),
            },
        ];
        let mut fixture = Self {
            recipe: HiddenRecipe {
                input: Vec::new(),
                flags: 7,
                initialize: false,
                lookup_class_id: 41,
                defining_loader_id: 7,
                requested_name_mutf8: b"fixtures/Forwarder".to_vec(),
            },
            snapshot: ExecutableSnapshot {
                constant_pool_count: 0,
                constant_pool: Vec::new(),
                methods: Vec::new(),
            },
            pool,
            methods,
            class_access: 0x1030,
            fields: Vec::new(),
            interfaces: vec![INTERFACE_CLASS],
            class_attributes: Vec::new(),
            source_map: Vec::new(),
            vm_map: Vec::new(),
            code_length_offsets: Vec::new(),
            attribute_length_offsets: Vec::new(),
        };
        fixture.rebuild();
        fixture
    }

    fn integer() -> Self {
        Self::for_descriptor("(I)I", vec![bytes(&[0x1b]), call(), bytes(&[0xac])])
    }

    fn clone_for_metadata(&self) -> Self {
        let mut fixture = Self::integer();
        fixture.pool = self.pool.clone();
        fixture.methods = self.methods.clone();
        fixture.class_access = self.class_access;
        fixture.fields = self.fields.clone();
        fixture.interfaces = self.interfaces.clone();
        fixture.class_attributes = self.class_attributes.clone();
        fixture.rebuild();
        fixture
    }

    fn rebuild(&mut self) {
        let source_order = (0..self.pool.len()).collect::<Vec<_>>();
        let (source_pool, source_mapping) = pool_encoding(&self.pool, &source_order);
        let mut input = Vec::new();
        u32_bytes(&mut input, 0xcafe_babe);
        u16_bytes(&mut input, 0);
        u16_bytes(&mut input, 69);
        u16_bytes(&mut input, (self.pool.len() + 1) as u16);
        input.extend_from_slice(&source_pool);
        u16_bytes(&mut input, self.class_access);
        u16_bytes(&mut input, source_mapping[SELF_CLASS]);
        u16_bytes(&mut input, source_mapping[OBJECT_CLASS]);
        u16_bytes(&mut input, self.interfaces.len() as u16);
        for interface in &self.interfaces {
            u16_bytes(&mut input, source_mapping[*interface]);
        }
        u16_bytes(&mut input, self.fields.len() as u16);
        for (access, name, descriptor) in &self.fields {
            u16_bytes(&mut input, *access);
            u16_bytes(&mut input, source_mapping[*name]);
            u16_bytes(&mut input, source_mapping[*descriptor]);
            u16_bytes(&mut input, 0);
        }
        u16_bytes(&mut input, self.methods.len() as u16);
        self.code_length_offsets.clear();
        self.attribute_length_offsets.clear();
        for method in &self.methods {
            u16_bytes(&mut input, method.access);
            u16_bytes(&mut input, source_mapping[method.name]);
            u16_bytes(&mut input, source_mapping[method.descriptor]);
            if let Some(instructions) = &method.instructions {
                let code = instructions_encoding(instructions, &source_mapping);
                let mut attribute = Vec::new();
                u16_bytes(&mut attribute, 16);
                u16_bytes(&mut attribute, 16);
                u32_bytes(&mut attribute, code.len() as u32);
                attribute.extend_from_slice(&code);
                u16_bytes(&mut attribute, method.handlers.len() as u16);
                for handler in &method.handlers {
                    for field in handler {
                        u16_bytes(&mut attribute, *field);
                    }
                }
                u16_bytes(&mut attribute, 0);
                u16_bytes(&mut input, 1);
                u16_bytes(&mut input, source_mapping[CODE_NAME]);
                self.attribute_length_offsets.push(input.len());
                u32_bytes(&mut input, attribute.len() as u32);
                self.code_length_offsets.push(input.len() + 4);
                input.extend_from_slice(&attribute);
            } else {
                u16_bytes(&mut input, 0);
            }
        }
        u16_bytes(&mut input, self.class_attributes.len() as u16);
        for (name, body) in &self.class_attributes {
            u16_bytes(&mut input, source_mapping[*name]);
            u32_bytes(&mut input, body.len() as u32);
            input.extend_from_slice(body);
        }
        self.recipe.input = input;
        self.source_map = source_mapping;

        // The VM side has a different ordering and one extra unused constant.
        let mut vm_pool = self.pool.clone();
        vm_pool.push(PoolEntry::Utf8(b"vm-unused-constant".to_vec()));
        let vm_order = (0..vm_pool.len()).rev().collect::<Vec<_>>();
        let (vm_bytes, vm_mapping) = pool_encoding(&vm_pool, &vm_order);
        let methods = self
            .methods
            .iter()
            .map(|method| {
                let name = match &self.pool[method.name] {
                    PoolEntry::Utf8(value) => value.clone(),
                    _ => panic!("fixture name tag"),
                };
                let descriptor = match &self.pool[method.descriptor] {
                    PoolEntry::Utf8(value) => value.clone(),
                    _ => panic!("fixture descriptor tag"),
                };
                let code = method.instructions.as_ref().map_or_else(
                    || {
                        if method.access & 0x100 != 0 {
                            MethodCode::Native
                        } else {
                            MethodCode::Abstract
                        }
                    },
                    |instructions| {
                        MethodCode::Bytecodes(instructions_encoding(instructions, &vm_mapping))
                    },
                );
                MethodSnapshot {
                    name_mutf8: name,
                    descriptor_mutf8: descriptor,
                    modifiers: i32::from(method.access),
                    code,
                }
            })
            .collect();
        self.snapshot = ExecutableSnapshot {
            constant_pool_count: (vm_pool.len() + 1) as u32,
            constant_pool: vm_bytes,
            methods,
        };
        self.vm_map = vm_mapping;
    }
}

fn assert_rejected(fixture: &Fixture) {
    assert!(match_hidden_forwarder(&fixture.recipe, &fixture.snapshot).is_err());
}

#[test]
fn independently_reordered_vm_pool_and_operands_keep_the_same_static_target() {
    let fixture = Fixture::integer();
    assert!(parse_classfile(&fixture.recipe.input).is_ok());
    assert_ne!(
        fixture.source_map[TARGET_REFERENCE],
        fixture.vm_map[TARGET_REFERENCE]
    );
    let forwarder = match_hidden_forwarder(&fixture.recipe, &fixture.snapshot).unwrap();
    assert_eq!(forwarder.class_name(), "fixtures/Forwarder");
    assert_eq!(forwarder.interface_name(), "fixtures/ForwarderFn");
    assert_eq!(forwarder.sam_name(), "apply");
    assert_eq!(forwarder.sam_descriptor(), "(I)I");
    assert_eq!(forwarder.target().owner(), "fixtures/Target");
    assert_eq!(forwarder.target().name(), "forward");
    assert_eq!(forwarder.target().descriptor(), "(I)I");
    assert!(!forwarder.target().is_interface());
    assert!(
        forwarder
            .reference_classes()
            .iter()
            .any(|class| class == "fixtures/Target")
    );
}

#[test]
fn static_interface_target_is_described_separately_from_ordinary_method_target() {
    let mut fixture = Fixture::integer();
    fixture.pool[TARGET_REFERENCE] = PoolEntry::MethodReference {
        tag: 11,
        class: TARGET_CLASS,
        name_type: TARGET_NAME_TYPE,
    };
    fixture.rebuild();
    let forwarder = match_hidden_forwarder(&fixture.recipe, &fixture.snapshot).unwrap();
    assert!(forwarder.target().is_interface());
    assert_eq!(forwarder.target().owner(), "fixtures/Target");
    assert_eq!(forwarder.target().descriptor(), "(I)I");
}

#[test]
fn compact_generic_and_wide_argument_loads_preserve_typed_slot_order() {
    for loads in [vec![0x1b], vec![0x15, 1], vec![0xc4, 0x15, 0, 1]] {
        let fixture = Fixture::for_descriptor("(I)I", vec![bytes(&loads), call(), bytes(&[0xac])]);
        assert!(match_hidden_forwarder(&fixture.recipe, &fixture.snapshot).is_ok());
    }
    let wide_values =
        Fixture::for_descriptor("(JD)J", vec![bytes(&[0x1f, 0x29]), call(), bytes(&[0xad])]);
    assert!(match_hidden_forwarder(&wide_values.recipe, &wide_values.snapshot).is_ok());
    for wrong_loads in [
        vec![0x1e, 0x29],
        vec![0x1f, 0x28],
        vec![0x29, 0x1f],
        vec![0x1f, 0x1f],
    ] {
        assert_rejected(&Fixture::for_descriptor(
            "(JD)J",
            vec![bytes(&wrong_loads), call(), bytes(&[0xad])],
        ));
    }
    assert_rejected(&Fixture::for_descriptor(
        "(II)I",
        vec![bytes(&[0x1c, 0x1b]), call(), bytes(&[0xac])],
    ));
    assert_rejected(&Fixture::for_descriptor(
        "(II)I",
        vec![bytes(&[0x1b, 0x1b]), call(), bytes(&[0xac])],
    ));
}

#[test]
fn same_opcode_primitive_family_does_not_authorize_descriptor_adaptation() {
    for tag in ['B', 'C', 'S', 'Z', 'I'] {
        let descriptor = format!("({tag}){tag}");
        let matching =
            Fixture::for_descriptor(&descriptor, vec![bytes(&[0x1b]), call(), bytes(&[0xac])]);
        assert!(match_hidden_forwarder(&matching.recipe, &matching.snapshot).is_ok());
    }
    for descriptor in [
        "(B)I", "(C)I", "(S)I", "(Z)I", "(I)B", "(I)C", "(I)S", "(I)Z",
    ] {
        let mut adapted = Fixture::integer();
        let label = adapted.pool.len();
        adapted
            .pool
            .push(PoolEntry::Utf8(descriptor.as_bytes().to_vec()));
        adapted.pool[TARGET_NAME_TYPE] = PoolEntry::NameAndType(TARGET_METHOD, label);
        adapted.rebuild();
        assert_rejected(&adapted);
    }
}

#[test]
fn only_exact_target_reference_argument_checkcast_is_allowed() {
    let accepted = Fixture::for_descriptor(
        "(Ljava/lang/Object;)Ljava/lang/Object;",
        vec![
            bytes(&[0x2b]),
            Instruction::PoolOperand(0xc0, OBJECT_CLASS),
            call(),
            bytes(&[0xb0]),
        ],
    );
    assert!(match_hidden_forwarder(&accepted.recipe, &accepted.snapshot).is_ok());
    let changed_cast = Fixture::for_descriptor(
        "(Ljava/lang/Object;)Ljava/lang/Object;",
        vec![
            bytes(&[0x2b]),
            Instruction::PoolOperand(0xc0, TARGET_CLASS),
            call(),
            bytes(&[0xb0]),
        ],
    );
    assert_rejected(&changed_cast);
    let no_cast = Fixture::for_descriptor(
        "(Ljava/lang/Object;)Ljava/lang/Object;",
        vec![bytes(&[0x2b]), call(), bytes(&[0xb0])],
    );
    assert!(match_hidden_forwarder(&no_cast.recipe, &no_cast.snapshot).is_ok());
}

#[test]
fn forwarded_code_rejects_capture_virtual_branch_extra_call_and_wrong_return() {
    for instructions in [
        vec![
            bytes(&[0x1b]),
            Instruction::PoolOperand(0xb6, TARGET_REFERENCE),
            bytes(&[0xac]),
        ],
        vec![bytes(&[0x1b, 0x99, 0, 3]), call(), bytes(&[0xac])],
        vec![bytes(&[0x1b]), call(), call(), bytes(&[0xac])],
        vec![bytes(&[0x1b, 0x59]), call(), bytes(&[0xac])],
        vec![bytes(&[0x04]), call(), bytes(&[0xac])],
        vec![bytes(&[0x1b]), call(), bytes(&[0xb0])],
        vec![bytes(&[0x1b]), call(), bytes(&[0xac, 0x00])],
    ] {
        assert_rejected(&Fixture::for_descriptor("(I)I", instructions));
    }
    let mut capture = Fixture::integer();
    let name = capture.pool.len();
    capture.pool.push(PoolEntry::Utf8(b"captured".to_vec()));
    let descriptor = capture.pool.len();
    capture.pool.push(PoolEntry::Utf8(b"I".to_vec()));
    capture.fields.push((0x12, name, descriptor));
    capture.rebuild();
    assert_rejected(&capture);
}

#[test]
fn native_abstract_duplicate_missing_and_modified_vm_sam_are_rejected() {
    for code in [
        MethodCode::Native,
        MethodCode::Abstract,
        MethodCode::Bytecodes(vec![0xb1]),
    ] {
        let mut fixture = Fixture::integer();
        fixture.snapshot.methods[1].code = code;
        assert_rejected(&fixture);
    }
    let mut missing = Fixture::integer();
    missing.snapshot.methods.pop();
    assert_rejected(&missing);
    let mut changed_modifier = Fixture::integer();
    changed_modifier.snapshot.methods[1].modifiers = 9;
    assert_rejected(&changed_modifier);
    let mut duplicate = Fixture::integer();
    duplicate.methods.push(duplicate.methods[1].clone());
    duplicate.rebuild();
    assert_rejected(&duplicate);
    let mut native_source = Fixture::integer();
    native_source.methods[1].access = 0x101;
    native_source.methods[1].instructions = None;
    native_source.rebuild();
    assert_rejected(&native_source);
}

#[test]
fn exact_class_shape_constructor_and_exception_free_code_are_required() {
    for access in [0x0030, 0x1020, 0x1031] {
        let mut fixture = Fixture::integer();
        fixture.class_access = access;
        fixture.rebuild();
        assert_rejected(&fixture);
    }
    let mut extra_interface = Fixture::integer();
    extra_interface.interfaces.push(OBJECT_CLASS);
    extra_interface.rebuild();
    assert_rejected(&extra_interface);
    let mut no_interface = Fixture::integer();
    no_interface.interfaces.clear();
    no_interface.rebuild();
    assert_rejected(&no_interface);
    let mut changed_super = Fixture::integer();
    changed_super.pool[OBJECT_NAME] = PoolEntry::Utf8(b"fixtures/OtherBase".to_vec());
    changed_super.rebuild();
    assert_rejected(&changed_super);
    let mut class_initializer = Fixture::integer();
    let name = class_initializer.pool.len();
    class_initializer
        .pool
        .push(PoolEntry::Utf8(b"<clinit>".to_vec()));
    class_initializer.methods.push(MethodSpec {
        access: 8,
        name,
        descriptor: INIT_DESCRIPTOR,
        instructions: Some(vec![bytes(&[0xb1])]),
        handlers: Vec::new(),
    });
    class_initializer.rebuild();
    assert_rejected(&class_initializer);
    let mut public_constructor = Fixture::integer();
    public_constructor.methods[0].access = 1;
    public_constructor.rebuild();
    assert_rejected(&public_constructor);
    let mut extra_constructor_op = Fixture::integer();
    extra_constructor_op.methods[0]
        .instructions
        .as_mut()
        .unwrap()
        .insert(0, bytes(&[0x00]));
    extra_constructor_op.rebuild();
    assert_rejected(&extra_constructor_op);
    for handler in [[0, 1, 0, 0], [0, 1, 0, 4], [1, 1, 0, 0], [0, 65535, 0, 0]] {
        let mut fixture = Fixture::integer();
        fixture.methods[1].handlers.push(handler);
        fixture.rebuild();
        assert_rejected(&fixture);
    }
}

#[test]
fn duplicate_missing_or_unknown_code_attributes_cannot_change_the_code_interpretation() {
    let mut duplicate = Fixture::integer();
    let length_offset = duplicate.attribute_length_offsets[1];
    let attribute_length = u32::from_be_bytes(
        duplicate.recipe.input[length_offset..length_offset + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let attribute_start = length_offset - 2;
    let attribute_end = length_offset + 4 + attribute_length;
    let original_attribute = duplicate.recipe.input[attribute_start..attribute_end].to_vec();
    duplicate.recipe.input[length_offset - 4..length_offset - 2]
        .copy_from_slice(&2u16.to_be_bytes());
    duplicate
        .recipe
        .input
        .splice(attribute_end..attribute_end, original_attribute);
    assert_rejected(&duplicate);

    let mut missing = Fixture::integer();
    missing.recipe.input[length_offset - 4..length_offset - 2].copy_from_slice(&0u16.to_be_bytes());
    missing.recipe.input.drain(attribute_start..attribute_end);
    assert_rejected(&missing);
    let mut unknown = Fixture::integer();
    unknown.recipe.input[attribute_start..attribute_start + 2]
        .copy_from_slice(&unknown.source_map[SAM_NAME].to_be_bytes());
    assert_rejected(&unknown);
}

#[test]
fn truncated_lengths_preview_trailing_bytes_and_invalid_modified_utf8_are_rejected() {
    let fixture = Fixture::integer();
    for length in 0..fixture.recipe.input.len() {
        assert!(
            parse_classfile(&fixture.recipe.input[..length]).is_err(),
            "truncated prefix {length}"
        );
    }
    let mut trailing = fixture.recipe.input.clone();
    trailing.push(0);
    assert!(parse_classfile(&trailing).is_err());
    let mut preview = fixture.recipe.input.clone();
    preview[4..6].copy_from_slice(&65535u16.to_be_bytes());
    assert!(parse_classfile(&preview).is_err());
    let mut zero_pool = fixture.recipe.input.clone();
    zero_pool[8..10].copy_from_slice(&0u16.to_be_bytes());
    assert!(parse_classfile(&zero_pool).is_err());
    for offset in fixture
        .code_length_offsets
        .iter()
        .chain(&fixture.attribute_length_offsets)
    {
        let mut oversized = fixture.recipe.input.clone();
        oversized[*offset..*offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_classfile(&oversized).is_err());
    }
    for invalid_name in [
        vec![0],
        vec![0xf0, 0x90, 0x80, 0x80],
        vec![0xc2],
        vec![0xc2, 0x20],
        vec![0xff],
    ] {
        let mut invalid = Fixture::integer();
        invalid.pool[SELF_NAME] = PoolEntry::Utf8(invalid_name);
        invalid.rebuild();
        assert!(parse_classfile(&invalid.recipe.input).is_err());
    }
}

#[test]
fn cp_cycles_wrong_tags_and_dynamic_or_method_handle_recipe_are_rejected() {
    for (label, entry) in [
        (SELF_CLASS, PoolEntry::Class(SELF_CLASS)),
        (TARGET_CLASS, PoolEntry::Class(TARGET_NAME_TYPE)),
        (
            TARGET_NAME_TYPE,
            PoolEntry::NameAndType(TARGET_NAME_TYPE, SAM_DESCRIPTOR),
        ),
        (
            TARGET_REFERENCE,
            PoolEntry::MethodReference {
                tag: 10,
                class: SAM_NAME,
                name_type: TARGET_NAME_TYPE,
            },
        ),
    ] {
        let mut invalid = Fixture::integer();
        invalid.pool[label] = entry;
        invalid.rebuild();
        assert_rejected(&invalid);
    }
    for extra in [
        PoolEntry::Dynamic(0, TARGET_NAME_TYPE),
        PoolEntry::MethodHandle(6, TARGET_REFERENCE),
    ] {
        let mut invalid = Fixture::integer();
        invalid.pool.push(extra);
        invalid.rebuild();
        assert_rejected(&invalid);
    }
}

#[test]
fn vm_same_index_different_owner_or_descriptor_and_partial_operand_remap_are_rejected() {
    let mut owner_changed = Fixture::integer();
    let mut vm_pool = owner_changed.pool.clone();
    vm_pool[TARGET_NAME] = PoolEntry::Utf8(b"fixtures/OtherTarget".to_vec());
    vm_pool.push(PoolEntry::Utf8(b"vm-unused-constant".to_vec()));
    let order = (0..vm_pool.len()).rev().collect::<Vec<_>>();
    owner_changed.snapshot.constant_pool = pool_encoding(&vm_pool, &order).0;
    assert_rejected(&owner_changed);
    let mut descriptor_changed = Fixture::integer();
    let mut vm_pool = descriptor_changed.pool.clone();
    vm_pool[SAM_DESCRIPTOR] = PoolEntry::Utf8(b"(F)F".to_vec());
    vm_pool.push(PoolEntry::Utf8(b"vm-unused-constant".to_vec()));
    descriptor_changed.snapshot.constant_pool = pool_encoding(&vm_pool, &order).0;
    assert_rejected(&descriptor_changed);
    let mut not_remapped = Fixture::integer();
    let original_index = not_remapped.source_map[TARGET_REFERENCE];
    let vm_code = match &mut not_remapped.snapshot.methods[1].code {
        MethodCode::Bytecodes(value) => value,
        _ => panic!("fixture code"),
    };
    vm_code[2..4].copy_from_slice(&original_index.to_be_bytes());
    assert_rejected(&not_remapped);
    let mut renamed = Fixture::integer();
    renamed.snapshot.methods[1].name_mutf8 = b"otherMethod".to_vec();
    assert_rejected(&renamed);
    let mut descriptor = Fixture::integer();
    descriptor.snapshot.methods[1].descriptor_mutf8 = b"(F)F".to_vec();
    assert_rejected(&descriptor);
}

#[test]
fn hidden_flag_and_requested_name_preconditions_do_not_substitute_for_vm_identity() {
    for flags in [0, 1, 4, 16, -1, 0x12] {
        let mut fixture = Fixture::integer();
        fixture.recipe.flags = flags;
        assert_rejected(&fixture);
    }
    let mut dotted = Fixture::integer();
    dotted.recipe.requested_name_mutf8 = b"fixtures.Forwarder".to_vec();
    assert!(match_hidden_forwarder(&dotted.recipe, &dotted.snapshot).is_ok());
    for name in [
        b"fixtures/OtherForwarder".to_vec(),
        vec![0],
        vec![0xf0, 0x90, 0x80, 0x80],
    ] {
        let mut fixture = Fixture::integer();
        fixture.recipe.requested_name_mutf8 = name;
        assert_rejected(&fixture);
    }
    // The descriptive matcher intentionally does not issue or validate lookup
    // and loader authority. The native issuer owns the IDs' provenance.
    let mut metadata = Fixture::integer();
    metadata.recipe.lookup_class_id = 0;
    metadata.recipe.defining_loader_id = u64::MAX;
    metadata.recipe.initialize = true;
    assert!(match_hidden_forwarder(&metadata.recipe, &metadata.snapshot).is_ok());
}

#[test]
fn input_snapshot_code_and_pool_bounds_are_checked_before_unbounded_parse() {
    let oversized = vec![0u8; MAX_CLASSFILE_BYTES + 1];
    assert!(matches!(
        parse_classfile(&oversized),
        Err(ClassfileError::Bounds(_))
    ));
    let mut pool_count = Fixture::integer();
    pool_count.snapshot.constant_pool_count = u32::MAX;
    assert!(matches!(
        match_hidden_forwarder(&pool_count.recipe, &pool_count.snapshot),
        Err(ClassfileError::Bounds(_))
    ));
    let mut oversized_code = Fixture::integer();
    oversized_code.snapshot.methods[1].code = MethodCode::Bytecodes(vec![0u8; 65536]);
    assert!(matches!(
        match_hidden_forwarder(&oversized_code.recipe, &oversized_code.snapshot),
        Err(ClassfileError::Bounds(_))
    ));
    let mut excess_methods = Fixture::integer();
    let extra = excess_methods.snapshot.methods[1].clone();
    excess_methods.snapshot.methods.resize(257, extra);
    assert_rejected(&excess_methods);
}

#[test]
fn error_categories_describe_failure_without_issuing_runtime_authority() {
    let error = parse_classfile(b"not a classfile").expect_err("malformed input rejected");
    assert!(matches!(
        error,
        ClassfileError::Malformed(_) | ClassfileError::Bounds(_)
    ));
    let mut fixture = Fixture::integer();
    fixture.snapshot.constant_pool_count = 0;
    let error = match_hidden_forwarder(&fixture.recipe, &fixture.snapshot)
        .expect_err("invalid snapshot rejected");
    assert!(matches!(
        error,
        ClassfileError::Malformed(_)
            | ClassfileError::Bounds(_)
            | ClassfileError::SnapshotMismatch(_)
            | ClassfileError::Unsupported(_)
    ));
}

// The existing authored encoder is sufficient to check metadata retention,
// remapping and rejection. These additions do not need external game bytes and
// do not claim a JVM-valid bootstrap signature or a live ordinary body proof.
fn bootstrap_fixture() -> (Fixture, usize, usize, usize) {
    let mut fixture = Fixture::integer();
    let attribute_name = fixture.pool.len();
    fixture
        .pool
        .push(PoolEntry::Utf8(b"BootstrapMethods".to_vec()));
    let handle = fixture.pool.len();
    fixture
        .pool
        .push(PoolEntry::MethodHandle(6, TARGET_REFERENCE));
    let method_type = fixture.pool.len();
    fixture.pool.push(PoolEntry::MethodType(SAM_DESCRIPTOR));
    let dynamic = fixture.pool.len();
    fixture
        .pool
        .push(PoolEntry::InvokeDynamic(1, TARGET_NAME_TYPE));
    fixture.rebuild();
    let mut body = Vec::new();
    u16_bytes(&mut body, 2);
    u16_bytes(&mut body, fixture.source_map[handle]);
    u16_bytes(&mut body, 0);
    u16_bytes(&mut body, fixture.source_map[handle]);
    u16_bytes(&mut body, 2);
    u16_bytes(&mut body, fixture.source_map[OBJECT_CLASS]);
    u16_bytes(&mut body, fixture.source_map[method_type]);
    fixture.class_attributes.push((attribute_name, body));
    fixture.rebuild();
    (fixture, dynamic, handle, method_type)
}

#[test]
fn selected_method_and_original_bootstrap_index_are_descriptive_metadata() {
    let (fixture, dynamic, handle, method_type) = bootstrap_fixture();
    let parsed = parse_classfile(&fixture.recipe.input).unwrap();
    let selected = parsed.selected_method("apply", "(I)I").unwrap();
    assert_eq!(selected.flags, 0x11);
    assert_eq!(selected.code.as_ref().unwrap().bytes[0], 0x1b);
    assert!(parsed.selected_method("apply", "()V").is_err());
    let (index, bootstrap) = parsed
        .bootstrap_for_dynamic(fixture.source_map[dynamic])
        .unwrap();
    assert_eq!(index, 1);
    assert_eq!(bootstrap.method_ref, fixture.source_map[handle]);
    assert_eq!(
        bootstrap.arguments,
        vec![
            fixture.source_map[OBJECT_CLASS],
            fixture.source_map[method_type]
        ]
    );
    assert!(
        parsed
            .bootstrap_for_dynamic(fixture.source_map[TARGET_REFERENCE])
            .is_err()
    );
    // Structural bootstrap retention never broadens the hidden recipe policy.
    assert_rejected(&fixture);
    let mut attribute_only = Fixture::integer();
    let name = attribute_only.pool.len();
    attribute_only
        .pool
        .push(PoolEntry::Utf8(b"BootstrapMethods".to_vec()));
    attribute_only.class_attributes.push((name, vec![0, 0]));
    attribute_only.rebuild();
    assert!(parse_classfile(&attribute_only.recipe.input).is_ok());
    assert_rejected(&attribute_only);
}

#[test]
fn dynamic_constants_and_loadable_arguments_keep_their_original_edges() {
    let (mut fixture, _, handle, _) = bootstrap_fixture();
    let descriptor = fixture.pool.len();
    fixture.pool.push(PoolEntry::Utf8(b"I".to_vec()));
    let name_type = fixture.pool.len();
    fixture
        .pool
        .push(PoolEntry::NameAndType(TARGET_METHOD, descriptor));
    let dynamic = fixture.pool.len();
    fixture.pool.push(PoolEntry::Dynamic(0, name_type));
    fixture.rebuild();
    let mut body = Vec::new();
    u16_bytes(&mut body, 2);
    for arguments in [Vec::new(), vec![fixture.source_map[dynamic]]] {
        u16_bytes(&mut body, fixture.source_map[handle]);
        u16_bytes(&mut body, arguments.len() as u16);
        for argument in arguments {
            u16_bytes(&mut body, argument);
        }
    }
    fixture.class_attributes[0].1 = body;
    fixture.rebuild();
    let parsed = parse_classfile(&fixture.recipe.input).unwrap();
    assert_eq!(
        parsed
            .bootstrap_for_dynamic(fixture.source_map[dynamic])
            .unwrap()
            .0,
        0
    );
    assert_eq!(
        parsed.bootstrap_methods[1].arguments,
        vec![fixture.source_map[dynamic]]
    );
    assert_rejected(&fixture);
}

#[test]
fn bootstrap_singleton_indices_tags_and_complete_attribute_body_are_checked() {
    let (fixture, dynamic, handle, _) = bootstrap_fixture();
    let mut missing = fixture.clone_for_metadata();
    missing.class_attributes.clear();
    missing.rebuild();
    assert!(parse_classfile(&missing.recipe.input).is_err());
    let mut duplicate = fixture.clone_for_metadata();
    duplicate
        .class_attributes
        .push(duplicate.class_attributes[0].clone());
    duplicate.rebuild();
    assert!(parse_classfile(&duplicate.recipe.input).is_err());
    let mut out_of_range = fixture.clone_for_metadata();
    out_of_range.pool[dynamic] = PoolEntry::InvokeDynamic(2, TARGET_NAME_TYPE);
    out_of_range.rebuild();
    assert!(parse_classfile(&out_of_range.recipe.input).is_err());
    let mut no_dynamic = fixture.clone_for_metadata();
    no_dynamic.pool[dynamic] = PoolEntry::Utf8(b"unused".to_vec());
    no_dynamic.rebuild();
    assert!(parse_classfile(&no_dynamic.recipe.input).is_ok());
    for bad_reference in [0, fixture.source_map[TARGET_REFERENCE]] {
        let mut invalid = fixture.clone_for_metadata();
        invalid.class_attributes[0].1[2..4].copy_from_slice(&bad_reference.to_be_bytes());
        invalid.rebuild();
        assert!(parse_classfile(&invalid.recipe.input).is_err());
    }
    for bad_argument in [0, fixture.source_map[SAM_NAME], fixture.source_map[dynamic]] {
        let mut invalid = fixture.clone_for_metadata();
        invalid.class_attributes[0].1[10..12].copy_from_slice(&bad_argument.to_be_bytes());
        invalid.rebuild();
        assert!(parse_classfile(&invalid.recipe.input).is_err());
    }
    let mut truncated = fixture.clone_for_metadata();
    truncated.class_attributes[0].1.pop();
    truncated.rebuild();
    assert!(parse_classfile(&truncated.recipe.input).is_err());
    let mut trailing = fixture.clone_for_metadata();
    trailing.class_attributes[0].1.push(0);
    trailing.rebuild();
    assert!(parse_classfile(&trailing.recipe.input).is_err());
    let mut virtual_handle = fixture.clone_for_metadata();
    virtual_handle.pool[handle] = PoolEntry::MethodHandle(5, TARGET_REFERENCE);
    virtual_handle.rebuild();
    assert!(parse_classfile(&virtual_handle.recipe.input).is_ok());
    assert_rejected(&virtual_handle);
}

#[test]
fn bootstrap_allocation_limits_precede_argument_collection() {
    let (fixture, _, handle, _) = bootstrap_fixture();
    for body in [
        ((super::MAX_BOOTSTRAP_METHODS + 1) as u16)
            .to_be_bytes()
            .to_vec(),
        [
            1u16.to_be_bytes(),
            fixture.source_map[handle].to_be_bytes(),
            ((super::MAX_BOOTSTRAP_ARGUMENTS + 1) as u16).to_be_bytes(),
        ]
        .concat(),
    ] {
        let mut invalid = fixture.clone_for_metadata();
        invalid.class_attributes[0].1 = body;
        invalid.rebuild();
        assert!(matches!(
            parse_classfile(&invalid.recipe.input),
            Err(ClassfileError::Bounds(_))
        ));
    }
    let mut total = fixture.clone_for_metadata();
    let count = super::MAX_TOTAL_BOOTSTRAP_ARGUMENTS / super::MAX_BOOTSTRAP_ARGUMENTS + 1;
    let mut body = Vec::new();
    u16_bytes(&mut body, count as u16);
    for _ in 0..count {
        u16_bytes(&mut body, fixture.source_map[handle]);
        u16_bytes(&mut body, super::MAX_BOOTSTRAP_ARGUMENTS as u16);
        for _ in 0..super::MAX_BOOTSTRAP_ARGUMENTS {
            u16_bytes(&mut body, fixture.source_map[OBJECT_CLASS]);
        }
    }
    total.class_attributes[0].1 = body;
    total.rebuild();
    assert!(matches!(
        parse_classfile(&total.recipe.input),
        Err(ClassfileError::Bounds(_))
    ));
}

#[test]
fn ordered_exception_handlers_retain_boundaries_and_catch_all() {
    let mut fixture = Fixture::integer();
    fixture.methods[1].handlers = vec![[0, 1, 4, 4], [1, 5, 0, 0]];
    fixture.rebuild();
    let parsed = parse_classfile(&fixture.recipe.input).unwrap();
    let code = parsed
        .selected_method("apply", "(I)I")
        .unwrap()
        .code
        .as_ref()
        .unwrap();
    assert_eq!(
        code.exception_handlers,
        vec![
            super::ExceptionHandler {
                start_pc: 0,
                end_pc: 1,
                handler_pc: 4,
                catch_type: 4
            },
            super::ExceptionHandler {
                start_pc: 1,
                end_pc: 5,
                handler_pc: 0,
                catch_type: 0
            },
        ]
    );
    assert_rejected(&fixture);
    for handler in [
        [2, 4, 4, 0],
        [0, 2, 4, 0],
        [0, 1, 2, 0],
        [0, 5, 5, 0],
        [0, 1, 4, 1],
    ] {
        let mut invalid = Fixture::integer();
        invalid.methods[1].handlers.push(handler);
        invalid.rebuild();
        assert!(parse_classfile(&invalid.recipe.input).is_err());
    }
    let mut too_many = Fixture::integer();
    too_many.methods[1]
        .handlers
        .resize(super::MAX_EXCEPTION_HANDLERS + 1, [0, 1, 4, 0]);
    too_many.rebuild();
    assert!(matches!(
        parse_classfile(&too_many.recipe.input),
        Err(ClassfileError::Bounds(_))
    ));
}

#[test]
fn exception_boundary_scan_handles_wide_switches_and_truncation_without_execution() {
    let cases = [
        vec![0xc4, 0x15, 0, 1, 0xb1],
        vec![0xc4, 0x84, 0, 1, 0, 1, 0xb1],
        vec![
            0xaa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0xb1,
        ],
        vec![
            0xab, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9, 0, 0, 0, 0, 0xb1,
        ],
    ];
    for code in cases {
        let mut fixture = Fixture::integer();
        let last = (code.len() - 1) as u16;
        fixture.methods[1].instructions = Some(vec![bytes(&code)]);
        fixture.methods[1].handlers = vec![[0, last, last, 0]];
        fixture.rebuild();
        assert!(parse_classfile(&fixture.recipe.input).is_ok());
        fixture.methods[1].handlers = vec![[0, 1, last, 0]];
        fixture.rebuild();
        assert!(parse_classfile(&fixture.recipe.input).is_err());
    }
    for code in [
        vec![0xc4, 0xb1],
        vec![0x11, 0],
        vec![0xba, 0, 1, 0],
        vec![0xaa],
        vec![0xca],
    ] {
        let mut fixture = Fixture::integer();
        fixture.methods[1].instructions = Some(vec![bytes(&code)]);
        fixture.methods[1].handlers = vec![[0, code.len() as u16, 0, 0]];
        fixture.rebuild();
        assert!(parse_classfile(&fixture.recipe.input).is_err());
    }
}

fn plain_text_fixture() -> Fixture {
    let (mut fixture, _, _, _) = bootstrap_fixture();
    fixture.pool[SELF_NAME] =
        PoolEntry::Utf8(b"net/minecraft/commands/functions/PlainTextFunction".to_vec());
    fixture.pool[SAM_NAME] = PoolEntry::Utf8(b"instantiate".to_vec());
    fixture.pool[SAM_DESCRIPTOR] = PoolEntry::Utf8(b"(Lnet/minecraft/nbt/CompoundTag;Lcom/mojang/brigadier/CommandDispatcher;)Lnet/minecraft/commands/functions/InstantiatedFunction;".to_vec());
    fixture.methods[1].access = 0x0001;
    fixture.methods[1].instructions = Some(vec![bytes(&[0x2a, 0xb0])]);
    fixture.rebuild();
    fixture
}

fn append_method_attribute(fixture: &mut Fixture, method: usize, name: usize, body: &[u8]) {
    let length_offset = fixture.attribute_length_offsets[method];
    let count_offset = length_offset - 4;
    let count = u16::from_be_bytes(
        fixture.recipe.input[count_offset..count_offset + 2]
            .try_into()
            .unwrap(),
    );
    let code_length = u32::from_be_bytes(
        fixture.recipe.input[length_offset..length_offset + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let end = length_offset + 4 + code_length;
    fixture.recipe.input[count_offset..count_offset + 2]
        .copy_from_slice(&(count + 1).to_be_bytes());
    let mut attribute = Vec::new();
    u16_bytes(&mut attribute, fixture.source_map[name]);
    u32_bytes(&mut attribute, body.len() as u32);
    attribute.extend_from_slice(body);
    fixture.recipe.input.splice(end..end, attribute);
}

#[test]
fn selected_plain_text_body_matches_both_sources_with_unrelated_dynamic_metadata() {
    let fixture = plain_text_fixture();
    let matched =
        super::match_plain_text_instantiate(&fixture.recipe.input, &fixture.snapshot).unwrap();
    assert_eq!(
        matched.method().owner(),
        "net/minecraft/commands/functions/PlainTextFunction"
    );
    assert_eq!(matched.method().name(), "instantiate");
    assert_eq!(
        matched.method().descriptor(),
        "(Lnet/minecraft/nbt/CompoundTag;Lcom/mojang/brigadier/CommandDispatcher;)Lnet/minecraft/commands/functions/InstantiatedFunction;"
    );
    assert!(!matched.method().is_interface());
}

#[test]
fn plain_text_body_rejects_effects_handlers_modifiers_and_snapshot_mismatch() {
    let fixture = plain_text_fixture();
    for flags in [0, 0x0009, 0x0011, 0x0021, 0x0041, 0x0101, 0x0401, 0x1001] {
        let mut invalid = fixture.clone_for_metadata();
        invalid.methods[1].access = flags;
        if flags & (0x0100 | 0x0400) != 0 {
            invalid.methods[1].instructions = None;
        }
        invalid.rebuild();
        assert!(
            super::match_plain_text_instantiate(&invalid.recipe.input, &invalid.snapshot).is_err()
        );
    }
    for instructions in [
        vec![0x2a, 0x00, 0xb0],
        vec![0x01, 0xb0],
        vec![0x2b, 0xb0],
        vec![0xb1],
    ] {
        let mut invalid = fixture.clone_for_metadata();
        invalid.methods[1].instructions = Some(vec![bytes(&instructions)]);
        invalid.rebuild();
        assert!(
            super::match_plain_text_instantiate(&invalid.recipe.input, &invalid.snapshot).is_err()
        );
    }
    let mut handler = fixture.clone_for_metadata();
    handler.methods[1].handlers = vec![[0, 1, 1, 0]];
    handler.rebuild();
    assert!(super::match_plain_text_instantiate(&handler.recipe.input, &handler.snapshot).is_err());
    let mut changed = plain_text_fixture();
    changed.snapshot.methods[1].code = MethodCode::Bytecodes(vec![0x01, 0xb0]);
    assert!(super::match_plain_text_instantiate(&changed.recipe.input, &changed.snapshot).is_err());
    let mut duplicate = plain_text_fixture();
    duplicate
        .snapshot
        .methods
        .push(duplicate.snapshot.methods[1].clone());
    assert!(
        super::match_plain_text_instantiate(&duplicate.recipe.input, &duplicate.snapshot).is_err()
    );
    let mut wrong_descriptor = fixture.clone_for_metadata();
    wrong_descriptor.pool[SAM_DESCRIPTOR] = PoolEntry::Utf8(b"()Ljava/lang/Object;".to_vec());
    wrong_descriptor.rebuild();
    assert!(
        super::match_plain_text_instantiate(
            &wrong_descriptor.recipe.input,
            &wrong_descriptor.snapshot
        )
        .is_err()
    );
    let mut other_owner = fixture.clone_for_metadata();
    other_owner.pool[SELF_NAME] = PoolEntry::Utf8(b"fixtures/OtherPlain".to_vec());
    other_owner.rebuild();
    assert!(
        super::match_plain_text_instantiate(&other_owner.recipe.input, &other_owner.snapshot)
            .is_err()
    );
}

#[test]
fn plain_text_declared_throws_and_signature_are_passive_but_unknown_attributes_are_not() {
    let mut fixture = plain_text_fixture();
    let exceptions = fixture.pool.len();
    fixture.pool.push(PoolEntry::Utf8(b"Exceptions".to_vec()));
    let signature = fixture.pool.len();
    fixture.pool.push(PoolEntry::Utf8(b"Signature".to_vec()));
    fixture.rebuild();
    let mut body = Vec::new();
    u16_bytes(&mut body, 1);
    u16_bytes(&mut body, fixture.source_map[OBJECT_CLASS]);
    append_method_attribute(&mut fixture, 1, exceptions, &body);
    let signature_body = fixture.source_map[SAM_DESCRIPTOR].to_be_bytes();
    append_method_attribute(&mut fixture, 1, signature, &signature_body);
    assert!(super::match_plain_text_instantiate(&fixture.recipe.input, &fixture.snapshot).is_ok());
    append_method_attribute(&mut fixture, 1, signature, &signature_body);
    assert!(super::match_plain_text_instantiate(&fixture.recipe.input, &fixture.snapshot).is_err());
    let mut unknown = plain_text_fixture();
    append_method_attribute(&mut unknown, 1, SAM_NAME, &[]);
    assert!(super::match_plain_text_instantiate(&unknown.recipe.input, &unknown.snapshot).is_err());
}
