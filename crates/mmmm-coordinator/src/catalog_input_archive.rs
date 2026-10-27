//! 승인된 selected input의 ordinary archive 사실만 보존한다. 완료 inventory는
//! runtime pack view·loaded definition·SourceAdmission 또는 읽기 grant가 아니다.
//! 원문은 immutable CAS에 나누어 보존하고 registry에는 작은 참조만 둔다.

use super::*;
use crate::native_catalog::NativeInputArchivePins;
use mmmm_reference::input_archive::{
    InputArchiveInventory, InputArchiveLimits, InputArchiveMemberKind, inventory_input_archive,
};
use mmmm_runtime::storage::catalog_source_use::PinnedCatalogSourceUse;
use std::{error::Error, fmt};

const PAGE_BYTES: usize = 256 * 1024;
const PAGE_ENTRIES: usize = 1024;
const ENCODED_BYTES: usize = 16 * 1024 * 1024;
const REGISTRY_BYTES: usize = 1024 * 1024;
const MEDIA: &str = "application/vnd.mmmm.input-archive-facts+json";

/// 기존 native publication의 exact owner와 연결된 사실 cache다. raw owner나
/// request witness, archive bytes, member 목록은 장기 보관하지 않는다.
pub(super) struct RetainedInputInventories {
    publication: NativeCatalogPublication,
    provenance: Value,
    summaries: Vec<Value>,
}
impl RetainedInputInventories {
    pub(super) fn owned_by(&self, publication: &NativeCatalogPublication) -> bool {
        self.publication.same_issuance(publication)
    }
    #[cfg(test)]
    pub(super) fn summaries(&self) -> &[Value] {
        &self.summaries
    }
}

struct WorkBudget {
    input: u64,
    decoded: u64,
    entries: usize,
    encoded: usize,
    reserved_manifests: usize,
}
struct ManifestReservation {
    encoded_bytes: usize,
}
impl WorkBudget {
    fn new(inputs: usize) -> AppResult<Self> {
        if inputs > MAX_SOURCES {
            return Err(work_limit());
        }
        Ok(Self {
            input: MAX_SOURCE_BYTES,
            decoded: 256 * 1024 * 1024,
            entries: 65_535,
            encoded: 0,
            reserved_manifests: 0,
        })
    }
    fn charge_input(&mut self, length: u64) -> AppResult<()> {
        self.input = self.input.checked_sub(length).ok_or_else(work_limit)?;
        Ok(())
    }
    fn reserve_parse(&mut self) -> AppResult<InputArchiveLimits> {
        if self.decoded == 0 || self.entries == 0 {
            return Err(work_limit());
        }
        let limits = InputArchiveLimits {
            total_bytes: self.decoded,
            member_bytes: self.decoded.min(64 * 1024 * 1024),
            entries: self.entries,
            ..InputArchiveLimits::default()
        };
        // 오류 API에는 중간 작업량이 없다. 실패 때 제공한 전체 allowance를
        // 소비한 것으로 남겨 다수 rejected archive의 재시도로 증폭하지 않는다.
        self.decoded = 0;
        self.entries = 0;
        Ok(limits)
    }
    fn refund_parse(
        &mut self,
        limits: InputArchiveLimits,
        inventory: &InputArchiveInventory,
    ) -> AppResult<()> {
        self.decoded = limits
            .total_bytes
            .checked_sub(inventory.decoded_bytes())
            .ok_or_else(work_limit)?;
        self.entries = limits
            .entries
            .checked_sub(inventory.members().len())
            .ok_or_else(work_limit)?;
        Ok(())
    }
    fn charge_encoded(&mut self, bytes: usize) -> AppResult<()> {
        let next = self.encoded.checked_add(bytes).ok_or_else(encode_limit)?;
        if next
            .checked_add(self.reserved_manifests)
            .is_none_or(|total| total > ENCODED_BYTES)
        {
            return Err(encode_limit());
        }
        self.encoded = next;
        Ok(())
    }
    fn reserve_manifest(&mut self, manifest: &Value) -> AppResult<ManifestReservation> {
        let encoded_bytes = encode_json(manifest).map_err(json_error)?.len();
        if encoded_bytes > PAGE_BYTES {
            return Err(encode_limit());
        }
        let reserved = self
            .reserved_manifests
            .checked_add(encoded_bytes)
            .ok_or_else(encode_limit)?;
        if self
            .encoded
            .checked_add(reserved)
            .is_none_or(|total| total > ENCODED_BYTES)
        {
            return Err(encode_limit());
        }
        self.reserved_manifests = reserved;
        Ok(ManifestReservation { encoded_bytes })
    }
    fn finish_input(&mut self, reservation: ManifestReservation) -> AppResult<()> {
        self.reserved_manifests = self
            .reserved_manifests
            .checked_sub(reservation.encoded_bytes)
            .ok_or_else(work_limit)?;
        Ok(())
    }
}

pub(super) fn retain_selected_inputs(
    call: &CatalogCall,
    slot: &RequestContextSlot,
    store: &PlanningStore<'_>,
) -> AppResult<()> {
    let context = &call.installed.registration.context;
    let admission = NativeCatalogAdmission {
        request: slot,
        authority: &call.sources.authority,
        hosts: &call.sources.hosts,
        sources: &call.sources,
    };
    let Some(pins) = store.with_read(|store| {
        admission.selected_input_archive_pins(&call.authenticated, context, store, &call.budget)
    })?
    else {
        return Ok(());
    };
    if pins.selected.selections().is_empty() {
        return Ok(());
    }
    let result = retain_batch(call, &admission, &pins, store);
    // 마지막 host I/O가 실패한 경우에도 원래 source/Store/Policy 후검사를 한다.
    // 취소된 budget을 연장하지 않고, 실패한 현재 호출의 새 cache는 게시하지 않는다.
    let fresh = call.fresh();
    let current = store.with_read(|store| {
        let current = admission
            .selected_input_archive_pins(&call.authenticated, context, store, &call.budget)?
            .ok_or_else(forbidden)?;
        if !current.publication.same_issuance(&pins.publication)
            || current.selected != pins.selected
            || current.policy != pins.policy
            || current.revision != pins.revision
        {
            return Err(forbidden());
        }
        Ok(())
    });
    let retained = finish(result, finish(fresh, current))?;
    call.budget.check().map_err(budget_error)?;
    call.local()?;
    let cost = registry_cost(&call.installed, &retained)?;
    if cost > REGISTRY_BYTES {
        return Err(encode_limit());
    }
    let mut state = call.sources.state.try_borrow_mut().map_err(|_| busy())?;
    let key = &pins.publication.key;
    if !call.authenticated.is_current()
        || state
            .environments
            .get(key)
            .is_none_or(|installed| installed.revision != call.installed.revision)
        || state
            .native_publishers
            .get(key)
            .is_none_or(|origin| !Rc::ptr_eq(&origin.receipt, &pins.publication.receipt))
    {
        return Err(forbidden());
    }
    call.budget.check().map_err(budget_error)?;
    state.input_archives.insert(key.clone(), retained);
    Ok(())
}

fn retain_batch(
    call: &CatalogCall,
    admission: &NativeCatalogAdmission<'_>,
    pins: &NativeInputArchivePins,
    store: &PlanningStore<'_>,
) -> AppResult<RetainedInputInventories> {
    let mut work = WorkBudget::new(pins.selected.selections().len())?;
    let provenance = json!({"format":"mmmm.selected-input-archive-provenance/1",
        "principal":call.authenticated.principal(), "projectId":call.installed.project,
        "contextDigest":call.installed.registration.context["contextDigest"],
        "sourceBindingRevision":call.installed.revision, "currentProjectRevision":pins.revision,
        "readPolicy":pins.policy, "sourceUse":pins.selected,
        "sourceUsePin":pins.publication.source_use(), "readPolicyPin":pins.publication.read_policy(),
        "producer":producer(), "consumer":consumer(), "scope":"selected_input_container_bytes"});
    let provenance = persist(call, store, &mut work, &provenance, PAGE_BYTES)?;
    // 모든 입력의 실제 fallback을 먼저 인코딩한다. canonical mod ID에 별도
    // 길이 상한을 추가하지 않고도 남은 각 입력의 거절 기록 공간을 보장한다.
    let mut reservations = Vec::new();
    for selected in pins.selected.selections() {
        check(call)?;
        reservations.push(work.reserve_manifest(&rejection_manifest(selected, &provenance))?);
    }
    let mut summaries = Vec::new();
    for (index, (selected, reservation)) in pins
        .selected
        .selections()
        .iter()
        .zip(reservations)
        .enumerate()
    {
        check(call)?;
        let (manifest, summary) = retain_input(
            call,
            admission,
            pins,
            index,
            selected,
            store,
            &provenance,
            &mut work,
            reservation,
        )?;
        summaries.push(
            json!({"selection":selected.selection(), "input":selected.resource(),
            "manifest":manifest, "inventory":summary}),
        );
        // summary만 남고 이 입력의 raw bytes/member Vec/page buffers는 해제됐다.
    }
    Ok(RetainedInputInventories {
        publication: pins.publication.clone(),
        provenance,
        summaries,
    })
}

#[allow(clippy::too_many_arguments)]
fn retain_input(
    call: &CatalogCall,
    admission: &NativeCatalogAdmission<'_>,
    pins: &NativeInputArchivePins,
    index: usize,
    selected: &PinnedCatalogSourceUse,
    store: &PlanningStore<'_>,
    provenance: &Value,
    work: &mut WorkBudget,
    reservation: ManifestReservation,
) -> AppResult<(Value, Value)> {
    let mut pages = Vec::new();
    let mut status =
        json!({"status":"rejected","complete":false,"code":"INPUT_ARCHIVE_AGGREGATE_LIMIT"});
    let mut limits = None;
    if work.charge_input(selected.blob().byte_length).is_ok()
        && let Ok(offered) = work.reserve_parse()
    {
        limits = Some(limits_value(offered));
        let bytes = store.with_read(|store| {
            admission.read_selected_input_archive(
                &call.authenticated,
                &call.installed.registration.context,
                store,
                &call.budget,
                pins,
                index,
            )
        })?;
        let control = CaptureControl {
            cancellation: call.budget.cancellation(),
            deadline: call.budget.deadline(),
        };
        match inventory_input_archive(&bytes, offered, &control) {
            Ok(inventory) => {
                if !inventory.complete()
                    || inventory.input_byte_length() != selected.blob().byte_length
                    || inventory.input_sha256() != &selected.blob().digest
                {
                    return Err(forbidden());
                }
                work.refund_parse(offered, &inventory)?;
                let encoded = member_pages(
                    &inventory,
                    provenance,
                    || check(call),
                    |page| persist(call, store, work, page, PAGE_BYTES),
                );
                match encoded {
                    Ok(retained) => {
                        pages = retained;
                        status = json!({"status":"complete","complete":true,
                            "decodedBytes":inventory.decoded_bytes(),"memberCount":inventory.members().len()});
                    }
                    Err(error) if error.code == "INPUT_ARCHIVE_ENCODE_LIMIT" => {
                        status["code"] = json!(error.code);
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) if matches!(error.code(), "CANCELLED" | "TIME_BUDGET_EXCEEDED") => {
                return Err(AppError::caused_by(
                    error.code(),
                    "원 요청이 입력 inventory 작업을 중단했습니다",
                    error,
                ));
            }
            Err(error) => {
                status["code"] = json!(error.code());
            }
        }
        drop(bytes);
    }
    check(call)?;
    work.finish_input(reservation)?;
    let manifest = input_manifest(selected, provenance, limits, &status, pages);
    let reference = match persist(call, store, work, &manifest, PAGE_BYTES) {
        Ok(reference) => reference,
        Err(error) if error.code == "INPUT_ARCHIVE_ENCODE_LIMIT" => {
            let fallback = rejection_manifest(selected, provenance);
            status = fallback["inventory"].clone();
            persist(call, store, work, &fallback, PAGE_BYTES)?
        }
        Err(error) => return Err(error),
    };
    Ok((reference, status))
}

fn input_manifest(
    selected: &PinnedCatalogSourceUse,
    provenance: &Value,
    limits: Option<Value>,
    status: &Value,
    pages: Vec<Value>,
) -> Value {
    json!({"format":"mmmm.selected-input-archive-inventory/1", "provenance":provenance,
        "selection":selected.selection(),"input":selected.resource(), "inputSha256":selected.blob().digest,
        "inputByteLength":selected.blob().byte_length,"producer":producer(),"consumer":consumer(),
        "limits":limits,"inventory":status,"memberPages":pages,"scope":"ordinary_input_archive"})
}

fn rejection_manifest(selected: &PinnedCatalogSourceUse, provenance: &Value) -> Value {
    // 인코딩 한도로 원문을 기록하지 못한 경우이므로 parse limits를 추정하지 않는다.
    input_manifest(
        selected,
        provenance,
        None,
        &json!({"status":"rejected","complete":false,"code":"INPUT_ARCHIVE_ENCODE_LIMIT"}),
        Vec::new(),
    )
}

/// 기존 JSON 제한보다 작은 page를 하나씩 전달한다. 원 central-directory 순서와
/// explicit Directory 구분을 유지하며 이름에서 Java class나 runtime 순서를 추정하지 않는다.
fn member_pages(
    inventory: &InputArchiveInventory,
    provenance: &Value,
    mut check: impl FnMut() -> AppResult<()>,
    mut emit: impl FnMut(&Value) -> AppResult<Value>,
) -> AppResult<Vec<Value>> {
    let mut references = Vec::new();
    let mut members = Vec::new();
    let mut bytes = page_base(inventory, provenance, 0, Vec::new());
    let mut used = encode_json(&bytes).map_err(json_error)?.len();
    for member in inventory.members() {
        check()?;
        let value = json!({"name":member.name(),"kind":match member.kind() {
            InputArchiveMemberKind::File => "file", InputArchiveMemberKind::Directory => "directory" },
            "byteLength":member.byte_length(),"sha256":member.sha256()});
        let length =
            encode_json(&value).map_err(json_error)?.len() + usize::from(!members.is_empty());
        if !members.is_empty() && (members.len() == PAGE_ENTRIES || used + length > PAGE_BYTES) {
            bytes = page_base(
                inventory,
                provenance,
                references.len(),
                std::mem::take(&mut members),
            );
            references.push(emit(&bytes)?);
            check()?;
            used = encode_json(&page_base(
                inventory,
                provenance,
                references.len(),
                Vec::new(),
            ))
            .map_err(json_error)?
            .len();
        }
        if used
            .checked_add(length)
            .is_none_or(|total| total > PAGE_BYTES)
        {
            return Err(encode_limit());
        }
        used += length;
        members.push(value);
    }
    if !members.is_empty() {
        bytes = page_base(inventory, provenance, references.len(), members);
        references.push(emit(&bytes)?);
    }
    check()?;
    Ok(references)
}
fn page_base(
    inventory: &InputArchiveInventory,
    provenance: &Value,
    index: usize,
    members: Vec<Value>,
) -> Value {
    json!({"format":"mmmm.input-archive-members/1","inputSha256":inventory.input_sha256(),
        "provenance":provenance,"pageIndex":index,"members":members})
}

fn persist(
    call: &CatalogCall,
    store: &PlanningStore<'_>,
    work: &mut WorkBudget,
    value: &Value,
    max: usize,
) -> AppResult<Value> {
    check(call)?;
    let bytes = encode_json(value).map_err(json_error)?;
    if bytes.len() > max {
        return Err(encode_limit());
    }
    work.charge_encoded(bytes.len())?;
    let digest = raw_digest(&bytes);
    let identity = canonical_digest(&json!({"project":call.installed.project,"sha256":digest,
        "sizeBytes":bytes.len(),"mediaType":MEDIA}))
    .map_err(digest_error)?;
    let reference = json!({"resourceId":format!("catalog-input-inventory-{identity}"),
        "sha256":digest,"sizeBytes":bytes.len(),"mediaType":MEDIA});
    store.with_write(|store| {
        check(call)?;
        let blob = store.put_blob(&bytes).map_err(storage_app)?;
        if blob.digest != digest || blob.byte_length != bytes.len() as u64 {
            return Err(forbidden());
        }
        register_resource(
            store,
            &reference,
            ResourceOwner::Project(call.installed.project.clone()),
        )
        .map_err(|cause| AppError::caused_by(cause.code, cause.message, cause))?;
        check(call)
    })?;
    Ok(reference)
}
fn registry_cost(
    installed: &InstalledEnvironment,
    retained: &RetainedInputInventories,
) -> AppResult<usize> {
    let mut source_bytes = 0usize;
    for source in installed.sources.values() {
        source_bytes = source_bytes
            .checked_add(
                encode_json(&source.approved.source)
                    .map_err(json_error)?
                    .len(),
            )
            .ok_or_else(encode_limit)?;
    }
    let provenance = json!({"resource":retained.provenance,"bindingRevision":retained.publication.revision,
        "sourceUsePin":retained.publication.source_use(),"readPolicyPin":retained.publication.read_policy(),
        "principal":retained.publication.key.0,"contextId":retained.publication.key.1});
    registry_values_cost(source_bytes, &provenance, &retained.summaries)
}
fn registry_values_cost(
    source_bytes: usize,
    provenance: &Value,
    summaries: &[Value],
) -> AppResult<usize> {
    let total = source_bytes
        .checked_add(
            encode_json(&json!({"provenance":provenance,"inputs":summaries}))
                .map_err(json_error)?
                .len(),
        )
        .ok_or_else(encode_limit)?;
    if total > REGISTRY_BYTES {
        return Err(encode_limit());
    }
    Ok(total)
}
fn limits_value(limits: InputArchiveLimits) -> Value {
    json!({"inputBytes":limits.input_bytes,"memberBytes":limits.member_bytes,"totalBytes":limits.total_bytes,
        "entries":limits.entries,"ratio":limits.ratio,"metadataBytes":limits.metadata_bytes,"nameBytes":limits.name_bytes})
}
fn producer() -> Sha256Digest {
    raw_digest(include_bytes!("../../mmmm-reference/src/input_archive.rs"))
}
fn consumer() -> Sha256Digest {
    raw_digest(include_bytes!("catalog_input_archive.rs"))
}
fn check(call: &CatalogCall) -> AppResult<()> {
    call.budget.check().map_err(budget_error)?;
    call.local()
}
fn budget_error(error: ServiceError) -> AppError {
    AppError::caused_by(error.code, error.message, error)
}
fn json_error(error: impl Error + Send + Sync + 'static) -> AppError {
    AppError::caused_by(
        "INPUT_ARCHIVE_ENCODE_LIMIT",
        "입력 inventory 원문을 기존 JSON 한도 안에 기록할 수 없습니다",
        error,
    )
}
fn digest_error(error: impl Error + Send + Sync + 'static) -> AppError {
    AppError::caused_by(
        "INPUT_ARCHIVE_DIGEST",
        "입력 inventory 사실의 digest를 계산할 수 없습니다",
        error,
    )
}
fn work_limit() -> AppError {
    AppError::new(
        "INPUT_ARCHIVE_AGGREGATE_LIMIT",
        "원 요청 전체의 inventory 작업 한도를 소진했습니다",
    )
}
fn encode_limit() -> AppError {
    AppError::new(
        "INPUT_ARCHIVE_ENCODE_LIMIT",
        "입력 inventory의 원문 또는 registry 한도를 소진했습니다",
    )
}
#[derive(Debug)]
struct InventoryBoundaryFailure {
    primary: AppError,
    checkpoint: AppError,
}
impl fmt::Display for InventoryBoundaryFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.checkpoint;
        f.write_str("입력 inventory 실패와 후속 현재성 실패를 함께 보존합니다")
    }
}
impl Error for InventoryBoundaryFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}
fn finish<T>(result: AppResult<T>, checked: AppResult<()>) -> AppResult<T> {
    match (result, checked) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(checkpoint)) => Err(AppError::caused_by(
            primary.code,
            primary.message,
            InventoryBoundaryFailure {
                primary,
                checkpoint,
            },
        )),
    }
}

#[cfg(test)]
#[path = "catalog_input_archive_tests.rs"]
mod tests;
