/// Parameters for uprobe attachment
#[derive(Debug, Clone)]
pub(crate) struct UprobeAttachmentParams {
    pub target_binary: String,
    pub function_name: String,
    pub offset: Option<u64>,
    pub pid: Option<i32>,
    pub program_name: String,
}
