use crate::communication::structs::Notification;

#[derive(Debug, Clone)]
pub struct NotifyNode {
    pub buff: Vec<u8>,
    pub notification: Notification,
}

impl NotifyNode {
    pub fn new(buff: Vec<u8>, variant: Notification) -> NotifyNode {
        NotifyNode {
            buff,
            notification: variant, // Replace with your actual variant
        }
    }
}
