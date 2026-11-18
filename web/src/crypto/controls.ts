// The control values a payload's `ctl` field takes (spec section 4).

/** Binds a live connection to a thread, carries no message. */
export const CTL_PRESENCE = 1
/** Delete the message `replyTo` names, or with no `replyTo` the whole thread, on the other side. */
export const CTL_DELETE = 2
/** The drop `replyTo` names reached the owner. */
export const CTL_ACK = 3
/** The owner verified this sender: `creds[0]` is the credential, or absent when withdrawn. */
export const CTL_VERIFIED = 4
