/**
 * Standards metadata used by the CDC Messaging Analyzer so it can
 * interpret CDC/LAES logs against ANSI T1.678 and 3GPP IMS signaling.
 */

const CDC_STANDARDS = {
    T1_678: {
        name: 'ANSI T1.678 / LAES',
        description: 'Defines the CDC/LAES attempt, signaling, and release message model (caseId/callId plus calling/called context) used in lawful interception data.',
        messageTypes: [
            {
                id: 'termAttempt',
                displayName: 'Terminating Attempt',
                keywords: ['termattempt', 'terminating attempt', 'targetattempt', 'ims_3gpp_voip_termattempt'],
                description: 'Incoming call attempts from the target (called) device; contains caseId, callId, calling/called URIs, and optional SDPs.'
            },
            {
                id: 'origAttempt',
                displayName: 'Originating Attempt',
                keywords: ['origattempt', 'originating attempt', 'ims_3gpp_voip_origination'],
                description: 'Outgoing call attempts from the target device including calling/called URIs and headers.'
            },
            {
                id: 'answer',
                displayName: 'Answer Notification',
                keywords: ['answer', 'ims_3gpp_voip_answer'],
                description: 'Indicates the call has been answered; often linked with location references for the target device.'
            },
            {
                id: 'release',
                displayName: 'Release Notification',
                keywords: ['release', 'ims_3gpp_voip_release'],
                description: 'Call teardown record recording signaling cause and final locations.'
            },
            {
                id: 'directSignalReporting',
                displayName: 'Direct Signal Reporting',
                keywords: ['directsignalreporting', 'ims_3gpp_voip_directsignalreporting'],
                description: 'Carries SIP/SDP bodies, headers (P-Asserted-Identity, User-Agent, P-Access-Network-Info) and can include PANI-encoded tower info.'
            },
            {
                id: 'ccOpen',
                displayName: 'Media Channel Open',
                keywords: ['ccopen', 'ims_3gpp_voip_ccopen'],
                description: 'Indicates the carrier opened a content channel (media) for the call.'
            },
            {
                id: 'ccClose',
                displayName: 'Media Channel Close',
                keywords: ['ccclose', 'ims_3gpp_voip_ccclose'],
                description: 'Indicates the carrier closed the content channel at call end.'
            },
            {
                id: 'smsMessage',
                displayName: 'SMS / MMS Message',
                keywords: ['smsmessage', 'mmsmessage', 'ims_3gpp_voip_message'],
                description: 'Contains SMS/MMS metadata (originator, recipient, userInput) reported via the T1.678 model.'
            }
        ],
        commonFieldAliases: {
            callId: ['callId', 'callID', 'callIdentifier', 'contentIdentifier', 'call-ID', 'call id'],
            caseId: ['caseId', 'caseIdentifier', 'case-id'],
            timestamp: ['timestamp', 'eventTimestamp', 'timeStamp', 'time'],
            correlationID: ['correlationID', 'correlationId', 'correlation-id']
        }
    },
    IMS: {
        name: '3GPP IMS Signaling (TS 24.229+)',
        description: 'IMS/SIP call state events (Origination, Answer, Release, CCOpen/CCClose, Direct Signal Reporting) with headers defined by TS 24.229 and related releases.',
        eventTypes: [
            {
                id: 'origAttempt',
                displayName: 'IMS Origination',
                keywords: ['ims_3gpp_voip_origination', 'ims voip origination'],
                description: 'IMS origin attempt recorded by the carrier.'
            },
            {
                id: 'termAttempt',
                displayName: 'IMS Terminating Attempt',
                keywords: ['ims_3gpp_voip_termattempt', 'ims voip terminating attempt'],
                description: 'IMS terminating attempt event aligned with TS 24.229 call state.'
            },
            {
                id: 'answer',
                displayName: 'IMS Answer',
                keywords: ['ims_3gpp_voip_answer'],
                description: 'IMS answer event for call establishment.'
            },
            {
                id: 'release',
                displayName: 'IMS Release',
                keywords: ['ims_3gpp_voip_release'],
                description: 'IMS release event for call teardown.'
            },
            {
                id: 'directSignalReporting',
                displayName: 'IMS Direct Signal Reporting',
                keywords: ['ims_3gpp_voip_directsignalreporting'],
                description: 'Carries SIP request/response bodies captured during the call.'
            },
            {
                id: 'ccOpen',
                displayName: 'IMS Media Open',
                keywords: ['ims_3gpp_voip_ccopen', 'ims media open'],
                description: 'Carrier-level signal that the media channel is open, analogous to T1.678 ccOpen.'
            },
            {
                id: 'ccClose',
                displayName: 'IMS Media Close',
                keywords: ['ims_3gpp_voip_ccclose', 'ims media close'],
                description: 'Carrier-level signal that the media channel is closed.'
            }
        ],
        commonFieldAliases: {
            userAgent: ['User-Agent', 'useragent', 'userAgent'],
            networkInfo: ['p-access-network-info', 'P-Access-Network-Info']
        }
    }
};

CDC_STANDARDS.ALL_MESSAGE_TYPES = [
    ...(CDC_STANDARDS.T1_678?.messageTypes ?? []),
    ...(CDC_STANDARDS.IMS?.eventTypes ?? [])
];

CDC_STANDARDS.ALL_FIELD_ALIASES = {
    ...(CDC_STANDARDS.T1_678?.commonFieldAliases ?? {}),
    ...(CDC_STANDARDS.IMS?.commonFieldAliases ?? {})
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = CDC_STANDARDS;
}
