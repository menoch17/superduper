/**
 * CDC Analyzer Constants & Metadata
 * Contains lookups for Carriers, SIP codes, and Investigative metadata
 */

const CDC_CONSTANTS = {
    // MCC/MNC Carrier Map
    CARRIERS: {
        '310': {
            '012': 'Verizon Wireless',
            '020': 'T-Mobile',
            '120': 'Sprint',
            '260': 'T-Mobile',
            '410': 'AT&T',
            '880': 'T-Mobile'
        },
        '311': {
            '180': 'Verizon Wireless',
            '480': 'Verizon Wireless',
            '490': 'T-Mobile',
            '660': 'Metro by T-Mobile'
        }
    },

    // SIP Status Codes
    SIP_CODES: {
        100: "Trying - Searching for the user",
        180: "Ringing - The destination is alerting",
        183: "Session Progress - Early media / customized ringback",
        200: "OK - Request successful",
        202: "Accepted - Typically used for Refer",
        400: "Bad Request",
        401: "Unauthorized - Authentication required",
        403: "Forbidden - Server understood but refuses",
        404: "Not Found - User does not exist",
        480: "Temporarily Unavailable",
        486: "Busy Here - User is on another call",
        487: "Request Terminated - Caller canceled",
        500: "Server Internal Error",
        603: "Decline - User declined the call"
    },

    // STIR/SHAKEN Attestation Levels
    ATTESTATION: {
        'A': 'Full Attestation - Carrier verified caller identity and number',
        'B': 'Partial Attestation - Carrier verified caller but not the number source',
        'C': 'Gateway Attestation - Call entered the network without verification'
    },

    // Get Carrier Name by MCC and MNC
    getCarrier(mcc, mnc) {
        if (!mcc || !mnc) return 'Unknown Carrier';
        // Normalize MNC to 3 digits if needed
        const paddedMnc = mnc.padStart(3, '0');
        const carrier = this.CARRIERS[mcc]?.[mnc] || this.CARRIERS[mcc]?.[paddedMnc];
        return carrier || `Unknown (${mcc}-${mnc})`;
    },

    // Get SIP Status Description
    getSipStatus(code) {
        return this.SIP_CODES[code] || `Status Code ${code}`;
    }
};

if (typeof module !== 'undefined' && module.exports) {
    module.exports = CDC_CONSTANTS;
}
