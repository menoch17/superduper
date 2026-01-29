// CDC Parser and Analyzer
class CDCAnalyzer {
    constructor(rawData) {
        this.rawData = rawData;
        this.messages = [];
        this.calls = new Map(); // Grouped by callId
        this.currentCallId = null;
    }

    parse() {
        const messageBlocks = this.splitIntoMessages(this.rawData);

        for (const block of messageBlocks) {
            const parsed = this.parseMessageBlock(block);
            if (parsed) {
                this.messages.push(parsed);

                // Group by callId
                const callId = parsed.callId || 'Global-Events';
                if (!this.calls.has(callId)) {
                    this.calls.set(callId, this.createCallObject(callId));
                }
                const call = this.calls.get(callId);
                call.messages.push(parsed);
                this.extractCallInfo(parsed, call);
            }
        }

        // Post-process each call
        for (const [id, call] of this.calls) {
            if (call.answerTime && call.endTime) {
                const start = this.parseTimestamp(call.answerTime);
                const end = this.parseTimestamp(call.endTime);
                if (start && end) {
                    call.duration = Math.round((end - start) / 1000);
                }
            }

            // Sort messages by timestamp
            call.messages.sort((a, b) => {
                const timeA = this.parseTimestamp(a.timestamp);
                const timeB = this.parseTimestamp(b.timestamp);
                return (timeA || 0) - (timeB || 0);
            });

            // Finalize status
            if (!call.callStatus) {
                if (call.endTime) call.callStatus = 'Ended';
                else if (call.startTime) call.callStatus = 'Initiated';
            }
        }

        return this;
    }

    createCallObject(callId) {
        return {
            callId: callId,
            caseId: null,
            messages: [],
            callingParty: {},
            calledParty: {},
            callerName: null,
            startTime: null,
            answerTime: null,
            endTime: null,
            duration: null,
            callType: 'Voice Call',
            callDirection: null,
            deviceInfo: {},
            locations: [],
            codecs: [],
            sipMessages: [],
            callStatus: null,
            releaseReason: null,
            verificationStatus: null,
            smsData: []
        };
    }

    splitIntoMessages(data) {
        const blocks = [];
        const lines = data.split('\n');
        let currentBlock = [];

        for (const line of lines) {
            const trimmed = line.trim();
            // Detect start of a new record (Type followed by Version)
            const isNewHeader = /^[A-Za-z].*Version \d/.test(trimmed);

            if (isNewHeader && currentBlock.length > 0) {
                blocks.push(currentBlock.join('\n'));
                currentBlock = [line];
            } else {
                currentBlock.push(line);
            }
        }

        if (currentBlock.length > 0) {
            blocks.push(currentBlock.join('\n'));
        }

        return blocks;
    }

    parseMessageBlock(block) {
        const result = {
            rawBlock: block,
            type: null,
            timestamp: null,
            caseId: null,
            callId: null,
            data: {}
        };

        if (block.includes('termAttempt') && !block.includes('ims_3GPP')) result.type = 'termAttempt';
        else if (block.includes('origAttempt') && !block.includes('ims_3GPP')) result.type = 'origAttempt';
        else if (block.includes('ims_3GPP_VoIP_origination')) result.type = 'origAttempt';
        else if (block.includes('ims_3GPP_VoIP_answer') || (block.includes('answer') && block.includes('answering'))) result.type = 'answer';
        else if (block.includes('ims_3GPP_VoIP_release') || (block.includes('release') && block.includes('cause'))) result.type = 'release';
        else if (block.includes('ims_3GPP_VoIP_directSignalReporting') || block.includes('directSignalReporting')) result.type = 'directSignalReporting';
        else if (block.includes('ims_3GPP_VoIP_subjectSignal') || block.includes('subjectSignal')) result.type = 'subjectSignal';
        else if (block.includes('ims_3GPP_VoIP_ccOpen') || block.includes('ccOpen')) result.type = 'ccOpen';
        else if (block.includes('ims_3GPP_VoIP_ccClose') || block.includes('ccClose')) result.type = 'ccClose';
        else if (block.includes('smsMessage')) result.type = 'smsMessage';
        else if (block.includes('mmsMessage')) result.type = 'mmsMessage';

        result.caseId = this.extractField(block, 'caseId');
        result.timestamp = this.extractField(block, 'timestamp');
        result.callId = this.extractNestedField(block, 'callId', 'main') ||
            this.extractNestedField(block, 'contentIdentifier', 'main') ||
            this.extractField(block, 'callId');

        switch (result.type) {
            case 'termAttempt':
            case 'origAttempt':
                result.data = this.parseAttemptMessage(block);
                break;
            case 'directSignalReporting':
            case 'subjectSignal':
                result.data = this.parseSIPMessage(block);
                if (!result.callId && result.data?.sipMessages?.length) {
                    const headers = result.data.sipMessages[0]?.parsed?.headers || {};
                    const sipCallId = this.getHeaderValue(headers, 'Call-ID');
                    if (sipCallId) result.callId = sipCallId;
                }
                break;
            case 'ccOpen':
            case 'ccClose':
                result.data = this.parseCCMessage(block);
                break;
            case 'answer':
                result.data = this.parseAnswerMessage(block);
                break;
            case 'release':
                result.data = this.parseReleaseMessage(block);
                break;
            case 'smsMessage':
            case 'mmsMessage':
                result.data = this.parseSMSMessage(block);
                break;
        }

        return result;
    }

    extractField(block, fieldName) {
        const regex = new RegExp(`${fieldName}\\s*=\\s*(.+?)(?:\\n|$)`, 'i');
        const match = block.match(regex);
        return match ? decodePossibleHex(match[1].trim()) : null;
    }

    extractNestedField(block, parentField, childField) {
        const regex = new RegExp(`${parentField}[\\s\\S]*?${childField}\\s*=\\s*(.+?)(?:\\n|$)`, 'i');
        const match = block.match(regex);
        return match ? decodePossibleHex(match[1].trim()) : null;
    }

    parseAttemptMessage(block) {
        const data = { calling: {}, called: {}, sdp: null, location: [] };
        const callingSection = block.match(/calling\s*\n([\s\S]*?)(?=called|$)/i);
        if (callingSection) {
            const uriMatch = callingSection[1].match(/uri\[0\]\s*=\s*(.+)/i);
            if (uriMatch) data.calling.uri = uriMatch[1].trim();
            const phoneMatch = data.calling.uri?.match(/\+(\d+)/);
            if (phoneMatch) data.calling.phoneNumber = '+' + phoneMatch[1];

            const headerMatches = callingSection[1].matchAll(/sipHeader\[\d+\]\s*=\s*(.+)/gi);
            data.calling.headers = [];
            for (const match of headerMatches) {
                const h = match[1].trim();
                data.calling.headers.push(h);
                const nameMatch = h.match(/"([^"]+)"/);
                if (nameMatch) data.calling.callerName = nameMatch[1];
            }
        }

        const calledSection = block.match(/called\s*\n([\s\S]*?)(?=associateMedia|location|$)/i);
        if (calledSection) {
            const uriMatch = calledSection[1].match(/uri\[0\]\s*=\s*(.+)/i);
            if (uriMatch) data.called.uri = uriMatch[1].trim();
            const phoneMatch = data.called.uri?.match(/\+(\d+)/);
            if (phoneMatch) data.called.phoneNumber = '+' + phoneMatch[1];
        }

        const sdpMatch = block.match(/sdp\s*=\s*([\s\S]*?)(?=\n\s*\n|\n[a-zA-Z])/);
        if (sdpMatch) {
            data.sdp = sdpMatch[1].trim();
            data.codecs = this.parseCodecsFromSDP(data.sdp);
        }
        data.location = this.parseLocationData(block);
        return data;
    }

    parseSIPMessage(block) {
        const data = { sipMessages: [], correlationId: null };
        data.correlationId = this.extractField(block, 'correlationID');
        const sigMsgMatch = block.match(/(?:sigMsg|signalingMsg(?:\[\d+\])?)\s*=\s*([\s\S]*?)(?=\[bin\]|$)/i);
        if (sigMsgMatch) {
            const sipContent = decodePossibleHex(sigMsgMatch[1]);
            data.sipMessages.push({
                content: sipContent,
                parsed: this.parseSIPContent(sipContent)
            });
        }
        return data;
    }

    parseSIPContent(sipContent) {
        const parsed = { method: null, statusCode: null, statusText: null, headers: {}, isRequest: false, isResponse: false };
        const lines = sipContent.replace(/\r\n/g, '\n').split('\n');
        if (lines.length === 0) return parsed;
        const firstLine = lines[0].trim();

        if (firstLine.startsWith('SIP/2.0')) {
            parsed.isResponse = true;
            const statusMatch = firstLine.match(/SIP\/2\.0\s+(\d+)\s+(.+)/);
            if (statusMatch) {
                parsed.statusCode = parseInt(statusMatch[1]);
                parsed.statusText = statusMatch[2];
            }
        } else {
            parsed.isRequest = true;
            const methodMatch = firstLine.match(/^(\w+)\s+/);
            if (methodMatch) parsed.method = methodMatch[1];
        }

        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            const headerMatch = line.match(/^([^:]+):\s*(.+)/);
            if (headerMatch) {
                const name = headerMatch[1].trim();
                const value = headerMatch[2].trim();
                if (parsed.headers[name]) {
                    if (Array.isArray(parsed.headers[name])) parsed.headers[name].push(value);
                    else parsed.headers[name] = [parsed.headers[name], value];
                } else parsed.headers[name] = value;
            }
        }
        return parsed;
    }

    parseSMSMessage(block) {
        const data = {
            from: this.extractField(block, 'originator'),
            to: this.extractField(block, 'recipient'),
            content: this.extractField(block, 'userInput') || this.extractField(block, 'smsMessage'),
            direction: block.includes('originating') ? 'Sent' : 'Received'
        };
        return data;
    }

    parseCCMessage(block) {
        const data = { sdp: null, codecs: [] };
        const sdpMatch = block.match(/sdp\s*=\s*([\s\S]*?)(?=\n\s*(?:associateMedia|deliveryIdentifier)|$)/);
        if (sdpMatch) {
            data.sdp = sdpMatch[1].trim();
            data.codecs = this.parseCodecsFromSDP(data.sdp);
        }
        return data;
    }

    parseAnswerMessage(block) {
        const data = { answering: {}, location: [] };
        const answeringSection = block.match(/answering\s*\n([\s\S]*?)(?=location|$)/i);
        if (answeringSection) {
            const uriMatch = answeringSection[1].match(/uri\[0\]\s*=\s*(.+)/i);
            if (uriMatch) data.answering.uri = uriMatch[1].trim();
            const phoneMatch = data.answering.uri?.match(/\+(\d+)/);
            if (phoneMatch) data.answering.phoneNumber = '+' + phoneMatch[1];
        }
        data.location = this.parseLocationData(block);
        return data;
    }

    parseReleaseMessage(block) {
        const data = { cause: null, location: [] };
        const causeSection = block.match(/cause\s*\n([\s\S]*?)(?=contactAddresses|location|$)/i);
        if (causeSection) {
            const sigTypeMatch = causeSection[1].match(/signalingType\s*=\s*(.+)/i);
            if (sigTypeMatch) data.cause = sigTypeMatch[1].trim();
        }
        data.location = this.parseLocationData(block);
        return data;
    }

    parseLocationData(block) {
        const locations = [];
        const locationBlocks = block.matchAll(
            /location\[\d+\][\s\S]*?(?=\n\s*location\[\d+\]|\n\s*(?:subjectMedia|associateMedia|calling|called|input|originationCause|signalingMsg|answering|cause|contactAddresses|$))/gi
        );
        for (const match of locationBlocks) {
            const chunk = match[0];
            const typeMatch = chunk.match(/locationType\s*=\s*(.+)/i);
            const dataMatch = chunk.match(/locationData\s*=\s*(.+)/i);
            if (!typeMatch || !dataMatch) continue;
            const locationData = { type: typeMatch[1].trim(), rawData: dataMatch[1].trim(), parsed: {} };
            const cellMatch = locationData.rawData.match(/(?:utran-cell-id-3gpp|cell-id-3gpp)=([a-fA-F0-9]+)/i);
            if (cellMatch) {
                locationData.parsed = this.parseCellId(cellMatch[1]);
            }
            locations.push(locationData);
        }

        if (locations.length === 0) {
            const fallbackMatch = block.match(/utran-cell-id-3gpp=([a-fA-F0-9]+)/i);
            if (fallbackMatch) {
                locations.push({
                    type: 'P-A-N-I-Header (Fallback)',
                    rawData: fallbackMatch[0],
                    parsed: this.parseCellId(fallbackMatch[1]),
                    timestamp: this.extractField(block, 'timestamp')
                });
            }
        }

        return locations;
    }

    parseCellId(cellId) {
        const result = { fullCellId: cellId, mcc: null, mnc: null, lac: null, cellId: null };
        if (cellId.length >= 15) {
            result.mcc = cellId.substring(0, 3);
            result.mnc = cellId.substring(3, 6);
            const tacAndCell = cellId.substring(6);

            // Check if it's hex (T-Mobile/Nokia style often uses hex for these fields)
            const isHex = /[a-fA-F]/.test(tacAndCell);

            if (isHex || tacAndCell.length > 8) {
                // Heuristic: If it has hex chars or is long, treat as hex
                result.lacHex = tacAndCell.substring(0, 4);
                result.cidHex = tacAndCell.substring(4);
                result.lac = parseInt(result.lacHex, 16);
                result.cellId = parseInt(result.cidHex, 16);
            } else {
                // Fallback to standard decimal parsing if it looks like decimal
                result.lac = tacAndCell.substring(0, 4);
                result.cellId = tacAndCell.substring(4);
            }
        }
        return result;
    }

    parseCodecsFromSDP(sdp) {
        const codecs = [];
        const rtpmapMatches = sdp.matchAll(/a=rtpmap:(\d+)\s+([^\s\/]+)/g);
        for (const match of rtpmapMatches) {
            codecs.push({ payloadType: match[1], name: match[2] });
        }
        return codecs;
    }

    extractCallInfo(message, call) {
        if (message.caseId) call.caseId = message.caseId;

        switch (message.type) {
            case 'termAttempt':
                call.callDirection = 'Incoming';
                call.startTime = message.timestamp;
                if (message.data.calling) {
                    call.callingParty = message.data.calling;
                    if (message.data.calling.callerName) call.callerName = message.data.calling.callerName;
                }
                if (message.data.called) call.calledParty = message.data.called;
                if (message.data.codecs) call.codecs = message.data.codecs;
                if (message.data.location && message.data.location.length) call.locations.push(...message.data.location);
                break;
            case 'origAttempt':
                call.callDirection = 'Outgoing';
                call.startTime = message.timestamp;
                if (message.data.calling) call.callingParty = message.data.calling;
                if (message.data.called) call.calledParty = message.data.called;
                if (message.data.location && message.data.location.length) call.locations.push(...message.data.location);
                break;
            case 'directSignalReporting':
            case 'subjectSignal':
                if (message.data.sipMessages) {
                    for (const sip of message.data.sipMessages) {
                        call.sipMessages.push({ timestamp: message.timestamp, ...sip });
                        if (sip.parsed?.headers) {
                            if (this.isSmsSipMessage(message, sip)) {
                                call.callType = 'SMS/MMS';
                                call.smsData.push(this.buildSmsEntryFromSip(message, sip));
                            }
                            const pai = sip.parsed.headers['P-Asserted-Identity'];
                            if (pai) {
                                const nameVal = Array.isArray(pai) ? pai[0] : pai;
                                const nameMatch = nameVal.match(/"([^"]+)"/);
                                if (nameMatch && !call.callerName) call.callerName = nameMatch[1];
                            }
                            const ua = sip.parsed.headers['User-Agent'];
                            if (ua) {
                                call.deviceInfo.userAgent = ua;
                                const appleMatch = ua.match(/APPLE---([^-]+)---(.+)/);
                                if (appleMatch) {
                                    call.deviceInfo.manufacturer = 'Apple';
                                    call.deviceInfo.model = appleMatch[1];
                                    call.deviceInfo.osVersion = appleMatch[2];
                                }
                            }
                            const pani = sip.parsed.headers['P-Access-Network-Info'];
                            if (pani) {
                                const paniVal = Array.isArray(pani) ? pani[0] : pani;
                                const cellMatch = paniVal.match(/utran-cell-id-3gpp=(\w+)/i);
                                if (cellMatch) {
                                    if (!call.locations.find(l => l.parsed?.fullCellId === cellMatch[1])) {
                                        call.locations.push({ type: 'P-A-N-I-Header', rawData: paniVal, parsed: this.parseCellId(cellMatch[1]), timestamp: message.timestamp });
                                    }
                                }
                            }
                            const rep = sip.parsed.headers['P-Com.NameId-Reputation'];
                            if (rep) {
                                const verMatch = rep.match(/verstat=([^;]+)/);
                                if (verMatch) call.verificationStatus = verMatch[1];
                            }
                        }
                    }
                }
                break;
            case 'answer':
                call.answerTime = message.timestamp;
                call.callStatus = 'Answered';
                if (message.data.location) call.locations.push(...message.data.location);
                break;
            case 'release':
                call.endTime = message.timestamp;
                call.releaseReason = message.data.cause;
                if (message.data.location) call.locations.push(...message.data.location);
                break;
            case 'smsMessage':
            case 'mmsMessage':
                call.callType = 'SMS/MMS';
                call.smsData.push({ timestamp: message.timestamp, ...message.data });
                break;
        }
    }

    isSmsSipMessage(message, sip) {
        if (!sip || !sip.parsed) return false;
        const method = sip.parsed.method || '';
        if (method.toUpperCase() === 'MESSAGE') return true;
        const headers = sip.parsed.headers || {};
        const contentType = this.getHeaderValue(headers, 'Content-Type');
        if (contentType && /3gpp\.sms/i.test(contentType)) return true;
        const acceptContact = this.getHeaderValue(headers, 'Accept-Contact');
        if (acceptContact && /smsip/i.test(acceptContact)) return true;
        const rawBlock = message?.rawBlock || '';
        if (/gsm\s+sms/i.test(rawBlock) || /sms\-deliver/i.test(rawBlock)) return true;
        return false;
    }

    buildSmsEntryFromSip(message, sip) {
        const headers = sip.parsed?.headers || {};
        const from = this.extractPhoneNumber(this.getHeaderValue(headers, 'From')) || this.extractPhoneNumber(this.getHeaderValue(headers, 'P-Asserted-Identity'));
        const to = this.extractPhoneNumber(this.getHeaderValue(headers, 'To')) || this.extractPhoneNumber(this.getHeaderValue(headers, 'P-Called-Party-ID'));
        let content = '';
        const rawBlock = message?.rawBlock || '';
        const smsHeaderMatch = rawBlock.match(/GSM\\s+SMS-DELIVER[^\\n]*:\\s*([0-9+]+)/i);
        if (smsHeaderMatch) {
            content = `GSM SMS-DELIVER from ${smsHeaderMatch[1]}`;
        } else {
            content = 'SIP MESSAGE (SMS)';
        }
        return {
            timestamp: message.timestamp,
            direction: 'SMS',
            from: from || 'Unknown',
            to: to || 'Unknown',
            content
        };
    }

    getHeaderValue(headers, name) {
        const key = Object.keys(headers).find(k => k.toLowerCase() === name.toLowerCase());
        if (!key) return null;
        const value = headers[key];
        return Array.isArray(value) ? value[0] : value;
    }

    parseTimestamp(timestamp) {
        if (!timestamp) return null;
        const match = timestamp.match(/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.?(\d*)Z?/);
        if (match) {
            const [_, y, m, d, h, min, s, ms] = match;
            return new Date(`${y}-${m}-${d}T${h}:${min}:${s}.${ms || '000'}Z`);
        }
        return null;
    }

    formatTimestamp(timestamp) {
        const date = this.parseTimestamp(timestamp);
        if (!date) return timestamp || 'Unknown';
        return date.toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true });
    }

    formatPhoneNumber(number) {
        if (!number) return 'Unknown';
        const digits = number.replace(/\D/g, '');
        if (digits.length === 11 && digits.startsWith('1')) return `+1 (${digits.substring(1, 4)}) ${digits.substring(4, 7)}-${digits.substring(7)}`;
        if (digits.length === 10) return `(${digits.substring(0, 3)}) ${digits.substring(3, 6)}-${digits.substring(6)}`;
        return number;
    }

    formatDuration(seconds) {
        if (seconds === null || seconds < 0) return 'N/A';
        const m = Math.floor(seconds / 60);
        const s = seconds % 60;
        return m > 0 ? `${m}m ${s}s` : `${s}s`;
    }
}

function decodePossibleHex(text) {
    if (!text) return '';
    const raw = String(text).trim();
    const compact = raw.replace(/\s+/g, '');
    const hex = compact.startsWith('0x') ? compact.slice(2) : compact;
    if (!isLikelyHex(hex)) return raw.trim();
    const decoded = decodeHexToString(hex);
    if (!decoded) return raw.trim();
    return isMostlyPrintable(decoded) ? decoded : raw.trim();
}

function isLikelyHex(value) {
    if (!value || value.length < 2) return false;
    if (value.length % 2 !== 0) return false;
    return /^[0-9a-fA-F]+$/.test(value);
}

function decodeHexToString(hex) {
    try {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
        }
        const decoder = new TextDecoder('utf-8');
        return decoder.decode(bytes);
    } catch (e) {
        return '';
    }
}

function isMostlyPrintable(text) {
    if (!text) return false;
    let printable = 0;
    for (let i = 0; i < text.length; i++) {
        const code = text.charCodeAt(i);
        const isPrintable = (code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9;
        if (isPrintable) printable++;
    }
    return printable / text.length >= 0.7;
}

function canUseLocalStorage() {
    try {
        const key = '__cdc_storage_test__';
        localStorage.setItem(key, '1');
        localStorage.removeItem(key);
        return true;
    } catch (e) {
        return false;
    }
}

function normalizeFullCellId(value) {
    if (!value) return null;
    return value.toString().trim().toLowerCase().replace(/[^0-9a-f]/g, '');
}

function normalizeShortCellId(value) {
    const normalized = normalizeFullCellId(value);
    if (!normalized) return null;
    if (!/^\d{6}/.test(normalized)) return null;
    const mccmnc = normalized.slice(0, 6);
    const rest = normalized.slice(6);
    if (rest.length === 7) return normalized;
    if (rest.length >= 11) return mccmnc + rest.slice(-7);
    return null;
}

function buildEcgiVariants(value) {
    const variants = new Set();
    const normalized = normalizeFullCellId(value);
    if (!normalized) return variants;
    variants.add(normalized);
    if (/^\d{6}/.test(normalized)) {
        const mccmnc = normalized.slice(0, 6);
        const tail = normalized.slice(6);
        if (tail) {
            variants.add(`${mccmnc}-${tail}`);
            variants.add(`${mccmnc}.${tail}`);
        }
    }
    return variants;
}

function deriveTacFromEcgi(ecgi) {
    if (!ecgi) return null;
    const cleaned = ecgi.toString().trim().replace(/[^0-9a-fA-F\-:]/g, '');
    if (!cleaned) return null;
    if (/^\d{6}[0-9a-fA-F]{7,}$/.test(cleaned)) {
        const tacHex = cleaned.slice(6, 10);
        const tacNum = parseInt(tacHex, 16);
        return Number.isNaN(tacNum) ? null : tacNum.toString();
    }
    const parts = cleaned.split(/[-:]/).filter(Boolean);
    const hexPart = parts.length > 1 ? parts[1] : parts[0];
    if (!hexPart) return null;
    const numeric = parseInt(hexPart, 16);
    if (Number.isNaN(numeric)) return null;
    return Math.floor(numeric / 256).toString();
}

// Global state for multi-call UI and tower data
let currentAnalyzer = null;
let towerDatabase = new Map(); // Key: LAC-CID, Value: { lat, lon, address, market, siteId }
let towerDatabaseFullId = new Map(); // Key: normalized full cell IDs (ECGI, UTRAN)
let towerDatabaseShortId = new Map(); // Key: normalized short cell IDs (MCCMNC + ECI)
let supabaseClient = null;

// Hardcoded Supabase Configuration
const SUPABASE_CONFIG = {
    URL: 'https://euiqgrouyrtygfwtthpo.supabase.co',
    KEY: 'sb_publishable_eysjqn_CJYqpP59sA8GELg_tZRT7qsS'
};

function analyzeCDC(options = {}) {
    console.log("Analyzing CDC data...");
    const input = document.getElementById('cdcInput').value;
    if (!input.trim()) {
        alert("Please paste some CDC data first.");
        return;
    }

    try {
        currentAnalyzer = new CDCAnalyzer(input);
        currentAnalyzer.parse();

        const selector = document.getElementById('callSelector');
        selector.innerHTML = '';

        if (currentAnalyzer.calls.size === 0) {
            alert("No recognizable CDC messages found. Check your data format.");
            return;
        }

        currentAnalyzer.calls.forEach((call, id) => {
            const option = document.createElement('option');
            option.value = id;
            const time = call.startTime ? currentAnalyzer.formatTimestamp(call.startTime) : 'No Start Time';
            const parties = `${call.callingParty.phoneNumber || 'Unknown'} -> ${call.calledParty.phoneNumber || 'Unknown'}`;
            option.textContent = `[${call.callType}] ${time} | ${parties}`;
            selector.appendChild(option);
        });

        document.getElementById('callSelectorContainer').style.display = 'flex';
        switchCall(selector.value);

        if (!options.skipTowerSync) {
            syncTowersFromCloud({ refreshAfter: true });
        }
    } catch (err) {
        console.error("Analysis failed:", err);
        alert("An error occurred during analysis. Check the console for details.");
    }
}

function switchCall(callId) {
    if (!currentAnalyzer) return;
    const call = currentAnalyzer.calls.get(callId);
    displayResults(call, currentAnalyzer);
}

function displayResults(call, analyzer) {
    const container = document.getElementById('callDetails');
    const resultsContainer = document.getElementById('resultsContainer');
    resultsContainer.classList.add('active');

    let html = '';

    // Summary Cards
    html += '<div class="summary-grid">';

    // Overview
    html += `
        <div class="summary-card highlight">
            <h3>Call Overview</h3>
            <div class="info-row"><span class="info-label">Type</span><span class="info-value"><span class="badge badge-info">${call.callType}</span></span></div>
            <div class="info-row"><span class="info-label">Direction</span><span class="info-value"><span class="badge ${call.callDirection === 'Incoming' ? 'badge-success' : 'badge-warning'}">${call.callDirection || 'Unknown'}</span></span></div>
            <div class="info-row"><span class="info-label">Status</span><span class="info-value"><span class="badge badge-success">${call.callStatus || 'Unknown'}</span></span></div>
            <div class="info-row"><span class="info-label">Duration</span><span class="info-value">${analyzer.formatDuration(call.duration)}</span></div>
            <div class="info-row"><span class="info-label">Case ID</span><span class="info-value">${call.caseId || 'N/A'}</span></div>
        </div>
    `;

    // Calling Party
    const callerCarrier = CDC_CONSTANTS.getCarrier(call.locations[0]?.parsed?.mcc, call.locations[0]?.parsed?.mnc);
    html += `
        <div class="summary-card caller">
            <h3>Calling Party (FROM)</h3>
            <div class="info-row"><span class="info-label">Number</span><span class="info-value phone-number">${analyzer.formatPhoneNumber(call.callingParty.phoneNumber)}</span></div>
            <div class="info-row"><span class="info-label">Caller ID</span><span class="info-value caller-name">${call.callerName || 'N/A'}</span></div>
            <div class="info-row"><span class="info-label">STIR/SHAKEN</span><span class="info-value"><span class="badge ${call.verificationStatus?.includes('Passed') ? 'badge-success' : 'badge-warning'}">${call.verificationStatus || 'N/A'}</span></span></div>
            <div class="info-row"><span class="info-label">Carrier</span><span class="info-value">${callerCarrier}</span></div>
        </div>
    `;

    // Called Party
    html += `
        <div class="summary-card called">
            <h3>Called Party (TO)</h3>
            <div class="info-row"><span class="info-label">Number</span><span class="info-value phone-number">${analyzer.formatPhoneNumber(call.calledParty.phoneNumber)}</span></div>
            <div class="info-row"><span class="info-label">Carrier</span><span class="info-value">${call.calledParty.uri?.includes('vzims') ? 'Verizon' : 'Lookup Needed'}</span></div>
        </div>
    `;

    // Timestamps
    html += `
        <div class="summary-card">
            <h3>Key Events</h3>
            <div class="info-row"><span class="info-label">Start</span><span class="info-value">${analyzer.formatTimestamp(call.startTime)}</span></div>
            <div class="info-row"><span class="info-label">Answer</span><span class="info-value">${analyzer.formatTimestamp(call.answerTime)}</span></div>
            <div class="info-row"><span class="info-label">End</span><span class="info-value">${analyzer.formatTimestamp(call.endTime)}</span></div>
        </div>
    `;
    html += '</div>';

    // Sequence Diagram (Mermaid)
    if (call.messages.length > 0) {
        html += `
            <div class="timeline-section">
                <h3>Call Flow Diagram</h3>
                <div class="mermaid">
                    sequenceDiagram
                        autonumber
                        participant T as Target Device
                        participant C as Carrier Network
                        participant P as Peer
                        ${generateFlowMarkup(call)}
                </div>
            </div>
        `;
    }

    // Mapping Section
    if (call.locations.length > 0) {
        html += `
            <div class="location-section">
                <h3>Cell Tower Mapping</h3>
                <p style="color: var(--warning-color); font-size: 0.85rem; margin-bottom: 10px; font-weight: 600;">
                    ⚠️ Note: These are estimated visual markers. For investigative precision, use the Cell ID links below.
                </p>
                <div id="map" style="height: 400px; border-radius: 8px; border: 1px solid var(--border-color); margin-bottom: 20px;"></div>
                <div class="location-grid">
                    ${call.locations.map(loc => {
            const compositeKey = `${loc.parsed.lac}-${loc.parsed.cellId}`;
            const fullKey = normalizeFullCellId(loc.parsed.fullCellId);
            const shortKey = normalizeShortCellId(loc.parsed.fullCellId);
            let tower = towerDatabase.get(compositeKey);
            if (!tower && fullKey) tower = towerDatabaseFullId.get(fullKey);
            if (!tower && shortKey) tower = towerDatabaseShortId.get(shortKey);
            return `
                        <div class="location-item" style="${tower ? 'border-left: 5px solid var(--success-color);' : ''}">
                            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                                <div>
                                    <strong>${loc.type}</strong> ${tower ? '<span class="badge badge-success" style="font-size: 0.6rem;">Matched</span>' : ''}<br>
                                    <small>${analyzer.formatTimestamp(loc.timestamp)}</small>
                                </div>
                                <a href="https://opencellid.org/#action=locations.search&mcc=${loc.parsed.mcc}&mnc=${loc.parsed.mnc}&lac=${parseInt(loc.parsed.lac, 16)}&cellid=${parseInt(loc.parsed.cellId, 16)}" 
                                   target="_blank" class="btn-secondary" style="font-size: 0.7rem; padding: 4px 8px; text-decoration: none;">
                                   Verify on OpenCellID
                                </a>
                            </div>
                            <div style="margin-top: 10px; font-family: monospace; font-size: 0.8rem;">
                                LAC:${loc.parsed.lac} CID:${loc.parsed.cellId}
                            </div>
                            ${tower ? `
                            <div style="margin-top: 5px; font-size: 0.85rem; color: var(--primary-color); font-weight: 600;">
                                📍 ${tower.address}
                                ${tower.siteId ? `<br><small style="color: var(--text-muted);">Site: ${tower.siteId} (${tower.market || 'Unknown Market'})</small>` : ''}
                            </div>
                            ` : ''}
                        </div>
                    `;
        }).join('')}
                </div>
            </div>
        `;
    }

    // SMS Content
    if (call.smsData.length > 0) {
        html += `
            <div class="device-section">
                <h3>SMS/MMS Messages (${call.smsData.length})</h3>
                <div class="sms-list">
                    ${call.smsData.map(sms => `
                        <div class="timeline-event">
                            <div class="timeline-time">${analyzer.formatTimestamp(sms.timestamp)}</div>
                            <div class="timeline-title">${sms.direction}: ${sms.from || 'Target'} -> ${sms.to || 'Peer'}</div>
                            <div class="timeline-details" style="font-family: inherit; color: var(--text-color); font-size: 1rem;">${sms.content}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    // Technical Message Timeline
    html += `
        <div class="timeline-section">
            <h3>Technical Message Timeline</h3>
            <div class="timeline-list">
                ${call.messages.map(msg => `
                    <div class="timeline-event">
                        <div class="timeline-time">${analyzer.formatTimestamp(msg.timestamp)}</div>
                        <div class="timeline-title">${msg.type}</div>
                        <div class="timeline-details">${msg.data.sipMessages?.[0]?.content || JSON.stringify(msg.data, null, 2)}</div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;

    // Raw Records Section
    html += `
        <div class="technical-section">
            <h3>Raw CDC Records</h3>
            <div class="raw-export">
                ${call.messages.map(msg => `
                   <div class="raw-record">
                       <pre>${msg.rawBlock}</pre>
                   </div>
                `).join('<hr>')}
            </div>
        </div>
    `;

    container.innerHTML = html;

    // Render Mermaid and Map
    setTimeout(() => {
        if (typeof mermaid !== 'undefined') {
            try {
                mermaid.init();
            } catch (e) { console.error("Mermaid init failed", e); }
        }
        if (call.locations.length > 0) initMap(call.locations);
    }, 100);
}

function generateFlowMarkup(call) {
    let markup = "";
    call.messages.forEach(msg => {
        switch (msg.type) {
            case 'termAttempt':
                markup += `Note over T,P: Incoming Call Attempt\n`;
                markup += `P->>C: Setup Request\n`;
                markup += `C->>T: termAttempt\n`;
                break;
            case 'origAttempt':
                markup += `Note over T,P: Outgoing Call Attempt\n`;
                markup += `T->>C: origAttempt\n`;
                markup += `C->>P: Setup Request\n`;
                break;
            case 'directSignalReporting':
                const sip = msg.data.sipMessages?.[0]?.parsed;
                if (sip) {
                    if (sip.isRequest) markup += `T->>C: SIP ${sip.method}\n`;
                    else markup += `C-->>T: SIP ${sip.statusCode} ${sip.statusText}\n`;
                }
                break;
            case 'ccOpen': markup += `C-->>T: ccOpen (Audio Path Open)\n`; break;
            case 'ccClose': markup += `C-->>T: ccClose (Audio Path Closed)\n`; break;
            case 'answer':
                markup += `Note right of T: Call Answered\n`;
                markup += `T->>C: answer\n`;
                markup += `C->>P: Answer Response\n`;
                break;
            case 'release':
                markup += `Note over T,P: Call Released (${msg.data.cause || 'Normal'})\n`;
                markup += `T->>C: release\n`;
                markup += `C->>P: Release Notification\n`;
                break;
            case 'smsMessage':
            case 'mmsMessage':
                if (msg.data.direction === 'Sent') {
                    markup += `T->>C: ${msg.type} (To: ${msg.data.to})\n`;
                    markup += `C->>P: Forward message\n`;
                } else {
                    markup += `P->>C: Incoming ${msg.type}\n`;
                    markup += `C->>T: ${msg.type} (From: ${msg.data.from})\n`;
                }
                break;
        }
    });
    return markup;
}

function initMap(locations) {
    if (locations.length === 0 || typeof L === 'undefined') return;

    try {
        const baseLat = 40.7128;
        const baseLng = -74.0060;
        const map = L.map('map');
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors'
        }).addTo(map);

        const markers = [];
        locations.forEach(loc => {
            if (!loc.parsed.lac || !loc.parsed.cellId) return;

            const compositeKey = `${loc.parsed.lac}-${loc.parsed.cellId}`;
            const fullKey = normalizeFullCellId(loc.parsed.fullCellId);
            const shortKey = normalizeShortCellId(loc.parsed.fullCellId);
            let tower = towerDatabase.get(compositeKey);
            if (!tower && fullKey) tower = towerDatabaseFullId.get(fullKey);
            if (!tower && shortKey) tower = towerDatabaseShortId.get(shortKey);
            let lat, lng, isPrecise = false;

            if (tower && tower.lat && tower.lon) {
                lat = tower.lat;
                lng = tower.lon;
                isPrecise = true;
            } else {
                const latOffset = (parseInt(loc.parsed.lac, 16) % 100) / 500;
                const lngOffset = (parseInt(loc.parsed.cellId, 16) % 100) / 500;
                lat = baseLat + latOffset;
                lng = baseLng + lngOffset;
            }

            const markerColor = isPrecise ? '#276749' : '#2b6cb0';
            const markerIcon = L.divIcon({
                className: 'custom-div-icon',
                html: `<div style="background-color: ${markerColor}; width: 12px; height: 12px; border-radius: 50%; border: 2px solid white; box-shadow: 0 0 3px rgba(0,0,0,0.4);"></div>`,
                iconSize: [12, 12],
                iconAnchor: [6, 6]
            });

            const marker = L.marker([lat, lng], { icon: markerIcon }).addTo(map)
                .bindPopup(`
                    <div style="font-family: sans-serif;">
                        <strong style="color: ${markerColor};">${loc.type}</strong><br>
                        ${isPrecise ? `<span style="color: #276749; font-weight: bold;">✓ Career Verified Tower</span><br>
                        <b>Address:</b> ${tower.address}<br>` : '<i>Estimated Location</i><br>'}
                        <b>Cell ID:</b> ${loc.parsed.cellId}<br>
                        <b>LAC:</b> ${loc.parsed.lac}
                    </div>
                `);
            markers.push(marker);
        });

        if (markers.length > 0) {
            const group = new L.featureGroup(markers);
            map.fitBounds(group.getBounds().pad(0.5));
            map.setZoom(Math.max(map.getZoom() - 3, 1));
        } else {
            map.setView([baseLat, baseLng], 13);
        }
    } catch (e) { console.error("Map init failed", e); }
}

function exportCSV() {
    if (!currentAnalyzer) return;
    let csv = "CallID,CaseID,Type,StartTime,EndTime,Duration,Caller,Called,Status\n";
    currentAnalyzer.calls.forEach(call => {
        csv += `${call.callId},${call.caseId || ''},${call.callType},${call.startTime || ''},${call.endTime || ''},${call.duration || 0},${call.callingParty.phoneNumber || ''},${call.calledParty.phoneNumber || ''},${call.callStatus || ''}\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.setAttribute('hidden', '');
    a.setAttribute('href', url);
    a.setAttribute('download', 'cdc_investigation_report.csv');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

function clearAll() {
    document.getElementById('cdcInput').value = '';
    document.getElementById('callSelectorContainer').style.display = 'none';
    document.getElementById('callDetails').innerHTML = '';
}

function loadSample() {
    document.getElementById('cdcInput').value = `termAttempt
T1.678 Version 4
   laesMessage
      termAttempt
         caseId = CASE-2025-001
         timestamp = 20250604035420.132Z
         callId
            main = 003A1486D04F061E
         calling
            uri[0] = sip:+16313841232@msg.pc.t-mobile.com
            sipHeader[2] = P-Asserted-Identity: "JOHN DOE" <sip:+16313841232;verstat=TN-Validation-Passed@msg.pc.t-mobile.com>
         called
            uri[0] = tel:+16313754560;rn=+16315996100

directSignalReporting
T1.678 Version 4
    laesMessage
        directSignalReporting
            timestamp = 20250604035421.500Z
            callId = 003A1486D04F061E
            sigMsg = 
INVITE sip:+16313754560@msg.pc.t-mobile.com SIP/2.0
User-Agent: APPLE---iPhone15---17.5.1
P-Access-Network-Info: 3GPP-UTRAN-FDD;utran-cell-id-3gpp=311480550414df40c

directSignalReporting
T1.678 Version 4
    laesMessage
        directSignalReporting
            timestamp = 20250604035422.200Z
            callId = 003A1486D04F061E
            sigMsg = 
SIP/2.0 180 Ringing

smsMessage
T1.678 Version 4
    laesMessage
        smsMessage
            caseId = CASE-2025-001
            timestamp = 20250604041000.000Z
            originator = +16313841232
            recipient = +16313754560
            userInput = See you there at 5pm.
            originating`;
}

function handleTowerUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
        const text = e.target.result;
        const count = parseTowerCSV(text);
        const status = document.getElementById('towerStatus');
        if (count > 0) {
            status.innerHTML = `<span style="color: var(--success-color); font-weight: 600;">✓ ${count} towers loaded</span>`;
            console.log(`Loaded ${count} towers into memory.`);

            // Show upload button now that we have local data
            document.getElementById('uploadBtn').style.display = 'inline-block';

            if (currentAnalyzer) {
                analyzeCDC();
            }
        } else {
            status.innerHTML = `<span style="color: var(--danger-color);">Format error (No LAC/CID found)</span>`;
        }
    };
    reader.readAsText(file);
}

function parseTowerCSV(text) {
    const lines = text.split('\n');
    if (lines.length < 2) return 0;

    // Detect delimiter
    let delimiter = ',';
    if (lines[0].includes('|')) delimiter = '|';
    else if (lines[0].includes(';')) delimiter = ';';

    const headers = lines[0].split(delimiter).map(h => h.trim().toLowerCase());
    console.log(`Parsing CSV with delimiter "${delimiter}". Headers:`, headers);

    const findHeaderIndex = (keywords) => headers.findIndex(h => keywords.some(keyword => h.includes(keyword)));

    const colIdx = {
        lac: headers.findIndex(h => h === 'lac' || h.includes('location area') || h === 'tac' || h === 'tracking area code'),
        cid: -1,
        cgi: headers.findIndex(h => h === 'cgi' || h.includes('cell global id')),
        lat: headers.findIndex(h => h === 'lat' || h.includes('latitude') || h === 'y' || h === 'site_latitude' || h === 'sector_latitude'),
        lon: headers.findIndex(h => h === 'lon' || h.includes('longitude') || h === 'x' || h === 'site_longitude' || h === 'sector_longitude'),
        address: headers.findIndex(h => h === 'address' || h.includes('street') || h.includes('location') || h === 'site_address'),
        market: headers.findIndex(h => h === 'market' || h === 'market_name'),
        siteId: headers.findIndex(h => h === 'site' || h === 'site id' || h === 'site_id' || h === 'enodeb_id' || h === 'site_id'),
        ecgi: findHeaderIndex(['ecgi', 'full cell id', 'cell global id'])
    };

    // Prioritize CGI for uniqueness, then fallback to other cell id headers
    const cidHeaders = ['cell id', 'cellid', 'cell_id', 'eci', 'ci'];
    for (const target of cidHeaders) {
        const idx = headers.findIndex(h => h === target || h.includes('cell identifier'));
        if (idx !== -1) {
            colIdx.cid = idx;
            break;
        }
    }

    // If we can't find core columns, fail
    if ((colIdx.lac === -1 && colIdx.ecgi === -1) || colIdx.cid === -1) {
        console.error("CSV Missing LAC/ECGI or CID/CGI columns. Detected headers:", headers);
        return 0;
    }

    let loadedCount = 0;
    for (let i = 1; i < lines.length; i++) {
        if (!lines[i].trim()) continue;

        // Simple split by delimiter, handling basic quoting
        const row = lines[i].split(delimiter).map(cell => cell.replace(/^"(.*)"$/, '$1').trim());
        if (row.length < 2) continue;

        let lac = colIdx.lac !== -1 ? row[colIdx.lac] : null;
        let cid = row[colIdx.cid];
        const cgiVal = colIdx.cgi !== -1 ? row[colIdx.cgi] : null;
        const ecgiVal = colIdx.ecgi !== -1 ? row[colIdx.ecgi] : null;
        const lat = colIdx.lat !== -1 ? parseFloat(row[colIdx.lat]) : null;
        const lon = colIdx.lon !== -1 ? parseFloat(row[colIdx.lon]) : null;
        const address = colIdx.address !== -1 ? row[colIdx.address] : null;

        if (!lac && ecgiVal) {
            lac = deriveTacFromEcgi(ecgiVal);
        }

        if (lac && cid) {
            const cgiNum = cgiVal && /^\d+$/.test(cgiVal) ? parseInt(cgiVal, 10) : null;
            const cidNum = /^\d+$/.test(cid) ? parseInt(cid, 10) : null;
            if (Number.isFinite(cgiNum) && Number.isFinite(cidNum) && cgiNum > 1000000 && cidNum < 1000) {
                cid = cgiVal;
            }
            const key = `${lac}-${cid}`;
            towerDatabase.set(key, {
                lat: isNaN(lat) ? null : lat,
                lon: isNaN(lon) ? null : lon,
                address: address || 'No address provided',
                market: colIdx.market !== -1 ? row[colIdx.market] : null,
                siteId: colIdx.siteId !== -1 ? row[colIdx.siteId] : null
            });
            const stored = towerDatabase.get(key);
            const fullIdKey = normalizeFullCellId(ecgiVal);
            const shortIdKey = normalizeShortCellId(ecgiVal);
            if (fullIdKey && stored) {
                towerDatabaseFullId.set(fullIdKey, stored);
            }
            if (shortIdKey && stored) {
                towerDatabaseShortId.set(shortIdKey, stored);
            }
            loadedCount++;
        }
    }

    // Update UI status to show both total rows and unique towers
    const status = document.getElementById('towerStatus');
    if (status) {
        status.innerHTML = `<span style="color: var(--success-color);">✓ ${loadedCount} rows parsed (${towerDatabase.size} unique towers)</span>`;
    }

    return loadedCount;
}

// --- Supabase Integration ---

function toggleSettings() {
    const modal = document.getElementById('cloudSettings');
    modal.style.display = modal.style.display === 'none' ? 'flex' : 'none';
}

function saveCloudSettings() {
    const url = document.getElementById('supabaseUrl').value.trim();
    const key = document.getElementById('supabaseKey').value.trim();

    if (!url || !key) {
        alert("Please enter both Supabase URL and Anon Key.");
        return;
    }

    localStorage.setItem('supabaseUrl', url);
    localStorage.setItem('supabaseKey', key);

    if (initializeSupabase()) {
        alert("Settings saved and Supabase initialized!");
        toggleSettings();
        syncTowersFromCloud();
    }
}

function initializeSupabase() {
    // Use hardcoded config if nothing is in local storage
    const url = localStorage.getItem('supabaseUrl') || SUPABASE_CONFIG.URL;
    const key = localStorage.getItem('supabaseKey') || SUPABASE_CONFIG.KEY;

    if (url && key) {
        try {
            // Check if supabase global exists from CDN
            if (window.supabase && window.supabase.createClient) {
                if (!supabaseClient) {
                    supabaseClient = window.supabase.createClient(url, key);
                    console.log("Supabase client initialized with:", url);
                }
                return true;
            } else {
                console.error("Supabase library not loaded from CDN.");
            }
        } catch (e) {
            console.error("Failed to init Supabase:", e);
        }
    }
    return false;
}

async function syncTowersFromCloud(options = {}) {
    const { refreshAfter = false } = options;
    if (!initializeSupabase()) {
        const towerStatus = document.getElementById('towerStatus');
        if (towerStatus) {
            towerStatus.textContent = canUseLocalStorage()
                ? "Cloud sync unavailable. Check Supabase settings."
                : "Cloud sync blocked: browser storage disabled. Load CSV locally or allow storage.";
        }
        console.warn("Supabase not initialized. Cannot sync.");
        return;
    }

    const syncBtn = document.getElementById('syncBtn');
    if (syncBtn) {
        syncBtn.textContent = "Syncing...";
        syncBtn.disabled = true;
    }

    try {
        let allData = [];
        let from = 0;
        let to = 999;
        let hasMore = true;
        const towerStatus = document.getElementById('towerStatus');

        while (hasMore) {
            towerStatus.textContent = `Syncing towers... (${allData.length} loaded)`;
            const { data, error } = await supabaseClient
                .from('towers')
                .select('*')
                .range(from, to);

            if (error) throw error;

            if (data && data.length > 0) {
                allData = allData.concat(data);
                from += 1000;
                to += 1000;
            } else {
                hasMore = false;
            }
        }

        if (allData.length > 0) {
            allData.forEach(row => {
                const key = `${row.lac}-${row.cid}`;
                towerDatabase.set(key, {
                    lat: row.lat,
                    lon: row.lon,
                    address: row.address,
                    market: row.market,
                    siteId: row.site_id
                });
                const stored = towerDatabase.get(key);
                const fullIdKey = normalizeFullCellId(row.ecgi);
                const shortIdKey = normalizeShortCellId(row.ecgi);
                if (fullIdKey && stored) {
                    towerDatabaseFullId.set(fullIdKey, stored);
                }
                if (shortIdKey && stored) {
                    towerDatabaseShortId.set(shortIdKey, stored);
                }
            });

            towerStatus.innerHTML = `<span style="color: var(--success-color); font-weight: 600;">✓ ${allData.length} towers synced from Cloud</span>`;
            console.log(`Synced ${allData.length} towers from Supabase.`);

            if (currentAnalyzer && refreshAfter) {
                analyzeCDC({ skipTowerSync: true });
            }
        } else {
            towerStatus.textContent = "No towers found in cloud.";
        }
    } catch (e) {
        console.error("Cloud sync failed:", e);
        alert("Cloud sync failed. Check your Supabase settings or internet connection.");
    } finally {
        if (syncBtn) {
            syncBtn.textContent = "Sync Cloud";
            syncBtn.disabled = false;
        }
    }
}

async function uploadTowersToCloud() {
    if (!initializeSupabase()) {
        alert("Please configure Supabase first.");
        toggleSettings();
        return;
    }

    if (towerDatabase.size === 0) {
        alert("No tower data in memory to upload. Load a CSV first.");
        return;
    }

    const uploadBtn = document.getElementById('uploadBtn');
    const towerStatus = document.getElementById('towerStatus');
    uploadBtn.textContent = "Uploading...";
    uploadBtn.disabled = true;

    try {
        const allRows = [];
        towerDatabase.forEach((val, key) => {
            const [lac, cid] = key.split('-');
            allRows.push({
                lac,
                cid,
                ecgi: val.ecgi || null,
                lat: val.lat,
                lon: val.lon,
                address: val.address,
                market: val.market,
                site_id: val.siteId
            });
        });

        const BATCH_SIZE = 500;
        let uploaded = 0;

        for (let i = 0; i < allRows.length; i += BATCH_SIZE) {
            const chunk = allRows.slice(i, i + BATCH_SIZE);
            towerStatus.textContent = `Uploading chunk... (${i + chunk.length} / ${allRows.length})`;

            const { error } = await supabaseClient.from('towers').upsert(chunk, { onConflict: 'lac,cid' });
            if (error) throw error;

            uploaded += chunk.length;
        }

        alert(`Successfully uploaded ${uploaded} records to the cloud!`);
        towerStatus.innerHTML = `<span style="color: var(--success-color); font-weight: 600;">✓ Cloud database updated (${uploaded} rows)</span>`;
    } catch (e) {
        console.error("Cloud upload failed:", e);
        alert("Cloud upload failed: " + (e.message || "Unknown error"));
    } finally {
        uploadBtn.textContent = "Upload to Cloud";
        uploadBtn.disabled = false;
    }
}


// --- Tab Management ---
function switchTab(tabId) {
    // Buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    const activeBtn = Array.from(document.querySelectorAll('.tab-btn'))
        .find(btn => btn.getAttribute('onclick').includes(tabId));
    if (activeBtn) activeBtn.classList.add('active');

    // Panels
    document.querySelectorAll('.tab-panel').forEach(panel => {
        panel.classList.remove('active');
    });
    document.getElementById(tabId).classList.add('active');

    // Special handling for map resize when switching to analyzer
    if (tabId === 'analyzerTab') {
        setTimeout(() => {
            if (window.map) window.map.invalidateSize();
        }, 100);
    }
    if (tabId === 'packetTab') {
        const results = document.getElementById('resultsContainer');
        if (results) results.style.display = 'none';
    }
    if (tabId === 'analyzerTab') {
        const results = document.getElementById('resultsContainer');
        if (results) results.style.display = '';
    }
}

// Explicitly expose functions to the global scope to ensure buttons work
window.analyzeCDC = analyzeCDC;
window.switchCall = switchCall;
window.clearAll = clearAll;
window.loadSample = loadSample;
window.exportCSV = exportCSV;
window.handleTowerUpload = handleTowerUpload;
window.toggleSettings = toggleSettings;
window.saveCloudSettings = saveCloudSettings;
window.syncTowersFromCloud = syncTowersFromCloud;
window.uploadTowersToCloud = uploadTowersToCloud;
window.switchTab = switchTab;

// Initialize on load
document.addEventListener('DOMContentLoaded', () => {
    // Populate settings if they exist (local storage takes priority for overrides)
    const url = localStorage.getItem('supabaseUrl') || SUPABASE_CONFIG.URL;
    const key = localStorage.getItem('supabaseKey') || SUPABASE_CONFIG.KEY;

    if (document.getElementById('supabaseUrl')) document.getElementById('supabaseUrl').value = url;
    if (document.getElementById('supabaseKey')) document.getElementById('supabaseKey').value = key;

    // Try to sync automatically
    if (url && key) {
        setTimeout(syncTowersFromCloud, 500);
    }
});

console.log("CDC Analyzer script v1.3 (build 2026-01-29-ecgi3) loaded and ready (Supabase Cloud Support).");
