// CDC Parser and Analyzer
class CDCAnalyzer {
    constructor(rawData) {
        this.rawData = rawData;
        this.messages = [];
        this.calls = new Map(); // Grouped by callId
        this.currentCallId = null;
        this.standardMessageTypes = this.loadStandardMessageTypes();
        this.standardTypeKeywordSet = this.buildStandardTypeKeywordSet();
        this.standardFieldAliases = this.getStandardFieldAliases();
    }

    parse() {
        const messageBlocks = this.splitIntoMessages(this.rawData);

        for (const block of messageBlocks) {
            const parsed = this.parseMessageBlock(block);
            if (parsed) {
                this.messages.push(parsed);

                // Group by callId
                const rawCallId = parsed.callId ? parsed.callId.trim() : null;
                const callKey = rawCallId ? rawCallId.toLowerCase() : 'global-events';
                if (!this.calls.has(callKey)) {
                    this.calls.set(callKey, this.createCallObject(rawCallId || 'Global-Events'));
                }
                const call = this.calls.get(callKey);
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
        const typeKeywords = new Set(this.standardTypeKeywordSet || []);
        typeKeywords.add('smsmessage');
        typeKeywords.add('mmsmessage');

        for (const line of lines) {
            const trimmed = line.trim();
            const normalized = trimmed.toLowerCase();
            const isTypeLine = trimmed && typeKeywords.has(normalized);

            if (isTypeLine && currentBlock.length > 0) {
                blocks.push(currentBlock.join('\n'));
                currentBlock = [];
            }

            currentBlock.push(line);
        }

        if (currentBlock.length > 0) {
            blocks.push(currentBlock.join('\n'));
        }

        return blocks;
    }

    detectMessageType(block) {
        const normalized = block.toLowerCase();
        for (const type of this.standardMessageTypes) {
            if (!type?.keywords) continue;
            for (const keyword of type.keywords) {
                if (!keyword) continue;
                if (normalized.includes(keyword.toLowerCase())) {
                    return type.id;
                }
            }
        }
        if (normalized.includes('smsmessage')) return 'smsMessage';
        if (normalized.includes('mmsmessage')) return 'mmsMessage';
        if (normalized.includes('subjectsignal')) return 'subjectSignal';
        return null;
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

        result.type = this.detectMessageType(block);

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
        const aliases = this.standardFieldAliases[fieldName] || [fieldName];
        for (const alias of aliases) {
            const regex = new RegExp(`${alias}\\s*=\\s*(.+?)(?:\\n|$)`, 'i');
            const match = block.match(regex);
            if (match) return decodePossibleHex(match[1].trim());
        }
        return null;
    }

    extractNestedField(block, parentField, childField) {
        const regex = new RegExp(`${parentField}[\\s\\S]*?${childField}\\s*=\\s*(.+?)(?:\\n|$)`, 'i');
        const match = block.match(regex);
        return match ? decodePossibleHex(match[1].trim()) : null;
    }

    loadStandardMessageTypes() {
        return CDC_STANDARDS?.ALL_MESSAGE_TYPES ? [...CDC_STANDARDS.ALL_MESSAGE_TYPES] : [];
    }

    buildStandardTypeKeywordSet() {
        const keywords = new Set();
        for (const type of this.standardMessageTypes) {
            if (!type?.keywords) continue;
            for (const keyword of type.keywords) {
                if (keyword) keywords.add(keyword.toLowerCase());
            }
        }
        return keywords;
    }

    getStandardFieldAliases() {
        return CDC_STANDARDS?.ALL_FIELD_ALIASES ? { ...CDC_STANDARDS.ALL_FIELD_ALIASES } : {};
    }

    parseAttemptMessage(block) {
        const data = { calling: {}, called: {}, sdp: null, location: [] };
        const callingSection = block.match(/calling\s*\n([\s\S]*?)(?=called|$)/i);
        if (callingSection) {
            const uriMatch = callingSection[1].match(/uri\[0\]\s*=\s*(.+)/i);
            if (uriMatch) data.calling.uri = uriMatch[1].trim();
            const phoneMatch = data.calling.uri?.match(/\+(\d+)/);
            if (phoneMatch) data.calling.phoneNumber = '+' + phoneMatch[1];
            const fallbackPhone = this.extractPhoneNumber(callingSection[1]);
            if (fallbackPhone && !data.calling.phoneNumber) {
                data.calling.phoneNumber = fallbackPhone;
            }

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
            const fallbackPhone = this.extractPhoneNumber(calledSection[1]);
            if (fallbackPhone && !data.called.phoneNumber) {
                data.called.phoneNumber = fallbackPhone;
            }
        }

        const sdpMatch = block.match(/sdp\s*=\s*([\s\S]*?)(?=\n\s*\n|\n[a-zA-Z])/);
        if (sdpMatch) {
            data.sdp = sdpMatch[1].trim();
            data.codecs = this.parseCodecsFromSDP(data.sdp);
        }
        data.location = this.parseLocationData(block);
        return data;
    }

    extractPhoneNumber(text) {
        if (!text) return null;
        const patterns = [
            /(?:dn|msisdn|mdn)\s*=\s*(\+?\d{7,})/i,
            /sip:\+?(\d{7,})/i,
            /tel:\+?(\d{7,})/i,
            /uri\[0\]\s*=\s*tel:\+?(\d{7,})/i,
            /uri\[0\]\s*=\s*sip:\+?(\d{7,})/i
        ];
        for (const pattern of patterns) {
            const match = text.match(pattern);
            if (match) return match[1].startsWith('+') ? match[1] : '+' + match[1];
        }
        return null;
    }

    // Detect and decode hex-encoded SIP messages (common in signalingMsg fields)
    decodeHexPayload(text) {
        return decodePossibleHex(text);
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
            // Support both decimal and hex cell IDs
            const cellMatch = locationData.rawData.match(/utran-cell-id-3gpp=([a-fA-F0-9]+)/i);
            if (cellMatch) {
                locationData.parsed = this.parseCellId(cellMatch[1]);
            }
            locations.push(locationData);
        }
        return locations;
    }

    parseCellId(cellId) {
        const result = { fullCellId: cellId, mcc: null, mnc: null, lac: null, cellId: null };
        if (typeof cellId !== 'string' || cellId.length < 15) return result;

        result.mcc = cellId.substring(0, 3);
        result.mnc = cellId.substring(3, 6);
        const tacAndCell = cellId.substring(6);
        const isHex = /[a-fA-F]/.test(tacAndCell);
        const lacPart = tacAndCell.substring(0, 4);
        const cidPart = tacAndCell.substring(4);

        if (isHex || tacAndCell.length > 8) {
            result.lacHex = lacPart;
            result.cidHex = cidPart;
            result.lac = parseInt(lacPart, 16);
            result.cellId = parseInt(cidPart, 16);
        } else {
            result.lac = parseInt(lacPart, 10);
            result.cellId = parseInt(cidPart, 10);
        }

        if (!Number.isFinite(result.lac)) result.lac = lacPart;
        if (!Number.isFinite(result.cellId)) result.cellId = cidPart;

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

function getDecimalValue(value) {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (typeof value === 'string' && value.trim()) {
        const parsed = parseInt(value.trim(), 10);
        if (!Number.isNaN(parsed)) return parsed;
    }
    return null;
}

// Global state for multi-call UI and tower data
let currentAnalyzer = null;
let towerDatabase = new Map(); // Key: LAC-CID, Value: { lat, lon, address, market, siteId, azimuth, beamWidth, sectorName, sectorRadiusMeters }
let towerDatabaseFullId = new Map(); // Key: normalized full cell IDs (ECGI, UTRAN)
let towerDatabaseShortId = new Map(); // Key: normalized short cell IDs (MCCMNC + ECI)
let supabaseClient = null;
let leafletMap = null;
let sectorLayers = [];

const SECTOR_DEFAULT_BEAM_WIDTH = 65;
const SECTOR_DEFAULT_RADIUS_METERS = 2000;

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
        if (![...currentAnalyzer.calls.values()].some(call => call.locations.length > 0)) {
            const matches = input.matchAll(/utran-cell-id-3gpp=([0-9a-fA-F]+)/gi);
            const firstCall = currentAnalyzer.calls.values().next().value;
            for (const match of matches) {
                const ecgi = match[1];
                const parsed = currentAnalyzer.parseCellId(ecgi);
                if (firstCall) {
                    firstCall.locations.push({
                        type: 'P-A-N-I-Header (Global Fallback)',
                        rawData: match[0],
                        parsed,
                        timestamp: firstCall.startTime || currentAnalyzer.messages?.[0]?.timestamp
                    });
                }
            }
        }
        if (![...currentAnalyzer.calls.values()].some(call => call.locations.length > 0)) {
            const firstCall = currentAnalyzer.calls.values().next().value;
            for (const message of currentAnalyzer.messages) {
                const sigMatch = message.rawBlock.match(/(?:sigMsg|signalingMsg(?:\[\d+\])?)\s*=\s*([\s\S]*?)(?=\[bin\]|$)/i);
                if (!sigMatch) continue;
                const decoded = decodePossibleHex(sigMatch[1]);
                const cellMatch = decoded.match(/P-Access-Network-Info:[^\n]*utran-cell-id-3gpp=([0-9a-fA-F]+)/i);
                if (cellMatch) {
                    const ecgi = cellMatch[1];
                    const parsed = currentAnalyzer.parseCellId(ecgi);
                    const callKey = (message.callId || 'global-events').toLowerCase();
                    const call = currentAnalyzer.calls.get(callKey) || firstCall;
                    if (call) {
                        call.locations.push({
                            type: 'P-A-N-I-Header (Hex Fallback)',
                            rawData: decoded,
                            parsed,
                            timestamp: message.timestamp || call.startTime || currentAnalyzer.messages?.[0]?.timestamp
                        });
                    }
                }
            }
        }
        if (![...currentAnalyzer.calls.values()].some(call => call.locations.length > 0)) {
            const firstCall = currentAnalyzer.calls.values().next().value;
            const signalMatches = input.matchAll(/signalingMsg\s*=\s*([0-9a-fA-F\s]+)/gi);
            for (const match of signalMatches) {
                const decoded = decodePossibleHex(match[1]);
                const cellMatch = decoded.match(/P-Access-Network-Info:[^\n]*utran-cell-id-3gpp=([0-9a-fA-F]+)/i);
                if (cellMatch && firstCall) {
                    const ecgi = cellMatch[1];
                    const parsed = currentAnalyzer.parseCellId(ecgi);
                    firstCall.locations.push({
                        type: 'P-A-N-I-Header (Hex Fallback)',
                        rawData: decoded,
                        parsed,
                        timestamp: firstCall.startTime || currentAnalyzer.messages?.[0]?.timestamp
                    });
                }
            }
        }
        if (currentAnalyzer.calls.size > 0) {
            const preferredId = choosePreferredCallId(currentAnalyzer.calls);
            const preferredCall = preferredId ? currentAnalyzer.calls.get(preferredId) : currentAnalyzer.calls.values().next().value;
            if (preferredCall && preferredCall.locations.length === 0) {
                const signalMatches = input.matchAll(/(?:sigMsg|signalingMsg(?:\[\d+\])?)\s*=\s*([0-9a-fA-F\s]+)/gi);
                for (const match of signalMatches) {
                    const decoded = decodePossibleHex(match[1]);
                    const cellMatch = decoded.match(/utran-cell-id-3gpp=([0-9a-fA-F]+)/i);
                    if (cellMatch) {
                        const ecgi = cellMatch[1];
                        const parsed = currentAnalyzer.parseCellId(ecgi);
                        preferredCall.locations.push({
                            type: 'P-A-N-I-Header (Preferred Call Fallback)',
                            rawData: decoded,
                            parsed,
                            timestamp: preferredCall.startTime || currentAnalyzer.messages?.[0]?.timestamp
                        });
                    }
                }
            }
        }

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
        const preferredId = choosePreferredCallId(currentAnalyzer.calls);
        if (preferredId) selector.value = preferredId;

        // Build global search index
        globalSearchIndex = buildGlobalSearchIndex(currentAnalyzer, packetData);
        console.log("Search index built successfully");

        // Run call correlation analysis (only if multiple calls)
        if (currentAnalyzer.calls.size > 1) {
            window.callCorrelations = findCallCorrelations(currentAnalyzer.calls, currentAnalyzer);
            console.log("Call correlation analysis complete");
        } else {
            window.callCorrelations = null;
        }

        switchCall(selector.value);

        // Setup search bar handlers
        setTimeout(() => {
            setupSearchBar();
        }, 200);

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

function choosePreferredCallId(calls) {
    if (!calls || calls.size === 0) return null;
    let bestId = null;
    let bestScore = -Infinity;
    for (const [id, call] of calls) {
        let score = 0;
        if (call.startTime) score += 3;
        if (call.callingParty?.phoneNumber) score += 4;
        if (call.callerName) score += 1;
        if (call.callStatus === 'Answered') score += 1;
        if (call.answerTime) score += 2;
        if (call.endTime) score += 1;
        if (score > bestScore) {
            bestScore = score;
            bestId = id;
        }
    }
    return bestId || calls.keys().next().value;
}

function displayResults(call, analyzer) {
    const container = document.getElementById('callDetails');
    const resultsContainer = document.getElementById('resultsContainer');
    resultsContainer.classList.add('active');
    if (leafletMap && (!call.locations.length)) {
        leafletMap.remove();
        leafletMap = null;
        window.map = null;
    }
    const reportControls = document.getElementById('reportControls');
    if (reportControls) reportControls.style.display = 'flex';

    const summaryHTML = `
        <div class="summary-grid">
            <div class="summary-card highlight">
                <h3>Call Overview</h3>
                <div class="info-row"><span class="info-label">Type</span><span class="info-value"><span class="badge badge-info">${call.callType}</span></span></div>
                <div class="info-row"><span class="info-label">Direction</span><span class="info-value"><span class="badge ${call.callDirection === 'Incoming' ? 'badge-success' : 'badge-warning'}">${call.callDirection || 'Unknown'}</span></span></div>
                <div class="info-row"><span class="info-label">Status</span><span class="info-value"><span class="badge badge-success">${call.callStatus || 'Unknown'}</span></span></div>
                <div class="info-row"><span class="info-label">Duration</span><span class="info-value">${analyzer.formatDuration(call.duration)}</span></div>
                <div class="info-row"><span class="info-label">Case ID</span><span class="info-value">${call.caseId || 'N/A'}</span></div>
            </div>
            <div class="summary-card caller">
                <h3>Calling Party (FROM)</h3>
                <div class="info-row"><span class="info-label">Number</span><span class="info-value phone-number">${analyzer.formatPhoneNumber(call.callingParty.phoneNumber)}</span></div>
                <div class="info-row"><span class="info-label">Caller ID</span><span class="info-value caller-name">${call.callerName || 'N/A'}</span></div>
                <div class="info-row"><span class="info-label">STIR/SHAKEN</span><span class="info-value"><span class="badge ${call.verificationStatus?.includes('Passed') ? 'badge-success' : 'badge-warning'}">${call.verificationStatus || 'N/A'}</span></span></div>
                <div class="info-row"><span class="info-label">Carrier</span><span class="info-value">${CDC_CONSTANTS.getCarrier(call.locations[0]?.parsed?.mcc, call.locations[0]?.parsed?.mnc)}</span></div>
            </div>
            <div class="summary-card called">
                <h3>Called Party (TO)</h3>
                <div class="info-row"><span class="info-label">Number</span><span class="info-value phone-number">${analyzer.formatPhoneNumber(call.calledParty.phoneNumber)}</span></div>
                <div class="info-row"><span class="info-label">Carrier</span><span class="info-value">${call.calledParty.uri?.includes('vzims') ? 'Verizon' : 'Lookup Needed'}</span></div>
            </div>
            <div class="summary-card">
                <h3>Key Events</h3>
                <div class="info-row"><span class="info-label">Start</span><span class="info-value">${analyzer.formatTimestamp(call.startTime)}</span></div>
                <div class="info-row"><span class="info-label">Answer</span><span class="info-value">${analyzer.formatTimestamp(call.answerTime)}</span></div>
                <div class="info-row"><span class="info-label">End</span><span class="info-value">${analyzer.formatTimestamp(call.endTime)}</span></div>
            </div>
        </div>`;

    const firstMessageTimestamp = call.messages.length ? analyzer.parseTimestamp(call.messages[0].timestamp) : null;
    const sections = [];
    sections.push(createCollapsibleSection('Call Overview', summaryHTML, true, 'overview'));

    // Add Call Correlation Analysis section (only if multiple calls)
    if (window.callCorrelations && analyzer.calls.size > 1) {
        const correlationHTML = displayCallCorrelations(window.callCorrelations, analyzer);
        sections.push(createCollapsibleSection('Call Correlation Analysis', correlationHTML, true, 'correlation'));
    }

    if (call.messages.length > 0) {
        const flowHTML = `
            <div class="mermaid">
                sequenceDiagram
                    autonumber
                    participant T as Target Device
                    participant C as Carrier Network
                    participant P as Peer
                    ${generateFlowMarkup(call, analyzer, firstMessageTimestamp)}
            </div>`;
        sections.push(createCollapsibleSection('Call Flow Diagram', flowHTML, true, 'callFlow'));
    }

    if (call.locations.length > 0) {
        const locationHTML = `
            <p class="sub-heading-note">⚠️ These are estimated visual markers—please verify externally.</p>
            <div id="map" style="height: 400px; border-radius: 8px; border: 1px solid var(--border-color); margin-bottom: 20px;"></div>
            <div class="location-grid">
                    ${call.locations.map(loc => {
            const compositeKey = `${loc.parsed.lac}-${loc.parsed.cellId}`;
            const fullKey = normalizeFullCellId(loc.parsed.fullCellId);
            const shortKey = normalizeShortCellId(loc.parsed.fullCellId);
            let tower = towerDatabase.get(compositeKey);
            if (!tower && fullKey) tower = towerDatabaseFullId.get(fullKey);
            if (!tower && shortKey) tower = towerDatabaseShortId.get(shortKey);
            const lacDecimal = getDecimalValue(loc.parsed.lac);
            const cellDecimal = getDecimalValue(loc.parsed.cellId);
            const openCellLink = (lacDecimal !== null && cellDecimal !== null)
                ? `https://opencellid.org/#action=locations.search&mcc=${loc.parsed.mcc}&mnc=${loc.parsed.mnc}&lac=${lacDecimal}&cellid=${cellDecimal}`
                : '#';
            return `
                    <div class="location-item" style="${tower ? 'border-left: 5px solid var(--success-color);' : ''}">
                        <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                            <div>
                                <strong>${loc.type}</strong> ${tower ? '<span class="badge badge-success" style="font-size: 0.6rem;">Matched</span>' : ''}<br>
                                <small>${analyzer.formatTimestamp(loc.timestamp)}</small>
                            </div>
                            <a href="${openCellLink}"
                               ${openCellLink !== '#' ? 'target="_blank"' : ''}
                               class="btn-secondary" style="font-size: 0.7rem; padding: 4px 8px; text-decoration: none;">
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
                    </div>`;
        }).join('')}
            </div>`;
        sections.push(createCollapsibleSection('Cell Tower Mapping', locationHTML, true, 'mapping'));
    }

    if (call.smsData.length > 0) {
        const smsHTML = `
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
            </div>`;
        sections.push(createCollapsibleSection('SMS/MMS Messages', smsHTML, false, 'sms'));
    }

    const techHTML = `
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
        </div>`;
    sections.push(createCollapsibleSection('Technical Message Timeline', techHTML, true, 'tech'));

    // Add Interactive Timeline Visualization
    const hasPacketData = (typeof packetData !== 'undefined' && packetData.length > 0);
    const timelineHTML = renderTimelineVisualization(call, analyzer, {
        includePackets: hasPacketData
    });
    sections.push(createCollapsibleSection('Interactive Timeline', timelineHTML, true, 'timeline'));

    const rawHTML = `
        <div class="technical-section">
            <h3>Raw CDC Records</h3>
            <div class="raw-export">
                ${call.messages.map(msg => `
                   <div class="raw-record">
                       <pre>${msg.rawBlock}</pre>
                   </div>
                `).join('<hr>')}
            </div>
        </div>`;
    sections.push(createCollapsibleSection('Raw CDC Records', rawHTML, false, 'raw'));

    // Add global search bar at the top
    const searchBarHTML = `
        <div class="global-search-bar">
            <input type="text" id="globalSearchInput" placeholder="Search phone numbers, IPs, keywords, locations..." class="search-input">
            <button id="globalSearchButton" class="btn-primary">Search</button>
            <button id="globalSearchClear" class="btn-secondary">Clear</button>
        </div>
        <div id="searchResultsContainer" class="search-results-container" style="display: none;"></div>
    `;

    container.innerHTML = searchBarHTML + sections.join('');
    setupCollapsibles();

    setTimeout(() => {
        if (typeof mermaid !== 'undefined') {
            try {
                mermaid.init();
            } catch (e) { console.error("Mermaid init failed", e); }
        }
        if (call.locations.length > 0) initMap(call.locations);

        // Setup timeline event handlers
        setupTimelineEventHandlers();
    }, 100);
}

function createCollapsibleSection(title, content, isOpen = false, idSuffix = '') {
    const key = idSuffix || title.toLowerCase().replace(/[^\w]+/g, '-');
    const arrow = isOpen ? '▼' : '▶';
    return `
        <section class="collapsible-section ${isOpen ? 'expanded' : 'collapsed'}">
            <div class="collapsible-header">
                <button type="button" class="collapse-toggle" aria-expanded="${isOpen}" data-target="${key}">${arrow}</button>
                <span class="collapsible-title">${title}</span>
            </div>
            <div class="collapsible-content" data-content="${key}" style="display:${isOpen ? 'block' : 'none'};">
                ${content}
            </div>
        </section>
    `;
}

function setupCollapsibles() {
    document.querySelectorAll('.collapse-toggle').forEach(btn => {
        if (btn.dataset.listenerAttached) return;
        btn.dataset.listenerAttached = 'true';
        btn.addEventListener('click', () => {
            const target = btn.dataset.target;
            const content = document.querySelector(`.collapsible-content[data-content="${target}"]`);
            if (!content) return;
            const isOpen = btn.getAttribute('aria-expanded') === 'true';
            btn.setAttribute('aria-expanded', String(!isOpen));
            btn.textContent = isOpen ? '▶' : '▼';
            content.style.display = isOpen ? 'none' : 'block';
            const section = btn.closest('.collapsible-section');
            if (section) {
                section.classList.toggle('expanded', !isOpen);
                section.classList.toggle('collapsed', isOpen);
            }
        });
    });
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
    const raw = value ? value.toString().trim() : '';
    if (raw) variants.add(raw);
    const normalized = normalizeFullCellId(value);
    if (!normalized) return variants;
    variants.add(normalized);
    variants.add(normalized.toUpperCase());
    if (/^\d{6}/.test(normalized)) {
        const mccmnc = normalized.slice(0, 6);
        const tail = normalized.slice(6);
        if (tail) {
            const dash = `${mccmnc}-${tail}`;
            const dot = `${mccmnc}.${tail}`;
            variants.add(dash);
            variants.add(dot);
            variants.add(dash.toUpperCase());
            variants.add(dot.toUpperCase());
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

function normalizeEcgiForCloud(value) {
    return normalizeFullCellId(value);
}

function generateFlowMarkup(call, analyzer, baseTimestamp) {
    let markup = "";
    call.messages.forEach(msg => {
        const relTime = getRelativeTimeSuffix(analyzer, baseTimestamp, msg.timestamp);
        switch (msg.type) {
            case 'termAttempt':
                markup += `Note over T,P: Incoming Call Attempt\n`;
                markup += `P->>C: Setup Request\n`;
                markup += `C->>T: termAttempt${relTime}\n`;
                break;
            case 'origAttempt':
                markup += `Note over T,P: Outgoing Call Attempt\n`;
                markup += `T->>C: origAttempt\n`;
                markup += `C->>P: Setup Request${relTime}\n`;
                break;
            case 'directSignalReporting':
                const sip = msg.data.sipMessages?.[0]?.parsed;
                if (sip) {
                    if (sip.isRequest) markup += `T->>C: SIP ${sip.method}${relTime}\n`;
                    else markup += `C-->>T: SIP ${sip.statusCode} ${sip.statusText}${relTime}\n`;
                }
                break;
            case 'ccOpen': markup += `C-->>T: ccOpen (Audio Path Open)${relTime}\n`; break;
            case 'ccClose': markup += `C-->>T: ccClose (Audio Path Closed)${relTime}\n`; break;
            case 'answer':
                markup += `Note right of T: Call Answered\n`;
                markup += `T->>C: answer${relTime}\n`;
                markup += `C->>P: Answer Response${relTime}\n`;
                break;
            case 'release':
                markup += `Note over T,P: Call Released (${msg.data.cause || 'Normal'})\n`;
                markup += `T->>C: release${relTime}\n`;
                markup += `C->>P: Release Notification${relTime}\n`;
                break;
            case 'smsMessage':
            case 'mmsMessage':
                if (msg.data.direction === 'Sent') {
                    markup += `T->>C: ${msg.type} (To: ${msg.data.to})${relTime}\n`;
                    markup += `C->>P: Forward message${relTime}\n`;
                } else {
                    markup += `P->>C: Incoming ${msg.type}${relTime}\n`;
                    markup += `C->>T: ${msg.type} (From: ${msg.data.from})${relTime}\n`;
                }
                break;
        }
    });
    return markup;
}

function getRelativeTimeSuffix(analyzer, baseTimestamp, messageTimestamp) {
    if (!baseTimestamp || !messageTimestamp) return '';
    const current = analyzer.parseTimestamp(messageTimestamp);
    if (!current) return '';
    const deltaMs = current.getTime() - baseTimestamp.getTime();
    if (Number.isNaN(deltaMs) || deltaMs < 0) return '';
    const totalSeconds = Math.floor(deltaMs / 1000);
    const minutes = Math.floor(totalSeconds / 60).toString().padStart(2, '0');
    const seconds = (totalSeconds % 60).toString().padStart(2, '0');
    return ` [+${minutes}:${seconds}]`;
}

function initMap(locations) {
    if (locations.length === 0 || typeof L === 'undefined') return;

    try {
        if (leafletMap) {
            leafletMap.remove();
            leafletMap = null;
            window.map = null;
        }
        sectorLayers.forEach(layer => layer.remove?.());
        sectorLayers = [];
        const baseLat = 40.7128;
        const baseLng = -74.0060;
        const map = L.map('map', { scrollWheelZoom: false });
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors'
        }).addTo(map);
        leafletMap = map;
        window.map = map;

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
                const lacDecimal = getDecimalValue(loc.parsed.lac) || 0;
                const cellDecimal = getDecimalValue(loc.parsed.cellId) || 0;
                const latOffset = (lacDecimal % 100) / 500;
                const lngOffset = (cellDecimal % 100) / 500;
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
            if (tower) {
                try {
            const sectorLayer = createSectorLayer(tower, lat, lng);
            if (sectorLayer) {
                sectorLayer.addTo(map);
                sectorLayers.push(sectorLayer);
            }
                } catch (err) {
                    console.error("Sector layer render failed", err);
                }
            }
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

function createSectorLayer(tower, lat, lng) {
    const azimuth = Number.isFinite(tower.azimuth) ? tower.azimuth : null;
    if (azimuth === null) return null;
    const beamWidth = Number.isFinite(tower.beamWidth) ? tower.beamWidth : SECTOR_DEFAULT_BEAM_WIDTH;
    const radiusMeters = Number.isFinite(tower.sectorRadiusMeters) ? tower.sectorRadiusMeters : SECTOR_DEFAULT_RADIUS_METERS;
    if (radiusMeters <= 0) return null;

    const polygonPoints = buildSectorPolygon(lat, lng, azimuth, beamWidth, radiusMeters);
    if (polygonPoints.length < 3) return null;

    const tooltipLines = [];
    if (tower.sectorName) tooltipLines.push(tower.sectorName);
    tooltipLines.push(`Azimuth: ${azimuth.toFixed(0)}°`);
    tooltipLines.push(`Beam: ${beamWidth.toFixed(0)}°`);

    const polygon = L.polygon(polygonPoints, {
        color: '#2b6cb0',
        fillColor: '#2b6cb0',
        fillOpacity: 0.12,
        weight: 1.2,
        dashArray: '6',
        interactive: false
    });
    polygon.bindTooltip(tooltipLines.join(' | '), { permanent: false, direction: 'top' });

    const arcPoints = buildSectorArc(lat, lng, azimuth, beamWidth, radiusMeters);
    const layerGroup = L.layerGroup([polygon]);

    if (arcPoints.length > 0) {
        const arcLayer = L.polyline(arcPoints, {
            color: '#c05621',
            weight: 3,
            dashArray: '10,6',
            opacity: 0.85,
            lineCap: 'round'
        });
        layerGroup.addLayer(arcLayer);
    }

    return layerGroup;
}

function buildSectorPolygon(lat, lng, azimuth, beamWidth, radiusMeters) {
    const points = [];
    const normalizedBeam = Math.max(5, Math.min(beamWidth, 180));
    const stepCount = Math.max(6, Math.ceil(Math.abs(normalizedBeam) / 5));
    const halfBeam = normalizedBeam / 2;
    for (let i = 0; i <= stepCount; i++) {
        const offset = (i / stepCount) * normalizedBeam;
        const angle = (azimuth - halfBeam + offset + 360) % 360;
        const dest = destinationPoint(lat, lng, radiusMeters, angle);
        if (dest && Number.isFinite(dest.lat) && Number.isFinite(dest.lon)) {
            points.push([dest.lat, dest.lon]);
        }
    }
    if (!points.length) return [];
    // Close the cone by returning to center
    points.unshift([lat, lng]);
    points.push([lat, lng]);
    return points;
}

function buildSectorArc(lat, lng, azimuth, beamWidth, radiusMeters) {
    const points = [];
    const normalizedBeam = Math.max(5, Math.min(beamWidth, 180));
    const stepCount = Math.max(12, Math.ceil(Math.abs(normalizedBeam) / 5));
    const halfBeam = normalizedBeam / 2;
    for (let i = 0; i <= stepCount; i++) {
        const offset = (i / stepCount) * normalizedBeam;
        const angle = (azimuth - halfBeam + offset + 360) % 360;
        const dest = destinationPoint(lat, lng, radiusMeters, angle);
        if (dest && Number.isFinite(dest.lat) && Number.isFinite(dest.lon)) {
            points.push([dest.lat, dest.lon]);
        }
    }
    return points;
}

function destinationPoint(lat, lng, distanceMeters, bearingDegrees) {
    const radiusEarth = 6371000;
    const delta = distanceMeters / radiusEarth;
    const theta = bearingDegrees * Math.PI / 180;
    const phi1 = lat * Math.PI / 180;
    const lambda1 = lng * Math.PI / 180;
    const sinPhi2 = Math.sin(phi1) * Math.cos(delta) + Math.cos(phi1) * Math.sin(delta) * Math.cos(theta);
    const phi2 = Math.asin(Math.min(1, Math.max(-1, sinPhi2)));
    const y = Math.sin(theta) * Math.sin(delta) * Math.cos(phi1);
    const x = Math.cos(delta) - Math.sin(phi1) * Math.sin(phi2);
    const lambda2 = lambda1 + Math.atan2(y, x);
    return { lat: phi2 * 180 / Math.PI, lon: (lambda2 * 180 / Math.PI + 540) % 360 - 180 };
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
        cid: headers.findIndex(h => h === 'cell id' || h === 'cellid' || h.includes('cell identifier') || h === 'cell_id' || h === 'eci' || h === 'ci'),
        cgi: headers.findIndex(h => h === 'cgi' || h.includes('cell global id')),
        lat: headers.findIndex(h => h === 'lat' || h.includes('latitude') || h === 'y' || h === 'site_latitude' || h === 'sector_latitude'),
        lon: headers.findIndex(h => h === 'lon' || h.includes('longitude') || h === 'x' || h === 'site_longitude' || h === 'sector_longitude'),
        address: headers.findIndex(h => h === 'address' || h.includes('street') || h.includes('location') || h === 'site_address'),
        market: headers.findIndex(h => h === 'market' || h === 'market_name'),
        siteId: headers.findIndex(h => h === 'site' || h === 'site id' || h === 'site_id' || h === 'enodeb_id' || h === 'site_id'),
        azimuth: findHeaderIndex(['azimuth', 'bearing', 'sector azimuth', 'sectorbearing']),
        beamWidth: findHeaderIndex(['beamwidth', 'beam width', 'sector width', 'sectorbeam', 'sector beamwidth', 'beam']),
        radius: findHeaderIndex(['radius', 'range', 'coverage radius', 'sector radius', 'beam radius', 'sector range']),
        sectorName: findHeaderIndex(['sector', 'sector name', 'panel', 'sectorid']),
        ecgi: findHeaderIndex(['ecgi', 'full cell id', 'cell global id'])
    };

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
        const lat = colIdx.lat !== -1 ? parseFloat(row[colIdx.lat]) : null;
        const lon = colIdx.lon !== -1 ? parseFloat(row[colIdx.lon]) : null;
        const address = colIdx.address !== -1 ? row[colIdx.address] : null;
        const azimuthVal = colIdx.azimuth !== -1 ? parseFloat(row[colIdx.azimuth]) : null;
        const beamVal = colIdx.beamWidth !== -1 ? parseFloat(row[colIdx.beamWidth]) : null;
        const radiusVal = colIdx.radius !== -1 ? parseFloat(row[colIdx.radius]) : null;
        const nameVal = colIdx.sectorName !== -1 ? row[colIdx.sectorName] : null;
        const ecgiVal = colIdx.ecgi !== -1 ? row[colIdx.ecgi] : null;

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
                siteId: colIdx.siteId !== -1 ? row[colIdx.siteId] : null,
                azimuth: Number.isFinite(azimuthVal) ? azimuthVal : null,
                beamWidth: Number.isFinite(beamVal) ? beamVal : null,
                sectorRadiusMeters: Number.isFinite(radiusVal) ? radiusVal : null,
                sectorName: nameVal ? nameVal : null,
                ecgi: ecgiVal ? ecgiVal.toLowerCase() : null,
                ecgi_norm: normalizeEcgiForCloud(ecgiVal)
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
        console.warn("Supabase not initialized. Cannot sync.");
        return;
    }

    const syncBtn = document.getElementById('syncBtn');
    if (syncBtn) {
        syncBtn.textContent = "Syncing...";
        syncBtn.disabled = true;
    }
    const towerStatus = document.getElementById('towerStatus');

    try {
        const { needed = new Set(), neededLacs = new Set(), neededEcgi = new Set() } = collectNeededTowerKeys() || {};
        if (needed.size === 0 && neededLacs.size === 0 && neededEcgi.size === 0) {
            const storageBlocked = !canUseLocalStorage();
            towerStatus.textContent = storageBlocked
                ? "Cloud sync skipped: browser storage blocked. Load CSV locally or allow storage."
                : "No referenced towers found in logs. Upload CSV for local data or load a log first.";
            console.warn("Skipping tower sync: no LAC/CID references detected.");
            return;
        }

        const lacList = Array.from(new Set([
            ...neededLacs,
            ...[...needed].map(key => key.split('-')[0])
        ]));
        let data = [];
        let error = null;
        let usedEcgiLookup = false;
        if (lacList.length > 0) {
            towerStatus.textContent = `Syncing ${lacList.length} LAC(s) from cloud...`;
            const resp = await supabaseClient
                .from('towers')
                .select('*')
                .in('lac', lacList);
            data = resp.data || [];
            error = resp.error;
        }
        if ((!data || data.length === 0) && neededEcgi.size > 0) {
            const ecgiList = Array.from(neededEcgi);
            const normList = ecgiList.map(val => normalizeEcgiForCloud(val)).filter(Boolean);
            towerStatus.textContent = `Syncing ${ecgiList.length} ECGI(s) from cloud...`;
            console.log("ECGI lookup list (first 10):", ecgiList.slice(0, 10));
            const resp = await supabaseClient
                .from('towers')
                .select('*')
                .in('ecgi_norm', Array.from(new Set(normList)));
            data = resp.data || [];
            error = resp.error;
            usedEcgiLookup = true;
        }

        if (error) throw error;

        if (data && data.length > 0) {
            let loaded = 0;
            data.forEach(row => {
                const key = `${row.lac}-${row.cid}`;
                if (usedEcgiLookup || needed.size === 0 || needed.has(key)) {
                    towerDatabase.set(key, {
                        lat: row.lat,
                        lon: row.lon,
                        address: row.address,
                        market: row.market,
                        siteId: row.site_id,
                        azimuth: row.azimuth,
                        beamWidth: row.beamwidth,
                        sectorRadiusMeters: row.radius,
                        sectorName: row.sector
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
                    loaded++;
                }
            });

            towerStatus.innerHTML = `<span style="color: var(--success-color); font-weight: 600;">✓ ${loaded} towers synced from Cloud</span>`;
            console.log(`Synced ${loaded} towers from Supabase (targeted).`);
            console.log("Cloud sync keys:", {
                needed: needed.size,
                neededLacs: neededLacs.size,
                neededEcgi: neededEcgi.size,
                fetched: data.length
            });

            if (currentAnalyzer && refreshAfter) {
                analyzeCDC({ skipTowerSync: true });
            }
        } else {
            towerStatus.textContent = "No matching towers found in cloud (LAC/ECGI).";
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

function collectNeededTowerKeys() {
    const needed = new Set();
    const neededLacs = new Set();
    const neededEcgi = new Set();
    if (!currentAnalyzer) return { needed, neededLacs, neededEcgi };
    currentAnalyzer.calls.forEach(call => {
        for (const loc of call.locations) {
            let lac = loc.parsed?.lac;
            let cellId = loc.parsed?.cellId;
            const fullCellId = loc.parsed?.fullCellId;
            if ((lac === null || lac === undefined) && loc.parsed?.fullCellId) {
                const parsed = currentAnalyzer.parseCellId(loc.parsed.fullCellId);
                lac = parsed?.lac ?? lac;
                cellId = parsed?.cellId ?? cellId;
            }
            if (lac !== null && lac !== undefined) {
                neededLacs.add(String(lac));
            }
            if (lac !== null && lac !== undefined && cellId !== null && cellId !== undefined) {
                needed.add(`${lac}-${cellId}`);
            }
            if (fullCellId) {
                const fullKey = normalizeFullCellId(fullCellId);
                const shortKey = normalizeShortCellId(fullCellId);
                if (fullKey) buildEcgiVariants(fullKey).forEach(v => neededEcgi.add(v));
                if (shortKey) buildEcgiVariants(shortKey).forEach(v => neededEcgi.add(v));
            }
        }
    });
    if (neededLacs.size === 0 && currentAnalyzer.rawData) {
        const matches = currentAnalyzer.rawData.matchAll(/utran-cell-id-3gpp=([0-9a-fA-F]+)/gi);
        for (const match of matches) {
            const ecgi = match[1];
            const parsed = currentAnalyzer.parseCellId(ecgi);
            const lac = parsed?.lac ?? deriveTacFromEcgi(ecgi);
            const cellId = parsed?.cellId ?? null;
            if (lac !== null && lac !== undefined) {
                neededLacs.add(String(lac));
            }
            if (lac !== null && lac !== undefined && cellId !== null && cellId !== undefined) {
                needed.add(`${lac}-${cellId}`);
            }
            const fullKey = normalizeFullCellId(ecgi);
            const shortKey = normalizeShortCellId(ecgi);
            if (fullKey) buildEcgiVariants(fullKey).forEach(v => neededEcgi.add(v));
            if (shortKey) buildEcgiVariants(shortKey).forEach(v => neededEcgi.add(v));
        }
    }
    return { needed, neededLacs, neededEcgi };
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
                ecgi: val.ecgi || `${lac}-${cid}`,
                ecgi_norm: normalizeEcgiForCloud(val.ecgi || `${lac}-${cid}`),
                lat: val.lat,
                lon: val.lon,
                address: val.address,
                market: val.market,
                site_id: val.siteId,
                azimuth: val.azimuth ?? null,
                beamwidth: val.beamWidth ?? null,
                radius: val.sectorRadiusMeters ?? null,
                sector: val.sectorName ?? null
            });
        });

        const BATCH_SIZE = 500;
        let uploaded = 0;
        const withEcgi = [];
        const withoutEcgi = [];

        allRows.forEach(row => {
            if (row.ecgi) withEcgi.push(row);
            else withoutEcgi.push(row);
        });

        const uploadChunks = async (rows, onConflict, label) => {
            for (let i = 0; i < rows.length; i += BATCH_SIZE) {
                const rawChunk = rows.slice(i, i + BATCH_SIZE);
                const chunkMap = new Map();
                rawChunk.forEach(row => {
                    const key = onConflict === 'ecgi' ? row.ecgi : `${row.lac}-${row.cid}`;
                    chunkMap.set(key, row);
                });
                const uniqueChunk = Array.from(chunkMap.values());
                towerStatus.textContent = `Uploading ${label}... (${Math.min(i + uniqueChunk.length, rows.length)} / ${rows.length})`;

                const { error } = await supabaseClient.from('towers').upsert(uniqueChunk, { onConflict });
                if (error) throw error;
                uploaded += uniqueChunk.length;
            }
        };

        if (withEcgi.length > 0) {
            await uploadChunks(withEcgi, 'ecgi', 'ECGI');
        }
        if (withoutEcgi.length > 0) {
            await uploadChunks(withoutEcgi, 'lac,cid', 'LAC/CID');
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

    const results = document.getElementById('resultsContainer');
    const callSelector = document.getElementById('callSelectorContainer');
    const callSelectorSelect = document.getElementById('callSelector');
    const callDetails = document.getElementById('callDetails');
    const packetResults = document.getElementById('packetResults');

    // Special handling for map resize when switching to analyzer
    if (tabId === 'analyzerTab') {
        setTimeout(() => {
            if (window.map) window.map.invalidateSize();
        }, 100);
    }

    if (tabId === 'packetTab') {
        if (results) results.style.display = '';
        if (callSelector) callSelector.style.display = 'none';
        if (callDetails) callDetails.style.display = 'none';
        if (packetResults) {
            packetResults.style.display = packetData.length ? 'block' : 'none';
        }
    } else if (tabId === 'analyzerTab') {
        if (results) results.style.display = '';
        if (callDetails) callDetails.style.display = '';
        if (callSelector) {
            const hasOptions = callSelectorSelect && callSelectorSelect.options && callSelectorSelect.options.length > 0;
            callSelector.style.display = hasOptions ? 'flex' : 'none';
        }
        if (packetResults) packetResults.style.display = 'none';
    } else {
        if (results) results.style.display = 'none';
        if (packetResults) packetResults.style.display = 'none';
    }

    // Check database connection when switching to packet tab
    if (tabId === 'packetTab') {
        const warningEl = document.getElementById('dbNotConnectedWarning');
        if (warningEl) {
            warningEl.style.display = supabaseClient ? 'none' : 'block';
        }
    }
}

// =====================================
// PACKET ANALYSIS FUNCTIONALITY
// =====================================

let packetData = [];
let ipWhoisCache = {};
let ipWhoisNameCache = {};
let packetTargetFilter = 'All';
let reverseDnsCache = {};
let lastPacketAnalysis = null;
let reverseDnsStats = { attempted: false, found: 0, total: 0, cached: 0, lookupErrors: 0, upsertErrors: 0 };

// Known IP ranges for common services
const IP_RANGES = {
    facebook: ['2a03:2880:', '157.240.', '31.13.', '66.220.', '69.63.', '69.171.', '173.252.', '179.60.'],
    instagram: ['2a03:2880:', '157.240.', '31.13.'],
    whatsapp: ['2a03:2880:', '157.240.', '31.13.', '18.194.', '34.', '50.22.'],
    apple: ['2620:149:', '17.', '2a01:b740:'],
    google: ['2607:f8b0:', '2001:4860:', '142.250.', '172.217.', '216.58.', '8.8.'],
    microsoft: ['2603:', '2620:1ec:', '13.', '20.', '40.', '52.', '104.'],
    telegram: ['2001:67c:4e8:', '91.108.', '149.154.', '95.161.'],
    signal: ['142.250.', '2001:4860:'],
    tiktok: ['2a04:4e42:', '2606:4700:'],
    snapchat: ['35.186.', '104.154.', '34.', '2600:1900:'],
    twitter: ['2606:1f80:', '104.244.', '192.133.', '199.16.', '199.59.'],
    netflix: ['2606:2800:', '2a00:86c0:', '23.246.', '37.77.', '45.57.', '198.38.', '208.75.'],
    amazon: ['2600:1f', '2600:9000:', '52.', '54.', '205.251.', '176.32.'],
    cloudflare: ['2606:4700:', '2803:f800:', '104.16.', '172.64.', '173.245.'],
    verizon: ['2001:4888:', '206.124.', '69.78.'],
    tmobile: ['2607:fb90:', '2607:fb91:', '208.54.'],
    att: ['2600:1700:', '2600:380:', '12.', '99.'],
    // Banking and Financial Services
    bankofamerica: ['171.161.', '209.86.', '159.53.'],
    chase: ['159.53.', '205.219.', '216.150.'],
    wellsfargo: ['159.45.', '206.112.', '206.180.'],
    paypal: ['64.4.', '66.211.', '173.0.'],
    venmo: ['64.4.', '66.211.', '173.0.'],
    cashapp: ['104.16.', '172.64.'], // Uses Cloudflare
    zelle: ['159.53.', '205.219.'], // Often via bank apps
    coinbase: ['104.18.', '172.66.', '104.16.'],
    robinhood: ['52.', '54.', '35.'],
    // Additional messaging/communication
    discord: ['2606:4700:', '104.16.', '162.159.'],
    slack: ['52.', '54.', '99.', '107.23.'],
    zoom: ['3.', '13.', '18.', '50.', '2600:1f'],
    skype: ['13.', '20.', '40.', '52.', '104.'],
    // Email services
    gmail: ['2607:f8b0:', '2001:4860:', '142.250.', '172.217.'],
    outlook: ['2603:', '13.', '20.', '40.', '52.'],
    yahoo: ['2001:4998:', '66.94.', '67.195.', '68.142.', '98.136.', '209.191.'],
    // Other popular services
    spotify: ['35.186.', '104.199.', '2600:1900:'],
    uber: ['2600:1f', '52.', '54.'],
    lyft: ['52.', '54.', '35.'],
    doordash: ['52.', '54.', '35.'],
    instacart: ['52.', '54.', '35.'],
};

// Common ports and services
const PORT_SERVICES = {
    20: 'FTP Data',
    21: 'FTP Control',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP (Email)',
    67: 'DHCP Server',
    68: 'DHCP Client',
    69: 'TFTP',
    88: 'Kerberos',
    110: 'POP3 (Email)',
    119: 'NNTP',
    123: 'NTP',
    135: 'MS RPC',
    137: 'NetBIOS Name Service',
    138: 'NetBIOS Datagram Service',
    139: 'NetBIOS Session Service',
    143: 'IMAP (Email)',
    161: 'SNMP',
    162: 'SNMP Trap',
    179: 'BGP',
    389: 'LDAP',
    445: 'SMB/CIFS',
    53: 'DNS',
    80: 'HTTP',
    443: 'HTTPS',
    465: 'SMTPS (Secure Email)',
    514: 'Syslog',
    587: 'SMTP Submission',
    636: 'LDAPS',
    993: 'IMAPS (Secure Email)',
    995: 'POP3S (Secure Email)',
    3306: 'MySQL',
    3389: 'RDP',
    1433: 'MSSQL',
    1521: 'Oracle DB',
    2049: 'NFS',
    5432: 'PostgreSQL',
    5900: 'VNC',
    5060: 'SIP (VoIP)',
    5061: 'SIP-TLS (Secure VoIP)',
    5223: 'Apple Push Notification / XMPP',
    5228: 'Google Cloud Messaging',
    5242: 'Viber',
    8080: 'HTTP Alternate',
    8443: 'HTTPS Alternate',
};

const PORT_SERVICE_DESCRIPTIONS = {
    20: 'FTP data channel used for actual file transfers in classic FTP sessions; control commands are on port 21.',
    21: 'FTP control channel for authentication and file operation commands; actual data transfers use port 20 or negotiated passive ports.',
    22: 'SSH provides encrypted remote login, command execution, and tunneling; commonly used for secure admin access.',
    23: 'Telnet is a legacy remote login protocol that sends data in cleartext and is generally considered insecure.',
    25: 'SMTP is used to relay email between servers; it is typically not used for end‑user submission.',
    53: 'DNS resolves hostnames to IP addresses and handles reverse lookups; used by both UDP and TCP.',
    67: 'DHCP server port used to offer and lease IP addresses to clients on a network.',
    68: 'DHCP client port used by devices to request and renew IP addresses from DHCP servers.',
    69: 'TFTP is a simple, unauthenticated file transfer protocol often used for device bootstrapping.',
    88: 'Kerberos authentication protocol for secure ticket‑based identity and service access.',
    110: 'POP3 is a legacy email retrieval protocol that downloads messages to the client.',
    119: 'NNTP is used for Usenet news distribution and client access to newsgroups.',
    123: 'NTP synchronizes device clocks for accurate timekeeping and log correlation.',
    135: 'Microsoft RPC endpoint mapper used by Windows services to discover dynamic RPC ports.',
    137: 'NetBIOS name service used for name registration and discovery on legacy Windows networks.',
    138: 'NetBIOS datagram service used for connectionless communications on legacy Windows networks.',
    139: 'NetBIOS session service used for file and printer sharing on legacy Windows networks.',
    143: 'IMAP provides server‑side email access and folder synchronization for clients.',
    161: 'SNMP is used to query and monitor network devices such as routers, switches, and servers.',
    162: 'SNMP trap port used by devices to send unsolicited alerts to monitoring systems.',
    179: 'BGP is the core routing protocol used between autonomous systems on the internet.',
    389: 'LDAP is used for directory services (users, groups, devices) and enterprise identity queries.',
    445: 'SMB/CIFS provides Windows file sharing, authentication, and related services.',
    80: 'HTTP is standard unencrypted web traffic for websites and APIs.',
    443: 'HTTPS is encrypted web traffic (TLS) for websites, APIs, and secure services.',
    465: 'SMTPS is SMTP over implicit TLS for secure email submission.',
    514: 'Syslog is used to transmit system and security logs to centralized log servers.',
    587: 'SMTP submission port for authenticated client email sending (STARTTLS).',
    636: 'LDAPS is LDAP over TLS for secure directory queries and authentication.',
    993: 'IMAPS is IMAP over TLS for secure email access.',
    995: 'POP3S is POP3 over TLS for secure email retrieval.',
    3306: 'MySQL database service port for client connections.',
    3389: 'RDP provides remote desktop access to Windows systems.',
    1433: 'Microsoft SQL Server database service port.',
    1521: 'Oracle database listener port for client connections.',
    2049: 'NFS provides network file sharing commonly on UNIX/Linux systems.',
    5432: 'PostgreSQL database service port.',
    5900: 'VNC provides remote desktop control, often for cross‑platform access.',
    5060: 'SIP is used for VoIP call signaling and session setup (unencrypted).',
    5061: 'SIP‑TLS is encrypted SIP signaling for VoIP sessions.',
    5223: 'Apple Push Notification service and related messaging traffic.',
    5228: 'Google Cloud Messaging / FCM legacy port for push notifications.',
    5242: 'Viber messaging and signaling port used by the client.',
    8080: 'Alternate HTTP port commonly used by proxies or internal web services.',
    8443: 'Alternate HTTPS port commonly used by web apps and management consoles.'
};

function handlePacketUpload(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const csvText = e.target.result;
            parsePacketCSV(csvText);
        } catch (error) {
            document.getElementById('packetStatus').innerHTML =
                `<span style="color: var(--danger-color);">Error: ${error.message}</span>`;
        }
    };
    reader.readAsText(file);
}

function parsePacketCSV(csvText) {
    const lines = csvText.trim().split('\n');
    if (lines.length < 2) {
        throw new Error('CSV file is empty or invalid');
    }

    // Remove BOM if present
    const headerLine = lines[0].replace(/^\uFEFF/, '');
    const headers = parseCSVLine(headerLine);

    packetData = [];
    for (let i = 1; i < lines.length; i++) {
        const values = parseCSVLine(lines[i]);
        if (values.length === headers.length) {
            const row = {};
            headers.forEach((header, idx) => {
                row[header] = values[idx];
            });
            packetData.push(row);
        }
    }

    document.getElementById('packetStatus').innerHTML =
        `<span style="color: var(--success-color);">✓ Loaded ${packetData.length} packet records</span>`;

    analyzePacketData();
}

function parseCSVLine(line) {
    const result = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
        const char = line[i];
        if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
            result.push(current);
            current = '';
        } else {
            current += char;
        }
    }
    result.push(current);
    return result;
}

function analyzePacketData() {
    if (packetData.length === 0) return;

    const filteredPackets = packetData.filter(packet => {
        if (!packetTargetFilter || packetTargetFilter === 'All') return true;
        const target = packet['Target'] || packet['Target Address'] || '';
        return target === packetTargetFilter;
    });

    // Analyze IPs and services
    const ipAnalysis = {};
    const serviceStats = {};
    const portStats = {};
    const appDetection = {};
    const destinationStats = {};
    const timelineStats = {};
    const durationStats = {
        all: [],
        byProtocol: {}
    };

    filteredPackets.forEach(packet => {
        const srcIP = packet['Source Address'];
        const dstIP = packet['Destination Address'];
        const srcPort = packet['Source Port'];
        const protocol = packet['Session Protocol'] || packet['Transport Protocol'];
        const bytes = parseInt(packet['Bytes']) || 0;
        const effectivePort = srcPort;
        const durationSeconds = parseDurationToSeconds(packet['Duration']);
        const startTime = packet['Start Time'] || packet['StartTime'] || '';

        // Analyze source IP
        if (srcIP && srcIP !== '' && !srcIP.startsWith('fd00:')) {
            if (!ipAnalysis[srcIP]) {
                ipAnalysis[srcIP] = {
                    packets: 0,
                    bytes: 0,
                    ports: new Set(),
                    service: identifyService(srcIP, effectivePort),
                    protocols: new Set()
                };
            }
            ipAnalysis[srcIP].packets++;
            ipAnalysis[srcIP].bytes += bytes;
            if (effectivePort) ipAnalysis[srcIP].ports.add(effectivePort);
            if (protocol) ipAnalysis[srcIP].protocols.add(protocol);
        }

        // Analyze destination IP
        if (dstIP && dstIP !== '' && !dstIP.startsWith('fd00:')) {
            if (!ipAnalysis[dstIP]) {
                ipAnalysis[dstIP] = {
                    packets: 0,
                    bytes: 0,
                    ports: new Set(),
                    service: identifyService(dstIP, effectivePort),
                    protocols: new Set()
                };
            }
            ipAnalysis[dstIP].packets++;
            ipAnalysis[dstIP].bytes += bytes;
            if (effectivePort) ipAnalysis[dstIP].ports.add(effectivePort);
            if (protocol) ipAnalysis[dstIP].protocols.add(protocol);

            if (!destinationStats[dstIP]) {
                destinationStats[dstIP] = { packets: 0, bytes: 0 };
            }
            destinationStats[dstIP].packets++;
            destinationStats[dstIP].bytes += bytes;
        }

        // Track port usage
        if (effectivePort && effectivePort !== '0' && effectivePort !== '') {
            portStats[effectivePort] = (portStats[effectivePort] || 0) + 1;
        }

        // Track protocols
        if (protocol && protocol !== '') {
            serviceStats[protocol] = (serviceStats[protocol] || 0) + 1;
        }

        // Duration stats
        if (durationSeconds > 0) {
            durationStats.all.push(durationSeconds);
            const protoKey = protocol ? protocol.toUpperCase() : 'UNKNOWN';
            if (!durationStats.byProtocol[protoKey]) {
                durationStats.byProtocol[protoKey] = [];
            }
            durationStats.byProtocol[protoKey].push(durationSeconds);
        }

        // App detection
        const app = detectApp(srcIP, dstIP, srcPort, null, protocol);
        if (app) {
            if (!appDetection[app]) {
                appDetection[app] = { count: 0, bytes: 0, ips: new Set() };
            }
            appDetection[app].count++;
            appDetection[app].bytes += bytes;
            appDetection[app].ips.add(srcIP);
            appDetection[app].ips.add(dstIP);
        }

        const bucketKey = getTimelineBucketKey(startTime);
        if (bucketKey) {
            if (!timelineStats[bucketKey]) {
                timelineStats[bucketKey] = { count: 0, bytes: 0, apps: {}, protocols: {} };
            }
            timelineStats[bucketKey].count++;
            timelineStats[bucketKey].bytes += bytes;
            if (app) {
                timelineStats[bucketKey].apps[app] = (timelineStats[bucketKey].apps[app] || 0) + bytes;
            }
            if (protocol) {
                const protoKey = protocol.toUpperCase();
                timelineStats[bucketKey].protocols[protoKey] = (timelineStats[bucketKey].protocols[protoKey] || 0) + 1;
            }
        }
    });

    lastPacketAnalysis = {
        ipAnalysis,
        serviceStats,
        portStats,
        appDetection,
        durationStats,
        destinationStats,
        timelineStats
    };
    displayPacketAnalysis(ipAnalysis, serviceStats, portStats, appDetection, durationStats, destinationStats, timelineStats);
    refreshPacketTargetSelect();
}

function identifyService(ip, port) {
    // Check known IP ranges
    for (const [service, ranges] of Object.entries(IP_RANGES)) {
        for (const range of ranges) {
            if (ip.startsWith(range)) {
                return service.charAt(0).toUpperCase() + service.slice(1);
            }
        }
    }

    // Check by port
    if (port && PORT_SERVICES[port]) {
        return PORT_SERVICES[port];
    }

    return 'Unknown';
}

function getPortServiceDisplay(port) {
    const service = PORT_SERVICES[port];
    if (service) {
        const desc = PORT_SERVICE_DESCRIPTIONS[port];
        if (desc) {
            return `<div>${service}</div><div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 2px;">${desc}</div>`;
        }
        return service;
    }
    const iana = getIanaPortDisplay(port);
    const safePort = encodeURIComponent(port);
    const speedGuide = ` <a href="https://www.speedguide.net/port.php?port=${safePort}" target="_blank" rel="noopener noreferrer" style="color: var(--info-color); text-decoration: none;">(SpeedGuide)</a>`;
    if (iana) return `${iana}${speedGuide}`;
    return `Unknown${speedGuide}`;
}

function getIanaPortDisplay(port) {
    if (!window.IANA_PORTS) return null;
    const entries = window.IANA_PORTS[port];
    if (!entries || !entries.length) return null;
    const labels = [];
    const seen = new Set();
    const descs = [];
    for (const entry of entries) {
        const service = (entry.service || entry.description || '').trim();
        if (!service) continue;
        const proto = (entry.protocol || '').trim().toUpperCase();
        const label = proto ? `${proto}/${service}` : service;
        const key = label.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        labels.push(label);
        if (entry.description) {
            descs.push(`${label}: ${entry.description}`);
        }
    }
    if (!labels.length) return null;
    const full = labels.join(', ');
    const maxItems = 4;
    const short = labels.length > maxItems ? `${labels.slice(0, maxItems).join(', ')} +${labels.length - maxItems} more` : full;
    const descText = descs.length ? descs.join(' | ') : '';
    const descHtml = descText ? `<div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 2px;">${descText}</div>` : '';
    return `<div>${short}</div>${descHtml}`;
}

function detectApp(srcIP, dstIP, srcPort, dstPort, protocol) {
    const checkIP = (ip) => {
        for (const [app, ranges] of Object.entries(IP_RANGES)) {
            for (const range of ranges) {
                if (ip && ip.startsWith(range)) {
                    return app;
                }
            }
        }
        return null;
    };

    let app = checkIP(srcIP) || checkIP(dstIP);

    // Special port-based detection
    if (!app) {
        if (dstPort === '5223' || srcPort === '5223') {
            app = 'apple-apns';
        } else if (dstPort === '5228' || srcPort === '5228') {
            app = 'google-gcm';
        } else if (dstPort === '5060' || srcPort === '5060' || dstPort === '5061' || srcPort === '5061') {
            app = 'voip-sip';
        } else if (protocol && protocol.toLowerCase().includes('sip')) {
            app = 'voip-sip';
        }
    }

    return app;
}

async function getWhoisCacheStats() {
    if (!supabaseClient) initializeSupabase();
    if (!supabaseClient) return 0;

    try {
        const { count, error } = await supabaseClient
            .from('ip_whois')
            .select('*', { count: 'exact', head: true });

        return error ? 0 : count;
    } catch (error) {
        return 0;
    }
}

function displayPacketAnalysis(ipAnalysis, serviceStats, portStats, appDetection, durationStats, destinationStats, timelineStats) {
    const resultsDiv = document.getElementById('packetResults');
    resultsDiv.style.display = 'block';

    const sections = [];

    // Database Stats Section
    const dbStatsHTML = `
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px; border-radius: 8px;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div><strong>IP WHOIS Database:</strong> <span id="dbCacheCount">Checking...</span></div>
            </div>
        </div>
    `;
    sections.push(createCollapsibleSection('Database Statistics', dbStatsHTML, true, 'packet-db-stats'));

    // App Detection Section
    let appHTML = '';
    if (Object.keys(appDetection).length > 0) {
        appHTML += '<div class="summary-grid packet-apps" style="grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 15px;">';
        const sortedApps = Object.entries(appDetection).sort((a, b) => b[1].bytes - a[1].bytes);
        sortedApps.forEach(([app, data]) => {
            const appName = formatAppName(app);
            const category = categorizeApp(app);
            appHTML += `
                <div class="summary-card app-card" style="background: ${getCategoryColor(category)};">
                    <div class="summary-label">${appName}</div>
                    <div class="summary-value">${data.count} connections</div>
                    <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 5px;">
                        ${formatBytes(data.bytes)} transferred<br>
                        ${data.ips.size} unique IPs<br>
                        <span class="app-category">${category}</span>
                    </div>
                </div>
            `;
        });
        appHTML += '</div>';
    } else {
        appHTML = '<p style="color: var(--text-secondary);">No specific apps detected</p>';
    }
    sections.push(createCollapsibleSection('Detected Applications & Services', appHTML, true, 'packet-apps'));

    // Top Talkers Section
    const topTalkersByBytes = Object.entries(ipAnalysis)
        .sort((a, b) => b[1].bytes - a[1].bytes)
        .slice(0, 10);
    const topTalkersByPackets = Object.entries(ipAnalysis)
        .sort((a, b) => b[1].packets - a[1].packets)
        .slice(0, 10);

    let talkersHTML = '<div style="display: grid; grid-template-columns: 1fr; gap: 16px;">';
    talkersHTML += '<div style="overflow-x: auto;"><table class="data-table compact-table" style="width: 100%; border-collapse: collapse;">';
    talkersHTML += '<thead><tr><th>By Bytes</th><th style="text-align: right;">Bytes</th><th style="text-align: right;">Packets</th></tr></thead><tbody>';
    topTalkersByBytes.forEach(([ip, data]) => {
        const ipKey = ip.replace(/:/g, '-');
        const displayMeta = getIpDisplayMeta(ip);
        talkersHTML += `<tr>
            <td style="padding: 10px;">
                <div data-whois-name="${ip}" style="font-weight: 600;">${displayMeta.name}</div>
                <div style="font-family: monospace; font-size: 0.85rem; color: var(--text-secondary);">${ip} · ${displayMeta.source}</div>
                <span id="whois-${ipKey}-talker" style="display: none;"></span>
            </td>
            <td style="padding: 10px; text-align: right;">${formatBytes(data.bytes)}</td>
            <td style="padding: 10px; text-align: right;">${data.packets}</td>
        </tr>`;
    });
    talkersHTML += '</tbody></table></div>';
    talkersHTML += '<div style="overflow-x: auto;"><table class="data-table compact-table" style="width: 100%; border-collapse: collapse;">';
    talkersHTML += '<thead><tr><th>By Packets</th><th style="text-align: right;">Packets</th><th style="text-align: right;">Bytes</th></tr></thead><tbody>';
    topTalkersByPackets.forEach(([ip, data]) => {
        const ipKey = ip.replace(/:/g, '-');
        const displayMeta = getIpDisplayMeta(ip);
        talkersHTML += `<tr>
            <td style="padding: 10px;">
                <div data-whois-name="${ip}" style="font-weight: 600;">${displayMeta.name}</div>
                <div style="font-family: monospace; font-size: 0.85rem; color: var(--text-secondary);">${ip} · ${displayMeta.source}</div>
                <span id="whois-${ipKey}-talker" style="display: none;"></span>
            </td>
            <td style="padding: 10px; text-align: right;">${data.packets}</td>
            <td style="padding: 10px; text-align: right;">${formatBytes(data.bytes)}</td>
        </tr>`;
    });
    talkersHTML += '</tbody></table></div></div>';
    sections.push(createCollapsibleSection('Top Talkers', talkersHTML, true, 'packet-talkers'));

    // Protocol Sessions Section
    let protocolHTML = '<p style="color: var(--text-secondary); margin-bottom: 14px; font-size: 0.9rem;">Counts reflect sessions grouped by protocol (Session Protocol or Transport Protocol).</p>';
    const protocolSessions = Object.entries(serviceStats)
        .sort((a, b) => b[1] - a[1]);
    if (protocolSessions.length) {
        protocolHTML += '<div style="overflow-x: auto;"><table class="data-table" style="width: 100%; border-collapse: collapse;">';
        protocolHTML += '<thead><tr><th>Protocol</th><th style="text-align: right;">Sessions</th></tr></thead><tbody>';
        protocolSessions.forEach(([protocol, count]) => {
            protocolHTML += `<tr>
                <td style="padding: 10px;">${protocol.toUpperCase()}</td>
                <td style="padding: 10px; text-align: right;">${count}</td>
            </tr>`;
        });
        protocolHTML += '</tbody></table></div>';
    } else {
        protocolHTML += '<p style="color: var(--text-secondary);">No protocol session data available.</p>';
    }
    sections.push(createCollapsibleSection('Protocol Sessions', protocolHTML, false, 'packet-protocols'));

    // Top Destinations Section
    const topDestinations = Object.entries(destinationStats || {})
        .sort((a, b) => b[1].bytes - a[1].bytes)
        .slice(0, 12)
        .map(([ip, stats]) => {
            const cacheKey = normalizeIpForCache(ip);
            const name = reverseDnsCache[ip] || ipWhoisNameCache[cacheKey] || ip;
            const source = reverseDnsCache[ip] ? 'PTR' : (ipWhoisNameCache[cacheKey] ? 'WHOIS' : 'IP');
            return { ip, name, source, bytes: stats.bytes, packets: stats.packets };
        });
    let destinationsHTML = '<div style="overflow-x: auto;"><table class="data-table" style="width: 100%; border-collapse: collapse;">';
    destinationsHTML += '<thead><tr><th>Destination</th><th style="text-align: right;">Connections</th><th style="text-align: right;">Bytes</th></tr></thead><tbody>';
    if (topDestinations.length) {
        topDestinations.forEach(item => {
            destinationsHTML += `<tr>
                <td style="padding: 10px;">
                    <div data-whois-name="${item.ip}" style="font-weight: 600;">${item.name}</div>
                    <div style="font-family: monospace; font-size: 0.85rem; color: var(--text-secondary);">${item.ip} · ${item.source}</div>
                </td>
                <td style="padding: 10px; text-align: right;">${item.packets}</td>
                <td style="padding: 10px; text-align: right;">${formatBytes(item.bytes)}</td>
            </tr>`;
        });
    } else {
        destinationsHTML += '<tr><td colspan="3" style="padding: 10px; color: var(--text-secondary);">No destination stats available.</td></tr>';
    }
    destinationsHTML += '</tbody></table>';
    destinationsHTML += '<div style="margin-top: 8px; color: var(--text-secondary); font-size: 0.85rem;">';
    destinationsHTML += '<span id="ptrStatus">PTR lookups are often missing; WHOIS is used as fallback.</span>';
    destinationsHTML += '</div></div>';
    sections.push(createCollapsibleSection('Top Destinations (PTR/WHOIS)', destinationsHTML, false, 'packet-destinations'));

    // Top IP Addresses Section
    let topIPsHTML = `
        <div style="display: flex; gap: 10px; margin-bottom: 15px; align-items: center; flex-wrap: wrap;">
            <span id="whoisProgress" style="padding: 10px; color: var(--text-secondary);"></span>
        </div>
    `;
    topIPsHTML += '<div style="overflow-x: auto;"><table class="data-table" style="width: 100%; border-collapse: collapse;">';
    topIPsHTML += '<thead><tr style="background: var(--primary-color); color: white;">';
    topIPsHTML += '<th style="padding: 12px; text-align: left;">WHOIS / IP</th>';
    topIPsHTML += '<th style="padding: 12px; text-align: left;">Service</th>';
    topIPsHTML += '<th style="padding: 12px; text-align: right;">Packets</th>';
    topIPsHTML += '<th style="padding: 12px; text-align: right;">Bytes</th>';
    topIPsHTML += '<th style="padding: 12px; text-align: left;">Ports</th>';
    topIPsHTML += '<th style="padding: 12px; text-align: left;">Protocols</th>';
    topIPsHTML += '</tr></thead><tbody>';

    const sortedIPs = Object.entries(ipAnalysis)
        .sort((a, b) => b[1].bytes - a[1].bytes)
        .slice(0, 50); // Top 50 IPs

    sortedIPs.forEach(([ip, data]) => {
        const ports = Array.from(data.ports).slice(0, 5).join(', ');
        const protocols = Array.from(data.protocols).join(', ');
        const ipKey = ip.replace(/:/g, '-');
        const displayMeta = getIpDisplayMeta(ip);
        topIPsHTML += `
            <tr style="border-bottom: 1px solid var(--border-color);">
                <td style="padding: 10px;">
                    <div id="whois-name-${ipKey}" style="font-weight: 600;">${displayMeta.name}</div>
                    <div style="font-family: monospace; font-size: 0.85rem; color: var(--text-secondary);">${ip} · ${displayMeta.source}</div>
                    <span id="whois-${ipKey}" style="display: none;"></span>
                </td>
                <td style="padding: 10px;"><span style="background: var(--info-color); color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.85rem;">${data.service}</span></td>
                <td style="padding: 10px; text-align: right;">${data.packets}</td>
                <td style="padding: 10px; text-align: right;">${formatBytes(data.bytes)}</td>
                <td style="padding: 10px; font-size: 0.85rem;">${ports}</td>
                <td style="padding: 10px; font-size: 0.85rem;">${protocols}</td>
            </tr>
        `;
    });

    topIPsHTML += '</tbody></table></div>';
    sections.push(createCollapsibleSection('Top IP Addresses', topIPsHTML, true, 'packet-top-ips'));

    // Port Usage Statistics Section
    let portHTML = '';
    const sortedPorts = Object.entries(portStats || {})
        .sort((a, b) => b[1] - a[1])
        .slice(0, 30);
    if (sortedPorts.length) {
        portHTML += '<div style="overflow-x: auto;"><table class="data-table" style="width: 100%; border-collapse: collapse;">';
        portHTML += '<thead><tr style="background: var(--primary-color); color: white;">';
        portHTML += '<th style="padding: 12px; text-align: left;">Port</th>';
        portHTML += '<th style="padding: 12px; text-align: left;">Service</th>';
        portHTML += '<th style="padding: 12px; text-align: right;">Connections</th>';
        portHTML += '</tr></thead><tbody>';

        sortedPorts.forEach(([port, count]) => {
            const service = getPortServiceDisplay(port);
            portHTML += `
                <tr style="border-bottom: 1px solid var(--border-color);">
                    <td style="padding: 10px; font-weight: 600;">${port}</td>
                    <td style="padding: 10px;">${service}</td>
                    <td style="padding: 10px; text-align: right;">${count}</td>
                </tr>
            `;
        });

        portHTML += '</tbody></table></div>';
        portHTML += '<div style="margin-top: 8px; color: var(--text-secondary); font-size: 0.85rem;">Service labels use built-ins, IANA where available, and SpeedGuide links for quick reference.</div>';
    } else {
        portHTML = '<p style="color: var(--text-secondary);">No port usage data available.</p>';
    }
    sections.push(createCollapsibleSection('Port Usage Statistics', portHTML, false, 'packet-ports'));

    // Usage Timeline Section
    if (timelineStats && Object.keys(timelineStats).length) {
        const timelineRows = Object.entries(timelineStats)
            .sort((a, b) => new Date(a[0]) - new Date(b[0]));
        let timelineHTML = '<div style="overflow-x: auto;"><table class="data-table" style="width: 100%; border-collapse: collapse;">';
        timelineHTML += '<thead><tr><th>Time Bucket</th><th style="text-align: right;">Connections</th><th style="text-align: right;">Bytes</th><th>Top App</th><th>Top Protocol</th></tr></thead><tbody>';
        timelineRows.forEach(([bucket, stats]) => {
            const topApp = Object.entries(stats.apps).sort((a, b) => b[1] - a[1])[0]?.[0] || '—';
            const topProto = Object.entries(stats.protocols).sort((a, b) => b[1] - a[1])[0]?.[0] || '—';
            timelineHTML += `<tr>
                <td style="padding: 10px;">${bucket}</td>
                <td style="padding: 10px; text-align: right;">${stats.count}</td>
                <td style="padding: 10px; text-align: right;">${formatBytes(stats.bytes)}</td>
                <td style="padding: 10px;">${formatAppName(topApp)}</td>
                <td style="padding: 10px;">${topProto}</td>
            </tr>`;
        });
        timelineHTML += '</tbody></table></div>';
        sections.push(createCollapsibleSection('Usage Timeline', timelineHTML, false, 'packet-timeline'));
    }

    // Render all sections
    resultsDiv.innerHTML = sections.join('');
    setupCollapsibles();
    if (!reverseDnsStats.attempted) {
        setTimeout(() => resolveReverseDNS(), 0);
    }

    // Update cache stats
    getWhoisCacheStats().then(count => {
        const el = document.getElementById('dbCacheCount');
        if (el) {
            if (supabaseClient) {
                el.innerHTML = `<strong>${count}</strong> IPs cached (saves API calls)`;
            } else {
                el.innerHTML = '<span style="color: #ffd700;">⚠ Database not connected - WHOIS results won\'t be cached</span>';
            }
        }
    });

    // Auto-run WHOIS lookup for top IPs
    setTimeout(() => {
        performBulkWhois();
    }, 0);
}

async function viewWhoisCache() {
    if (!supabaseClient) {
        alert('Database not connected. Please configure Supabase in Tower Management > Cloud Config');
        return;
    }

    try {
        const { data, error } = await supabaseClient
            .from('ip_whois')
            .select('*')
            .order('lookup_date', { ascending: false })
            .limit(100);

        if (error) throw error;

        // Create modal to display cache
        let modal = document.getElementById('whoisCacheModal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'whoisCacheModal';
            modal.className = 'settings-modal';
            document.body.appendChild(modal);
        }

        let html = '<div class="settings-content" style="max-width: 900px; max-height: 80vh; overflow-y: auto;">';
        html += '<h3>WHOIS Cache Database <button class="btn-secondary" onclick="closeWhoisCache()" style="float: right;">Close</button></h3>';
        html += '<p style="color: var(--text-secondary); margin-bottom: 15px;">Last 100 cached IP lookups (most recent first)</p>';

        if (data && data.length > 0) {
            html += '<table class="data-table" style="width: 100%;">';
            html += '<thead><tr style="background: var(--primary-color); color: white;">';
            html += '<th style="padding: 10px;">IP Address</th>';
            html += '<th style="padding: 10px;">Organization</th>';
            html += '<th style="padding: 10px;">Location</th>';
            html += '<th style="padding: 10px;">Lookup Date</th>';
            html += '</tr></thead><tbody>';

            data.forEach(record => {
                const date = new Date(record.lookup_date).toLocaleDateString();
                html += `<tr style="border-bottom: 1px solid var(--border-color);">
                    <td style="padding: 8px; font-family: monospace;">${record.ip_address}</td>
                    <td style="padding: 8px;">${record.organization || 'Unknown'}</td>
                    <td style="padding: 8px;">${record.city || ''} ${record.country || ''}</td>
                    <td style="padding: 8px; font-size: 0.85rem;">${date}</td>
                </tr>`;
            });

            html += '</tbody></table>';
        } else {
            html += '<p style="color: var(--text-secondary);">No cached IPs yet. Run WHOIS lookups to build the cache.</p>';
        }

        html += '</div>';
        modal.innerHTML = html;
        modal.style.display = 'block';
    } catch (error) {
        console.error('Error viewing cache:', error);
        alert('Error loading cache: ' + error.message);
    }
}

function closeWhoisCache() {
    const modal = document.getElementById('whoisCacheModal');
    if (modal) modal.style.display = 'none';
}

function formatAppName(app) {
    const names = {
        'facebook': 'Facebook',
        'instagram': 'Instagram',
        'whatsapp': 'WhatsApp',
        'apple': 'Apple Services',
        'apple-apns': 'Apple Push Notifications',
        'google': 'Google Services',
        'google-gcm': 'Google Cloud Messaging',
        'microsoft': 'Microsoft',
        'telegram': 'Telegram',
        'signal': 'Signal',
        'tiktok': 'TikTok',
        'snapchat': 'Snapchat',
        'twitter': 'Twitter/X',
        'netflix': 'Netflix',
        'amazon': 'Amazon',
        'voip-sip': 'VoIP/SIP Calling',
        'cloudflare': 'Cloudflare CDN',
        'verizon': 'Verizon Network',
        'tmobile': 'T-Mobile Network',
        'att': 'AT&T Network',
        // Banking & Financial
        'bankofamerica': 'Bank of America',
        'chase': 'Chase Bank',
        'wellsfargo': 'Wells Fargo',
        'paypal': 'PayPal',
        'venmo': 'Venmo',
        'cashapp': 'Cash App',
        'zelle': 'Zelle',
        'coinbase': 'Coinbase',
        'robinhood': 'Robinhood',
        // Messaging & Communication
        'discord': 'Discord',
        'slack': 'Slack',
        'zoom': 'Zoom',
        'skype': 'Skype',
        'gmail': 'Gmail',
        'outlook': 'Outlook',
        'yahoo': 'Yahoo Mail',
        // Other Services
        'spotify': 'Spotify',
        'uber': 'Uber',
        'lyft': 'Lyft',
        'doordash': 'DoorDash',
        'instacart': 'Instacart',
    };
    return names[app] || app;
}

function categorizeApp(app) {
    const categories = {
        // Messaging
        'whatsapp': 'Messaging',
        'telegram': 'Messaging',
        'signal': 'Messaging',
        'discord': 'Messaging',
        'slack': 'Messaging',
        // Social Media
        'facebook': 'Social Media',
        'instagram': 'Social Media',
        'twitter': 'Social Media',
        'snapchat': 'Social Media',
        'tiktok': 'Social Media',
        // System Services
        'apple': 'System Service',
        'apple-apns': 'Push Notifications',
        'google': 'System Service',
        'google-gcm': 'Push Notifications',
        'microsoft': 'Productivity',
        // Banking & Financial
        'bankofamerica': 'Banking',
        'chase': 'Banking',
        'wellsfargo': 'Banking',
        'paypal': 'Financial',
        'venmo': 'Financial',
        'cashapp': 'Financial',
        'zelle': 'Financial',
        'coinbase': 'Financial',
        'robinhood': 'Financial',
        // Communication
        'voip-sip': 'Voice/Video Call',
        'zoom': 'Voice/Video Call',
        'skype': 'Voice/Video Call',
        'gmail': 'Email',
        'outlook': 'Email',
        'yahoo': 'Email',
        // Entertainment
        'netflix': 'Streaming',
        'spotify': 'Streaming',
        // Services
        'amazon': 'E-Commerce/Cloud',
        'uber': 'Transportation',
        'lyft': 'Transportation',
        'doordash': 'Food Delivery',
        'instacart': 'Food Delivery',
    };
    return categories[app] || 'Other';
}

function getCategoryColor(category) {
    const colors = {
        'Messaging': 'linear-gradient(135deg, #2340c8 0%, #3c6cf1 100%)',
        'Social Media': 'linear-gradient(135deg, #b12645 0%, #e24f7c 100%)',
        'System Service': 'linear-gradient(135deg, #0f7a8f 0%, #1fb6c7 100%)',
        'Push Notifications': 'linear-gradient(135deg, #0e8b5a 0%, #22c48b 100%)',
        'Voice/Video Call': 'linear-gradient(135deg, #9a4c0f 0%, #d77a1f 100%)',
        'Streaming': 'linear-gradient(135deg, #4a2aa9 0%, #7450d3 100%)',
        'Banking': 'linear-gradient(135deg, #0f6b3f 0%, #1aa868 100%)',
        'Financial': 'linear-gradient(135deg, #8a4f0c 0%, #c47b1a 100%)',
        'E-Commerce/Cloud': 'linear-gradient(135deg, #7a2a7a 0%, #a74aa7 100%)',
        'Productivity': 'linear-gradient(135deg, #2a5a9d 0%, #4a88d9 100%)',
        'Email': 'linear-gradient(135deg, #1f5c8e 0%, #2f7ec2 100%)',
        'Transportation': 'linear-gradient(135deg, #0c7c6f 0%, #19b7a5 100%)',
        'Food Delivery': 'linear-gradient(135deg, #9c2c24 0%, #d85a4d 100%)',
        'Other': 'linear-gradient(135deg, #3f4a5c 0%, #5c6b80 100%)',
    };
    return colors[category] || colors['Other'];
}

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

function parseDurationToSeconds(duration) {
    if (!duration) return 0;
    const parts = String(duration).trim().split(':').map(Number);
    if (!parts.length || parts.some(n => Number.isNaN(n))) return 0;
    let h = 0;
    let m = 0;
    let s = 0;
    if (parts.length === 3) {
        [h, m, s] = parts;
    } else if (parts.length === 2) {
        [m, s] = parts;
    } else if (parts.length === 1) {
        [s] = parts;
    } else {
        return 0;
    }
    return Math.max(0, (h * 3600) + (m * 60) + s);
}

function parsePacketTime(value) {
    if (!value) return null;
    const parsed = new Date(value);
    if (!Number.isNaN(parsed.getTime())) return parsed;
    return null;
}

function getTimelineBucketKey(value) {
    const date = parsePacketTime(value);
    if (!date) return null;
    const bucketMinutes = 5;
    const ms = date.getTime();
    const bucketMs = bucketMinutes * 60 * 1000;
    const floored = new Date(Math.floor(ms / bucketMs) * bucketMs);
    return floored.toLocaleString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
    });
}

function normalizeIpForCache(ip) {
    return String(ip || '').trim().toLowerCase();
}

function getIpDisplayMeta(ip) {
    if (reverseDnsCache[ip]) {
        return { name: reverseDnsCache[ip], source: 'PTR' };
    }
    const cacheKey = normalizeIpForCache(ip);
    if (ipWhoisNameCache[cacheKey]) {
        return { name: ipWhoisNameCache[cacheKey], source: 'WHOIS' };
    }
    return { name: ip, source: 'IP' };
}

function summarizeDurations(list) {
    if (!list || list.length === 0) return null;
    const sorted = [...list].sort((a, b) => a - b);
    const count = sorted.length;
    const sum = sorted.reduce((acc, val) => acc + val, 0);
    const avg = sum / count;
    const mid = Math.floor(count / 2);
    const median = count % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
    const max = sorted[sorted.length - 1];
    return { count, avg, median, max };
}

function formatDuration(seconds) {
    if (!Number.isFinite(seconds) || seconds <= 0) return '0s';
    const total = Math.round(seconds);
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
}

function expandIPv6(address) {
    if (!address || !address.includes(':')) return null;
    const [left, right] = address.split('::');
    const leftParts = left ? left.split(':').filter(Boolean) : [];
    const rightParts = right ? right.split(':').filter(Boolean) : [];
    if (leftParts.length + rightParts.length > 8) return null;
    const fillCount = 8 - (leftParts.length + rightParts.length);
    const parts = [
        ...leftParts,
        ...Array(fillCount).fill('0'),
        ...rightParts
    ].map(part => part.padStart(4, '0').toLowerCase());
    if (parts.length !== 8 || parts.some(p => p.length !== 4)) return null;
    return parts.join('');
}

function ipToPtrName(ip) {
    if (!ip) return null;
    if (ip.includes('.')) {
        const octets = ip.split('.');
        if (octets.length !== 4) return null;
        return `${octets.reverse().join('.')}.in-addr.arpa`;
    }
    const expanded = expandIPv6(ip);
    if (!expanded) return null;
    const nibbles = expanded.split('').reverse().join('.');
    return `${nibbles}.ip6.arpa`;
}

async function getReverseDnsName(ip) {
    const ptr = ipToPtrName(ip);
    if (!ptr) return null;
    try {
        const response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(ptr)}&type=PTR`);
        if (!response.ok) return null;
        const data = await response.json();
        const answer = data && data.Answer && data.Answer.find(a => a && a.data);
        if (!answer || !answer.data) return null;
        return answer.data.replace(/\.$/, '');
    } catch (error) {
        return null;
    }
}

async function loadReverseDnsCacheFromDb(ips) {
    if (!ips || ips.length === 0) return 0;
    if (!supabaseClient) initializeSupabase();
    if (!supabaseClient) return 0;
    try {
        const { data, error } = await supabaseClient
            .from('ip_ptr')
            .select('ip_address,ptr_name')
            .in('ip_address', ips);
        if (error || !data) return 0;
        data.forEach(record => {
            if (record.ptr_name) {
                reverseDnsCache[record.ip_address] = record.ptr_name;
            }
        });
        return data.length;
    } catch (e) {
        console.error("PTR cache lookup failed:", e);
        return 0;
    }
}

async function resolveReverseDNS() {
    if (!lastPacketAnalysis || !lastPacketAnalysis.destinationStats) return;
    reverseDnsStats.attempted = true;
    const dests = Object.entries(lastPacketAnalysis.destinationStats)
        .sort((a, b) => b[1].bytes - a[1].bytes)
        .slice(0, 30)
        .map(([ip]) => ip)
        .filter(ip => !reverseDnsCache[ip] && !isPrivateOrReservedIP(ip));

    const statusEl = document.getElementById('ptrStatus');
    if (!dests.length) {
        if (statusEl) statusEl.textContent = 'No destinations to resolve for PTR.';
        return;
    }

    reverseDnsStats.total = dests.length;
    reverseDnsStats.found = 0;
    reverseDnsStats.cached = 0;
    reverseDnsStats.lookupErrors = 0;
    reverseDnsStats.upsertErrors = 0;
    if (statusEl) statusEl.textContent = `Resolving PTR for ${dests.length} destinations...`;

    const cachedCount = await loadReverseDnsCacheFromDb(dests);
    reverseDnsStats.cached = cachedCount || 0;
    const remaining = dests.filter(ip => !reverseDnsCache[ip]);
    if (cachedCount && statusEl) {
        statusEl.textContent = `PTR cache hit for ${cachedCount}. Resolving ${remaining.length} remaining...`;
    }

    for (const ip of remaining) {
        const name = await getReverseDnsName(ip);
        if (name) {
            reverseDnsCache[ip] = name;
            reverseDnsStats.found++;
            if (!supabaseClient) initializeSupabase();
            if (supabaseClient) {
                try {
                    await supabaseClient
                        .from('ip_ptr')
                        .upsert({
                            ip_address: ip,
                            ptr_name: name,
                            lookup_date: new Date().toISOString()
                        }, { onConflict: 'ip_address' });
                } catch (e) {
                    reverseDnsStats.upsertErrors++;
                    console.error("PTR cache upsert failed:", ip, e);
                }
            }
        } else {
            reverseDnsStats.lookupErrors++;
        }
        await new Promise(resolve => setTimeout(resolve, 200));
    }

    if (statusEl) {
        const resolved = reverseDnsStats.found + reverseDnsStats.cached;
        const errorTotal = reverseDnsStats.lookupErrors + reverseDnsStats.upsertErrors;
        statusEl.textContent = resolved
            ? `PTR: cached ${reverseDnsStats.cached}, resolved ${reverseDnsStats.found}, errors ${errorTotal}.`
            : `No PTR records found for top destinations (common). WHOIS is used as fallback. Errors: ${errorTotal}.`;
    }

    displayPacketAnalysis(
        lastPacketAnalysis.ipAnalysis,
        lastPacketAnalysis.serviceStats,
        lastPacketAnalysis.portStats,
        lastPacketAnalysis.appDetection,
        lastPacketAnalysis.durationStats,
        lastPacketAnalysis.destinationStats,
        lastPacketAnalysis.timelineStats
    );
}

function getPacketTargetOptions() {
    const targets = new Set();
    packetData.forEach(packet => {
        const target = packet['Target'] || packet['Target Address'];
        if (target && target.trim()) targets.add(target.trim());
    });
    return ['All', ...Array.from(targets).sort()];
}

function setPacketTargetFilter(value) {
    packetTargetFilter = value || 'All';
    analyzePacketData();
}

function refreshPacketTargetSelect() {
    const targetSelect = document.getElementById('packetTargetSelectCard');
    if (!targetSelect) return;
    const options = getPacketTargetOptions();
    targetSelect.innerHTML = options.map(t => `<option value="${t}">${t}</option>`).join('');
    targetSelect.value = packetTargetFilter || 'All';
}

async function lookupWhois(ip) {
    const displayId = 'whois-' + ip.replace(/:/g, '-');
    const displayEl = document.getElementById(displayId);
    const cacheKey = normalizeIpForCache(ip);
    let delayMs = 1500;

    if (!supabaseClient) initializeSupabase();

    if (isPrivateOrReservedIP(ip)) {
        const privateLabel = '<span style="color: var(--text-secondary);">Private/Reserved</span>';
        ipWhoisCache[cacheKey] = privateLabel;
        ipWhoisNameCache[cacheKey] = 'Private/Reserved';
        if (displayEl) displayEl.innerHTML = privateLabel;
        setWhoisName(ip, 'Private/Reserved');
        return;
    }

    // Check in-memory cache first
    if (ipWhoisCache[cacheKey]) {
        if (displayEl) displayEl.innerHTML = ipWhoisCache[cacheKey];
        setWhoisName(ip, ipWhoisNameCache[cacheKey] || ip);
        return;
    }

    if (displayEl) displayEl.innerHTML = '<span style="color: var(--info-color);">Loading...</span>';

    try {
        // Step 1: Check database first
        if (supabaseClient) {
            const { data: dbData, error: dbError } = await supabaseClient
                .from('ip_whois')
                .select('*')
                .ilike('ip_address', cacheKey)
                .single();

            if (!dbError && dbData) {
                // Found in database - use cached data
                const info = formatWhoisInfo(dbData);
                ipWhoisCache[cacheKey] = info;
                ipWhoisNameCache[cacheKey] = formatWhoisName(dbData, ip);
                if (displayEl) {
                    displayEl.innerHTML = info + ' <span style="color: var(--success-color); font-size: 0.75rem;">(cached)</span>';
                }
                setWhoisName(ip, ipWhoisNameCache[cacheKey]);
                return;
            }
        }

        // Step 2: Not in database - perform API lookup (primary + fallback)
        let whoisData = await fetchIpApiWhois(ip).catch(err => {
            if (err && String(err.message || '').includes('429')) delayMs = 7000;
            return null;
        });

        if (!whoisData) {
            whoisData = await fetchIpWhoisIo(ip).catch(() => null);
        }

        if (whoisData) {
            const orgName = whoisData.organization || whoisData.asn || 'Unknown';
            // Step 3: Store in database for future use
            if (supabaseClient) {
                const { error: upsertError } = await supabaseClient
                    .from('ip_whois')
                    .upsert({
                        ip_address: cacheKey,
                        organization: orgName,
                        country: whoisData.country || '',
                        city: whoisData.city || '',
                        region: whoisData.region || '',
                        asn: whoisData.asn || '',
                        isp: whoisData.isp || '',
                        lookup_date: new Date().toISOString()
                    }, {
                        onConflict: 'ip_address'
                    });
                if (upsertError) {
                    console.warn('WHOIS cache upsert failed:', ip, upsertError);
                }
            }

            const info = formatWhoisInfo({
                organization: orgName,
                country: whoisData.country || '',
                city: whoisData.city || ''
            });
            ipWhoisCache[cacheKey] = info;
            ipWhoisNameCache[cacheKey] = orgName || ip;
            if (displayEl) displayEl.innerHTML = info;
            setWhoisName(ip, ipWhoisNameCache[cacheKey]);
        } else {
            if (displayEl) displayEl.innerHTML = '<span style="color: var(--text-secondary);">Unavailable</span>';
            setWhoisName(ip, ip);
        }
    } catch (error) {
        console.error('WHOIS lookup error:', error);
        const msg = error.message && error.message.includes('429') ? 'Rate limited' : 'Unavailable';
        if (displayEl) displayEl.innerHTML = `<span style="color: var(--text-secondary);">${msg}</span>`;
        setWhoisName(ip, ip);
    }

    // Rate limit: wait 1.5 seconds between requests (ipapi.co free tier: 1000/day, ~1 req/sec recommended)
    await new Promise(resolve => setTimeout(resolve, delayMs));
}

async function fetchIpApiWhois(ip) {
    const response = await fetch(`https://ipapi.co/${encodeURIComponent(ip)}/json/`);
    if (!response.ok) {
        throw new Error(`WHOIS lookup failed (${response.status})`);
    }
    const data = await response.json();
    if (data && !data.error) {
        return {
            organization: data.org || data.asn || '',
            country: data.country_name || '',
            city: data.city || '',
            region: data.region || '',
            asn: data.asn || '',
            isp: data.org || ''
        };
    }
    return null;
}

async function fetchIpWhoisIo(ip) {
    const response = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`);
    if (!response.ok) return null;
    const data = await response.json();
    if (!data || data.success === false) return null;
    return {
        organization: (data.connection && (data.connection.org || data.connection.isp)) || data.org || '',
        country: data.country || '',
        city: data.city || '',
        region: data.region || '',
        asn: (data.connection && data.connection.asn) ? `AS${data.connection.asn}` : '',
        isp: (data.connection && data.connection.isp) || ''
    };
}

function formatWhoisInfo(data) {
    return `<div style="font-size: 0.85rem; margin-top: 5px;">
        <strong>${data.organization || 'Unknown'}</strong><br>
        ${data.country || ''} ${data.city ? '- ' + data.city : ''}
    </div>`;
}

function formatWhoisName(data, fallbackIp) {
    return (data && (data.organization || data.asn)) ? (data.organization || data.asn) : fallbackIp;
}

function setWhoisName(ip, name) {
    const cacheKey = normalizeIpForCache(ip);
    const preferred = reverseDnsCache[ip] || ipWhoisNameCache[cacheKey] || name || ip;
    const nameEl = document.getElementById('whois-name-' + ip.replace(/:/g, '-'));
    if (nameEl) nameEl.textContent = preferred;
    document.querySelectorAll(`[data-whois-name="${ip}"]`).forEach(el => {
        el.textContent = preferred;
    });
}

function isPrivateOrReservedIP(ip) {
    if (!ip) return true;
    const ipv4 = ip.split('.');
    if (ipv4.length === 4) {
        const nums = ipv4.map(n => parseInt(n, 10));
        if (nums.some(n => isNaN(n) || n < 0 || n > 255)) return true;
        const [a, b] = nums;
        if (a === 10) return true;
        if (a === 127) return true;
        if (a === 0) return true;
        if (a === 169 && b === 254) return true;
        if (a === 172 && b >= 16 && b <= 31) return true;
        if (a === 192 && b === 168) return true;
        if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
        if (a >= 224) return true; // multicast/reserved
        return false;
    }

    const lower = ip.toLowerCase();
    if (lower === '::' || lower === '::1') return true;
    if (lower.startsWith('fe80:')) return true; // link-local
    if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // ULA
    if (lower.startsWith('ff')) return true; // multicast
    if (lower.startsWith('fec0:')) return true; // site-local (deprecated)
    if (lower.startsWith('2001:db8')) return true; // documentation
    return false;
}

async function performBulkWhois() {
    const progressEl = document.getElementById('whoisProgress');

    // Get all IP elements that need lookup
    const ipElements = document.querySelectorAll('span[id^="whois-"]');
    const ipsToLookup = Array.from(ipElements).map(el => {
        let id = el.id.replace(/^whois-/, '');
        if (id.endsWith('-talker')) {
            id = id.slice(0, -'-talker'.length);
        }
        const ip = id.replace(/-/g, ':');
        return { ip, cacheKey: normalizeIpForCache(ip), element: el };
    }).filter(item => item.ip && item.cacheKey);

    if (ipsToLookup.length === 0) {
        progressEl.textContent = 'No IPs to lookup';
        return;
    }

    const ipMap = new Map();
    ipsToLookup.forEach(item => {
        if (!ipMap.has(item.cacheKey)) ipMap.set(item.cacheKey, []);
        ipMap.get(item.cacheKey).push(item);
    });

    const total = ipMap.size;
    progressEl.innerHTML = `<span style="color: var(--info-color);">Looking up ${total} IPs...</span>`;

    // Step 1: Bulk check database for all IPs
    let dbHits = 0;
    let apiCalls = 0;
    let skipped = 0;

    if (!supabaseClient) initializeSupabase();
    if (supabaseClient) {
        try {
            const ipAddresses = new Set();
            for (const [cacheKey, items] of ipMap.entries()) {
                ipAddresses.add(cacheKey);
                items.forEach(item => {
                    if (item.ip) ipAddresses.add(item.ip);
                });
            }
            const { data: dbData, error: dbError } = await supabaseClient
                .from('ip_whois')
                .select('*')
                .in('ip_address', Array.from(ipAddresses));

            if (!dbError && dbData) {
                // Display all database hits immediately
                dbData.forEach(record => {
                    const cacheKey = normalizeIpForCache(record.ip_address);
                    const items = ipMap.get(cacheKey);
                    if (!items || items.length === 0) return;
                    const info = formatWhoisInfo({
                        organization: record.organization,
                        country: record.country,
                        city: record.city
                    });
                    ipWhoisCache[cacheKey] = info;
                    ipWhoisNameCache[cacheKey] = formatWhoisName(record, items[0].ip);
                    items.forEach(item => {
                        if (item.element) {
                            item.element.innerHTML = info + ' <span style="color: var(--success-color); font-size: 0.75rem;">(cached)</span>';
                        }
                        setWhoisName(item.ip, ipWhoisNameCache[cacheKey]);
                    });
                    dbHits++;
                });

                progressEl.innerHTML = `<span style="color: var(--success-color);">Found ${dbHits} in cache, looking up remaining...</span>`;
            }
        } catch (error) {
            console.error('Database bulk lookup error:', error);
        }
    }

    // Step 2: API lookup for IPs not in database
    for (const [cacheKey, items] of ipMap.entries()) {
        const targetIp = items[0].ip;

        // Skip if already loaded from database
        if (ipWhoisCache[cacheKey]) {
            continue;
        }

        if (isPrivateOrReservedIP(targetIp)) {
            const privateLabel = '<span style="color: var(--text-secondary);">Private/Reserved</span>';
            ipWhoisCache[cacheKey] = privateLabel;
            ipWhoisNameCache[cacheKey] = 'Private/Reserved';
            items.forEach(item => {
                if (item.element) item.element.innerHTML = privateLabel;
                setWhoisName(item.ip, 'Private/Reserved');
            });
            skipped++;
            progressEl.innerHTML = `<span style="color: var(--info-color);">Progress: ${dbHits + apiCalls + skipped}/${total} (${dbHits} cached, ${apiCalls} new, ${skipped} private)</span>`;
            continue;
        }

        await lookupWhois(targetIp);
        const resolvedName = ipWhoisNameCache[cacheKey] || targetIp;
        items.forEach(item => setWhoisName(item.ip, resolvedName));
        apiCalls++;
        const privateSuffix = skipped ? `, ${skipped} private` : '';
        progressEl.innerHTML = `<span style="color: var(--info-color);">Progress: ${dbHits + apiCalls + skipped}/${total} (${dbHits} cached, ${apiCalls} new${privateSuffix})</span>`;
    }

    const privateSuffix = skipped ? `, ${skipped} private` : '';
    progressEl.innerHTML = `<span style="color: var(--success-color);">Complete! ${dbHits} from cache, ${apiCalls} new lookups${privateSuffix}</span>`;
    setTimeout(() => {
        progressEl.textContent = '';
    }, 5000);
}

function clearPacketAnalysis() {
    packetData = [];
    ipWhoisCache = {};
    ipWhoisNameCache = {};
    packetTargetFilter = 'All';
    document.getElementById('packetResults').style.display = 'none';
    document.getElementById('packetStatus').innerHTML = 'No packet data loaded';
    document.getElementById('packetFileInput').value = '';
}

// ============================================================================
// UTILITY HELPER FUNCTIONS
// ============================================================================

// Debounce utility - delays function execution until after wait period of inactivity
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Phone normalization - removes all non-digit characters
function normalizePhone(phone) {
    if (!phone) return '';
    return phone.replace(/\D/g, '');
}

// Extract keywords from text for search indexing
function extractKeywords(text) {
    if (!text) return [];
    return text.toLowerCase()
        .split(/\s+/)
        .filter(word => word.length > 2); // Minimum 3 characters
}

// Truncate text with ellipsis
function truncate(str, maxLen) {
    if (!str || str.length <= maxLen) return str;
    return str.substring(0, maxLen) + '...';
}

// Group array by key function
function groupBy(array, keyFn) {
    return array.reduce((result, item) => {
        const key = keyFn(item);
        (result[key] = result[key] || []).push(item);
        return result;
    }, {});
}

// Capitalize first letter
function capitalize(str) {
    if (!str) return '';
    return str.charAt(0).toUpperCase() + str.slice(1);
}

// Add value to search index map (handles array creation)
function addToIndex(map, key, value) {
    if (!map.has(key)) {
        map.set(key, []);
    }
    map.get(key).push(value);
}

// ============================================================================
// TIMELINE VISUALIZATION FUNCTIONS
// ============================================================================

// Build unified timeline from call messages, SMS data, and packet data
function buildUnifiedTimeline(call, analyzer, includePackets = false) {
    const events = [];

    // Add CDC signaling events from call messages
    if (call.messages && call.messages.length > 0) {
        call.messages.forEach(msg => {
            const timestamp = analyzer.parseTimestamp(msg.timestamp);
            if (timestamp) {
                events.push({
                    timestamp: timestamp,
                    timestampStr: msg.timestamp,
                    type: 'call',
                    subtype: msg.type || 'Unknown',
                    participants: [
                        call.callingParty?.number || 'Unknown',
                        call.calledParty?.number || 'Unknown'
                    ],
                    location: msg.location || null,
                    data: msg,
                    callId: call.callId
                });
            }
        });
    }

    // Add SMS/MMS events
    if (call.smsData && call.smsData.length > 0) {
        call.smsData.forEach(sms => {
            const timestamp = analyzer.parseTimestamp(sms.timestamp);
            if (timestamp) {
                events.push({
                    timestamp: timestamp,
                    timestampStr: sms.timestamp,
                    type: 'sms',
                    subtype: sms.messageType || 'SMS',
                    participants: [
                        sms.from || 'Unknown',
                        sms.to || 'Unknown'
                    ],
                    location: null,
                    data: sms,
                    callId: call.callId
                });
            }
        });
    }

    // Add packet events if requested and available
    if (includePackets && typeof packetData !== 'undefined' && packetData.length > 0) {
        // Filter packets by time range correlation with this call
        const callStartTime = analyzer.parseTimestamp(call.startTime);
        const callEndTime = analyzer.parseTimestamp(call.endTime);

        if (callStartTime) {
            // Include packets within 5 minutes before and after the call
            const timeWindow = 5 * 60 * 1000; // 5 minutes in ms
            const windowStart = callStartTime - timeWindow;
            const windowEnd = (callEndTime || callStartTime) + timeWindow;

            packetData.forEach(packet => {
                // Try to parse packet timestamp (format may vary)
                let packetTime = null;
                if (packet.time || packet.timestamp || packet.Time || packet.Timestamp) {
                    const timeStr = packet.time || packet.timestamp || packet.Time || packet.Timestamp;
                    packetTime = analyzer.parseTimestamp(timeStr);
                }

                if (packetTime && packetTime >= windowStart && packetTime <= windowEnd) {
                    events.push({
                        timestamp: packetTime,
                        timestampStr: packet.time || packet.timestamp || packet.Time || packet.Timestamp,
                        type: 'packet',
                        subtype: packet.protocol || packet.Protocol || 'Unknown',
                        participants: [
                            packet.source || packet.Source || packet['Source IP'] || 'Unknown',
                            packet.destination || packet.Destination || packet['Destination IP'] || 'Unknown'
                        ],
                        location: null,
                        data: packet,
                        callId: call.callId
                    });
                }
            });
        }
    }

    // Sort all events by timestamp
    events.sort((a, b) => a.timestamp - b.timestamp);

    return events;
}

// Apply filters to timeline events
function applyTimelineFilters(events, filters) {
    return events.filter(event => {
        // Filter by event type
        if (filters.eventTypes && filters.eventTypes.length > 0) {
            if (!filters.eventTypes.includes(event.type)) {
                return false;
            }
        }

        // Filter by time range
        if (filters.startTime && event.timestamp < filters.startTime) {
            return false;
        }
        if (filters.endTime && event.timestamp > filters.endTime) {
            return false;
        }

        // Filter by participant
        if (filters.participant) {
            const normalizedFilter = normalizePhone(filters.participant);
            const hasParticipant = event.participants.some(p =>
                normalizePhone(p).includes(normalizedFilter)
            );
            if (!hasParticipant) {
                return false;
            }
        }

        // Filter by location
        if (filters.location && event.location) {
            if (!event.location.includes(filters.location)) {
                return false;
            }
        }

        return true;
    });
}

// Render individual timeline event
function renderTimelineEvent(event, analyzer) {
    const icons = {
        'call': '📞',
        'sms': '💬',
        'packet': '📦'
    };

    const icon = icons[event.type] || '•';
    const typeLabel = capitalize(event.type);
    const subtypeLabel = event.subtype || 'Unknown';

    let participants = '';
    if (event.participants && event.participants.length > 0) {
        participants = event.participants
            .filter(p => p && p !== 'Unknown')
            .map(p => `<span class="participant-chip">${p}</span>`)
            .join(' → ');
    }

    let locationHTML = '';
    if (event.location) {
        locationHTML = `<div class="timeline-location">📍 ${event.location}</div>`;
    }

    let detailsHTML = '';
    if (event.type === 'sms' && event.data.content) {
        detailsHTML = `<div class="timeline-event-details">${truncate(event.data.content, 100)}</div>`;
    } else if (event.type === 'packet' && event.data.info) {
        detailsHTML = `<div class="timeline-event-details">${truncate(event.data.info, 100)}</div>`;
    }

    return `
        <div class="timeline-event" data-type="${event.type}">
            <div class="timeline-event-header">
                <span class="timeline-icon">${icon}</span>
                <span class="timeline-time">${event.timestampStr}</span>
                <span class="timeline-type">${typeLabel} - ${subtypeLabel}</span>
            </div>
            ${participants ? `<div class="timeline-participants">${participants}</div>` : ''}
            ${locationHTML}
            ${detailsHTML}
        </div>
    `;
}

// Render timeline visualization with filters
function renderTimelineVisualization(call, analyzer, options = {}) {
    const includePackets = options.includePackets || false;
    const allEvents = buildUnifiedTimeline(call, analyzer, includePackets);

    if (allEvents.length === 0) {
        return '<p class="no-data">No timeline events available for this call.</p>';
    }

    // Get unique participants for filter dropdown
    const uniqueParticipants = new Set();
    allEvents.forEach(event => {
        event.participants.forEach(p => {
            if (p && p !== 'Unknown') {
                uniqueParticipants.add(p);
            }
        });
    });

    // Get unique locations for filter dropdown
    const uniqueLocations = new Set();
    allEvents.forEach(event => {
        if (event.location) {
            uniqueLocations.add(event.location);
        }
    });

    // Get time range
    const minTime = allEvents[0].timestamp;
    const maxTime = allEvents[allEvents.length - 1].timestamp;

    // Build filter controls HTML
    const filterChipsHTML = `
        <div class="filter-chips">
            <button class="filter-chip active" data-filter="all">All Events</button>
            <button class="filter-chip" data-filter="call">📞 Calls</button>
            <button class="filter-chip" data-filter="sms">💬 SMS/MMS</button>
            ${includePackets ? '<button class="filter-chip" data-filter="packet">📦 Packets</button>' : ''}
        </div>
    `;

    const participantOptions = Array.from(uniqueParticipants)
        .map(p => `<option value="${p}">${p}</option>`)
        .join('');

    const locationOptions = Array.from(uniqueLocations)
        .map(loc => `<option value="${loc}">${loc}</option>`)
        .join('');

    const filterControlsHTML = `
        <div class="timeline-controls">
            ${filterChipsHTML}
            <div class="timeline-filters">
                ${uniqueParticipants.size > 0 ? `
                    <select class="timeline-filter-select" id="timelineParticipantFilter">
                        <option value="">All Participants</option>
                        ${participantOptions}
                    </select>
                ` : ''}
                ${uniqueLocations.size > 0 ? `
                    <select class="timeline-filter-select" id="timelineLocationFilter">
                        <option value="">All Locations</option>
                        ${locationOptions}
                    </select>
                ` : ''}
            </div>
            <div class="timeline-stats">
                <span id="timelineEventCount">${allEvents.length} events</span>
            </div>
        </div>
    `;

    // Render all events
    const eventsHTML = allEvents.map(event => renderTimelineEvent(event, analyzer)).join('');

    return `
        <div class="timeline-visualization" id="timelineVisualization">
            ${filterControlsHTML}
            <div class="timeline-events-list" id="timelineEventsList">
                ${eventsHTML}
            </div>
        </div>
    `;
}

// ============================================================================
// ADVANCED SEARCH & FILTER FUNCTIONS
// ============================================================================

// Global search index storage
let globalSearchIndex = null;

// Build comprehensive search index from all data
function buildGlobalSearchIndex(analyzer, packetData = []) {
    const index = {
        phoneNumbers: new Map(),    // phone -> [{callId, context, timestamp, type}]
        keywords: new Map(),         // keyword -> [{callId, context, timestamp, type}]
        ipAddresses: new Map(),      // ip -> [{context, timestamp, type}]
        deviceIds: new Map(),        // device -> [{callId, context, timestamp}]
        locations: new Map()         // location -> [{callId, context, timestamp}]
    };

    // Index calls
    if (analyzer && analyzer.calls) {
        for (const [callId, call] of analyzer.calls) {
            // Index phone numbers from calling and called parties
            const callingNumber = call.callingParty?.number || call.callingParty?.phoneNumber;
            const calledNumber = call.calledParty?.number || call.calledParty?.phoneNumber;

            if (callingNumber) {
                addToIndex(index.phoneNumbers, normalizePhone(callingNumber), {
                    callId: callId,
                    context: `Calling party in ${call.callType}`,
                    timestamp: analyzer.parseTimestamp(call.startTime),
                    type: 'calling'
                });
            }

            if (calledNumber) {
                addToIndex(index.phoneNumbers, normalizePhone(calledNumber), {
                    callId: callId,
                    context: `Called party in ${call.callType}`,
                    timestamp: analyzer.parseTimestamp(call.startTime),
                    type: 'called'
                });
            }

            // Index SMS content keywords
            if (call.smsData && call.smsData.length > 0) {
                call.smsData.forEach(sms => {
                    // Index phone numbers from SMS
                    if (sms.from) {
                        addToIndex(index.phoneNumbers, normalizePhone(sms.from), {
                            callId: callId,
                            context: `SMS sender`,
                            timestamp: analyzer.parseTimestamp(sms.timestamp),
                            type: 'sms_from'
                        });
                    }
                    if (sms.to) {
                        addToIndex(index.phoneNumbers, normalizePhone(sms.to), {
                            callId: callId,
                            context: `SMS recipient`,
                            timestamp: analyzer.parseTimestamp(sms.timestamp),
                            type: 'sms_to'
                        });
                    }

                    // Index keywords from SMS content
                    if (sms.content) {
                        const keywords = extractKeywords(sms.content);
                        keywords.forEach(keyword => {
                            addToIndex(index.keywords, keyword, {
                                callId: callId,
                                context: `SMS: "${truncate(sms.content, 80)}"`,
                                timestamp: analyzer.parseTimestamp(sms.timestamp),
                                type: 'sms'
                            });
                        });
                    }
                });
            }

            // Index device IDs (User-Agent, device info)
            if (call.deviceInfo) {
                const deviceString = call.deviceInfo.userAgent ||
                                   call.deviceInfo.deviceType ||
                                   call.deviceInfo.manufacturer;
                if (deviceString) {
                    addToIndex(index.deviceIds, deviceString.toLowerCase(), {
                        callId: callId,
                        context: `Device: ${deviceString}`,
                        timestamp: analyzer.parseTimestamp(call.startTime),
                        type: 'device'
                    });
                }
            }

            // Index locations (LAC-CID)
            if (call.locations && call.locations.length > 0) {
                call.locations.forEach(loc => {
                    if (loc.parsed) {
                        const lacCidKey = `${loc.parsed.lac}-${loc.parsed.cellId}`;
                        addToIndex(index.locations, lacCidKey, {
                            callId: callId,
                            context: `Cell Tower: LAC ${loc.parsed.lac}, CID ${loc.parsed.cellId}`,
                            timestamp: analyzer.parseTimestamp(loc.timestamp),
                            type: 'location'
                        });

                        // Also index just LAC for broader searches
                        if (loc.parsed.lac) {
                            addToIndex(index.locations, `lac:${loc.parsed.lac}`, {
                                callId: callId,
                                context: `Location Area Code: ${loc.parsed.lac}`,
                                timestamp: analyzer.parseTimestamp(loc.timestamp),
                                type: 'lac'
                            });
                        }
                    }
                });
            }
        }
    }

    // Index packet data
    if (packetData && packetData.length > 0) {
        packetData.forEach((packet, idx) => {
            // Index source IP
            const sourceIp = packet.source || packet.Source || packet['Source IP'];
            if (sourceIp) {
                addToIndex(index.ipAddresses, sourceIp.toLowerCase(), {
                    context: `Packet source: ${packet.protocol || 'Unknown'} protocol`,
                    timestamp: analyzer?.parseTimestamp(packet.time || packet.timestamp) || null,
                    type: 'source_ip',
                    packetIndex: idx
                });
            }

            // Index destination IP
            const destIp = packet.destination || packet.Destination || packet['Destination IP'];
            if (destIp) {
                addToIndex(index.ipAddresses, destIp.toLowerCase(), {
                    context: `Packet destination: ${packet.protocol || 'Unknown'} protocol`,
                    timestamp: analyzer?.parseTimestamp(packet.time || packet.timestamp) || null,
                    type: 'dest_ip',
                    packetIndex: idx
                });
            }
        });
    }

    return index;
}

// Perform global search across all indexed data
function performGlobalSearch(searchTerm, index) {
    if (!searchTerm || !index) return [];

    const results = [];
    const normalizedTerm = searchTerm.toLowerCase().trim();

    // Search phone numbers (partial match)
    if (index.phoneNumbers.size > 0) {
        for (const [phone, entries] of index.phoneNumbers) {
            if (phone.includes(normalizedTerm) || normalizedTerm.includes(phone)) {
                entries.forEach(entry => {
                    results.push({
                        matchType: 'phone',
                        matchValue: phone,
                        ...entry
                    });
                });
            }
        }
    }

    // Search keywords (exact word match)
    if (index.keywords.size > 0) {
        const searchWords = extractKeywords(normalizedTerm);
        searchWords.forEach(word => {
            if (index.keywords.has(word)) {
                const entries = index.keywords.get(word);
                entries.forEach(entry => {
                    results.push({
                        matchType: 'keyword',
                        matchValue: word,
                        ...entry
                    });
                });
            }
        });
    }

    // Search IP addresses (substring match)
    if (index.ipAddresses.size > 0) {
        for (const [ip, entries] of index.ipAddresses) {
            if (ip.includes(normalizedTerm)) {
                entries.forEach(entry => {
                    results.push({
                        matchType: 'ip',
                        matchValue: ip,
                        ...entry
                    });
                });
            }
        }
    }

    // Search device IDs (substring match)
    if (index.deviceIds.size > 0) {
        for (const [deviceId, entries] of index.deviceIds) {
            if (deviceId.includes(normalizedTerm)) {
                entries.forEach(entry => {
                    results.push({
                        matchType: 'device',
                        matchValue: deviceId,
                        ...entry
                    });
                });
            }
        }
    }

    // Search locations (LAC or CID match)
    if (index.locations.size > 0) {
        for (const [location, entries] of index.locations) {
            if (location.includes(normalizedTerm)) {
                entries.forEach(entry => {
                    results.push({
                        matchType: 'location',
                        matchValue: location,
                        ...entry
                    });
                });
            }
        }
    }

    // Sort by timestamp (most recent first)
    results.sort((a, b) => {
        const timeA = a.timestamp || 0;
        const timeB = b.timestamp || 0;
        return timeB - timeA;
    });

    return results;
}

// Display search results
function displaySearchResults(results, searchTerm) {
    const container = document.getElementById('searchResultsContainer');
    if (!container) return;

    if (results.length === 0) {
        container.innerHTML = `
            <div class="search-results-empty">
                <p>No results found for "${searchTerm}"</p>
            </div>
        `;
        container.style.display = 'block';
        return;
    }

    // Group results by match type
    const grouped = groupBy(results, r => r.matchType);

    const matchTypeLabels = {
        'phone': '📞 Phone Numbers',
        'keyword': '💬 Keywords',
        'ip': '🌐 IP Addresses',
        'device': '📱 Devices',
        'location': '📍 Locations'
    };

    let html = `
        <div class="search-results-header">
            <strong>${results.length} results found</strong> for "${searchTerm}"
        </div>
        <div class="search-results-groups">
    `;

    for (const [matchType, items] of Object.entries(grouped)) {
        const label = matchTypeLabels[matchType] || capitalize(matchType);
        const displayLimit = 20;
        const hasMore = items.length > displayLimit;
        const displayItems = items.slice(0, displayLimit);

        html += `
            <div class="search-group">
                <div class="search-group-title">${label} (${items.length})</div>
                <div class="search-group-items">
        `;

        displayItems.forEach(item => {
            const timeStr = item.timestamp ?
                new Date(item.timestamp).toLocaleString() :
                'Unknown time';

            html += `
                <div class="search-result-item" data-call-id="${item.callId || ''}" data-packet-index="${item.packetIndex || ''}">
                    <div class="search-result-match">
                        <strong>${item.matchValue}</strong>
                    </div>
                    <div class="search-result-context">${item.context}</div>
                    <div class="search-result-time">${timeStr}</div>
                </div>
            `;
        });

        if (hasMore) {
            html += `<div class="search-more-indicator">... ${items.length - displayLimit} more results</div>`;
        }

        html += `
                </div>
            </div>
        `;
    }

    html += '</div>';
    container.innerHTML = html;
    container.style.display = 'block';

    // Add click handlers for navigation
    container.querySelectorAll('.search-result-item').forEach(item => {
        item.addEventListener('click', () => {
            const callId = item.getAttribute('data-call-id');
            if (callId && callId !== 'null' && callId !== '') {
                // Switch to that call
                const selector = document.getElementById('callSelector');
                if (selector) {
                    selector.value = callId;
                    switchCall(callId);
                }
            }
        });
    });
}

// Setup search bar with debounced search
function setupSearchBar() {
    const searchInput = document.getElementById('globalSearchInput');
    const searchButton = document.getElementById('globalSearchButton');
    const clearButton = document.getElementById('globalSearchClear');
    const resultsContainer = document.getElementById('searchResultsContainer');

    if (!searchInput || !searchButton || !clearButton) return;

    const performSearch = () => {
        const searchTerm = searchInput.value.trim();
        if (!searchTerm) {
            if (resultsContainer) {
                resultsContainer.style.display = 'none';
            }
            return;
        }

        if (!globalSearchIndex) {
            console.error('Search index not built');
            return;
        }

        const results = performGlobalSearch(searchTerm, globalSearchIndex);
        displaySearchResults(results, searchTerm);
    };

    // Debounced search on input
    const debouncedSearch = debounce(performSearch, 300);
    searchInput.addEventListener('input', debouncedSearch);

    // Immediate search on button click or Enter key
    searchButton.addEventListener('click', performSearch);
    searchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            performSearch();
        }
    });

    // Clear button
    clearButton.addEventListener('click', () => {
        searchInput.value = '';
        if (resultsContainer) {
            resultsContainer.style.display = 'none';
        }
    });
}

// ============================================================================
// CALL CORRELATION FUNCTIONS
// ============================================================================

// Detect time overlap between two calls
function detectTimeOverlap(call1, call2, analyzer) {
    const call1Start = analyzer.parseTimestamp(call1.answerTime || call1.startTime);
    const call1End = analyzer.parseTimestamp(call1.endTime);
    const call2Start = analyzer.parseTimestamp(call2.answerTime || call2.startTime);
    const call2End = analyzer.parseTimestamp(call2.endTime);

    if (!call1Start || !call2Start) return null;

    // Check if calls overlap
    const overlapStart = Math.max(call1Start, call2Start);
    const overlapEnd = Math.min(call1End || Infinity, call2End || Infinity);

    if (overlapStart < overlapEnd) {
        const overlapDuration = Math.round((overlapEnd - overlapStart) / 1000); // seconds
        return {
            call1: call1,
            call2: call2,
            overlapDuration: overlapDuration,
            scenario: 'Target on two calls simultaneously'
        };
    }

    return null;
}

// Find common participants between two calls
function findCommonParticipants(call1, call2) {
    const participants1 = new Set();
    const participants2 = new Set();

    // Collect participants from call1
    if (call1.callingParty?.number) participants1.add(normalizePhone(call1.callingParty.number));
    if (call1.callingParty?.phoneNumber) participants1.add(normalizePhone(call1.callingParty.phoneNumber));
    if (call1.calledParty?.number) participants1.add(normalizePhone(call1.calledParty.number));
    if (call1.calledParty?.phoneNumber) participants1.add(normalizePhone(call1.calledParty.phoneNumber));

    // Collect participants from call2
    if (call2.callingParty?.number) participants2.add(normalizePhone(call2.callingParty.number));
    if (call2.callingParty?.phoneNumber) participants2.add(normalizePhone(call2.callingParty.phoneNumber));
    if (call2.calledParty?.number) participants2.add(normalizePhone(call2.calledParty.number));
    if (call2.calledParty?.phoneNumber) participants2.add(normalizePhone(call2.calledParty.phoneNumber));

    // Find intersection
    const common = [];
    participants1.forEach(p => {
        if (participants2.has(p)) {
            common.push(p);
        }
    });

    return common;
}

// Find common cell towers between two calls
function findCommonTowers(call1, call2) {
    if (!call1.locations || !call2.locations) return [];

    const towers1 = new Map();
    const towers2 = new Map();

    // Build tower maps
    call1.locations.forEach(loc => {
        if (loc.parsed?.lac && loc.parsed?.cellId) {
            const key = `${loc.parsed.lac}-${loc.parsed.cellId}`;
            towers1.set(key, {
                lac: loc.parsed.lac,
                cellId: loc.parsed.cellId,
                timestamp: loc.timestamp
            });
        }
    });

    call2.locations.forEach(loc => {
        if (loc.parsed?.lac && loc.parsed?.cellId) {
            const key = `${loc.parsed.lac}-${loc.parsed.cellId}`;
            towers2.set(key, {
                lac: loc.parsed.lac,
                cellId: loc.parsed.cellId,
                timestamp: loc.timestamp
            });
        }
    });

    // Find common towers
    const common = [];
    towers1.forEach((tower, key) => {
        if (towers2.has(key)) {
            common.push({
                lac: tower.lac,
                cellId: tower.cellId,
                key: key
            });
        }
    });

    return common;
}

// Detect call forwarding sequences
function detectCallForwardingSequences(callArray, analyzer) {
    const sequences = [];

    // Sort calls by start time
    const sortedCalls = [...callArray].sort((a, b) => {
        const timeA = analyzer.parseTimestamp(a.startTime) || 0;
        const timeB = analyzer.parseTimestamp(b.startTime) || 0;
        return timeA - timeB;
    });

    // Check consecutive calls for forwarding pattern
    for (let i = 0; i < sortedCalls.length - 1; i++) {
        const call1 = sortedCalls[i];
        const call2 = sortedCalls[i + 1];

        const call1End = analyzer.parseTimestamp(call1.endTime || call1.startTime);
        const call2Start = analyzer.parseTimestamp(call2.startTime);

        if (!call1End || !call2Start) continue;

        // Check if calls are within 30 seconds
        const timeDiff = (call2Start - call1End) / 1000; // seconds
        if (timeDiff >= 0 && timeDiff <= 30) {
            // Check if called party of call1 becomes calling party of call2
            const call1Called = normalizePhone(call1.calledParty?.number || call1.calledParty?.phoneNumber || '');
            const call2Calling = normalizePhone(call2.callingParty?.number || call2.callingParty?.phoneNumber || '');

            if (call1Called && call2Calling && call1Called === call2Calling) {
                sequences.push({
                    call1: call1,
                    call2: call2,
                    timeDiff: Math.round(timeDiff),
                    forwardingNumber: call1Called
                });
            }
        }
    }

    return sequences;
}

// Main correlation orchestrator - finds all types of correlations
function findCallCorrelations(calls, analyzer) {
    const correlations = {
        timeOverlaps: [],
        commonParticipants: [],
        sameTowers: [],
        callForwarding: []
    };

    if (!calls || calls.size < 2) {
        return correlations;
    }

    const callArray = Array.from(calls.values());

    // Check all pairs for time overlap, common participants, and same towers
    for (let i = 0; i < callArray.length; i++) {
        for (let j = i + 1; j < callArray.length; j++) {
            const call1 = callArray[i];
            const call2 = callArray[j];

            // Check time overlap
            const overlap = detectTimeOverlap(call1, call2, analyzer);
            if (overlap) {
                correlations.timeOverlaps.push(overlap);
            }

            // Check common participants
            const commonParticipants = findCommonParticipants(call1, call2);
            if (commonParticipants.length > 0) {
                correlations.commonParticipants.push({
                    call1: call1,
                    call2: call2,
                    participants: commonParticipants
                });
            }

            // Check common towers
            const commonTowers = findCommonTowers(call1, call2);
            if (commonTowers.length > 0) {
                correlations.sameTowers.push({
                    call1: call1,
                    call2: call2,
                    towers: commonTowers
                });
            }
        }
    }

    // Check for call forwarding sequences
    correlations.callForwarding = detectCallForwardingSequences(callArray, analyzer);

    return correlations;
}

// Display call correlations
function displayCallCorrelations(correlations, analyzer) {
    if (!correlations) {
        return '<p class="no-data">No correlation data available.</p>';
    }

    const totalCorrelations = correlations.timeOverlaps.length +
                            correlations.commonParticipants.length +
                            correlations.sameTowers.length +
                            correlations.callForwarding.length;

    if (totalCorrelations === 0) {
        return '<p class="no-data">No significant correlations detected between calls.</p>';
    }

    let html = '<div class="correlation-analysis">';

    // Summary cards
    html += `
        <div class="correlation-summary">
            <div class="correlation-summary-card">
                <div class="correlation-summary-count">${correlations.timeOverlaps.length}</div>
                <div class="correlation-summary-label">Time Overlaps</div>
            </div>
            <div class="correlation-summary-card">
                <div class="correlation-summary-count">${correlations.commonParticipants.length}</div>
                <div class="correlation-summary-label">Common Participants</div>
            </div>
            <div class="correlation-summary-card">
                <div class="correlation-summary-count">${correlations.sameTowers.length}</div>
                <div class="correlation-summary-label">Same Towers</div>
            </div>
            <div class="correlation-summary-card">
                <div class="correlation-summary-count">${correlations.callForwarding.length}</div>
                <div class="correlation-summary-label">Call Forwarding</div>
            </div>
        </div>
    `;

    // Time Overlaps
    if (correlations.timeOverlaps.length > 0) {
        html += '<div class="correlation-section">';
        html += '<h3 class="correlation-section-title">⏱️ Time Overlaps</h3>';
        html += '<div class="correlation-list">';
        correlations.timeOverlaps.forEach(overlap => {
            html += `
                <div class="correlation-card">
                    <div class="correlation-header">
                        <strong>${overlap.scenario}</strong>
                    </div>
                    <div class="correlation-details">
                        <div class="correlation-call">
                            📞 Call 1: ${overlap.call1.callingParty?.phoneNumber || 'Unknown'} → ${overlap.call1.calledParty?.phoneNumber || 'Unknown'}
                            <br><small>${analyzer.formatTimestamp(overlap.call1.startTime)} - ${analyzer.formatTimestamp(overlap.call1.endTime)}</small>
                        </div>
                        <div class="correlation-call">
                            📞 Call 2: ${overlap.call2.callingParty?.phoneNumber || 'Unknown'} → ${overlap.call2.calledParty?.phoneNumber || 'Unknown'}
                            <br><small>${analyzer.formatTimestamp(overlap.call2.startTime)} - ${analyzer.formatTimestamp(overlap.call2.endTime)}</small>
                        </div>
                        <div class="correlation-stat">Overlap Duration: <strong>${overlap.overlapDuration} seconds</strong></div>
                    </div>
                </div>
            `;
        });
        html += '</div></div>';
    }

    // Common Participants
    if (correlations.commonParticipants.length > 0) {
        html += '<div class="correlation-section">';
        html += '<h3 class="correlation-section-title">👥 Common Participants</h3>';
        html += '<div class="correlation-list">';
        correlations.commonParticipants.forEach(item => {
            html += `
                <div class="correlation-card">
                    <div class="correlation-header">
                        <strong>Shared Contact</strong>
                    </div>
                    <div class="correlation-details">
                        <div class="correlation-call">
                            📞 Call 1: ${item.call1.callingParty?.phoneNumber || 'Unknown'} → ${item.call1.calledParty?.phoneNumber || 'Unknown'}
                        </div>
                        <div class="correlation-call">
                            📞 Call 2: ${item.call2.callingParty?.phoneNumber || 'Unknown'} → ${item.call2.calledParty?.phoneNumber || 'Unknown'}
                        </div>
                        <div class="correlation-stat">
                            Common Numbers: ${item.participants.map(p => `<span class="participant-chip">${p}</span>`).join(' ')}
                        </div>
                    </div>
                </div>
            `;
        });
        html += '</div></div>';
    }

    // Same Towers
    if (correlations.sameTowers.length > 0) {
        html += '<div class="correlation-section">';
        html += '<h3 class="correlation-section-title">📡 Same Cell Towers</h3>';
        html += '<div class="correlation-list">';
        correlations.sameTowers.forEach(item => {
            html += `
                <div class="correlation-card">
                    <div class="correlation-header">
                        <strong>Same Location</strong>
                    </div>
                    <div class="correlation-details">
                        <div class="correlation-call">
                            📞 Call 1: ${item.call1.callingParty?.phoneNumber || 'Unknown'} → ${item.call1.calledParty?.phoneNumber || 'Unknown'}
                        </div>
                        <div class="correlation-call">
                            📞 Call 2: ${item.call2.callingParty?.phoneNumber || 'Unknown'} → ${item.call2.calledParty?.phoneNumber || 'Unknown'}
                        </div>
                        <div class="correlation-stat">
                            Common Towers: ${item.towers.map(t => `LAC ${t.lac}, CID ${t.cellId}`).join(' | ')}
                        </div>
                    </div>
                </div>
            `;
        });
        html += '</div></div>';
    }

    // Call Forwarding
    if (correlations.callForwarding.length > 0) {
        html += '<div class="correlation-section">';
        html += '<h3 class="correlation-section-title">↪️ Call Forwarding Sequences</h3>';
        html += '<div class="correlation-list">';
        correlations.callForwarding.forEach(seq => {
            html += `
                <div class="correlation-card">
                    <div class="correlation-header">
                        <strong>Possible Call Forward</strong>
                    </div>
                    <div class="correlation-details">
                        <div class="correlation-call">
                            📞 First Call: ${seq.call1.callingParty?.phoneNumber || 'Unknown'} → <strong>${seq.forwardingNumber}</strong>
                            <br><small>Ended: ${analyzer.formatTimestamp(seq.call1.endTime)}</small>
                        </div>
                        <div class="correlation-call">
                            📞 Second Call: <strong>${seq.forwardingNumber}</strong> → ${seq.call2.calledParty?.phoneNumber || 'Unknown'}
                            <br><small>Started: ${analyzer.formatTimestamp(seq.call2.startTime)}</small>
                        </div>
                        <div class="correlation-stat">Time Gap: <strong>${seq.timeDiff} seconds</strong></div>
                    </div>
                </div>
            `;
        });
        html += '</div></div>';
    }

    html += '</div>';
    return html;
}

// Setup event handlers for timeline filters
function setupTimelineEventHandlers() {
    const visualization = document.getElementById('timelineVisualization');
    if (!visualization) return;

    // Store original events data
    const eventsList = document.getElementById('timelineEventsList');
    if (!eventsList) return;

    const allEventElements = eventsList.querySelectorAll('.timeline-event');
    let activeFilters = {
        eventTypes: [],
        participant: '',
        location: ''
    };

    // Update display based on active filters
    function updateDisplay() {
        let visibleCount = 0;
        allEventElements.forEach(eventEl => {
            const eventType = eventEl.getAttribute('data-type');
            let visible = true;

            // Check event type filter
            if (activeFilters.eventTypes.length > 0 && !activeFilters.eventTypes.includes(eventType)) {
                visible = false;
            }

            // Check participant filter (search in text content)
            if (visible && activeFilters.participant) {
                const participantSection = eventEl.querySelector('.timeline-participants');
                if (!participantSection || !participantSection.textContent.includes(activeFilters.participant)) {
                    visible = false;
                }
            }

            // Check location filter
            if (visible && activeFilters.location) {
                const locationSection = eventEl.querySelector('.timeline-location');
                if (!locationSection || !locationSection.textContent.includes(activeFilters.location)) {
                    visible = false;
                }
            }

            eventEl.style.display = visible ? 'block' : 'none';
            if (visible) visibleCount++;
        });

        // Update count
        const countEl = document.getElementById('timelineEventCount');
        if (countEl) {
            countEl.textContent = `${visibleCount} of ${allEventElements.length} events`;
        }
    }

    // Filter chip click handlers
    const filterChips = visualization.querySelectorAll('.filter-chip');
    filterChips.forEach(chip => {
        chip.addEventListener('click', () => {
            const filterType = chip.getAttribute('data-filter');

            if (filterType === 'all') {
                // Reset event type filter
                activeFilters.eventTypes = [];
                filterChips.forEach(c => c.classList.remove('active'));
                chip.classList.add('active');
            } else {
                // Toggle specific event type
                const allChip = visualization.querySelector('.filter-chip[data-filter="all"]');
                allChip.classList.remove('active');

                if (chip.classList.contains('active')) {
                    chip.classList.remove('active');
                    activeFilters.eventTypes = activeFilters.eventTypes.filter(t => t !== filterType);

                    // If no chips active, activate "All"
                    if (activeFilters.eventTypes.length === 0) {
                        allChip.classList.add('active');
                    }
                } else {
                    chip.classList.add('active');
                    activeFilters.eventTypes.push(filterType);
                }
            }

            updateDisplay();
        });
    });

    // Participant filter
    const participantFilter = document.getElementById('timelineParticipantFilter');
    if (participantFilter) {
        participantFilter.addEventListener('change', (e) => {
            activeFilters.participant = e.target.value;
            updateDisplay();
        });
    }

    // Location filter
    const locationFilter = document.getElementById('timelineLocationFilter');
    if (locationFilter) {
        locationFilter.addEventListener('change', (e) => {
            activeFilters.location = e.target.value;
            updateDisplay();
        });
    }
}

// Explicitly expose functions to the global scope to ensure buttons work
window.analyzeCDC = analyzeCDC;
window.switchCall = switchCall;
window.clearAll = clearAll;
window.exportCSV = exportCSV;
window.handleTowerUpload = handleTowerUpload;
window.toggleSettings = toggleSettings;
window.saveCloudSettings = saveCloudSettings;
window.syncTowersFromCloud = syncTowersFromCloud;
window.uploadTowersToCloud = uploadTowersToCloud;
window.switchTab = switchTab;
window.handlePacketUpload = handlePacketUpload;
window.clearPacketAnalysis = clearPacketAnalysis;
window.lookupWhois = lookupWhois;
window.performBulkWhois = performBulkWhois;
window.viewWhoisCache = viewWhoisCache;
window.closeWhoisCache = closeWhoisCache;
window.resolveReverseDNS = resolveReverseDNS;

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

console.log("CDC Analyzer script v2.0 (build 2026-02-10-timeline-search-correlation) loaded and ready (Timeline Visualization, Advanced Search, Call Correlation).");
