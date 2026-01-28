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
                result.data = this.parseSIPMessage(block);
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
            if (match) return match[1].trim();
        }
        return null;
    }

    extractNestedField(block, parentField, childField) {
        const regex = new RegExp(`${parentField}[\\s\\S]*?${childField}\\s*=\\s*(.+?)(?:\\n|$)`, 'i');
        const match = block.match(regex);
        return match ? match[1].trim() : null;
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
        const data = { calling: {}, called: {}, sdp: null };
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

    parseSIPMessage(block) {
        const data = { sipMessages: [], correlationId: null };
        data.correlationId = this.extractField(block, 'correlationID');
        const sigMsgMatch = block.match(/sigMsg\s*=\s*([\s\S]*?)(?=\[bin\]|$)/);
        if (sigMsgMatch) {
            const sipContent = sigMsgMatch[1].trim();
            data.sipMessages.push({
                content: sipContent,
                parsed: this.parseSIPContent(sipContent)
            });
        }
        return data;
    }

    parseSIPContent(sipContent) {
        const parsed = { method: null, statusCode: null, statusText: null, headers: {}, isRequest: false, isResponse: false };
        const lines = sipContent.split('\n');
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
        const locationMatches = block.matchAll(/location\[\d+\]\s*\n\s*locationType\s*=\s*(.+)\n\s*locationData\s*=\s*(.+)/gi);
        for (const match of locationMatches) {
            const locationData = { type: match[1].trim(), rawData: match[2].trim(), parsed: {} };
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
                break;
            case 'origAttempt':
                call.callDirection = 'Outgoing';
                call.startTime = message.timestamp;
                if (message.data.calling) call.callingParty = message.data.calling;
                if (message.data.called) call.calledParty = message.data.called;
                break;
            case 'directSignalReporting':
                if (message.data.sipMessages) {
                    for (const sip of message.data.sipMessages) {
                        call.sipMessages.push({ timestamp: message.timestamp, ...sip });
                        if (sip.parsed?.headers) {
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

function analyzeCDC() {
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
        const preferredId = choosePreferredCallId(currentAnalyzer.calls);
        if (preferredId) selector.value = preferredId;
        switchCall(selector.value);
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
            let tower = towerDatabase.get(compositeKey);
            if (!tower && fullKey) tower = towerDatabaseFullId.get(fullKey);
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

    container.innerHTML = sections.join('');
    setupCollapsibles();

    setTimeout(() => {
        if (typeof mermaid !== 'undefined') {
            try {
                mermaid.init();
            } catch (e) { console.error("Mermaid init failed", e); }
        }
        if (call.locations.length > 0) initMap(call.locations);
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

function deriveTacFromEcgi(ecgi) {
    if (!ecgi) return null;
    const cleaned = ecgi.toString().trim().replace(/[^0-9a-fA-F\-:]/g, '');
    const parts = cleaned.split(/[-:]/).filter(Boolean);
    const hexPart = parts.length > 1 ? parts[1] : parts[0];
    if (!hexPart) return null;
    const numeric = parseInt(hexPart, 16);
    if (Number.isNaN(numeric)) return null;
    return Math.floor(numeric / 256).toString();
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

            const tower = towerDatabase.get(`${loc.parsed.lac}-${loc.parsed.cellId}`);
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
        cid: headers.findIndex(h => h === 'cgi' || h === 'cell id' || h === 'cellid' || h.includes('cell identifier') || h === 'cell_id' || h === 'eci' || h === 'ci'),
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
        const cid = row[colIdx.cid];
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
                sectorName: nameVal ? nameVal : null
            });
            const stored = towerDatabase.get(key);
            const fullIdKey = normalizeFullCellId(ecgiVal);
            if (fullIdKey && stored) {
                towerDatabaseFullId.set(fullIdKey, stored);
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

async function syncTowersFromCloud() {
    if (!initializeSupabase()) {
        console.warn("Supabase not initialized. Cannot sync.");
        return;
    }

    const syncBtn = document.getElementById('syncBtn');
    syncBtn.textContent = "Syncing...";
    syncBtn.disabled = true;
    const towerStatus = document.getElementById('towerStatus');

    try {
        const needed = collectNeededTowerKeys();
        if (needed.size === 0) {
            towerStatus.textContent = "No referenced towers found in logs. Upload CSV for local data or load a log first.";
            console.warn("Skipping tower sync: no LAC/CID references detected.");
            return;
        }

        const neededLacs = Array.from(new Set([...needed].map(key => key.split('-')[0])).values());
        towerStatus.textContent = `Syncing ${needed.size} towers...`;
        const { data, error } = await supabaseClient
            .from('towers')
            .select('*')
            .in('lac', neededLacs);

        if (error) throw error;

        if (data && data.length > 0) {
            let loaded = 0;
            data.forEach(row => {
                const key = `${row.lac}-${row.cid}`;
                if (needed.has(key)) {
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
                    loaded++;
                }
            });

            towerStatus.innerHTML = `<span style="color: var(--success-color); font-weight: 600;">✓ ${loaded} towers synced from Cloud</span>`;
            console.log(`Synced ${loaded} towers from Supabase (targeted).`);

            if (currentAnalyzer) {
                analyzeCDC();
            }
        } else {
            towerStatus.textContent = "No matching towers found in cloud.";
        }

    } catch (e) {
        console.error("Cloud sync failed:", e);
        alert("Cloud sync failed. Check your Supabase settings or internet connection.");
    } finally {
        syncBtn.textContent = "Sync Cloud";
        syncBtn.disabled = false;
    }
}

function collectNeededTowerKeys() {
    const needed = new Set();
    if (!currentAnalyzer) return needed;
    currentAnalyzer.calls.forEach(call => {
        for (const loc of call.locations) {
            const lac = loc.parsed?.lac;
            const cellId = loc.parsed?.cellId;
            if (lac && cellId) {
                needed.add(`${lac}-${cellId}`);
            }
        }
    });
    return needed;
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
            const rawChunk = allRows.slice(i, i + BATCH_SIZE);
            const chunkMap = new Map();
            rawChunk.forEach(row => {
                const key = `${row.lac}-${row.cid}`;
                chunkMap.set(key, row);
            });
            const uniqueChunk = Array.from(chunkMap.values());

            towerStatus.textContent = `Uploading chunk... (${i + uniqueChunk.length} / ${allRows.length})`;

            const { error } = await supabaseClient.from('towers').upsert(uniqueChunk, { onConflict: 'lac,cid' });
            if (error) throw error;

            uploaded += uniqueChunk.length;
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
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3 (Email)',
    143: 'IMAP (Email)',
    443: 'HTTPS',
    465: 'SMTPS (Secure Email)',
    587: 'SMTP Submission',
    993: 'IMAPS (Secure Email)',
    995: 'POP3S (Secure Email)',
    3306: 'MySQL',
    3389: 'RDP',
    5060: 'SIP (VoIP)',
    5061: 'SIP-TLS (Secure VoIP)',
    5223: 'Apple Push Notification / XMPP',
    5228: 'Google Cloud Messaging',
    5242: 'Viber',
    8080: 'HTTP Alternate',
    8443: 'HTTPS Alternate',
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

    // Analyze IPs and services
    const ipAnalysis = {};
    const serviceStats = {};
    const portStats = {};
    const appDetection = {};

    packetData.forEach(packet => {
        const srcIP = packet['Source Address'];
        const dstIP = packet['Destination Address'];
        const srcPort = packet['Source Port'];
        const dstPort = packet['Destination Port'];
        const protocol = packet['Session Protocol'] || packet['Transport Protocol'];
        const bytes = parseInt(packet['Bytes']) || 0;

        // Analyze source IP
        if (srcIP && srcIP !== '' && !srcIP.startsWith('fd00:')) {
            if (!ipAnalysis[srcIP]) {
                ipAnalysis[srcIP] = {
                    packets: 0,
                    bytes: 0,
                    ports: new Set(),
                    service: identifyService(srcIP, srcPort),
                    protocols: new Set()
                };
            }
            ipAnalysis[srcIP].packets++;
            ipAnalysis[srcIP].bytes += bytes;
            if (srcPort) ipAnalysis[srcIP].ports.add(srcPort);
            if (protocol) ipAnalysis[srcIP].protocols.add(protocol);
        }

        // Analyze destination IP
        if (dstIP && dstIP !== '' && !dstIP.startsWith('fd00:')) {
            if (!ipAnalysis[dstIP]) {
                ipAnalysis[dstIP] = {
                    packets: 0,
                    bytes: 0,
                    ports: new Set(),
                    service: identifyService(dstIP, dstPort),
                    protocols: new Set()
                };
            }
            ipAnalysis[dstIP].packets++;
            ipAnalysis[dstIP].bytes += bytes;
            if (dstPort) ipAnalysis[dstIP].ports.add(dstPort);
            if (protocol) ipAnalysis[dstIP].protocols.add(protocol);
        }

        // Track port usage
        if (dstPort && dstPort !== '0' && dstPort !== '') {
            portStats[dstPort] = (portStats[dstPort] || 0) + 1;
        }

        // Track protocols
        if (protocol && protocol !== '') {
            serviceStats[protocol] = (serviceStats[protocol] || 0) + 1;
        }

        // App detection
        const app = detectApp(srcIP, dstIP, srcPort, dstPort, protocol);
        if (app) {
            if (!appDetection[app]) {
                appDetection[app] = { count: 0, bytes: 0, ips: new Set() };
            }
            appDetection[app].count++;
            appDetection[app].bytes += bytes;
            appDetection[app].ips.add(srcIP);
            appDetection[app].ips.add(dstIP);
        }
    });

    displayPacketAnalysis(ipAnalysis, serviceStats, portStats, appDetection);
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

function displayPacketAnalysis(ipAnalysis, serviceStats, portStats, appDetection) {
    const resultsDiv = document.getElementById('packetResults');
    resultsDiv.style.display = 'block';

    let html = '<div class="input-section">';

    // Database Stats
    html += '<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px; border-radius: 8px; margin-bottom: 20px;">';
    html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
    html += '<div><strong>IP WHOIS Database:</strong> <span id="dbCacheCount">Checking...</span></div>';
    html += '<button class="btn-secondary" onclick="viewWhoisCache()" style="background: white; color: #667eea; border: none;">View Cache</button>';
    html += '</div></div>';

    // App Detection Section
    html += '<h3 style="color: var(--primary-color); margin-bottom: 15px;">Detected Applications & Services</h3>';
    if (Object.keys(appDetection).length > 0) {
        html += '<div class="summary-grid" style="grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin-bottom: 25px;">';

        const sortedApps = Object.entries(appDetection).sort((a, b) => b[1].bytes - a[1].bytes);
        sortedApps.forEach(([app, data]) => {
            const appName = formatAppName(app);
            const category = categorizeApp(app);
            html += `
                <div class="summary-card" style="background: ${getCategoryColor(category)};">
                    <div class="summary-label">${appName}</div>
                    <div class="summary-value">${data.count} connections</div>
                    <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 5px;">
                        ${formatBytes(data.bytes)} transferred<br>
                        ${data.ips.size} unique IPs<br>
                        <span style="color: var(--warning-color); font-weight: 600;">${category}</span>
                    </div>
                </div>
            `;
        });
        html += '</div>';
    } else {
        html += '<p style="color: var(--text-secondary);">No specific apps detected</p>';
    }

    // Top IPs Section
    html += '<h3 style="color: var(--primary-color); margin-bottom: 15px; margin-top: 25px;">Top IP Addresses</h3>';
    html += `
        <div style="display: flex; gap: 10px; margin-bottom: 15px;">
            <button class="btn-secondary" onclick="performBulkWhois()">Run WHOIS on All IPs</button>
            <span id="whoisProgress" style="padding: 10px; color: var(--text-secondary);"></span>
        </div>
    `;
    html += '<div style="overflow-x: auto;"><table class="data-table" style="width: 100%; border-collapse: collapse;">';
    html += '<thead><tr style="background: var(--primary-color); color: white;">';
    html += '<th style="padding: 12px; text-align: left;">IP Address</th>';
    html += '<th style="padding: 12px; text-align: left;">Service</th>';
    html += '<th style="padding: 12px; text-align: right;">Packets</th>';
    html += '<th style="padding: 12px; text-align: right;">Bytes</th>';
    html += '<th style="padding: 12px; text-align: left;">Ports</th>';
    html += '<th style="padding: 12px; text-align: left;">Protocols</th>';
    html += '<th style="padding: 12px; text-align: left;">WHOIS</th>';
    html += '</tr></thead><tbody>';

    const sortedIPs = Object.entries(ipAnalysis)
        .sort((a, b) => b[1].bytes - a[1].bytes)
        .slice(0, 50); // Top 50 IPs

    sortedIPs.forEach(([ip, data]) => {
        const ports = Array.from(data.ports).slice(0, 5).join(', ');
        const protocols = Array.from(data.protocols).join(', ');
        html += `
            <tr style="border-bottom: 1px solid var(--border-color);">
                <td style="padding: 10px; font-family: monospace;">${ip}</td>
                <td style="padding: 10px;"><span style="background: var(--info-color); color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.85rem;">${data.service}</span></td>
                <td style="padding: 10px; text-align: right;">${data.packets}</td>
                <td style="padding: 10px; text-align: right;">${formatBytes(data.bytes)}</td>
                <td style="padding: 10px; font-size: 0.85rem;">${ports}</td>
                <td style="padding: 10px; font-size: 0.85rem;">${protocols}</td>
                <td style="padding: 10px;"><button class="btn-secondary" style="padding: 5px 10px; font-size: 0.8rem;" onclick="lookupWhois('${ip}')">Lookup</button> <span id="whois-${ip.replace(/:/g, '-')}"></span></td>
            </tr>
        `;
    });

    html += '</tbody></table></div>';

    // Port Statistics
    html += '<h3 style="color: var(--primary-color); margin-bottom: 15px; margin-top: 25px;">Port Usage Statistics</h3>';
    html += '<div style="overflow-x: auto;"><table class="data-table" style="width: 100%; border-collapse: collapse;">';
    html += '<thead><tr style="background: var(--primary-color); color: white;">';
    html += '<th style="padding: 12px; text-align: left;">Port</th>';
    html += '<th style="padding: 12px; text-align: left;">Service</th>';
    html += '<th style="padding: 12px; text-align: right;">Connections</th>';
    html += '</tr></thead><tbody>';

    const sortedPorts = Object.entries(portStats)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 30);

    sortedPorts.forEach(([port, count]) => {
        const service = PORT_SERVICES[port] || 'Unknown';
        html += `
            <tr style="border-bottom: 1px solid var(--border-color);">
                <td style="padding: 10px; font-weight: 600;">${port}</td>
                <td style="padding: 10px;">${service}</td>
                <td style="padding: 10px; text-align: right;">${count}</td>
            </tr>
        `;
    });

    html += '</tbody></table></div>';

    // Protocol Statistics
    html += '<h3 style="color: var(--primary-color); margin-bottom: 15px; margin-top: 25px;">Protocol Distribution</h3>';
    html += '<div class="summary-grid" style="grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">';

    Object.entries(serviceStats).forEach(([protocol, count]) => {
        html += `
            <div class="summary-card">
                <div class="summary-label">${protocol.toUpperCase()}</div>
                <div class="summary-value">${count}</div>
            </div>
        `;
    });

    html += '</div></div>';

    resultsDiv.innerHTML = html;

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
        'Messaging': 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
        'Social Media': 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
        'System Service': 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
        'Push Notifications': 'linear-gradient(135deg, #43e97b 0%, #38f9d7 100%)',
        'Voice/Video Call': 'linear-gradient(135deg, #fa709a 0%, #fee140 100%)',
        'Streaming': 'linear-gradient(135deg, #30cfd0 0%, #330867 100%)',
        'Banking': 'linear-gradient(135deg, #2ecc71 0%, #27ae60 100%)',
        'Financial': 'linear-gradient(135deg, #f39c12 0%, #e67e22 100%)',
        'E-Commerce/Cloud': 'linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%)',
        'Productivity': 'linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%)',
        'Email': 'linear-gradient(135deg, #3498db 0%, #2980b9 100%)',
        'Transportation': 'linear-gradient(135deg, #1abc9c 0%, #16a085 100%)',
        'Food Delivery': 'linear-gradient(135deg, #e74c3c 0%, #c0392b 100%)',
        'Other': 'linear-gradient(135deg, #a1c4fd 0%, #c2e9fb 100%)',
    };
    return colors[category] || colors['Other'];
}

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

async function lookupWhois(ip) {
    const displayId = 'whois-' + ip.replace(/:/g, '-');
    const displayEl = document.getElementById(displayId);

    // Check in-memory cache first
    if (ipWhoisCache[ip]) {
        displayEl.innerHTML = ipWhoisCache[ip];
        return;
    }

    displayEl.innerHTML = '<span style="color: var(--info-color);">Loading...</span>';

    try {
        // Step 1: Check database first
        if (supabaseClient) {
            const { data: dbData, error: dbError } = await supabaseClient
                .from('ip_whois')
                .select('*')
                .eq('ip_address', ip)
                .single();

            if (!dbError && dbData) {
                // Found in database - use cached data
                const info = formatWhoisInfo(dbData);
                ipWhoisCache[ip] = info;
                displayEl.innerHTML = info + ' <span style="color: var(--success-color); font-size: 0.75rem;">(cached)</span>';
                return;
            }
        }

        // Step 2: Not in database - perform API lookup
        const response = await fetch(`https://ipapi.co/${ip}/json/`);
        const data = await response.json();

        if (!data.error) {
            // Step 3: Store in database for future use
            if (supabaseClient) {
                await supabaseClient
                    .from('ip_whois')
                    .upsert({
                        ip_address: ip,
                        organization: data.org || data.asn || 'Unknown',
                        country: data.country_name || '',
                        city: data.city || '',
                        region: data.region || '',
                        asn: data.asn || '',
                        isp: data.org || '',
                        lookup_date: new Date().toISOString()
                    }, {
                        onConflict: 'ip_address'
                    });
            }

            const info = formatWhoisInfo({
                organization: data.org || data.asn || 'Unknown',
                country: data.country_name || '',
                city: data.city || ''
            });
            ipWhoisCache[ip] = info;
            displayEl.innerHTML = info;
        } else {
            displayEl.innerHTML = '<span style="color: var(--danger-color);">Failed</span>';
        }
    } catch (error) {
        console.error('WHOIS lookup error:', error);
        displayEl.innerHTML = '<span style="color: var(--danger-color);">Error</span>';
    }

    // Rate limit: wait 1.5 seconds between requests (ipapi.co free tier: 1000/day, ~1 req/sec recommended)
    await new Promise(resolve => setTimeout(resolve, 1500));
}

function formatWhoisInfo(data) {
    return `<div style="font-size: 0.85rem; margin-top: 5px;">
        <strong>${data.organization || 'Unknown'}</strong><br>
        ${data.country || ''} ${data.city ? '- ' + data.city : ''}
    </div>`;
}

async function performBulkWhois() {
    const progressEl = document.getElementById('whoisProgress');

    // Get all IP elements that need lookup
    const ipElements = document.querySelectorAll('[id^="whois-"]');
    const ipsToLookup = Array.from(ipElements).map(el => {
        const ip = el.id.replace('whois-', '').replace(/-/g, ':');
        return { ip, element: el };
    });

    if (ipsToLookup.length === 0) {
        progressEl.textContent = 'No IPs to lookup';
        return;
    }

    const total = Math.min(ipsToLookup.length, 50); // Limit to 50 IPs
    progressEl.innerHTML = `<span style="color: var(--info-color);">Looking up ${total} IPs...</span>`;

    // Step 1: Bulk check database for all IPs
    let dbHits = 0;
    let apiCalls = 0;

    if (supabaseClient) {
        try {
            const ipAddresses = ipsToLookup.slice(0, total).map(item => item.ip);
            const { data: dbData, error: dbError } = await supabaseClient
                .from('ip_whois')
                .select('*')
                .in('ip_address', ipAddresses);

            if (!dbError && dbData) {
                // Display all database hits immediately
                dbData.forEach(record => {
                    const displayId = 'whois-' + record.ip_address.replace(/:/g, '-');
                    const displayEl = document.getElementById(displayId);
                    if (displayEl) {
                        const info = formatWhoisInfo({
                            organization: record.organization,
                            country: record.country,
                            city: record.city
                        });
                        ipWhoisCache[record.ip_address] = info;
                        displayEl.innerHTML = info + ' <span style="color: var(--success-color); font-size: 0.75rem;">(cached)</span>';
                        dbHits++;
                    }
                });

                progressEl.innerHTML = `<span style="color: var(--success-color);">Found ${dbHits} in cache, looking up remaining...</span>`;
            }
        } catch (error) {
            console.error('Database bulk lookup error:', error);
        }
    }

    // Step 2: API lookup for IPs not in database
    for (let i = 0; i < total; i++) {
        const { ip, element } = ipsToLookup[i];

        // Skip if already loaded from database
        if (ipWhoisCache[ip]) {
            continue;
        }

        await lookupWhois(ip);
        apiCalls++;
        progressEl.innerHTML = `<span style="color: var(--info-color);">Progress: ${dbHits + apiCalls}/${total} (${dbHits} cached, ${apiCalls} new)</span>`;
    }

    progressEl.innerHTML = `<span style="color: var(--success-color);">Complete! ${dbHits} from cache, ${apiCalls} new lookups</span>`;
    setTimeout(() => {
        progressEl.textContent = '';
    }, 5000);
}

function clearPacketAnalysis() {
    packetData = [];
    ipWhoisCache = {};
    document.getElementById('packetResults').style.display = 'none';
    document.getElementById('packetStatus').innerHTML = 'No packet data loaded';
    document.getElementById('packetFileInput').value = '';
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

console.log("CDC Analyzer script v1.2 loaded and ready (Supabase Cloud Support).");
