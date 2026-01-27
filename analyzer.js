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
        const messageTypes = [
            'termAttempt', 'origAttempt', 'directSignalReporting',
            'ccOpen', 'ccClose', 'answer', 'release',
            'ims_3gpp_VoIP_answer', 'ims_3gpp_VoIP_release',
            'smsMessage', 'mmsMessage'
        ];

        const blocks = [];
        const lines = data.split('\n');
        let currentBlock = [];

        for (const line of lines) {
            const trimmed = line.trim();
            const isNewHeader = (trimmed.match(/^[A-Za-z].*Version \d/));

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

        if (block.includes('termAttempt') && !block.includes('ims_3gpp')) result.type = 'termAttempt';
        else if (block.includes('origAttempt')) result.type = 'origAttempt';
        else if (block.includes('directSignalReporting')) result.type = 'directSignalReporting';
        else if (block.includes('ccOpen')) result.type = 'ccOpen';
        else if (block.includes('ccClose')) result.type = 'ccClose';
        else if (block.includes('ims_3gpp_VoIP_answer') || (block.includes('answer') && block.includes('answering'))) result.type = 'answer';
        else if (block.includes('ims_3gpp_VoIP_release') || (block.includes('release') && block.includes('cause'))) result.type = 'release';
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
        const regex = new RegExp(`${fieldName}\\s*=\\s*(.+?)(?:\\n|$)`, 'i');
        const match = block.match(regex);
        return match ? match[1].trim() : null;
    }

    extractNestedField(block, parentField, childField) {
        const regex = new RegExp(`${parentField}[\\s\\S]*?${childField}\\s*=\\s*(.+?)(?:\\n|$)`, 'i');
        const match = block.match(regex);
        return match ? match[1].trim() : null;
    }

    parseAttemptMessage(block) {
        const data = { calling: {}, called: {}, sdp: null };
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
        return data;
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
            const cellMatch = locationData.rawData.match(/utran-cell-id-3gpp=(\d+)/i);
            if (cellMatch) {
                locationData.parsed = this.parseCellId(cellMatch[1]);
            }
            locations.push(locationData);
        }
        return locations;
    }

    parseCellId(cellId) {
        const result = { fullCellId: cellId, mcc: null, mnc: null, lac: null, cellId: null };
        if (cellId.length >= 15) {
            result.mcc = cellId.substring(0, 3);
            result.mnc = cellId.substring(3, 6);
            const tacAndCell = cellId.substring(6);
            result.lac = tacAndCell.substring(0, 4);
            result.cellId = tacAndCell.substring(4);
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
                                const nameMatch = (Array.isArray(pai) ? pai[0] : pai).match(/"([^"]+)"/);
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
                                const cellMatch = (Array.isArray(pani) ? pani[0] : pani).match(/utran-cell-id-3gpp=(\w+)/i);
                                if (cellMatch) {
                                    if (!call.locations.find(l => l.parsed?.fullCellId === cellMatch[1])) {
                                        call.locations.push({ type: 'P-A-N-I-Header', rawData: pani, parsed: this.parseCellId(cellMatch[1]), timestamp: message.timestamp });
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

// Global state for multi-call UI
let currentAnalyzer = null;

function analyzeCDC() {
    const input = document.getElementById('cdcInput').value;
    if (!input.trim()) return;

    currentAnalyzer = new CDCAnalyzer(input);
    currentAnalyzer.parse();

    const selector = document.getElementById('callSelector');
    selector.innerHTML = '';

    currentAnalyzer.calls.forEach((call, id) => {
        const option = document.createElement('option');
        option.value = id;
        const time = call.startTime ? currentAnalyzer.formatTimestamp(call.startTime) : 'No Start Time';
        const parties = `${call.callingParty.phoneNumber || 'Unknown'} -> ${call.calledParty.phoneNumber || 'Unknown'}`;
        option.textContent = `[${call.callType}] ${time} | ${parties}`;
        selector.appendChild(option);
    });

    document.getElementById('callSelectorContainer').style.display = currentAnalyzer.calls.size > 0 ? 'flex' : 'none';

    if (currentAnalyzer.calls.size > 0) {
        switchCall(selector.value);
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
            <div class="info-row"><span class="info-label">Status</span><span class="info-value"><span class="badge badge-success">${call.callStatus || 'Known'}</span></span></div>
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
    if (call.sipMessages.length > 0) {
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
                <div id="map" style="height: 400px; border-radius: 8px; border: 1px solid var(--border-color); margin-bottom: 20px;"></div>
                <div class="location-grid">
                    ${call.locations.map(loc => `
                        <div class="location-item">
                            <strong>${loc.type}</strong> (${analyzer.formatTimestamp(loc.timestamp)})<br>
                            MCC: ${loc.parsed.mcc} MNC: ${loc.parsed.mnc} LAC: ${loc.parsed.lac} CellID: ${loc.parsed.cellId}
                        </div>
                    `).join('')}
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

    // Timeline and Technical remains similar but filtered for the call
    // ...

    container.innerHTML = html;

    // Render Mermaid and Map
    setTimeout(() => {
        mermaid.init();
        if (call.locations.length > 0) initMap(call.locations);
    }, 100);
}

function generateFlowMarkup(call) {
    let markup = "";
    call.sipMessages.forEach(msg => {
        const p = msg.parsed;
        if (p.isRequest) {
            markup += `T->>C: ${p.method}\n`;
        } else {
            markup += `C-->>T: ${p.statusCode} ${p.statusText}\n`;
        }
    });
    return markup;
}

function initMap(locations) {
    const map = L.map('map').setView([40.7128, -74.0060], 13); // Default NYC, but should use lookup
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; OpenStreetMap contributors'
    }).addTo(map);

    locations.forEach(loc => {
        // Placeholder coordinate generation based on LAC/CellID bits
        const lat = 40.7 + (parseInt(loc.parsed.lac || 0, 16) % 100) / 1000;
        const lng = -73.9 + (parseInt(loc.parsed.cellId || 0, 16) % 100) / 1000;
        L.marker([lat, lng]).addTo(map)
            .bindPopup(`<b>${loc.type}</b><br>Cell ID: ${loc.parsed.cellId}`)
            .openPopup();
    });
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
