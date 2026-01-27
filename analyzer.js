// CDC Parser and Analyzer
class CDCAnalyzer {
    constructor(rawData) {
        this.rawData = rawData;
        this.messages = [];
        this.callInfo = {
            caseId: null,
            callId: null,
            callingParty: {},
            calledParty: {},
            callerName: null,
            startTime: null,
            answerTime: null,
            endTime: null,
            duration: null,
            callType: null,
            callDirection: null,
            deviceInfo: {},
            locations: [],
            codecs: [],
            sipMessages: [],
            callStatus: null,
            releaseReason: null,
            verificationStatus: null
        };
    }

    parse() {
        // Split into individual message blocks
        const messageBlocks = this.splitIntoMessages(this.rawData);

        for (const block of messageBlocks) {
            const parsed = this.parseMessageBlock(block);
            if (parsed) {
                this.messages.push(parsed);
                this.extractCallInfo(parsed);
            }
        }

        // Calculate call duration if we have both answer and end times
        if (this.callInfo.answerTime && this.callInfo.endTime) {
            const start = this.parseTimestamp(this.callInfo.answerTime);
            const end = this.parseTimestamp(this.callInfo.endTime);
            if (start && end) {
                this.callInfo.duration = Math.round((end - start) / 1000);
            }
        }

        // Sort messages by timestamp
        this.messages.sort((a, b) => {
            const timeA = this.parseTimestamp(a.timestamp);
            const timeB = this.parseTimestamp(b.timestamp);
            return (timeA || 0) - (timeB || 0);
        });

        return this;
    }

    splitIntoMessages(data) {
        // Split by message type headers
        const messageTypes = [
            'termAttempt', 'origAttempt', 'directSignalReporting',
            'ccOpen', 'ccClose', 'answer', 'release',
            'ims_3gpp_VoIP_answer', 'ims_3gpp_VoIP_release',
            'smsMessage', 'mmsMessage'
        ];

        const blocks = [];
        const lines = data.split('\n');
        let currentBlock = [];
        let inBlock = false;

        for (const line of lines) {
            // Check if this line starts a new message type
            const isNewMessage = messageTypes.some(type =>
                line.trim().startsWith(type) ||
                line.includes('laesMessage') ||
                (line.match(/^[A-Za-z].*Version \d/) && currentBlock.length > 0)
            );

            if (line.match(/^[A-Za-z].*Version \d/) && currentBlock.length > 0) {
                // Save previous block and start new one
                blocks.push(currentBlock.join('\n'));
                currentBlock = [line];
                inBlock = true;
            } else {
                currentBlock.push(line);
                inBlock = true;
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

        // Determine message type
        if (block.includes('termAttempt') && !block.includes('ims_3gpp')) {
            result.type = 'termAttempt';
        } else if (block.includes('origAttempt')) {
            result.type = 'origAttempt';
        } else if (block.includes('directSignalReporting')) {
            result.type = 'directSignalReporting';
        } else if (block.includes('ccOpen')) {
            result.type = 'ccOpen';
        } else if (block.includes('ccClose')) {
            result.type = 'ccClose';
        } else if (block.includes('ims_3gpp_VoIP_answer') || (block.includes('answer') && block.includes('answering'))) {
            result.type = 'answer';
        } else if (block.includes('ims_3gpp_VoIP_release') || (block.includes('release') && block.includes('cause'))) {
            result.type = 'release';
        }

        // Extract common fields
        result.caseId = this.extractField(block, 'caseId');
        result.timestamp = this.extractField(block, 'timestamp');
        result.callId = this.extractNestedField(block, 'callId', 'main') ||
            this.extractNestedField(block, 'contentIdentifier', 'main');

        // Extract type-specific data
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
        const data = {
            calling: {},
            called: {},
            sdp: null
        };

        // Extract calling party info
        const callingSection = block.match(/calling\s*\n([\s\S]*?)(?=called|$)/i);
        if (callingSection) {
            const uriMatch = callingSection[1].match(/uri\[0\]\s*=\s*(.+)/i);
            if (uriMatch) data.calling.uri = uriMatch[1].trim();

            // Extract phone number from URI
            const phoneMatch = data.calling.uri?.match(/\+(\d+)/);
            if (phoneMatch) data.calling.phoneNumber = '+' + phoneMatch[1];

            // Extract headers
            const headerMatches = callingSection[1].matchAll(/sipHeader\[\d+\]\s*=\s*(.+)/gi);
            data.calling.headers = [];
            for (const match of headerMatches) {
                data.calling.headers.push(match[1].trim());

                // Extract caller name from P-Asserted-Identity
                const nameMatch = match[1].match(/"([^"]+)"/);
                if (nameMatch) data.calling.callerName = nameMatch[1];
            }
        }

        // Extract called party info
        const calledSection = block.match(/called\s*\n([\s\S]*?)(?=associateMedia|location|$)/i);
        if (calledSection) {
            const uriMatch = calledSection[1].match(/uri\[0\]\s*=\s*(.+)/i);
            if (uriMatch) data.called.uri = uriMatch[1].trim();

            const phoneMatch = data.called.uri?.match(/\+(\d+)/);
            if (phoneMatch) data.called.phoneNumber = '+' + phoneMatch[1];

            const headerMatches = calledSection[1].matchAll(/sipHeader\[\d+\]\s*=\s*(.+)/gi);
            data.called.headers = [];
            for (const match of headerMatches) {
                data.called.headers.push(match[1].trim());
            }
        }

        // Extract SDP (codec info)
        const sdpMatch = block.match(/sdp\s*=\s*([\s\S]*?)(?=\n\s*\n|\n[a-zA-Z])/);
        if (sdpMatch) {
            data.sdp = sdpMatch[1].trim();
            data.codecs = this.parseCodecsFromSDP(data.sdp);
        }

        return data;
    }

    parseSIPMessage(block) {
        const data = {
            sipMessages: [],
            correlationId: null
        };

        data.correlationId = this.extractField(block, 'correlationID');

        // Extract SIP message content
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
        const parsed = {
            method: null,
            statusCode: null,
            statusText: null,
            headers: {},
            isRequest: false,
            isResponse: false
        };

        const lines = sipContent.split('\n');
        if (lines.length === 0) return parsed;

        const firstLine = lines[0].trim();

        // Check if it's a request or response
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
            if (methodMatch) {
                parsed.method = methodMatch[1];
            }
        }

        // Parse headers
        for (let i = 1; i < lines.length; i++) {
            const line = lines[i].trim();
            const headerMatch = line.match(/^([^:]+):\s*(.+)/);
            if (headerMatch) {
                const headerName = headerMatch[1].trim();
                const headerValue = headerMatch[2].trim();

                if (parsed.headers[headerName]) {
                    if (Array.isArray(parsed.headers[headerName])) {
                        parsed.headers[headerName].push(headerValue);
                    } else {
                        parsed.headers[headerName] = [parsed.headers[headerName], headerValue];
                    }
                } else {
                    parsed.headers[headerName] = headerValue;
                }
            }
        }

        return parsed;
    }

    parseCCMessage(block) {
        const data = {
            sdp: null,
            codecs: []
        };

        // Extract SDP from subjectMedia or associateMedia
        const sdpMatch = block.match(/sdp\s*=\s*([\s\S]*?)(?=\n\s*(?:associateMedia|deliveryIdentifier)|$)/);
        if (sdpMatch) {
            data.sdp = sdpMatch[1].trim();
            data.codecs = this.parseCodecsFromSDP(data.sdp);
        }

        return data;
    }

    parseAnswerMessage(block) {
        const data = {
            answering: {},
            location: []
        };

        // Extract answering party
        const answeringSection = block.match(/answering\s*\n([\s\S]*?)(?=location|$)/i);
        if (answeringSection) {
            const uriMatch = answeringSection[1].match(/uri\[0\]\s*=\s*(.+)/i);
            if (uriMatch) data.answering.uri = uriMatch[1].trim();

            const phoneMatch = data.answering.uri?.match(/\+(\d+)/);
            if (phoneMatch) data.answering.phoneNumber = '+' + phoneMatch[1];
        }

        // Extract location
        data.location = this.parseLocationData(block);

        return data;
    }

    parseReleaseMessage(block) {
        const data = {
            cause: null,
            location: []
        };

        // Extract cause
        const causeSection = block.match(/cause\s*\n([\s\S]*?)(?=contactAddresses|location|$)/i);
        if (causeSection) {
            const sigTypeMatch = causeSection[1].match(/signalingType\s*=\s*(.+)/i);
            if (sigTypeMatch) data.cause = sigTypeMatch[1].trim();
        }

        // Extract location
        data.location = this.parseLocationData(block);

        return data;
    }

    parseLocationData(block) {
        const locations = [];
        const locationMatches = block.matchAll(/location\[\d+\]\s*\n\s*locationType\s*=\s*(.+)\n\s*locationData\s*=\s*(.+)/gi);

        for (const match of locationMatches) {
            const locationData = {
                type: match[1].trim(),
                rawData: match[2].trim(),
                parsed: {}
            };

            // Parse cell tower info from P-Access-Network-Info
            const cellMatch = locationData.rawData.match(/utran-cell-id-3gpp=(\d+)/i);
            if (cellMatch) {
                const cellId = cellMatch[1];
                locationData.parsed = this.parseCellId(cellId);
            }

            locations.push(locationData);
        }

        return locations;
    }

    parseCellId(cellId) {
        // Parse 3GPP cell ID format: MCC (3) + MNC (2-3) + LAC/TAC (4-5 hex) + Cell ID (7-8 hex)
        // Example: 311480550414df40c
        const result = {
            fullCellId: cellId,
            mcc: null,
            mnc: null,
            lac: null,
            cellId: null
        };

        if (cellId.length >= 15) {
            result.mcc = cellId.substring(0, 3);
            result.mnc = cellId.substring(3, 6);
            // The remaining is TAC + Cell ID in hex
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
            codecs.push({
                payloadType: match[1],
                name: match[2]
            });
        }

        return codecs;
    }

    extractCallInfo(message) {
        if (message.caseId) this.callInfo.caseId = message.caseId;
        if (message.callId) this.callInfo.callId = message.callId;

        switch (message.type) {
            case 'termAttempt':
                this.callInfo.callDirection = 'Incoming';
                this.callInfo.callType = 'Voice Call';
                this.callInfo.startTime = message.timestamp;
                if (message.data.calling) {
                    this.callInfo.callingParty = message.data.calling;
                    if (message.data.calling.callerName) {
                        this.callInfo.callerName = message.data.calling.callerName;
                    }
                }
                if (message.data.called) {
                    this.callInfo.calledParty = message.data.called;
                }
                if (message.data.codecs) {
                    this.callInfo.codecs = message.data.codecs;
                }
                break;

            case 'origAttempt':
                this.callInfo.callDirection = 'Outgoing';
                this.callInfo.callType = 'Voice Call';
                this.callInfo.startTime = message.timestamp;
                if (message.data.calling) {
                    this.callInfo.callingParty = message.data.calling;
                }
                if (message.data.called) {
                    this.callInfo.calledParty = message.data.called;
                }
                break;

            case 'directSignalReporting':
                if (message.data.sipMessages) {
                    for (const sip of message.data.sipMessages) {
                        this.callInfo.sipMessages.push({
                            timestamp: message.timestamp,
                            ...sip
                        });

                        // Extract additional info from SIP headers
                        if (sip.parsed?.headers) {
                            // Caller name from P-Asserted-Identity
                            const pai = sip.parsed.headers['P-Asserted-Identity'];
                            if (pai) {
                                const nameMatch = (Array.isArray(pai) ? pai[0] : pai).match(/"([^"]+)"/);
                                if (nameMatch && !this.callInfo.callerName) {
                                    this.callInfo.callerName = nameMatch[1];
                                }
                            }

                            // Device info from User-Agent
                            const ua = sip.parsed.headers['User-Agent'];
                            if (ua) {
                                this.callInfo.deviceInfo.userAgent = ua;
                                // Parse Apple device
                                const appleMatch = ua.match(/APPLE---([^-]+)---(.+)/);
                                if (appleMatch) {
                                    this.callInfo.deviceInfo.manufacturer = 'Apple';
                                    this.callInfo.deviceInfo.model = appleMatch[1];
                                    this.callInfo.deviceInfo.osVersion = appleMatch[2];
                                }
                            }

                            // Location from P-Access-Network-Info
                            const pani = sip.parsed.headers['P-Access-Network-Info'];
                            if (pani) {
                                const cellMatch = (Array.isArray(pani) ? pani[0] : pani).match(/utran-cell-id-3gpp=(\w+)/i);
                                if (cellMatch) {
                                    const existingLoc = this.callInfo.locations.find(l =>
                                        l.parsed?.fullCellId === cellMatch[1]
                                    );
                                    if (!existingLoc) {
                                        this.callInfo.locations.push({
                                            type: 'P-A-N-I-Header',
                                            rawData: pani,
                                            parsed: this.parseCellId(cellMatch[1]),
                                            timestamp: message.timestamp
                                        });
                                    }
                                }
                            }

                            // Verification status
                            const verstat = sip.parsed.headers['P-Com.NameId-Reputation'];
                            if (verstat) {
                                const verMatch = verstat.match(/verstat=([^;]+)/);
                                if (verMatch) {
                                    this.callInfo.verificationStatus = verMatch[1];
                                }
                            }
                        }
                    }
                }
                break;

            case 'answer':
                this.callInfo.answerTime = message.timestamp;
                this.callInfo.callStatus = 'Answered';
                if (message.data.location) {
                    this.callInfo.locations.push(...message.data.location);
                }
                break;

            case 'release':
                this.callInfo.endTime = message.timestamp;
                this.callInfo.releaseReason = message.data.cause;
                if (message.data.location) {
                    this.callInfo.locations.push(...message.data.location);
                }
                break;

            case 'ccOpen':
                if (message.data.codecs && message.data.codecs.length > 0) {
                    this.callInfo.codecs = message.data.codecs;
                }
                break;
        }
    }

    parseTimestamp(timestamp) {
        if (!timestamp) return null;

        // Format: 20250604035420.132Z
        const match = timestamp.match(/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.?(\d*)Z?/);
        if (match) {
            const [_, year, month, day, hour, min, sec, ms] = match;
            const isoString = `${year}-${month}-${day}T${hour}:${min}:${sec}.${ms || '000'}Z`;
            return new Date(isoString);
        }
        return null;
    }

    formatTimestamp(timestamp) {
        const date = this.parseTimestamp(timestamp);
        if (!date) return timestamp || 'Unknown';

        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true,
            timeZoneName: 'short'
        });
    }

    formatPhoneNumber(number) {
        if (!number) return 'Unknown';

        // Remove + and format as US number
        const digits = number.replace(/\D/g, '');
        if (digits.length === 11 && digits.startsWith('1')) {
            return `+1 (${digits.substring(1, 4)}) ${digits.substring(4, 7)}-${digits.substring(7)}`;
        } else if (digits.length === 10) {
            return `(${digits.substring(0, 3)}) ${digits.substring(3, 6)}-${digits.substring(6)}`;
        }
        return number;
    }

    formatDuration(seconds) {
        if (!seconds || seconds < 0) return 'N/A';

        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;

        if (hours > 0) {
            return `${hours}h ${minutes}m ${secs}s`;
        } else if (minutes > 0) {
            return `${minutes}m ${secs}s`;
        } else {
            return `${secs}s`;
        }
    }
}

// UI Functions
function analyzeCDC() {
    const input = document.getElementById('cdcInput').value;
    if (!input.trim()) {
        alert('Please paste CDC data to analyze.');
        return;
    }

    const analyzer = new CDCAnalyzer(input);
    analyzer.parse();

    displayResults(analyzer);
}

function displayResults(analyzer) {
    const container = document.getElementById('resultsContainer');
    container.classList.add('active');

    const info = analyzer.callInfo;

    let html = '';

    // Explanation Panel
    html += `
        <div class="explanation-panel">
            <h3>What This Data Shows</h3>
            <p>This is <strong>CALEA (Communications Assistance for Law Enforcement Act)</strong> intercept data from a phone carrier.
            The data captures communication events in real-time as they occur on the network.</p>
            <ul>
                <li><strong>T1.678</strong> - Industry standard format for delivering intercept data</li>
                <li><strong>LAES</strong> - Lawfully Authorized Electronic Surveillance message format</li>
                <li><strong>SIP</strong> - Session Initiation Protocol (how VoIP/VoLTE calls are set up)</li>
            </ul>
        </div>
    `;

    // Summary Cards
    html += '<div class="summary-grid">';

    // Call Overview Card
    html += `
        <div class="summary-card highlight">
            <h3>Call Overview</h3>
            <div class="info-row">
                <span class="info-label">Call Type</span>
                <span class="info-value"><span class="badge badge-info">${info.callType || 'Voice Call'}</span></span>
            </div>
            <div class="info-row">
                <span class="info-label">Direction</span>
                <span class="info-value"><span class="badge ${info.callDirection === 'Incoming' ? 'badge-success' : 'badge-warning'}">${info.callDirection || 'Unknown'}</span></span>
            </div>
            <div class="info-row">
                <span class="info-label">Status</span>
                <span class="info-value"><span class="badge ${info.callStatus === 'Answered' ? 'badge-success' : 'badge-warning'}">${info.callStatus || 'Unknown'}</span></span>
            </div>
            <div class="info-row">
                <span class="info-label">Call Duration</span>
                <span class="info-value">${analyzer.formatDuration(info.duration)}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Case ID</span>
                <span class="info-value" style="font-family: monospace;">${info.caseId || 'N/A'}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Call ID</span>
                <span class="info-value" style="font-family: monospace; font-size: 0.8rem;">${info.callId || 'N/A'}</span>
            </div>
        </div>
    `;

    // Calling Party Card
    html += `
        <div class="summary-card caller">
            <h3>Calling Party (FROM)</h3>
            <div class="info-row">
                <span class="info-label">Phone Number</span>
                <span class="info-value phone-number">${analyzer.formatPhoneNumber(info.callingParty.phoneNumber)}</span>
            </div>
            ${info.callerName ? `
            <div class="info-row">
                <span class="info-label">Caller ID Name</span>
                <span class="info-value caller-name">${info.callerName}</span>
            </div>
            ` : ''}
            ${info.verificationStatus ? `
            <div class="info-row">
                <span class="info-label">STIR/SHAKEN</span>
                <span class="info-value"><span class="badge ${info.verificationStatus.includes('Passed') ? 'badge-success' : 'badge-warning'}">${info.verificationStatus}</span></span>
            </div>
            ` : ''}
            <div class="info-row">
                <span class="info-label">Carrier</span>
                <span class="info-value">${info.callingParty.uri?.includes('t-mobile') ? 'T-Mobile' : 'Unknown'}</span>
            </div>
        </div>
    `;

    // Called Party Card
    html += `
        <div class="summary-card called">
            <h3>Called Party (TO)</h3>
            <div class="info-row">
                <span class="info-label">Phone Number</span>
                <span class="info-value phone-number">${analyzer.formatPhoneNumber(info.calledParty.phoneNumber)}</span>
            </div>
            ${info.calledParty.uri?.includes('rn=') ? `
            <div class="info-row">
                <span class="info-label">Routing Number</span>
                <span class="info-value" style="font-family: monospace;">${info.calledParty.uri.match(/rn=\+?(\d+)/)?.[1] || 'N/A'}</span>
            </div>
            ` : ''}
            <div class="info-row">
                <span class="info-label">Carrier</span>
                <span class="info-value">${info.calledParty.uri?.includes('vzims') || info.sipMessages.some(s => s.content?.includes('vzims')) ? 'Verizon' : 'Unknown'}</span>
            </div>
        </div>
    `;

    // Timestamps Card
    html += `
        <div class="summary-card">
            <h3>Timestamps (All Times)</h3>
            <div class="info-row">
                <span class="info-label">Call Initiated</span>
                <span class="info-value">${analyzer.formatTimestamp(info.startTime)}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Call Answered</span>
                <span class="info-value">${analyzer.formatTimestamp(info.answerTime)}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Call Ended</span>
                <span class="info-value">${analyzer.formatTimestamp(info.endTime)}</span>
            </div>
            <div class="info-row">
                <span class="info-label">End Reason</span>
                <span class="info-value">${info.releaseReason || 'Normal'}</span>
            </div>
        </div>
    `;

    html += '</div>';

    // Device Information Section
    if (info.deviceInfo.userAgent) {
        html += `
            <div class="device-section">
                <h3>Device Information</h3>
                <div class="device-grid">
                    ${info.deviceInfo.manufacturer ? `
                    <div class="device-item">
                        <h4>Manufacturer</h4>
                        <p>${info.deviceInfo.manufacturer}</p>
                    </div>
                    ` : ''}
                    ${info.deviceInfo.model ? `
                    <div class="device-item">
                        <h4>Device Model</h4>
                        <p>${info.deviceInfo.model}</p>
                    </div>
                    ` : ''}
                    ${info.deviceInfo.osVersion ? `
                    <div class="device-item">
                        <h4>OS Version</h4>
                        <p>iOS ${info.deviceInfo.osVersion}</p>
                    </div>
                    ` : ''}
                    <div class="device-item">
                        <h4>Full User Agent</h4>
                        <p style="font-size: 0.85rem; font-family: monospace;">${info.deviceInfo.userAgent}</p>
                    </div>
                </div>
            </div>
        `;
    }

    // Location Information
    if (info.locations.length > 0) {
        html += `
            <div class="location-section">
                <h3>Location / Cell Tower Information</h3>
                <p style="color: var(--text-muted); margin-bottom: 15px; font-size: 0.9rem;">
                    Cell tower information from the target device's network registration. This shows which cell tower(s) the device connected through during the call.
                </p>
        `;

        // Deduplicate locations
        const uniqueLocations = [];
        const seen = new Set();
        for (const loc of info.locations) {
            const key = loc.parsed?.fullCellId || loc.rawData;
            if (!seen.has(key)) {
                seen.add(key);
                uniqueLocations.push(loc);
            }
        }

        for (const loc of uniqueLocations) {
            html += `
                <div class="location-item">
                    <strong>Source:</strong> ${loc.type}<br>
                    <div class="cell-info">
                        ${loc.parsed?.mcc ? `
                        <div class="cell-detail">
                            <label>MCC (Country)</label>
                            <span>${loc.parsed.mcc}</span>
                            <small style="display: block; color: var(--text-muted);">${loc.parsed.mcc === '311' ? 'USA' : ''}</small>
                        </div>
                        ` : ''}
                        ${loc.parsed?.mnc ? `
                        <div class="cell-detail">
                            <label>MNC (Network)</label>
                            <span>${loc.parsed.mnc}</span>
                            <small style="display: block; color: var(--text-muted);">${loc.parsed.mnc === '480' ? 'Verizon' : ''}</small>
                        </div>
                        ` : ''}
                        ${loc.parsed?.lac ? `
                        <div class="cell-detail">
                            <label>TAC/LAC</label>
                            <span>${loc.parsed.lac}</span>
                        </div>
                        ` : ''}
                        ${loc.parsed?.cellId ? `
                        <div class="cell-detail">
                            <label>Cell ID</label>
                            <span>${loc.parsed.cellId}</span>
                        </div>
                        ` : ''}
                        <div class="cell-detail">
                            <label>Full Cell ID String</label>
                            <span style="font-size: 0.8rem;">${loc.parsed?.fullCellId || 'N/A'}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        html += '</div>';
    }

    // Audio Codecs
    if (info.codecs.length > 0) {
        html += `
            <div class="device-section">
                <h3>Audio Codecs (Media Capabilities)</h3>
                <p style="color: var(--text-muted); margin-bottom: 10px; font-size: 0.9rem;">
                    These are the audio encoding formats negotiated for the call. VoLTE typically uses EVS or AMR-WB for HD voice.
                </p>
                <div class="codec-list">
                    ${info.codecs.map(c => `<span class="codec-badge">${c.name}</span>`).join('')}
                </div>
            </div>
        `;
    }

    // Timeline
    html += `
        <div class="timeline-section">
            <h3>Call Event Timeline</h3>
            <p style="color: var(--text-muted); margin-bottom: 20px; font-size: 0.9rem;">
                Chronological sequence of events during this communication session.
            </p>
            <div class="timeline">
    `;

    for (const msg of analyzer.messages) {
        let eventClass = '';
        let eventTitle = '';
        let eventDetails = '';

        switch (msg.type) {
            case 'termAttempt':
                eventClass = 'event-start';
                eventTitle = 'Incoming Call Attempt';
                eventDetails = `From: ${analyzer.formatPhoneNumber(msg.data.calling?.phoneNumber)} → To: ${analyzer.formatPhoneNumber(msg.data.called?.phoneNumber)}`;
                break;
            case 'origAttempt':
                eventClass = 'event-start';
                eventTitle = 'Outgoing Call Attempt';
                eventDetails = `From: ${analyzer.formatPhoneNumber(msg.data.calling?.phoneNumber)} → To: ${analyzer.formatPhoneNumber(msg.data.called?.phoneNumber)}`;
                break;
            case 'directSignalReporting':
                if (msg.data.sipMessages?.[0]?.parsed) {
                    const sip = msg.data.sipMessages[0].parsed;
                    if (sip.isRequest) {
                        eventTitle = `SIP ${sip.method}`;
                        if (sip.method === 'INVITE') {
                            eventDetails = 'Call setup request sent';
                        } else if (sip.method === 'PRACK') {
                            eventDetails = 'Provisional acknowledgment';
                        } else if (sip.method === 'ACK') {
                            eventDetails = 'Call establishment confirmed';
                        } else if (sip.method === 'BYE') {
                            eventClass = 'event-end';
                            eventDetails = 'Call termination request';
                        } else if (sip.method === 'UPDATE') {
                            eventDetails = 'Session parameter update';
                        }
                    } else if (sip.isResponse) {
                        eventTitle = `SIP ${sip.statusCode} ${sip.statusText}`;
                        if (sip.statusCode === 180) {
                            eventClass = 'event-ring';
                            eventDetails = 'Phone is ringing';
                        } else if (sip.statusCode === 183) {
                            eventDetails = 'Call progressing (early media)';
                        } else if (sip.statusCode === 200) {
                            if (msg.data.sipMessages[0].content?.includes('INVITE')) {
                                eventClass = 'event-answer';
                                eventDetails = 'Call answered';
                            } else {
                                eventDetails = 'Request successful';
                            }
                        }
                    }
                } else {
                    eventTitle = 'SIP Signaling';
                    eventDetails = 'Network signaling message';
                }
                break;
            case 'ccOpen':
                eventTitle = 'Content Channel Opened';
                eventDetails = 'Audio/media stream established';
                break;
            case 'ccClose':
                eventClass = 'event-end';
                eventTitle = 'Content Channel Closed';
                eventDetails = 'Audio/media stream terminated';
                break;
            case 'answer':
                eventClass = 'event-answer';
                eventTitle = 'Call Answered';
                eventDetails = `Answered by: ${analyzer.formatPhoneNumber(msg.data.answering?.phoneNumber)}`;
                break;
            case 'release':
                eventClass = 'event-end';
                eventTitle = 'Call Released';
                eventDetails = `Reason: ${msg.data.cause || 'Normal termination'}`;
                break;
            default:
                eventTitle = msg.type || 'Unknown Event';
                eventDetails = '';
        }

        html += `
            <div class="timeline-event ${eventClass}">
                <div class="timeline-time">${analyzer.formatTimestamp(msg.timestamp)}</div>
                <div class="timeline-title">${eventTitle}</div>
                <div class="timeline-details">${eventDetails}</div>
            </div>
        `;
    }

    html += '</div></div>';

    // Technical Details (collapsible)
    html += `
        <div class="technical-section collapsed">
            <h3 onclick="toggleSection(this.parentElement)">Technical Details - SIP Messages</h3>
            <div class="technical-content">
                <p style="color: var(--text-muted); margin-bottom: 15px; font-size: 0.9rem;">
                    Raw SIP (Session Initiation Protocol) messages captured during the call. Click each to expand.
                </p>
    `;

    for (const sip of info.sipMessages) {
        const parsed = sip.parsed;
        let label = 'SIP Message';
        if (parsed?.isRequest) {
            label = `SIP ${parsed.method} Request`;
        } else if (parsed?.isResponse) {
            label = `SIP ${parsed.statusCode} ${parsed.statusText}`;
        }

        html += `
            <div class="message-type-label">${label}</div>
            <div class="timeline-time" style="margin-bottom: 5px;">${analyzer.formatTimestamp(sip.timestamp)}</div>
            <div class="sip-message">${escapeHtml(sip.content || '')}</div>
        `;
    }

    html += '</div></div>';

    // Raw Message Blocks (collapsible)
    html += `
        <div class="technical-section collapsed">
            <h3 onclick="toggleSection(this.parentElement)">Raw CDC Message Blocks (${analyzer.messages.length} messages)</h3>
            <div class="technical-content">
    `;

    for (const msg of analyzer.messages) {
        html += `
            <div class="message-type-label">${msg.type || 'Unknown'}</div>
            <div class="sip-message">${escapeHtml(msg.rawBlock)}</div>
        `;
    }

    html += '</div></div>';

    container.innerHTML = html;
}

function toggleSection(element) {
    element.classList.toggle('collapsed');
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function clearAll() {
    document.getElementById('cdcInput').value = '';
    document.getElementById('resultsContainer').classList.remove('active');
    document.getElementById('resultsContainer').innerHTML = '';
}

function loadSample() {
    // This would load sample data for testing
    document.getElementById('cdcInput').value = `termAttempt
T1.678 Version 4
   laesMessage
      termAttempt
         caseId = 6313754560
         iAPSystemId
            string_ = ZZ5
         timestamp = 20250604035420.132Z
         callId
            main = 003A1486D04F061E
         calling
            uri[0] = sip:+16313841232@msg.pc.t-mobile.com
            sipHeader[0] = From: sip:+16313841232@msg.pc.t-mobile.com
            sipHeader[1] = Contact: sip:mavodi-0-12e-9cf-e-fffff
            sipHeader[2] = P-Asserted-Identity: <sip:+16313841232;verstat=TN-Validation-Passed@msg.pc.t-mobile.com:5060;user=phone>
         called
            uri[0] = tel:+16313754560;phone-context=INPEER.TMOBILE.COM;npdi;rn=+16315996100
            sipHeader[0] = To:  <sip:+16313754560@msg.pc.t-mobile.com;user=phone>

Sample data loaded. Click "Analyze CDC Data" to parse.`;
}
