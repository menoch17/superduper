# CDC Messaging Analyzer

A high-performance, single-page application for parsing and analyzing **CDC (Call Detail Content)** messaging data in **CALEA/LAES** (Law Enforcement Assistance for Electronic Surveillance) formats.

This tool helps Law Enforcement Investigators quickly interpret complex, raw carrier signaling data into an easy-to-understand timeline.

## Features

- **Multi-Format Parsing**: Supports T1.678 and LAES message formats.
- **Visual Call Timeline**: Automatically builds a chronological timeline of all signaling events.
- **Identity Extraction**: Parses and formats caller/called parties, including phone numbers and names.
- **Location Analysis**: Extracts cell tower and sector information from SIP headers (`P-Access-Network-Info`).
- **Device Identification**: Identifies manufacturer, model, and OS version of the target device.
- **STIR/SHAKEN Verification**: Displays the verification status and attestation level of incoming calls.
- **Audio Codec Analysis**: Shows negotiated voice codecs for better understanding of call quality.
- **SIP Signaling View**: Interactive, syntax-highlighted viewers for raw SIP messages.
- **Print Ready**: Optimized styling for generating PDF reports of investigations.

## How to Use

1. **Paste Data**: Paste the raw CDC/LAES messaging data from the carrier into the input area.
2. **Analyze**: Click "Analyze CDC Data" to process the information.
3. **Review**:
   - The **Summary Cards** show the caller, called party, and basic call statistics.
   - The **Call Timeline** provides a step-by-step view of the call lifecycle.
   - **Device & Location** sections show where the target was and what device they were using.
   - **Technical Details** (optional) show the raw signaling messages for deeper forensic analysis.

## Development

This project is built using:
- HTML5
- Vanilla CSS
- Vanilla JavaScript

No external dependencies are required.

## License

Law Enforcement Use Only.
