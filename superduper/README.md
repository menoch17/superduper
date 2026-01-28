# CDC Messaging Analyzer

A high-performance, single-page application for parsing and analyzing **CDC (Call Detail Content)** messaging data in **CALEA/LAES** (Law Enforcement Assistance for Electronic Surveillance) formats.

This tool helps Law Enforcement Investigators quickly interpret complex, raw carrier signaling data into an easy-to-understand timeline.

## Key Features

- **Multi-Call Analysis**: Automatically groups messages by Call ID, allowing you to analyze multiple calls/events from a single log file.
- **Interactive Mapping**: Visualizes cell tower locations on an interactive map using Leaflet.js.
- **Call Flow Diagrams**: Generates SIP sequence diagrams using Mermaid.js to visualize the network handshake.
- **Enhanced Parsing**:
    - **T1.678/LAES**: Full support for attempt, signaling, and release messages.
    - **SMS/MMS**: Visualizes text message content and direction.
    - **Carrier Lookup**: Automatic identification of carriers via MCC/MNC codes.
    - **Device Info**: Extracts User-Agent strings and device models.
- **Investigative Reporting**:
    - **STIR/SHAKEN**: Displays caller ID verification status.
    - **CSV Export**: Export call summaries for use in Case Management Systems or Excel.
    - **Print-Ready**: Optimized styling for PDF generation in case folders.

## How to Use

1. **Paste Data**: Copy your raw CDC/LAES text logs into the input area.
2. **Analyze**: Click "Analyze CDC Data".
3. **Select Event**: If the log contains multiple calls, use the dropdown to switch between them.
4. **Explore**:
    - Check the **Summary Cards** for high-level info (Parties, Duration, Carrier).
    - Review the **Map** to see cell tower locations (approximate based on LAC/CellID).
    - Use the **Call Flow Diagram** to trace SIP signaling.
5. **Export**: Use the "Export CSV" button for reporting.

## Privacy & Security

This is a **client-side only** tool. No data is uploaded to any server. All parsing, mapping, and visualization happen entirely within your local browser, making it safe for sensitive investigative data.

## License

Law Enforcement Use Only.
