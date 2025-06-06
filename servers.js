const express = require('express');
const multer = require('multer');
const fs = require('fs');
const { Client } = require('@elastic/elasticsearch');
const http = require('http');
const net = require('net');
const socketIo = require('socket.io');
const cors = require('cors');
const puppeteer = require('puppeteer'); // For Kibana Screenshot
const PDFDocument = require('pdfkit'); // For generating reports
const path = require('path');

const app = express();
const upload = multer({ dest: 'E:/FINAL/uploads/' });

app.use(cors());
app.use(express.static('public'));

const client = new Client({
    node: 'https://localhost:9200',
    auth: { username: 'elastic', password: 's4Wlq-JCoxo2AmDz0H*6' },
    tls: { rejectUnauthorized: false }
});

const server = http.createServer(app);
const io = socketIo(server);

// ✅ File Upload Endpoint (Unchanged)
app.post('/upload-log', upload.single('logfile'), async (req, res) => {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });

    const filePath = req.file.path;
    fs.readFile(filePath, 'utf8', async (err, data) => {
        if (err) return res.status(500).json({ message: 'Error reading file' });

        const logstash = net.createConnection({ port: 5044 }, () => {
            console.log('Connected to Logstash');
            logstash.write(data);
            logstash.end();
        });

        logstash.on('end', async () => {
            console.log('Data sent to Logstash');

            const logLines = data.split('\n').filter(line => line.trim() !== '');
            const logEntries = logLines.map(line => ({
                message: line,
                severity: determineSeverity(line),
                logType: categorizeLog(line),
                impact: assessImpact(line),
                description: generateDescription(line),
                timestamp: new Date().toISOString()
            }));

            for (let log of logEntries) {
                await client.index({
                    index: 'logs',
                    body: log
                });
            }

            io.emit('logUpdate', { status: "uploaded", logs: logEntries });

            const reportPath = await generateReport(logEntries);
            res.json({ message: 'Log file uploaded successfully', reportPath });
        });

        logstash.on('error', (err) => {
            console.error('Error sending data to Logstash:', err);
            res.status(500).json({ message: 'Error sending data to Logstash' });
        });
    });
});

// ✅ New Route for Downloading Report
app.get('/download-report', (req, res) => {
    const reportPath = 'E:/FINAL/reports/log_analysis_report.pdf';
    res.download(reportPath, 'log_analysis_report.pdf', (err) => {
        if (err) {
            console.error("Error downloading report:", err);
            res.status(500).json({ message: 'Error downloading the report' });
        }
    });
});

// ✅ Generate PDF Report
async function generateReport(logs) {
    const reportPath = 'E:/FINAL/reports/log_analysis_report.pdf';
    const doc = new PDFDocument();
    const writeStream = fs.createWriteStream(reportPath);
    doc.pipe(writeStream);

    doc.fontSize(20).text('Log Analysis Report', { align: 'center' });
    doc.moveDown();

    logs.forEach(log => {
        doc.fontSize(14).text(`Message: ${log.message}`);
        doc.text(`Severity: ${log.severity}`);
        doc.text(`Log Type: ${log.logType}`);
        doc.text(`Impact: ${log.impact}`);
        doc.text(`Description: ${log.description}`);
        doc.moveDown();
    });

    doc.text('Kibana Dashboard Screenshot:', { align: 'center' });
    await captureKibanaScreenshot();
    doc.image('E:/FINAL/reports/kibana_screenshot.png', { width: 500 });

    doc.end();
    return reportPath;
}

// ✅ Capture Kibana Dashboard Screenshot
async function captureKibanaScreenshot() {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.goto('http://localhost:5601/app/dashboards', { waitUntil: 'networkidle2' });
    await page.screenshot({ path: 'E:/FINAL/reports/kibana_screenshot.png' });
    await browser.close();
}

// ✅ Helper Functions
function determineSeverity(log) {
    if (log.toLowerCase().includes('error')) return 'High';
    if (log.toLowerCase().includes('warning')) return 'Medium';
    return 'Low';
}

function categorizeLog(log) {
    if (log.toLowerCase().includes('windows')) return 'Windows Log';
    if (log.toLowerCase().includes('network')) return 'Network Log';
    return 'Other';
}

function assessImpact(log) {
    if (log.toLowerCase().includes('failed login')) return 'Possible brute force attack';
    return 'No immediate threat';
}

function generateDescription(log) {
    const logLower = log.toLowerCase();

    if (logLower.includes('unauthorized access') || logLower.includes('failed login')) {
        return 'Unauthorized access attempt detected. Possible brute-force attack.';
    }
    if (logLower.includes('malware') || logLower.includes('ransomware')) {
        return 'Potential malware/ransomware activity detected. Immediate action required.';
    }
    if (logLower.includes('port scanning')) {
        return 'Suspicious network scanning detected. Possible reconnaissance activity.';
    }
    if (logLower.includes('firewall detected')) {
        return 'Firewall blocked a potentially harmful connection attempt.';
    }
    if (logLower.includes('system file modification')) {
        return 'System file modification detected. Could indicate tampering or unauthorized changes.';
    }
    if (logLower.includes('powerShell script')) {
        return 'Suspicious PowerShell execution detected. Possible malware execution attempt.';
    }
    if (logLower.includes('keylogger')) {
        return 'Keylogging activity detected. This could indicate credential theft.';
    }
    if (logLower.includes('data exfiltration') || logLower.includes('unusual outbound traffic')) {
        return 'Unusual outbound traffic detected. Possible data exfiltration attempt.';
    }
    if (logLower.includes('security scan completed')) {
        return 'Security scan completed successfully. No threats detected.';
    }
    if (logLower.includes('normal') || logLower.includes('info')) {
        return 'Normal system activity. No immediate action required.';
    }
    
    return 'Log entry detected but requires further analysis.';
}


// ✅ Start Server
server.listen(3002, () => console.log(`Server running at http://localhost:3002`));
