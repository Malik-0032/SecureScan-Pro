// Backend Configuration
const BACKEND_URL = "https://securescan.onrender.com";

// DOM Elements
const urlInput = document.getElementById('url');
const scanTypeSelect = document.getElementById('scan-type');
const scanButton = document.getElementById('scan-button');
const progressContainer = document.getElementById('progress-container');
const progressBar = document.getElementById('scan-progress');
const progressText = document.getElementById('progress-text');
const resultsContainer = document.getElementById('results-container');
const downloadJsonBtn = document.getElementById('download-json');
const downloadPdfBtn = document.getElementById('download-pdf');
const shareResultsBtn = document.getElementById('share-results');
const tabButtons = document.querySelectorAll('.tab-button');
const tabContents = document.querySelectorAll('.tab-content');
const scoreValue = document.getElementById('score-value');

// State
let scanResults = null;
let currentProgress = 0;
let progressInterval;

// Event Listeners
scanButton.addEventListener('click', startScan);
downloadJsonBtn.addEventListener('click', downloadJson);
downloadPdfBtn.addEventListener('click', downloadPdf);
shareResultsBtn.addEventListener('click', shareResults);
scanTypeSelect.addEventListener('change', handleScanTypeChange);

tabButtons.forEach(button => {
    button.addEventListener('click', () => switchTab(button.dataset.tab));
});

// Functions
function handleScanTypeChange() {
    const advancedOptions = document.getElementById('advanced-options');
    advancedOptions.style.display = 
        scanTypeSelect.value === 'custom' ? 'block' : 'none';
}

async function startScan() {
    const url = urlInput.value.trim();
    if (!url) {
        showError('Please enter a valid URL or IP address');
        return;
    }

    // Reset and show progress
    resetProgress();
    progressContainer.style.display = 'block';
    resultsContainer.style.display = 'none';
    scanButton.disabled = true;

    try {
        // Simulate scan progress
        progressInterval = setInterval(updateProgress, 100);

        // Make API call to backend
        const response = await fetch(`${BACKEND_URL}/run_scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: url,
                scanType: scanTypeSelect.value,
                options: getSelectedOptions()
            })
        });

        if (!response.ok) {
            throw new Error(`Scan failed: ${response.statusText}`);
        }

        scanResults = await response.json();
        
        // Complete the progress bar
        clearInterval(progressInterval);
        progressBar.style.width = '100%';
        
        // Show results after a short delay
        setTimeout(() => {
            displayResults(scanResults);
            scanButton.disabled = false;
        }, 500);

    } catch (error) {
        clearInterval(progressInterval);
        showError('Scan failed: ' + error.message);
        scanButton.disabled = false;
    }
}

function getSelectedOptions() {
    return {
        portScan: document.getElementById('port-scan').checked,
        vulnerabilityCheck: document.getElementById('vulnerability-check').checked,
        sslCheck: document.getElementById('ssl-check').checked,
        headersCheck: document.getElementById('headers-check').checked
    };
}

function updateProgress() {
    if (currentProgress < 90) {
        currentProgress += Math.random() * 10;
        progressBar.style.width = `${currentProgress}%`;
        updateProgressText(currentProgress);
    }
}

function updateProgressText(progress) {
    const stages = [
        { threshold: 20, text: 'Initializing scan...' },
        { threshold: 40, text: 'Analyzing security headers...' },
        { threshold: 60, text: 'Checking vulnerabilities...' },
        { threshold: 80, text: 'Scanning ports...' },
        { threshold: 90, text: 'Generating report...' }
    ];

    const stage = stages.find(s => progress <= s.threshold);
    if (stage) {
        progressText.textContent = stage.text;
    }
}

function resetProgress() {
    currentProgress = 0;
    progressBar.style.width = '0%';
    progressText.textContent = 'Initializing scan...';
}

function displayResults(results) {
    resultsContainer.style.display = 'block';
    progressContainer.style.display = 'none';

    // For raw JSON display (temporary until backend provides structured data)
    const detailedResults = document.getElementById('detailed-results');
    detailedResults.innerHTML = `<pre>${JSON.stringify(results, null, 2)}</pre>`;

    // Show the results container
    resultsContainer.style.display = 'block';
    
    // Switch to the details tab
    switchTab('details');
}

function switchTab(tabId) {
    tabButtons.forEach(button => {
        button.classList.toggle('active', button.dataset.tab === tabId);
    });
    
    tabContents.forEach(content => {
        content.classList.toggle('active', content.id === tabId);
    });
}

function downloadJson() {
    if (!scanResults) return;
    
    const dataStr = JSON.stringify(scanResults, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-scan-${new Date().toISOString()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function downloadPdf() {
    if (!scanResults) return;
    // Make API call to backend to generate PDF
    fetch(`${BACKEND_URL}/generate_pdf`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(scanResults)
    })
    .then(response => response.blob())
    .then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `security-scan-${new Date().toISOString()}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    })
    .catch(error => showError('Failed to generate PDF'));
}

function shareResults() {
    if (!scanResults) return;
    
    // Generate shareable link
    fetch(`${BACKEND_URL}/share`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(scanResults)
    })
    .then(response => response.json())
    .then(data => {
        // Create a temporary input to copy the link
        const input = document.createElement('input');
        input.value = data.shareableLink;
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        document.body.removeChild(input);
        
        showNotification('Shareable link copied to clipboard!');
    })
    .catch(error => showError('Failed to generate shareable link'));
}

function showError(message) {
    // Create and show error notification
    const notification = document.createElement('div');
    notification.className = 'notification error';
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

function showNotification(message) {
    // Create and show success notification
    const notification = document.createElement('div');
    notification.className = 'notification success';
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// Initialize
handleScanTypeChange();