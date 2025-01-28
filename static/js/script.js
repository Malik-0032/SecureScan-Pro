const BACKEND_URL = "https://securescan.onrender.com";

document.getElementById('scan-button').addEventListener('click', async () => {
    const url = document.getElementById('url').value;
    if (!url) {
        alert('Please enter a URL');
        return;
    }

    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = '<p>Scanning...</p>';

    try {
        const response = await fetch(`${BACKEND_URL}/run_scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        if (response.ok) {
            const data = await response.json();
            resultsDiv.innerHTML = `<pre>${JSON.stringify(data, null, 4)}</pre>`;
        } else {
            resultsDiv.innerHTML = '<p>Error running scan. Please try again later.</p>';
        }
    } catch (error) {
        resultsDiv.innerHTML = `<p>Error: ${error.message}</p>`;
    }
});
