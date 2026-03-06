document.addEventListener("DOMContentLoaded", () => {

    const analyzeBtn = document.getElementById("analyzeBtn");
    const linkInput = document.getElementById("linkInput");
    const resultDiv = document.getElementById("result");

    if (!analyzeBtn || !linkInput || !resultDiv) {
        console.error("Required elements not found in DOM.");
        return;
    }

    analyzeBtn.addEventListener("click", analyzeLink);

    function analyzeLink() {

        let link = linkInput.value.trim();
        resultDiv.innerHTML = "";

        if (!link) {
            return showError("Please enter a link.");
        }

        // Auto-add https if missing
        if (!/^https?:\/\//i.test(link)) {
            link = "https://" + link;
        }

        if (!isValidURL(link)) {
            return showError("Invalid URL format.");
        }

        runAnalysis(link);
    }

    function runAnalysis(link) {

        let score = 0;
        let reasons = [];

        let url;

        try {
            url = new URL(link);
        } catch (error) {
            return showError("Invalid URL structure.");
        }

        const hostname = url.hostname.toLowerCase();
        const path = url.pathname.toLowerCase();
        const query = url.search.toLowerCase();

        const addRisk = (points, reason) => {
            score += points;
            reasons.push(reason);
        };

        if (url.protocol === "http:") {
            addRisk(15, "Uses insecure HTTP protocol");
        }

        const ipRegex = /^\d{1,3}(\.\d{1,3}){3}$/;
        if (ipRegex.test(hostname)) {
            addRisk(40, "IP address used instead of domain name");
        }

        if (hostname.includes("xn--")) {
            addRisk(30, "Possible homograph attack detected");
        }

        const shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"];
        if (shorteners.includes(hostname)) {
            addRisk(35, "URL shortening service detected");
        }

        const suspiciousWords = [
            "login", "verify", "update",
            "secure", "account", "bank",
            "bonus", "signin", "confirm",
            "password"
        ];

        suspiciousWords.forEach(word => {
            if (hostname.includes(word) || path.includes(word)) {
                addRisk(10, `Suspicious keyword detected: ${word}`);
            }
        });

        const parts = hostname.split(".");
        if (parts.length > 3) {
            addRisk(15, "Excessive subdomains");
        }

        const suspiciousTLDs = ["ru", "tk", "ml", "ga", "cf", "gq"];
        const tld = parts[parts.length - 1];

        if (suspiciousTLDs.includes(tld)) {
            addRisk(20, "Suspicious top-level domain");
        }

        if (hostname.length > 30) {
            addRisk(10, "Unusually long domain name");
        }

        const randomPattern = /^[a-z0-9]{10,}$/;
        if (randomPattern.test(parts[0])) {
            addRisk(20, "Random-looking domain segment");
        }

        if (query.length > 60) {
            addRisk(15, "Long query string detected");
        }

        const finalScore = Math.min(score, 100);
        showResult(finalScore, reasons);
    }

    function isValidURL(str) {
        try {
            const url = new URL(str);
            return ["http:", "https:"].includes(url.protocol);
        } catch {
            return false;
        }
    }

    function showResult(score, reasons) {

        let level = "";
        let cssClass = "";

        if (score >= 70) {
            level = "🚨 HIGH RISK - Likely Phishing";
            cssClass = "danger";
        } else if (score >= 40) {
            level = "⚠️ Suspicious - Proceed With Caution";
            cssClass = "warning";
        } else {
            level = "✅ Likely Safe";
            cssClass = "safe";
        }

        resultDiv.innerHTML = `
            <div class="result-box ${cssClass}">
                <strong>${level}</strong>
                <div class="score">
                    Risk Score: <span id="animatedScore">0</span>%
                </div>
                <div class="reasons">
                    ${reasons.length ? reasons.join("<br>") : "No major threats detected."}
                </div>
            </div>
        `;

        animateScore(score);
    }

    function animateScore(target) {

        const scoreElement = document.getElementById("animatedScore");
        let current = 0;

        const interval = setInterval(() => {
            current += 2;
            if (current >= target) {
                current = target;
                clearInterval(interval);
            }
            scoreElement.textContent = current;
        }, 10);
    }

    function showError(message) {
        resultDiv.innerHTML = `
            <div class="result-box danger">
                <strong>Input Error</strong>
                <div class="reasons">${message}</div>
            </div>
        `;
    }

});