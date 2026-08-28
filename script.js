/* ==========================================================================
   SYNEXUS PHISHGUARD — Interactive Frontend Logic & Heuristics
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
    // 1. DOM Elements
    const header = document.querySelector('.header');
    const hamburgerBtn = document.getElementById('hamburger-btn');
    const mobileMenu = document.getElementById('mobile-menu');
    const mobileLinks = document.querySelectorAll('.mobile-link');
    const navLinks = document.querySelectorAll('.nav-link');
    
    const urlForm = document.getElementById('url-form');
    const urlInput = document.getElementById('url-input');
    const scanInputView = document.getElementById('scan-input-view');
    const scanLoadingView = document.getElementById('scan-loading-view');
    const scanResultView = document.getElementById('scan-result-view');
    const scannerCard = document.getElementById('scanner');
    
    const resultVerdict = document.getElementById('result-verdict');
    const resultUrl = document.getElementById('result-url');
    const resultRiskLevel = document.getElementById('result-risk-level');
    const resultConfidence = document.getElementById('result-confidence');
    const btnReScan = document.getElementById('btn-re-scan');
    const gaugeFillRing = document.getElementById('gauge-fill-ring');
    const gaugeText = document.getElementById('gauge-text');
    
    // Heuristic Dashboards Badges & Values
    const badgeLength = document.getElementById('badge-length');
    const valLength = document.getElementById('val-length');
    const badgeSubdomains = document.getElementById('badge-subdomains');
    const valSubdomains = document.getElementById('val-subdomains');
    const badgeIp = document.getElementById('badge-ip');
    const valIp = document.getElementById('val-ip');
    const badgeHttps = document.getElementById('badge-https');
    const valHttps = document.getElementById('val-https');
    const badgeSpecials = document.getElementById('badge-specials');
    const valSpecials = document.getElementById('val-specials');
    const badgePattern = document.getElementById('badge-pattern');
    const valPattern = document.getElementById('val-pattern');

    // Dashboard Elements
    const statTotal = document.getElementById('stat-total');
    const statThreats = document.getElementById('stat-threats');
    const statLegit = document.getElementById('stat-legit');
    const statConfidence = document.getElementById('stat-confidence');
    const recentScansList = document.getElementById('recent-scans-list');
    const btnClearHistory = document.getElementById('btn-clear-history');
    const canvas = document.getElementById('threatDistributionChart');

    // SVG Gradients Injection for Guages
    injectSvgGradients();

    // 2. Navigation & Layout Listeners
    // Scroll header background transition
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            header.classList.add('scrolled');
        } else {
            header.classList.remove('scrolled');
        }
        updateActiveNavLink();
    });

    // Mobile Menu Toggle
    hamburgerBtn.addEventListener('click', () => {
        hamburgerBtn.classList.toggle('active');
        mobileMenu.classList.toggle('active');
    });

    // Mobile Link Click handler
    mobileLinks.forEach(link => {
        link.addEventListener('click', () => {
            hamburgerBtn.classList.remove('active');
            mobileMenu.classList.remove('active');
        });
    });

    // Smooth Scroll Active States
    function updateActiveNavLink() {
        let currentSectionId = '';
        const sections = document.querySelectorAll('section');
        const scrollPosition = window.scrollY + 120; // offset header

        sections.forEach(section => {
            const top = section.offsetTop;
            const height = section.offsetHeight;
            if (scrollPosition >= top && scrollPosition < top + height) {
                currentSectionId = section.getAttribute('id');
            }
        });

        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${currentSectionId}`) {
                link.classList.add('active');
            }
        });
    }

    // Intersection Observer for scroll animations
    const revealElements = document.querySelectorAll('.reveal');
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('active');
            }
        });
    }, {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    });

    revealElements.forEach(el => observer.observe(el));

    // 3. Simulated Scans History (Local Storage Setup)
    const HISTORY_KEY = 'synexus_phishguard_scans';
    const DEFAULT_HISTORY = [
        { url: 'https://secure-paypal-login.net/verification-update', verdict: 'phishing', riskLevel: 'HIGH', confidence: 94, timestamp: Date.now() - 3600000 * 2.5 },
        { url: 'https://google.com', verdict: 'legitimate', riskLevel: 'LOW', confidence: 99, timestamp: Date.now() - 3600000 * 12 },
        { url: 'http://192.168.86.104/admin/security/login.asp', verdict: 'phishing', riskLevel: 'HIGH', confidence: 96, timestamp: Date.now() - 3600000 * 24 },
        { url: 'https://github.com/login', verdict: 'legitimate', riskLevel: 'LOW', confidence: 98, timestamp: Date.now() - 3600000 * 48 },
        { url: 'http://verify-bankofamerica-account.com/signin', verdict: 'phishing', riskLevel: 'HIGH', confidence: 89, timestamp: Date.now() - 3600000 * 72 }
    ];

    function getHistory() {
        const stored = localStorage.getItem(HISTORY_KEY);
        if (!stored) {
            localStorage.setItem(HISTORY_KEY, JSON.stringify(DEFAULT_HISTORY));
            return DEFAULT_HISTORY;
        }
        return JSON.parse(stored);
    }

    function saveScanToHistory(scan) {
        const history = getHistory();
        history.unshift(scan);
        // Cap history at 15 items
        if (history.length > 15) history.pop();
        localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
        renderHistory();
        updateStats();
    }

    function clearHistory() {
        localStorage.setItem(HISTORY_KEY, JSON.stringify([]));
        renderHistory();
        updateStats();
    }

    btnClearHistory.addEventListener('click', clearHistory);

    // 4. URL Heuristic Lexing & Analysis Logic
    function evaluateUrlHeuristics(inputUrl) {
        let urlString = inputUrl.trim();
        // Fallback for simple inputs without protocols
        if (!/^https?:\/\//i.test(urlString)) {
            urlString = 'http://' + urlString;
        }

        let parsedUrl;
        try {
            parsedUrl = new URL(urlString);
        } catch (e) {
            // Safe fallback structure
            return {
                url: inputUrl,
                length: inputUrl.length,
                subdomains: 0,
                isIp: false,
                isHttps: false,
                specialChars: 0,
                patterns: ['Invalid structural parsing format'],
                verdict: 'phishing',
                riskLevel: 'HIGH',
                confidence: 99
            };
        }

        const hostname = parsedUrl.hostname;
        const protocol = parsedUrl.protocol;
        const path = parsedUrl.pathname + parsedUrl.search;

        // Heuristic 1: URL Length
        const length = urlString.length;
        let lengthScore = 0; // 0: safe, 1: warning, 2: danger
        if (length > 75) {
            lengthScore = 2;
        } else if (length > 45) {
            lengthScore = 1;
        }

        // Heuristic 2: Subdomain Count
        // Standard domain like google.com has 2 levels (google, com) after filtering www
        const cleanHost = hostname.replace(/^www\./i, '');
        const hostParts = cleanHost.split('.');
        const subdomainCount = hostParts.length - 2 > 0 ? hostParts.length - 2 : 0;
        let subdomainScore = 0;
        if (subdomainCount >= 3) {
            subdomainScore = 2;
        } else if (subdomainCount >= 1) {
            subdomainScore = 1;
        }

        // Heuristic 3: IP Address Domain
        // Simple regex matching IPv4 formats
        const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        const isIp = ipRegex.test(hostname);
        const ipScore = isIp ? 2 : 0;

        // Heuristic 4: HTTPS Status
        const isHttps = protocol.toLowerCase() === 'https:';
        const httpsScore = isHttps ? 0 : 2;

        // Heuristic 5: Special Characters
        const specialCharMatches = urlString.match(/[?=&_@\-]/g);
        const specialCharsCount = specialCharMatches ? specialCharMatches.length : 0;
        let specialScore = 0;
        if (specialCharsCount > 5) {
            specialScore = 2;
        } else if (specialCharsCount > 2) {
            specialScore = 1;
        }

        // Heuristic 6: Suspicious Keywords
        const suspKeywords = [
            'login', 'secure', 'bank', 'update', 'signin', 'paypal', 'verify', 
            'free', 'gift', 'bonus', 'account', 'credential', 'banking', 'support',
            'recovery', 'wp-admin', 'ebay', 'amazon', 'netflix', 'wallet', 'crypto'
        ];
        
        let foundKeywords = [];
        suspKeywords.forEach(word => {
            if (urlString.toLowerCase().includes(word)) {
                foundKeywords.push(word);
            }
        });
        
        // Pattern checks: checks for nested domains or double extensions
        if (hostname.includes('-security') || hostname.includes('-secure') || hostname.includes('verification-')) {
            foundKeywords.push('domain-spoofing-pattern');
        }
        
        let patternScore = 0;
        if (foundKeywords.length >= 2) {
            patternScore = 2;
        } else if (foundKeywords.length === 1) {
            patternScore = 1;
        }

        // Calculate combined risk value
        // Max theoretical points = 12
        const totalPoints = lengthScore + subdomainScore + ipScore + httpsScore + specialScore + patternScore;
        
        // Define verdict based on points & conditions
        let verdict = 'legitimate';
        let riskLevel = 'LOW';
        let confidence = 0;

        // Known super-clean exclusions (whitelist simulation)
        const whitelist = ['google.com', 'github.com', 'microsoft.com', 'apple.com', 'wikipedia.org', 'youtube.com', 'gmail.com'];
        const isWhitelisted = whitelist.some(domain => hostname === domain || hostname.endsWith('.' + domain));

        if (isWhitelisted && !path.includes('login')) {
            verdict = 'legitimate';
            riskLevel = 'LOW';
            confidence = 99 - Math.floor(Math.random() * 2);
        } else if (totalPoints >= 4) {
            verdict = 'phishing';
            riskLevel = totalPoints >= 7 ? 'HIGH' : 'MEDIUM';
            
            // Map confidence between 75% and 98%
            const minConf = 75;
            const maxConf = 98;
            confidence = Math.min(maxConf, Math.floor(minConf + ((totalPoints - 4) / 8) * (maxConf - minConf) + Math.random() * 5));
        } else if (totalPoints >= 2) {
            // Borderline case
            verdict = 'phishing';
            riskLevel = 'MEDIUM';
            confidence = Math.floor(70 + Math.random() * 10);
        } else {
            verdict = 'legitimate';
            riskLevel = 'LOW';
            // Low risk confidence ranges from 82% to 99% depending on clean elements
            confidence = Math.min(99, Math.floor(85 + (3 - totalPoints) * 4.5 + Math.random() * 4));
        }

        return {
            url: urlString,
            length,
            lengthScore,
            subdomains: subdomainCount,
            subdomainScore,
            isIp,
            ipScore,
            isHttps,
            httpsScore,
            specialChars: specialCharsCount,
            specialScore,
            patterns: foundKeywords,
            patternScore,
            verdict,
            riskLevel,
            confidence
        };
    }

    // 5. Submit Handler & Scan Animation Transitions
    urlForm.addEventListener('submit', (e) => {
        e.preventDefault();
        
        const urlToScan = urlInput.value.trim();
        if (!urlToScan) return;
        
        // Transition views: Inputs -> Loader
        scanInputView.classList.add('hidden');
        scanLoadingView.classList.remove('hidden');
        
        // Reset loading step styling classes
        const steps = ['step-1', 'step-2', 'step-3', 'step-4'];
        steps.forEach(id => {
            const item = document.getElementById(id);
            item.className = 'progress-step-item';
            item.querySelector('.step-status').textContent = 'Pending';
        });

        // Run Heuristics analysis ahead of time
        const result = evaluateUrlHeuristics(urlToScan);

        // Sequence steps with simulated timeouts
        let currentStep = 0;
        
        function runNextStep() {
            if (currentStep > 0) {
                // Set previous step as success
                const prevItem = document.getElementById(steps[currentStep - 1]);
                prevItem.classList.remove('active');
                prevItem.classList.add('success');
                prevItem.querySelector('.step-status').textContent = 'Complete';
            }
            
            if (currentStep < steps.length) {
                // Activate current step
                const currItem = document.getElementById(steps[currentStep]);
                currItem.classList.add('active');
                currItem.querySelector('.step-status').textContent = 'Running...';
                
                currentStep++;
                // Speed up analysis sequence for interactive feel
                setTimeout(runNextStep, 500 + Math.random() * 400); 
            } else {
                // Done! Save and Render result page
                setTimeout(() => {
                    revealResults(result);
                    saveScanToHistory({
                        url: result.url,
                        verdict: result.verdict,
                        riskLevel: result.riskLevel,
                        confidence: result.confidence,
                        timestamp: Date.now()
                    });
                }, 400);
            }
        }
        
        // Start sequence
        setTimeout(runNextStep, 300);
    });

    // Reset scanner click
    btnReScan.addEventListener('click', () => {
        scanResultView.classList.add('hidden');
        scanLoadingView.classList.add('hidden');
        scanInputView.classList.remove('hidden');
        
        // Clean themes
        scannerCard.classList.remove('phishing-theme', 'legit-theme');
        urlInput.value = '';
        urlInput.focus();
    });

    // 6. Reveal Results Screen & Animate Circular Gauge
    function revealResults(result) {
        // Switch Views: Loader -> Result
        scanLoadingView.classList.add('hidden');
        scanResultView.classList.remove('hidden');
        
        // Setup card styling themes
        if (result.verdict === 'phishing') {
            scannerCard.classList.add('phishing-theme');
            resultVerdict.textContent = 'Potentially Phishing';
            document.getElementById('result-icon-phishing').classList.remove('hidden');
            document.getElementById('result-icon-legitimate').classList.add('hidden');
            
            // Risk level badges mapping
            resultRiskLevel.className = 'risk-badge badge-high';
            resultRiskLevel.textContent = result.riskLevel;
        } else {
            scannerCard.classList.add('legit-theme');
            resultVerdict.textContent = 'Likely Legitimate';
            document.getElementById('result-icon-legitimate').classList.remove('hidden');
            document.getElementById('result-icon-phishing').classList.add('hidden');
            
            resultRiskLevel.className = 'risk-badge badge-low';
            resultRiskLevel.textContent = 'LOW';
        }
        
        resultUrl.textContent = result.url;
        
        // Populate Heuristics indicators grid
        // Length
        valLength.textContent = `${result.length} characters`;
        badgeLength.className = 'feature-badge ' + (result.lengthScore === 2 ? 'danger' : result.lengthScore === 1 ? 'warning' : 'safe');
        badgeLength.textContent = result.lengthScore === 2 ? 'High Risk' : result.lengthScore === 1 ? 'Warning' : 'Safe';
        
        // Subdomains
        valSubdomains.textContent = `${result.subdomains} found`;
        badgeSubdomains.className = 'feature-badge ' + (result.subdomainScore === 2 ? 'danger' : result.subdomainScore === 1 ? 'warning' : 'safe');
        badgeSubdomains.textContent = result.subdomainScore === 2 ? 'High Risk' : result.subdomainScore === 1 ? 'Warning' : 'Safe';
        
        // IP
        valIp.textContent = result.isIp ? 'Yes (Raw Host)' : 'No (DNS Domain)';
        badgeIp.className = 'feature-badge ' + (result.isIp ? 'danger' : 'safe');
        badgeIp.textContent = result.isIp ? 'High Risk' : 'Safe';
        
        // HTTPS
        valHttps.textContent = result.isHttps ? 'Yes (TLS Active)' : 'No (Plain HTTP)';
        badgeHttps.className = 'feature-badge ' + (result.isHttps ? 'safe' : 'danger');
        badgeHttps.textContent = result.isHttps ? 'Safe' : 'High Risk';
        
        // Specials
        valSpecials.textContent = `${result.specialChars} characters`;
        badgeSpecials.className = 'feature-badge ' + (result.specialScore === 2 ? 'danger' : result.specialScore === 1 ? 'warning' : 'safe');
        badgeSpecials.textContent = result.specialScore === 2 ? 'High Risk' : result.specialScore === 1 ? 'Warning' : 'Safe';
        
        // Patterns
        if (result.patterns.length > 0) {
            valPattern.textContent = result.patterns.slice(0, 2).join(', ');
            badgePattern.className = 'feature-badge ' + (result.patternScore === 2 ? 'danger' : 'warning');
            badgePattern.textContent = result.patternScore === 2 ? 'High Risk' : 'Warning';
        } else {
            valPattern.textContent = 'None detected';
            badgePattern.className = 'feature-badge safe';
            badgePattern.textContent = 'Safe';
        }

        // Circular confidence animation
        animateConfidenceGauge(result.confidence);
    }

    function animateConfidenceGauge(targetPercentage) {
        let currentVal = 0;
        const radius = 40;
        const circumference = 2 * Math.PI * radius; // 251.2
        
        // Reset gauge ring
        gaugeFillRing.style.strokeDasharray = circumference;
        gaugeFillRing.style.strokeDashoffset = circumference;
        
        const interval = setInterval(() => {
            if (currentVal >= targetPercentage) {
                clearInterval(interval);
            } else {
                currentVal++;
                resultConfidence.textContent = `${currentVal}%`;
                gaugeText.textContent = `${currentVal}%`;
                
                const offset = circumference - (currentVal / 100) * circumference;
                gaugeFillRing.style.strokeDashoffset = offset;
            }
        }, 12);
    }

    // 7. Inject Custom Gradients to SVG inside header or layout
    function injectSvgGradients() {
        const svgNamespace = "http://www.w3.org/2000/svg";
        const defs = document.querySelector('svg defs');
        if (!defs) return;

        // Phishing Gradient Gauge Fill
        const gradRed = document.createElementNS(svgNamespace, "linearGradient");
        gradRed.setAttribute("id", "gradGaugeRed");
        gradRed.setAttribute("x1", "0%");
        gradRed.setAttribute("y1", "0%");
        gradRed.setAttribute("x2", "100%");
        gradRed.setAttribute("y2", "100%");
        
        const stopRed1 = document.createElementNS(svgNamespace, "stop");
        stopRed1.setAttribute("offset", "0%");
        stopRed1.setAttribute("stop-color", "#ff0055");
        
        const stopRed2 = document.createElementNS(svgNamespace, "stop");
        stopRed2.setAttribute("offset", "100%");
        stopRed2.setAttribute("stop-color", "#7c3aed");
        
        gradRed.appendChild(stopRed1);
        gradRed.appendChild(stopRed2);

        // Legitimate Gradient Gauge Fill
        const gradGreen = document.createElementNS(svgNamespace, "linearGradient");
        gradGreen.setAttribute("id", "gradGaugeGreen");
        gradGreen.setAttribute("x1", "0%");
        gradGreen.setAttribute("y1", "0%");
        gradGreen.setAttribute("x2", "100%");
        gradGreen.setAttribute("y2", "100%");
        
        const stopGreen1 = document.createElementNS(svgNamespace, "stop");
        stopGreen1.setAttribute("offset", "0%");
        stopGreen1.setAttribute("stop-color", "#10b981");
        
        const stopGreen2 = document.createElementNS(svgNamespace, "stop");
        stopGreen2.setAttribute("offset", "100%");
        stopGreen2.setAttribute("stop-color", "#00f0ff");
        
        gradGreen.appendChild(stopGreen1);
        gradGreen.appendChild(stopGreen2);

        defs.appendChild(gradRed);
        defs.appendChild(gradGreen);
    }

    // 8. Renders Dashboard Recent Scans List
    function renderHistory() {
        const history = getHistory();
        recentScansList.innerHTML = '';
        
        if (history.length === 0) {
            recentScansList.innerHTML = `<div class="history-empty-state">No recent scan history logs found.</div>`;
            return;
        }

        history.forEach(item => {
            const timeStr = formatRelativeTime(item.timestamp);
            const isPhish = item.verdict === 'phishing';
            const badgeClass = isPhish ? 'phishing' : 'legitimate';
            const riskClass = isPhish ? (item.riskLevel === 'HIGH' ? 'danger' : 'warning') : 'safe';
            const badgeLabel = isPhish ? 'Phishing' : 'Legitimate';
            
            const historyItem = document.createElement('div');
            historyItem.className = 'history-item';
            historyItem.innerHTML = `
                <div class="history-url-info">
                    <span class="history-url" title="${item.url}">${item.url}</span>
                    <span class="history-time">${timeStr}</span>
                </div>
                <div class="history-status-badge">
                    <span class="history-badge ${badgeClass}">${badgeLabel}</span>
                    <span class="feature-badge ${riskClass}">${item.riskLevel} Risk</span>
                </div>
            `;
            
            // Allow users to re-populate the URL input box by clicking history items
            historyItem.style.cursor = 'pointer';
            historyItem.addEventListener('click', () => {
                urlInput.value = item.url;
                scannerCard.scrollIntoView({ behavior: 'smooth' });
                urlInput.focus();
            });

            recentScansList.appendChild(historyItem);
        });
    }

    function formatRelativeTime(timestamp) {
        const diff = Date.now() - timestamp;
        if (diff < 60000) return 'Just now';
        const mins = Math.floor(diff / 60000);
        if (mins < 60) return `${mins}m ago`;
        const hrs = Math.floor(mins / 60);
        if (hrs < 24) return `${hrs}h ago`;
        const days = Math.floor(hrs / 24);
        return `${days}d ago`;
    }

    // 9. Update Live Stats Counter Values
    function updateStats() {
        const history = getHistory();
        
        // Base starting counts (to represent the overall security feed history)
        const baseTotal = 1248;
        const baseThreats = 342;
        const baseLegit = 906;
        const baseConfidenceSum = 1248 * 94.7;

        let addedTotal = history.length;
        let addedThreats = history.filter(h => h.verdict === 'phishing').length;
        let addedLegit = history.filter(h => h.verdict === 'legitimate').length;
        let addedConfidenceSum = history.reduce((sum, h) => sum + h.confidence, 0);

        const newTotal = baseTotal + addedTotal;
        const newThreats = baseThreats + addedThreats;
        const newLegit = baseLegit + addedLegit;
        const newConfidence = ((baseConfidenceSum + addedConfidenceSum) / newTotal).toFixed(1);

        // Animate counter values
        animateCounter(statTotal, parseInt(statTotal.textContent.replace(/,/g, '')), newTotal, true);
        animateCounter(statThreats, parseInt(statThreats.textContent.replace(/,/g, '')), newThreats, false);
        animateCounter(statLegit, parseInt(statLegit.textContent.replace(/,/g, '')), newLegit, false);
        
        // Display average confidence
        statConfidence.textContent = `${newConfidence}%`;

        // Trigger Canvas Chart Redraw
        drawCanvasChart(newLegit, newThreats);
    }

    function animateCounter(element, start, end, formatComma) {
        if (isNaN(start)) start = 0;
        let current = start;
        const duration = 1000;
        const increment = Math.ceil((end - start) / 30);
        
        const timer = setInterval(() => {
            current += increment;
            if ((increment > 0 && current >= end) || (increment < 0 && current <= end)) {
                current = end;
                clearInterval(timer);
            }
            element.textContent = formatComma ? current.toLocaleString() : current;
        }, 30);
    }

    // 10. Draw Custom Gradient Area Chart on Canvas
    function drawCanvasChart(legitVal, threatsVal) {
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        // Clear canvas and handle dimensions
        const width = canvas.clientWidth;
        const height = canvas.clientHeight;
        canvas.width = width;
        canvas.height = height;

        ctx.clearRect(0, 0, width, height);

        // Draw grid lines
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.04)';
        ctx.lineWidth = 1;
        const gridLines = 4;
        for (let i = 0; i <= gridLines; i++) {
            const y = (height / gridLines) * i;
            ctx.beginPath();
            ctx.moveTo(0, y);
            ctx.lineTo(width, y);
            ctx.stroke();
        }

        // Setup chart labels & data (simulating daily activity mapping)
        const labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
        
        // Calculate scaling variables based on inputs to show active changes
        const factor = (legitVal + threatsVal) / 1200;
        const legitData = [120 * factor, 150 * factor, 140 * factor, 180 * factor, 160 * factor, 210 * factor, legitVal / 4.2];
        const threatData = [40 * factor, 45 * factor, 30 * factor, 60 * factor, 50 * factor, 70 * factor, threatsVal / 4.2];

        // Draw Legitimate Area Chart (Green)
        drawAreaSpline(ctx, legitData, width, height, 'rgba(16, 185, 129, 0.15)', 'rgba(16, 185, 129, 0)', '#10b981');
        // Draw Threats Area Chart (Red)
        drawAreaSpline(ctx, threatData, width, height, 'rgba(255, 0, 85, 0.15)', 'rgba(255, 0, 85, 0)', '#ff0055');

        // Draw X-Axis labels
        ctx.fillStyle = '#64748b';
        ctx.font = '9px JetBrains Mono, monospace';
        ctx.textAlign = 'center';
        const paddingX = 40;
        const stepX = (width - paddingX * 2) / (labels.length - 1);
        
        labels.forEach((label, index) => {
            const x = paddingX + stepX * index;
            ctx.fillText(label, x, height - 5);
        });
    }

    function drawAreaSpline(ctx, data, width, height, startColor, endColor, strokeColor) {
        const paddingX = 40;
        const bottomY = height - 20;
        const topY = 20;
        
        const stepX = (width - paddingX * 2) / (data.length - 1);
        const maxVal = Math.max(...data) * 1.2 || 1;

        let points = [];
        data.forEach((val, idx) => {
            const x = paddingX + stepX * idx;
            const y = bottomY - ((val / maxVal) * (bottomY - topY));
            points.push({ x, y });
        });

        // 1. Draw area gradient fill
        const gradient = ctx.createLinearGradient(0, topY, 0, bottomY);
        gradient.addColorStop(0, startColor);
        gradient.addColorStop(1, endColor);

        ctx.beginPath();
        ctx.moveTo(points[0].x, bottomY);
        
        // Draw bezier curves
        ctx.lineTo(points[0].x, points[0].y);
        for (let i = 0; i < points.length - 1; i++) {
            const xc = (points[i].x + points[i + 1].x) / 2;
            const yc = (points[i].y + points[i + 1].y) / 2;
            ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
        }
        ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
        ctx.lineTo(points[points.length - 1].x, bottomY);
        ctx.closePath();
        ctx.fillStyle = gradient;
        ctx.fill();

        // 2. Draw stroke line
        ctx.beginPath();
        ctx.moveTo(points[0].x, points[0].y);
        for (let i = 0; i < points.length - 1; i++) {
            const xc = (points[i].x + points[i + 1].x) / 2;
            const yc = (points[i].y + points[i + 1].y) / 2;
            ctx.quadraticCurveTo(points[i].x, points[i].y, xc, yc);
        }
        ctx.lineTo(points[points.length - 1].x, points[points.length - 1].y);
        ctx.strokeStyle = strokeColor;
        ctx.lineWidth = 2;
        ctx.shadowColor = strokeColor;
        ctx.shadowBlur = 4;
        ctx.stroke();
        
        // Clear shadow effects for future operations
        ctx.shadowBlur = 0;

        // 3. Draw active point dots
        points.forEach((pt, index) => {
            if (index === points.length - 1) {
                ctx.beginPath();
                ctx.arc(pt.x, pt.y, 4, 0, 2 * Math.PI);
                ctx.fillStyle = strokeColor;
                ctx.fill();
                ctx.strokeStyle = '#ffffff';
                ctx.lineWidth = 1;
                ctx.stroke();
            }
        });
    }

    // 11. Initialization
    renderHistory();
    updateStats();

    // Redraw chart on resize to remain fully responsive
    window.addEventListener('resize', () => {
        const history = getHistory();
        const baseThreats = 342 + history.filter(h => h.verdict === 'phishing').length;
        const baseLegit = 906 + history.filter(h => h.verdict === 'legitimate').length;
        drawCanvasChart(baseLegit, baseThreats);
    });
});
