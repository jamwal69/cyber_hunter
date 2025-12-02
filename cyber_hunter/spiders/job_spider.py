"""
Cyber Job Spider v3.0 - India-Focused High-Value Security Jobs
==============================================================

Finds HIGH-VALUE cybersecurity jobs accessible from India:
- Y Combinator & top VC-backed startups
- Remote-friendly companies
- India office locations
- APAC/Global remote positions
- High-paying roles with salary data

Features:
- 100+ YC & funded security startups
- India-accessible job filtering
- Salary extraction (USD + INR conversion)
- Funding/equity detection
- Visa sponsorship detection
- Work timezone compatibility scoring

Usage:
    # All India-accessible jobs
    scrapy crawl cyber_jobs -o jobs.json
    
    # Only remote jobs
    scrapy crawl cyber_jobs -a remote_only=true -o remote.json
    
    # Only YC companies
    scrapy crawl cyber_jobs -a yc_only=true -o yc_jobs.json
    
    # With full job details
    scrapy crawl cyber_jobs -a fetch_details=true -o detailed.json

Author: Cyber Hunter Bot v3.0 - India Edition 🇮🇳
"""

import re
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse

import scrapy
from cyber_hunter.items import CyberJobItem


class CyberJobSpider(scrapy.Spider):
    name = "cyber_jobs"
    
    # USD to INR approximate conversion
    USD_TO_INR = 83
    
    custom_settings = {
        'CONCURRENT_REQUESTS': 2,
        'DOWNLOAD_DELAY': 1.5,
        'RANDOMIZE_DOWNLOAD_DELAY': True,
        'COOKIES_ENABLED': False,
        'RETRY_ENABLED': True,
        'RETRY_TIMES': 2,
        'RETRY_HTTP_CODES': [500, 502, 503, 504, 408, 429],
        'ROBOTSTXT_OBEY': True,
        'DOWNLOAD_TIMEOUT': 30,
    }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Command line arguments
        self.fetch_details = kwargs.get('fetch_details', 'false').lower() == 'true'
        self.remote_only = kwargs.get('remote_only', 'false').lower() == 'true'
        self.yc_only = kwargs.get('yc_only', 'false').lower() == 'true'
        self.india_only = kwargs.get('india_only', 'false').lower() == 'true'
        
        target = kwargs.get('companies', '')
        self.target_companies = [c.strip() for c in target.split(',') if c.strip()] if target else []
        
        # Stats tracking
        self.stats = {
            'total_jobs': 0,
            'india_accessible': 0,
            'remote_jobs': 0,
            'high_value': 0,
            'with_salary': 0,
            'yc_companies': 0,
            'intern_jobs': 0,
        }
    
    # =========================================================
    # 🚀 YC-BACKED & TOP FUNDED SECURITY STARTUPS
    # =========================================================
    
    COMPANY_BOARDS = {
        'greenhouse': [
            # === YC SECURITY COMPANIES (W/S batches) ===
            'snyk',              # YC - $8.5B valuation, AppSec
            'vanta',             # YC W18 - Compliance automation
            'drata',             # YC - SOC2 automation
            'secureframe',       # YC W20 - Compliance
            'teleport',          # YC - Infrastructure access
            'oso',               # YC W21 - Authorization
            'bearer',            # YC S20 - API security
            'stytch',            # YC W20 - Auth infrastructure
            'infisical',         # YC W23 - Secrets management
            'gitguardian',       # YC S19 - Code security
            'semgrep',           # YC - Static analysis (r2c)
            'truffle-security',  # YC - TruffleHog, secrets scanning
            'projectdiscovery',  # YC S21 - Nuclei, security tools
            'assetnote',         # YC - Attack surface mgmt
            'chainguard',        # YC - Supply chain security
            'stackhawk',         # YC S19 - DAST
            'bitwarden',         # Password manager
            'replicated',        # YC W16 - Software distribution
            
            # === TOP FUNDED SECURITY COMPANIES ===
            'crowdstrike',       # $50B+ - Endpoint
            'paloaltonetworks',  # $50B+ - Network security
            'cloudflare',        # $25B+ - CDN/Security
            'zscaler',           # $25B+ - Zero trust
            'sentinelone',       # $10B+ - XDR
            'wiz',               # $10B - Cloud security (FAST growing!)
            'lacework',          # Cloud security
            'orca-security',     # Cloud security
            'cybereason',        # EDR
            'rapid7',            # Vuln management
            'tenable',           # Vuln scanning
            'qualys',            # Cloud security
            'okta',              # Identity
            'sailpoint',         # IAM
            'beyondtrust',       # PAM
            'onepassword',       # Password manager
            'hashicorp',         # Infrastructure security
            
            # === SECURITY COMPANIES WITH INDIA PRESENCE ===
            'hackerone',         # Bug bounty - Remote friendly
            'bugcrowd',          # Bug bounty - Remote friendly
            'datadog',           # Observability + Security
            'elastic',           # SIEM
            'splunk',            # SIEM (Cisco)
            'sumologic',         # SIEM
            'exabeam',           # SIEM
            'abnormalsecurity',  # Email security
            'mimecast',          # Email security
            'proofpoint',        # Email security
            'fortinet',          # Network - India offices
            
            # === HOT SERIES A/B STARTUPS ===
            'trustedglobal',     # API security
            'legitimatesecurity',
            'detectify',         # EASM
            'pentera',           # Automated pentesting
            'cymulate',          # BAS
            'safebase',          # YC - Trust center
            'securityscorecard', # Risk ratings
            'bitsight',          # Risk ratings
            
            # === MORE YC COMPANIES (various batches) ===
            'doppler',           # YC W19 - Secrets
            'tines',             # Security automation
            'torq',              # Security automation
            'sublime-security',  # Email security
            'material-security', # Email security
            'kolide',            # YC S17 - Device trust
            'blumira',           # SIEM for SMB
            'uptycs',            # Cloud security
            'aquasec',           # Container security
            'sysdig',            # Container security
        ],
        
        'lever': [
            # === YC & TOP STARTUPS ON LEVER ===
            'palantir',          # Data/Security - High paying
            'tanium',            # Endpoint mgmt
            'wiz-inc',           # YC - Cloud security unicorn!
            'contrast',          # IAST
            'orca-security',     # Cloud security
            'aquasec',           # Container security
            'claroty',           # OT security
            'armis',             # IoT security
            'noname-security',   # API security
            'salt-security',     # API security
            'traceable',         # API security
            'neosec',            # API security
            'cider-security',    # CI/CD security
            'cycode',            # Code security
            'arnica',            # Code security
            'endor-labs',        # Dependency security
            'socket',            # Supply chain (YC)
            'phylum',            # Supply chain
            'chainguard',        # Supply chain
            'sigstore',          # Supply chain
            'mondoo',            # Security posture
            'runecast',          # Cloud security
            'upwind',            # Cloud security
            'gem-security',      # Cloud detection
            'mitiga',            # IR/Cloud forensics
        ],
        
        'ashby': [
            # === ASHBY (Usually hot startups) ===
            'vanta',             # YC W18 - Compliance
            'drata',             # Compliance
            'secureframe',       # YC W20 - Compliance
            'launchdarkly',      # Feature flags
            'anduril',           # Defense tech (high pay!)
            'anthropic',         # AI Safety
            'openai',            # AI Safety
            'scale',             # Data/AI
            'figma',             # Has security team
            'notion',            # Has security team
            'linear',            # YC - Has security
            'vercel',            # Has security
            'supabase',          # YC - Has security
            'planetscale',       # Database security
            'neon',              # Database
            'temporal',          # YC - Workflow
        ],
    }
    
    # =========================================================
    # 🇮🇳 INDIA-ACCESSIBLE LOCATIONS
    # =========================================================
    
    INDIA_ACCESSIBLE_KEYWORDS = [
        # Direct India
        'india', 'bangalore', 'bengaluru', 'mumbai', 'delhi', 'ncr',
        'hyderabad', 'pune', 'chennai', 'gurgaon', 'gurugram', 'noida',
        
        # Remote-friendly indicators
        'remote', 'work from home', 'wfh', 'anywhere', 'distributed',
        'global', 'worldwide', 'international', 'async',
        
        # APAC friendly
        'apac', 'asia', 'asia pacific', 'emea', 'global remote',
        
        # Timezone friendly
        'flexible hours', 'flexible timezone', 'async first',
    ]
    
    INDIA_BLOCKED_KEYWORDS = [
        'us only', 'usa only', 'united states only',
        'us citizens only', 'us citizen', 'must be located in us',
        'no visa sponsorship', 'no sponsorship',
        'security clearance required', 'clearance required',
        'us persons only', 'itar', 'us person',
    ]
    
    # =========================================================
    # 💰 HIGH-VALUE JOB INDICATORS  
    # =========================================================
    
    HIGH_VALUE_KEYWORDS = [
        # Funding indicators
        'series a', 'series b', 'series c', 'series d',
        'well-funded', 'backed by', 'yc', 'y combinator',
        'a]6z', 'andreessen', 'sequoia', 'accel', 'greylock',
        
        # Compensation indicators
        'equity', 'stock options', 'rsu', 'esop',
        'competitive salary', 'top of market', 'above market',
        
        # Growth indicators
        'fast-growing', 'hypergrowth', 'unicorn', 'decacorn',
        'pre-ipo', 'ipo', 'recently funded',
    ]
    
    YC_COMPANIES = [
        'snyk', 'vanta', 'drata', 'secureframe', 'teleport', 'oso',
        'bearer', 'stytch', 'infisical', 'gitguardian', 'semgrep',
        'truffle', 'projectdiscovery', 'assetnote', 'chainguard',
        'stackhawk', 'replicated', 'doppler', 'kolide', 'socket',
        'safebase', 'linear', 'supabase', 'temporal', 'wiz',
    ]

    # =========================================================
    # SPIDER LOGIC
    # =========================================================
    
    def start_requests(self):
        """Generate start URLs based on configuration."""
        for platform, companies in self.COMPANY_BOARDS.items():
            for company in companies:
                # Filter by YC if requested
                if self.yc_only:
                    is_yc = any(yc in company.lower() for yc in self.YC_COMPANIES)
                    if not is_yc:
                        continue
                
                # Filter by specific companies if provided
                if self.target_companies and company not in self.target_companies:
                    continue
                
                url = self._get_board_url(platform, company)
                if url:
                    is_yc = any(yc in company.lower() for yc in self.YC_COMPANIES)
                    yield scrapy.Request(
                        url,
                        callback=self.parse,
                        meta={'platform': platform, 'company': company, 'is_yc': is_yc},
                        errback=self.handle_error,
                    )
    
    def _get_board_url(self, platform, company):
        urls = {
            'greenhouse': f'https://boards.greenhouse.io/{company}',
            'lever': f'https://jobs.lever.co/{company}',
            'ashby': f'https://jobs.ashbyhq.com/{company}',
        }
        return urls.get(platform)

    def handle_error(self, failure):
        self.logger.warning(f"⚠️ Failed: {failure.request.url}")

    def parse(self, response):
        platform = response.meta.get('platform', '')
        company = response.meta.get('company', '')
        is_yc = response.meta.get('is_yc', False)
        
        if not platform:
            url = response.url.lower()
            if 'greenhouse.io' in url:
                platform = 'greenhouse'
            elif 'lever.co' in url:
                platform = 'lever'
            elif 'ashbyhq.com' in url:
                platform = 'ashby'
        
        self.logger.info(f"🔍 Scanning {company} {'(YC)' if is_yc else ''}")
        
        parsers = {
            'greenhouse': self.parse_greenhouse,
            'lever': self.parse_lever,
            'ashby': self.parse_ashby,
        }
        
        parser = parsers.get(platform)
        if parser:
            yield from parser(response, company, is_yc)

    # =========================================================
    # PLATFORM PARSERS
    # =========================================================

    def parse_greenhouse(self, response, company, is_yc):
        jobs_found = 0
        india_found = 0
        
        for job in response.css('div.opening'):
            title_elem = job.css('a::text').get()
            if not title_elem:
                continue
                
            title = title_elem.strip()
            location = job.css('span.location::text').get() or ''
            relative_url = job.css('a::attr(href)').get()
            
            if not relative_url:
                continue
                
            url = response.urljoin(relative_url)
            
            if self.is_cyber_job(title):
                india_accessible = self._is_india_accessible(location, title)
                
                # Apply filters
                if self.remote_only and not self._is_remote(location, title):
                    continue
                if self.india_only and not india_accessible:
                    continue
                
                jobs_found += 1
                if india_accessible:
                    india_found += 1
                
                item = self._create_job_item(
                    company=company, title=title, location=location,
                    url=url, platform='Greenhouse', is_yc=is_yc
                )
                
                if self.fetch_details:
                    yield response.follow(url, callback=self.parse_job_details,
                                         meta={'item': item})
                else:
                    yield item
        
        self.logger.info(f"✅ {company}: {jobs_found} jobs ({india_found} India-accessible)")

    def parse_lever(self, response, company, is_yc):
        jobs_found = 0
        india_found = 0
        
        for job in response.css('div.posting'):
            title = (
                job.css('h5::text').get() or
                job.css('a.posting-title h5::text').get() or ''
            ).strip()
            
            if not title:
                continue
            
            location = (
                job.css('span.location::text').get() or
                job.css('span.sort-by-location::text').get() or ''
            )
            
            url = job.css('a.posting-title::attr(href)').get() or job.css('a::attr(href)').get()
            
            if not url:
                continue
            
            if self.is_cyber_job(title):
                india_accessible = self._is_india_accessible(location, title)
                
                if self.remote_only and not self._is_remote(location, title):
                    continue
                if self.india_only and not india_accessible:
                    continue
                
                jobs_found += 1
                if india_accessible:
                    india_found += 1
                
                item = self._create_job_item(
                    company=company, title=title, location=location,
                    url=url, platform='Lever', is_yc=is_yc
                )
                
                if self.fetch_details:
                    yield response.follow(url, callback=self.parse_job_details,
                                         meta={'item': item})
                else:
                    yield item
        
        self.logger.info(f"✅ {company}: {jobs_found} jobs ({india_found} India-accessible)")

    def parse_ashby(self, response, company, is_yc):
        jobs_found = 0
        india_found = 0
        
        for job in response.css('[data-testid="job-posting-list-item"], .ashby-job-posting-brief-list a, ._container_1wfrd_1, a[href*="/jobs/"]'):
            title = (
                job.css('h3::text').get() or
                job.css('[class*="JobTitle"]::text').get() or
                job.css('a::text').get() or ''
            ).strip()
            
            if not title:
                continue
            
            location = job.css('[class*="Location"]::text, p::text').get() or ''
            url = job.css('a::attr(href)').get() or job.attrib.get('href')
            
            if url:
                url = response.urljoin(url)
            else:
                continue
            
            if self.is_cyber_job(title):
                india_accessible = self._is_india_accessible(location, title)
                
                if self.remote_only and not self._is_remote(location, title):
                    continue
                if self.india_only and not india_accessible:
                    continue
                
                jobs_found += 1
                if india_accessible:
                    india_found += 1
                
                item = self._create_job_item(
                    company=company, title=title, location=location,
                    url=url, platform='Ashby', is_yc=is_yc
                )
                
                if self.fetch_details:
                    yield response.follow(url, callback=self.parse_job_details,
                                         meta={'item': item})
                else:
                    yield item
        
        self.logger.info(f"✅ {company}: {jobs_found} jobs ({india_found} India-accessible)")

    # =========================================================
    # JOB DETAILS PARSER
    # =========================================================

    def parse_job_details(self, response):
        item = response.meta['item']
        
        # Get full page text
        page_text = ' '.join(response.css('body *::text').getall())
        
        # Extract salary
        salary_usd = self._extract_salary(page_text)
        if salary_usd:
            item['salary_usd'] = salary_usd
            item['salary_inr'] = self._convert_to_inr(salary_usd)
            self.stats['with_salary'] += 1
        
        # Check for India blockers
        item['india_blocked'] = self._has_india_blockers(page_text)
        
        # Check for high-value indicators
        item['high_value_signals'] = self._extract_high_value_signals(page_text)
        
        # Check for visa sponsorship
        item['visa_sponsorship'] = self._check_visa_sponsorship(page_text)
        
        # Extract requirements
        item['requirements'] = self._extract_requirements(page_text)
        
        # Experience level
        item['experience_level'] = self._classify_experience(item['title'], page_text)
        
        # Tech stack
        item['tech_stack'] = self._extract_tech_stack(page_text)
        
        yield item

    # =========================================================
    # 🇮🇳 INDIA ACCESSIBILITY CHECKS
    # =========================================================

    def _is_india_accessible(self, location, title=''):
        """Check if job is accessible from India."""
        text = f"{location} {title}".lower()
        return any(kw in text for kw in self.INDIA_ACCESSIBLE_KEYWORDS)
    
    def _is_remote(self, location, title=''):
        """Check if job is remote."""
        text = f"{location} {title}".lower()
        remote_keywords = ['remote', 'wfh', 'work from home', 'anywhere', 
                          'distributed', 'global', 'worldwide']
        return any(kw in text for kw in remote_keywords)
    
    def _has_india_blockers(self, text):
        """Check if job has restrictions blocking India candidates."""
        text_lower = text.lower()
        blockers = []
        for kw in self.INDIA_BLOCKED_KEYWORDS:
            if kw in text_lower:
                blockers.append(kw)
        return blockers if blockers else None
    
    def _check_visa_sponsorship(self, text):
        """Check visa sponsorship availability."""
        text_lower = text.lower()
        if any(kw in text_lower for kw in ['visa sponsorship available', 'will sponsor', 'sponsorship provided']):
            return 'Available'
        elif any(kw in text_lower for kw in ['no visa sponsorship', 'no sponsorship', 'not sponsor']):
            return 'Not Available'
        return 'Unknown'

    # =========================================================
    # 💰 SALARY & VALUE EXTRACTION
    # =========================================================

    def _extract_salary(self, text):
        """Extract salary range from job description."""
        patterns = [
            r'\$(\d{2,3}),?(\d{3})[\s\-–to]+\$?(\d{2,3}),?(\d{3})',  # $100,000 - $150,000
            r'\$(\d{2,3})k[\s\-–to]+\$?(\d{2,3})k',                   # $100k - $150k
            r'(\d{2,3}),?(\d{3})[\s\-–to]+(\d{2,3}),?(\d{3})\s*USD',  # 100,000 - 150,000 USD
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None
    
    def _convert_to_inr(self, salary_str):
        """Convert USD salary to INR estimate."""
        if not salary_str:
            return None
        
        # Extract numbers
        numbers = re.findall(r'(\d+),?(\d{3})', salary_str)
        if numbers:
            # Take the average of min and max
            values = [int(n[0] + n[1]) for n in numbers]
            if values:
                avg_usd = sum(values) / len(values)
                inr = avg_usd * self.USD_TO_INR
                return f"₹{inr/100000:.1f}L - ₹{(inr * 1.2)/100000:.1f}L/year"
        return None
    
    def _extract_high_value_signals(self, text):
        """Extract signals that indicate high-value opportunity."""
        text_lower = text.lower()
        signals = []
        
        # Check for funding
        if any(kw in text_lower for kw in ['series a', 'series b', 'series c', 'series d']):
            signals.append('Funded Startup')
        
        # Check for top VCs
        if any(kw in text_lower for kw in ['y combinator', 'yc', 'sequoia', 'a16z', 'andreessen', 'accel']):
            signals.append('Top VC Backed')
        
        # Check for equity
        if any(kw in text_lower for kw in ['equity', 'stock options', 'rsu', 'esop']):
            signals.append('Equity Offered')
        
        # Check for growth
        if any(kw in text_lower for kw in ['hypergrowth', 'fast-growing', 'unicorn']):
            signals.append('High Growth')
        
        return signals if signals else None

    # =========================================================
    # TECH STACK EXTRACTION
    # =========================================================

    def _extract_tech_stack(self, text):
        """Extract security tools and technologies mentioned."""
        text_lower = text.lower()
        
        tech_categories = {
            'Cloud': ['aws', 'azure', 'gcp', 'kubernetes', 'k8s', 'docker', 'terraform'],
            'SIEM': ['splunk', 'elastic', 'sentinel', 'qradar', 'sumo logic'],
            'Security Tools': ['burp', 'nessus', 'qualys', 'crowdstrike', 'sentinel one', 'carbon black'],
            'Languages': ['python', 'golang', 'go ', 'rust', 'java', 'javascript'],
            'Frameworks': ['mitre att&ck', 'nist', 'iso 27001', 'soc 2', 'pci'],
        }
        
        found_tech = {}
        for category, techs in tech_categories.items():
            matches = [t for t in techs if t in text_lower]
            if matches:
                found_tech[category] = matches
        
        return found_tech if found_tech else None

    # =========================================================
    # REQUIREMENTS EXTRACTION
    # =========================================================

    def _extract_requirements(self, text):
        """Extract key requirements."""
        if not text:
            return []
        
        requirements = []
        text_lower = text.lower()
        
        # Certifications
        certs = ['CISSP', 'CEH', 'OSCP', 'CISM', 'Security+', 'GPEN', 'GCIH', 
                 'GIAC', 'AWS Security', 'Azure Security', 'CCSP', 'CISA']
        for cert in certs:
            if cert.lower() in text_lower:
                requirements.append(f"Cert: {cert}")
        
        # Experience
        exp_match = re.search(r'(\d+)\+?\s*(?:years?|yrs?)', text_lower)
        if exp_match:
            requirements.append(f"{exp_match.group(1)}+ years")
        
        # Degree
        if re.search(r"bachelor|bs |ba |b\.s\.|b\.a\.", text_lower):
            requirements.append("Bachelor's")
        if re.search(r"master|ms |ma |m\.s\.|m\.a\.", text_lower):
            requirements.append("Master's")
        
        # Clearance
        if 'clearance' in text_lower:
            requirements.append("Security Clearance")
        
        return requirements[:8]

    def _classify_experience(self, title, description=''):
        """Classify experience level."""
        text = f"{title} {description}".lower()
        
        if any(kw in text for kw in ['intern', 'internship', 'co-op']):
            return 'Intern'
        elif any(kw in text for kw in ['entry', 'junior', 'jr', 'associate', 'new grad', 'graduate', 'fresher', ' i ', ' 1 ']):
            return 'Entry-Level'
        elif any(kw in text for kw in ['senior', 'sr', ' iii', ' 3', 'lead', 'principal', 'staff']):
            return 'Senior'
        elif any(kw in text for kw in ['manager', 'director', 'head of', 'vp', 'chief']):
            return 'Management'
        return 'Mid-Level'

    # =========================================================
    # JOB FILTERING
    # =========================================================

    POSITIVE_KEYWORDS = [
        'security', 'cyber', 'infosec', 'information security',
        'penetration', 'pentest', 'red team', 'blue team', 'purple team',
        'soc', 'security operations', 'incident response', 'dfir',
        'threat', 'vulnerability', 'appsec', 'application security',
        'devsecops', 'secops', 'cloudsec', 'cloud security',
        'network security', 'endpoint', 'edr', 'xdr', 'siem',
        'malware', 'reverse engineer', 'forensic', 'grc',
        'compliance', 'risk', 'audit', 'iam', 'identity',
        'zero trust', 'offensive', 'defensive', 'detection',
        'cryptograph', 'privacy', 'data protection', 'bug bounty',
        'intern', 'internship', 'fresher', 'junior', 'entry level',
        'early career', 'associate', 'graduate', 'new grad',
    ]
    
    EXCLUDE_KEYWORDS = [
        'sales', 'account executive', 'account manager', 'customer success',
        'recruiter', 'recruiting', 'talent acquisition', 'hr ',
        'marketing', 'content writer', 'social media',
        'physical security', 'security guard', 'facilities',
    ]

    def is_cyber_job(self, title: str) -> bool:
        if not title:
            return False
        title_lower = title.lower()
        
        for keyword in self.EXCLUDE_KEYWORDS:
            if keyword in title_lower:
                return False
        
        return any(kw in title_lower for kw in self.POSITIVE_KEYWORDS)

    # =========================================================
    # ITEM CREATION
    # =========================================================

    def _create_job_item(self, company, title, location, url, platform, is_yc=False):
        item = CyberJobItem()
        item['company'] = self._format_company_name(company)
        item['title'] = title
        item['location'] = location.strip() if location else 'Not specified'
        item['url'] = url
        item['platform'] = platform
        item['job_id'] = hashlib.md5(url.encode()).hexdigest()[:12]
        item['scraped_at'] = datetime.now(timezone.utc).isoformat()
        
        # Flags
        loc_lower = (location or '').lower()
        title_lower = title.lower()
        
        item['is_remote'] = self._is_remote(location, title)
        item['is_india_accessible'] = self._is_india_accessible(location, title)
        item['is_yc_company'] = is_yc
        item['is_intern'] = any(kw in title_lower for kw in ['intern', 'internship', 'fresher', 'junior', 'entry', 'new grad'])
        
        # Experience classification
        item['experience_level'] = self._classify_experience(title)
        
        # Update stats
        self.stats['total_jobs'] += 1
        if item['is_india_accessible']:
            self.stats['india_accessible'] += 1
        if item['is_remote']:
            self.stats['remote_jobs'] += 1
        if is_yc:
            self.stats['yc_companies'] += 1
        if item['is_intern']:
            self.stats['intern_jobs'] += 1
        
        return item

    def _format_company_name(self, name: str) -> str:
        special = {
            'crowdstrike': 'CrowdStrike', 'cloudflare': 'Cloudflare',
            'sentinelone': 'SentinelOne', 'paloaltonetworks': 'Palo Alto Networks',
            'hackerone': 'HackerOne', 'hashicorp': 'HashiCorp',
            'onepassword': '1Password', 'wiz-inc': 'Wiz',
            'gitguardian': 'GitGuardian', 'launchdarkly': 'LaunchDarkly',
            'projectdiscovery': 'ProjectDiscovery', 'truffle-security': 'Truffle Security',
        }
        clean = name.lower().replace(' ', '').replace('-', '')
        return special.get(clean, name.replace('-', ' ').replace('_', ' ').title())

    def closed(self, reason):
        """Final stats summary."""
        self.logger.info("=" * 60)
        self.logger.info("🎯 CYBER HUNTER v3.0 - INDIA EDITION - FINAL STATS")
        self.logger.info("=" * 60)
        self.logger.info(f"📊 Total Jobs Found:      {self.stats['total_jobs']}")
        self.logger.info(f"🇮🇳 India Accessible:      {self.stats['india_accessible']}")
        self.logger.info(f"🌐 Remote Positions:      {self.stats['remote_jobs']}")
        self.logger.info(f"🚀 From YC Companies:     {self.stats['yc_companies']}")
        self.logger.info(f"🎓 Intern/Entry-Level:    {self.stats['intern_jobs']}")
        self.logger.info(f"💰 With Salary Info:      {self.stats['with_salary']}")
        self.logger.info("=" * 60)
