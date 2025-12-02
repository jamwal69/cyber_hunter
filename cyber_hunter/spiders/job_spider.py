"""
Cyber Job Spider v2.0 - Advanced OSINT for Cybersecurity Job Hunting
====================================================================

Advanced Features:
- Multi-platform support (Greenhouse, Lever, Ashby)
- Job detail scraping (full descriptions, requirements)
- Salary extraction when available
- Duplicate detection across runs
- Remote job detection
- Experience level classification

Usage:
    # Quick run (just listings)
    scrapy crawl cyber_jobs -o jobs.json
    
    # Full run with job details
    scrapy crawl cyber_jobs -a fetch_details=true -o jobs.json
    
    # Target specific companies
    scrapy crawl cyber_jobs -a companies=crowdstrike,cloudflare -o jobs.json

Author: Cyber Hunter Bot v2.0
"""

import re
import hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import scrapy
from cyber_hunter.items import CyberJobItem


class CyberJobSpider(scrapy.Spider):
    name = "cyber_jobs"
    
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
    
    # =========================================================
    # CONFIGURATION - Customize via command line args
    # =========================================================
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Parse command line arguments
        self.fetch_details = kwargs.get('fetch_details', 'false').lower() == 'true'
        target = kwargs.get('companies', '')
        self.target_companies = [c.strip() for c in target.split(',') if c.strip()] if target else []
        
        # Track stats
        self.stats = {
            'total_jobs': 0,
            'intern_jobs': 0,
            'remote_jobs': 0,
            'with_salary': 0,
        }
    
    # =========================================================
    # TARGET COMPANIES - Organized by platform
    # =========================================================
    
    COMPANY_BOARDS = {
        'greenhouse': [
            'crowdstrike', 'cloudflare', 'databricks', 'snyk', 'mandiant',
            'paloaltonetworks', 'sentinelone', 'lacework', 'cybereason',
            'rapid7', 'tenable', 'hackerone', 'bugcrowd', 'elastic',
            'splunk', 'hashicorp', 'okta', 'zscaler', 'fortinet',
            'proofpoint', 'qualys', 'beyondtrust', 'sailpoint',
            'onepassword', 'bitwarden', 'keeper',
            'datadog', 'sumologic', 'exabeam',
            'abnormalsecurity', 'tessian', 'mimecast',
        ],
        'lever': [
            'palantir', 'tanium', 'sonatype', 'wiz-inc', 'contrast',
            'orca-security', 'aquasec', 'claroty',
        ],
        'ashby': [
            'vanta', 'drata', 'secureframe', 'launchdarkly',
            'anduril',
        ],
    }
    
    def start_requests(self):
        """Generate start URLs based on configuration."""
        for platform, companies in self.COMPANY_BOARDS.items():
            for company in companies:
                # Skip if targeting specific companies and this isn't one
                if self.target_companies and company not in self.target_companies:
                    continue
                
                url = self._get_board_url(platform, company)
                if url:
                    yield scrapy.Request(
                        url,
                        callback=self.parse,
                        meta={'platform': platform, 'company': company},
                        errback=self.handle_error,
                    )
    
    def _get_board_url(self, platform, company):
        """Generate job board URL for a given platform and company."""
        urls = {
            'greenhouse': f'https://boards.greenhouse.io/{company}',
            'lever': f'https://jobs.lever.co/{company}',
            'ashby': f'https://jobs.ashbyhq.com/{company}',
        }
        return urls.get(platform)

    def handle_error(self, failure):
        """Handle request failures gracefully."""
        self.logger.warning(f"⚠️ Request failed: {failure.request.url}")

    def parse(self, response):
        """Route to the appropriate parser based on job board platform."""
        platform = response.meta.get('platform', '')
        company = response.meta.get('company', '')
        
        if not platform:
            url = response.url.lower()
            if 'greenhouse.io' in url:
                platform = 'greenhouse'
            elif 'lever.co' in url:
                platform = 'lever'
            elif 'ashbyhq.com' in url:
                platform = 'ashby'
        
        self.logger.info(f"🔍 Scanning {company} on {platform}")
        
        parsers = {
            'greenhouse': self.parse_greenhouse,
            'lever': self.parse_lever,
            'ashby': self.parse_ashby,
        }
        
        parser = parsers.get(platform)
        if parser:
            yield from parser(response, company)
        else:
            self.logger.warning(f"Unknown platform: {platform}")

    # =========================================================
    # PLATFORM PARSERS
    # =========================================================

    def parse_greenhouse(self, response, company):
        """Parse Greenhouse job boards."""
        jobs_found = 0
        
        for job in response.css('div.opening'):
            title_elem = job.css('a::text').get()
            if not title_elem:
                continue
                
            title = title_elem.strip()
            location = job.css('span.location::text').get()
            relative_url = job.css('a::attr(href)').get()
            
            if not relative_url:
                continue
                
            url = response.urljoin(relative_url)
            
            if self.is_cyber_job(title):
                jobs_found += 1
                item = self._create_job_item(
                    company=company,
                    title=title,
                    location=location,
                    url=url,
                    platform='Greenhouse'
                )
                
                if self.fetch_details:
                    yield response.follow(
                        url,
                        callback=self.parse_job_details,
                        meta={'item': item, 'platform': 'greenhouse'},
                    )
                else:
                    yield item
        
        self.logger.info(f"✅ {company}: Found {jobs_found} security jobs (Greenhouse)")

    def parse_lever(self, response, company):
        """Parse Lever job boards."""
        jobs_found = 0
        
        for job in response.css('div.posting'):
            title = (
                job.css('h5::text').get() or
                job.css('a.posting-title h5::text').get() or
                job.css('.posting-title::text').get() or
                ''
            ).strip()
            
            if not title:
                continue
            
            location = (
                job.css('span.location::text').get() or
                job.css('span.sort-by-location::text').get() or
                job.css('.posting-categories .location::text').get()
            )
            
            url = (
                job.css('a.posting-title::attr(href)').get() or
                job.css('a::attr(href)').get()
            )
            
            if not url:
                continue
            
            if self.is_cyber_job(title):
                jobs_found += 1
                item = self._create_job_item(
                    company=company,
                    title=title,
                    location=location,
                    url=url,
                    platform='Lever'
                )
                
                if self.fetch_details:
                    yield response.follow(
                        url,
                        callback=self.parse_job_details,
                        meta={'item': item, 'platform': 'lever'},
                    )
                else:
                    yield item
        
        self.logger.info(f"✅ {company}: Found {jobs_found} security jobs (Lever)")

    def parse_ashby(self, response, company):
        """Parse Ashby job boards."""
        jobs_found = 0
        
        for job in response.css('[data-testid="job-posting-list-item"], .ashby-job-posting-brief-list a, ._container_1wfrd_1'):
            title = (
                job.css('h3::text').get() or
                job.css('[class*="JobTitle"]::text').get() or
                job.css('a::text').get() or
                ''
            ).strip()
            
            if not title:
                continue
            
            location = (
                job.css('[class*="Location"]::text').get() or
                job.css('p::text').get()
            )
            
            url = job.css('a::attr(href)').get() or job.attrib.get('href')
            if url:
                url = response.urljoin(url)
            
            if not url:
                continue
            
            if self.is_cyber_job(title):
                jobs_found += 1
                item = self._create_job_item(
                    company=company,
                    title=title,
                    location=location,
                    url=url,
                    platform='Ashby'
                )
                
                if self.fetch_details:
                    yield response.follow(
                        url,
                        callback=self.parse_job_details,
                        meta={'item': item, 'platform': 'ashby'},
                    )
                else:
                    yield item
        
        self.logger.info(f"✅ {company}: Found {jobs_found} security jobs (Ashby)")

    # =========================================================
    # JOB DETAILS PARSER
    # =========================================================

    def parse_job_details(self, response):
        """Extract full job details from individual job page."""
        item = response.meta['item']
        
        # Extract job description
        description_parts = response.css('#content *::text, .job-description *::text, [class*="description"] *::text').getall()
        description = ' '.join([p.strip() for p in description_parts if p.strip()])
        item['description'] = description[:5000] if description else None
        
        # Extract salary if present
        salary = self._extract_salary(response.text)
        if salary:
            item['salary'] = salary
            self.stats['with_salary'] += 1
        
        # Extract requirements
        item['requirements'] = self._extract_requirements(description)
        
        # Extract experience level
        item['experience_level'] = self._classify_experience(item['title'], description)
        
        yield item

    # =========================================================
    # SALARY EXTRACTION
    # =========================================================

    def _extract_salary(self, text):
        """Extract salary information from job text."""
        patterns = [
            r'\$[\d,]+\s*[-–to]+\s*\$[\d,]+(?:\s*(?:per year|annually|/year|/yr))?',
            r'\$\d+k?\s*[-–to]+\s*\$?\d+k(?:\s*(?:per year|annually|/year|/yr))?',
            r'[\d,]+\s*[-–to]+\s*[\d,]+\s*(?:USD|usd)',
            r'[Ss]alary[:\s]+\$[\d,]+',
            r'\$[\d,]+\s*/\s*(?:year|yr|annually)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0).strip()
        
        return None

    # =========================================================
    # REQUIREMENTS EXTRACTION
    # =========================================================

    def _extract_requirements(self, description):
        """Extract key requirements from job description."""
        if not description:
            return []
        
        requirements = []
        
        # Common certifications
        certs = ['CISSP', 'CEH', 'OSCP', 'CISM', 'CompTIA Security+', 'Security+',
                 'GPEN', 'GCIH', 'GIAC', 'AWS', 'Azure', 'GCP', 'CCNA', 'CCNP']
        for cert in certs:
            if cert.lower() in description.lower():
                requirements.append(f"Cert: {cert}")
        
        # Years of experience
        exp_match = re.search(r'(\d+)\+?\s*(?:years?|yrs?)\s*(?:of\s+)?experience', description, re.IGNORECASE)
        if exp_match:
            requirements.append(f"{exp_match.group(1)}+ years experience")
        
        # Degree requirements
        if re.search(r"bachelor'?s?|BS|BA|undergraduate", description, re.IGNORECASE):
            requirements.append("Bachelor's degree")
        if re.search(r"master'?s?|MS|MA|graduate degree", description, re.IGNORECASE):
            requirements.append("Master's degree")
        
        # Clearance
        if re.search(r'clearance|secret|top secret|TS/SCI', description, re.IGNORECASE):
            requirements.append("Security clearance")
        
        return requirements[:10]

    # =========================================================
    # EXPERIENCE LEVEL CLASSIFICATION
    # =========================================================

    def _classify_experience(self, title, description=''):
        """Classify job by experience level."""
        text = f"{title} {description}".lower()
        
        if any(kw in text for kw in ['intern', 'internship', 'co-op']):
            return 'Intern'
        elif any(kw in text for kw in ['entry', 'junior', 'jr.', 'jr ', 'associate', 'i ', ' 1', 'new grad', 'graduate', 'fresher']):
            return 'Entry-Level'
        elif any(kw in text for kw in ['senior', 'sr.', 'sr ', 'iii', ' 3', 'lead', 'principal', 'staff']):
            return 'Senior'
        elif any(kw in text for kw in ['manager', 'director', 'head of', 'vp', 'chief']):
            return 'Management'
        else:
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
        'cryptograph', 'privacy', 'data protection',
        'intern', 'internship', 'fresher', 'junior', 'entry level',
        'early career', 'associate', 'graduate', 'new grad', 'rotational',
        'apprentice', 'trainee', 'analyst i', 'analyst 1', 'engineer i', 'engineer 1',
    ]
    
    EXCLUDE_KEYWORDS = [
        'sales', 'account executive', 'account manager', 'customer success',
        'recruiter', 'recruiting', 'talent acquisition', 'hr ',
        'marketing', 'content writer', 'social media',
        'physical security', 'security guard', 'facilities',
        'janitorial', 'custodian',
    ]

    def is_cyber_job(self, title: str) -> bool:
        """Filter jobs to only relevant cybersecurity roles."""
        if not title:
            return False
            
        title_lower = title.lower()
        
        for keyword in self.EXCLUDE_KEYWORDS:
            if keyword in title_lower:
                return False
        
        return any(kw in title_lower for kw in self.POSITIVE_KEYWORDS)

    # =========================================================
    # UTILITY METHODS
    # =========================================================

    def _create_job_item(self, company, title, location, url, platform):
        """Create a structured job item with all metadata."""
        item = CyberJobItem()
        item['company'] = self._format_company_name(company)
        item['title'] = title
        item['location'] = location.strip() if location else 'Not specified'
        item['url'] = url
        item['platform'] = platform
        
        # Generate unique ID for deduplication
        item['job_id'] = hashlib.md5(url.encode()).hexdigest()[:12]
        
        # Detect remote jobs
        loc_lower = (location or '').lower()
        title_lower = title.lower()
        item['is_remote'] = any(kw in loc_lower or kw in title_lower 
                                for kw in ['remote', 'work from home', 'wfh', 'anywhere', 'distributed'])
        
        # Detect intern/entry-level
        item['is_intern'] = any(kw in title_lower 
                               for kw in ['intern', 'internship', 'fresher', 'junior', 
                                         'entry', 'early career', 'associate', 'new grad'])
        
        # Update stats
        self.stats['total_jobs'] += 1
        if item['is_intern']:
            self.stats['intern_jobs'] += 1
        if item['is_remote']:
            self.stats['remote_jobs'] += 1
        
        return item

    def _format_company_name(self, name: str) -> str:
        """Format company name with proper capitalization."""
        special_cases = {
            'crowdstrike': 'CrowdStrike',
            'cloudflare': 'Cloudflare',
            'sentinelone': 'SentinelOne',
            'paloaltonetworks': 'Palo Alto Networks',
            'hackerone': 'HackerOne',
            'hashicorp': 'HashiCorp',
            'onepassword': '1Password',
            'wiz-inc': 'Wiz',
            'orca-security': 'Orca Security',
            'abnormalsecurity': 'Abnormal Security',
            'launchdarkly': 'LaunchDarkly',
        }
        
        lower_name = name.lower().replace(' ', '').replace('-', '')
        if lower_name in special_cases:
            return special_cases[lower_name]
        
        return name.replace('-', ' ').replace('_', ' ').title()

    def closed(self, reason):
        """Log final statistics when spider closes."""
        self.logger.info("=" * 50)
        self.logger.info("🎯 CYBER HUNTER FINAL STATS")
        self.logger.info("=" * 50)
        self.logger.info(f"Total Jobs Found:    {self.stats['total_jobs']}")
        self.logger.info(f"Intern/Entry-Level:  {self.stats['intern_jobs']}")
        self.logger.info(f"Remote Positions:    {self.stats['remote_jobs']}")
        self.logger.info(f"With Salary Info:    {self.stats['with_salary']}")
        self.logger.info("=" * 50)
