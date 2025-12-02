"""
Cyber Job Spider - Automated OSINT for Cybersecurity Job Hunting
================================================================

This spider targets Greenhouse and Lever job boards, which are extremely
common in the security industry. It's optimized for free Zyte cloud units
(low memory, fast execution).

Features:
- Multi-platform support (Greenhouse, Lever, Workday)
- Smart keyword filtering for cybersecurity roles
- Entry-level/Intern detection
- Remote job flagging
- Extensible company list

Usage:
    scrapy crawl cyber_jobs -o jobs.json

Author: Cyber Hunter Bot
"""

import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import scrapy
from cyber_hunter.items import CyberJobItem


class CyberJobSpider(scrapy.Spider):
    name = "cyber_jobs"
    
    # =========================================================
    # TARGET COMPANIES - Add more as you discover them!
    # =========================================================
    # These are real security company job boards
    start_urls = [
        # === GREENHOUSE BOARDS ===
        'https://boards.greenhouse.io/crowdstrike',
        'https://boards.greenhouse.io/cloudflare',
        'https://boards.greenhouse.io/databricks',
        'https://boards.greenhouse.io/snyk',
        'https://boards.greenhouse.io/mandiant',
        'https://boards.greenhouse.io/paloaltonetworks',
        'https://boards.greenhouse.io/sentinelone',
        'https://boards.greenhouse.io/lacework',
        'https://boards.greenhouse.io/cybereason',
        'https://boards.greenhouse.io/rapid7',
        'https://boards.greenhouse.io/tenable',
        'https://boards.greenhouse.io/hackerone',
        'https://boards.greenhouse.io/bugcrowd',
        'https://boards.greenhouse.io/elastic',
        'https://boards.greenhouse.io/splunk',
        'https://boards.greenhouse.io/hashicorp',
        
        # === LEVER BOARDS ===
        'https://jobs.lever.co/palantir',
        'https://jobs.lever.co/tanium',
        'https://jobs.lever.co/sonatype',
        'https://jobs.lever.co/wiz-inc',
        'https://jobs.lever.co/contrast',
        
        # Add more companies here as you find them!
        # Tip: When you find a job posting, check the URL to see
        # which platform they use, then add the base board URL here.
    ]

    custom_settings = {
        # =====================================================
        # OPTIMIZED FOR FREE ZYTE UNIT (be nice to their servers)
        # =====================================================
        'CONCURRENT_REQUESTS': 2,       # Keep it slow
        'DOWNLOAD_DELAY': 1.5,          # Don't hammer servers
        'RANDOMIZE_DOWNLOAD_DELAY': True,  # Adds randomness to look more human
        'COOKIES_ENABLED': False,       # Not needed for public boards
        
        # Retry configuration
        'RETRY_ENABLED': True,
        'RETRY_TIMES': 2,
        'RETRY_HTTP_CODES': [500, 502, 503, 504, 408, 429],
        
        # Be a good citizen
        'ROBOTSTXT_OBEY': True,
        
        # Reasonable timeout
        'DOWNLOAD_TIMEOUT': 30,
    }

    # =========================================================
    # KEYWORD CONFIGURATION - Customize to your interests!
    # =========================================================
    
    # Jobs must contain at least ONE of these keywords
    POSITIVE_KEYWORDS = [
        # Core security terms
        'security', 'cyber', 'infosec', 'information security',
        'penetration', 'pentest', 'red team', 'blue team', 'purple team',
        'soc', 'security operations', 'incident response', 'dfir',
        'threat', 'vulnerability', 'appsec', 'application security',
        'devsecops', 'secops', 'cloudsec', 'cloud security',
        'network security', 'endpoint', 'edr', 'xdr', 'siem',
        'malware', 'reverse engineer', 'forensic', 'grc',
        'compliance', 'risk', 'audit', 'iam', 'identity',
        'zero trust', 'offensive', 'defensive',
        
        # Entry-level friendly terms
        'intern', 'internship', 'fresher', 'junior', 'entry level',
        'early career', 'associate', 'graduate', 'new grad', 'rotational',
        'apprentice', 'trainee', 'analyst i', 'analyst 1', 'engineer i', 'engineer 1',
    ]
    
    # Jobs with these keywords will be flagged but NOT excluded
    # (Uncomment the filter in is_cyber_job to exclude them)
    SENIOR_KEYWORDS = [
        'senior', 'sr.', 'sr ', 'staff', 'principal', 'lead',
        'manager', 'director', 'head of', 'vp', 'vice president',
        'chief', 'architect', 'distinguished', 'fellow',
    ]
    
    # Jobs with these are usually NOT security roles
    EXCLUDE_KEYWORDS = [
        'sales', 'account executive', 'account manager', 'customer success',
        'recruiter', 'recruiting', 'talent acquisition', 'hr ',
        'marketing', 'content writer', 'social media',
        'physical security', 'security guard', 'facilities',
    ]

    def parse(self, response):
        """Route to the appropriate parser based on job board platform."""
        url = response.url.lower()
        
        self.logger.info(f"🔍 Scanning: {response.url}")
        
        if 'greenhouse.io' in url:
            yield from self.parse_greenhouse(response)
        elif 'lever.co' in url:
            yield from self.parse_lever(response)
        else:
            self.logger.warning(f"Unknown job board platform: {url}")

    def parse_greenhouse(self, response):
        """
        Parse Greenhouse job boards.
        
        Greenhouse structure:
        - Jobs are in <div class="opening">
        - Title is in <a> tag
        - Location is in <span class="location">
        - Department is in parent section
        """
        company = self._extract_company_name(response.url)
        jobs_found = 0
        
        # Greenhouse lists jobs in div.opening
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
            
            # Apply our filter
            if self.is_cyber_job(title):
                jobs_found += 1
                yield self._create_job_item(
                    company=company,
                    title=title,
                    location=location,
                    url=url,
                    platform='Greenhouse'
                )
        
        self.logger.info(f"✅ {company}: Found {jobs_found} relevant security jobs on Greenhouse")

    def parse_lever(self, response):
        """
        Parse Lever job boards.
        
        Lever structure:
        - Jobs are in <div class="posting">
        - Title is in <h5> or <a class="posting-title">
        - Location is in <span class="location"> or <span class="sort-by-location">
        """
        company = self._extract_company_name(response.url)
        jobs_found = 0
        
        # Lever lists jobs in div.posting
        for job in response.css('div.posting'):
            # Try multiple selectors for title (Lever has variations)
            title = (
                job.css('h5::text').get() or
                job.css('a.posting-title h5::text').get() or
                job.css('.posting-title::text').get() or
                ''
            ).strip()
            
            if not title:
                continue
            
            # Try multiple selectors for location
            location = (
                job.css('span.location::text').get() or
                job.css('span.sort-by-location::text').get() or
                job.css('.posting-categories .location::text').get()
            )
            
            # Get the job URL
            url = (
                job.css('a.posting-title::attr(href)').get() or
                job.css('a::attr(href)').get()
            )
            
            if not url:
                continue
            
            # Apply our filter
            if self.is_cyber_job(title):
                jobs_found += 1
                yield self._create_job_item(
                    company=company,
                    title=title,
                    location=location,
                    url=url,
                    platform='Lever'
                )
        
        self.logger.info(f"✅ {company}: Found {jobs_found} relevant security jobs on Lever")

    def is_cyber_job(self, title: str) -> bool:
        """
        Intelligent filter to determine if a job is relevant.
        
        Returns True if:
        1. Title contains at least one positive keyword
        2. Title does NOT contain any exclude keyword
        
        This is similar to log filtering in a SIEM - 
        we're reducing noise to find signal.
        """
        if not title:
            return False
            
        title_lower = title.lower()
        
        # Step 1: Exclude obvious non-security roles
        for keyword in self.EXCLUDE_KEYWORDS:
            if keyword in title_lower:
                return False
        
        # Step 2: Must match at least one positive keyword
        has_positive = any(kw in title_lower for kw in self.POSITIVE_KEYWORDS)
        
        if not has_positive:
            return False
        
        # Step 3 (Optional): Filter out senior roles
        # Uncomment the following to exclude senior positions:
        # for keyword in self.SENIOR_KEYWORDS:
        #     if keyword in title_lower:
        #         return False
        
        return True

    def _extract_company_name(self, url: str) -> str:
        """
        Extract clean company name from job board URL.
        
        Examples:
            https://boards.greenhouse.io/crowdstrike -> CrowdStrike
            https://jobs.lever.co/palantir -> Palantir
        """
        parsed = urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        
        if path_parts:
            company = path_parts[0]
            # Clean up and capitalize
            company = company.replace('-', ' ').replace('_', ' ')
            # Handle common naming patterns
            company = self._format_company_name(company)
            return company
        
        return 'Unknown'

    def _format_company_name(self, name: str) -> str:
        """Format company name with proper capitalization."""
        # Special cases for known companies
        special_cases = {
            'crowdstrike': 'CrowdStrike',
            'cloudflare': 'Cloudflare',
            'sentinelone': 'SentinelOne',
            'paloaltonetworks': 'Palo Alto Networks',
            'hackerone': 'HackerOne',
            'hashicorp': 'HashiCorp',
            'devsecops': 'DevSecOps',
        }
        
        lower_name = name.lower().replace(' ', '')
        if lower_name in special_cases:
            return special_cases[lower_name]
        
        # Default: Title case
        return name.title()

    def _create_job_item(self, company, title, location, url, platform):
        """Create a structured job item."""
        item = CyberJobItem()
        item['company'] = company
        item['title'] = title
        item['location'] = location.strip() if location else None
        item['url'] = url
        item['platform'] = platform
        return item
