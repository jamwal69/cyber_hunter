# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class CyberJobItem(scrapy.Item):
    """
    Structured item for cybersecurity job postings.
    Optimized for India-based job seekers looking for high-value opportunities.
    """
    # === BASIC INFO ===
    company = scrapy.Field()
    title = scrapy.Field()
    location = scrapy.Field()
    url = scrapy.Field()
    platform = scrapy.Field()
    
    # === METADATA ===
    job_id = scrapy.Field()              # Unique hash for deduplication
    scraped_at = scrapy.Field()
    experience_level = scrapy.Field()    # Intern/Entry/Mid/Senior/Management
    
    # === INDIA-SPECIFIC FLAGS ===
    is_india_accessible = scrapy.Field() # Remote or India-based
    is_remote = scrapy.Field()           # Fully remote
    india_blocked = scrapy.Field()       # List of blocking reasons (US only, clearance, etc)
    visa_sponsorship = scrapy.Field()    # Available/Not Available/Unknown
    
    # === HIGH-VALUE INDICATORS ===
    is_yc_company = scrapy.Field()       # Y Combinator backed
    is_intern = scrapy.Field()           # Intern/entry-level position
    high_value_signals = scrapy.Field()  # List: Funded, Top VC, Equity, etc
    
    # === SALARY INFO ===
    salary_usd = scrapy.Field()          # Original USD salary
    salary_inr = scrapy.Field()          # Converted to INR (Lakhs)
    
    # === JOB DETAILS (when fetch_details=true) ===
    description = scrapy.Field()         # Full job description
    requirements = scrapy.Field()        # Certs, experience, degree
    tech_stack = scrapy.Field()          # Tools & technologies mentioned
