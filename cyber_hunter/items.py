# Define here the models for your scraped items
#
# See documentation in:
# https://docs.scrapy.org/en/latest/topics/items.html

import scrapy


class CyberJobItem(scrapy.Item):
    """
    Structured item for cybersecurity job postings.
    Using proper Items gives us validation and cleaner pipelines.
    """
    # Basic info
    company = scrapy.Field()
    title = scrapy.Field()
    location = scrapy.Field()
    url = scrapy.Field()
    platform = scrapy.Field()
    
    # Metadata
    job_id = scrapy.Field()          # Unique hash for deduplication
    scraped_at = scrapy.Field()
    
    # Flags
    is_intern = scrapy.Field()       # Flag for intern/entry-level positions
    is_remote = scrapy.Field()       # Flag for remote positions
    
    # Advanced fields (when fetch_details=true)
    description = scrapy.Field()     # Full job description
    salary = scrapy.Field()          # Extracted salary info
    requirements = scrapy.Field()    # List of key requirements
    experience_level = scrapy.Field()  # Intern/Entry/Mid/Senior/Management
