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
    company = scrapy.Field()
    title = scrapy.Field()
    location = scrapy.Field()
    url = scrapy.Field()
    platform = scrapy.Field()
    scraped_at = scrapy.Field()
    is_intern = scrapy.Field()  # Flag for intern/entry-level positions
    is_remote = scrapy.Field()  # Flag for remote positions
