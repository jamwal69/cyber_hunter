# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html

import os
import json
import logging
from datetime import datetime, timezone

import requests
from scrapy.exceptions import DropItem


class CyberJobPipeline:
    """
    Main pipeline for processing cyber job items.
    - Validates required fields
    - Adds metadata
    - Deduplicates jobs
    """

    def __init__(self):
        self.seen_urls = set()
        self.jobs_count = 0

    def open_spider(self, spider):
        self.seen_urls = set()
        self.jobs_count = 0
        spider.logger.info("🔍 CyberJobPipeline initialized - Starting hunt for security jobs!")

    def close_spider(self, spider):
        spider.logger.info(f"✅ Hunt complete! Found {self.jobs_count} cybersecurity jobs.")

    def process_item(self, item, spider):
        # Validate required fields
        if not item.get('title'):
            raise DropItem(f"Missing title in {item}")
        if not item.get('url'):
            raise DropItem(f"Missing URL in {item}")

        # Deduplicate by URL
        if item['url'] in self.seen_urls:
            raise DropItem(f"Duplicate job: {item['url']}")
        self.seen_urls.add(item['url'])

        # Add scrape timestamp
        item['scraped_at'] = datetime.now(timezone.utc).isoformat()

        # Clean up location
        if item.get('location'):
            item['location'] = item['location'].strip()
        else:
            item['location'] = 'Not specified'

        # Flag remote positions
        location_lower = (item.get('location') or '').lower()
        title_lower = (item.get('title') or '').lower()
        item['is_remote'] = any(kw in location_lower or kw in title_lower 
                                for kw in ['remote', 'work from home', 'wfh', 'anywhere'])

        # Flag intern/entry-level positions
        intern_keywords = ['intern', 'internship', 'fresher', 'junior', 'entry', 
                          'early career', 'associate', 'graduate', 'new grad']
        item['is_intern'] = any(kw in title_lower for kw in intern_keywords)

        self.jobs_count += 1
        
        # Log exciting finds
        if item['is_intern']:
            spider.logger.info(f"🎯 INTERN ALERT: {item['title']} at {item['company']}")
        
        return item


class DiscordNotificationPipeline:
    """
    Optional pipeline that sends Discord webhook notifications for new jobs.
    
    Setup:
    1. Create a Discord webhook in your server (Server Settings -> Integrations -> Webhooks)
    2. Set DISCORD_WEBHOOK_URL in settings.py or as environment variable
    3. Enable this pipeline in ITEM_PIPELINES
    
    Pro tip: Create a dedicated #job-alerts channel for these notifications!
    """

    def __init__(self, webhook_url, notify_interns_only):
        self.webhook_url = webhook_url
        self.notify_interns_only = notify_interns_only
        self.logger = logging.getLogger(__name__)

    @classmethod
    def from_crawler(cls, crawler):
        webhook_url = (
            crawler.settings.get('DISCORD_WEBHOOK_URL') or 
            os.environ.get('DISCORD_WEBHOOK_URL')
        )
        notify_interns_only = crawler.settings.getbool('DISCORD_NOTIFY_INTERNS_ONLY', True)
        return cls(webhook_url, notify_interns_only)

    def open_spider(self, spider):
        if not self.webhook_url:
            spider.logger.warning(
                "⚠️ Discord webhook not configured. "
                "Set DISCORD_WEBHOOK_URL in settings.py or environment."
            )

    def process_item(self, item, spider):
        if not self.webhook_url:
            return item

        # Skip if we only want intern notifications and this isn't one
        if self.notify_interns_only and not item.get('is_intern'):
            return item

        try:
            self._send_discord_notification(item)
        except Exception as e:
            spider.logger.error(f"Failed to send Discord notification: {e}")

        return item

    def _send_discord_notification(self, item):
        """Send a formatted embed to Discord."""
        
        # Choose emoji based on job type
        if item.get('is_intern'):
            emoji = "🎯"
            title_prefix = "INTERN/ENTRY-LEVEL"
        else:
            emoji = "🔒"
            title_prefix = "SECURITY"

        # Build the embed
        embed = {
            "title": f"{emoji} {title_prefix}: {item['title']}",
            "description": f"**Company:** {item['company']}\n**Location:** {item['location']}",
            "url": item['url'],
            "color": 0x00FF00 if item.get('is_intern') else 0x0099FF,  # Green for interns, blue for others
            "fields": [
                {
                    "name": "Platform",
                    "value": item.get('platform', 'Unknown'),
                    "inline": True
                },
                {
                    "name": "Remote",
                    "value": "✅ Yes" if item.get('is_remote') else "❌ No",
                    "inline": True
                }
            ],
            "footer": {
                "text": "Cyber Hunter Bot 🕷️"
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        payload = {
            "embeds": [embed]
        }

        response = requests.post(
            self.webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response.raise_for_status()
        self.logger.debug(f"Discord notification sent for: {item['title']}")
